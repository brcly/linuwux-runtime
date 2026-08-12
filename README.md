# Proton + LinUwUx Builder

Build **proton-cachyos** or **proton-ge-custom** from source with the **LinUwUx** patch set applied, and package a Steam Play compatibility tool.

Other projects ship pre-built tarballs or apply a pre-made `.patch` file to Wine, which can be volatile if Proton/Wine updates and shifts layout (for example Proton/Wine 10 → 11). This one is a reproducible *builder*: regenerate the latest patched Proton yourself when upstream moves. Functionality lives in an LD_PRELOAD library, not in patches against Wine's own source, so upstream reshuffling `signal_x86_64.c` (as happened between GE-Proton 11-3 and 11-5) has nothing to break.

This project does **not** configure host-side requirements for the bypass (UMIP, HV DKMS, etc.). It only builds patched Proton. See [cs.rin.ru](https://csrin.org) for those instructions.

**Proton 11 only** (for now). Valve's official Proton is not supported. Covers both GE-Proton 11-3-style trees (seccomp+BPF) and GE-Proton 11-5+ trees (Syscall User Dispatch) — which one you're building against is detected at runtime from the process's own signal setup, not guessed from a version number.

## Layout

```
build.sh                 # orchestrator
lib/
  common.sh              # logging, line-insert helpers
  source.sh               # clone, submodules, stage patches/wine
  apply-content.sh        # regedit fix, faketime protocol, force-wineboot gate
  apply-patches.sh        # traditional .patch apply + GE protonprep
  apply-proton-dll.sh     # winmm/version/reflex + lsteamclient defaults
  apply-preload.sh        # builds and installs liblinuwux_preload.so
  package.sh              # base checks, configure, redist, verify
patches/
  base/
    hwprofile_guid.reg
    set_faketime.protocol
  preload/
    linuwux_preload.c     # LD_PRELOAD library -- all LinUwUx logic lives here
  wine/
    server/0001-apply_faketime.patch
```

## How LinUwUx is applied

The script runs these steps automatically:

1. Append HwProfileGuid / `set_faketime` protocol definitions; apply the server faketime `.patch`; regenerate protocol headers.
2. Content-insert `winmm` / `version` / `reflex` = `n,b` and default `PROTON_DISABLE_LSTEAMCLIENT=1` into the `proton` launcher script (so natives load without relying on `user_settings.py`).
3. Content-insert an `LD_PRELOAD` entry for `liblinuwux_preload.so` into the `proton` launcher script, appending to (never overwriting) any value already set.
4. Compile `patches/preload/linuwux_preload.c` into `liblinuwux_preload.so` and install it into the redist package.

Wine's own source is never patched for any of the CPUID/SIGSYS/faketime logic — `signal_x86_64.c` stays completely stock. `liblinuwux_preload.so` interposes the libc calls Wine itself makes for signal delivery (`sigaction()`, `prctl()`) and for wineserver communication (`recvmsg()`, `write()`, `writev()`), and wraps around whatever Wine registers at runtime instead of splicing text into Wine's source at build time.

### Runtime

| Stage | What happens |
|-------|----------------|
| Library load | `detect_cpu_vendor()` fills spoof tables |
| First `sigaction(SIGSEGV, ...)` | Interposed; wraps Wine's own handler, then enables `ARCH_SET_CPUID` faulting |
| First `sigaction(SIGSYS, ...)` | Interposed; wraps Wine's own handler |
| First `prctl(PR_SET_SYSCALL_USER_DISPATCH, ...)` | Interposed; learns the per-thread SUD selector's TEB offset from Wine's own real call, instead of guessing struct layout |
| Guest `CPUID` | `linuwux_cpuid_spoof()` rewrites registers (identity leaves + control leaves) |
| Leaf `0x336933` | Arms `TargetSysHandler`, patches `KUSER_SHARED_DATA` |
| Leaf `0x336967` | Wineserver `set_faketime`, via `wine_server_call()` resolved from the already-loaded `ntdll.so` |
| Blocked syscall | `linuwux_sigsys_route()` may redirect into the usermode trampoline |

**Syscall User Dispatch (GE-Proton 11-5+).** These trees replace seccomp+BPF
with Linux's Syscall User Dispatch. Rather than detecting this from the
tree's source at build time, the preload library learns the SUD selector's
TEB offset directly from Wine's own real `prctl()` call at runtime — the
same offset resolves correctly whether or not the tree has SUD support,
since the whole mechanism is a no-op on GE-Proton 11-3 / CachyOS trees that
never make that `prctl()` call in the first place.

**Faketime.** `REQ_set_faketime`'s numeric ID is positionally generated
(depends on every request defined before it in `protocol.def`), so it's
extracted at *build* time from the tree's own generated
`server_protocol.h` and baked into the library via
`-DLINUWUX_REQ_SET_FAKETIME`. `sizeof(union generic_request)` — needed to
lay out a `wine_server_call()` request correctly, and also per-build/version
specific — is learned at *runtime* by observing Wine's own real wineserver
traffic (the first `SCM_RIGHTS` fd-passing `recvmsg()` and the first
`write()`/`writev()` on that fd). `wine_server_call` itself is resolved by
finding `ntdll.so`'s real on-disk path via `/proc/self/maps` and
`dlopen(path, RTLD_NOLOAD)`, since Wine's own module loader loads it
without `RTLD_GLOBAL` — invisible to a plain `dlsym(RTLD_DEFAULT, ...)`.

**SIGSYS redirect scope.** After arm, DenuvOwO's hypervisor only vectors the tracked process. Under Wine we approximate that by **not** handing post-arm SIGSYS faults to `TargetSysHandler` when the fault RIP sits in the Wine system PE band `[0x6FFFFF000000, 0x700000000000)` (typical ntdll/kernel32-class layout on Proton/GE). Game, crack, and other guest RIPs still redirect. Addresses in the Linux high range (`0x7fff…`) are **not** treated as Wine PE — some packs need those redirects.

| Environment | Effect |
|-------------|--------|
| `LINUWUX_DEBUG=1` | Event tracing (arm, KUSER, learned offsets/sizes, faketime sends, actual redirects). Wine-system skips are silent — too frequent to log. |
| `LINUWUX_REDIRECT_ALL=1` | Disable the RIP scope filter; every post-arm SIGSYS redirects (pre-scope behaviour). |
| `PROTON_AVX=1` | AVX/XSAVE in spoofed CPUID/KUSER data |

## Requirements

`git`, `podman` or `docker`, `make`, `sed`, `awk`, `tar`, `patch`, `perl`, `gcc`. `xz` preferred for CachyOS archives. `curl`/`wget` optional (version check).

## Usage

```bash
./build.sh [OPTIONS] [VARIANT] [BRANCH/TAG]
```

| Variant | Source | Default |
|---------|--------|--------|
| `cachyos` (default) | CachyOS/proton-cachyos | latest `cachyos-N.N-YYYYMMDD-slr` **release tag** |
| `ge` | GloriousEggroll/proton-ge-custom | latest `GE-ProtonN-M` tag |

```bash
./build.sh                          # latest CachyOS SLR release tag
./build.sh cachyos cachyos-11.0-20260703-slr
./build.sh cachyos cachyos-11.0-20260703-native
./build.sh ge GE-Proton11-3
./build.sh ge GE-Proton11-5
./build.sh --force --no-clean cachyos
./build.sh --update-patches
```

Pass any explicit branch or tag after the variant to override auto-resolution (including `cachyos_*/main` development branches if you really need them).

| Flag | Effect |
|------|--------|
| `-f`, `--force` | Full re-clone and clean rebuild |
| `-k`, `--no-clean` | Keep `-src`/`-build` after success |
| `--update-patches` | Re-clone `patches/` from this repo |
| `--container-engine=<name>` | Default `podman` |
| `-h`, `--help` | Help |

| Environment | Effect |
|-------------|--------|
| `PATCH_BRANCH=<name>` | Branch for patch clone when `patches/` is missing |
| `LINUWUX_DEBUG=1` | Runtime event tracing |
| `LINUWUX_REDIRECT_ALL=1` | Disable SIGSYS Wine-PE scope filter |
| `PROTON_AVX=1` | AVX/XSAVE in spoofed CPUID/KUSER data |

## Output

```
dist/<version>-LinUwUx.tar.xz   # CachyOS when xz is available
dist/<version>-LinUwUx.tar.gz   # GE, or no xz
```

```bash
mkdir -p ~/.steam/root/compatibilitytools.d/<name>
tar -xf dist/<archive> -C ~/.steam/root/compatibilitytools.d/<name> --strip-components=1
```

Restart Steam and select the tool under the game's *Compatibility* settings.

## Behaviour notes

- Host-side, fail-loud inserts and patches; unified log under `logs/<version>/linuwux-patches.log`.
- Local `patches/` is reused unless `--update-patches`.
- Success leaves only the tarball in `dist/`; failure keeps trees for debugging.
- Startup version check is warn-only (never aborts the build).
- CachyOS defaults to a **published release tag** (`cachyos-*-slr`), not the newest development branch, so submodule pins match a known-good release.
- Native `winmm` / `version` / `reflex` overrides and `PROTON_DISABLE_LSTEAMCLIENT` are baked into the `proton` script at build time (no `user_settings.py`).

## License

This project is free software under the [GNU Affero General Public License v3](LICENSE)
(or, at your option, any later version).

Copyright (C) 2026 brcly.

- Upstream **Proton**, **Wine**, **CachyOS**, and **GE** sources retain their
  own licenses (typically LGPL). This repository's scripts and patches
  are AGPL-3.0; combining them with upstream trees does not relicense Valve's
  or Wine's code.

Please keep copyright notices intact when you redistribute or modify this work.
Preferred credit line for derived builds:

`LinUwUx Proton builder by brcly (https://github.com/brcly/proton-LinUwUx-patch)`

## Credits
- LinUwUx - Original Bypass creator
- DenuvOwO - Hypervisor Bypass
- [Kurt Himebauch](https://github.com/xXJSONDeruloXx) - Legacy Reflex Fix (historical; the dual-trampoline protocol this covered is no longer carried by the current LD_PRELOAD-based design)
