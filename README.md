# Proton + LinUwUx Builder

Build **proton-cachyos** or **proton-ge-custom** from source with the **LinUwUx** patch set applied, and package a Steam Play compatibility tool.

Other projects ship pre-built tarballs or apply a pre-made `.patch` file to Wine, which can be volatile if Proton/Wine updates and shifts layout (for example Proton/Wine 10 → 11). This one is a reproducible *builder*: regenerate the latest patched Proton yourself when upstream moves, using an external hook file and minimal Wine intrusions, improving the chance of cross-version compatibility.

This build script restructures LinUwUx’s original patch code. Whether that is better or worse is up to you; it does not claim to be superior, only clearer to maintain. Functionality of the DenuvOwO HV bypass is unchanged (plus optional QoL for older Reflex via `--legacy-reflex`). If the patch logic needs updating, edit `patches/base/linuwux_hooks.c` in one place.

This project does **not** configure host-side requirements for the bypass (UMIP, HV DKMS, etc.). It only builds patched Proton. See [cs.rin.ru](https://csrin.org) for those instructions.

**Proton 11 only** (for now). Valve’s official Proton is not supported.

## Layout

```
build.sh                 # orchestrator
lib/
  common.sh              # logging, line-insert helpers
  source.sh              # clone, submodules, stage patches/wine
  apply-content.sh       # content inserts + hooks install
  apply-patches.sh       # traditional .patch apply + GE protonprep
  apply-proton-dll.sh    # winmm/version/reflex + lsteamclient defaults
  package.sh             # base checks, configure, redist, verify
patches/
  base/
    linuwux_hooks.c      # modern ntdll unix hooks (bulk logic)
    hwprofile_guid.reg
    set_faketime.protocol
  legacy-reflex/
    linuwux_hooks_legacy.c   # same API; used only with --legacy-reflex
  wine/
    server/0001-apply_faketime.patch
```

## How LinUwUx is applied

The script runs these steps automatically:

1. Copy `linuwux_hooks.c` (or `linuwux_hooks_legacy.c`) into `dlls/ntdll/unix/` as `linuwux_hooks.c`.
2. `#include "linuwux_hooks.c"` into `signal_x86_64.c` (before Linux `sigsys_handler`, after `REG_*` macros).
3. Inject tiny call stubs into `segv_handler`, Linux `sigsys_handler`, and `signal_init_process`.
4. Append HwProfileGuid / `set_faketime` protocol definitions; apply the server faketime `.patch`; regenerate protocol headers.
5. Content-insert `winmm` / `version` / `reflex` = `n,b` and default `PROTON_DISABLE_LSTEAMCLIENT=1` into the `proton` launcher script (so natives load without relying on `user_settings.py`).

The signal file stays almost stock. All bulk logic lives in one hooks file you can edit without fighting context diffs.

### Runtime (modern hooks)

| Stage | What happens |
|-------|----------------|
| Process init | `detect_cpu_vendor()` fills spoof tables; `ARCH_SET_CPUID` makes guest `CPUID` fault |
| Guest `CPUID` | `linuwux_cpuid_spoof()` rewrites registers (identity leaves + control leaves) |
| Leaf `0x336933` | Arms `TargetSysHandler`, patches `KUSER_SHARED_DATA` |
| Leaf `0x336967` | Wineserver `set_faketime` |
| Blocked syscall | `linuwux_sigsys_route()` may redirect into the usermode trampoline |

**SIGSYS redirect scope.** After arm, DenuvOwO’s hypervisor only vectors the tracked process. Under Wine we approximate that by **not** handing post-arm SIGSYS faults to `TargetSysHandler` when the fault RIP sits in the Wine system PE band `[0x6FFFFF000000, 0x700000000000)` (typical ntdll/kernel32-class layout on Proton/GE). Game, crack, and other guest RIPs still redirect. Addresses in the Linux high range (`0x7fff…`) are **not** treated as Wine PE — some packs need those redirects.

| Environment | Effect |
|-------------|--------|
| `LINUWUX_DEBUG=1` | Hook tracing (arm, KUSER, actual redirects). Wine-system skips are silent — too frequent to log. |
| `LINUWUX_REDIRECT_ALL=1` | Disable the RIP scope filter; every post-arm SIGSYS redirects (pre-scope behaviour). |
| `PROTON_AVX=1` | AVX/XSAVE in spoofed CPUID/KUSER |

### `--legacy-reflex`

Uses `linuwux_hooks_legacy.c` instead of the modern file (same symbols, same stubs). Adds the older dual-trampoline protocol and alternate KUSER profile for some older Reflex builds. Output trees/packages get a `-Legacy-Reflex` suffix. When that support is no longer needed, delete `patches/legacy-reflex/` and the flag.

## Requirements

`git`, `podman` or `docker`, `make`, `sed`, `awk`, `tar`, `patch`, `perl`. `xz` preferred for CachyOS archives. `curl`/`wget` optional (version check).

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
./build.sh --legacy-reflex ge GE-Proton11-3
./build.sh --force --no-clean cachyos
./build.sh --update-patches
```

Pass any explicit branch or tag after the variant to override auto-resolution (including `cachyos_*/main` development branches if you really need them).

| Flag | Effect |
|------|--------|
| `-f`, `--force` | Full re-clone and clean rebuild |
| `-k`, `--no-clean` | Keep `-src`/`-build` after success |
| `--legacy-reflex` | Install `linuwux_hooks_legacy.c` |
| `--update-patches` | Re-clone `patches/` from this repo |
| `--container-engine=<name>` | Default `podman` |
| `-h`, `--help` | Help |

| Environment | Effect |
|-------------|--------|
| `PATCH_BRANCH=<name>` | Branch for patch clone when `patches/` is missing |
| `LINUWUX_DEBUG=1` | Runtime hook tracing |
| `LINUWUX_REDIRECT_ALL=1` | Disable SIGSYS Wine-PE scope filter |
| `PROTON_AVX=1` | AVX/XSAVE in spoofed CPUID/KUSER |

## Output

```
dist/<version>-LinUwUx.tar.xz                    # CachyOS when xz is available
dist/<version>-LinUwUx.tar.gz                    # GE, or no xz
dist/<version>-LinUwUx-Legacy-Reflex.tar.{xz,gz} # with --legacy-reflex
```

```bash
mkdir -p ~/.steam/root/compatibilitytools.d/<name>
tar -xf dist/<archive> -C ~/.steam/root/compatibilitytools.d/<name> --strip-components=1
```

Restart Steam and select the tool under the game’s *Compatibility* settings.

## Behaviour notes

- Host-side, fail-loud inserts and patches; unified log under `logs/<version>/linuwux-patches.log`.
- Local `patches/` is reused unless `--update-patches`.
- Success leaves only the tarball in `dist/`; failure keeps trees for debugging.
- SIGSYS stubs target Linux/`HAVE_SECCOMP` only (Apple handler untouched).
- Startup version check is warn-only (never aborts the build).
- CachyOS defaults to a **published release tag** (`cachyos-*-slr`), not the newest development branch, so submodule pins match a known-good release.
- Native `winmm` / `version` / `reflex` overrides and `PROTON_DISABLE_LSTEAMCLIENT` are baked into the `proton` script at build time (no `user_settings.py`).

## License

This project is free software under the [GNU Affero General Public License v3](LICENSE)
(or, at your option, any later version).

Copyright (C) 2026 brcly, except where noted below.

- `patches/legacy-reflex/linuwux_hooks_legacy.c` — primarily authored by
  **Kurt Himebauch** ([xXJSONDeruloXx](https://github.com/xXJSONDeruloXx));
  copyright held by Kurt Himebauch, with repository integration by brcly.
- Upstream **Proton**, **Wine**, **CachyOS**, and **GE** sources retain their
  own licenses (typically LGPL). This repository’s scripts, hooks, and patches
  are AGPL-3.0; combining them with upstream trees does not relicense Valve’s
  or Wine’s code.

Please keep copyright notices intact when you redistribute or modify this work.
Preferred credit line for derived builds:

`LinUwUx Proton builder by brcly (https://github.com/brcly/proton-LinUwUx-patch)`

## Credits
- LinUwUx - Original Bypass creator
- DenuvOwO - Hypervisor Bypass
- [Kurt Himebauch](https://github.com/xXJSONDeruloXx) - Legacy Reflex Fix
