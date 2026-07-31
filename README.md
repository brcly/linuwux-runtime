# Proton + LinUwUx Builder

A carefully structured Bash build system that builds **proton-cachyos** or **proton-ge-custom** from source with the **LinUwUx** patch set applied, then packages a ready-to-install Steam Play compatibility tool.

Other projects offer pre-built tarballs. This one gives you a reproducible, maintainable *build system* so you can generate the latest patched Proton yourself whenever upstream moves — without waiting for someone else to upload a release.

## Layout

```
build.sh                 # thin orchestrator
lib/
  common.sh              # logging, insert helpers
  source.sh              # clone, submodules, patch staging
  apply-content.sh       # content-based inserts (patches/base/)
  apply-patches.sh       # traditional .patch apply + GE protonprep
  package.sh             # user_settings, configure, redist, verify
patches/
  base/                  # additive .c / .reg / .protocol fragments
  wine/                  # remaining traditional .patch files
  legacy-reflex/base/    # optional --legacy-reflex overlays
  overrides/<key>/wine/  # version-specific full replacements
```

## Why this structure is different (and better)

Most LinUwUx Proton repos simply ship pre-patched binaries. That's convenient for "download and go", but it doesn't scale and it hides how the patches were applied.

This project is built differently on purpose:

- **Version-isolated trees** — every branch/tag gets its own `-src` / `-build` / `logs/` directories. Multiple builds never clobber each other. `--legacy-reflex` adds a `-Legacy-Reflex` suffix so normal and legacy builds never share trees.
- **Host-side, fail-loud patching** — LinUwUx changes are applied *before* the container ever sees the tree. If an insert, `.patch`, or `Makefile.in` anchor fails, the build stops.
- **Content-based inserts for additive code** — CPUID defs, KUSER patch, segv/SIGSYS handlers, and `signal_init` hooks live under `patches/base/` as plain fragments and are injected by stable anchors (not fragile context diffs). Large upstream rearrangements are less likely to break the build.
- **Modular scripts** — logic lives under `lib/` so each concern stays small and reviewable; `build.sh` only orchestrates.
- **Unified patch log** — console messages from content inserts and traditional `.patch` applies both land in `logs/<version>/linuwux-patches.log`.
- **Clean layering** — LinUwUx sits *on top of* upstream (GE's `protonprep` or CachyOS's already-patched wine-cachyos fork).
- **Version-specific overrides** — drop a complete set under `patches/overrides/<branch-or-tag>/wine/` and it fully replaces the common set for that version.
- **Local patch iteration** — the `patches/` folder is preferred over a fresh clone. Edit, re-run with `--no-clean`, iterate. Pass `--update-patches` only when you want upstream again.
- **Live latest resolution** — no branch/tag given? It queries the remote for the newest `cachyos_*/main` or `GE-ProtonN-M` tag.
- **Self-updating awareness** — the script checks its own version against GitHub (warns instead of dying when you intentionally build from a non-`main` `PATCH_BRANCH`).
- **Proper packaging of `user_settings.py`** — wired into the redist via targeted `Makefile.in` edits that die if the anchors move upstream.
- **Clean on success, keep on failure** — successful builds leave only the tarball in `dist/`. Failed builds leave the trees for debugging. `--no-clean` for a fast patch-dev loop.

You still get pre-built releases for convenience, but the primary deliverable is the builder itself.

## CURRENTLY ONLY PROTON V11 IS SUPPORTED.

---

## What it produces

```
dist/<version>-LinUwUx.tar.xz                    # CachyOS (xz when available)
dist/<version>-LinUwUx.tar.gz                    # GE, or when xz is unavailable
dist/<version>-LinUwUx-Legacy-Reflex.tar.{xz,gz} # only with --legacy-reflex
```

Install into Steam:

```bash
mkdir -p ~/.steam/root/compatibilitytools.d/<version>-LinUwUx
tar -xf dist/<version>-LinUwUx.tar.xz \
    -C ~/.steam/root/compatibilitytools.d/<version>-LinUwUx --strip-components=1
```

Then restart Steam and pick the tool under a game's *Compatibility* settings.

---

## What the patches do

LinUwUx is a set of ntdll/server hooks that make Wine look more like a “normal” Windows box to anti-cheat and games that fingerprint the environment. The pieces work together:

### CPUID spoofing

Games (and some anti-cheats) call `CPUID` to fingerprint the host CPU. With `ARCH_SET_CPUID` faulting enabled, those instructions trap into `segv_handler`, where we rewrite the returned registers before the guest continues.

| Piece | What it does |
|-------|----------------|
| `cpuid_spoof_defs.c` | Declares spoof tables + `TargetSysHandler`, and `detect_cpu_vendor()` which picks Intel- or AMD-shaped leaf values at process start (optional AVX via `PROTON_AVX=1`). |
| `signal_init_process_hooks.c` | After SIGSEGV is registered: run `detect_cpu_vendor()`, then `ARCH_SET_CPUID = 0` so guest `CPUID` faults into our handler. |
| `cpuid_spoof_handler.c` | In `segv_handler`, after the steamclient trampoline local: intercept real `CPUID` (`0F A2`). Spoofs leaf 1 / hypervisor leaves / brand string; special leaves `0x336933` (arm syscall routing + patch KUSER) and `0x336967` (set server faketime). Unhandled leaves briefly re-enable real CPUID, execute, then fault again. |

Result: the guest sees a consistent Windows-on-bare-metal style CPU identity instead of a hypervisor / Wine-telltale signature.

### Syscall routing (SIGSYS)

Once the game’s own trampoline is registered via the special CPUID leaf, blocked or interesting syscalls can be redirected into that guest code instead of Wine’s normal path.

| Piece | What it does |
|-------|----------------|
| `sigsys_handler.c` | In the **Linux / `HAVE_SECCOMP`** `sigsys_handler` only: if `TargetSysHandler` is set and the XMM “bypass magic” is not active, rewrite RIP/RCX to the game trampoline and return. Clears the magic marker when present. The Apple `sigsys_handler` is never touched. |

`TargetSysHandler` is filled when the guest issues CPUID leaf `0x336933` (see handler above).

### KUSER_SHARED_DATA hardening

Windows exposes a fixed page at `0x7FFE0000` (`KUSER_SHARED_DATA`) that many games read for OS version, features, and system root. We overwrite the important fields so those probes stay stable.

| Piece | What it does |
|-------|----------------|
| `kuser_shared_data_patch.c` | `patch_kuser_shared_data()`: `mprotect` the page, force `NtSystemRoot` to `C:\Windows`, write a fixed feature/version layout, and clear noisy bits (MONITORX, RDTSCP, RDPID, RDRAND; AVX/XSAVE unless `PROTON_AVX=1`). Called from the `0x336933` path. |

### Hardware profile GUID

| Piece | What it does |
|-------|----------------|
| `hwprofile_guid.reg` | Appends a fixed `HwProfileGuid` under the hardware profile key in `wine.inf.in`, so installs that key off the GUID always see the same value. |

### Faketime

Some titles / anti-cheats care about wall-clock consistency. LinUwUx can push a faketime into the wineserver.

| Piece | What it does |
|-------|----------------|
| `set_faketime.protocol` | Adds the `@REQ(set_faketime)` request definition so clients can talk to the server. |
| `server/0001-apply_faketime.patch` | Server-side implementation of that request (the one remaining traditional `.patch`). |
| CPUID leaf `0x336967` (in the handler) | Guest path that issues `SERVER_START_REQ(set_faketime)` with the desired timestamp. |

### Proton user settings shipped in the redist

| Piece | What it does |
|-------|----------------|
| `user_settings.py` | Default overrides: `winmm` / `version` / `reflex` native,buitin, and `PROTON_DISABLE_LSTEAMCLIENT=1`. Wired into the package via `Makefile.in` so every build ships them. |

### Optional legacy Reflex (`--legacy-reflex`)

Extra protocol for older Reflex-style flows. Isolated build flavor (`-Legacy-Reflex` trees and package name):

| File | Role |
|------|------|
| `cpuid_legacy_reflex_defs.c` | Legacy handler globals + legacy KUSER patch helper |
| `cpuid_legacy_reflex_handler.c` | Alternate CPUID handler body (same insert marker / contract) |
| `legacy_reflex_sigsys_handler.c` | Extra SIGSYS routing layered on the common `TargetSysHandler` block |

Normal builds never include these paths.

> Valve's official Proton is intentionally **not** supported (debugger-detection issues).
> Use `cachyos` or `ge`.

---

## Requirements

`git`, a container engine (`podman` by default, or `docker`), `make`, `sed`, `awk`,
`tar`, and `patch`. `xz` is used for CachyOS output when present. `curl` or `wget`
is used for the startup version check (optional — if neither is present, or you're
offline, that check is skipped).

---

## Usage

```bash
./build.sh [OPTIONS] [VARIANT] [BRANCH/TAG]
```

### Variants

| Variant             | Source                           | Default branch/tag                                   |
|---------------------|----------------------------------|------------------------------------------------------|
| `cachyos` (default) | CachyOS/proton-cachyos           | latest `cachyos_*/main` (resolved live)              |
| `ge`                | GloriousEggroll/proton-ge-custom | latest `GE-ProtonN-M` tag (resolved live → `master`) |

### Examples

```bash
./build.sh                          # latest CachyOS
./build.sh cachyos <branch>         # a specific CachyOS branch
./build.sh ge                       # latest GE
./build.sh ge GE-Proton11-3         # a specific GE tag
./build.sh --legacy-reflex ge GE-Proton11-3
./build.sh --container-engine=docker ge
./build.sh --update-patches         # force a fresh clone of patches/
PATCH_BRANCH=dev/content-based-handler ./build.sh --update-patches
```

### Options

| Flag                        | Effect                                                    |
|-----------------------------|-----------------------------------------------------------|
| `-f`, `--force`             | Force a full re-clone and clean rebuild.                  |
| `-k`, `--no-clean`          | Keep the `-src`/`-build` trees after a successful build.  |
| `--legacy-reflex`           | Build an isolated legacy Reflex compatibility variant.    |
| `--update-patches`          | Delete and re-clone the `patches/` folder from upstream.  |
| `--container-engine=<name>` | Container engine to build with (default: `podman`).       |
| `-h`, `--help`              | Show help.                                                |

### Environment

| Variable | Effect |
|----------|--------|
| `SLOW=1` | Restore the 1.2s pauses between steps (off by default). |
| `PATCH_BRANCH=<name>` | Branch of this repo to clone when `patches/` is missing (default: `main`). |
| `PROTON_AVX=1` | At runtime in the built Proton: include AVX/XSAVE in spoofed CPUID / KUSER features. |

---

## How it works

1. **Obtain LinUwUx patches** — reuses local `patches/` if present, otherwise clones `PATCH_BRANCH` from the patch repo.
2. **Resolve version & clone/reuse source** — version id (+ optional `-Legacy-Reflex` flavor).
3. **Update submodules** — recursive; deinit + re-init on `--force`.
4. **Install patch files** — stage `patches/wine` (or a version override).
5. **Apply content inserts + `.patch`es** — host-side, fail-loud; regenerate server protocol. `--legacy-reflex` swaps the CPUID handler and adds legacy defs/SIGSYS overlay.
6. **Install `user_settings.py`** and verify required base (and legacy) files.
7. **Wire `user_settings.py` into `Makefile.in`**.
8. **Configure & build** — `configure.sh` + `make redist`.
9. **Package & verify** — archive must contain `user_settings.py` and core files.
10. **Move to `dist/` & clean up** unless `--no-clean`.

---

## Behaviour notes

- **Content inserts prefer stable anchors** (`#include "dwarf.h"`, `void *steamclient_addr = NULL`, `sigaction(SIGSEGV, …)`, seccomp `0xffff` test inside Linux `sigsys_handler`).
- **Idempotent markers** — e.g. `/* linuwux-cpuid-handler */`, `/* linuwux-sigsys-handler */` so re-runs skip already-applied inserts.
- **SIGSYS targets Linux only** — the Apple `sigsys_handler` is never touched.
- **LinUwUx layers on top of upstream** — CachyOS wine patches come pre-applied; GE's via `protonprep`.
- **Logs** — `logs/<version>/` holds `build.log`, `linuwux-patches.log`, and `prep.log` (GE).
