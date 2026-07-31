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

LinUwUx is a set of ntdll/server hooks that make Wine look more like a “normal” Windows box to anti-cheat and games that fingerprint the environment. The pieces work together at runtime roughly like this:

1. Process start → `detect_cpu_vendor()` fills spoof tables; `ARCH_SET_CPUID` makes guest `CPUID` fault.
2. Guest `CPUID` → `segv_handler` rewrites registers (identity spoof, or special control leaves).
3. Special leaf arms a trampoline address and patches `KUSER_SHARED_DATA`.
4. Later blocked syscalls → `sigsys_handler` can redirect into that trampoline.

### File / symbol inventory (`patches/base/`)

#### `cpuid_spoof_defs.c` (file-scope insert)

| Symbol | Kind | Purpose |
|--------|------|--------|
| `TargetSysHandler` | `uint64_t` global | Guest trampoline address for syscall redirection; set by CPUID leaf `0x336933`. |
| `SyscallBypassMagic` | `uint64_t` global | `0x1337133713371337` — magic used with XMM state so selected paths can bypass trampoline routing. |
| `spoof_leaf1_*` | `unsigned int` globals | Spoofed EAX/EBX/ECX/EDX for CPUID leaf 1. |
| `spoof_leaf40000000_*` | globals | Spoofed hypervisor leaf `0x40000000` (vendor-shaped strings). |
| `spoof_leaf40000001_*` | globals | Spoofed hypervisor leaf `0x40000001`. |
| `detect_cpu_vendor()` | `static void` | Runs once at init: real CPUID(0), then fills the spoof tables for GenuineIntel or AuthenticAMD. Honours `PROTON_AVX=1` for AVX-capable feature bits. |

#### `kuser_shared_data_patch.c` (file-scope insert)

| Symbol | Kind | Purpose |
|--------|------|--------|
| `patch_kuser_shared_data()` | `static void` | `mprotect`s `0x7FFE0000`, forces `NtSystemRoot` to `C:\Windows`, writes a fixed OS/feature layout, clears MONITORX / RDTSCP / RDPID / RDRAND (and AVX/XSAVE unless `PROTON_AVX=1`). Called from the `0x336933` handler path. |

#### `signal_init_process_hooks.c` (insert after SIGSEGV registration)

Not a named function file — two statements injected into `signal_init_process`:

| Statement | Purpose |
|-----------|--------|
| `detect_cpu_vendor();` | Fill spoof tables before any guest code runs. |
| `syscall(SYS_arch_prctl, ARCH_SET_CPUID, 0);` | Enable CPUID faulting so guest `CPUID` enters `segv_handler`. |

#### `cpuid_spoof_handler.c` (insert inside `segv_handler`)

Marked `/* linuwux-cpuid-handler */`. Intercepts real `CPUID` (`0F A2`) when `si_code == SI_KERNEL` or leaf is the control leaf:

| Leaf | Behaviour |
|------|-----------|
| `1` | Return spoofed leaf-1 registers; sets hypervisor bit in ECX unless `TargetSysHandler` is already armed. |
| `0x40000000` / `0x40000001` | Return spoofed hypervisor vendor / interface leaves. |
| `0x80000002`–`0x80000004` | Spoofed processor brand string. |
| `0x336933` | Register `TargetSysHandler` from RCX, call `patch_kuser_shared_data()`, zero result regs. |
| `0x336967` | `SERVER_START_REQ(set_faketime)` with RCX as timestamp. |
| default | Briefly `ARCH_SET_CPUID=1`, execute real CPUID, re-enable faulting. |

Always advances RIP by 2 (skip the `CPUID` opcode) and returns from the signal handler.

#### `sigsys_handler.c` (insert inside Linux `sigsys_handler` only)

Marked `/* linuwux-sigsys-handler */`:

| Logic | Purpose |
|-------|--------|
| If `TargetSysHandler != 0` and XMM[5] low half ≠ bypass magic | Save syscall id into XMM[4], set RAX←RCX, RCX/RIP←`TargetSysHandler`, return — guest trampoline handles the call. |
| If XMM[5] holds the bypass magic | Clear XMM[5] (one-shot bypass). |

Anchored on the seccomp `0xffff` self-test so the Apple `sigsys_handler` is never modified.

#### `hwprofile_guid.reg`

Appends a fixed `HwProfileGuid` under
`HKLM\System\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001`
in `wine.inf.in`, so software that keys off that GUID always sees the same value.

#### `set_faketime.protocol`

Adds the wineserver request definition:

```text
@REQ(set_faketime)
    timeout_t faketime;
@REPLY
@END
```

Paired with `patches/wine/server/0001-apply_faketime.patch` (server implementation) and the `0x336967` guest path above.

#### `user_settings.py`

Shipped in every redist via `Makefile.in` wiring:

```python
user_settings = {
    "WINEDLLOVERRIDES": "winmm=n,b;version=n,b;reflex=n,b",
    "PROTON_DISABLE_LSTEAMCLIENT": "1",
}
```

### Traditional `.patch` (`patches/wine/`)

| File | Purpose |
|------|--------|
| `server/0001-apply_faketime.patch` | Implements `set_faketime` inside wineserver so the protocol request actually changes server time. |

### Optional legacy Reflex (`--legacy-reflex`)

Compared to a normal build, this flag mainly changes:

- **Isolated output** — source/build/log trees and the package name get a `-Legacy-Reflex` suffix so they never collide with a normal build of the same Proton version.
- **Different CPUID handler** — uses the legacy Reflex body instead of the modern one (extra control leaves to arm the protocol and register two syscall trampolines).
- **Extra SIGSYS routing** — after the protocol is armed, matching syscalls can be redirected to those legacy trampolines *before* the normal `TargetSysHandler` path runs.
- **Alternate KUSER profile** — once armed, a separate legacy KUSER write path can be triggered (SimpleSvm-style layout) instead of only the modern `patch_kuser_shared_data()`.

Everything else (CPUID identity spoof tables, faketime, HwProfileGuid, `user_settings.py`, server faketime patch) stays the same. Normal builds never include the legacy fragments.

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
