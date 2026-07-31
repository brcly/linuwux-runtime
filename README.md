# Proton + LinUwUx Builder

A single, carefully structured Bash script (`build.sh`) that builds **proton-cachyos** or **proton-ge-custom** from source with the **LinUwUx** patch set applied, then packages a ready-to-install Steam Play compatibility tool.

Other projects offer pre-built tarballs. This one gives you a reproducible, maintainable *build system* so you can generate the latest patched Proton yourself whenever upstream moves — without waiting for someone else to upload a release.

## Why this structure is different (and better)

Most LinUwUx Proton repos simply ship pre-patched binaries. That's convenient for "download and go", but it doesn't scale and it hides how the patches were applied.

This project is built differently on purpose:

- **Version-isolated trees** — every branch/tag gets its own `-src` / `-build` / `logs/` directories. Multiple builds never clobber each other. `--legacy-reflex` adds a `-Legacy-Reflex` suffix so normal and legacy builds never share trees.
- **Host-side, fail-loud patching** — LinUwUx changes are applied *before* the container ever sees the tree. If an insert, `.patch`, or `Makefile.in` anchor fails, the build stops.
- **Content-based inserts for additive code** — CPUID defs, KUSER patch, handler body, and `signal_init` hooks live under `patches/base/` as plain `.c` fragments and are injected by stable anchors (not fragile context diffs). Large upstream rearrangements are less likely to break the build.
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

### Content inserts (`patches/base/`)

| File | Role |
|------|------|
| `hwprofile_guid.reg` | Stable HwProfileGuid line appended to `wine.inf.in` |
| `set_faketime.protocol` | `@REQ(set_faketime)` appended to `server/protocol.def` |
| `cpuid_spoof_defs.c` | Globals + `detect_cpu_vendor()` at file scope |
| `kuser_shared_data_patch.c` | `patch_kuser_shared_data()` at file scope |
| `cpuid_spoof_handler.c` | CPUID spoof body inserted after `steamclient_addr` in `segv_handler` |
| `signal_init_process_hooks.c` | `detect_cpu_vendor()` + `ARCH_SET_CPUID` after SIGSEGV registration |
| `user_settings.py` | Shipped in the redist (`winmm`/`version`/`reflex` overrides, etc.) |

### Traditional `.patch` files (`patches/wine/`)

- `dlls/ntdll/unix/0001-sigsys_handler.patch` — SIGSYS routing for `TargetSysHandler`
- `server/0001-apply_faketime.patch` — server-side faketime handling

### Optional legacy Reflex (`--legacy-reflex`)

Content under `patches/legacy-reflex/base/`:

| File | Role |
|------|------|
| `cpuid_legacy_reflex_defs.c` | Legacy handler globals + `patch_legacy_kuser_shared_data()` |
| `cpuid_legacy_reflex_handler.c` | Alternate CPUID handler (same insert contract / marker) |
| `legacy_reflex_sigsys_handler.c` | Extra SIGSYS routing when legacy protocol is active |

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

- **Content inserts prefer stable anchors** (`#include "dwarf.h"`, `void *steamclient_addr = NULL`, `sigaction(SIGSEGV, …)`).
- **Idempotent markers** — e.g. `/* linuwux-cpuid-handler */` so re-runs skip already-applied inserts.
- **LinUwUx layers on top of upstream** — CachyOS wine patches come pre-applied; GE's via `protonprep`.
- **Logs** — `logs/<version>/` holds `build.log`, `linuwux-patches.log`, and `prep.log` (GE).
