# Proton + LinUwUx Builder

A single, carefully structured Bash script (`build.sh`) that builds **proton-cachyos** or **proton-ge-custom** from source with the **LinUwUx** patch set applied, then packages a ready-to-install Steam Play compatibility tool.

Other projects offer pre-built tarballs. This one gives you a reproducible, maintainable *build system* so you can generate the latest patched Proton yourself whenever upstream moves — without waiting for someone else to upload a release.

## Why this structure is different (and better)

Most LinUwUx Proton repos simply ship pre-patched binaries. That’s convenient for “download and go”, but it doesn’t scale and it hides how the patches were applied.

This project is built differently on purpose:

- **Version-isolated trees** — every branch/tag gets its own `-src` / `-build` / `logs/` directories. Multiple builds never clobber each other.
- **Host-side, fail-loud patching** — LinUwUx patches are applied *before* the container ever sees the tree. If a patch or a required `Makefile.in` anchor fails, the build stops. You never ship a silently broken Proton.
- **Clean layering** — LinUwUx is applied *on top of* upstream (GE’s `protonprep` or CachyOS’s already-patched wine-cachyos fork). We don’t replace their work.
- **Version-specific overrides** — drop a complete set under `patches/overrides/<branch-or-tag>/wine/` and it fully replaces the common set for that version. Perfect for when a new Proton needs adjusted context.
- **Local patch iteration** — the `patches/` folder is preferred over a fresh clone. Edit, re-run with `--no-clean`, iterate. Pass `--update-patches` only when you want upstream again.
- **Live latest resolution** — no branch/tag given? It queries the remote for the newest `cachyos_*/main` or `GE-ProtonN-M` tag.
- **Self-updating awareness** — the script checks its own version against GitHub and refuses to run if you’re on an outdated copy (offline builds still work).
- **Proper packaging of `user_settings.py`** — the real file (not just the sample) is wired into the redist via targeted `Makefile.in` edits that die if the anchors move upstream.
- **Clean on success, keep on failure** — successful builds leave only the tarball in `dist/`. Failed builds leave the trees for debugging. `--no-clean` for a fast patch-dev loop.

You still get pre-built releases for convenience, but the primary deliverable is the builder itself.

## CURRENTLY ONLY PROTON V11 IS SUPPORTED.

---

## What it produces

A compressed redistributable in `dist/`:

```
dist/<version>-LinUwUx.tar.xz      # CachyOS (xz when available)
dist/<version>-LinUwUx.tar.gz      # GE, or when xz is unavailable
```

Install it into Steam:

```bash
mkdir -p ~/.steam/root/compatibilitytools.d/<version>-LinUwUx
tar -xf dist/<version>-LinUwUx.tar.xz \
    -C ~/.steam/root/compatibilitytools.d/<version>-LinUwUx --strip-components=1
```

Then restart Steam and pick the tool under a game's *Compatibility* settings.

---

## What the patches do

The LinUwUx set layers three targeted additive changes onto Wine, plus a set of `.patch` files:

- **HwProfileGuid** — adds a stable hardware-profile GUID to the registry
  (`wine.inf.in`) so the guest presents a consistent machine identity.
  Content lives in `patches/base/hwprofile_guid.reg`.
- **faketime request** — adds a `set_faketime` request to the Wine server protocol
  (`protocol.def`), used to spoof the reported time.
  Content lives in `patches/base/set_faketime.protocol`.
- **CPUID spoofing** — injects `cpuid_spoof_defs.c` into the ntdll unix signal handler
  and adds handling for CPUID leaf `0x336933`, so the guest sees a spoofed CPU identity.

A `user_settings.py` — supplied in the patch repo at `patches/base/` — is copied into
the redist, typically setting `winmm`/`version`/`reflex` DLL overrides and
`PROTON_DISABLE_LSTEAMCLIENT=1`. The build fails if that file is missing.

The patch repo is expected to provide these required files under `patches/base/`:

- `user_settings.py`
- `cpuid_spoof_defs.c`
- `hwprofile_guid.reg`
- `set_faketime.protocol`

plus the common `patches/wine/` set, and optionally
`patches/overrides/<branch-or-tag>/wine/` for version-specific patch sets.

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
./build.sh --container-engine=docker ge
./build.sh --update-patches         # force a fresh clone of patches/
```

### Options

| Flag                        | Effect                                                    |
|-----------------------------|-----------------------------------------------------------|
| `-f`, `--force`             | Force a full re-clone and clean rebuild.                  |
| `-k`, `--no-clean`          | Keep the `-src`/`-build` trees after a successful build.  |
| `--update-patches`          | Delete and re-clone the `patches/` folder from upstream.  |
| `--container-engine=<name>` | Container engine to build with (default: `podman`).       |
| `-h`, `--help`              | Show help.                                                |

### Environment

| Variable | Effect                                                     |
|----------|------------------------------------------------------------|
| `SLOW=1` | Restore the 1.2s pauses between steps (off by default).    |

---

## How it works

The script runs a preflight (dependency + free-space checks and a startup version
check — see Behaviour notes), then a numbered pipeline:

1. **Obtain LinUwUx patches** — reuses the local `patches/` folder if present,
   otherwise clones the patch repo. Pass `--update-patches` to force a fresh clone.
2. **Resolve version & clone/reuse source** — derives a version id from the branch/tag,
   then clones the Proton source (or reuses an existing tree unless `--force`).
3. **Update submodules** — recursive and tree-filtered (Wine, DXVK, etc.); deinit +
   re-init on `--force`.
4. **Install patch files** — populates a fresh `patches/wine` staging directory in the
   source tree from your LinUwUx repo: the common `wine` set, or a version-specific
   `overrides/<branch>/wine` set if one exists.
5. **Apply the patches** — applies the three targeted fixes (HwProfileGuid, faketime
   request, CPUID definitions) and the `.patch` set on the host, then regenerates the
   Wine server protocol. For GE, `protonprep` runs first so LinUwUx layers on top; for
   CachyOS the staged `.patch` files are removed afterward as cleanup.
6. **Install `user_settings.py`** — copies `patches/base/user_settings.py` into the
   source tree; the build stops with an error if any of the required base files are missing.
7. **Wire `user_settings.py` into the package** — patches `Makefile.in` so the file
   ships in the redist, and fails loudly if the expected anchors have moved upstream.
8. **Configure & build** — runs `configure.sh` (ccache enabled for CachyOS) and
   `make redist` inside the container.
9. **Package & verify** — finds or creates the `*-LinUwUx.*` archive, then fails the
   build if `user_settings.py` or the core `proton`/`version` files are missing (and
   warns on a suspiciously small archive).
10. **Move to `dist/` & clean up** — moves the tarball to `dist/` and, unless
    `--no-clean`, removes the `-src`/`-build` trees.

---

## Behaviour notes

- **Latest version is resolved live.** With no branch/tag given, `cachyos` queries the
  remote for the newest `cachyos_*/main` branch and `ge` for the newest `GE-ProtonN-M`
  tag, each falling back to a pinned default if the lookup fails.
- **Startup version check.** On each run the script compares its own `VERSION` against
  the copy published on GitHub. If the local script is older it stops and asks you to
  update; if you're offline (or `curl`/`wget` are absent) the check is skipped with a
  warning.
- **Clean on success, keep on failure.** A successful build leaves only the tarball in
  `dist/`; the `-src`/`-build` trees are removed so the next run starts fresh. A
  *failed* build leaves its trees in place for debugging. Pass `--no-clean` to always
  keep them (faster patch-development loop).
- **LinUwUx layers on top of upstream — it doesn't replace it.** The `patches/wine`
  directory the script wipes and repopulates is a private staging area; neither CachyOS
  nor GE ships wine patches there. CachyOS's wine patches come pre-applied via its
  `wine-cachyos` fork submodule, and GE's are applied by `protonprep`. LinUwUx patches
  apply on top of that already-patched wine tree, so both sets end up in the build.
- **Patches are applied on the host, and fail loudly.** They're applied before the
  container ever sees the source, so a build can't silently ship without them. If a
  patch or a required `Makefile.in` anchor doesn't apply, the script stops rather than
  producing a quietly-broken build.
- **Versioned folders.** Source, build, and log folders are named per version, so
  multiple builds never clobber each other.
- **Logs** are written to `logs/<version>/` (`build.log`, `linuwux-patches.log`, and
  `prep.log` for GE).
