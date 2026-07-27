# Proton + LinUwUx Builder

Automated script to build **proton-cachyos** or **proton-ge-custom (GE)** with the LinUwUx patches applied.

## Requirements

- `git`
- `podman` (default) or `docker` — pass `--container-engine=docker` to use Docker instead
- `make`, `sed`, `tar`, `patch`
- Sufficient disk space (~30–40 GB per build)

## Usage

```bash
chmod +x build.sh

# Build latest CachyOS (default)
./build.sh

# Build a specific CachyOS branch
./build.sh cachyos cachyos_11.0_20260702/main

# Build latest GE (master)
./build.sh ge

# Build a specific GE tag
./build.sh ge GE-Proton11-3
./build.sh ge GE-Proton10-28

# Force a clean re-clone instead of reusing an existing source tree
./build.sh --force ge GE-Proton11-3

# Build with Docker instead of Podman
./build.sh --container-engine=docker ge
```

## What It Does

1. Clones the LinUwUx patch files from this repo.
2. Clones (or reuses/updates) the proton-cachyos or proton-ge-custom source for the requested branch/tag.
3. Updates submodules.
4. Installs the LinUwUx Wine patches.
5. Applies them:
   - **GE** — applied directly by this script (`protonprep` first, then the LinUwUx patches).
   - **CachyOS** — installed into `patches/wine/`, where CachyOS's own build system auto-applies them.
   - Both variants get the hardware profile GUID (regedit) fix and the faketime protocol request appended directly, rather than as `.patch` files.
6. Adds `user_settings.py` (DLL overrides, `PROTON_DISABLE_LSTEAMCLIENT=1`) and patches `Makefile.in` so it's packaged.
7. Runs `configure.sh` and `make redist`.
8. Packages the result into a single `*-LinUwUx.tar.gz`/`.tar.xz`.

If any LinUwUx patch fails to apply, the build stops rather than shipping a Proton that's silently missing it.

## Folder Structure

Every branch/tag gets its own folder, so multiple versions can coexist and rebuilding one never touches another:

```
./
├── build.sh
├── logs/
│   ├── GE-Proton-11-3/
│   │   ├── prep.log               # GE only
│   │   ├── linuwux-patches.log     # GE only
│   │   └── build.log
│   └── proton-cachyos-11.0-20260702-slr/
│       └── build.log
├── GE-Proton-11-3-src/
├── GE-Proton-11-3-build/
├── proton-cachyos-11.0-20260702-slr-src/
└── proton-cachyos-11.0-20260702-slr-build/
```

Re-running the same branch/tag reuses its existing source tree (fetches and checks out the latest) instead of re-cloning from scratch. Use `--force` to wipe and re-clone.

## Naming

The folder/package name comes straight from the branch or tag you build:

- GE tags read through as-is: `GE-Proton11-3` → `GE-Proton-11-3`.
- CachyOS branches (`cachyos_<version>_<date>/<subpath>`) are translated to match CachyOS's actual release naming: `/main` → `-slr`, `/main_native` → `-native`.

## Patches Are Downloaded Once, Then Reused

The first time you build anything, the script clones `proton-LinUwUx-patch` and keeps its `patches/` folder next to `build.sh`:

```
build.sh
patches/
├── wine/...
├── overrides/...
└── base/...
```

Every later run checks for that folder first: if it's there, it's used exactly as-is with **no network call at all** — the script never re-downloads or overwrites it. That makes it the natural place to test patch changes before pushing them: edit `patches/` directly (or `cd patches/ && git init` / point it at your own checkout if you want version control while iterating), rerun `build.sh`, and your local edits are what gets built.

To go back to a fresh copy of whatever's currently on GitHub, just delete the folder:

```bash
rm -rf patches/
```

and the next run will re-download it.

## The patches/base/ Folder

Alongside `patches/wine/` (the diff patches, subject to the override system below) there's `patches/base/`, which holds plain source snippets that get appended directly into wine's source rather than applied with `patch`. Currently that's `cpuid_spoof_defs.c` — the CPUID-spoofing variables and helper functions, appended into `signal_x86_64.c` before it's compiled.

This folder is **not** part of the override system: its contents are applied identically for every version, every variant, regardless of which override (if any) is in play. It exists as a separate category specifically because this content is self-contained new code with no dependency on a particular version's source layout — unlike the diff patches, it never needs re-offsetting.

## Version-Specific Patch Overrides

Not every LinUwUx patch applies cleanly to every Proton version (e.g. an older base like `GE-Proton9-4` may need its own patch set entirely). Drop version-specific files in the patch repo under:

```
patches/overrides/<exact branch or tag you'd pass on the CLI>/wine/...
```

mirroring the same layout as the common `patches/wine/` tree, e.g.:

```
patches/overrides/GE-Proton9-4/wine/dlls/ntdll/unix/0001-spoof-cpuid.patch
```

The build script uses one or the other, never both: if a version has an override folder, that becomes its *entire* patch set — the common patches are not applied alongside it. Versions without an override folder just use the common patches as normal.

**This mechanism itself is solid, but making an override actually work for a given version is not guaranteed** — that part depends on the patch content, not the script. In practice, getting a version working has meant:

- Manually re-offsetting a patch's context to match that version's source, which can require real investigation (checking the actual post-patch code, verifying the patched function is genuinely reachable, not just that `patch` applied without complaint).
- Splitting large patches into smaller ones, since a single patch touching several unrelated functions makes any one hunk's failure block everything else.
- Compiler differences between versions can surface bugs that were already present but never triggered — e.g. a stricter GCC catching an out-of-bounds `memcpy` that had been silently overreading a buffer in every build up to that point.

So: the script will *build* whatever override you give it and apply the same checks either way (patch failures still `die`, a stale patch redefining something `cpuid_spoof_defs.c` already owns still gets caught). Whether the *resulting Proton actually works correctly* for a given version needs real testing — a clean build is not the same as a working build.

## Output Package

The finished redistributable is named `<version>-LinUwUx.tar.gz` (or `.tar.xz` for CachyOS, matching their official releases), and contains:

- The LinUwUx Wine patches (CPU ID spoof, faketime, hardware profile GUID)
- `user_settings.py` with the DLL overrides and `PROTON_DISABLE_LSTEAMCLIENT=1`

## Installing the Build

```bash
mkdir -p ~/.steam/root/compatibilitytools.d/GE-Proton-11-3-LinUwUx
tar -xf GE-Proton-11-3-LinUwUx.tar.gz -C ~/.steam/root/compatibilitytools.d/GE-Proton-11-3-LinUwUx --strip-components=1
# restart Steam and select the new tool
```

(The script prints the exact commands for whatever it just built at the end of every run.)

## Notes

- First run of any version takes a long time (submodules + full compile).
- Subsequent runs of the same version reuse the existing source folder.
- Different versions never overwrite each other.
- Check `logs/<version>/` if a build fails or a patch doesn't apply cleanly.
- A version-specific override building cleanly doesn't mean the resulting Proton actually works correctly - see [Version-Specific Patch Overrides](#version-specific-patch-overrides).

## Credits
- LinUwUx for the patches.
- DenuvOwO for the HV Bypass.
