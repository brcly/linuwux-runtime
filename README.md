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
   - Both variants get the hardware profile GUID (regedit) fix applied directly.
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

## Credits
- LinUwUx for the patches.
- DenuvOwO for the HV Bypass.
