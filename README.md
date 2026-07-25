# Proton + LinUwUx Builder

Automated script to build **proton-cachyos** or **proton-ge-custom (GE)** with the LinUwUx patches applied.

## Requirements

- `git`
- `podman` (or docker)
- `make`
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
```

## Folder Structure

The script creates versioned folders so multiple builds can coexist:

```
./
├── build.sh
├── GE-Proton-11-3-src/          # source tree
├── GE-Proton-11-3-build/        # build directory + final package
├── GE-Proton-10-28-src/
├── GE-Proton-10-28-build/
├── proton-cachyos-11.0-20260702-src/
└── ...
```

## Output Package

The finished redistributable is named:

```
GE-Proton-11-3-LinUwUx.tar.gz
```

or the equivalent for CachyOS.

It already contains:

- The four LinUwUx Wine patches
- `user_settings.py` with the DLL overrides and `PROTON_DISABLE_LSTEAMCLIENT=1`

## Installing the Build

```bash
mkdir -p ~/.steam/root/compatibilitytools.d/GE-Proton-11-3-LinUwUx
# extract the tarball into that folder
# restart Steam and select the new tool
```

## Notes

- First run of any version will take a long time (submodules + full compile).
- Subsequent runs of the same version reuse the existing source folder.
- Different versions never overwrite each other.
