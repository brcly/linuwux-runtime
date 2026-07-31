# Proton + LinUwUx Builder

Build **proton-cachyos** or **proton-ge-custom** from source with the **LinUwUx** patch set applied, and package a Steam Play compatibility tool.

Other projects ship pre-built tarballs. This one is a reproducible *builder* so you can regenerate the latest patched Proton yourself when upstream moves.

**Proton 11 only** (for now). Valve’s official Proton is not supported.

## Layout

```
build.sh                 # orchestrator
lib/
  common.sh              # logging, line-insert helpers
  source.sh              # clone, submodules, stage patches/wine
  apply-content.sh       # content inserts + hooks install
  apply-patches.sh       # traditional .patch apply + GE protonprep
  package.sh             # user_settings, configure, redist, verify
patches/
  base/
    linuwux_hooks.c      # modern ntdll unix hooks (bulk logic)
    hwprofile_guid.reg
    set_faketime.protocol
    user_settings.py
  legacy-reflex/
    linuwux_hooks_legacy.c   # same API; used only with --legacy-reflex
  wine/
    server/0001-apply_faketime.patch
```

## How LinUwUx is applied

1. Copy `linuwux_hooks.c` (or `linuwux_hooks_legacy.c`) into `dlls/ntdll/unix/` as `linuwux_hooks.c`.
2. `#include "linuwux_hooks.c"` into `signal_x86_64.c` (before Linux `sigsys_handler`, after `REG_*` macros).
3. Inject tiny call stubs into `segv_handler`, Linux `sigsys_handler`, and `signal_init_process`.
4. Append HwProfileGuid / `set_faketime` protocol definitions; apply the server faketime `.patch`; regenerate protocol headers.

The signal file stays almost stock. All bulk logic lives in one hooks file you can edit without fighting context diffs.

### Runtime (modern hooks)

| Stage | What happens |
|-------|----------------|
| Process init | `detect_cpu_vendor()` fills spoof tables; `ARCH_SET_CPUID` makes guest `CPUID` fault |
| Guest `CPUID` | `linuwux_cpuid_spoof()` rewrites registers (identity leaves + control leaves) |
| Leaf `0x336933` | Arms `TargetSysHandler`, patches `KUSER_SHARED_DATA` |
| Leaf `0x336967` | Wineserver `set_faketime` |
| Blocked syscall | `linuwux_sigsys_route()` may redirect into the trampoline |

Opt-in log: `LINUWUX_DEBUG=1`. AVX in spoofed features: `PROTON_AVX=1`.

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
| `cachyos` (default) | CachyOS/proton-cachyos | latest `cachyos_*/main` |
| `ge` | GloriousEggroll/proton-ge-custom | latest `GE-ProtonN-M` tag |

```bash
./build.sh                          # latest CachyOS
./build.sh ge GE-Proton11-3
./build.sh --legacy-reflex ge GE-Proton11-3
./build.sh --force --no-clean cachyos
./build.sh --update-patches
```

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
