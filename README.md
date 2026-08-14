# LinUwUx

Build `liblinuwux.so`: an `LD_PRELOAD` library that installs the **LinUwUx** DenuvOwO hypervisor-bypass patch set into GE-Proton or CachyOS Proton, with nothing to build, patch, or configure on the Proton side.

CPUID spoofing, the SIGSYS/DenuvOwO redirect, the `HwProfileGuid` registry fix, faketime, and the native DLL overrides (`winmm`/`version`/`reflex=n,b`) all happen live, from inside the library, the moment it loads — no Wine source is patched, no launcher script is touched, no registry file needs importing.

**Official Valve Proton is not currently supported.** GE-Proton and CachyOS Proton are confirmed working end-to-end through the real Steam client; official Valve Proton has hit game-side debug/anti-tamper detection we haven't tracked down yet. Use GE-Proton or CachyOS Proton for now.

This project does **not** configure host-side requirements for the bypass (UMIP, HV DKMS, etc.) — see [cs.rin.ru](https://csrin.org) for those instructions.

## Requirements

- **Prebuilt install:** `curl`, `sha256sum` — present on virtually any Linux install already.
- **Build from source:** `git`, `gcc`.

## Quick start

Two ways to get `liblinuwux.so` running — pick whichever you prefer.

### Fastest: prebuilt install

```bash
curl -fsSL https://raw.githubusercontent.com/brcly/linuwux-runtime/main/install.sh | sh
```

Downloads the latest [release](https://github.com/brcly/linuwux-runtime/releases)'s `liblinuwux.so` and the `linuwux` wrapper straight into `~/.local/lib` / `~/.local/bin`, verifies the download against a published checksum, and you're done — no `git clone`, no compiler. Steam launch options:

```
~/.local/bin/linuwux %command%
```

Re-running the command later re-installs whatever the newest release is — that's the whole update story.

### Build from source

```bash
./build.sh
```

Compiles `src/linuwux.c` and `src/modules/*.c` and drops `liblinuwux.so` in `dist/` — no Proton/Wine clone, no container engine, done in seconds. Add it to the game's launch options, **appending** to `LD_PRELOAD` rather than replacing it:

```
LD_PRELOAD="${LD_PRELOAD}:/path/to/liblinuwux.so" %command%
```

Steam sets its own `LD_PRELOAD` earlier in the launch chain to inject the Steam Overlay (`GameOverlayRenderer64.so`); a bare `LD_PRELOAD=/path/to/liblinuwux.so %command%` clobbers that outright and silences the overlay.

**Using MangoHud?** Put `linuwux` (or the `LD_PRELOAD=...` form) *before* MangoHud's own arguments, not before:

```
linuwux mangohud %command%
```

not

```
mangohud linuwux %command%
```

`mangohud` is itself a wrapper script that sets `LD_PRELOAD` and `exec`s, same trick `linuwux` uses. Chaining them the wrong way round loads `libMangoHud.so` into an extra intermediate shell process it was never meant to survive twice in a launch chain, and the game never starts.

Prefer your launcher's own MangoHud toggle over writing `mangohud` into the launch command by hand, if it has one — Faugus and Heroic (Settings → Other → MangoHud, per-game) both do, and it places MangoHud in the correct position automatically. Manual command-line chaining is only needed for launchers without that option.

#### Simpler: `--install`

```bash
./build.sh --install
```

Installs the library to `~/.local/lib` and a `linuwux` wrapper to `~/.local/bin` (the same destinations `install.sh` uses, so the two are interchangeable), so the launch option is just:

```
~/.local/bin/linuwux %command%
```

The wrapper appends to `LD_PRELOAD` itself (same rule as above, handled for you) before exec'ing the real command. The absolute path works immediately regardless of `PATH` — once `~/.local/bin` is confirmed on `PATH`, plain `linuwux %command%` works too (handy from a terminal, Lutris, or Heroic; Steam's own process environment won't pick up a `PATH` change until it's restarted, so the absolute form is what to use there).

Once installed, plain `./build.sh` (no `--install` needed again) keeps the installed copy in sync on every rebuild — pull an update, rebuild, and it's live with no extra step. Check what's actually installed any time with `linuwux --version`.

## Layout

```
build.sh                 # self-contained: builds, and optionally installs
install.sh                # fetches + installs the latest prebuilt release
src/
  linuwux.c              # constructor only -- ties the modules below together
  linuwux.sh            # 'linuwux' wrapper template, installed by --install
  modules/
    linuwux.h            # shared logging/TEB declarations
    common.c             # linuwux_log()
    cpuid.c              # CPUID spoof, KUSER_SHARED_DATA patch, arm/faketime leaves
    sigsys.c             # SIGSYS/DenuvOwO syscall redirect
    registry.c           # HwProfileGuid via the real NT registry API
    faketime.c           # clock_gettime()/gettimeofday() interposition
    hooks.c              # sigaction()/prctl() interposition, handler chaining
```

`build.sh` globs `src/linuwux.c` and `src/modules/*.c` into one `liblinuwux.so`; the split is source organization only, not separate libraries. `-fvisibility=hidden` keeps everything except the four interposition targets (`sigaction`, `prctl`, `clock_gettime`, `gettimeofday`) out of the shared object's exported symbol table, same as when it was a single file.

A tagged push (`vYY.MM.DD`) triggers [`.github/workflows/release.yml`](.github/workflows/release.yml), which builds `liblinuwux.so` from that exact commit, stamps it with the tag's version, and publishes it plus `linuwux.sh` and a `SHA256SUMS` file as a GitHub Release — what `install.sh` downloads.

## How LinUwUx is applied

`liblinuwux.so` interposes libc calls Wine itself already makes — for signal delivery (`sigaction()`, `prctl()`) and for the wall clock (`clock_gettime()`, `gettimeofday()`) — and wraps around whatever Wine registers at runtime, rather than touching Wine's source, a prefix's registry, or a launcher script at all.

### Runtime

| Stage | What happens |
|-------|----------------|
| Library load | `detect_cpu_vendor()` fills spoof tables; `WINEDLLOVERRIDES` gets `winmm`/`version`/`reflex=n,b` appended (skipping any the user already set); `PROTON_DISABLE_LSTEAMCLIENT` defaults to `1`; `[linuwux] vX.Y.Z loaded (pid=...)` is printed to stderr unconditionally |
| First `sigaction(SIGSEGV, ...)` | Interposed; wraps Wine's own handler, then enables `ARCH_SET_CPUID` faulting |
| First `sigaction(SIGSYS, ...)` | Interposed; wraps Wine's own handler |
| First `prctl(PR_SET_SYSCALL_USER_DISPATCH, ...)` | Interposed; learns the per-thread SUD selector's TEB offset from Wine's own real call, instead of guessing struct layout |
| Guest `CPUID` | `linuwux_cpuid_spoof()` rewrites registers (identity leaves + control leaves) |
| Leaf `0x336933` | Arms `TargetSysHandler`, patches `KUSER_SHARED_DATA`, and creates the `HwProfileGuid` registry key/value live via `NtCreateKey`/`NtSetValueKey` (real NT API, resolved from the already-loaded `ntdll.so`) |
| Leaf `0x336967` | Faketime -- stores an offset, then every later `clock_gettime(CLOCK_REALTIME)`/`gettimeofday()` reflects it |
| Blocked syscall | `linuwux_sigsys_route()` may redirect into the usermode trampoline |

**Syscall User Dispatch (GE-Proton 11-5+).** These trees replace seccomp+BPF
with Linux's Syscall User Dispatch. Rather than detecting this from the
tree's source at build time, the library learns the SUD selector's
TEB offset directly from Wine's own real `prctl()` call at runtime — the
same offset resolves correctly whether or not the tree has SUD support,
since the whole mechanism is a no-op on trees that never make that
`prctl()` call in the first place (seccomp-based trees, e.g. GE-Proton
11-3 / CachyOS).

**HwProfileGuid and DLL overrides** are both written using the real,
stable Windows/NT API — `NtCreateKey`/`NtSetValueKey` for the registry,
`WINEDLLOVERRIDES` via a plain `setenv()` early enough to beat Wine's own
first load-order decision — rather than a source-level `wine.inf`/launcher
insert. That's what makes them work identically on a Proton install this
project never built.

**Faketime** interposes `clock_gettime()`/`gettimeofday()` directly,
subtracting a stored offset from `CLOCK_REALTIME`/`CLOCK_REALTIME_COARSE`
queries only — never `CLOCK_MONOTONIC`, which would break
`sleep()`/`poll()`/timeout logic elsewhere in the process. This is the
wall clock `NtQuerySystemTime()`/`GetSystemTimeAsFileTime()` actually read
on real Wine, so it fakes the time the game sees. Needs nothing from a
Wine build, same as everything else here.

**SIGSYS redirect scope.** After arm, DenuvOwO's hypervisor only vectors the tracked process. Under Wine we approximate that by **not** handing post-arm SIGSYS faults to `TargetSysHandler` when the fault RIP sits in the Wine system PE band `[0x6FFFFF000000, 0x700000000000)` (typical ntdll/kernel32-class layout on Proton/GE). Game, crack, and other guest RIPs still redirect. Addresses in the Linux high range (`0x7fff…`) are **not** treated as Wine PE — some packs need those redirects.

| Environment | Effect |
|-------------|--------|
| `LINUWUX_DEBUG=1` | Event tracing (arm, KUSER, learned offsets, registry/DLL-override writes, faketime shifts, actual redirects). Wine-system skips are silent — too frequent to log. |
| `LINUWUX_REDIRECT_ALL=1` | Disable the RIP scope filter; every post-arm SIGSYS redirects (pre-scope behaviour). |
| `PROTON_AVX=1` | AVX/XSAVE in spoofed CPUID/KUSER data |

## Usage

```bash
./build.sh [OPTIONS]
```

| Flag | Effect |
|------|--------|
| `--install` | Also install to `~/.local/lib` + a `linuwux` wrapper in `~/.local/bin` |
| `-h`, `--help` | Help |

The installed `linuwux` wrapper has its own flag:

| Flag | Effect |
|------|--------|
| `--version`, `-V` | Print the installed library's version (read from the `.so` itself via `strings`) and exit |

| Environment | Effect |
|-------------|--------|
| `LINUWUX_DEBUG=1` | Runtime event tracing |
| `LINUWUX_REDIRECT_ALL=1` | Disable SIGSYS Wine-PE scope filter |
| `LINUWUX_PRELOAD=<path>` | `linuwux` wrapper only: override the library path it loads |
| `PROTON_AVX=1` | AVX/XSAVE in spoofed CPUID/KUSER data |

## Output

```
dist/liblinuwux.so
```

With `--install`, also:

```
~/.local/lib/liblinuwux.so
~/.local/bin/linuwux
```

Neither is a real "install" in the traditional sense — no compatibility-tool registration, nothing Proton or Steam needs to know about ahead of time. It's just a file to point a launch option at (see Quick start).

To uninstall, just remove the two files:

```bash
rm -f ~/.local/lib/liblinuwux.so ~/.local/bin/linuwux
```

Then remove it from the game's launch options.

## Behaviour notes

- `WINEDLLOVERRIDES` and `PROTON_DISABLE_LSTEAMCLIENT` are set live by the library itself at load time (see Runtime table above) — not baked into any script.
- `PROTON_DISABLE_LSTEAMCLIENT=1` bypasses Steam DRM/Steamworks checks some DenuvOwO packs trip on. It doesn't affect the Steam Overlay — that keeps working as long as `LD_PRELOAD` is appended rather than replaced (see Quick start).
- The library announces its version on every load (`[linuwux] vX.Y.Z loaded (pid=...)`, printed to stderr regardless of `LINUWUX_DEBUG`) so it shows up in whatever log gets pasted for a bug report. Check it any time without launching a game via `linuwux --version` or `strings liblinuwux.so | grep linuwux`.
- Confirmed working launched directly through the real Steam client (not just Lutris/Heroic/Faugus) with GE-Proton/CachyOS — the game's `LD_PRELOAD` does reach the process inside Steam's own pressure-vessel container.
- With MangoHud, order matters: `linuwux mangohud %command%`, not `mangohud linuwux %command%` — or better, use your launcher's own MangoHud toggle instead of chaining it by hand (see Quick start).

## Reporting issues

Open an [issue](https://github.com/brcly/linuwux-runtime/issues/new/choose) and include:

- `linuwux --version` (or `strings liblinuwux.so | grep linuwux` if you built from source)
- A `LINUWUX_DEBUG=1` run — set it before launching, either as a Steam launch option prefix (`LINUWUX_DEBUG=1 ~/.local/bin/linuwux %command%`) or via `LINUWUX_DEBUG=1 linuwux <game exe>` from a terminal — and paste the resulting log
- GE-Proton/CachyOS version, and whether it's a Denuvo pack, another DRM, or something else

Without the version and a debug log, diagnosing a report usually starts with a guess.

## License

This project is free software under the [GNU Affero General Public License v3](LICENSE)
(or, at your option, any later version).

Copyright (C) 2026 brcly.

- Upstream **Proton** and **Wine** retain their own licenses (typically
  LGPL). This repository's scripts and patches are AGPL-3.0; combining
  them with upstream trees does not relicense Valve's or Wine's code.

Please keep copyright notices intact when you redistribute or modify this work.
Preferred credit line for derived builds:

`LinUwUx by brcly (https://github.com/brcly/linuwux-runtime)`

## About the documentation

Parts of this README, the in-source comments, and some debugging discussion were drafted with AI assistance, then reviewed and edited by hand. The library code, design decisions, and testing are human work — AI was not used to invent or implement any of the bypass logic itself.

## Credits
- LinUwUx - Original Bypass creator
- DenuvOwO - Hypervisor Bypass
- [Kurt Himebauch](https://github.com/xXJSONDeruloXx) - Legacy Reflex Fix (historical; the dual-trampoline protocol this covered is no longer carried by the current LD_PRELOAD-based design)
