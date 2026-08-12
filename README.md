# LinUwUx Pre-load library.

Build `liblinuwux_preload.so`: an `LD_PRELOAD` library that installs the **LinUwUx** DenuvOwO hypervisor-bypass patch set into GE-Proton or CachyOS Proton, with nothing to build, patch, or configure on the Proton side. Drop the library next to an existing Proton install and launch with:

```
LD_PRELOAD="${LD_PRELOAD}:/path/to/liblinuwux_preload.so" %command%
```

That's the whole integration. No Wine source is patched, no launcher script is touched, no registry file needs importing — CPUID spoofing, the SIGSYS/DenuvOwO redirect, the `HwProfileGuid` registry fix, faketime, and the native DLL overrides (`winmm`/`version`/`reflex=n,b`) all happen live, from inside the library, the moment it loads.

Append to `LD_PRELOAD` rather than replacing it (`"${LD_PRELOAD}:..."`, not `LD_PRELOAD=...`) — Steam sets its own `LD_PRELOAD` earlier in the launch chain to inject the Steam Overlay (`GameOverlayRenderer64.so`), and a bare `LD_PRELOAD=/path/to/liblinuwux_preload.so %command%` clobbers that outright, silencing the overlay.

**Official Valve Proton is not currently supported.** GE-Proton and CachyOS Proton are confirmed working end-to-end through the real Steam client; official Valve Proton has hit game-side debug/anti-tamper detection we haven't tracked down yet. Use GE-Proton or CachyOS Proton for now.

This project does **not** configure host-side requirements for the bypass (UMIP, HV DKMS, etc.) — see [cs.rin.ru](https://csrin.org) for those instructions.

## Quick start

```bash
./build.sh
```

Compiles `patches/preload/linuwux_preload.c` and drops `liblinuwux_preload.so` in `dist/` — no Proton/Wine clone, no container engine, done in seconds. Point `LD_PRELOAD` at it from any existing Proton's launch options (append, don't replace — see above).

## Layout

```
build.sh                 # orchestrator
lib/
  common.sh              # logging helpers
  apply-preload.sh       # fetches patches/, builds liblinuwux_preload.so
patches/
  preload/
    linuwux_preload.c    # LD_PRELOAD library -- all LinUwUx logic lives here
```

## How LinUwUx is applied

`liblinuwux_preload.so` interposes libc calls Wine itself already makes — for signal delivery (`sigaction()`, `prctl()`) and for the wall clock (`clock_gettime()`, `gettimeofday()`) — and wraps around whatever Wine registers at runtime, rather than touching Wine's source, a prefix's registry, or a launcher script at all.

### Runtime

| Stage | What happens |
|-------|----------------|
| Library load | `detect_cpu_vendor()` fills spoof tables; `WINEDLLOVERRIDES` gets `winmm`/`version`/`reflex=n,b` appended (skipping any the user already set); `PROTON_DISABLE_LSTEAMCLIENT` defaults to `1` |
| First `sigaction(SIGSEGV, ...)` | Interposed; wraps Wine's own handler, then enables `ARCH_SET_CPUID` faulting |
| First `sigaction(SIGSYS, ...)` | Interposed; wraps Wine's own handler |
| First `prctl(PR_SET_SYSCALL_USER_DISPATCH, ...)` | Interposed; learns the per-thread SUD selector's TEB offset from Wine's own real call, instead of guessing struct layout |
| Guest `CPUID` | `linuwux_cpuid_spoof()` rewrites registers (identity leaves + control leaves) |
| Leaf `0x336933` | Arms `TargetSysHandler`, patches `KUSER_SHARED_DATA`, and creates the `HwProfileGuid` registry key/value live via `NtCreateKey`/`NtSetValueKey` (real NT API, resolved from the already-loaded `ntdll.so`) |
| Leaf `0x336967` | Faketime -- stores an offset, then every later `clock_gettime(CLOCK_REALTIME)`/`gettimeofday()` reflects it |
| Blocked syscall | `linuwux_sigsys_route()` may redirect into the usermode trampoline |

**Syscall User Dispatch (GE-Proton 11-5+).** These trees replace seccomp+BPF
with Linux's Syscall User Dispatch. Rather than detecting this from the
tree's source at build time, the preload library learns the SUD selector's
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

**Faketime** interposes `clock_gettime()`/`gettimeofday()` directly and
subtracts a stored offset from `CLOCK_REALTIME`/`CLOCK_REALTIME_COARSE`
queries specifically — never `CLOCK_MONOTONIC` or anything else, which
would corrupt `sleep()`/`poll()`/timeout logic elsewhere in the process.
This fakes the wall clock `NtQuerySystemTime()`/`GetSystemTimeAsFileTime()`
actually reads (confirmed against real Wine source: it calls
`clock_gettime()`/`gettimeofday()` directly, never touching wineserver at
all). The offset math mirrors the formula a wineserver-side patch would
use (`((current_time_ticks >> 32) - requested_value) << 32`, in
Windows-tick units), computed once when the leaf fires from real time at
that moment, so a real trampoline's call produces a consistent time shift.
Needs nothing from a Wine build — same as everything else this library does.

**SIGSYS redirect scope.** After arm, DenuvOwO's hypervisor only vectors the tracked process. Under Wine we approximate that by **not** handing post-arm SIGSYS faults to `TargetSysHandler` when the fault RIP sits in the Wine system PE band `[0x6FFFFF000000, 0x700000000000)` (typical ntdll/kernel32-class layout on Proton/GE). Game, crack, and other guest RIPs still redirect. Addresses in the Linux high range (`0x7fff…`) are **not** treated as Wine PE — some packs need those redirects.

| Environment | Effect |
|-------------|--------|
| `LINUWUX_DEBUG=1` | Event tracing (arm, KUSER, learned offsets, registry/DLL-override writes, faketime shifts, actual redirects). Wine-system skips are silent — too frequent to log. |
| `LINUWUX_REDIRECT_ALL=1` | Disable the RIP scope filter; every post-arm SIGSYS redirects (pre-scope behaviour). |
| `PROTON_AVX=1` | AVX/XSAVE in spoofed CPUID/KUSER data |

## Requirements

`git`, `gcc`. That's it.

## Usage

```bash
./build.sh [OPTIONS]
```

| Flag | Effect |
|------|--------|
| `--update-patches` | Re-clone `patches/` from this repo |
| `-h`, `--help` | Help |

| Environment | Effect |
|-------------|--------|
| `PATCH_BRANCH=<name>` | Branch for patch clone when `patches/` is missing |
| `LINUWUX_DEBUG=1` | Runtime event tracing |
| `LINUWUX_REDIRECT_ALL=1` | Disable SIGSYS Wine-PE scope filter |
| `PROTON_AVX=1` | AVX/XSAVE in spoofed CPUID/KUSER data |

## Output

```
dist/liblinuwux_preload.so
```

No installation step, no compatibility-tool registration — just point an existing Proton's `LD_PRELOAD` launch option at it (append, don't replace — see Quick start).

## Behaviour notes

- Local `patches/` is reused unless `--update-patches`.
- `WINEDLLOVERRIDES` and `PROTON_DISABLE_LSTEAMCLIENT` are set live by the library itself at load time (see Runtime table above) — not baked into any script.
- `PROTON_DISABLE_LSTEAMCLIENT=1` is needed for the bypass on DenuvOwO packs that dislike Proton's `lsteamclient` translation layer — but it also silences the Steam Overlay's in-game activation, since the overlay goes through `lsteamclient` too. If your pack doesn't need it, set `PROTON_DISABLE_LSTEAMCLIENT=0` yourself via launch options to keep the overlay.
- Covers both GE-Proton 11-3-style trees (seccomp+BPF) and GE-Proton 11-5+ trees (Syscall User Dispatch) — which one a given Proton uses is detected at runtime from the process's own signal setup, not guessed from a version number.
- Confirmed working launched directly through the real Steam client (not just Lutris/Heroic/Faugus) with GE-Proton/CachyOS — the game's `LD_PRELOAD` does reach the process inside Steam's own pressure-vessel container.

## License

This project is free software under the [GNU Affero General Public License v3](LICENSE)
(or, at your option, any later version).

Copyright (C) 2026 brcly.

- Upstream **Proton** and **Wine** retain their own licenses (typically
  LGPL). This repository's scripts and patches are AGPL-3.0; combining
  them with upstream trees does not relicense Valve's or Wine's code.

Please keep copyright notices intact when you redistribute or modify this work.
Preferred credit line for derived builds:

`LinUwUx Proton builder by brcly (https://github.com/brcly/proton-LinUwUx-patch)`

## Credits
- LinUwUx - Original Bypass creator
- DenuvOwO - Hypervisor Bypass
- [Kurt Himebauch](https://github.com/xXJSONDeruloXx) - Legacy Reflex Fix (historical; the dual-trampoline protocol this covered is no longer carried by the current LD_PRELOAD-based design)
