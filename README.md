# LinUwUx

LinUwUx is a small Linux compatibility runtime for Windows games running through
Wine or Proton. It uses `LD_PRELOAD` to keep the CPU profile, Windows shared
system data, clocks, signal handling, and Wine environment consistent across the
game and its child processes.

It does not replace Proton or modify game files and prefixes. The installer adds
a `linuwux` wrapper which goes in front of the normal launch command.

## Why Rust?

The original LinUwUx was written in C. I mostly work with C++, so Rust felt
familiar while catching more mistakes at compile time. That is useful in code
which deals with signals, raw pointers, shared state, CPU registers, and libc
interposition.

Some `unsafe` code is unavoidable, but Rust keeps those boundaries visible. The
release library still has no garbage collector, uses `no_std`, exports a C ABI,
and compiles to a small native shared object.

## Requirements

Valve Proton, Proton Experimental, GE-Proton, and UMU-managed builds should all
work. The host needs:

- x86-64 Linux with glibc 2.34 or newer
- a 64-bit Wine/Proton host process or modern WoW64 setup
- working `LD_PRELOAD` support
- access to the installed library from inside any launcher sandbox

Native 32-bit Wine processes cannot load the 64-bit library and may print a
`wrong ELF class` warning.

### CPU and kernel prerequisites

LinUwUx needs UMIP disabled and CPUID faulting available. Check both flags first:

```sh
grep -m1 '^flags' /proc/cpuinfo | tr ' ' '\n' | grep -E '^(umip|cpuid_fault)$'
```

- `umip` means UMIP is enabled and needs to be disabled.
- `cpuid_fault` means native CPUID faulting is available and no emulation module
  is needed.

As a rough guide, Intel 9th generation and AMD Ryzen 3000 or newer CPUs normally
need UMIP disabled. AMD Ryzen AM4 CPUs up to the Ryzen 5000 series, including the
Steam Deck, normally need the `cpuid_fault_emulation` DKMS module as well. Trust
the flags over the model name.

#### Disable UMIP

If `umip` is listed, add this to your kernel command line using your
distribution's bootloader instructions, then reboot:

```text
clearcpuid=514
```

Check it afterwards:

```sh
cat /proc/cmdline
grep -qw umip /proc/cpuinfo && echo 'UMIP is still enabled' || echo 'UMIP is not enabled'
```

This affects the whole system. The kernel documents `clearcpuid` as a debugging
aid and notes that it taints the kernel. Remove the parameter and reboot to undo
the change.

#### CPUID faulting on AMD

If `cpuid_fault` is missing on an AMD AM4 system or Steam Deck, install the
`cpuid_fault_emulation` DKMS module. It needs matching kernel headers and build
tools, DKMS, and AMD virtualization enabled in the firmware.

The LinUwUx installer does not provide this module. Get it from a source you
trust. Secure Boot systems must sign it with an enrolled key.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/brcly/linuwux-runtime/main/install.sh | bash
```

This installs:

```text
~/.local/bin/linuwux
~/.local/share/linuwux/LinUwUx.so
```

No root access is needed. If `~/.local/bin` is missing from `PATH`, add this to
your shell profile and sign out and back in:

```sh
export PATH="$HOME/.local/bin:$PATH"
```

Check the install with `command -v linuwux`. Run the installer again to update.

## Steam

Add this under **Properties > Launch Options**:

```text
linuwux %command%
```

`linuwux` is a command prefix, despite Steam presenting launch options like an
environment-variable field. Put actual variables before it:

```text
PROTON_AVX=1 linuwux %command%
```

For Flatpak Steam, use the full path if the command cannot be found:

```text
/home/USERNAME/.local/bin/linuwux %command%
```

The Flatpak must also be able to read
`/home/USERNAME/.local/share/linuwux/LinUwUx.so`.

## Gamescope and MangoHud

Ordering matters. Put Gamescope options before `--` and `linuwux` immediately
before the game command:

```text
gamescope -f -- linuwux %command%
mangohud linuwux %command%
MANGOHUD=1 linuwux %command%
gamescope --mangoapp -f -- linuwux %command%
PROTON_AVX=1 gamescope --mangoapp -f -- linuwux %command%
```

## Other launchers

- **Faugus Launcher:** Edit the game, open **Tools > Launch Settings**, and set
  **Launch Argument** to `linuwux`. Use **Launch Arguments**, rather than **Game
  Arguments**. Its built-in GameMode and MangoHud switches can stay enabled.
- **Lutris:** Open **Configure > Advanced options > System options** and set
  **Command prefix** to `linuwux`.
- **Heroic, Bottles, and other frontends:** Put `linuwux` in the per-game
  **Wrapper** or **Command prefix** field.

For Flatpak launchers, use `/home/USERNAME/.local/bin/linuwux` and allow access
to the installed library. If a launcher only accepts environment variables, set:

| Name | Value |
| --- | --- |
| `LD_PRELOAD` | `/home/USERNAME/.local/share/linuwux/LinUwUx.so` |

Keep any existing `LD_PRELOAD` value and append LinUwUx with a colon. Use an
absolute path without spaces or colons.

## Configuration

LinUwUx needs no extra variables by default.

| Variable | Behaviour |
| --- | --- |
| `PROTON_AVX=1` | Enables AVX flags for the modern profile |
| `LINUWUX_DENUVOWODLL=1` | Experimental: enables native DenuvOwO.dll loading; protocol support activates only for a target game directory containing the DLL |
| `LINUWUX_DEBUG=1` | Enables runtime diagnostics |
| `LINUWUX_LOG=/absolute/path.log` | Writes diagnostics to a private `0600` file |

`LinUwUx` is an internal process marker and should not be set manually.

## Troubleshooting

- **`linuwux: command not found`:** Use the full wrapper path or add
  `~/.local/bin` to `PATH`.
- **The game does not launch:** Try `linuwux %command%` without other wrappers.
  For containerised launchers, check that the wrapper and library are visible in
  the sandbox and that the runner starts a 64-bit Wine host.

To collect a debug log, use:

```text
LINUWUX_DEBUG=1 LINUWUX_LOG=/tmp/linuwux.log linuwux %command%
```

Remove the debug variables afterwards. To report a problem, open a
[bug report](https://github.com/brcly/linuwux-runtime/issues/new?template=bug_report.yml)
and attach the full LinUwUx log plus the Proton, UMU, or launcher log.

## Build from source

Install Rust 1.98 or newer, a native C linker, and GNU binutils, then run:

```sh
cargo xtask build
```

The finished library is `target/runtime/LinUwUx.so`. You can also use:

```sh
cargo xtask build --debug
cargo xtask build --output /absolute/path/LinUwUx.so
```

The build checks the public exports, constructor order, ELF architecture, and
linker hardening.

## Uninstall

```sh
rm "$HOME/.local/bin/linuwux"
rm "$HOME/.local/share/linuwux/LinUwUx.so"
```

Remove `linuwux` or the direct `LD_PRELOAD` entry from each launcher too.

## AI disclosure

I used AI during debugging, testing, and parts of the documentation. Hate it as
much as you want; it saved me a lot of time staring at memory addresses and
helped me think through ideas which never made it into the project. I also used
it as another pair of eyes while checking a few small pieces of code for
performance regressions.

## License

LinUwUx is distributed under the terms in [LICENSE](LICENSE).

## Credits

- LinUwUx - original Proton patch
- DenuvOwO - Reflex and HV bypass
