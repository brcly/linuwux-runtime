<p align="center">
  <img src="assets/banner.png" alt="LinUwUx — LD_PRELOAD runtime" width="880">
</p>

`liblinuwux.so` — an `LD_PRELOAD` library that applies the **LinUwUx** DenuvOwO hypervisor-bypass set under **GE-Proton** or **CachyOS Proton**. No Proton/Wine source patches, no prefix registry imports, no launcher script rewrites.Ux

`liblinuwux.so` — an `LD_PRELOAD` library that applies the **LinUwUx** DenuvOwO hypervisor-bypass set under **GE-Proton** or **CachyOS Proton**. No Proton/Wine source patches, no prefix registry imports, no launcher script rewrites.

**Official Valve Proton is not supported.** Use GE-Proton or CachyOS Proton.

This project does **not** set up host-side requirements (UMIP, HV DKMS, etc.) — see [cs.rin.ru](https://csrin.org) for those.

## Install

**Prebuilt** (needs `curl`, `sha256sum`):

```bash
curl -fsSL https://raw.githubusercontent.com/brcly/linuwux-runtime/main/install.sh | sh
```

Installs `~/.local/lib/liblinuwux.so` and `~/.local/bin/linuwux`.

**From source** (needs `git`, `gcc`):

```bash
./build.sh --install
```

Same destinations; plain `./build.sh` afterward refreshes the installed `.so`.

## Launch (Steam example)

Per **game** launch options — not the whole Steam/Lutris UI (`~/.local/bin` on `PATH`):

```text
linuwux %command%
```

If a GUI app (e.g. Steam) was already running when you fixed `PATH`, restart it once — or use `~/.local/bin/linuwux %command%` until you do.

### Do not wrap the launcher

```bash
linuwux lutris     # wrong — preloads the UI, not the game
linuwux heroic     # wrong
```

Full setup for **Lutris, Heroic, Faugus, MangoHud order, gamescope limits, and common mistakes**:

- **[GitHub Wiki](https://github.com/brcly/linuwux-runtime/wiki)** (same pages when published)

## Requirements

| Path | Tools |
|------|--------|
| Prebuilt | `curl`, `sha256sum` |
| Source build | `git`, `gcc` |

## Reporting issues

Open an [issue](https://github.com/brcly/linuwux-runtime/issues/new/choose) with:

- `linuwux --version`
- A log from `LINUWUX_DEBUG=1 linuwux %command%` (or the equivalent on your launcher)
- GE-Proton/CachyOS version and game/DRM context

## License

[GNU Affero General Public License v3](LICENSE) (or later). Copyright (C) 2026 brcly.

Upstream Proton/Wine keep their own licenses. Preferred credit:

`LinUwUx by brcly (https://github.com/brcly/linuwux-runtime)`

## About the documentation

Parts of the docs and in-source comments were drafted with AI assistance, then reviewed and edited by hand. Library code, design decisions, and testing are human work — AI was not used to invent or implement bypass logic.

## Credits

- LinUwUx — original bypass creator  
- DenuvOwO — hypervisor bypass  
- [Kurt Himebauch](https://github.com/xXJSONDeruloXx) — legacy Reflex fix (historical; not used by the current LD_PRELOAD design)
