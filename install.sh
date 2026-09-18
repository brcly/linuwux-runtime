#!/usr/bin/env bash
set -euo pipefail

case "${1-}" in
    "") ;;
    --help|-h)
        cat <<'USAGE'
Usage: install.sh [--global]

Install LinUwUx for the current user. The optional --global flag also symlinks
the launcher into /usr/local/bin and may ask for a sudo password.
USAGE
        exit 0
        ;;
    --global)
        if [ "$#" -ne 1 ]; then
            echo "install.sh: --global does not accept additional arguments" >&2
            exit 2
        fi
        ;;
    *)
        echo "install.sh: unknown option: $1" >&2
        echo "Usage: install.sh [--global]" >&2
        exit 2
        ;;
esac

REPO="${LINUWUX_REPO:-brcly/linuwux-runtime}"
VERSION="${LINUWUX_VERSION:-latest}"
INSTALL_GLOBAL=0
[ "${1-}" = "--global" ] && INSTALL_GLOBAL=1

LIB_DIR="$HOME/.local/share/linuwux"
BIN_DIR="$HOME/.local/bin"
LIB_PATH="$LIB_DIR/LinUwUx.so"
BIN_PATH="$BIN_DIR/linuwux"
GLOBAL_BIN_PATH="/usr/local/bin/linuwux"

if [ "$VERSION" = "latest" ]; then
    asset_url="https://github.com/$REPO/releases/latest/download/LinUwUx.so"
else
    asset_url="https://github.com/$REPO/releases/download/$VERSION/LinUwUx.so"
fi

tmp_lib="$(mktemp)"
trap 'rm -f "$tmp_lib"' EXIT

echo "linuwux: downloading LinUwUx.so ($VERSION) from $REPO"
curl -fsSL "$asset_url" -o "$tmp_lib"

magic="$(od -An -tx1 -N4 "$tmp_lib" | tr -d ' ')"
if [ "$magic" != "7f454c46" ]; then
    echo "install.sh: downloaded file is not an ELF library, aborting" >&2
    exit 1
fi

mkdir -p "$LIB_DIR" "$BIN_DIR"
install -m 0644 "$tmp_lib" "$LIB_PATH"

cat >"$BIN_PATH" <<EOF
#!/bin/sh
set -eu
set -f

lib="$LIB_PATH"

if [ ! -r "\$lib" ]; then
    echo "linuwux: library not found: \$lib" >&2
    echo "  Reinstall with install.sh" >&2
    exit 1
fi

case "\$lib" in
    *:*)
        echo "linuwux: library path cannot contain ':' when used in LD_PRELOAD" >&2
        exit 1
        ;;
esac

if [ "\$#" -eq 0 ]; then
    echo "linuwux: no command given -- use it as a launch option:" >&2
    echo "  $BIN_PATH %command%" >&2
    exit 1
fi

preload="\${LD_PRELOAD-}"
command_name="\${1##*/}"
filtered=
old_ifs=\$IFS
IFS=:
for entry in \$preload; do
    [ -n "\$entry" ] || continue
    case "\$entry" in
        "\$lib") continue ;;
    esac
    if [ "\$command_name" = gamescope ]; then
        case "\$entry" in
            *gameoverlayrenderer.so*) continue ;;
        esac
    fi
    filtered="\${filtered:+\$filtered:}\$entry"
done
IFS=\$old_ifs

export LD_PRELOAD="\$lib\${filtered:+:\$filtered}"
exec "\$@"
EOF
chmod 0755 "$BIN_PATH"

if [ "$INSTALL_GLOBAL" -eq 1 ]; then
    if ! command -v sudo >/dev/null 2>&1; then
        echo "install.sh: --global requires sudo" >&2
        exit 1
    fi
    echo "linuwux: installing global launcher to $GLOBAL_BIN_PATH"
    sudo ln -sf "$BIN_PATH" "$GLOBAL_BIN_PATH"
fi

echo "linuwux: installed library to $LIB_PATH"
echo "linuwux: installed launcher to $BIN_PATH"

if [ "$INSTALL_GLOBAL" -eq 1 ]; then
    echo "linuwux: global launcher installed to $GLOBAL_BIN_PATH"
fi

echo
echo "Set your game's launch command to:"
echo "  $BIN_PATH %command%"

if [ "$INSTALL_GLOBAL" -eq 1 ]; then
    echo
    echo "Bare 'linuwux' now resolves through $GLOBAL_BIN_PATH."
else
    echo
    echo "GUI launchers may not inherit $BIN_DIR in PATH. Use the absolute path above"
    echo "for Steam, Faugus, Lutris, and other desktop launchers."
    echo "To make bare 'linuwux' available, rerun this installer with --global."
fi

echo
echo "In a launcher that only accepts environment variables, set:"
echo "  LD_PRELOAD=$LIB_PATH"
echo "Keep any existing LD_PRELOAD value and prepend LinUwUx with a colon."
