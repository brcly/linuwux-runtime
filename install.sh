#!/usr/bin/env bash
set -euo pipefail

REPO="${LINUWUX_REPO:-brcly/linuwux-runtime}"
VERSION="${LINUWUX_VERSION:-latest}"

LIB_DIR="$HOME/.local/share/linuwux"
BIN_DIR="$HOME/.local/bin"
LIB_PATH="$LIB_DIR/LinUwUx.so"
BIN_PATH="$BIN_DIR/linuwux"

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
#!/usr/bin/env bash
set -euo pipefail

lib="$LIB_PATH"

if [ ! -f "\$lib" ]; then
    echo "linuwux: \$lib not found; reinstall with install.sh" >&2
    exit 1
fi

if [ \$# -eq 0 ]; then
    echo "usage: linuwux <command> [args...]" >&2
    exit 1
fi

if [ -n "\${LD_PRELOAD:-}" ]; then
    export LD_PRELOAD="\$LD_PRELOAD:\$lib"
else
    export LD_PRELOAD="\$lib"
fi

exec "\$@"
EOF
chmod 0755 "$BIN_PATH"

echo "linuwux: installed library to $LIB_PATH"
echo "linuwux: installed launcher to $BIN_PATH"

case ":$PATH:" in
*":$BIN_DIR:"*) ;;
*)
    echo
    echo "Note: $BIN_DIR is not on your PATH. Add this to your shell profile:"
    echo "  export PATH=\"$BIN_DIR:\$PATH\""
    ;;
esac

echo
echo "Set your game's launch command to:"
echo "  linuwux %command%"
