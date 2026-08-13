#!/usr/bin/env bash
# Copyright (C) 2026 brcly
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: AGPL-3.0-or-later

set -euo pipefail

# ============================================================
# LinUwUx preload builder
#
# Compiles liblinuwux_preload.so -- an LD_PRELOAD library carrying all of
# LinUwUx's CPUID spoofing, SIGSYS/DenuvOwO redirect, HwProfileGuid,
# faketime, and DLL-override handling. Nothing else: no Proton/Wine
# source is cloned, patched, or built. See src/linuwux_preload.c for
# the mechanism.
# ============================================================

VERSION="26.08.13"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${SCRIPT_DIR}/src/linuwux_preload.c"
DIST_DIR="${SCRIPT_DIR}/dist"
INSTALL=0

if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    RED='' GREEN='' CYAN='' BOLD='' RESET=''
fi

ts() { date '+%H:%M:%S'; }

die()  { echo -e "${RED}[$(ts)] ERROR: $*${RESET}" >&2; exit 1; }
info() { echo -e "${GREEN}[$(ts)] ==> $*${RESET}"; }
header(){ echo -e "\n${CYAN}${BOLD}$*${RESET}"; }
need() { command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not found"; }

HR="$(printf '=%.0s' {1..60})"

trap 'echo -e "\n${RED}[$(ts)] Build failed${RESET}" >&2' ERR

usage() {
    cat << EOF
LinUwUx preload builder v${VERSION}

Build liblinuwux_preload.so -- an LD_PRELOAD library that installs the
LinUwUx DenuvOwO hypervisor-bypass patch set into GE-Proton or CachyOS
Proton. Nothing to clone, patch, or configure on the Proton side.
Official Valve Proton is not currently supported.

Usage:
  $(basename "$0") [OPTIONS]

Options:
  --install                   Also install to ~/.local/lib + a 'linuwux'
                               wrapper in ~/.local/bin, for a plain
                               'linuwux %command%' launch option
  -h, --help                  Show this help

Environment:
  LINUWUX_DEBUG=1             Runtime: event tracing from liblinuwux_preload.so
  LINUWUX_REDIRECT_ALL=1      Runtime: disable SIGSYS Wine-PE scope filter
  PROTON_AVX=1                Runtime: AVX/XSAVE in spoofed CPUID/KUSER data

Everything liblinuwux_preload.so does -- CPUID spoofing, SIGSYS/DenuvOwO
redirect, HwProfileGuid, faketime, and DLL overrides (winmm/version/
reflex=n,b, PROTON_DISABLE_LSTEAMCLIENT) -- happens live at load time
from inside the library itself. Wine's own source is never touched, no
prefix registry file needs importing, no launcher script needs
editing. Use it with an existing GE-Proton or CachyOS Proton install
(append, don't replace, LD_PRELOAD -- a bare LD_PRELOAD=... clobbers
Steam's own overlay preload entry):

  LD_PRELOAD="\${LD_PRELOAD}:/path/to/liblinuwux_preload.so" %command%

Required files:
  src/linuwux_preload.c
  src/linuwux.sh          (only for --install)

EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)   usage ;;
        --install) INSTALL=1; shift ;;
        *)
            die "Unknown argument: $1  (use --help)"
            ;;
    esac
done

already_installed() {
    [[ -f "${HOME}/.local/lib/liblinuwux_preload.so" ]]
}

# Compile liblinuwux_preload.so and drop it in dist/. No Proton/Wine
# source is touched or needed.
build_preload() {
    local out="${DIST_DIR}/liblinuwux_preload.so"

    info "Building liblinuwux_preload.so ..."
    [[ -f "$SRC" ]] || die "$SRC not found"
    need gcc

    mkdir -p "$DIST_DIR"
    gcc -std=gnu11 -O2 -fPIC -shared -Wall -o "$out" "$SRC" -ldl \
        || die "Failed to compile liblinuwux_preload.so"

    echo
    header "$HR"
    header "  BUILD SUCCESSFUL"
    header "$HR"
    echo -e "  ${BOLD}Library${RESET}  : $out"
    header "$HR"
    echo

    if [[ $INSTALL -eq 1 ]] || already_installed; then
        return 0
    fi

    echo "Use it with an existing GE-Proton or CachyOS Proton install -- add to that"
    echo "game's launch options (append, don't replace, LD_PRELOAD -- a bare"
    echo "LD_PRELOAD=... clobbers Steam's own overlay preload entry):"
    echo "  LD_PRELOAD=\"\${LD_PRELOAD}:$out\" %command%"
    echo
    echo "Or run with --install for a 'linuwux %command%' launch option instead."
    echo
}

# If a previous --install exists, keep it in sync automatically -- so
# "installed once" stays current on every plain rebuild too, not just
# when --install is passed again.
refresh_installed_copy() {
    local out="${DIST_DIR}/liblinuwux_preload.so"
    local dest="${HOME}/.local/lib/liblinuwux_preload.so"

    cp -f "$out" "$dest"
    info "Refreshed installed copy → $dest"
}

# Install the library plus a 'linuwux' wrapper under ~/.local so launch
# options don't need a raw LD_PRELOAD path.
install_preload() {
    local src="${DIST_DIR}/liblinuwux_preload.so"
    local wrapper_src="${SCRIPT_DIR}/src/linuwux.sh"
    local libdir="${HOME}/.local/lib"
    local bindir="${HOME}/.local/bin"
    local dest="${libdir}/liblinuwux_preload.so"
    local wrapper="${bindir}/linuwux"

    [[ -f "$src" ]] || die "Nothing to install -- build liblinuwux_preload.so first"
    [[ -f "$wrapper_src" ]] || die "$wrapper_src not found"

    mkdir -p "$libdir" "$bindir"
    cp -f "$src" "$dest"
    info "Installed library → $dest"

    cp -f "$wrapper_src" "$wrapper"
    chmod 0755 "$wrapper"
    info "Installed wrapper  → $wrapper"

    echo
    header "$HR"
    header "  INSTALL SUCCESSFUL"
    header "$HR"
    echo -e "  ${BOLD}Library${RESET}  : $dest"
    echo -e "  ${BOLD}Wrapper${RESET}  : $wrapper"
    header "$HR"
    echo
    echo "Steam launch options for any GE-Proton / CachyOS game:"
    echo "  ${wrapper} %command%"
    echo
    if [[ ":$PATH:" == *":${bindir}:"* ]]; then
        echo "${bindir} is already on your PATH, so this also works from a terminal"
        echo "(Lutris, Heroic, bare umu-run, etc.):"
        echo "  linuwux %command%"
        echo
    else
        echo "${bindir} is not on your PATH yet. That only matters for a terminal,"
        echo "Lutris, or Heroic -- Steam uses the absolute path above regardless."
        echo "To get the plain 'linuwux' command elsewhere, add this to ~/.bashrc"
        echo "(or equivalent) and open a new terminal:"
        echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
        echo
    fi
    echo "LINUWUX_PRELOAD=/other/path overrides the library the wrapper loads."
    echo
    echo "Advanced (no wrapper) — absolute path only, never relative:"
    echo "  LD_PRELOAD=\"\${LD_PRELOAD}:$dest\" %command%"
    echo
}

build_preload
if [[ $INSTALL -eq 1 ]]; then
    install_preload
elif already_installed; then
    refresh_installed_copy
fi
exit 0
