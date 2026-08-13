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

# Build liblinuwux_preload.so: an LD_PRELOAD library that installs LinUwUx's
# CPUID spoofing, SIGSYS/DenuvOwO redirect, HwProfileGuid, faketime, and
# DLL-override handling. Works against an existing GE-Proton or CachyOS
# Proton install (official Valve Proton not currently supported).
#
# Sourced by build.sh — requires lib/common.sh already loaded.

# Prefer an existing local patches/ tree; clone only when missing (or --update-patches).
ensure_patches_dir() {
    if [[ $UPDATE_PATCHES -eq 1 ]]; then
        info "--update-patches: removing existing patches/ so a fresh copy is fetched"
        rm -rf "$PATCHES_DIR"
    fi

    if [[ -d "$PATCHES_DIR" ]]; then
        info "Using existing patches/ folder ($PATCHES_DIR) – not re-downloading"
        info "  (pass --update-patches to force a fresh clone)"
    else
        info "Downloading LinUwUx patches..."
        need git
        local tmp_clone="${SCRIPT_DIR}/.tmp-patches-clone"
        rm -rf "$tmp_clone"
        git clone --depth 1 --branch "$PATCH_BRANCH" "$PATCH_REPO" "$tmp_clone" \
            || die "Failed to clone patch repository (branch $PATCH_BRANCH)"
        [[ -d "$tmp_clone/patches" ]] || die "Cloned patch repo has no patches/ folder"
        mv "$tmp_clone/patches" "$PATCHES_DIR"
        rm -rf "$tmp_clone"
    fi
}

check_required_base_files() {
    info "Checking required base files..."
    [[ -f "${PATCHES_DIR}/preload/linuwux_preload.c" ]] \
        || die "linuwux_preload.c not found under ${PATCHES_DIR}/preload/ – required"
    need gcc
    info "  Base files present"
}

already_installed() {
    [[ -f "${HOME}/.local/lib/liblinuwux_preload.so" ]]
}

# Compile liblinuwux_preload.so and drop it in dist/. No Proton/Wine
# source is touched or needed.
build_preload() {
    local src="${PATCHES_DIR}/preload/linuwux_preload.c"
    local out="${DIST_DIR}/liblinuwux_preload.so"

    info "Building liblinuwux_preload.so ..."
    [[ -f "$src" ]] || die "$src not found"
    need gcc

    mkdir -p "$DIST_DIR"
    gcc -std=gnu11 -O2 -fPIC -shared -Wall -o "$out" "$src" -ldl \
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
    local libdir="${HOME}/.local/lib"
    local bindir="${HOME}/.local/bin"
    local dest="${libdir}/liblinuwux_preload.so"
    local wrapper="${bindir}/linuwux"

    [[ -f "$src" ]] || die "Nothing to install -- build liblinuwux_preload.so first"

    mkdir -p "$libdir" "$bindir"
    cp -f "$src" "$dest"
    info "Installed library → $dest"

    cat > "$wrapper" <<'EOF'
#!/bin/sh
# linuwux -- launch helper for liblinuwux_preload.so
lib="${LINUWUX_PRELOAD:-${HOME}/.local/lib/liblinuwux_preload.so}"
if [ ! -f "$lib" ]; then
    echo "linuwux: library not found: $lib" >&2
    echo "  Build/install it from proton-LinUwUx-patch, or set LINUWUX_PRELOAD to its path" >&2
    exit 1
fi
if [ "$#" -eq 0 ]; then
    echo "linuwux: no command given -- use it as a Steam launch option:" >&2
    echo "  ~/.local/bin/linuwux %command%" >&2
    exit 1
fi
export LD_PRELOAD="${LD_PRELOAD:+$LD_PRELOAD:}$lib"
exec "$@"
EOF
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
    echo "Launch options for any GE-Proton / CachyOS game:"
    echo "  ${wrapper} %command%"
    echo
    if [[ ":$PATH:" == *":${bindir}:"* ]]; then
        echo "${bindir} is already on your PATH, so this also works from a terminal"
        echo "(Steam, Lutris, Heroic, bare umu-run, etc.):"
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
