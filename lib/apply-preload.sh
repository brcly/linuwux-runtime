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

# --preload-interposition (EXPERIMENTAL): build and install
# liblinuwux_preload.so instead of patching ntdll's source. See
# patches/preload/linuwux_preload.c for the mechanism (including faketime,
# leaf 0x336967 -- learned/extracted at build+runtime, no wine source
# modification needed), and the "Interposition Sketch" design writeup for
# why this exists.
#
# Sourced by build.sh — requires lib/common.sh already loaded.

# Content-insert LD_PRELOAD into the proton launcher script, appending to
# (never overwriting) any value already set -- Steam overlay / pressure-
# vessel may already use LD_PRELOAD for their own purposes. Reuses the same
# winebth.sys anchor as apply_proton_dll_overrides() in apply-content.sh,
# which is already proven to survive upstream reformatting.
apply_preload_ld_env() {
    local target="${SRC_DIR}/proton"
    local stub
    local brace_line

    plog "Applying LD_PRELOAD env insert to $target ..."
    [[ -f "$target" ]] || plog_die "$target not found – proton script missing"

    if grep -qF 'linuwux-preload-ld-env' "$target"; then
        plog "  LD_PRELOAD insert already present"
        return
    fi

    brace_line=$(awk '
        /winebth\.sys/ { seen = 1; next }
        seen && /^[[:space:]]*\}[[:space:]]*$/ { print NR; exit }
    ' "$target")
    [[ -n "$brace_line" ]] || plog_die "Could not find closing brace of dlloverrides after winebth.sys"

    stub=$(mktemp -p "$(dirname "$target")")
    cat > "$stub" <<'STUB'

        # linuwux-preload-ld-env
        _lu_preload = os.path.join(os.path.dirname(os.path.abspath(__file__)), "files", "bin", "liblinuwux_preload.so")
        if os.path.exists(_lu_preload):
            _lu_ld_existing = os.environ.get("LD_PRELOAD", "")
            _lu_ld_new = (_lu_ld_existing + ":" + _lu_preload) if _lu_ld_existing else _lu_preload
            os.environ["LD_PRELOAD"] = _lu_ld_new
            self.env["LD_PRELOAD"] = _lu_ld_new
STUB
    insert_after_line "$target" "$brace_line" "$stub"
    rm -f "$stub"
    grep -qF 'linuwux-preload-ld-env' "$target" || plog_die "LD_PRELOAD insert produced no change"
    plog "  Inserted LD_PRELOAD append after line $brace_line (after dlloverrides brace)"
}

# Extract REQ_set_faketime's value from this tree's own generated
# include/wine/server_protocol.h (a build artifact tools/make_requests
# already produced during apply_linuwux_patches() -- reading it here, not
# modifying it). The enum value is positionally generated -- it depends on
# every request defined before it in protocol.def -- so it varies by wine
# version/patch chain and can't be hardcoded. Prints the value on stdout,
# nothing on failure; caller decides how to treat a miss.
extract_req_set_faketime() {
    local server_protocol_h="${SRC_DIR}/wine/include/wine/server_protocol.h"
    [[ -f "$server_protocol_h" ]] || return 1

    awk '
        /^enum request$/ { in_enum=1; next }
        in_enum && /^\};/ { exit }
        in_enum && match($0, /REQ_[A-Za-z0-9_]+/) {
            name = substr($0, RSTART, RLENGTH)
            if (name == "REQ_set_faketime") { print count; found=1; exit }
            count++
        }
        END { if (!found) exit 1 }
    ' "$server_protocol_h"
}

# Compile liblinuwux_preload.so and get it into whatever redist artifact
# package_and_verify() will actually end up using. Run this AFTER
# run_configure_and_build() and BEFORE package_and_verify().
#
# make redist produces its OWN tarball directly, packaging a loose staging
# directory (also left on disk) at the point make redist finishes -- before
# this function ever runs. package_and_verify() checks for that pre-built
# tarball FIRST and uses it as-is if found, only falling back to re-tarring
# a loose directory when no tarball exists yet. Confirmed the hard way: an
# earlier version of this function only handled the loose-directory case,
# silently injecting the library into a directory that had already been
# tarred up and was never looked at again -- correctly built, silently
# unused. This handles both paths package_and_verify() can take, in the
# same priority order it uses.
build_preload_library() {
    local src="${PATCHES_DIR}/preload/linuwux_preload.c"
    local so_tmp tarball
    local req_faketime

    plog "Building liblinuwux_preload.so ..."
    [[ -f "$src" ]] || plog_die "$src not found"
    need gcc

    if req_faketime=$(extract_req_set_faketime); then
        plog "  REQ_set_faketime=${req_faketime} (from this tree's server_protocol.h) -- faketime support enabled"
    else
        req_faketime=-1
        plog_warn "  Could not determine REQ_set_faketime from ${SRC_DIR}/wine/include/wine/server_protocol.h -- faketime (cpuid leaf 0x336967) will log and no-op at runtime. Build continues."
    fi

    so_tmp=$(mktemp -p "$PWD" liblinuwux_preload.XXXXXX.so)
    gcc -std=gnu11 -O2 -fPIC -shared -Wall -DLINUWUX_REQ_SET_FAKETIME="${req_faketime}" -o "$so_tmp" "$src" -ldl \
        || plog_die "Failed to compile liblinuwux_preload.so"
    plog "  Compiled $(basename "$so_tmp")"

    tarball=$(find . -maxdepth 3 \( -name '*.tar.gz' -o -name '*.tar.xz' \) 2>/dev/null | head -1)

    if [[ -n "$tarball" ]]; then
        plog "  Found existing redist tarball ($tarball) -- injecting into it directly"
        local work inner
        work=$(mktemp -d -p "$PWD")
        if [[ "$tarball" == *.tar.xz ]]; then
            tar -xJf "$tarball" -C "$work" || plog_die "Failed to extract $tarball"
        else
            tar -xzf "$tarball" -C "$work" || plog_die "Failed to extract $tarball"
        fi
        inner=$(find "$work" -maxdepth 1 -mindepth 1 -type d | head -1)
        [[ -n "$inner" ]] || plog_die "Could not find the extracted redist tree inside $tarball"

        mkdir -p "$inner/files/bin"
        cp "$so_tmp" "$inner/files/bin/liblinuwux_preload.so"

        rm -f "$tarball"
        if [[ "$tarball" == *.tar.xz ]]; then
            need xz
            tar -cJf "$tarball" -C "$work" "$(basename "$inner")" || plog_die "Failed to re-pack $tarball"
        else
            tar -czf "$tarball" -C "$work" "$(basename "$inner")" || plog_die "Failed to re-pack $tarball"
        fi
        rm -rf "$work"
        plog "  Re-packed $tarball with liblinuwux_preload.so included"
    else
        local redist_dir=""
        for candidate in redist dist "${BUILD_NAME}" *; do
            if [[ -d "$candidate" && ( -f "$candidate/proton" || -f "$candidate/version" ) ]]; then
                redist_dir="$candidate"
                break
            fi
        done

        if [[ -z "$redist_dir" ]]; then
            plog_warn "  Could not locate a redist tarball or loose directory to install liblinuwux_preload.so into -- skipping. Build continues without preload interposition; see lib/apply-preload.sh if this needs adjusting for your build layout."
            rm -f "$so_tmp"
            return
        fi

        mkdir -p "${redist_dir}/files/bin"
        cp "$so_tmp" "${redist_dir}/files/bin/liblinuwux_preload.so"
        plog "  Installed into loose redist dir ${redist_dir}/files/bin/liblinuwux_preload.so"
    fi

    rm -f "$so_tmp"
}
