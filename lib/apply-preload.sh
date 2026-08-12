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
# patches/preload/linuwux_preload.c for the mechanism and its known gaps
# (faketime leaf 0x336967 unsupported), and the "Interposition Sketch"
# design writeup for why this exists.
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

# Compile liblinuwux_preload.so and drop it into the built redist tree, so
# it ends up inside the packaged tarball. Run this AFTER run_configure_and_
# build() (needs the built "files/" tree to already exist) and BEFORE
# package_and_verify() (which tars up whatever's in the redist dir).
#
# LEAST VERIFIED PART of --preload-interposition: the redist-directory
# search below is copied from package_and_verify()'s own fallback logic in
# package.sh, but hasn't been confirmed against a real build's actual
# output layout. If make redist produces a tarball directly rather than a
# loose directory, this step finds nothing to inject into and warns
# instead of failing the whole build -- opt-in experimental step, so a
# soft failure here shouldn't block an otherwise-successful build.
build_preload_library() {
    local src="${PATCHES_DIR}/preload/linuwux_preload.c"
    local redist_dir="" dst_dir

    plog "Building liblinuwux_preload.so ..."
    [[ -f "$src" ]] || plog_die "$src not found"
    need gcc

    for candidate in redist dist "${BUILD_NAME}" *; do
        if [[ -d "$candidate" && ( -f "$candidate/proton" || -f "$candidate/version" ) ]]; then
            redist_dir="$candidate"
            break
        fi
    done

    if [[ -z "$redist_dir" ]]; then
        plog_warn "  Could not locate a loose redist directory to install liblinuwux_preload.so into (make redist may have produced a tarball directly) -- skipping. Build continues without preload interposition; see lib/apply-preload.sh if this needs adjusting for your build layout."
        return
    fi

    dst_dir="${redist_dir}/files/bin"
    mkdir -p "$dst_dir"
    gcc -std=gnu11 -O2 -fPIC -shared -Wall -o "${dst_dir}/liblinuwux_preload.so" "$src" -ldl \
        || plog_die "Failed to compile liblinuwux_preload.so"
    plog "  Built ${dst_dir}/liblinuwux_preload.so"
}
