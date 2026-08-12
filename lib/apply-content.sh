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

# Content-based inserts (additive LinUwUx fragments under patches/base/).
# Sourced by build.sh — requires lib/common.sh already loaded.
#
# CPUID/SIGSYS/faketime logic all lives in liblinuwux_preload.so (see
# apply-preload.sh) -- ntdll's signal_x86_64.c is never touched. This file
# only handles the small additive fragments Wine itself still needs:
# HwProfileGuid regedit fix, the set_faketime server protocol definition,
# and the proton-script inserts (force wineboot).

apply_regedit_fix() {
    local wine_dir="wine"
    local inf="${wine_dir}/loader/wine.inf.in"
    local content_file="${PATCHES_DIR}/base/hwprofile_guid.reg"

    plog "Applying regedit fix (HwProfileGuid) to $inf ..."
    [[ -f "$inf" ]]          || plog_die "$inf not found - wine's layout may have changed upstream"
    [[ -f "$content_file" ]] || plog_die "$content_file not found - expected under patches/base/"

    if grep -q 'HwProfileGuid' "$inf"; then
        plog "  HwProfileGuid already present"
    else
        cat "$content_file" >> "$inf"
        echo >> "$inf"
        plog "  Appended HwProfileGuid line from $content_file"
    fi
}

apply_faketime_protocol_fix() {
    local wine_dir="wine"
    local proto="${wine_dir}/server/protocol.def"
    local content_file="${PATCHES_DIR}/base/set_faketime.protocol"

    plog "Applying faketime request definition to $proto ..."
    [[ -f "$proto" ]]          || plog_die "$proto not found - wine's layout may have changed upstream"
    [[ -f "$content_file" ]]   || plog_die "$content_file not found - expected under patches/base/"

    if grep -q '@REQ(set_faketime)' "$proto"; then
        plog "  set_faketime request already present"
    else
        echo >> "$proto"
        cat "$content_file" >> "$proto"
        plog "  Appended set_faketime request from $content_file"
    fi
}

# Force one wineboot -u on a fresh prefix. Context-diff patches against proton
# break when surrounding lines shift; anchor on the stable setup_prefix call.
apply_force_wineboot_first_run() {
    local target="${SRC_DIR}/proton"
    local stub
    local anchor_line

    plog "Applying force-wineboot first-run gate to $target ..."
    [[ -f "$target" ]] || plog_die "$target not found – proton script missing"

    if grep -qF 'linuwux-force-wineboot' "$target"; then
        plog "  force-wineboot gate already present"
        return
    fi

    # Prefer the update_prefix_files → setup_prefix() pair; fall back to any
    # g_compatdata.setup_prefix() if the if-line was reformatted upstream.
    anchor_line=$(awk '
        /if[[:space:]]+update_prefix_files:/ { seen = 1; next }
        seen && /g_compatdata\.setup_prefix\(\)/ { print NR; exit }
    ' "$target")
    if [[ -z "$anchor_line" ]]; then
        anchor_line=$(grep -n 'g_compatdata\.setup_prefix()' "$target" | head -1 | cut -d: -f1)
    fi
    [[ -n "$anchor_line" ]] || plog_die "Could not find g_compatdata.setup_prefix() after update_prefix_files in $target"

    stub=$(mktemp -p "$(dirname "$target")")
    cat > "$stub" <<'EOF'

        # linuwux-force-wineboot
        # Fresh prefixes under LinUwUx need an explicit wineboot pass before
        # the game will run. setup_prefix/createprefix alone is not enough.
        # Marker ensures this runs once per prefix, not every launch.
        _wb_marker = g_compatdata.path("linuwux_wineboot_done")
        if not file_exists(_wb_marker, follow_symlinks=False):
            log("LinUwUx: first-time prefix, running wineboot -u")
            _wb_env = dict(self.env)
            _wb_env["WINEDEBUG"] = "-all"
            try:
                self.run_proc([g_proton.wine_bin, "wineboot", "-u"], _wb_env)
                self.run_proc([g_proton.wineserver_bin, "-w"], _wb_env)
                with open(_wb_marker, "w") as _f:
                    _f.write("1\n")
                log("LinUwUx: wineboot -u complete (cold-start gate)")
            except Exception as _e:
                log("LinUwUx: wineboot -u failed: %s" % _e)
EOF
    insert_after_line "$target" "$anchor_line" "$stub"
    rm -f "$stub"
    grep -qF 'linuwux-force-wineboot' "$target" || plog_die "force-wineboot insert produced no change"
    plog "  Inserted cold-start wineboot gate after line $anchor_line (after setup_prefix())"
}
