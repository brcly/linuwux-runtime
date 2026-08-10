#!/usr/bin/env bash
# Copyright (C) 2026 brcly
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Sourced from apply-content.sh (or build.sh). Injects native DLL overrides
# into the proton launcher so winmm/version/reflex always load as n,b.

apply_proton_dll_overrides() {
    local target="${SRC_DIR}/proton"
    local stub
    local anchor_line
    local brace_line

    plog "Applying LinUwUx DLL overrides to $target ..."
    [[ -f "$target" ]] || plog_die "$target not found – proton script missing"

    if grep -qF 'linuwux-dll-overrides' "$target"; then
        plog "  DLL overrides already present"
    else
        anchor_line=$(grep -n 'winebth\.sys' "$target" | head -1 | cut -d: -f1)
        [[ -n "$anchor_line" ]] || plog_die "Could not find winebth.sys in $target – upstream dlloverrides layout changed"

        stub=$(mktemp -p "$(dirname "$target")")
        cat > "$stub" <<'STUB'
                # linuwux-dll-overrides
                "winmm": "n,b",
                "version": "n,b",
                "reflex": "n,b",
STUB
        insert_after_line "$target" "$anchor_line" "$stub"
        rm -f "$stub"
        grep -qF 'linuwux-dll-overrides' "$target" || plog_die "DLL overrides insert produced no change"
        plog "  Inserted winmm/version/reflex=n,b after winebth.sys (line $anchor_line)"
    fi

    if grep -qF 'linuwux-disable-lsteamclient' "$target"; then
        plog "  PROTON_DISABLE_LSTEAMCLIENT gate already present"
        return
    fi

    brace_line=$(awk '
        /winebth\.sys/ { seen = 1; next }
        seen && /^[[:space:]]*\}[[:space:]]*$/ { print NR; exit }
    ' "$target")
    [[ -n "$brace_line" ]] || plog_die "Could not find closing brace of dlloverrides after winebth.sys"

    stub=$(mktemp -p "$(dirname "$target")")
    cat > "$stub" <<'STUB'

        # linuwux-disable-lsteamclient
        # Prefer stock steamclient over Proton's lsteamclient for DenuvOwO packs.
        if "PROTON_DISABLE_LSTEAMCLIENT" not in os.environ:
            os.environ["PROTON_DISABLE_LSTEAMCLIENT"] = "1"
            self.env["PROTON_DISABLE_LSTEAMCLIENT"] = "1"
STUB
    insert_after_line "$target" "$brace_line" "$stub"
    rm -f "$stub"
    grep -qF 'linuwux-disable-lsteamclient' "$target" || plog_die "lsteamclient gate insert produced no change"
    plog "  Inserted PROTON_DISABLE_LSTEAMCLIENT default after dlloverrides brace (line $brace_line)"
}
