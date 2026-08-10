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
# Bulk logic: linuwux_hooks.c (or linuwux_hooks_legacy.c with --legacy-reflex),
# copied into ntdll/unix and #include'd. Tiny Wine call sites are inline here.
# Proton-script inserts (force wineboot) also live here.

apply_regedit_fix() {
    local wine_dir="$1"
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
    local wine_dir="$1"
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

# Copy hooks source into the wine tree and #include it once, before Linux
# sigsys_handler (so REG_* macros already exist).
# --legacy-reflex uses linuwux_hooks_legacy.c; otherwise linuwux_hooks.c.
apply_linuwux_hooks() {
    local wine_dir="$1"
    local unix_dir="${wine_dir}/dlls/ntdll/unix"
    local target="${unix_dir}/signal_x86_64.c"
    local hooks_src hooks_label
    local hooks_dst="${unix_dir}/linuwux_hooks.c"
    local stub

    if [[ $LEGACY_REFLEX -eq 1 ]]; then
        hooks_src="${PATCHES_DIR}/legacy-reflex/linuwux_hooks_legacy.c"
        hooks_label="linuwux_hooks_legacy.c"
    else
        hooks_src="${PATCHES_DIR}/base/linuwux_hooks.c"
        hooks_label="linuwux_hooks.c"
    fi

    plog "Installing $hooks_label into $unix_dir ..."
    [[ -f "$target" ]]    || plog_die "$target not found - wine's layout may have changed upstream"
    [[ -f "$hooks_src" ]] || plog_die "$hooks_src not found"

    cp "$hooks_src" "$hooks_dst"
    plog "  Copied $hooks_label → linuwux_hooks.c"

    if grep -qF 'linuwux-hooks-include' "$target"; then
        plog "  #include already present in signal_x86_64.c"
        return
    fi

    local test_line func_line
    test_line=$(grep -n '0xffff' "$target" | head -1 | cut -d: -f1)
    [[ -n "$test_line" ]] || plog_die "Could not find seccomp 0xffff test (Linux sigsys_handler) in $target"

    func_line=$(awk -v end="$test_line" '
        NR <= end && /^static void sigsys_handler/ { line = NR }
        END { if (line) print line }
    ' "$target")
    [[ -n "$func_line" ]] || plog_die "Could not find 'static void sigsys_handler' above 0xffff test"

    stub=$(mktemp -p "$(dirname "$target")")
    cat > "$stub" <<'EOF'
/* linuwux-hooks-include */
#include "linuwux_hooks.c"

EOF
    insert_before_line "$target" "$func_line" "$stub"
    rm -f "$stub"
    grep -qF 'linuwux-hooks-include' "$target" || plog_die "hooks include insert produced no change"
    plog "  Inserted #include \"linuwux_hooks.c\" before Linux sigsys_handler (line $func_line)"
}

apply_cpuid_spoof_handler_fix() {
    local wine_dir="$1"
    local target="${wine_dir}/dlls/ntdll/unix/signal_x86_64.c"
    local stub

    plog "Applying CPUID call stub to $target ..."
    [[ -f "$target" ]] || plog_die "$target not found - wine's layout may have changed upstream"

    if grep -qF 'linuwux-cpuid-handler-call' "$target"; then
        plog "  Handler call stub already present"
        return
    fi

    local func_line anchor_line
    func_line=$(grep -n '^static void segv_handler' "$target" | head -1 | cut -d: -f1)
    [[ -n "$func_line" ]] || plog_die "Could not find 'static void segv_handler' in $target"
    anchor_line=$(awk -v start="$func_line" '
        NR >= start && /void[[:space:]]*\*[[:space:]]*steamclient_addr[[:space:]]*=[[:space:]]*NULL/ { print NR; exit }
    ' "$target")
    [[ -n "$anchor_line" ]] || plog_die "Could not find steamclient_addr inside segv_handler"

    stub=$(mktemp -p "$(dirname "$target")")
    cat > "$stub" <<'EOF'
    /* linuwux-cpuid-handler-call */
    if (linuwux_cpuid_spoof(siginfo, sigcontext, ucontext))
        return;
EOF
    insert_after_line "$target" "$anchor_line" "$stub"
    rm -f "$stub"
    grep -qF 'linuwux-cpuid-handler-call' "$target" || plog_die "handler call stub insert produced no change"
    plog "  Inserted call stub after line $anchor_line (after steamclient_addr in segv_handler)"
}

apply_signal_init_process_hooks() {
    local wine_dir="$1"
    local target="${wine_dir}/dlls/ntdll/unix/signal_x86_64.c"
    local stub

    plog "Applying signal_init_process hooks to $target ..."
    [[ -f "$target" ]] || plog_die "$target not found - wine's layout may have changed upstream"

    if grep -q 'detect_cpu_vendor();' "$target"; then
        plog "  signal_init_process hooks already present"
        return
    fi

    local func_line
    func_line=$(grep -n 'signal_init_process' "$target" | head -1 | cut -d: -f1)
    [[ -n "$func_line" ]] || plog_die "Could not find signal_init_process in $target"

    local anchor_line
    anchor_line=$(awk -v start="$func_line" '
        NR >= start && /sigaction\( SIGSEGV, &sig_act, NULL \)/ { print NR; exit }
    ' "$target")
    [[ -n "$anchor_line" ]] || plog_die "Could not find SIGSEGV sigaction inside signal_init_process"

    stub=$(mktemp -p "$(dirname "$target")")
    cat > "$stub" <<'EOF'
    detect_cpu_vendor();
    syscall(SYS_arch_prctl, ARCH_SET_CPUID, 0);
EOF
    insert_after_line "$target" "$anchor_line" "$stub"
    rm -f "$stub"
    grep -q 'detect_cpu_vendor();' "$target" || plog_die "signal_init hooks insert produced no change"
    plog "  Inserted init hooks after line $anchor_line (after SIGSEGV registration)"
}

apply_sigsys_handler_fix() {
    local wine_dir="$1"
    local target="${wine_dir}/dlls/ntdll/unix/signal_x86_64.c"
    local stub

    plog "Applying SIGSYS call stub to $target ..."
    [[ -f "$target" ]] || plog_die "$target not found - wine's layout may have changed upstream"

    if grep -qF 'linuwux-sigsys-handler-call' "$target"; then
        plog "  SIGSYS call stub already present"
        return
    fi

    local test_line func_line
    test_line=$(grep -n '0xffff' "$target" | head -1 | cut -d: -f1)
    [[ -n "$test_line" ]] || plog_die "Could not find seccomp 0xffff test (Linux sigsys_handler) in $target"

    func_line=$(awk -v end="$test_line" '
        NR <= end && /^static void sigsys_handler/ { line = NR }
        END { if (line) print line }
    ' "$target")
    [[ -n "$func_line" ]] || plog_die "Could not find 'static void sigsys_handler' above 0xffff test"

    local anchor_line
    anchor_line=$(awk -v start="$func_line" -v end="$test_line" '
        NR >= start && NR <= end && /struct[[:space:]]+syscall_frame[[:space:]]*\*[[:space:]]*frame[[:space:]]*=[[:space:]]*get_syscall_frame/ {
            print NR; exit
        }
    ' "$target")
    [[ -n "$anchor_line" ]] || plog_die "Could not find get_syscall_frame() inside Linux sigsys_handler"

    stub=$(mktemp -p "$(dirname "$target")")
    cat > "$stub" <<'EOF'
    /* linuwux-sigsys-handler-call */
    if (linuwux_sigsys_route(sigcontext))
        return;
EOF
    insert_after_line "$target" "$anchor_line" "$stub"
    rm -f "$stub"
    grep -qF 'linuwux-sigsys-handler-call' "$target" || plog_die "sigsys call stub insert produced no change"
    plog "  Inserted call stub after line $anchor_line (Linux/HAVE_SECCOMP sigsys_handler only)"
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
# Native DLL overrides (winmm/version/reflex) + lsteamclient default
# shellcheck source=lib/apply-proton-dll.sh
source "$LIB_DIR/apply-proton-dll.sh"