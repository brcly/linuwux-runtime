#!/usr/bin/env bash
# Content-based inserts (additive LinUwUx fragments under patches/base/).
# Sourced by build.sh — requires lib/common.sh already loaded.
#
# Bulk logic: patches/base/linuwux_hooks.c (copied into ntdll/unix, #include'd).
# Tiny Wine call sites are written inline here — no one-line fragment files.

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

# Copy external hooks source into the wine tree and #include it once, before
# the Linux sigsys_handler (so REG_* macros already exist).
apply_linuwux_hooks() {
    local wine_dir="$1"
    local unix_dir="${wine_dir}/dlls/ntdll/unix"
    local target="${unix_dir}/signal_x86_64.c"
    local hooks_src="${PATCHES_DIR}/base/linuwux_hooks.c"
    local hooks_dst="${unix_dir}/linuwux_hooks.c"
    local stub tmp

    plog "Installing linuwux_hooks.c into $unix_dir ..."
    [[ -f "$target" ]]    || plog_die "$target not found - wine's layout may have changed upstream"
    [[ -f "$hooks_src" ]] || plog_die "$hooks_src not found - expected under patches/base/"

    cp "$hooks_src" "$hooks_dst"
    plog "  Copied linuwux_hooks.c"

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
    local handler_label="CPUID spoof"
    local stub

    if [[ $LEGACY_REFLEX -eq 1 ]]; then
        local handler_file="${PATCHES_DIR}/legacy-reflex/base/cpuid_legacy_reflex_handler.c"
        handler_label="legacy Reflex CPUID"
        plog "Applying $handler_label call site to $target ..."
        [[ -f "$target" ]]       || plog_die "$target not found - wine's layout may have changed upstream"
        [[ -f "$handler_file" ]] || plog_die "$handler_file not found - expected for $handler_label"

        if grep -qF 'linuwux-cpuid-handler' "$target" && ! grep -qF 'linuwux-cpuid-handler-call' "$target"; then
            plog "  Handler logic already present"
            return
        fi
        local func_line anchor_line
        func_line=$(grep -n '^static void segv_handler' "$target" | head -1 | cut -d: -f1)
        [[ -n "$func_line" ]] || plog_die "Could not find 'static void segv_handler' in $target"
        anchor_line=$(awk -v start="$func_line" '
            NR >= start && /void[[:space:]]*\*[[:space:]]*steamclient_addr[[:space:]]*=[[:space:]]*NULL/ { print NR; exit }
        ' "$target")
        [[ -n "$anchor_line" ]] || plog_die "Could not find steamclient_addr inside segv_handler"
        insert_after_line "$target" "$anchor_line" "$handler_file"
        grep -qF 'linuwux-cpuid-handler' "$target" || plog_die "legacy handler insert produced no change"
        plog "  Inserted legacy handler after line $anchor_line"
        return
    fi

    plog "Applying $handler_label call stub to $target ..."
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

apply_legacy_reflex_definitions_fix() {
    local wine_dir="$1"
    local target="${wine_dir}/dlls/ntdll/unix/signal_x86_64.c"
    local defs_file="${PATCHES_DIR}/legacy-reflex/base/cpuid_legacy_reflex_defs.c"

    [[ $LEGACY_REFLEX -eq 1 ]] || return 0

    plog "Applying legacy Reflex definitions to $target ..."
    [[ -f "$target" ]] || plog_die "$target not found - wine's layout may have changed upstream"
    [[ -f "$defs_file" ]] || plog_die "$defs_file not found - expected for legacy Reflex"

    if grep -q '^uint64_t LegacyQuerySystemInformationHandler' "$target"; then
        plog "  Already present"
        return
    fi

    local anchor_line
    anchor_line=$(file_scope_anchor "$target")
    insert_after_line "$target" "$anchor_line" "$defs_file"
    grep -q '^uint64_t LegacyQuerySystemInformationHandler' "$target" \
        || plog_die "legacy Reflex defs insert produced no change"
    plog "  Inserted legacy Reflex definitions after line $anchor_line (file scope)"
}

# Overlay legacy SIGSYS routing into the external hooks file (not signal_x86_64.c).
apply_legacy_reflex_sigsys_fix() {
    local wine_dir="$1"
    local target="${wine_dir}/dlls/ntdll/unix/linuwux_hooks.c"
    local handler_file="${PATCHES_DIR}/legacy-reflex/base/legacy_reflex_sigsys_handler.c"
    local count tmp

    [[ $LEGACY_REFLEX -eq 1 ]] || return 0

    plog "Applying legacy Reflex SIGSYS routing to $target ..."
    [[ -f "$target" ]] || plog_die "$target not found - run apply_linuwux_hooks first"
    [[ -f "$handler_file" ]] || plog_die "$handler_file not found - expected for legacy Reflex"

    if grep -q 'LegacyQuerySystemInformationId &&' "$target"; then
        plog "  Already present"
        return
    fi

    count=$(grep -c 'if (TargetSysHandler != 0 &&' "$target" || true)
    [[ "$count" -eq 1 ]] || plog_die "Expected one SIGSYS routing block in $target, found $count"

    tmp=$(mktemp -p "$(dirname "$target")")
    awk -v handler="$handler_file" '
        BEGIN { if ((getline t < handler) < 0) exit 1; close(handler) }
        /if \(TargetSysHandler != 0 &&/ && !inserted {
            while ((getline l < handler) > 0) print l
            inserted = 1
        }
        { print }
        END { if (!inserted) exit 1 }
    ' "$target" > "$tmp" || { rm -f "$tmp"; plog_die "Could not insert legacy SIGSYS routing"; }
    chmod --reference="$target" "$tmp" 2>/dev/null || true
    mv "$tmp" "$target"
    grep -q 'LegacyQuerySystemInformationId &&' "$target" \
        || plog_die "legacy SIGSYS insert produced no change"
    plog "  Inserted legacy SIGSYS routing into linuwux_hooks.c"
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
