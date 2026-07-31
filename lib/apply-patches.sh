#!/usr/bin/env bash
# Traditional .patch apply + GE protonprep.
# Sourced by build.sh — requires lib/common.sh already loaded.

apply_patch_file() {
    local patch_file="$1" label="$2" log="$3"
    {
        echo "$HR"
        echo "[$(ts)] Applying: $label"
        echo "$HR"
    } >> "$log" 2>&1

    if patch -Np1 --forward --fuzz=0 < "$patch_file" >> "$log" 2>&1; then
        plog "  $label applied"
        return 0
    else
        plog_warn "  $label FAILED to apply – see $log"
        return 1
    fi
}

apply_linuwux_patches() {
    local wine_dir="$1"
    local patch_log="${PATCH_LOG:-${LOG_DIR}/linuwux-patches.log}"
    local failures=0
    plog "Applying traditional .patch files to $wine_dir ..."

    pushd "$wine_dir" > /dev/null

    while IFS= read -r patch_file; do
        apply_patch_file "$patch_file" "$(basename "$patch_file")" "$patch_log" \
            || failures=$((failures+1))
    done < <(find "$SRC_DIR/patches/wine" -name '*.patch' | sort)

    if grep -q 'linuwux-cpuid-handler\|0x336933' dlls/ntdll/unix/signal_x86_64.c; then
        plog "  CPUID leaf handling is present"
    else
        plog_warn "  CPUID leaf handling is missing"
        failures=$((failures+1))
    fi

    plog "Regenerating server protocol (tools/make_requests)..."
    [[ -x tools/make_requests ]] || plog_die "tools/make_requests missing or not executable"
    ./tools/make_requests >> "$patch_log" 2>&1 \
        || plog_die "tools/make_requests failed – see $patch_log"

    if ! grep -rq 'set_faketime' include/wine/server_protocol.h server/request.h server/protocol.h 2>/dev/null; then
        plog_die "set_faketime missing from generated server protocol headers after make_requests"
    fi
    plog "  set_faketime present in server protocol headers"

    popd > /dev/null

    if [[ $failures -gt 0 ]]; then
        plog_die "$failures LinUwUx patch step(s) failed - see $patch_log (stopping rather than shipping a build silently missing them)"
    fi
    plog "LinUwUx patch session complete"
}

ge_protonprep() {
    local prep_script
    prep_script=$(find patches -maxdepth 1 -name 'protonprep*.sh' | head -1)
    if [[ -z "$prep_script" ]]; then
        warn "No protonprep script found – continuing"
        return
    fi
    info "Running GE protonprep..."
    bash "$prep_script" 2>&1 | tee "$LOG_DIR/prep.log" || warn "protonprep returned non-zero"

    local fail_lines
    fail_lines=$(grep -ic 'fail' "$LOG_DIR/prep.log" 2>/dev/null || true)
    if [[ "${fail_lines:-0}" -gt 0 ]]; then
        warn "protonprep log contains ${fail_lines} line(s) mentioning 'fail' – review $LOG_DIR/prep.log:"
        grep -i 'fail' "$LOG_DIR/prep.log" | sed 's|^|      |'
    else
        info "protonprep log clean – no failures mentioned"
    fi
}
