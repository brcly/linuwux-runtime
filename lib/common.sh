#!/usr/bin/env bash
# Shared helpers for Proton + LinUwUx builder.
# Sourced by build.sh — do not execute directly.

if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    RED='' GREEN='' YELLOW='' CYAN='' BOLD='' RESET=''
fi

ts() { date '+%H:%M:%S'; }

die()  { echo -e "${RED}[$(ts)] ERROR: $*${RESET}" >&2; exit 1; }
info() { echo -e "${GREEN}[$(ts)] ==> $*${RESET}"; }
warn() { echo -e "${YELLOW}[$(ts)] WARNING: $*${RESET}" >&2; }
header(){ echo -e "\n${CYAN}${BOLD}$*${RESET}"; }
need() { command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not found"; }
pause(){ [[ "${SLOW:-0}" == "1" ]] && sleep 1.2; return 0; }

# Mirror console messages into the patch session log when it is open.
plog() {
    info "$@"
    [[ -n "${PATCH_LOG:-}" ]] && echo "[$(ts)] ==> $*" >> "$PATCH_LOG"
}
plog_warn() {
    warn "$@"
    [[ -n "${PATCH_LOG:-}" ]] && echo "[$(ts)] WARNING: $*" >> "$PATCH_LOG"
}
plog_die() {
    [[ -n "${PATCH_LOG:-}" ]] && echo "[$(ts)] ERROR: $*" >> "$PATCH_LOG"
    die "$@"
}

HR="$(printf '=%.0s' {1..60})"

file_scope_anchor() {
    local target="$1"
    local line
    line=$(grep -n '^#include "dwarf.h"' "$target" | head -1 | cut -d: -f1)
    if [[ -z "$line" ]]; then
        line=$(head -n 120 "$target" | grep -n '^#include' | tail -1 | cut -d: -f1)
    fi
    [[ -n "$line" ]] || plog_die "No safe file-scope insertion point found in $target"
    echo "$line"
}

insert_after_line() {
    local target="$1" line="$2" content_file="$3"
    [[ -r "$content_file" ]] || plog_die "insert_after_line: unreadable $content_file"
    local tmp
    tmp=$(mktemp -p "$(dirname "$target")")
    awk -v line="$line" -v content="$content_file" '
        BEGIN { if ((getline t < content) < 0) exit 1; close(content) }
        NR == line { print; while ((getline l < content) > 0) print l; next }
        { print }
    ' "$target" > "$tmp" || { rm -f "$tmp"; plog_die "insert_after_line: awk failed on $target"; }
    chmod --reference="$target" "$tmp" 2>/dev/null || true
    mv "$tmp" "$target"
}

insert_before_line() {
    local target="$1" line="$2" content_file="$3"
    [[ -r "$content_file" ]] || plog_die "insert_before_line: unreadable $content_file"
    local tmp
    tmp=$(mktemp -p "$(dirname "$target")")
    awk -v line="$line" -v content="$content_file" '
        BEGIN { if ((getline t < content) < 0) exit 1; close(content) }
        NR == line { while ((getline l < content) > 0) print l; print; next }
        { print }
    ' "$target" > "$tmp" || { rm -f "$tmp"; plog_die "insert_before_line: awk failed on $target"; }
    chmod --reference="$target" "$tmp" 2>/dev/null || true
    mv "$tmp" "$target"
}
