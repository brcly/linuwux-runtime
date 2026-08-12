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

# Pre-flight check: verify every grep anchor lib/apply-content.sh relies on
# actually resolves against a real, unpatched wine tree -- before spending a
# full build on it. Run against both a CachyOS/GE-11-3-style tree and a
# GE-11-5+ tree when checking cross-tree compatibility.
#
# Usage: tools/verify-anchors.sh <path-to-wine-checkout>

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $(basename "$0") <path-to-wine-checkout>" >&2
    exit 2
fi

target="$1/dlls/ntdll/unix/signal_x86_64.c"
if [[ ! -f "$target" ]]; then
    echo "not found: $target" >&2
    exit 1
fi

fail=0

check() {
    local desc="$1" pattern="$2"
    if grep -qF "$pattern" "$target"; then
        echo "  OK    $desc"
    else
        echo "  FAIL  $desc  (pattern: $pattern)"
        fail=1
    fi
}

echo "Checking $target ..."
check "SIGSYS trace string (sigsys_handler)" 'SIGSYS, rax %#'
check "segv_handler present"                 'static void segv_handler'
check "steamclient_addr anchor (segv_handler)" 'steamclient_addr = NULL'
check "signal_init_process present"          'signal_init_process'
check "SIGSEGV sigaction registration"       'sigaction( SIGSEGV, &sig_act, NULL )'

sud=0
grep -qE 'amd64_thread_data,[[:space:]]*syscall_dispatch' "$target" && sud=1
echo "  INFO  Syscall User Dispatch support: $([[ $sud -eq 1 ]] && echo yes || echo no)"

if [[ $fail -eq 0 ]]; then
    echo "All anchors resolved."
else
    echo "One or more anchors did not resolve -- apply-content.sh will plog_die on this tree." >&2
fi

exit $fail
