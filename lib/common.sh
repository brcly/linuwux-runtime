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

# Shared helpers for the Proton + LinUwUx builder.
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

HR="$(printf '=%.0s' {1..60})"
