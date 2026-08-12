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

set -euo pipefail

# ============================================================
# LinUwUx preload builder
#
# Compiles liblinuwux_preload.so -- an LD_PRELOAD library carrying all of
# LinUwUx's CPUID spoofing, SIGSYS/DenuvOwO redirect, HwProfileGuid,
# faketime, and DLL-override handling. Nothing else: no Proton/Wine
# source is cloned, patched, or built. See patches/preload/
# linuwux_preload.c for the mechanism.
#
#   lib/common.sh         – logging helpers
#   lib/apply-preload.sh  – fetches patches/, builds the library
# ============================================================

VERSION="26.08.12"
PATCH_REPO="https://github.com/brcly/proton-LinUwUx-patch.git"
PATCH_BRANCH="${PATCH_BRANCH:-main}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATCHES_DIR="${SCRIPT_DIR}/patches"
DIST_DIR="${SCRIPT_DIR}/dist"
LIB_DIR="${SCRIPT_DIR}/lib"
UPDATE_PATCHES=0

# shellcheck source=lib/common.sh
source "${LIB_DIR}/common.sh"
# shellcheck source=lib/apply-preload.sh
source "${LIB_DIR}/apply-preload.sh"

trap 'echo -e "\n${RED}[$(ts)] Build failed${RESET}" >&2' ERR

usage() {
    cat << EOF
LinUwUx preload builder v${VERSION}

Build liblinuwux_preload.so -- an LD_PRELOAD library that installs the
LinUwUx DenuvOwO hypervisor-bypass patch set into GE-Proton or CachyOS
Proton. Nothing to clone, patch, or configure on the Proton side.
Official Valve Proton is not currently supported.

Usage:
  $(basename "$0") [OPTIONS]

Options:
  --update-patches            Delete and re-clone patches/ from this repo
  -h, --help                  Show this help

Environment:
  PATCH_BRANCH=<name>         Branch of this repo to clone when patches/ is
                              missing (default: main)
  LINUWUX_DEBUG=1             Runtime: event tracing from liblinuwux_preload.so
  LINUWUX_REDIRECT_ALL=1      Runtime: disable SIGSYS Wine-PE scope filter
  PROTON_AVX=1                Runtime: AVX/XSAVE in spoofed CPUID/KUSER data

Everything liblinuwux_preload.so does -- CPUID spoofing, SIGSYS/DenuvOwO
redirect, HwProfileGuid, faketime, and DLL overrides (winmm/version/
reflex=n,b, PROTON_DISABLE_LSTEAMCLIENT) -- happens live at load time
from inside the library itself. Wine's own source is never touched, no
prefix registry file needs importing, no launcher script needs
editing. Use it with an existing GE-Proton or CachyOS Proton install
(append, don't replace, LD_PRELOAD -- a bare LD_PRELOAD=... clobbers
Steam's own overlay preload entry):

  LD_PRELOAD="\${LD_PRELOAD}:/path/to/liblinuwux_preload.so" %command%

Required files:
  patches/preload/linuwux_preload.c

EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)   usage ;;
        --update-patches) UPDATE_PATCHES=1; shift ;;
        *)
            die "Unknown argument: $1  (use --help)"
            ;;
    esac
done

ensure_patches_dir
check_required_base_files
build_preload
