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
# Proton + LinUwUx Builder
#
# Thin orchestrator. Implementation lives under lib/:
#   common.sh         – logging, line-insert helpers
#   source.sh         – clone, submodules, stage patches/wine
#   apply-content.sh  – hooks install + content inserts
#   apply-patches.sh  – traditional .patch apply + GE protonprep
#   apply-proton-dll.sh – winmm/version/reflex + lsteamclient defaults
#   apply-preload.sh  – EXPERIMENTAL: --preload-interposition alternative
#   package.sh        – base checks, configure, redist, verify
# ============================================================

VERSION="26.08.12"
CONTAINER_ENGINE="podman"
PATCH_REPO="https://github.com/brcly/proton-LinUwUx-patch.git"
PATCH_BRANCH="${PATCH_BRANCH:-main}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATCHES_DIR="${SCRIPT_DIR}/patches"
DIST_DIR="${SCRIPT_DIR}/dist"
LIB_DIR="${SCRIPT_DIR}/lib"
FORCE=0
CLEAN=1
LEGACY_REFLEX=0
UPDATE_PATCHES=0
PRELOAD_INTERPOSITION=0
PATCH_LOG=""

# shellcheck source=lib/common.sh
source "${LIB_DIR}/common.sh"
# shellcheck source=lib/source.sh
source "${LIB_DIR}/source.sh"
# shellcheck source=lib/apply-content.sh
source "${LIB_DIR}/apply-content.sh"
# shellcheck source=lib/apply-patches.sh
source "${LIB_DIR}/apply-patches.sh"
# shellcheck source=lib/apply-proton-dll.sh
source "${LIB_DIR}/apply-proton-dll.sh"
# shellcheck source=lib/apply-preload.sh
source "${LIB_DIR}/apply-preload.sh"
# shellcheck source=lib/package.sh
source "${LIB_DIR}/package.sh"

trap 'echo -e "\n${RED}[$(ts)] Build failed – source/build trees left in place for debugging${RESET}" >&2' ERR

usage() {
    cat << EOF
Proton + LinUwUx Builder v${VERSION}

Build CachyOS or GE Proton from source with LinUwUx hooks applied.

Usage:
  $(basename "$0") [OPTIONS] [VARIANT] [BRANCH/TAG]

Variants:
  cachyos (default)   CachyOS Proton (latest cachyos-*-slr release tag if none given)
  ge                  GloriousEggroll Proton (latest GE-ProtonN-M tag if none given)

Examples:
  $(basename "$0")
  $(basename "$0") cachyos
  $(basename "$0") cachyos cachyos-11.0-20260703-slr
  $(basename "$0") cachyos cachyos-11.0-20260703-native
  $(basename "$0") ge
  $(basename "$0") ge GE-Proton11-3
  $(basename "$0") --legacy-reflex ge GE-Proton11-3
  $(basename "$0") --preload-interposition ge GE-Proton11-5
  $(basename "$0") --force --no-clean cachyos
  $(basename "$0") --update-patches
  $(basename "$0") --container-engine=docker ge

Options:
  -f, --force                 Full re-clone and clean rebuild
  -k, --no-clean              Keep -src/-build trees after a successful build
  --legacy-reflex             Use patches/legacy-reflex/linuwux_hooks_legacy.c
                              (older Reflex dual-trampoline protocol)
  --preload-interposition     EXPERIMENTAL: build liblinuwux_preload.so and
                              hook via LD_PRELOAD instead of patching
                              ntdll's source. See patches/preload/
                              linuwux_preload.c. Known gap: faketime CPUID
                              leaf (0x336967) is unsupported in this mode.
  --update-patches            Delete and re-clone patches/ from this repo
  --container-engine=<name>   Container engine (default: podman)
  -h, --help                  Show this help

Environment:
  PATCH_BRANCH=<name>         Branch of this repo to clone when patches/ is
                              missing (default: main)
  LINUWUX_DEBUG=1             Runtime: event tracing from linuwux_hooks*.c
  LINUWUX_REDIRECT_ALL=1      Runtime: disable SIGSYS Wine-PE scope filter
  PROTON_AVX=1                Runtime: AVX/XSAVE in spoofed CPUID/KUSER data

How hooks land:
  Bulk logic lives in patches/base/linuwux_hooks.c (or the legacy file).
  It is copied to dlls/ntdll/unix/linuwux_hooks.c and #include'd into
  signal_x86_64.c. Only tiny call stubs are pasted into the signal file.
  Proton cold-start wineboot is a content insert after setup_prefix().
  DLL overrides (winmm/version/reflex) and PROTON_DISABLE_LSTEAMCLIENT
  are content-inserted into the proton launcher script.

  --preload-interposition builds liblinuwux_preload.so from
  patches/preload/linuwux_preload.c instead and skips all of the above
  ntdll-side hooks -- it hooks sigaction()/prctl() via LD_PRELOAD (content-
  inserted into the proton launcher script) rather than patching
  signal_x86_64.c's source at all.

Required files:
  patches/base/linuwux_hooks.c
  patches/base/hwprofile_guid.reg
  patches/base/set_faketime.protocol
  patches/wine/server/0001-apply_faketime.patch
  lib/apply-proton-dll.sh

  With --legacy-reflex also:
  patches/legacy-reflex/linuwux_hooks_legacy.c

  With --preload-interposition also:
  patches/preload/linuwux_preload.c

EOF
    exit 0
}

VARIANT="cachyos"
BRANCH=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)   usage ;;
        -f|--force)  FORCE=1; shift ;;
        -k|--no-clean) CLEAN=0; shift ;;
        --legacy-reflex) LEGACY_REFLEX=1; shift ;;
        --preload-interposition) PRELOAD_INTERPOSITION=1; shift ;;
        --update-patches) UPDATE_PATCHES=1; shift ;;
        --container-engine=*)
            CONTAINER_ENGINE="${1#--container-engine=}"
            [[ -n "$CONTAINER_ENGINE" ]] || die "--container-engine requires a value"
            shift
            ;;
        cachyos|cachy|ge|proton-ge|eggroll)
            VARIANT="$1"; shift
            [[ $# -gt 0 && ! "$1" =~ ^- ]] && { BRANCH="$1"; shift; }
            ;;
        valve|proton)
            die "Valve/official Proton builds are not currently supported. Use cachyos or ge."
            ;;
        *)
            die "Unknown argument: $1  (use --help)"
            ;;
    esac
done

resolve_repo_and_branch

need git
need "$CONTAINER_ENGINE"
need make
need sed
need awk
need tar
need patch
need perl

if ! command -v xz >/dev/null 2>&1; then
    warn "xz not found – CachyOS packages will fall back to .tar.gz"
fi

FREE_GB=$(df -BG --output=avail "$SCRIPT_DIR" 2>/dev/null | tail -1 | tr -dc '0-9' || echo 0)
: "${FREE_GB:=0}"
if [[ "$FREE_GB" -gt 0 && "$FREE_GB" -lt 35 ]]; then
    warn "Only ~${FREE_GB} GB free under $SCRIPT_DIR – a full build typically needs 30-40 GB"
elif [[ "$FREE_GB" -gt 0 ]]; then
    info "Free space: ~${FREE_GB} GB"
fi

check_script_version

header "$HR"
header "  Proton + LinUwUx Builder v${VERSION}"
header "  Variant     : $VARIANT"
header "  Branch/Tag  : $BRANCH"
header "  Legacy Reflex: $([[ $LEGACY_REFLEX -eq 1 ]] && echo enabled || echo disabled)"
header "$HR"

ensure_patches_dir
setup_paths
check_required_base_files
clone_or_reuse_source
update_submodules
stage_wine_patches

# ------------------------------------------------------------
# Apply LinUwUx fixes and patches
# ------------------------------------------------------------
init_patch_log

if [[ "$VARIANT" == "ge" ]]; then
    ge_protonprep
else
    info "CachyOS – applying LinUwUx patches on the host (not relying on upstream auto-apply)"
fi

apply_regedit_fix
apply_faketime_protocol_fix
if [[ $PRELOAD_INTERPOSITION -eq 1 ]]; then
    info "--preload-interposition: skipping ntdll-side hooks entirely (segv/sigsys call stubs +"
    info "  signal_init_process insert) -- liblinuwux_preload.so's own constructor does the"
    info "  CPUID-fault-enable syscall that signal_init_process_hooks would otherwise insert"
else
    apply_linuwux_hooks
    apply_cpuid_spoof_handler_fix
    apply_signal_init_process_hooks
    apply_sigsys_handler_fix
fi
apply_linuwux_patches

if [[ "$VARIANT" == "cachyos" ]]; then
    # Avoid CachyOS's own patch pass re-applying staged files after we already did.
    find patches/wine -name '*.patch' -delete
fi

apply_force_wineboot_first_run
apply_proton_dll_overrides
if [[ $PRELOAD_INTERPOSITION -eq 1 ]]; then
    apply_preload_ld_env
fi
run_configure_and_build
if [[ $PRELOAD_INTERPOSITION -eq 1 ]]; then
    build_preload_library
fi
package_and_verify
cleanup_trees
print_success
