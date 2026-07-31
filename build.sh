#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Proton + LinUwUx Builder
#
# Thin orchestrator. Implementation lives under lib/:
#   lib/common.sh         – logging, insert helpers
#   lib/source.sh         – clone, submodules, patch staging
#   lib/apply-content.sh  – content-based inserts (patches/base/)
#   lib/apply-patches.sh  – traditional .patch apply + GE prep
#   lib/package.sh        – user_settings, configure, redist, verify
# ============================================================

VERSION="26.07.31"
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
PATCH_LOG=""

# shellcheck source=lib/common.sh
source "${LIB_DIR}/common.sh"
# shellcheck source=lib/source.sh
source "${LIB_DIR}/source.sh"
# shellcheck source=lib/apply-content.sh
source "${LIB_DIR}/apply-content.sh"
# shellcheck source=lib/apply-patches.sh
source "${LIB_DIR}/apply-patches.sh"
# shellcheck source=lib/package.sh
source "${LIB_DIR}/package.sh"

trap 'echo -e "\n${RED}[$(ts)] Build failed – source/build trees left in place for debugging${RESET}" >&2' ERR

usage() {
    cat << EOF
Proton + LinUwUx Builder v${VERSION}

Usage:
  $(basename "$0") [OPTIONS] [VARIANT] [BRANCH/TAG]

Variants:
  cachyos (default)   Build CachyOS Proton
  ge                  Build GloriousEggroll Proton

Examples:
  $(basename "$0")                          # latest CachyOS
  $(basename "$0") cachyos <branch>
  $(basename "$0") ge                       # latest GE tag (or master)
  $(basename "$0") ge GE-Proton11-3
  $(basename "$0") ge GE-Proton9-4
  $(basename "$0") --container-engine=docker ge
  $(basename "$0") --legacy-reflex ge GE-Proton11-3
  $(basename "$0") --update-patches         # force re-download of patches/

Options:
  -f, --force               Force full re-clone and clean rebuild of the Proton source
  -k, --no-clean            Keep the -src/-build trees after a successful build
                            (default: they're removed, leaving only the tarball)
  --legacy-reflex           Include the legacy Reflex compatibility protocol
  --update-patches          Delete and re-clone the patches/ folder from upstream
  --container-engine=<name> Container engine to build with (default: podman)
  -h, --help                Show this help

Environment:
  SLOW=1                     Restore the 1.2s pauses between steps (off by default)
  PATCH_BRANCH=<name>        Branch of the patch repo to clone when patches/ is missing
                             (default: main). Useful while developing on a non-main branch.

Notes:
  Versioned folders are used so multiple builds never overwrite each other.
  With no branch given:
    - cachyos resolves the latest cachyos_*/main branch from the remote
    - ge resolves the newest GE-ProtonN-M tag (falls back to master)
  On success the finished tarball is moved to dist/ and the -src/-build trees are
  removed, so each run starts from a fresh clone. A failed build leaves its trees
  in place for debugging. Pass --no-clean to keep them (faster patch-dev loop).

  Required additive content lives under patches/base/:
    user_settings.py, cpuid_spoof_defs.c, kuser_shared_data_patch.c,
    cpuid_spoof_handler.c, signal_init_process_hooks.c, sigsys_handler.c,
    hwprofile_guid.reg, set_faketime.protocol

  With --legacy-reflex, also required under patches/legacy-reflex/base/:
    cpuid_legacy_reflex_defs.c, cpuid_legacy_reflex_handler.c,
    legacy_reflex_sigsys_handler.c

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
        --update-patches) UPDATE_PATCHES=1; shift ;;
        --container-engine=*)
            CONTAINER_ENGINE="${1#--container-engine=}"
            [[ -n "$CONTAINER_ENGINE" ]] || die "--container-engine requires a value (e.g. --container-engine=docker)"
            shift
            ;;
        cachyos|cachy|ge|proton-ge|eggroll)
            VARIANT="$1"; shift
            [[ $# -gt 0 && ! "$1" =~ ^- ]] && { BRANCH="$1"; shift; }
            ;;
        valve|proton)
            die "Valve/official Proton builds are not currently supported (debugger detection issues). Use cachyos or ge."
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
pause

ensure_patches_dir
pause

setup_paths
pause

clone_or_reuse_source
pause

update_submodules
pause

stage_wine_patches
pause

# ------------------------------------------------------------
# Apply LinUwUx fixes and patches
# ------------------------------------------------------------
init_patch_log

if [[ "$VARIANT" == "ge" ]]; then
    ge_protonprep
    pause
else
    info "CachyOS – applying LinUwUx patches directly rather than trusting CachyOS's own auto-apply"
fi

apply_regedit_fix "wine"
apply_faketime_protocol_fix "wine"
apply_cpuid_spoof_definitions_fix "wine"
apply_kuser_shared_data_patch_fix "wine"
apply_cpuid_spoof_handler_fix "wine"
apply_legacy_reflex_definitions_fix "wine"
apply_signal_init_process_hooks "wine"
apply_sigsys_handler_fix "wine"
apply_linuwux_patches "wine"
apply_legacy_reflex_sigsys_fix "wine"

if [[ "$VARIANT" == "cachyos" ]]; then
    find patches/wine -name '*.patch' -delete
fi
pause

install_user_settings_and_check_base
pause

wire_makefile_user_settings
pause

run_configure_and_build
pause

package_and_verify
cleanup_trees
print_success
