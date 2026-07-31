#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Proton + LinUwUx Builder
#
# Builds proton-cachyos or proton-ge-custom with the LinUwUx
# patch set applied (CPUID spoofing, faketime, hardware profile
# GUID), then packages the result as a ready-to-install Steam
# Play compatibility tool.
#
# Design notes:
#   - Each branch/tag gets its own -src/-build folders so builds
#     never overwrite each other.
#   - Version-specific patch overrides live under
#     patches/overrides/<key>/wine/, where <key> is the branch/tag with
#     CachyOS's trailing /main[_native] removed.
#   - Additive content (HwProfileGuid, set_faketime request, CPUID
#     definitions + kuser patch + handler logic, signal_init hooks, SIGSYS routing,
#     user_settings.py) lives under patches/base/ and is applied by
#     content rather than fragile context diffs so the changes survive
#     large rearrangements of upstream Wine sources.
#   - Optional --legacy-reflex pulls extra content from
#     patches/legacy-reflex/base/ into an isolated -Legacy-Reflex build.
# ============================================================

VERSION="26.07.30"
CONTAINER_ENGINE="podman"
PATCH_REPO="https://github.com/brcly/proton-LinUwUx-patch.git"
# Branch of PATCH_REPO to clone when patches/ is missing (override with env).
PATCH_BRANCH="${PATCH_BRANCH:-main}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATCHES_DIR="${SCRIPT_DIR}/patches"
DIST_DIR="${SCRIPT_DIR}/dist"
FORCE=0
CLEAN=1
LEGACY_REFLEX=0
UPDATE_PATCHES=0
PATCH_LOG=""

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
