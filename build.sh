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
