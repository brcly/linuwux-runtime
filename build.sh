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
#     definitions + kuser patch + handler logic, signal_init hooks,
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
    cpuid_spoof_handler.c, signal_init_process_hooks.c,
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

detect_latest_cachyos_branch() {
    local fallback="$1" latest
    command -v git >/dev/null 2>&1 || { echo "$fallback"; return; }
    latest=$(git ls-remote --heads "$REPO" 'refs/heads/cachyos_*' 2>/dev/null \
        | sed 's|.*refs/heads/||' \
        | grep '/main$' \
        | sort -t_ -k3 \
        | tail -1)
    [[ -n "$latest" ]] && echo "$latest" || echo "$fallback"
}

detect_latest_ge_tag() {
    local fallback="master" latest
    command -v git >/dev/null 2>&1 || { echo "$fallback"; return; }
    latest=$(git ls-remote --tags "$REPO" 'refs/tags/GE-Proton*' 2>/dev/null \
        | sed 's|.*refs/tags/||' \
        | grep -E '^GE-Proton[0-9]+-[0-9]+$' \
        | sort -V \
        | tail -1)
    [[ -n "$latest" ]] && echo "$latest" || echo "$fallback"
}

case "$VARIANT" in
    cachyos|cachy)
        VARIANT="cachyos"
        REPO="https://github.com/CachyOS/proton-cachyos.git"
        DEFAULT_BRANCH="cachyos_11.0_20260702/main"
        ;;
    ge|proton-ge|eggroll)
        VARIANT="ge"
        REPO="https://github.com/GloriousEggroll/proton-ge-custom.git"
        DEFAULT_BRANCH="master"
        ;;
esac

if [[ -z "$BRANCH" ]]; then
    if [[ "$VARIANT" == "cachyos" ]]; then
        info "Resolving latest CachyOS branch from remote..."
        DEFAULT_BRANCH=$(detect_latest_cachyos_branch "$DEFAULT_BRANCH")
        info "  Using branch: $DEFAULT_BRANCH"
    else
        info "Resolving latest GE-Proton tag from remote..."
        DEFAULT_BRANCH=$(detect_latest_ge_tag)
        info "  Using tag/branch: $DEFAULT_BRANCH"
    fi
fi
BRANCH="${BRANCH:-$DEFAULT_BRANCH}"

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

check_script_version() {
    local remote_version=""
    local raw_url="https://raw.githubusercontent.com/brcly/proton-LinUwUx-patch/main/build.sh"

    if command -v curl >/dev/null 2>&1; then
        remote_version=$(curl -fsSL --max-time 8 "$raw_url" 2>/dev/null \
            | grep -m1 '^VERSION=' | sed -E 's/^VERSION="([^"]+)".*/\1/') || true
    elif command -v wget >/dev/null 2>&1; then
        remote_version=$(wget -qO- --timeout=8 "$raw_url" 2>/dev/null \
            | grep -m1 '^VERSION=' | sed -E 's/^VERSION="([^"]+)".*/\1/') || true
    fi

    if [[ -z "$remote_version" ]]; then
        warn "Could not check for script updates (offline or network error) – continuing"
        return 0
    fi

    if [[ "$remote_version" == "$VERSION" ]]; then
        info "Script is up to date (v${VERSION})"
        return 0
    fi

    if printf '%s\n%s\n' "$VERSION" "$remote_version" | sort -V | head -1 | grep -Fqx "$VERSION"; then
        if [[ "${PATCH_BRANCH:-main}" != "main" ]]; then
            warn "Script is older than main (v${VERSION} < v${remote_version}) – continuing because PATCH_BRANCH=${PATCH_BRANCH}"
        else
            die "This script is outdated (v${VERSION}). Latest is v${remote_version}.
  Update with:  git -C \"$(dirname "$0")\" pull
  or re-download from: https://github.com/brcly/proton-LinUwUx-patch"
        fi
    fi

    info "Local script (v${VERSION}) is newer than published v${remote_version}"
}

check_script_version

header "$HR"
header "  Proton + LinUwUx Builder v${VERSION}"
header "  Variant     : $VARIANT"
header "  Branch/Tag  : $BRANCH"
header "  Legacy Reflex: $([[ $LEGACY_REFLEX -eq 1 ]] && echo enabled || echo disabled)"
header "$HR"
pause

if [[ $UPDATE_PATCHES -eq 1 ]]; then
    info "--update-patches: removing existing patches/ so a fresh copy is fetched"
    rm -rf "$PATCHES_DIR"
fi

if [[ -d "$PATCHES_DIR" ]]; then
    info "Using existing patches/ folder ($PATCHES_DIR) – not re-downloading"
    info "  (pass --update-patches to force a fresh clone)"
else
    info "Downloading LinUwUx patches..."
    tmp_clone="${SCRIPT_DIR}/.tmp-patches-clone"
    rm -rf "$tmp_clone"
    git clone --depth 1 --branch "$PATCH_BRANCH" "$PATCH_REPO" "$tmp_clone" || die "Failed to clone patch repository (branch $PATCH_BRANCH)"
    [[ -d "$tmp_clone/patches" ]] || die "Cloned patch repo has no patches/ folder"
    mv "$tmp_clone/patches" "$PATCHES_DIR"
    rm -rf "$tmp_clone"
fi
pause

compute_version_id() {
    local raw="$1" variant="$2" id
    case "$variant" in
        ge)
            id=$(echo "$raw" | sed -E 's/^GE-Proton/GE-Proton-/; s/_/-/g; s|/|-|g')
            ;;
        *)
            id=$(echo "$raw" | sed -E \
                -e 's/^cachyos[_-]?/proton-cachyos-/' \
                -e 's|/main_native$|-native|' \
                -e 's|/main$|-slr|' \
                -e 's|/|-|g; s/_/-/g')
            ;;
    esac
    echo "$id" | sed -E 's/-+/-/g; s/^-//; s/-$//'
}

ensure_unshallow() {
    if git -C "$SRC_DIR" rev-parse --is-shallow-repository 2>/dev/null | grep -q true; then
        info "  Repo is shallow – fetching full history/tags..."
        git -C "$SRC_DIR" fetch --unshallow --tags --force \
            || warn "  Unshallow fetch failed – version detection may still break at build time!"
    fi
}

VERSION_ID=$(compute_version_id "$BRANCH" "$VARIANT")
BUILD_FLAVOR=""
if [[ $LEGACY_REFLEX -eq 1 ]]; then
    BUILD_FLAVOR="-Legacy-Reflex"
fi
SRC_DIR="${SCRIPT_DIR}/${VERSION_ID}${BUILD_FLAVOR}-src"
BUILD_DIR="${SCRIPT_DIR}/${VERSION_ID}${BUILD_FLAVOR}-build"
BUILD_NAME="${VERSION_ID}-LinUwUx${BUILD_FLAVOR}"
LOG_DIR="${SCRIPT_DIR}/logs/${VERSION_ID}${BUILD_FLAVOR}"
PATCH_LOG="${LOG_DIR}/linuwux-patches.log"

info "Building version : $BRANCH"
info "Source folder    : $SRC_DIR"
info "Build  folder    : $BUILD_DIR"
info "Log    folder    : $LOG_DIR"
info "Package name     : $BUILD_NAME"
pause

rm -rf "$LOG_DIR"
mkdir -p "$LOG_DIR"

if [[ $FORCE -eq 0 && -d "$SRC_DIR/.git" ]]; then
    info "Reusing existing source tree (use --force to re-clone)"
    ensure_unshallow
    git -C "$SRC_DIR" fetch --tags --force || true
    git -C "$SRC_DIR" checkout -q "$BRANCH" 2>/dev/null \
        || git -C "$SRC_DIR" checkout -q -B "$BRANCH" "origin/$BRANCH"
    if git -C "$SRC_DIR" symbolic-ref -q HEAD >/dev/null; then
        git -C "$SRC_DIR" pull --ff-only || true
    fi
else
    info "Cloning source..."
    rm -rf "$SRC_DIR"
    if ! git clone --branch "$BRANCH" --filter=tree:0 "$REPO" "$SRC_DIR" 2>/dev/null; then
        info "Branch/tag not found on default clone attempt – retrying without --branch..."
        git clone --filter=tree:0 "$REPO" "$SRC_DIR" || die "Failed to clone $REPO"
        git -C "$SRC_DIR" checkout -q "$BRANCH" 2>/dev/null || die "Branch/tag '$BRANCH' not found"
    fi
    ensure_unshallow
fi
pause

info "Updating submodules (this can take a while)..."
if [[ $FORCE -eq 1 ]]; then
    info "  --force: deiniting submodules for a full clean update"
    git -C "$SRC_DIR" submodule deinit -f --all 2>/dev/null || true
fi
git -C "$SRC_DIR" submodule update --init --recursive --force --filter=tree:0 \
    || die "Submodule update failed"
pause

info "Installing LinUwUx patch files..."

cd "$SRC_DIR"

rm -rf patches/wine
mkdir -p patches/wine

override_key="$BRANCH"
if [[ "$VARIANT" == "cachyos" ]]; then
    override_key="${BRANCH%/*}"
fi

if [[ -d "$PATCHES_DIR/overrides/$override_key/wine" ]]; then
    info "Using version-specific overrides for '$override_key'"
    info "  (common patches under patches/wine/ are NOT applied when an override exists)"
    cp -r "$PATCHES_DIR/overrides/$override_key/wine/." patches/wine/
else
    info "No version-specific overrides for '$override_key' – using common patches"
    if [[ -d "$PATCHES_DIR/wine" ]]; then
        cp -r "$PATCHES_DIR/wine/." patches/wine/
    fi
fi

rm -rf patches/wine/loader

[[ -n "$(find patches/wine -name '*.patch' 2>/dev/null)" ]] \
    || die "No patch files found under patches/wine/ - check $PATCHES_DIR"

info "Installed patches:"
find patches/wine -name '*.patch' | sed 's|^|      |'

STALE_DEF_PATCHES=$(grep -rl \
    '^\+u\?int64_t TargetSysHandler\|^\+static void detect_cpu_vendor\|^\+void detect_cpu_vendor\|^\+static void patch_kuser_shared_data\|^\+[[:space:]]*detect_cpu_vendor();\|^\+[[:space:]]*/\* linuwux-cpuid-handler' \
    patches/wine 2>/dev/null || true)
if [[ -n "$STALE_DEF_PATCHES" ]]; then
    die "Patch(es) below still add content that now lives exclusively in patches/base/, remove it from: $STALE_DEF_PATCHES"
fi
pause

# ------------------------------------------------------------
# 5. Apply LinUwUx fixes and patches
# ------------------------------------------------------------

# Unified log for content inserts + traditional .patch files
: > "$PATCH_LOG"
{
    echo "$HR"
    echo "[$(ts)] LinUwUx patch session start"
    echo "  Variant : $VARIANT"
    echo "  Branch  : $BRANCH"
    echo "  Legacy  : $([[ $LEGACY_REFLEX -eq 1 ]] && echo yes || echo no)"
    echo "  Source  : $SRC_DIR"
    echo "$HR"
} >> "$PATCH_LOG"
plog "Patch log → $PATCH_LOG"

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

apply_cpuid_spoof_definitions_fix() {
    local wine_dir="$1"
    local target="${wine_dir}/dlls/ntdll/unix/signal_x86_64.c"
    local defs_file="${PATCHES_DIR}/base/cpuid_spoof_defs.c"

    plog "Applying CPUID spoof definitions to $target ..."
    [[ -f "$target" ]]    || plog_die "$target not found - wine's layout may have changed upstream"
    [[ -f "$defs_file" ]] || plog_die "$defs_file not found - patch repo structure may have changed"

    if grep -q '^uint64_t TargetSysHandler' "$target"; then
        plog "  Already present"
        return
    fi

    local anchor_line
    anchor_line=$(file_scope_anchor "$target")
    insert_after_line "$target" "$anchor_line" "$defs_file"
    grep -q '^uint64_t TargetSysHandler' "$target" || plog_die "defs insert produced no change"
    plog "  Inserted definitions after line $anchor_line (file scope, outside platform ifdefs)"
}

apply_kuser_shared_data_patch_fix() {
    local wine_dir="$1"
    local target="${wine_dir}/dlls/ntdll/unix/signal_x86_64.c"
    local patch_file="${PATCHES_DIR}/base/kuser_shared_data_patch.c"

    plog "Applying KUSER_SHARED_DATA patch function to $target ..."
    [[ -f "$target" ]]     || plog_die "$target not found - wine's layout may have changed upstream"
    [[ -f "$patch_file" ]] || plog_die "$patch_file not found - expected under patches/base/"

    if grep -q 'static void patch_kuser_shared_data' "$target"; then
        plog "  KUSER_SHARED_DATA patch function already present"
        return
    fi

    local anchor_line
    anchor_line=$(file_scope_anchor "$target")
    insert_after_line "$target" "$anchor_line" "$patch_file"
    grep -q 'static void patch_kuser_shared_data' "$target" || plog_die "kuser insert produced no change"
    plog "  Inserted KUSER_SHARED_DATA patch function after line $anchor_line (file scope, outside platform ifdefs)"
}

apply_cpuid_spoof_handler_fix() {
    local wine_dir="$1"
    local target="${wine_dir}/dlls/ntdll/unix/signal_x86_64.c"
    local handler_file="${PATCHES_DIR}/base/cpuid_spoof_handler.c"
    local handler_label="CPUID spoof"

    if [[ $LEGACY_REFLEX -eq 1 ]]; then
        handler_file="${PATCHES_DIR}/legacy-reflex/base/cpuid_legacy_reflex_handler.c"
        handler_label="legacy Reflex CPUID"
    fi

    plog "Applying $handler_label handler logic to $target ..."
    [[ -f "$target" ]]       || plog_die "$target not found - wine's layout may have changed upstream"
    [[ -f "$handler_file" ]] || plog_die "$handler_file not found - expected for $handler_label"

    if grep -q 'linuwux-cpuid-handler' "$target"; then
        plog "  Handler logic already present"
        return
    fi

    local func_line
    func_line=$(grep -n '^static void segv_handler' "$target" | head -1 | cut -d: -f1)
    [[ -n "$func_line" ]] || plog_die "Could not find 'static void segv_handler' in $target"

    local anchor_line
    anchor_line=$(awk -v start="$func_line" '
        NR >= start && /void[[:space:]]*\*[[:space:]]*steamclient_addr[[:space:]]*=[[:space:]]*NULL/ { print NR; exit }
    ' "$target")
    [[ -n "$anchor_line" ]] || plog_die "Could not find 'void *steamclient_addr = NULL' inside segv_handler after line $func_line"

    insert_after_line "$target" "$anchor_line" "$handler_file"
    grep -q 'linuwux-cpuid-handler' "$target" || plog_die "handler insert produced no change"
    plog "  Inserted handler logic after line $anchor_line (after steamclient_addr in segv_handler)"
}

apply_signal_init_process_hooks() {
    local wine_dir="$1"
    local target="${wine_dir}/dlls/ntdll/unix/signal_x86_64.c"
    local hooks_file="${PATCHES_DIR}/base/signal_init_process_hooks.c"

    plog "Applying signal_init_process hooks to $target ..."
    [[ -f "$target" ]]     || plog_die "$target not found - wine's layout may have changed upstream"
    [[ -f "$hooks_file" ]] || plog_die "$hooks_file not found - expected under patches/base/"

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

    insert_after_line "$target" "$anchor_line" "$hooks_file"
    grep -q 'detect_cpu_vendor();' "$target" || plog_die "signal_init hooks insert produced no change"
    plog "  Inserted init hooks after line $anchor_line (after SIGSEGV registration)"
}

# f) Insert legacy protocol globals at file scope when requested.
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

# g) Overlay legacy SIGSYS routing after the common SIGSYS patch has applied.
apply_legacy_reflex_sigsys_fix() {
    local wine_dir="$1"
    local target="${wine_dir}/dlls/ntdll/unix/signal_x86_64.c"
    local handler_file="${PATCHES_DIR}/legacy-reflex/base/legacy_reflex_sigsys_handler.c"
    local count tmp

    [[ $LEGACY_REFLEX -eq 1 ]] || return 0

    plog "Applying legacy Reflex SIGSYS routing to $target ..."
    [[ -f "$target" ]] || plog_die "$target not found - wine's layout may have changed upstream"
    [[ -f "$handler_file" ]] || plog_die "$handler_file not found - expected for legacy Reflex"

    if grep -q 'LegacyQuerySystemInformationId &&' "$target"; then
        plog "  Already present"
        return
    fi

    count=$(grep -c 'if (TargetSysHandler != 0 &&' "$target" || true)
    [[ "$count" -eq 1 ]] || plog_die "Expected one common SIGSYS routing block in $target, found $count"

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
    plog "  Inserted legacy SIGSYS routing"
}

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
apply_linuwux_patches "wine"
apply_legacy_reflex_sigsys_fix "wine"

if [[ "$VARIANT" == "cachyos" ]]; then
    find patches/wine -name '*.patch' -delete
fi
pause

info "Installing user_settings.py and checking required base files..."

user_settings_src="${PATCHES_DIR}/base/user_settings.py"
[[ -f "$user_settings_src" ]] \
    || die "user_settings.py not found at $user_settings_src – obtain it and place it there before building"
[[ -f "${PATCHES_DIR}/base/cpuid_spoof_defs.c" ]] \
    || die "cpuid_spoof_defs.c not found under ${PATCHES_DIR}/base/ – required"
[[ -f "${PATCHES_DIR}/base/kuser_shared_data_patch.c" ]] \
    || die "kuser_shared_data_patch.c not found under ${PATCHES_DIR}/base/ – required"
[[ -f "${PATCHES_DIR}/base/cpuid_spoof_handler.c" ]] \
    || die "cpuid_spoof_handler.c not found under ${PATCHES_DIR}/base/ – required"
[[ -f "${PATCHES_DIR}/base/signal_init_process_hooks.c" ]] \
    || die "signal_init_process_hooks.c not found under ${PATCHES_DIR}/base/ – required"
if [[ $LEGACY_REFLEX -eq 1 ]]; then
    [[ -f "${PATCHES_DIR}/legacy-reflex/base/cpuid_legacy_reflex_defs.c" ]] \
        || die "cpuid_legacy_reflex_defs.c not found – required for legacy Reflex"
    [[ -f "${PATCHES_DIR}/legacy-reflex/base/cpuid_legacy_reflex_handler.c" ]] \
        || die "cpuid_legacy_reflex_handler.c not found – required for legacy Reflex"
    [[ -f "${PATCHES_DIR}/legacy-reflex/base/legacy_reflex_sigsys_handler.c" ]] \
        || die "legacy_reflex_sigsys_handler.c not found – required for legacy Reflex"
fi
[[ -f "${PATCHES_DIR}/base/hwprofile_guid.reg" ]] \
    || die "hwprofile_guid.reg not found under ${PATCHES_DIR}/base/ – required"
[[ -f "${PATCHES_DIR}/base/set_faketime.protocol" ]] \
    || die "set_faketime.protocol not found under ${PATCHES_DIR}/base/ – required"

cp "$user_settings_src" user_settings.py
info "  Installed from $user_settings_src"
pause

info "Ensuring user_settings.py is included in the package..."

if grep -q 'USER_SETTINGS_REAL_TARGET' Makefile.in; then
    info "Makefile.in already contains the rule"
else
    anchor_dst='USER_SETTINGS_PY_TARGET := $(addprefix $(DST_BASE)/,user_settings.sample.py)'
    anchor_src='$(USER_SETTINGS_PY_TARGET): $(addprefix $(SRCDIR)/,user_settings.sample.py)'
    anchor_dist='DIST_COPY_TARGETS := $(FILELOCK_TARGET) $(PROTON_PY_TARGET) \'

    grep -qF "$anchor_dst"  Makefile.in || die "Makefile.in anchor missing (DST_BASE target) – upstream layout changed, user_settings.py wiring needs updating"
    grep -qF "$anchor_src"  Makefile.in || die "Makefile.in anchor missing (SRCDIR target) – upstream layout changed, user_settings.py wiring needs updating"
    grep -qF "$anchor_dist" Makefile.in || die "Makefile.in anchor missing (DIST_COPY_TARGETS) – upstream layout changed, user_settings.py wiring needs updating"

    sed -i \
        -e '/USER_SETTINGS_PY_TARGET := \$(addprefix \$(DST_BASE)\/,user_settings.sample.py)/a\
USER_SETTINGS_REAL_TARGET := \$(addprefix \$(DST_BASE)\/,user_settings.py)' \
        Makefile.in

    sed -i \
        -e '/\$(USER_SETTINGS_PY_TARGET): \$(addprefix \$(SRCDIR)\/,user_settings.sample.py)/a\
\$(USER_SETTINGS_REAL_TARGET): \$(addprefix \$(SRCDIR)\/,user_settings.py)' \
        Makefile.in

    sed -i \
        -e 's|DIST_COPY_TARGETS := \$(FILELOCK_TARGET) \$(PROTON_PY_TARGET) \\|DIST_COPY_TARGETS := \$(FILELOCK_TARGET) \$(PROTON_PY_TARGET) \$(USER_SETTINGS_REAL_TARGET) \\|' \
        Makefile.in

    grep -qF 'USER_SETTINGS_REAL_TARGET := $(addprefix $(DST_BASE)/,user_settings.py)' Makefile.in \
        || die "Makefile.in edit failed: DST_BASE rule not inserted"
    grep -qF '$(USER_SETTINGS_REAL_TARGET): $(addprefix $(SRCDIR)/,user_settings.py)' Makefile.in \
        || die "Makefile.in edit failed: SRCDIR rule not inserted"
    grep -qF 'DIST_COPY_TARGETS := $(FILELOCK_TARGET) $(PROTON_PY_TARGET) $(USER_SETTINGS_REAL_TARGET)' Makefile.in \
        || die "Makefile.in edit failed: DIST_COPY_TARGETS not updated"
    info "Makefile.in updated"
fi
pause

info "Preparing build directory..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"
pause

info "Running configure.sh..."
ccache_flag=()
if [[ "$VARIANT" == "cachyos" ]]; then
    ccache_flag=(--enable-ccache)
fi
"$SRC_DIR/configure.sh" "${ccache_flag[@]}" \
    --build-name="$BUILD_NAME" \
    --container-engine="$CONTAINER_ENGINE" \
    || die "configure.sh failed"
pause

info "Building redist (this will take a long time)..."
make redist 2>&1 | tee "$LOG_DIR/build.log" || die "make redist failed – see $LOG_DIR/build.log"

info "Verifying / packaging output..."

TARBALL=$(find . -maxdepth 3 \( -name "${BUILD_NAME}*.tar.gz" -o -name "${BUILD_NAME}*.tar.xz" \) | head -1)

if [[ -z "$TARBALL" ]]; then
    TARBALL=$(find . -maxdepth 3 \( -name '*.tar.gz' -o -name '*.tar.xz' \) | head -1)
fi

if [[ -z "$TARBALL" ]]; then
    REDIST_DIR=""
    for candidate in redist dist "${BUILD_NAME}" *; do
        if [[ -d "$candidate" && ( -f "$candidate/proton" || -f "$candidate/version" ) ]]; then
            REDIST_DIR="$candidate"
            break
        fi
    done

    if [[ -n "$REDIST_DIR" ]]; then
        info "Found redist directory: $REDIST_DIR"
        info "Creating archive from it..."

        if [[ "$REDIST_DIR" != "$BUILD_NAME" ]]; then
            mv "$REDIST_DIR" "$BUILD_NAME"
            REDIST_DIR="$BUILD_NAME"
        fi

        if [[ "$VARIANT" == "cachyos" ]] && command -v xz >/dev/null 2>&1; then
            tar -c "$REDIST_DIR" | xz -T0 > "${BUILD_NAME}.tar.xz"
            TARBALL="${BUILD_NAME}.tar.xz"
        else
            tar -czf "${BUILD_NAME}.tar.gz" "$REDIST_DIR"
            TARBALL="${BUILD_NAME}.tar.gz"
        fi
        info "Created $TARBALL"
    fi
fi

if [[ -z "$TARBALL" || ! -s "$TARBALL" ]]; then
    die "No valid redistributable (tarball or directory) was produced"
fi

info "Found package: $TARBALL"

MISSING=0
listing=$(tar -tf "$TARBALL" 2>/dev/null || true)
if grep -q 'user_settings.py' <<<"$listing"; then
    info "user_settings.py is present in the package"
else
    warn "user_settings.py was NOT found inside the archive"
    MISSING=1
fi
if grep -qE '(^|/)(proton|version)$' <<<"$listing"; then
    info "Core files (proton / version) look present"
else
    warn "Could not locate 'proton' or 'version' inside the archive – package may be incomplete"
    MISSING=1
fi

SIZE_MB=$(du -m "$TARBALL" | cut -f1)
info "Package size: ${SIZE_MB} MB"
if [[ "$SIZE_MB" -lt 200 ]]; then
    warn "Tarball is only ${SIZE_MB} MB – this is unusually small for a Proton redist"
fi

[[ $MISSING -eq 0 ]] || die "Package failed verification (missing user_settings.py or core files) – see warnings above"

mkdir -p "$DIST_DIR"
FINAL_TARBALL="${DIST_DIR}/$(basename "$TARBALL")"
mv -f "$TARBALL" "$FINAL_TARBALL"
info "Tarball moved to $FINAL_TARBALL"

cd "$SCRIPT_DIR"

if [[ $CLEAN -eq 1 ]]; then
    info "Cleaning up build artifacts (use --no-clean to keep them)..."
    rm -rf "$SRC_DIR" "$BUILD_DIR"
    info "  Removed $(basename "$SRC_DIR") and $(basename "$BUILD_DIR")"
else
    info "Keeping -src/-build trees (--no-clean)"
fi

echo
header "$HR"
header "  BUILD SUCCESSFUL"
header "$HR"
echo -e "  ${BOLD}Variant${RESET}      : $VARIANT"
echo -e "  ${BOLD}Branch/Tag${RESET}   : $BRANCH"
if [[ $CLEAN -eq 1 ]]; then
    echo -e "  ${BOLD}Source/Build${RESET} : cleaned (--no-clean to keep)"
else
    echo -e "  ${BOLD}Source${RESET}       : $SRC_DIR"
    echo -e "  ${BOLD}Build dir${RESET}    : $BUILD_DIR"
fi
echo -e "  ${BOLD}Logs${RESET}         : $LOG_DIR"
echo -e "  ${BOLD}Package${RESET}      : $FINAL_TARBALL"
header "$HR"
echo
echo "Install with:"
echo "  mkdir -p ~/.steam/root/compatibilitytools.d/${BUILD_NAME}"
echo "  tar -xf \"$FINAL_TARBALL\" -C ~/.steam/root/compatibilitytools.d/${BUILD_NAME} --strip-components=1"
echo
