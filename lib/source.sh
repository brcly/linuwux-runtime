#!/usr/bin/env bash
# Source tree management: version detection, clone, submodules, patch staging.
# Sourced by build.sh — requires lib/common.sh already loaded.

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

resolve_repo_and_branch() {
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
}

setup_paths() {
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
}

ensure_patches_dir() {
    if [[ $UPDATE_PATCHES -eq 1 ]]; then
        info "--update-patches: removing existing patches/ so a fresh copy is fetched"
        rm -rf "$PATCHES_DIR"
    fi

    if [[ -d "$PATCHES_DIR" ]]; then
        info "Using existing patches/ folder ($PATCHES_DIR) – not re-downloading"
        info "  (pass --update-patches to force a fresh clone)"
    else
        info "Downloading LinUwUx patches..."
        local tmp_clone="${SCRIPT_DIR}/.tmp-patches-clone"
        rm -rf "$tmp_clone"
        git clone --depth 1 --branch "$PATCH_BRANCH" "$PATCH_REPO" "$tmp_clone" \
            || die "Failed to clone patch repository (branch $PATCH_BRANCH)"
        [[ -d "$tmp_clone/patches" ]] || die "Cloned patch repo has no patches/ folder"
        mv "$tmp_clone/patches" "$PATCHES_DIR"
        rm -rf "$tmp_clone"
    fi
}

clone_or_reuse_source() {
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
}

update_submodules() {
    info "Updating submodules (this can take a while)..."
    if [[ $FORCE -eq 1 ]]; then
        info "  --force: deiniting submodules for a full clean update"
        git -C "$SRC_DIR" submodule deinit -f --all 2>/dev/null || true
    fi
    git -C "$SRC_DIR" submodule update --init --recursive --force --filter=tree:0 \
        || die "Submodule update failed"
}

stage_wine_patches() {
    info "Installing LinUwUx patch files..."
    cd "$SRC_DIR"

    rm -rf patches/wine
    mkdir -p patches/wine

    local override_key="$BRANCH"
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

    local STALE_DEF_PATCHES
    STALE_DEF_PATCHES=$(grep -rl \
        '^\+u\?int64_t TargetSysHandler\|^\+static void detect_cpu_vendor\|^\+void detect_cpu_vendor\|^\+static void patch_kuser_shared_data\|^\+[[:space:]]*detect_cpu_vendor();\|^\+[[:space:]]*/\* linuwux-cpuid-handler\|^\+[[:space:]]*/\* linuwux-sigsys-handler\|^\+[[:space:]]*if (TargetSysHandler != 0 &&' \
        patches/wine 2>/dev/null || true)
    if [[ -n "$STALE_DEF_PATCHES" ]]; then
        die "Patch(es) below still add content that now lives exclusively in patches/base/, remove it from: $STALE_DEF_PATCHES"
    fi
}

init_patch_log() {
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
}
