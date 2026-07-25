#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Proton + LinUwUx Builder
# Builds proton-cachyos or proton-ge-custom with LinUwUx patches
# ============================================================

VERSION="1.4"
CONTAINER_ENGINE="podman"
PATCH_REPO="https://github.com/brcly/proton-LinUwUx-patch.git"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP_PATCHES="${SCRIPT_DIR}/.tmp-patches"
FORCE=0

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "==> $*"; }
warn() { echo "WARNING: $*" >&2; }
need() { command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not found"; }

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
  $(basename "$0") cachyos <branch>         # specific CachyOS branch
  $(basename "$0") ge                       # latest GE (master)
  $(basename "$0") ge GE-Proton11-3         # specific GE tag
  $(basename "$0") ge GE-Proton9-4          # older GE (auto-fixes faketime type)

Options:
  -f, --force     Force full re-clone and clean rebuild
  -h, --help      Show this help

The script creates versioned folders so multiple builds never overwrite each other.
EOF
    exit 0
}

# -------------------- Argument parsing --------------------
VARIANT="cachyos"
BRANCH=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)   usage ;;
        -f|--force)  FORCE=1; shift ;;
        cachyos|cachy|ge|proton-ge|eggroll)
            VARIANT="$1"; shift
            [[ $# -gt 0 && ! "$1" =~ ^- ]] && { BRANCH="$1"; shift; }
            ;;
        *)
            die "Unknown argument: $1  (use --help)"
            ;;
    esac
done

# -------------------- Resolve variant --------------------
case "$VARIANT" in
    cachyos|cachy)
        REPO="https://github.com/CachyOS/proton-cachyos.git"
        DEFAULT_BRANCH="cachyos_11.0_20260702/main"
        ;;
    ge|proton-ge|eggroll)
        REPO="https://github.com/GloriousEggroll/proton-ge-custom.git"
        DEFAULT_BRANCH="master"
        ;;
    *)
        die "Unknown variant '$VARIANT'"
        ;;
esac

BRANCH="${BRANCH:-$DEFAULT_BRANCH}"

need git
need podman
need make
need sed
need tar

echo
echo "============================================================"
echo "  Proton + LinUwUx Builder v${VERSION}"
echo "  Variant     : $VARIANT"
echo "  Branch/Tag  : $BRANCH"
echo "============================================================"
echo

# ============================================================
# 1. Download LinUwUx patches
# ============================================================
info "Downloading LinUwUx patches..."
rm -rf "$TMP_PATCHES"
git clone --depth 1 "$PATCH_REPO" "$TMP_PATCHES" || die "Failed to clone patch repository"

# ============================================================
# 2. Determine version string
# ============================================================
TEMP_SRC="${SCRIPT_DIR}/.tmp-src-version"
rm -rf "$TEMP_SRC"

info "Detecting exact version..."
if ! git clone --branch "$BRANCH" --depth 1 --tags "$REPO" "$TEMP_SRC" 2>/dev/null; then
    git clone --depth 1 --tags "$REPO" "$TEMP_SRC" || die "Failed to clone $REPO"
    cd "$TEMP_SRC"
    git checkout "$BRANCH" 2>/dev/null || die "Branch/tag '$BRANCH' not found"
else
    cd "$TEMP_SRC"
fi

RAW_VERSION=$(git describe --tags --always 2>/dev/null || echo "$BRANCH")
VERSION_ID=$(echo "$RAW_VERSION" | \
    sed -E 's/^GE-Proton/GE-Proton-/; s/^cachyos_/proton-cachyos-/; s/_/-/g; s|/|-|g')

SRC_DIR="${SCRIPT_DIR}/${VERSION_ID}-src"
BUILD_DIR="${SCRIPT_DIR}/${VERSION_ID}-build"
BUILD_NAME="${VERSION_ID}-LinUwUx"

info "Detected version : $RAW_VERSION"
info "Source folder    : $SRC_DIR"
info "Build  folder    : $BUILD_DIR"
info "Package name     : $BUILD_NAME"

# ============================================================
# 3. Prepare source tree (reuse if possible)
# ============================================================
if [[ -d "$SRC_DIR/.git" && $FORCE -eq 0 ]]; then
    info "Reusing existing source tree (use --force to re-clone)"
    cd "$SRC_DIR"
    git fetch --tags --force || true
    git checkout "$BRANCH" 2>/dev/null || git checkout -B "$BRANCH" "origin/$BRANCH"
    git pull --ff-only || true
else
    info "Creating fresh source tree..."
    rm -rf "$SRC_DIR"
    mv "$TEMP_SRC" "$SRC_DIR"
    cd "$SRC_DIR"
fi
rm -rf "$TEMP_SRC" 2>/dev/null || true

# ============================================================
# 4. Force clean submodule update
# ============================================================
info "Updating submodules (this can take a while)..."
git submodule deinit -f --all 2>/dev/null || true
git submodule update --init --recursive --force || die "Submodule update failed"

# ============================================================
# 5. Install LinUwUx patches
# ============================================================
info "Installing LinUwUx patch files..."

rm -rf patches/wine/dlls/ntdll/unix patches/wine/loader patches/wine/server
mkdir -p patches/wine/dlls/ntdll/unix patches/wine/loader patches/wine/server

cp "$TMP_PATCHES/patches/wine/dlls/ntdll/unix/0001-spoof-cpuid.patch" \
   patches/wine/dlls/ntdll/unix/ || die "Missing spoof-cpuid patch"
cp "$TMP_PATCHES/patches/wine/loader/0001-regedit.patch" \
   patches/wine/loader/ || die "Missing regedit patch"
cp "$TMP_PATCHES/patches/wine/server/0001-apply_faketime.patch" \
   patches/wine/server/ || die "Missing faketime patch 1"
cp "$TMP_PATCHES/patches/wine/server/0002-apply_faketime.patch" \
   patches/wine/server/ || die "Missing faketime patch 2"

# Older GE (pre-10) does not understand modern 64-bit type names in protocol.def.
# timeout_t has existed for many years and is accepted by old make_requests.
if [[ "$VARIANT" == "ge" || "$VARIANT" == "proton-ge" || "$VARIANT" == "eggroll" ]]; then
    if ! grep -q 'apply_patch ()' patches/protonprep*.sh 2>/dev/null; then
        info "Older GE detected – rewriting faketime patch type to timeout_t"
        sed -i 's/unsigned __int64 faketime/timeout_t faketime/g' \
            patches/wine/server/0002-apply_faketime.patch
        sed -i 's/unsigned hyper faketime/timeout_t faketime/g' \
            patches/wine/server/0002-apply_faketime.patch
    fi
fi

info "Installed patches:"
find patches/wine -name '*.patch' | sed 's|^|      |'

# ============================================================
# 6. GE: inject patches into protonprep (with style detection)
# ============================================================
if [[ "$VARIANT" == "ge" || "$VARIANT" == "proton-ge" || "$VARIANT" == "eggroll" ]]; then
    PREP_SCRIPT=$(find patches -maxdepth 1 -name 'protonprep*.sh' | head -1)

    if [[ -z "$PREP_SCRIPT" ]]; then
        die "No protonprep script found in patches/"
    fi

    info "Injecting LinUwUx patches into $(basename "$PREP_SCRIPT")..."

    if grep -q "0001-spoof-cpuid.patch" "$PREP_SCRIPT"; then
        info "Patches already registered – skipping injection"
    else
        # Try several known markers (most specific first)
        MARKER_LINE=""
        for marker in \
            '### END WINE HOTFIX/BACKPORT SECTION ###' \
            '### END WINE PENDING UPSTREAM SECTION ###' \
            '### END PROTON-GE ADDITIONAL CUSTOM PATCHES ###' \
            '### END WINE PATCHING ###'
        do
            MARKER_LINE=$(grep -n "$marker" "$PREP_SCRIPT" | head -1 | cut -d: -f1 || true)
            [[ -n "$MARKER_LINE" ]] && break
        done

        if [[ -z "$MARKER_LINE" ]]; then
            die "Could not find any known insertion marker in $PREP_SCRIPT"
        fi

        # Detect apply style
        if grep -q 'apply_patch ()' "$PREP_SCRIPT"; then
            # GE-Proton10-9+
            INSERT_BLOCK=$(cat << 'EOF'
### LinUwUx patches (auto-added by build script)
apply_patch "../patches/wine/dlls/ntdll/unix/0001-spoof-cpuid.patch"
apply_patch "../patches/wine/loader/0001-regedit.patch"
apply_patch "../patches/wine/server/0001-apply_faketime.patch"
apply_patch "../patches/wine/server/0002-apply_faketime.patch"

EOF
)
        else
            # Pre GE-Proton10-9
            INSERT_BLOCK=$(cat << 'EOF'
### LinUwUx patches (auto-added by build script)
patch -Np1 < ../patches/wine/dlls/ntdll/unix/0001-spoof-cpuid.patch
patch -Np1 < ../patches/wine/loader/0001-regedit.patch
patch -Np1 < ../patches/wine/server/0001-apply_faketime.patch
patch -Np1 < ../patches/wine/server/0002-apply_faketime.patch

EOF
)
        fi

        {
            head -n $((MARKER_LINE - 1)) "$PREP_SCRIPT"
            printf '%s\n' "$INSERT_BLOCK"
            tail -n +$MARKER_LINE "$PREP_SCRIPT"
        } > "${PREP_SCRIPT}.tmp"

        mv "${PREP_SCRIPT}.tmp" "$PREP_SCRIPT"
        chmod +x "$PREP_SCRIPT"
        info "Patches injected successfully"
    fi
fi

rm -rf "$TMP_PATCHES"

# ============================================================
# 7. GE: run protonprep
# ============================================================
if [[ "$VARIANT" == "ge" || "$VARIANT" == "proton-ge" || "$VARIANT" == "eggroll" ]]; then
    PREP_SCRIPT=$(find patches -maxdepth 1 -name 'protonprep*.sh' | head -1)
    if [[ -n "$PREP_SCRIPT" ]]; then
        info "Running GE prep script (this applies all patches)..."
        if ! bash "$PREP_SCRIPT" 2>&1 | tee prep.log; then
            warn "Prep script returned non-zero – check prep.log"
        fi

        if ! grep -q "spoof-cpuid\|LinUwUx" prep.log 2>/dev/null; then
            warn "LinUwUx patches may not have been applied – check prep.log"
        else
            info "LinUwUx patches appear in prep log – good"
        fi
    fi
fi

# ============================================================
# 8. Create user_settings.py
# ============================================================
info "Creating user_settings.py..."
cat > user_settings.py << 'EOF'
# LinUwUx defaults – automatically included in the redist
user_settings = {
    "WINEDLLOVERRIDES": "winmm=n,b;version=n,b;reflex=n,b",
    "PROTON_DISABLE_LSTEAMCLIENT": "1",
}
EOF

# ============================================================
# 9. Patch Makefile.in so user_settings.py is packaged
# ============================================================
info "Ensuring user_settings.py is included in the package..."

if ! grep -q 'USER_SETTINGS_REAL_TARGET' Makefile.in; then
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
    info "Makefile.in updated"
else
    info "Makefile.in already contains the rule"
fi

# ============================================================
# 10. Configure + Build
# ============================================================
info "Preparing build directory..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

info "Running configure.sh..."
if [[ "$VARIANT" == "cachyos" || "$VARIANT" == "cachy" ]]; then
    "$SRC_DIR/configure.sh" \
        --enable-ccache \
        --build-name="$BUILD_NAME" \
        --container-engine="$CONTAINER_ENGINE" \
        || die "configure.sh failed"
else
    "$SRC_DIR/configure.sh" \
        --build-name="$BUILD_NAME" \
        --container-engine="$CONTAINER_ENGINE" \
        || die "configure.sh failed"
fi

info "Building redist (this will take a long time)..."
make redist 2>&1 | tee build.log || die "make redist failed – see build.log"

# ============================================================
# 11. Final verification
# ============================================================
info "Verifying output..."

TARBALL=$(find . -maxdepth 2 -name "${BUILD_NAME}*.tar.gz" | head -1)

if [[ -z "$TARBALL" ]]; then
    TARBALL=$(find . -maxdepth 2 -name "*.tar.gz" -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2-)
fi

if [[ -z "$TARBALL" || ! -s "$TARBALL" ]]; then
    die "No valid redistributable tarball was produced"
fi

info "Found package: $TARBALL"

if tar -tzf "$TARBALL" | grep -q 'user_settings.py'; then
    info "user_settings.py is present in the package"
else
    warn "user_settings.py was NOT found inside the tarball"
fi

echo
echo "============================================================"
echo "  BUILD SUCCESSFUL"
echo "============================================================"
echo "  Variant      : $VARIANT"
echo "  Branch/Tag   : $BRANCH"
echo "  Source       : $SRC_DIR"
echo "  Build dir    : $BUILD_DIR"
echo "  Package      : $TARBALL"
echo "============================================================"
echo
echo "Install with:"
echo "  mkdir -p ~/.steam/root/compatibilitytools.d/${BUILD_NAME}"
echo "  tar -xf \"$TARBALL\" -C ~/.steam/root/compatibilitytools.d/${BUILD_NAME} --strip-components=1"
echo
