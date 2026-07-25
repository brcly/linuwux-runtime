#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Proton + LinUwUx patches – universal builder
# Supports: proton-cachyos  and  proton-ge-custom (GE)
# ============================================================

VARIANT="${1:-cachyos}"          # cachyos | ge
BRANCH="${2:-}"                  # optional
CONTAINER_ENGINE="podman"
PATCH_REPO="https://github.com/brcly/proton-LinUwUx-patch.git"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP_PATCHES="${SCRIPT_DIR}/.tmp-patches"

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "==> $*"; }
need() { command -v "$1" >/dev/null 2>&1 || die "'$1' is required"; }

need git
need podman
need make
need sed

# -------------------- Resolve variant --------------------
case "$VARIANT" in
    cachyos|cachy)
        REPO="https://github.com/CachyOS/proton-cachyos.git"
        DEFAULT_BRANCH="cachyos_11.0_20260702/main"
        NAME_PREFIX="proton-cachyos"
        ;;
    ge|proton-ge|eggroll)
        REPO="https://github.com/GloriousEggroll/proton-ge-custom.git"
        DEFAULT_BRANCH="master"
        NAME_PREFIX="GE-Proton"
        ;;
    *)
        die "Unknown variant '$VARIANT'. Use: cachyos  or  ge"
        ;;
esac

BRANCH="${BRANCH:-$DEFAULT_BRANCH}"

echo
echo "============================================================"
echo "  Proton + LinUwUx builder"
echo "  Variant     : $VARIANT"
echo "  Branch/Tag  : $BRANCH"
echo "============================================================"
echo

# ============================================================
# 1. Download LinUwUx patches
# ============================================================
info "Downloading LinUwUx patches..."
rm -rf "$TMP_PATCHES"
git clone --depth 1 "$PATCH_REPO" "$TMP_PATCHES"

# ============================================================
# 2. Temporary clone to determine the real version string
# ============================================================
# We need the version *before* deciding the final folder names
TEMP_SRC="${SCRIPT_DIR}/.tmp-src-version"
rm -rf "$TEMP_SRC"

info "Detecting version..."
git clone --branch "$BRANCH" --depth 1 --tags "$REPO" "$TEMP_SRC" 2>/dev/null || \
git clone --depth 1 --tags "$REPO" "$TEMP_SRC"

cd "$TEMP_SRC"
git checkout "$BRANCH" 2>/dev/null || true

RAW_VERSION=$(git describe --tags --always 2>/dev/null || echo "$BRANCH")

# Clean the version string for folder / package names
# Examples:
#   GE-Proton11-3          → GE-Proton-11-3
#   cachyos_11.0_20260702  → proton-cachyos-11.0-20260702
VERSION_ID=$(echo "$RAW_VERSION" | \
    sed -E 's/^GE-Proton/GE-Proton-/; s/^cachyos_/proton-cachyos-/; s/_/-/g; s|/|-|g')

# Final names
SRC_DIR="${SCRIPT_DIR}/${VERSION_ID}-src"
BUILD_DIR="${SCRIPT_DIR}/${VERSION_ID}-build"
BUILD_NAME="${VERSION_ID}-LinUwUx"

info "Detected version : $RAW_VERSION"
info "Source folder    : $SRC_DIR"
info "Build  folder    : $BUILD_DIR"
info "Package name     : $BUILD_NAME"

# Move the temporary clone to the final source location
rm -rf "$SRC_DIR"
mv "$TEMP_SRC" "$SRC_DIR"
cd "$SRC_DIR"

# ============================================================
# 3. Force clean submodule update (critical for GE)
# ============================================================
info "Forcing full submodule update (this can take a while)..."
git submodule deinit -f --all 2>/dev/null || true
git submodule update --init --recursive --force

# ============================================================
# 4. Install LinUwUx patches + register them for GE
# ============================================================
info "Installing LinUwUx patches..."

rm -rf patches/wine/dlls/ntdll/unix patches/wine/loader patches/wine/server
mkdir -p patches/wine/dlls/ntdll/unix patches/wine/loader patches/wine/server

cp "$TMP_PATCHES/patches/wine/dlls/ntdll/unix/0001-spoof-cpuid.patch" \
   patches/wine/dlls/ntdll/unix/
cp "$TMP_PATCHES/patches/wine/loader/0001-regedit.patch" \
   patches/wine/loader/
cp "$TMP_PATCHES/patches/wine/server/0001-apply_faketime.patch" \
   patches/wine/server/
cp "$TMP_PATCHES/patches/wine/server/0002-apply_faketime.patch" \
   patches/wine/server/

info "Patch files installed:"
find patches/wine -name '*.patch' | sed 's|^|      |'

# GE only: inject the patches into the correct section of the prep script
if [[ "$VARIANT" == "ge" || "$VARIANT" == "proton-ge" || "$VARIANT" == "eggroll" ]]; then
    PREP_SCRIPT=$(find patches -maxdepth 1 -name 'protonprep*.sh' | head -1)

    if [[ -z "$PREP_SCRIPT" ]]; then
        die "No protonprep script found in patches/"
    fi

    info "Injecting LinUwUx patches into $PREP_SCRIPT ..."

    if ! grep -q "0001-spoof-cpuid.patch" "$PREP_SCRIPT"; then
        MARKER_LINE=$(grep -n '### END WINE HOTFIX/BACKPORT SECTION ###' "$PREP_SCRIPT" | head -1 | cut -d: -f1)

        if [[ -z "$MARKER_LINE" ]]; then
            die "Could not find '### END WINE HOTFIX/BACKPORT SECTION ###' marker"
        fi

        INSERT_BLOCK=$(cat << 'EOF'
### LinUwUx patches (auto-added by build script)
apply_patch "../patches/wine/dlls/ntdll/unix/0001-spoof-cpuid.patch"
apply_patch "../patches/wine/loader/0001-regedit.patch"
apply_patch "../patches/wine/server/0001-apply_faketime.patch"
apply_patch "../patches/wine/server/0002-apply_faketime.patch"

EOF
)

        {
            head -n $((MARKER_LINE - 1)) "$PREP_SCRIPT"
            echo "$INSERT_BLOCK"
            tail -n +$MARKER_LINE "$PREP_SCRIPT"
        } > "${PREP_SCRIPT}.tmp"

        mv "${PREP_SCRIPT}.tmp" "$PREP_SCRIPT"
        chmod +x "$PREP_SCRIPT"

        info "Patches successfully injected before line $MARKER_LINE"
    else
        info "Patches already present – skipping"
    fi
fi

rm -rf "$TMP_PATCHES"

# ============================================================
# 5. GE-specific: run protonprep script
# ============================================================
if [[ "$VARIANT" == "ge" || "$VARIANT" == "proton-ge" || "$VARIANT" == "eggroll" ]]; then
    PREP_SCRIPT=$(find patches -maxdepth 1 -name 'protonprep*.sh' | head -1)
    if [[ -n "$PREP_SCRIPT" ]]; then
        info "Running GE prep script: $PREP_SCRIPT"
        bash "$PREP_SCRIPT" 2>&1 | tee prep.log
        if grep -qiE 'fail|error' prep.log; then
            echo "WARNING: prep script reported possible issues – check prep.log"
        fi
    else
        info "No protonprep script found – continuing without it"
    fi
fi

# ============================================================
# 6. Create user_settings.py
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
# 7. Patch Makefile.in so user_settings.py is packaged
# ============================================================
info "Patching Makefile.in..."

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
# 8. Clean build directory + Configure
# ============================================================
info "Preparing clean build directory..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

info "Running configure.sh..."

if [[ "$VARIANT" == "cachyos" || "$VARIANT" == "cachy" ]]; then
    "$SRC_DIR/configure.sh" \
        --enable-ccache \
        --build-name="$BUILD_NAME" \
        --container-engine="$CONTAINER_ENGINE"
else
    "$SRC_DIR/configure.sh" \
        --build-name="$BUILD_NAME" \
        --container-engine="$CONTAINER_ENGINE"
fi

# ============================================================
# 9. Build
# ============================================================
info "Building redist (this will take a long time)..."
make redist 2>&1 | tee build.log

echo
echo "============================================================"
echo "  Build finished successfully!"
echo "  Variant      : $VARIANT"
echo "  Branch/Tag   : $BRANCH"
echo "  Source       : $SRC_DIR"
echo "  Build        : $BUILD_DIR"
echo "  Package name : $BUILD_NAME"
echo "============================================================"
