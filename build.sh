#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Proton + LinUwUx Builder v2.2
# Supports: proton-cachyos, proton-ge-custom (GE)
# ============================================================

VERSION="1.5"
CONTAINER_ENGINE="podman"
PATCH_REPO="https://github.com/brcly/proton-LinUwUx-patch.git"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP_PATCHES="${SCRIPT_DIR}/.tmp-patches"
FORCE=0

# -------------------- Colours --------------------
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

die()  { echo -e "${RED}ERROR: $*${RESET}" >&2; exit 1; }
info() { echo -e "${GREEN}==> $*${RESET}"; }
warn() { echo -e "${YELLOW}WARNING: $*${RESET}" >&2; }
header(){ echo -e "\n${CYAN}${BOLD}$*${RESET}"; }
need() { command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not found"; }
pause(){ sleep 1.2; }

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
  $(basename "$0") ge                       # latest GE
  $(basename "$0") ge GE-Proton11-3
  $(basename "$0") ge GE-Proton9-4

Options:
  -f, --force     Force full re-clone and clean rebuild
  -h, --help      Show this help

Versioned folders are used so multiple builds never overwrite each other.

Notes:
  - Both variants use the standard 0001-spoof-cpuid.patch
  - CachyOS local make redist → redist/ directory (official releases are .tar.xz)
  - GE typically produces a .tar.gz
  - This script accepts .tar.gz, .tar.xz, or a redist directory and always
    ends with a single redistributable archive named *-LinUwUx.*
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
        valve|proton)
            die "Valve/official Proton builds are not currently supported (debugger detection issues). Use cachyos or ge."
            ;;
        *)
            die "Unknown argument: $1  (use --help)"
            ;;
    esac
done

# -------------------- Resolve variant --------------------
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
need patch

header "============================================================"
header "  Proton + LinUwUx Builder v${VERSION}"
header "  Variant     : $VARIANT"
header "  Branch/Tag  : $BRANCH"
header "============================================================"
pause

# ============================================================
# 1. Download LinUwUx patches
# ============================================================
info "Downloading LinUwUx patches..."
rm -rf "$TMP_PATCHES"
git clone --depth 1 "$PATCH_REPO" "$TMP_PATCHES" || die "Failed to clone patch repository"
pause

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

RAW_VERSION=$(git describe --tags --always 2>/dev/null || true)
# If describe only gave a short hash (no tag), fall back to the branch name
if [[ -z "$RAW_VERSION" || "$RAW_VERSION" =~ ^[0-9a-f]{7,12}$ ]]; then
    RAW_VERSION="$BRANCH"
fi

case "$VARIANT" in
    ge)
        VERSION_ID=$(echo "$RAW_VERSION" | sed -E 's/^GE-Proton/GE-Proton-/; s/_/-/g; s|/|-|g')
        ;;
    *)
        # Turn branch-style names into folder-safe IDs
        VERSION_ID=$(echo "$RAW_VERSION" | sed -E 's/^cachyos[_-]?/proton-cachyos-/; s|/|-|g; s/_/-/g')
        # Still only a hash? prefix it
        if [[ "$VERSION_ID" =~ ^[0-9a-f]{7,12}$ ]]; then
            VERSION_ID="proton-cachyos-${VERSION_ID}"
        fi
        ;;
esac

case "$VARIANT" in
    ge)
        VERSION_ID=$(echo "$RAW_VERSION" | sed -E 's/^GE-Proton/GE-Proton-/; s/_/-/g; s|/|-|g')
        ;;
    *)
        VERSION_ID=$(echo "$RAW_VERSION" | sed -E 's/^cachyos_/proton-cachyos-/; s/_/-/g; s|/|-|g')
        ;;
esac

SRC_DIR="${SCRIPT_DIR}/${VERSION_ID}-src"
BUILD_DIR="${SCRIPT_DIR}/${VERSION_ID}-build"
BUILD_NAME="${VERSION_ID}-LinUwUx"

info "Detected version : $RAW_VERSION"
info "Source folder    : $SRC_DIR"
info "Build  folder    : $BUILD_DIR"
info "Package name     : $BUILD_NAME"
pause

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
pause

# ============================================================
# 4. Force clean submodule update
# ============================================================
info "Updating submodules (this can take a while)..."
git submodule deinit -f --all 2>/dev/null || true
git submodule update --init --recursive --force || die "Submodule update failed"
pause

# ============================================================
# 5. Install LinUwUx patch files
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

info "Ensuring faketime patch uses timeout_t (compatible with all versions)"
sed -i 's/unsigned __int64 faketime/timeout_t faketime/g' \
    patches/wine/server/0002-apply_faketime.patch
sed -i 's/unsigned hyper faketime/timeout_t faketime/g' \
    patches/wine/server/0002-apply_faketime.patch

info "Installed patches:"
find patches/wine -name '*.patch' | sed 's|^|      |'
pause

rm -rf "$TMP_PATCHES"

# ============================================================
# 6. Apply patches according to variant
# ============================================================

apply_linuwux_patches() {
    local wine_dir="$1"
    local patch_log="${SRC_DIR}/linuwux-patches.log"
    info "Applying LinUwUx patches to $wine_dir ..."
    info "Patch log → $patch_log"
    : > "$patch_log"

    pushd "$wine_dir" > /dev/null

    info "  → 0001-spoof-cpuid.patch"
    {
        echo "============================================================"
        echo "Applying: 0001-spoof-cpuid.patch  (variant=$VARIANT)"
        echo "============================================================"
        if patch -Np1 --forward < "$SRC_DIR/patches/wine/dlls/ntdll/unix/0001-spoof-cpuid.patch"; then
            echo "Result: OK"
        else
            echo "Result: FAILED (some hunks)"
        fi
    } >> "$patch_log" 2>&1

    if grep -q "FAILED" "$patch_log" 2>/dev/null; then
        warn "  CPUID patch had failed hunk(s) – check $patch_log"
    else
        info "  CPUID patch applied"
    fi

    info "  → 0001-regedit.patch (robust method)"
    {
        echo "============================================================"
        echo "Applying: 0001-regedit.patch (append method)"
        echo "============================================================"
        local inf="loader/wine.inf.in"
        local line='HKLM,System\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001,"HwProfileGuid",,"{12345678-1234-1234-1234-123456789012}"'
        if [[ -f "$inf" ]]; then
            if grep -q 'HwProfileGuid' "$inf"; then
                echo "HwProfileGuid already present"
            else
                echo "$line" >> "$inf"
                echo "Appended HwProfileGuid line"
            fi
        else
            echo "WARNING: $inf not found"
        fi
    } >> "$patch_log" 2>&1
    info "  regedit handled"

    info "  → 0001-apply_faketime.patch"
    patch -Np1 --forward < "$SRC_DIR/patches/wine/server/0001-apply_faketime.patch" >> "$patch_log" 2>&1 \
        || warn "  faketime #1 returned non-zero"

    info "  → 0002-apply_faketime.patch"
    patch -Np1 --forward < "$SRC_DIR/patches/wine/server/0002-apply_faketime.patch" >> "$patch_log" 2>&1 \
        || warn "  faketime #2 returned non-zero"

    if grep -q "0x336933\|Spoofing CPUID" dlls/ntdll/unix/signal_x86_64.c; then
        info "  CPUID leaf handling is present"
    else
        warn "  CPUID leaf handling (0x336933) is missing – check $patch_log"
    fi

    info "Regenerating server protocol (tools/make_requests)..."
    if [[ -x tools/make_requests ]]; then
        ./tools/make_requests >> "$patch_log" 2>&1 || warn "tools/make_requests returned non-zero"
    else
        warn "tools/make_requests not found or not executable"
    fi

    popd > /dev/null
    info "Full patch log: $patch_log"
}

if [[ "$VARIANT" == "ge" ]]; then
    PREP_SCRIPT=$(find patches -maxdepth 1 -name 'protonprep*.sh' | head -1)
    if [[ -n "$PREP_SCRIPT" ]]; then
        info "Running GE protonprep..."
        bash "$PREP_SCRIPT" 2>&1 | tee prep.log || warn "protonprep returned non-zero"
    else
        warn "No protonprep script found – continuing"
    fi
    pause
    apply_linuwux_patches "wine"
else
    # CachyOS: only install into patches/; Makefile applies them in .wine-post-source
    info "CachyOS – patch files installed; build system will apply them"
    info "Skipping manual apply to avoid double-patching"
fi
pause

# ============================================================
# 7. Create user_settings.py
# ============================================================
info "Creating user_settings.py..."
cat > user_settings.py << 'EOF'
# LinUwUx defaults – automatically included in the redist
user_settings = {
    "WINEDLLOVERRIDES": "winmm=n,b;version=n,b;reflex=n,b",
    "PROTON_DISABLE_LSTEAMCLIENT": "1",
}
EOF
pause

# ============================================================
# 8. Patch Makefile.in so user_settings.py is packaged
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
pause

# ============================================================
# 9. Configure + Build
# ============================================================
info "Preparing build directory..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"
pause

info "Running configure.sh..."
case "$VARIANT" in
    cachyos)
        "$SRC_DIR/configure.sh" \
            --enable-ccache \
            --build-name="$BUILD_NAME" \
            --container-engine="$CONTAINER_ENGINE" \
            || die "configure.sh failed"
        ;;
    ge)
        "$SRC_DIR/configure.sh" \
            --build-name="$BUILD_NAME" \
            --container-engine="$CONTAINER_ENGINE" \
            || die "configure.sh failed"
        ;;
esac
pause

info "Building redist (this will take a long time)..."
make redist 2>&1 | tee build.log || die "make redist failed – see build.log"

# ============================================================
# 10. Final verification & packaging
# ============================================================
info "Verifying / packaging output..."

# Prefer an existing archive produced by the build
TARBALL=$(find . -maxdepth 3 \( -name "${BUILD_NAME}*.tar.gz" -o -name "${BUILD_NAME}*.tar.xz" \) | head -1)

# Also accept any redist-named archive the Makefile may have produced
if [[ -z "$TARBALL" ]]; then
    TARBALL=$(find . -maxdepth 3 \( -name '*.tar.gz' -o -name '*.tar.xz' \) | head -1)
fi

# CachyOS (and sometimes others) only produce a redist/ directory
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

        # Official CachyOS releases use .tar.xz; GE uses .tar.gz.
        # Prefer xz for cachyos when xz is available, else gzip.
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

if tar -tf "$TARBALL" 2>/dev/null | grep -q 'user_settings.py'; then
    info "user_settings.py is present in the package"
else
    warn "user_settings.py was NOT found inside the archive"
fi

echo
header "============================================================"
header "  BUILD SUCCESSFUL"
header "============================================================"
echo -e "  ${BOLD}Variant${RESET}      : $VARIANT"
echo -e "  ${BOLD}Branch/Tag${RESET}   : $BRANCH"
echo -e "  ${BOLD}Source${RESET}       : $SRC_DIR"
echo -e "  ${BOLD}Build dir${RESET}    : $BUILD_DIR"
echo -e "  ${BOLD}Package${RESET}      : $TARBALL"
header "============================================================"
echo
echo "Install with:"
echo "  mkdir -p ~/.steam/root/compatibilitytools.d/${BUILD_NAME}"
echo "  tar -xf \"$TARBALL\" -C ~/.steam/root/compatibilitytools.d/${BUILD_NAME} --strip-components=1"
echo
