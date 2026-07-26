#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Proton + LinUwUx Builder
#
# Clones proton-cachyos or proton-ge-custom, applies the LinUwUx patch set
# (CPU ID spoof, faketime, hardware profile GUID), and produces a
# redistributable Steam Play compatibility tool.
# ============================================================

VERSION="1.8.2"
CONTAINER_ENGINE="podman"
PATCH_REPO="https://github.com/brcly/proton-LinUwUx-patch.git"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP_PATCHES="${SCRIPT_DIR}/.tmp-patches"
FORCE=0

# -------------------- Colour output (disabled when not a terminal) --------------------
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

# -------------------- Small helpers used throughout --------------------
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
  $(basename "$0") --container-engine=docker ge

Options:
  -f, --force               Force full re-clone and clean rebuild
  --container-engine=<name> Container engine to build with (default: podman)
  -h, --help                Show this help

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
need "$CONTAINER_ENGINE"
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
# 2 & 3. Determine version string + prepare source tree (reuse if possible)
# ============================================================

# Turns a branch/tag string into a folder-safe version ID. For both variants
# the branch/tag the user gave us already IS the version - GE tags read
# straight through (GE-Proton11-3), while CachyOS branches encode the date
# and an internal subpath (/main, /main_native) that we map to their actual
# release naming (-slr, -native) so that doesn't leak through literally.
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

# Repairs a shallow git history. A --depth clone (or --filter=tree:0 clone
# missing full history) leaves `git describe --tags` unable to find anything
# - and the Proton build system runs that same command later to stamp the
# redist's version file, so a shallow tree here breaks protonfixes at launch.
ensure_unshallow() {
    if git rev-parse --is-shallow-repository 2>/dev/null | grep -q true; then
        info "  Repo is shallow – fetching full history/tags..."
        git fetch --unshallow --tags --force \
            || warn "  Unshallow fetch failed – version detection may still break at build time!"
    fi
}

VERSION_ID=$(compute_version_id "$BRANCH" "$VARIANT")
SRC_DIR="${SCRIPT_DIR}/${VERSION_ID}-src"
BUILD_DIR="${SCRIPT_DIR}/${VERSION_ID}-build"
BUILD_NAME="${VERSION_ID}-LinUwUx"
LOG_DIR="${SCRIPT_DIR}/logs/${VERSION_ID}"

info "Building version : $BRANCH"
info "Source folder    : $SRC_DIR"
info "Build  folder    : $BUILD_DIR"
info "Log    folder    : $LOG_DIR"
info "Package name     : $BUILD_NAME"
pause

# LOG_DIR lives outside SRC_DIR/BUILD_DIR so logs survive both a --force
# re-clone and the build directory being wiped later in step 9.
rm -rf "$LOG_DIR"
mkdir -p "$LOG_DIR"

if [[ $FORCE -eq 0 && -d "$SRC_DIR/.git" ]]; then
    info "Reusing existing source tree (use --force to re-clone)"
    cd "$SRC_DIR"
    ensure_unshallow
    git fetch --tags --force || true
    git checkout -q "$BRANCH" 2>/dev/null || git checkout -q -B "$BRANCH" "origin/$BRANCH"
    # A tag (e.g. GE-Proton11-3) checks out detached with nothing to pull;
    # only try when we actually landed on a real branch.
    if git symbolic-ref -q HEAD >/dev/null; then
        git pull --ff-only || true
    fi
else
    info "Cloning source..."
    rm -rf "$SRC_DIR"
    # --filter=tree:0 keeps full commit/tag history (unlike --depth) while
    # still deferring blob/tree content, so `git describe --tags` works both
    # here and later inside the build system's own dist rule.
    if ! git clone --branch "$BRANCH" --filter=tree:0 --tags "$REPO" "$SRC_DIR" 2>/dev/null; then
        info "Branch/tag not found on default clone attempt – retrying without --branch..."
        git clone --filter=tree:0 --tags "$REPO" "$SRC_DIR" || die "Failed to clone $REPO"
        cd "$SRC_DIR"
        git checkout -q "$BRANCH" 2>/dev/null || die "Branch/tag '$BRANCH' not found"
    else
        cd "$SRC_DIR"
    fi
    ensure_unshallow
fi
pause

# ============================================================
# 4. Submodule update (full deinit only on --force)
# ============================================================
info "Updating submodules (this can take a while)..."
if [[ $FORCE -eq 1 ]]; then
    info "  --force: deiniting submodules for a full clean update"
    git submodule deinit -f --all 2>/dev/null || true
fi
git submodule update --init --recursive --force --filter=tree:0 || die "Submodule update failed"
pause

# ============================================================
# 5. Install LinUwUx patch files
# ============================================================
info "Installing LinUwUx patch files..."

rm -rf patches/wine/dlls/ntdll/unix patches/wine/server
mkdir -p patches/wine/dlls/ntdll/unix patches/wine/server

# patches/wine/loader/0001-regedit.patch is deliberately not installed here -
# apply_regedit_fix() (below) handles that fix directly instead. Remove any
# copy left over from an older run, since CachyOS's build system would
# otherwise auto-apply it too.
rm -rf patches/wine/loader

cp "$TMP_PATCHES/patches/wine/dlls/ntdll/unix/0001-spoof-cpuid.patch" \
   patches/wine/dlls/ntdll/unix/ || die "Missing spoof-cpuid patch"
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
#
# CachyOS auto-applies anything under patches/wine/ during its own build
# (installed above), so only the regedit fix needs to run manually there.
# GE has no such mechanism, so we apply everything ourselves.
# ============================================================

# HwProfileGuid is appended directly rather than shipped as a .patch file:
# wine.inf.in content drifts enough between branches that a literal patch
# can fail to apply, and on CachyOS a failed auto-applied patch hard-fails
# the whole build. This append is idempotent and identical for both variants.
apply_regedit_fix() {
    local wine_dir="$1"
    local inf="${wine_dir}/loader/wine.inf.in"
    local line='HKLM,System\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001,"HwProfileGuid",,"{12345678-1234-1234-1234-123456789012}"'

    info "Applying regedit fix (HwProfileGuid) to $inf ..."
    # This is one of the patches the project exists for - fail loudly rather
    # than silently shipping a build that's missing it.
    [[ -f "$inf" ]] || die "$inf not found - wine's layout may have changed upstream"

    if grep -q 'HwProfileGuid' "$inf"; then
        info "  HwProfileGuid already present"
    else
        echo "$line" >> "$inf"
        info "  Appended HwProfileGuid line"
    fi
}

# Applies one patch file with consistent logging. --fuzz=0 requires an exact
# context match: without it, `patch` can "succeed" against drifted context
# and land the hunk in subtly the wrong place. An honest failure (returned to
# the caller) beats a quiet, wrong patch application.
apply_patch_file() {
    local patch_file="$1" label="$2" log="$3"
    {
        echo "============================================================"
        echo "Applying: $label"
        echo "============================================================"
    } >> "$log" 2>&1

    if patch -Np1 --forward --fuzz=0 < "$patch_file" >> "$log" 2>&1; then
        info "  $label applied"
        return 0
    else
        warn "  $label FAILED to apply – see $log"
        return 1
    fi
}

# Applies the GE-side patch set and fails the build if any of them didn't
# actually take - a build that "succeeds" while silently missing these
# patches defeats the entire point of the project.
apply_linuwux_patches() {
    local wine_dir="$1"
    local patch_log="${LOG_DIR}/linuwux-patches.log"
    local failures=0
    info "Applying LinUwUx patches to $wine_dir ..."
    info "Patch log → $patch_log"
    : > "$patch_log"

    pushd "$wine_dir" > /dev/null

    apply_patch_file "$SRC_DIR/patches/wine/dlls/ntdll/unix/0001-spoof-cpuid.patch" \
        "0001-spoof-cpuid.patch" "$patch_log" || failures=$((failures+1))
    apply_patch_file "$SRC_DIR/patches/wine/server/0001-apply_faketime.patch" \
        "0001-apply_faketime.patch" "$patch_log" || failures=$((failures+1))
    apply_patch_file "$SRC_DIR/patches/wine/server/0002-apply_faketime.patch" \
        "0002-apply_faketime.patch" "$patch_log" || failures=$((failures+1))

    # Confirm the CPUID patch actually took effect - `patch` exiting 0 only
    # means the hunk applied somewhere, not that it's the code we expect.
    if grep -q "0x336933\|Spoofing CPUID" dlls/ntdll/unix/signal_x86_64.c; then
        info "  CPUID leaf handling is present"
    else
        warn "  CPUID leaf handling (0x336933) is missing"
        failures=$((failures+1))
    fi

    info "Regenerating server protocol (tools/make_requests)..."
    if [[ -x tools/make_requests ]]; then
        ./tools/make_requests >> "$patch_log" 2>&1 || warn "tools/make_requests returned non-zero"
    else
        warn "tools/make_requests not found or not executable"
    fi

    popd > /dev/null
    info "Full patch log: $patch_log"

    if [[ $failures -gt 0 ]]; then
        die "$failures LinUwUx patch step(s) failed - see $patch_log (stopping rather than shipping a build silently missing them)"
    fi
}

if [[ "$VARIANT" == "ge" ]]; then
    PREP_SCRIPT=$(find patches -maxdepth 1 -name 'protonprep*.sh' | head -1)
    if [[ -n "$PREP_SCRIPT" ]]; then
        info "Running GE protonprep..."
        bash "$PREP_SCRIPT" 2>&1 | tee "$LOG_DIR/prep.log" || warn "protonprep returned non-zero"

        # GE's own docs say to check the prep log for failed patches rather
        # than treat any single one as fatal - do that check automatically.
        FAIL_LINES=$(grep -ic 'fail' "$LOG_DIR/prep.log" 2>/dev/null || true)
        if [[ "${FAIL_LINES:-0}" -gt 0 ]]; then
            warn "protonprep log contains ${FAIL_LINES} line(s) mentioning 'fail' – review $LOG_DIR/prep.log:"
            grep -i 'fail' "$LOG_DIR/prep.log" | sed 's|^|      |'
        else
            info "protonprep log clean – no failures mentioned"
        fi
    else
        warn "No protonprep script found – continuing"
    fi
    pause
    apply_regedit_fix "wine"
    apply_linuwux_patches "wine"
else
    info "CachyOS – patch files installed; build system will apply them"
    info "Skipping manual apply to avoid double-patching"
    apply_regedit_fix "wine"
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
#
# Proton's Makefile only ships user_settings.sample.py by default; this adds
# a matching rule so our real user_settings.py gets copied into the redist
# too. Skipped if already present, so reused source trees don't get patched
# twice.
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
# 9. Configure + build
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
make redist 2>&1 | tee "$LOG_DIR/build.log" || die "make redist failed – see $LOG_DIR/build.log"

# ============================================================
# 10. Final verification & packaging
#
# CachyOS produces a redist/ directory; GE produces a tarball directly. This
# normalizes either into one archive named *-LinUwUx.* so installation is
# identical for both.
# ============================================================
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

        # Official CachyOS releases ship .tar.xz; GE ships .tar.gz. Match that
        # convention, falling back to gzip if xz isn't installed.
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
echo -e "  ${BOLD}Logs${RESET}         : $LOG_DIR"
echo -e "  ${BOLD}Package${RESET}      : $TARBALL"
header "============================================================"
echo
echo "Install with:"
echo "  mkdir -p ~/.steam/root/compatibilitytools.d/${BUILD_NAME}"
echo "  tar -xf \"$TARBALL\" -C ~/.steam/root/compatibilitytools.d/${BUILD_NAME} --strip-components=1"
echo
