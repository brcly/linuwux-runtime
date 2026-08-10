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

# Base file checks, configure, make redist, package, verify, cleanup.
# DLL overrides live in the proton script (apply_proton_dll_overrides).
# Sourced by build.sh — requires lib/common.sh already loaded.

check_required_base_files() {
    info "Checking required base files..."

    [[ -f "${PATCHES_DIR}/base/linuwux_hooks.c" ]] \
        || die "linuwux_hooks.c not found under ${PATCHES_DIR}/base/ – required"
    if [[ $LEGACY_REFLEX -eq 1 ]]; then
        [[ -f "${PATCHES_DIR}/legacy-reflex/linuwux_hooks_legacy.c" ]] \
            || die "linuwux_hooks_legacy.c not found under ${PATCHES_DIR}/legacy-reflex/ – required for --legacy-reflex"
    fi
    [[ -f "${PATCHES_DIR}/base/hwprofile_guid.reg" ]] \
        || die "hwprofile_guid.reg not found under ${PATCHES_DIR}/base/ – required"
    [[ -f "${PATCHES_DIR}/base/set_faketime.protocol" ]] \
        || die "set_faketime.protocol not found under ${PATCHES_DIR}/base/ – required"
    [[ -f "${LIB_DIR}/apply-proton-dll.sh" ]] \
        || die "apply-proton-dll.sh not found under ${LIB_DIR}/ – required"

    info "  Base files present"
}

run_configure_and_build() {
    info "Preparing build directory..."
    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"

    info "Running configure.sh..."
    local ccache_flag=()
    if [[ "$VARIANT" == "cachyos" ]]; then
        ccache_flag=(--enable-ccache)
    fi
    "$SRC_DIR/configure.sh" "${ccache_flag[@]}" \
        --build-name="$BUILD_NAME" \
        --container-engine="$CONTAINER_ENGINE" \
        || die "configure.sh failed"

    info "Building redist (this will take a long time)..."
    make redist 2>&1 | tee "$LOG_DIR/build.log" || die "make redist failed – see $LOG_DIR/build.log"
}

package_and_verify() {
    info "Verifying / packaging output..."

    local TARBALL REDIST_DIR SIZE_MB MISSING listing FINAL_TARBALL

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

    [[ $MISSING -eq 0 ]] || die "Package failed verification (missing core files) – see warnings above"

    mkdir -p "$DIST_DIR"
    FINAL_TARBALL="${DIST_DIR}/$(basename "$TARBALL")"
    mv -f "$TARBALL" "$FINAL_TARBALL"
    info "Tarball moved to $FINAL_TARBALL"

    FINAL_TARBALL_PATH="$FINAL_TARBALL"
}

cleanup_trees() {
    cd "$SCRIPT_DIR"
    if [[ $CLEAN -eq 1 ]]; then
        info "Cleaning up build artifacts (use --no-clean to keep them)..."
        rm -rf "$SRC_DIR" "$BUILD_DIR"
        info "  Removed $(basename "$SRC_DIR") and $(basename "$BUILD_DIR")"
    else
        info "Keeping -src/-build trees (--no-clean)"
    fi
}

print_success() {
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
    echo -e "  ${BOLD}Package${RESET}      : $FINAL_TARBALL_PATH"
    header "$HR"
    echo
    echo "Install with:"
    echo "  mkdir -p ~/.steam/root/compatibilitytools.d/${BUILD_NAME}"
    echo "  tar -xf \"$FINAL_TARBALL_PATH\" -C ~/.steam/root/compatibilitytools.d/${BUILD_NAME} --strip-components=1"
    echo
}
