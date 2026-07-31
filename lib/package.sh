#!/usr/bin/env bash
# user_settings wiring, configure, make redist, package, verify, cleanup.
# Sourced by build.sh — requires lib/common.sh already loaded.

install_user_settings_and_check_base() {
    info "Installing user_settings.py and checking required base files..."

    local user_settings_src="${PATCHES_DIR}/base/user_settings.py"
    [[ -f "$user_settings_src" ]] \
        || die "user_settings.py not found at $user_settings_src – obtain it and place it there before building"
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

    cp "$user_settings_src" user_settings.py
    info "  Installed from $user_settings_src"
}

wire_makefile_user_settings() {
    info "Ensuring user_settings.py is included in the package..."

    if grep -q 'USER_SETTINGS_REAL_TARGET' Makefile.in; then
        info "Makefile.in already contains the rule"
        return
    fi

    local anchor_dst='USER_SETTINGS_PY_TARGET := $(addprefix $(DST_BASE)/,user_settings.sample.py)'
    local anchor_src='$(USER_SETTINGS_PY_TARGET): $(addprefix $(SRCDIR)/,user_settings.sample.py)'
    local anchor_dist='DIST_COPY_TARGETS := $(FILELOCK_TARGET) $(PROTON_PY_TARGET) \'

    grep -qF "$anchor_dst"  Makefile.in || die "Makefile.in anchor missing (DST_BASE target) – upstream layout changed"
    grep -qF "$anchor_src"  Makefile.in || die "Makefile.in anchor missing (SRCDIR target) – upstream layout changed"
    grep -qF "$anchor_dist" Makefile.in || die "Makefile.in anchor missing (DIST_COPY_TARGETS) – upstream layout changed"

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
