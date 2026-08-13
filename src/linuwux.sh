#!/bin/sh
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

# linuwux -- launch helper for liblinuwux.so
#
# Installed to ~/.local/bin/linuwux by build.sh --install. Steam launch
# option: ~/.local/bin/linuwux %command%

lib="${LINUWUX_PRELOAD:-${HOME}/.local/lib/liblinuwux.so}"

if [ "${1-}" = "--version" ] || [ "${1-}" = "-V" ]; then
    if [ ! -f "$lib" ]; then
        echo "linuwux: library not found: $lib" >&2
        exit 1
    fi
    if ! command -v strings >/dev/null 2>&1; then
        echo "linuwux: 'strings' (binutils) not found -- can't read the version tag" >&2
        echo "  every launch also prints it to stderr regardless (not just under LINUWUX_DEBUG)" >&2
        exit 1
    fi
    ver=$(strings "$lib" | sed -n 's/^linuwux //p' | head -1)
    echo "linuwux ${ver:-unknown} ($lib)"
    exit 0
fi

if [ ! -f "$lib" ]; then
    echo "linuwux: library not found: $lib" >&2
    echo "  Build/install it from proton-LinUwUx-patch, or set LINUWUX_PRELOAD to its path" >&2
    exit 1
fi
if [ "$#" -eq 0 ]; then
    echo "linuwux: no command given -- use it as a Steam launch option:" >&2
    echo "  ~/.local/bin/linuwux %command%" >&2
    exit 1
fi
export LD_PRELOAD="${LD_PRELOAD:+$LD_PRELOAD:}$lib"
exec "$@"
