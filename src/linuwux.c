/*
 * Copyright (C) 2026 brcly
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/*
 * linuwux — LD_PRELOAD library for DenuvOwO/LinUwUx under Wine/Proton.
 *
 * Hooks: sigaction, prctl, clock_gettime, gettimeofday.
 * Provides: CPUID spoof, SIGSYS redirect, HwProfileGuid, DLL overrides, faketime.
 * Debug: LINUWUX_DEBUG=1
 *
 * Source is split by concern under modules/: cpuid.c, sigsys.c,
 * registry.c, faketime.c, hooks.c, common.c. This file is just the
 * constructor.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "modules/linuwux.h"
#include "modules/cpuid.h"

/* Kept for `strings` / `linuwux --version`. */
static const char linuwux_version_tag[] __attribute__((used)) =
    "linuwux " LINUWUX_VERSION;

static void linuwux_append_override(char *buf, size_t bufsize, const char *entry)
{
    size_t len = strlen(buf);
    int n;

    if (len >= bufsize)
        return;

    n = snprintf(buf + len, bufsize - len, "%s%s", len ? ";" : "", entry);
    if (n < 0 || len + (size_t)n >= bufsize)
        linuwux_log("WINEDLLOVERRIDES: not enough room to append \"%s\" -- skipping\n", entry);
}

__attribute__((constructor))
static void linuwux_init(void)
{
    char overrides[4096];
    const char *existing;
    int n;

    linuwux_detect_cpu_vendor();

    /* Append our DLL overrides without clobbering user-set keys. */
    existing = getenv("WINEDLLOVERRIDES");
    n = snprintf(overrides, sizeof(overrides), "%s", existing ? existing : "");
    if (existing && (n < 0 || (size_t)n >= sizeof(overrides)))
        linuwux_log("WINEDLLOVERRIDES: existing value (%zu bytes) doesn't fit our %zu-byte buffer -- truncated\n",
                     strlen(existing), sizeof(overrides));

    if (!existing || !strstr(existing, "winmm="))
        linuwux_append_override(overrides, sizeof(overrides), "winmm=n,b");
    if (!existing || !strstr(existing, "version="))
        linuwux_append_override(overrides, sizeof(overrides), "version=n,b");
    if (!existing || !strstr(existing, "reflex="))
        linuwux_append_override(overrides, sizeof(overrides), "reflex=n,b");

    setenv("WINEDLLOVERRIDES", overrides, 1);
    linuwux_log("WINEDLLOVERRIDES=\"%s\"\n", overrides);

    /* Default on for DenuvOwO; user can set 0. Overlay does not need lsteamclient. */
    setenv("PROTON_DISABLE_LSTEAMCLIENT", "1", 0);

    /* Always print version (not only under LINUWUX_DEBUG) for bug reports. */
    fprintf(stderr, "[linuwux] v%s loaded (pid=%d)\n", LINUWUX_VERSION, getpid());
}
