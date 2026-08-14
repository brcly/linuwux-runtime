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
 * linuwux — LD_PRELOAD library for DenuvOwO under Wine/Proton.
 * Constructor only; modules/ holds hooks, cpuid, sigsys, registry, faketime.
 * Debug: LINUWUX_DEBUG=1
 */

#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
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

/* is_game: argv[1] Windows path with reflex.dll in the same directory. */
static int linuwux_dir_has_reflex(const char *dir)
{
    DIR *d;
    struct dirent *ent;
    int found = 0;

    d = opendir(dir);
    if (!d)
        return 0;

    while ((ent = readdir(d))) {
        if (!strcasecmp(ent->d_name, "reflex.dll")) {
            found = 1;
            break;
        }
    }
    closedir(d);

    return found;
}

static int linuwux_game_dir_has_reflex(const char *argv0)
{
    const char *prefix;
    char path[PATH_MAX];
    char drive;
    char *slash;
    size_t i;
    int found;

    if (!argv0 || !argv0[0] || argv0[1] != ':') {
        linuwux_log("is_game: argv path missing or not X:\\... (%s)\n",
                    argv0 ? argv0 : "(null)");
        return 0;
    }

    drive = (char)tolower((unsigned char)argv0[0]);

    /* Z: = host filesystem root; skip dosdevices. */
    if (drive == 'z') {
        if (snprintf(path, sizeof(path), "%s", argv0 + 2) >= (int)sizeof(path))
            return 0;
    } else {
        /* dosdevices/<drive>: */
        prefix = getenv("WINEPREFIX");
        if (!prefix) {
            linuwux_log("is_game: no WINEPREFIX for drive %c:\n", drive);
            return 0;
        }

        if (snprintf(path, sizeof(path), "%s/dosdevices/%c:%s", prefix, drive, argv0 + 2) >= (int)sizeof(path))
            return 0;
    }

    for (i = 0; path[i]; i++)
        if (path[i] == '\\')
            path[i] = '/';

    slash = strrchr(path, '/');
    if (!slash)
        return 0;
    *slash = '\0';

    found = linuwux_dir_has_reflex(path);
    linuwux_log("is_game: dir=%s reflex=%s\n", path, found ? "yes" : "no");
    return found;
}

/* GNU constructor extension: glibc passes real argc/argv/envp. */
__attribute__((constructor))
static void linuwux_init(int argc, char **argv, char **envp)
{
    char overrides[4096];
    const char *existing;
    int n, is_game;

    (void)envp;

    /* Wine: argv[0] is the loader; argv[1] is the Windows target path. */
    is_game = linuwux_game_dir_has_reflex(argc > 1 ? argv[1] : NULL);
    linuwux_log("is_game: argv[1]=%s -> %s\n",
                (argc > 1 && argv[1]) ? argv[1] : "(none)",
                is_game ? "game" : "helper");
    linuwux_set_game_process(is_game);

    /* Spoof leaves only needed in the game process (CPUID path gated). */
    if (is_game)
        linuwux_detect_cpu_vendor();

    /* Overrides only in the game process (Wine reads env at PE load). */
    if (is_game) {
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
    }

    /* Global: Proton may read this before any Wine process starts. */
    setenv("PROTON_DISABLE_LSTEAMCLIENT", "1", 0);

    /* Version banner only for the game process. */
    if (is_game)
        fprintf(stderr, "[linuwux] v%s loaded (pid=%d)\n", LINUWUX_VERSION, getpid());
}
