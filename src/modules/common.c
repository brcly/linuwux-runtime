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
 * linuwux -- shared logging.
 */

#define _GNU_SOURCE
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "linuwux.h"

/* Default 1 so test harnesses without set_game_process still log. */
static int g_is_game_process = 1;

void linuwux_set_game_process(int is_game)
{
    g_is_game_process = is_game;
}

int linuwux_is_game_process(void)
{
    return g_is_game_process;
}

void linuwux_log(const char *fmt, ...)
{
    va_list ap;
    if (!g_is_game_process || !getenv("LINUWUX_DEBUG"))
        return;
    fprintf(stderr, "[linuwux] ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}
