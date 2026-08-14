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

#ifndef LINUWUX_H
#define LINUWUX_H

#include <stdlib.h>

/* From -DLINUWUX_VERSION; "dev" if built by hand. */
#ifndef LINUWUX_VERSION
#define LINUWUX_VERSION "dev"
#endif

#ifndef ARCH_SET_CPUID
#define ARCH_SET_CPUID 0x1012
#endif

/* Proton/GE builtin system PE range — exclude from CPUID/SIGSYS.
 * Exclusion (not allow-list) so relocated DRM still gets spoofed. */
#define LINUWUX_WINE_SYSTEM_RIP_MIN 0x00006FFFFF000000ULL
#define LINUWUX_WINE_SYSTEM_RIP_MAX 0x0000700000000000ULL

static inline int linuwux_rip_is_wine_system(unsigned long long rip)
{
    return rip >= LINUWUX_WINE_SYSTEM_RIP_MIN && rip < LINUWUX_WINE_SYSTEM_RIP_MAX;
}

/* LINUWUX_REDIRECT_ALL=1 disables the Wine-system exclusion. */
static inline int linuwux_redirect_all_enabled(void)
{
    const char *env = getenv("LINUWUX_REDIRECT_ALL");
    return env && env[0] == '1' && env[1] == '\0';
}

/* Shared by every module; implemented in common.c. */
void linuwux_log(const char *fmt, ...);

/* is_game: set once in the constructor. Gates log/hooks/overrides. */
void linuwux_set_game_process(int is_game);
int linuwux_is_game_process(void);

/* Win64 TEB: %gs:0x30 (NtTib.Self). Header-only: each TU gets its own
 * static copy, which is fine for a one-instruction inline. */
static inline void *linuwux_get_teb(void)
{
    void *teb;
    __asm__ volatile ("movq %%gs:0x30, %0" : "=r"(teb));
    return teb;
}

#endif /* LINUWUX_H */
