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

/* From -DLINUWUX_VERSION; "dev" if built by hand. */
#ifndef LINUWUX_VERSION
#define LINUWUX_VERSION "dev"
#endif

#ifndef ARCH_SET_CPUID
#define ARCH_SET_CPUID 0x1012
#endif

/* Shared by every module; implemented in common.c. */
void linuwux_log(const char *fmt, ...);

/* Win64 TEB: %gs:0x30 (NtTib.Self). Header-only: each TU gets its own
 * static copy, which is fine for a one-instruction inline. */
static inline void *linuwux_get_teb(void)
{
    void *teb;
    __asm__ volatile ("movq %%gs:0x30, %0" : "=r"(teb));
    return teb;
}

#endif /* LINUWUX_H */
