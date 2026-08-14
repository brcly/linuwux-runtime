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

#ifndef LINUWUX_CPUID_H
#define LINUWUX_CPUID_H

#include <signal.h>
#include <stdint.h>
#include <ucontext.h>

/* Reads the host CPU vendor and fills the spoofed leaf tables.
 * Must run in the constructor, before any other thread exists. */
void linuwux_detect_cpu_vendor(void);

/* Handle a CPUID fault. Returns 1 if handled. */
int linuwux_cpuid_spoof(siginfo_t *info, ucontext_t *ctx);

/* True after a legacy Reflex init leaf selects the compatibility protocol. */
int linuwux_cpuid_legacy_active(void);

/* TargetSysHandler, set by the arm leaf; 0 == not armed yet. */
uint64_t linuwux_cpuid_target_sys_handler(void);

/*
 * Protocol-aware syscall redirect target for SIGSYS.
 * Modern: handler from arm leaf, RAX := resume after syscall.
 * Legacy can set rax_is_resume = 0 (RAX keeps the pre-redirect RCX).
 */
struct linuwux_syscall_route {
    uint64_t handler;
    int rax_is_resume;
};

/* Returns 1 if armed and out is filled; 0 if not armed. */
int linuwux_cpuid_syscall_route(ucontext_t *ctx, struct linuwux_syscall_route *out);

#endif /* LINUWUX_CPUID_H */
