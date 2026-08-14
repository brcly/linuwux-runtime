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
 * linuwux -- SIGSYS/DenuvOwO redirect.
 */

#define _GNU_SOURCE
#include <stdatomic.h>
#include <stddef.h>
#include <stdlib.h>
#include <ucontext.h>

#include "linuwux.h"
#include "cpuid.h"
#include "sigsys.h"

/* Typical Proton/GE ntdll/kernel PE range — skip redirects here unless forced. */
#define LINUWUX_WINE_SYSTEM_RIP_MIN 0x00006FFFFF000000ULL
#define LINUWUX_WINE_SYSTEM_RIP_MAX 0x0000700000000000ULL

static int linuwux_rip_is_wine_system(unsigned long long rip)
{
    return rip >= LINUWUX_WINE_SYSTEM_RIP_MIN && rip < LINUWUX_WINE_SYSTEM_RIP_MAX;
}

static int linuwux_redirect_all_enabled(void)
{
    const char *env = getenv("LINUWUX_REDIRECT_ALL");
    return env && env[0] == '1' && env[1] == '\0';
}

/* TEB offset of SUD selector; -1 if unused (seccomp trees). */
static _Atomic ptrdiff_t g_sud_teb_offset = -1;

void linuwux_sigsys_learn_sud_offset(ptrdiff_t teb_offset)
{
    atomic_store(&g_sud_teb_offset, teb_offset);
}

static void linuwux_rearm_sud(void)
{
    ptrdiff_t teb_offset = atomic_load(&g_sud_teb_offset);
    if (teb_offset < 0)
        return;
    unsigned char *teb = (unsigned char *)linuwux_get_teb();
    teb[teb_offset] = 1;  /* BLOCK */
}

int linuwux_sigsys_route(ucontext_t *ctx)
{
    __uint128_t *xmm_regs;
    unsigned long long syscall_nr, rip, resume, target_sys_handler;
    unsigned char *fault_ip, opcode0, opcode1;

    if (!ctx->uc_mcontext.fpregs)
        return 0;
    xmm_regs = (__uint128_t *)ctx->uc_mcontext.fpregs->_xmm;

    target_sys_handler = linuwux_cpuid_target_sys_handler();
    if (target_sys_handler == 0 ||
        (xmm_regs[5] & 0xFFFFFFFFFFFFFFFFULL) == 0x1337133713371337ULL)
        goto not_ours;

    syscall_nr = (unsigned long long)ctx->uc_mcontext.gregs[REG_RAX];
    rip = (unsigned long long)ctx->uc_mcontext.gregs[REG_RIP];

    if (!linuwux_redirect_all_enabled() && linuwux_rip_is_wine_system(rip))
        return 0;

    fault_ip = (unsigned char *)(uintptr_t)rip;
    opcode0 = fault_ip[0];
    opcode1 = fault_ip[1];
    /* Advance past `syscall` (0f 05) when that is the fault site. */
    resume = (opcode0 == 0x0f && opcode1 == 0x05) ? rip + 2 : rip;

    linuwux_log("sigsys redirect rax=%llx rip=%llx resume=%llx -> %#llx\n",
                syscall_nr, rip, resume, target_sys_handler);

    xmm_regs[4] = (xmm_regs[4] & ~(__uint128_t)0xFFFFFFFFULL) | (syscall_nr & 0xFFFFFFFF);
    ctx->uc_mcontext.gregs[REG_RAX] = (long long)resume;
    ctx->uc_mcontext.gregs[REG_RCX] = (long long)target_sys_handler;
    ctx->uc_mcontext.gregs[REG_RIP] = (long long)target_sys_handler;

    linuwux_rearm_sud();
    return 1;

not_ours:
    if ((xmm_regs[5] & 0xFFFFFFFFFFFFFFFFULL) == 0x1337133713371337ULL)
        xmm_regs[5] = 0;
    return 0;
}
