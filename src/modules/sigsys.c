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
#include <stddef.h>
#include <stdlib.h>
#include <ucontext.h>

#include "linuwux.h"
#include "cpuid.h"
#include "sigsys.h"

/* Wine-system RIP helpers: linuwux.h */

/*
 * Wine amd64 keeps the SUD filter byte at TEB+0x340
 * (amd64_thread_data.syscall_dispatch). No prctl interpose needed.
 * ALLOW=0, BLOCK=1; only poke if it already looks like a filter byte
 * so seccomp-only trees (Proton 10) are left alone.
 */
#define LINUWUX_WINE_SUD_TEB_OFFSET 0x340

static void linuwux_rearm_sud(void)
{
    unsigned char *teb = (unsigned char *)linuwux_get_teb();
    unsigned char *sel;

    if (!teb)
        return;

    sel = teb + LINUWUX_WINE_SUD_TEB_OFFSET;
    if (*sel == 0 || *sel == 1)
        *sel = 1;  /* BLOCK before resuming TargetSysHandler */
}

int linuwux_sigsys_route(ucontext_t *ctx)
{
    __uint128_t *xmm_regs;
    struct linuwux_syscall_route route;
    unsigned long long syscall_nr, rip, resume, saved_rcx;
    unsigned char *fault_ip, opcode0, opcode1;

    if (!ctx->uc_mcontext.fpregs)
        return 0;
    xmm_regs = (__uint128_t *)ctx->uc_mcontext.fpregs->_xmm;

    if (!linuwux_cpuid_syscall_route(ctx, &route) ||
        (xmm_regs[5] & 0xFFFFFFFFFFFFFFFFULL) == 0x1337133713371337ULL)
        goto not_ours;

    syscall_nr = (unsigned long long)ctx->uc_mcontext.gregs[REG_RAX];
    rip = (unsigned long long)ctx->uc_mcontext.gregs[REG_RIP];
    saved_rcx = (unsigned long long)ctx->uc_mcontext.gregs[REG_RCX];

    if (!linuwux_redirect_all_enabled() && linuwux_rip_is_wine_system(rip))
        return 0;

    fault_ip = (unsigned char *)(uintptr_t)rip;
    opcode0 = fault_ip[0];
    opcode1 = fault_ip[1];
    /* Advance past `syscall` (0f 05) when that is the fault site. */
    resume = (opcode0 == 0x0f && opcode1 == 0x05) ? rip + 2 : rip;

    linuwux_log("sigsys redirect rax=%llx rip=%llx resume=%llx -> %#llx\n",
                syscall_nr, rip, resume, (unsigned long long)route.handler);

    xmm_regs[4] = (xmm_regs[4] & ~(__uint128_t)0xFFFFFFFFULL) | (syscall_nr & 0xFFFFFFFF);
    ctx->uc_mcontext.gregs[REG_RAX] = (long long)(route.rax_is_resume ? resume : saved_rcx);
    ctx->uc_mcontext.gregs[REG_RCX] = (long long)route.handler;
    ctx->uc_mcontext.gregs[REG_RIP] = (long long)route.handler;

    linuwux_rearm_sud();
    return 1;

not_ours:
    if ((xmm_regs[5] & 0xFFFFFFFFFFFFFFFFULL) == 0x1337133713371337ULL)
        xmm_regs[5] = 0;
    return 0;
}
