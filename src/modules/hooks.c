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
 * linuwux -- sigaction()/prctl() interposition: installs the SIGSEGV/
 * SIGSYS wrappers, chains to whatever Wine originally registered, and
 * learns the Syscall User Dispatch selector's TEB offset.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

#include "linuwux.h"
#include "cpuid.h"
#include "sigsys.h"

#ifndef PR_SET_SYSCALL_USER_DISPATCH
#define PR_SET_SYSCALL_USER_DISPATCH 59
#endif
#ifndef PR_SYS_DISPATCH_ON
#define PR_SYS_DISPATCH_ON 1
#endif

typedef int (*sigaction_fn)(int, const struct sigaction *, struct sigaction *);
typedef long (*prctl_fn)(int, unsigned long, unsigned long, unsigned long, unsigned long);

static sigaction_fn real_sigaction;
static prctl_fn real_prctl;

/* Only sa_sigaction is chained; store it atomically to avoid torn struct copies. */
typedef void (*linuwux_sig_handler_fn)(int, siginfo_t *, void *);
static _Atomic(linuwux_sig_handler_fn) s_real_segv_handler;
static _Atomic(linuwux_sig_handler_fn) s_real_sys_handler;

static void linuwux_segv_wrapper(int sig, siginfo_t *info, void *uctx);
static void linuwux_sigsys_wrapper(int sig, siginfo_t *info, void *uctx);

static void linuwux_chain_segv(int sig, siginfo_t *info, void *uctx)
{
    linuwux_sig_handler_fn real = atomic_load(&s_real_segv_handler);
    if (real)
        real(sig, info, uctx);
    else {
        signal(SIGSEGV, SIG_DFL);
        raise(SIGSEGV);
    }
}

static void linuwux_chain_sigsys(int sig, siginfo_t *info, void *uctx)
{
    linuwux_sig_handler_fn real = atomic_load(&s_real_sys_handler);
    if (real)
        real(sig, info, uctx);
}

static void linuwux_segv_wrapper(int sig, siginfo_t *info, void *uctx)
{
    ucontext_t *ctx = (ucontext_t *)uctx;
    if (linuwux_cpuid_spoof(info, ctx))
        return;
    linuwux_chain_segv(sig, info, uctx);
}

static void linuwux_sigsys_wrapper(int sig, siginfo_t *info, void *uctx)
{
    ucontext_t *ctx = (ucontext_t *)uctx;
    if (linuwux_sigsys_route(ctx))
        return;
    linuwux_chain_sigsys(sig, info, uctx);
}

/* Enable CPUID faults once; TIF_NOCPUID is inherited by new threads on clone. */
static void linuwux_enable_cpuid_fault(void)
{
    static _Atomic int done;
    int expected_done = 0;
    if (!atomic_compare_exchange_strong(&done, &expected_done, 1))
        return;
    syscall(SYS_arch_prctl, ARCH_SET_CPUID, 0);
    linuwux_log("CPUID faulting enabled (tid=%d)\n", (int)syscall(SYS_gettid));
}

__attribute__((visibility("default")))
int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
{
    if (!real_sigaction)
        real_sigaction = (sigaction_fn)dlsym(RTLD_NEXT, "sigaction");

    if (!linuwux_is_game_process())
        return real_sigaction(signum, act, oldact);

    if (act && signum == SIGSEGV && act->sa_sigaction != linuwux_segv_wrapper) {
        struct sigaction ours = *act;
        ours.sa_sigaction = linuwux_segv_wrapper;
        int r = real_sigaction(signum, &ours, oldact);
        if (r == 0) {
            atomic_store(&s_real_segv_handler, act->sa_sigaction);
            linuwux_log("intercepted Wine's sigaction(SIGSEGV, ...)\n");
            linuwux_enable_cpuid_fault();
        }
        return r;
    }
    if (act && signum == SIGSYS && act->sa_sigaction != linuwux_sigsys_wrapper) {
        struct sigaction ours = *act;
        ours.sa_sigaction = linuwux_sigsys_wrapper;
        int r = real_sigaction(signum, &ours, oldact);
        if (r == 0) {
            atomic_store(&s_real_sys_handler, act->sa_sigaction);
            linuwux_log("intercepted Wine's sigaction(SIGSYS, ...)\n");
        }
        return r;
    }
    return real_sigaction(signum, act, oldact);
}

/* Match glibc's variadic prctl declaration. */
__attribute__((visibility("default")))
int prctl(int option, ...)
{
    va_list ap;
    unsigned long a2, a3, a4, a5;

    va_start(ap, option);
    a2 = va_arg(ap, unsigned long);
    a3 = va_arg(ap, unsigned long);
    a4 = va_arg(ap, unsigned long);
    a5 = va_arg(ap, unsigned long);
    va_end(ap);

    if (!real_prctl)
        real_prctl = (prctl_fn)dlsym(RTLD_NEXT, "prctl");

    long ret = real_prctl(option, a2, a3, a4, a5);

    if (linuwux_is_game_process() &&
        ret >= 0 && option == PR_SET_SYSCALL_USER_DISPATCH && a2 == PR_SYS_DISPATCH_ON) {
        unsigned char *selector_addr = (unsigned char *)a5;
        unsigned char *teb = (unsigned char *)linuwux_get_teb();
        ptrdiff_t teb_offset = selector_addr - teb;
        linuwux_sigsys_learn_sud_offset(teb_offset);
        linuwux_log("learned SUD selector: teb-offset=%#tx (teb=%p selector=%p)\n",
                    teb_offset, (void *)teb, (void *)selector_addr);
    }
    return (int)ret;
}
