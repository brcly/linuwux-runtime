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
 * linuwux -- sigaction() interposition: installs the SIGSEGV/
 * SIGSYS wrappers, chains to whatever Wine originally registered.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <signal.h>
#include <stdatomic.h>
#include <stddef.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

#include "linuwux.h"
#include "cpuid.h"
#include "sigsys.h"


typedef int (*sigaction_fn)(int, const struct sigaction *, struct sigaction *);
static sigaction_fn real_sigaction;

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

