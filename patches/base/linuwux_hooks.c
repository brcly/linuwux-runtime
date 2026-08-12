/*
 * Copyright (C) 2026 LinUwUx
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

/* linuwux-hooks
 *
 * All LinUwUx unix-side helpers for ntdll. Copied next to signal_x86_64.c and
 * pulled in via #include so we stay in the same TU (REG_* macros, server
 * protocol, etc.) without dumping a large blob into the signal file itself.
 *
 * Enable tracing with LINUWUX_DEBUG=1.
 *
 * Redirect scope (dev/redirect-scope):
 *   DenuvOwO only vectors the tracked process (DR3/DR7). Under Wine we approx
 *   that by skipping TargetSysHandler when the fault RIP is in the Wine system
 *   PE band [0x6FFFFF000000, 0x700000000000). 0x7fff… is NOT included — ACBFR
 *   needs at least one redirect from that range (rax=0xffe).
 *   Set LINUWUX_REDIRECT_ALL=1 to restore pre-scope behaviour.
 *   Wine-system skips are intentional and not logged (too hot under DEBUG).
 *
 * Trampoline resume (dev/trampoline-resume-rip):
 *   Default path in reflex does mov rcx,rax / sub rcx,2 / jmp rcx after
 *   arming xmm5 bypass magic. RAX must be a code address so after sub 2 we
 *   land on the syscall insn — not a syscall argument.
 *
 * LINUWUX_STOP_SYSCALL=<hex|dec> (dev/linuwux-stop-syscall, throwaway):
 *   Freeze with SIGSTOP right before a redirect into TargetSysHandler whose
 *   syscall number (rax) matches. LINUWUX_STOP_SYSCALL_SKIP=<n> skips the
 *   first n matches so one specific occurrence can be isolated. Occurrence
 *   count of a shared syscall number is NOT reliably deterministic across
 *   runs (BL4 has multiple unrelated rax=0x18 call sites) — prefer
 *   LINUWUX_STOP_RIP below once the exact faulting rip is known.
 *
 * LINUWUX_STOP_RIP=<hex|dec> (dev/linuwux-stop-syscall, throwaway):
 *   Freeze with SIGSTOP the instant a redirect's fault rip matches exactly.
 *   BL4's addr=0x225FF crash always faults from rip=0x1572cee4c — deterministic
 *   per call site, unlike counting syscall-number occurrences. Continue with
 *   kill -CONT <pid>.
 */
#ifndef LINUWUX_HOOKS_INCLUDED
#define LINUWUX_HOOKS_INCLUDED

/*
 * Standard headers this file needs directly, rather than relying on
 * whatever signal_x86_64.c happens to have already pulled in by the point
 * of #include -- that's fragile to upstream reordering the file (see the
 * GE-Proton 11-5 SUD patchset moving segv_handler ahead of sigsys_handler,
 * which shifted our include point and broke the implicit errno.h pickup).
 * Standard headers are self-guarding, so re-including them here is safe
 * even when signal_x86_64.c already pulled them in earlier.
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>

/*
 * Set by apply_linuwux_hooks() (lib/apply-content.sh) from the wine tree's
 * actual content -- 1 if signal_x86_64.c has Syscall User Dispatch support
 * (GE-Proton 11-5+), 0 otherwise (GE 11-3, CachyOS). Not derived from the
 * build machine's <linux/prctl.h>, which doesn't reflect the tree being built.
 *
 * SUD-sensitive early-return sites (LINUWUX_HAVE_SUD only): any code path
 * that returns from segv_handler()/sigsys_handler() without reaching
 * Wine's own leave_handler() must re-arm syscall_dispatch itself, or every
 * syscall on that thread runs raw and unintercepted from then on.
 *
 * Known sites:
 *   - linuwux_sigsys_route()  return 1               (this file)
 *   - segv_handler() CPUID early return  (lib/apply-content.sh,
 *     apply_cpuid_spoof_handler_fix)
 *
 * Adding a new early return under LINUWUX_HAVE_SUD? Add it here too.
 */
#ifndef LINUWUX_HAVE_SUD
#define LINUWUX_HAVE_SUD 0
#endif

#ifndef LINUWUX_LOG_DEFINED
#define LINUWUX_LOG_DEFINED
static void linuwux_log(const char *fmt, ...)
{
    va_list ap;
    if (!getenv("LINUWUX_DEBUG"))
        return;
    fprintf(stderr, "[linuwux] ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}
#endif

/* Games' syscall spoof trampoline (set via CPUID leaf 0x336933). */
uint64_t TargetSysHandler = 0;
uint64_t SyscallBypassMagic = 0x1337133713371337;

unsigned int spoof_leaf1_eax, spoof_leaf1_ebx, spoof_leaf1_ecx, spoof_leaf1_edx;
unsigned int spoof_leaf40000000_eax, spoof_leaf40000000_ebx, spoof_leaf40000000_ecx, spoof_leaf40000000_edx;
unsigned int spoof_leaf40000001_eax, spoof_leaf40000001_ebx, spoof_leaf40000001_ecx, spoof_leaf40000001_edx;

/*
 * Wine system PE band (64-bit Proton/GE observations):
 *   ntdll/kernel32/kernelbase often sit in [0x6FFFFF000000, 0x700000000000).
 * Game EXEs ~0x140000000; crack modules often under 0x6FFFFF000000.
 * Do not treat 0x7fff… as Wine PE — some packs (ACBFR) redirect from there.
 */
#ifndef LINUWUX_WINE_SYSTEM_RIP_MIN
#define LINUWUX_WINE_SYSTEM_RIP_MIN 0x00006FFFFF000000ULL
#endif
#ifndef LINUWUX_WINE_SYSTEM_RIP_MAX
#define LINUWUX_WINE_SYSTEM_RIP_MAX 0x0000700000000000ULL
#endif

static int linuwux_rip_is_wine_system(unsigned long long rip)
{
    return rip >= LINUWUX_WINE_SYSTEM_RIP_MIN && rip < LINUWUX_WINE_SYSTEM_RIP_MAX;
}

static int linuwux_redirect_all_enabled(void)
{
    const char *env = getenv("LINUWUX_REDIRECT_ALL");
    return env && env[0] == '1' && env[1] == '\0';
}

/*
 * Throwaway debug aid (dev/linuwux-stop-syscall): freeze the process with
 * SIGSTOP right before a specific matching redirect into TargetSysHandler,
 * so a debugger can attach and step through the trampoline for that exact
 * call. Targets a syscall number (rax) and, optionally, skips the first N
 * matches so a specific occurrence can be isolated (e.g. BL4's rax=0x18
 * crash only reproduces on the 3rd redirect of that syscall number, not
 * the first two).
 *
 *   LINUWUX_STOP_SYSCALL=<hex|dec>   syscall number (rax) to match
 *   LINUWUX_STOP_SYSCALL_SKIP=<n>    skip the first n matches (default 0)
 *
 * Continue with kill -CONT <pid> or gdb continue.
 */
static void linuwux_maybe_stop_for_syscall(unsigned long long syscall_nr,
                                            unsigned long long rip,
                                            unsigned long long resume)
{
    static int match_count;
    static int stopped_once;
    const char *env_sys;
    const char *env_skip;
    unsigned long long target;
    int skip;

    if (stopped_once)
        return;

    env_sys = getenv("LINUWUX_STOP_SYSCALL");
    if (!env_sys || env_sys[0] == '\0')
        return;

    target = strtoull(env_sys, NULL, 0);
    if (syscall_nr != target)
        return;

    skip = 0;
    env_skip = getenv("LINUWUX_STOP_SYSCALL_SKIP");
    if (env_skip && env_skip[0] != '\0')
        skip = atoi(env_skip);

    if (match_count++ < skip)
        return;

    stopped_once = 1;
    /* Always print — attach window is useless if only DEBUG sees it. */
    fprintf(stderr,
            "[linuwux] LINUWUX_STOP_SYSCALL: SIGSTOP pid=%d before redirect #%d of "
            "syscall %#llx (rip=%#llx resume=%#llx). Attach debugger, then kill -CONT %d\n",
            getpid(), match_count, syscall_nr, rip, resume, getpid());
    fflush(stderr);
    raise(SIGSTOP);
}

/*
 * Throwaway debug aid (dev/linuwux-stop-syscall): freeze the instant a
 * redirect's fault RIP matches exactly, for isolating one deterministic
 * call site (e.g. BL4's rax=0x18 crash always faults from rip=0x1572cee4c
 * regardless of how many other rax=0x18 redirects happened earlier in the
 * run) rather than counting occurrences of a shared syscall number.
 *
 *   LINUWUX_STOP_RIP=<hex|dec>   exact fault rip to match
 *
 * Continue with kill -CONT <pid> or gdb continue.
 */
static void linuwux_maybe_stop_for_rip(unsigned long long rip,
                                        unsigned long long resume)
{
    static int stopped_once;
    const char *env_rip;
    unsigned long long target;

    if (stopped_once)
        return;

    env_rip = getenv("LINUWUX_STOP_RIP");
    if (!env_rip || env_rip[0] == '\0')
        return;

    target = strtoull(env_rip, NULL, 0);
    if (rip != target)
        return;

    stopped_once = 1;
    fprintf(stderr,
            "[linuwux] LINUWUX_STOP_RIP: SIGSTOP pid=%d at matching rip=%#llx "
            "(resume=%#llx). Attach debugger, then kill -CONT %d\n",
            getpid(), rip, resume, getpid());
    fflush(stderr);
    raise(SIGSTOP);
}

static void detect_cpu_vendor(void)
{
    unsigned int eax, ebx, ecx, edx;
    int avx = 0;
    if (getenv("PROTON_AVX") != NULL && strcmp(getenv("PROTON_AVX"), "1") == 0)
        avx = 1;

    __asm__ volatile(
        "cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(0)
        : "memory"
    );

    if (ebx == 0x756E6547 && edx == 0x49656E69 && ecx == 0x6C65746E) {
        /* GenuineIntel */
        spoof_leaf1_eax = 0x000A0655;
        spoof_leaf1_ebx = 0x00200800;
        spoof_leaf1_ecx = avx ? 0x7BFAFBFF : 0x01FAEBFF;
        spoof_leaf1_edx = 0xBFEBFBFF;

        spoof_leaf40000000_eax = 0x40000001;
        spoof_leaf40000000_ebx = 0x65707948; /* epyH */
        spoof_leaf40000000_ecx = 0x67624472; /* gbDr */
        spoof_leaf40000000_edx = 0;

        spoof_leaf40000001_eax = 0x30237648; /* 0#vH */
        spoof_leaf40000001_ebx = 0;
        spoof_leaf40000001_ecx = 0;
        spoof_leaf40000001_edx = 0;

        linuwux_log("detect_cpu_vendor: Intel (avx=%d)\n", avx);
    } else if (ebx == 0x68747541 && edx == 0x69746E65 && ecx == 0x444D4163) {
        /* AuthenticAMD */
        spoof_leaf1_eax = 0x00A20F12;
        spoof_leaf1_ebx = 0x00100800;
        spoof_leaf1_ecx = avx ? 0x7AD8320B : 0x00F8220B;
        spoof_leaf1_edx = 0x178BFBFF;

        spoof_leaf40000000_eax = 0x40000001;
        spoof_leaf40000000_ebx = 0x706D6953; /* pmiS */
        spoof_leaf40000000_ecx = 0x7653656C; /* vSel */
        spoof_leaf40000000_edx = 0x2020206D; /*    m */

        spoof_leaf40000001_eax = 0x30237648; /* 0#vH */
        spoof_leaf40000001_ebx = 0;
        spoof_leaf40000001_ecx = 0;
        spoof_leaf40000001_edx = 0;

        linuwux_log("detect_cpu_vendor: AMD (avx=%d)\n", avx);
    } else {
        linuwux_log("detect_cpu_vendor: unknown vendor ebx=%08x edx=%08x ecx=%08x\n",
                    ebx, edx, ecx);
    }
}

/**
 * Patch KUSER_SHARED_DATA with spoofed values.
 * Called from the special CPUID leaf 0x336933 path.
 */
static void patch_kuser_shared_data(void)
{
    UINT8 *kuser = (UINT8 *)0x000000007FFE0000UL;
    size_t page_size = sysconf(_SC_PAGESIZE);
    void *page_start = (void *)((uintptr_t)0x000000007FFE0000UL & ~(page_size - 1));

    if (mprotect(page_start, page_size, PROT_READ | PROT_WRITE) == -1) {
        MESSAGE("Failed to make kuser_shared_data writable: %s\n", strerror(errno));
        linuwux_log("kuser_shared_data: mprotect failed: %s\n", strerror(errno));
        return;
    }

    /* NtSystemRoot – stable "C:\\Windows" (unsigned short, not WCHAR/L""). */
    {
        static const unsigned short nt_system_root[] = {
            'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', 0
        };
        memcpy(kuser + 0x30, nt_system_root, sizeof(nt_system_root));
    }

    *(UINT64 *)(kuser + 0x260) = 0x0100006658;
    *(UINT32 *)(kuser + 0x268) = 0x090001;
    *(UINT32 *)(kuser + 0x26C) = 0x0A;
    *(UINT32 *)(kuser + 0x270) = 0x00;

    *(UINT32 *)(kuser + 0x274) = 0x01010000;
    *(UINT32 *)(kuser + 0x278) = 0x010000;
    *(UINT32 *)(kuser + 0x27C) = 0x010101;
    *(UINT32 *)(kuser + 0x280) = 0x010101;
    *(UINT32 *)(kuser + 0x284) = 0x0100;
    *(UINT32 *)(kuser + 0x288) = 0x01010101;
    *(UINT32 *)(kuser + 0x28C) = 0x0;
    *(UINT32 *)(kuser + 0x290) = 0x01;
    *(UINT32 *)(kuser + 0x294) = 0x01000101;
    *(UINT32 *)(kuser + 0x298) = 0x01010101;
    *(UINT32 *)(kuser + 0x29C) = 0x010001;
    *(UINT32 *)(kuser + 0x2A0) = 0x0;
    *(UINT32 *)(kuser + 0x2A4) = 0x0;
    *(UINT32 *)(kuser + 0x2A8) = 0x0;
    *(UINT32 *)(kuser + 0x2AC) = 0x0;
    *(UINT32 *)(kuser + 0x2B0) = 0x1;

    *(UINT8 *)(kuser + 0x290) = 0x0; /* MONITORX */
    *(UINT8 *)(kuser + 0x294) = 0x0; /* RDTSCP */
    *(UINT8 *)(kuser + 0x295) = 0x0; /* RDPID */
    *(UINT8 *)(kuser + 0x297) = 0x0; /* RDRAND */

    if (getenv("PROTON_AVX") == NULL ||
        (getenv("PROTON_AVX") != NULL && strcmp(getenv("PROTON_AVX"), "1") != 0)) {
        *(UINT8 *)(kuser + 0x285) = 0x0; /* XSAVE */
        *(UINT8 *)(kuser + 0x29B) = 0x0; /* AVX */
        *(UINT8 *)(kuser + 0x29C) = 0x0; /* AVX2 */
    }

    *(UINT64 *)(kuser + 0x3D8) = 0x0;
    *(UINT64 *)(kuser + 0x3E0) = 0x0;
    *(UINT32 *)(kuser + 0x3EC) = 0x0;
    memset((void *)(kuser + 0x3F0), 0x00, 0x200);
    *(UINT64 *)(kuser + 0x5F0) = 0x0;
    *(UINT64 *)(kuser + 0x5F8) = 0x0;
    memset((void *)(kuser + 0x604), 0x00, 0x200);
    *(UINT64 *)(kuser + 0x808) = 0x0;
    *(UINT64 *)(kuser + 0x810) = 0x0;

    *(UINT64 *)(kuser + 0x2D0) = 0x320A0000000110;
    *(UINT64 *)(kuser + 0x2E8) = 0x0100007FB10B;
    *(UINT32 *)(kuser + 0x2F4) = 0x0;
    *(UINT64 *)(kuser + 0x36C) = 0x0;
    *(UINT64 *)(kuser + 0x374) = 0x0;
    *(UINT32 *)(kuser + 0x37C) = 0x1;
    *(UINT64 *)(kuser + 0x3C0) = 0x83000100000010;

    /* SystemCall – force user-mode dispatch (same as syscall_hack.dll). */
    //*(UINT8 *)(kuser + 0x308) = 0;

    *(UINT32 *)(kuser + 0xFFC) = 0x13371337;

    linuwux_log("kuser_shared_data: patched\n");
}

/* Returns 1 if the fault was handled and segv_handler should return. */
static int linuwux_cpuid_spoof(siginfo_t *siginfo, void *sigcontext, ucontext_t *ucontext)
{
    unsigned int spoof_leaf;
    unsigned int spoof_subleaf;
    ucontext_t *spoof_uc;
    unsigned char *spoof_rip;

    spoof_uc = (ucontext_t *)sigcontext;
    spoof_rip = (unsigned char *)spoof_uc->uc_mcontext.gregs[REG_RIP];
    spoof_leaf = ucontext->uc_mcontext.gregs[REG_RAX];
    spoof_subleaf = ucontext->uc_mcontext.gregs[REG_RCX];

    if (!((siginfo->si_code == SI_KERNEL || spoof_leaf == 0x336933) &&
          spoof_rip[0] == 0x0F && spoof_rip[1] == 0xA2))
        return 0;

    switch (spoof_leaf) {
    case 1:
        spoof_uc->uc_mcontext.gregs[REG_RAX] = spoof_leaf1_eax;
        spoof_uc->uc_mcontext.gregs[REG_RBX] = spoof_leaf1_ebx;
        spoof_uc->uc_mcontext.gregs[REG_RCX] = spoof_leaf1_ecx | (TargetSysHandler ? 0 : (0x1 << 31));
        spoof_uc->uc_mcontext.gregs[REG_RDX] = spoof_leaf1_edx;
        break;

    case 0x40000000:
        spoof_uc->uc_mcontext.gregs[REG_RAX] = spoof_leaf40000000_eax;
        spoof_uc->uc_mcontext.gregs[REG_RBX] = spoof_leaf40000000_ebx;
        spoof_uc->uc_mcontext.gregs[REG_RCX] = spoof_leaf40000000_ecx;
        spoof_uc->uc_mcontext.gregs[REG_RDX] = spoof_leaf40000000_edx;
        break;

    case 0x40000001:
        spoof_uc->uc_mcontext.gregs[REG_RAX] = spoof_leaf40000001_eax;
        spoof_uc->uc_mcontext.gregs[REG_RBX] = spoof_leaf40000001_ebx;
        spoof_uc->uc_mcontext.gregs[REG_RCX] = spoof_leaf40000001_ecx;
        spoof_uc->uc_mcontext.gregs[REG_RDX] = spoof_leaf40000001_edx;
        break;

    case 0x80000002:
        spoof_uc->uc_mcontext.gregs[REG_RAX] = 0x756E6544;
        spoof_uc->uc_mcontext.gregs[REG_RBX] = 0x4F774F76;
        spoof_uc->uc_mcontext.gregs[REG_RCX] = 0x55504320;
        spoof_uc->uc_mcontext.gregs[REG_RDX] = 0x31204020;
        break;

    case 0x80000003:
        spoof_uc->uc_mcontext.gregs[REG_RAX] = 0x20373333;
        spoof_uc->uc_mcontext.gregs[REG_RBX] = 0x007A4847;
        spoof_uc->uc_mcontext.gregs[REG_RCX] = 0x00000000;
        spoof_uc->uc_mcontext.gregs[REG_RDX] = 0x00000000;
        break;

    case 0x80000004:
        spoof_uc->uc_mcontext.gregs[REG_RAX] = 0x0;
        spoof_uc->uc_mcontext.gregs[REG_RBX] = 0x0;
        spoof_uc->uc_mcontext.gregs[REG_RCX] = 0x0;
        spoof_uc->uc_mcontext.gregs[REG_RDX] = 0x0;
        break;

    case 0x336933:
        MESSAGE("Spoofing CPUID leaf %x\n", spoof_leaf);
        TargetSysHandler = spoof_uc->uc_mcontext.gregs[REG_RCX];
        linuwux_log("cpuid 0x336933 TargetSysHandler=%p\n", (void *)TargetSysHandler);
        patch_kuser_shared_data();
        spoof_uc->uc_mcontext.gregs[REG_RAX] = 0x0;
        spoof_uc->uc_mcontext.gregs[REG_RBX] = 0x0;
        spoof_uc->uc_mcontext.gregs[REG_RCX] = 0x0;
        spoof_uc->uc_mcontext.gregs[REG_RDX] = 0x0;
        break;

    case 0x336967:
        MESSAGE("Setting Faketime to %llx... \n", spoof_uc->uc_mcontext.gregs[REG_RCX]);
        linuwux_log("cpuid 0x336967 faketime=%llx\n",
                    (unsigned long long)spoof_uc->uc_mcontext.gregs[REG_RCX]);
        SERVER_START_REQ(set_faketime)
        {
            req->faketime = spoof_uc->uc_mcontext.gregs[REG_RCX];
            wine_server_call(req);
        }
        SERVER_END_REQ;
        spoof_uc->uc_mcontext.gregs[REG_RAX] = 0x0;
        spoof_uc->uc_mcontext.gregs[REG_RBX] = 0x0;
        spoof_uc->uc_mcontext.gregs[REG_RCX] = 0x0;
        spoof_uc->uc_mcontext.gregs[REG_RDX] = 0x0;
        break;

    default:
        syscall(SYS_arch_prctl, ARCH_SET_CPUID, 1);
        __asm__ volatile(
            "cpuid"
            : "=a"(spoof_uc->uc_mcontext.gregs[REG_RAX]),
              "=b"(spoof_uc->uc_mcontext.gregs[REG_RBX]),
              "=c"(spoof_uc->uc_mcontext.gregs[REG_RCX]),
              "=d"(spoof_uc->uc_mcontext.gregs[REG_RDX])
            : "a"(spoof_leaf), "c"(spoof_subleaf)
            : "memory");
        syscall(SYS_arch_prctl, ARCH_SET_CPUID, 0);
    }

    spoof_uc->uc_mcontext.gregs[REG_RIP] += 2;
    return 1;
}

/* Returns 1 if sigsys_handler should return immediately. */
static int linuwux_sigsys_route(void *sigcontext)
{
    ucontext_t *ctx = sigcontext;
    __uint128_t *xmm_regs = (__uint128_t *)ctx->uc_mcontext.fpregs->_xmm;
    unsigned long long syscall_nr;
    unsigned long long rip;
    unsigned long long resume;
    unsigned char *ip;
    unsigned char b0 = 0, b1 = 0;

    if (TargetSysHandler != 0 &&
        (xmm_regs[5] & 0xFFFFFFFFFFFFFFFF) != 0x1337133713371337) {
        syscall_nr = (unsigned long long)ctx->uc_mcontext.gregs[REG_RAX];
        rip = (unsigned long long)ctx->uc_mcontext.gregs[REG_RIP];

        /*
         * Scope filter: approximate DenuvOwO "tracked process only" by not
         * vectoring Wine system PE syscall sites into the usermode trampoline.
         * Window is closed above so 0x7fff… still redirects (ACBFR 0xffe).
         * Skips are silent — this path is too hot for LINUWUX_DEBUG.
         */
        if (!linuwux_redirect_all_enabled() && linuwux_rip_is_wine_system(rip))
            return 0;

        /*
         * Protocol match for current reflex trampoline (RVA 0x1000):
         *   mov rcx, rax
         *   … special cases …
         *   movq xmm5, 0x1337133713371337   ; bypass on re-issue
         *   mov eax, r11d                  ; syscall nr from xmm4
         *   sub rcx, 2
         *   jmp rcx
         *
         * RAX must be a code address so after sub 2 we land on the syscall
         * insn. If SIGSYS RIP is already at 0F 05, pass rip+2; if RIP is
         * already past the insn, pass rip as-is.
         */
        ip = (unsigned char *)(uintptr_t)rip;
        b0 = ip[0];
        b1 = ip[1];
        if (b0 == 0x0f && b1 == 0x05)
            resume = rip + 2;
        else
            resume = rip;

        linuwux_log("sigsys redirect rax=%llx rip=%llx resume=%llx → %p\n",
                    syscall_nr, rip, resume, (void *)TargetSysHandler);
        /* Neighbourhood dump: confirm whether 0F 05 sits at rip-2 (syscall; ret). */
        linuwux_log("sigsys near -4=%02x %02x -2=%02x %02x | %02x %02x +2=%02x %02x\n",
                    ip[-4], ip[-3], ip[-2], ip[-1], b0, b1, ip[2], ip[3]);

        /*
         * Only the trampoline's `movd %xmm4,%r11d` (low 32 bits) is read.
         * A raw `syscall` never touches XMM state, so preserve xmm4's upper
         * 96 bits rather than zeroing them here — the guest may have live
         * SSE-resident data stashed there across this syscall boundary.
         */
        xmm_regs[4] = (xmm_regs[4] & ~(__uint128_t)0xFFFFFFFFULL) | (syscall_nr & 0xFFFFFFFF);
        ctx->uc_mcontext.gregs[REG_RAX] = (long long)resume;
        ctx->uc_mcontext.gregs[REG_RCX] = (long long)TargetSysHandler;
        ctx->uc_mcontext.gregs[REG_RIP] = (long long)TargetSysHandler;

#if LINUWUX_HAVE_SUD
        /*
         * Re-arm Syscall User Dispatch before diverting into TargetSysHandler.
         * init_handler() disarms it (ALLOW) on every signal handler entry;
         * Wine's normal completion paths re-arm it (BLOCK) before returning
         * to app code, but our early `return 1` below reaches neither, so
         * without this the selector stays stuck at ALLOW and every syscall
         * on this thread afterwards runs raw instead of trapping back into
         * Wine's NT emulation. No equivalent on GE 11-3 (seccomp, not SUD).
         */
        leave_handler( ctx ); /* SYSCALL_DISPATCH_FILTER_BLOCK */
#endif

        /* Throwaway: freeze on a matching redirect so gdb can attach and
         * step through TargetSysHandler with these exact register values. */
        linuwux_maybe_stop_for_syscall(syscall_nr, rip, resume);
        linuwux_maybe_stop_for_rip(rip, resume);
        return 1;
    }

    if ((xmm_regs[5] & 0xFFFFFFFFFFFFFFFF) == 0x1337133713371337)
        xmm_regs[5] = 0;

    return 0;
}

#endif /* LINUWUX_HOOKS_INCLUDED */
