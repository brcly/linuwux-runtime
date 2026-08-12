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

/*
 * linuwux-preload
 *
 * Installs LinUwUx's CPUID spoofing, SIGSYS/DenuvOwO redirect,
 * HwProfileGuid, DLL overrides, and faketime entirely via LD_PRELOAD --
 * Wine's own source is never touched. This interposes libc calls Wine
 * itself makes -- sigaction()/prctl() for signal delivery,
 * clock_gettime()/gettimeofday() for the wall clock -- and wraps around
 * whatever Wine registers at runtime, rather than splicing call-stub
 * text into Wine's own source (fragile to upstream reordering/
 * reformatting -- see the GE 11-3 -> 11-5 SIGSYS anchor breakage an
 * earlier, source-patching implementation of this hit before this
 * replaced it).
 *
 * Verified against a real GE-Proton 11-5 tree before building this:
 * Wine's SIGSEGV/SIGSYS registration (signal_init_process()) and its
 * Syscall User Dispatch registration (init_syscall_frame(), called once
 * per thread) both go through the plain libc sigaction()/prctl() symbols,
 * not a raw syscall() that would bypass LD_PRELOAD interposition.
 *
 * See linuwux_set_faketime() below for why faketime is fully
 * client-side rather than the wineserver-round-trip protocol an earlier
 * version of this used.
 *
 * Enable event tracing with LINUWUX_DEBUG=1.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

#ifndef PR_SET_SYSCALL_USER_DISPATCH
#define PR_SET_SYSCALL_USER_DISPATCH 59
#endif
#ifndef PR_SYS_DISPATCH_ON
#define PR_SYS_DISPATCH_ON 1
#endif
#ifndef ARCH_SET_CPUID
#define ARCH_SET_CPUID 0x1012
#endif

static void linuwux_log(const char *fmt, ...)
{
    va_list ap;
    if (!getenv("LINUWUX_DEBUG"))
        return;
    fprintf(stderr, "[linuwux-preload] ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

/*
 * TEB access via the %gs self-pointer (Win64 NtTib.Self, offset 0x30) --
 * the same thing NtCurrentTeb() does, but without needing to dlsym() a
 * symbol out of ntdll.so (which may not even be mapped yet when our own
 * constructor runs). This is core x86_64 Windows ABI, not a Wine-internal
 * implementation detail, so it's about as stable an assumption as this
 * whole approach can make.
 */
static inline void *linuwux_get_teb(void)
{
    void *teb;
    __asm__ volatile ("movq %%gs:0x30, %0" : "=r"(teb));
    return teb;
}

/* ------------------------------------------------------------------ */
/* CPUID spoofing                                                      */
/* ------------------------------------------------------------------ */

static uint64_t g_target_sys_handler = 0;

static unsigned int spoof_leaf1_eax, spoof_leaf1_ebx, spoof_leaf1_ecx, spoof_leaf1_edx;
static unsigned int spoof_leaf40000000_eax, spoof_leaf40000000_ebx, spoof_leaf40000000_ecx, spoof_leaf40000000_edx;
static unsigned int spoof_leaf40000001_eax, spoof_leaf40000001_ebx, spoof_leaf40000001_ecx, spoof_leaf40000001_edx;

static void linuwux_detect_cpu_vendor(void)
{
    unsigned int eax, ebx, ecx, edx;
    int avx = 0;
    if (getenv("PROTON_AVX") != NULL && strcmp(getenv("PROTON_AVX"), "1") == 0)
        avx = 1;

    __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(0) : "memory");

    if (ebx == 0x756E6547 && edx == 0x49656E69 && ecx == 0x6C65746E) {
        /* GenuineIntel */
        spoof_leaf1_eax = 0x000A0655;
        spoof_leaf1_ebx = 0x00200800;
        spoof_leaf1_ecx = avx ? 0x7BFAFBFF : 0x01FAEBFF;
        spoof_leaf1_edx = 0xBFEBFBFF;
        spoof_leaf40000000_eax = 0x40000001;
        spoof_leaf40000000_ebx = 0x65707948;
        spoof_leaf40000000_ecx = 0x67624472;
        spoof_leaf40000000_edx = 0;
        spoof_leaf40000001_eax = 0x30237648;
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
        spoof_leaf40000000_ebx = 0x706D6953;
        spoof_leaf40000000_ecx = 0x7653656C;
        spoof_leaf40000000_edx = 0x2020206D;
        spoof_leaf40000001_eax = 0x30237648;
        spoof_leaf40000001_ebx = 0;
        spoof_leaf40000001_ecx = 0;
        spoof_leaf40000001_edx = 0;
        linuwux_log("detect_cpu_vendor: AMD (avx=%d)\n", avx);
    } else {
        linuwux_log("detect_cpu_vendor: unknown vendor ebx=%08x edx=%08x ecx=%08x\n", ebx, edx, ecx);
    }
}

static void linuwux_patch_kuser_shared_data(void)
{
    uint8_t *kuser = (uint8_t *)0x000000007FFE0000UL;
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    void *page_start = (void *)((uintptr_t)0x000000007FFE0000UL & ~(page_size - 1));

    if (mprotect(page_start, page_size, PROT_READ | PROT_WRITE) == -1) {
        linuwux_log("kuser_shared_data: mprotect failed: %s\n", strerror(errno));
        return;
    }

    {
        static const unsigned short nt_system_root[] = { 'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', 0 };
        memcpy(kuser + 0x30, nt_system_root, sizeof(nt_system_root));
    }

    *(uint64_t *)(kuser + 0x260) = 0x0100006658;
    *(uint32_t *)(kuser + 0x268) = 0x090001;
    *(uint32_t *)(kuser + 0x26C) = 0x0A;
    *(uint32_t *)(kuser + 0x270) = 0x00;
    *(uint32_t *)(kuser + 0x274) = 0x01010000;
    *(uint32_t *)(kuser + 0x278) = 0x010000;
    *(uint32_t *)(kuser + 0x27C) = 0x010101;
    *(uint32_t *)(kuser + 0x280) = 0x010101;
    *(uint32_t *)(kuser + 0x284) = 0x0100;
    *(uint32_t *)(kuser + 0x288) = 0x01010101;
    *(uint32_t *)(kuser + 0x28C) = 0x0;
    *(uint32_t *)(kuser + 0x290) = 0x01;
    *(uint32_t *)(kuser + 0x294) = 0x01000101;
    *(uint32_t *)(kuser + 0x298) = 0x01010101;
    *(uint32_t *)(kuser + 0x29C) = 0x010001;
    *(uint32_t *)(kuser + 0x2A0) = 0x0;
    *(uint32_t *)(kuser + 0x2A4) = 0x0;
    *(uint32_t *)(kuser + 0x2A8) = 0x0;
    *(uint32_t *)(kuser + 0x2AC) = 0x0;
    *(uint32_t *)(kuser + 0x2B0) = 0x1;
    *(uint8_t *)(kuser + 0x290) = 0x0;  /* MONITORX */
    *(uint8_t *)(kuser + 0x294) = 0x0;  /* RDTSCP */
    *(uint8_t *)(kuser + 0x295) = 0x0;  /* RDPID */
    *(uint8_t *)(kuser + 0x297) = 0x0;  /* RDRAND */

    if (getenv("PROTON_AVX") == NULL || strcmp(getenv("PROTON_AVX"), "1") != 0) {
        *(uint8_t *)(kuser + 0x285) = 0x0;  /* XSAVE */
        *(uint8_t *)(kuser + 0x29B) = 0x0;  /* AVX */
        *(uint8_t *)(kuser + 0x29C) = 0x0;  /* AVX2 */
    }

    *(uint64_t *)(kuser + 0x3D8) = 0x0;
    *(uint64_t *)(kuser + 0x3E0) = 0x0;
    *(uint32_t *)(kuser + 0x3EC) = 0x0;
    memset((void *)(kuser + 0x3F0), 0x00, 0x200);
    *(uint64_t *)(kuser + 0x5F0) = 0x0;
    *(uint64_t *)(kuser + 0x5F8) = 0x0;
    memset((void *)(kuser + 0x604), 0x00, 0x200);
    *(uint64_t *)(kuser + 0x808) = 0x0;
    *(uint64_t *)(kuser + 0x810) = 0x0;
    *(uint64_t *)(kuser + 0x2D0) = 0x320A0000000110;
    *(uint64_t *)(kuser + 0x2E8) = 0x0100007FB10B;
    *(uint32_t *)(kuser + 0x2F4) = 0x0;
    *(uint64_t *)(kuser + 0x36C) = 0x0;
    *(uint64_t *)(kuser + 0x374) = 0x0;
    *(uint32_t *)(kuser + 0x37C) = 0x1;
    *(uint64_t *)(kuser + 0x3C0) = 0x83000100000010;
    *(uint32_t *)(kuser + 0xFFC) = 0x13371337;

    linuwux_log("kuser_shared_data: patched\n");
}

/* Defined below (needs the clock_gettime() interposition plumbing);
 * forward-declared here so the 0x336967 (faketime) case in
 * linuwux_cpuid_spoof() can call it. */
static void linuwux_set_faketime(long long faketime);

/* Defined below (needs linuwux_find_ntdll_symbol() and the NT registry
 * structs/typedefs); forward-declared here so the 0x336933 (arm) case in
 * linuwux_cpuid_spoof() can call it. Called from there specifically
 * because a CPUID-trap SIGSEGV can only fire while guest code is actively
 * executing an instruction -- never while this thread is blocked inside
 * a wine_server_call() -- which makes it safe for NtCreateKey/
 * NtSetValueKey's own internal wine_server_call() to run here. An earlier
 * version called this from inside the recvmsg() interposition instead,
 * on the theory that "first SCM_RIGHTS reply" meant "connection is live";
 * in practice that point is still *inside* the wine_server_call() that
 * owns that exact recvmsg, so issuing a second, nested request/reply
 * cycle on the same server socket corrupted wineserver's client-side
 * protocol state for the thread ("wine client error:0: write: Bad file
 * descriptor", confirmed against a real Proton 11.0 + Steam Linux Runtime
 * launch). */
static void linuwux_set_hwprofile_guid(void);

/* Returns 1 if the fault was ours to handle. */
static int linuwux_cpuid_spoof(ucontext_t *ctx)
{
    unsigned int spoof_leaf, spoof_subleaf;
    unsigned char *rip = (unsigned char *)ctx->uc_mcontext.gregs[REG_RIP];

    spoof_leaf = (unsigned int)ctx->uc_mcontext.gregs[REG_RAX];
    spoof_subleaf = (unsigned int)ctx->uc_mcontext.gregs[REG_RCX];

    if (!(rip[0] == 0x0F && rip[1] == 0xA2))
        return 0;   /* not a cpuid instruction at the fault site */

    switch (spoof_leaf) {
    case 1:
        ctx->uc_mcontext.gregs[REG_RAX] = spoof_leaf1_eax;
        ctx->uc_mcontext.gregs[REG_RBX] = spoof_leaf1_ebx;
        ctx->uc_mcontext.gregs[REG_RCX] = spoof_leaf1_ecx | (g_target_sys_handler ? 0 : (0x1 << 31));
        ctx->uc_mcontext.gregs[REG_RDX] = spoof_leaf1_edx;
        break;

    case 0x40000000:
        ctx->uc_mcontext.gregs[REG_RAX] = spoof_leaf40000000_eax;
        ctx->uc_mcontext.gregs[REG_RBX] = spoof_leaf40000000_ebx;
        ctx->uc_mcontext.gregs[REG_RCX] = spoof_leaf40000000_ecx;
        ctx->uc_mcontext.gregs[REG_RDX] = spoof_leaf40000000_edx;
        break;

    case 0x40000001:
        ctx->uc_mcontext.gregs[REG_RAX] = spoof_leaf40000001_eax;
        ctx->uc_mcontext.gregs[REG_RBX] = spoof_leaf40000001_ebx;
        ctx->uc_mcontext.gregs[REG_RCX] = spoof_leaf40000001_ecx;
        ctx->uc_mcontext.gregs[REG_RDX] = spoof_leaf40000001_edx;
        break;

    case 0x80000002:
        ctx->uc_mcontext.gregs[REG_RAX] = 0x756E6544;
        ctx->uc_mcontext.gregs[REG_RBX] = 0x4F774F76;
        ctx->uc_mcontext.gregs[REG_RCX] = 0x55504320;
        ctx->uc_mcontext.gregs[REG_RDX] = 0x31204020;
        break;

    case 0x80000003:
        ctx->uc_mcontext.gregs[REG_RAX] = 0x20373333;
        ctx->uc_mcontext.gregs[REG_RBX] = 0x007A4847;
        ctx->uc_mcontext.gregs[REG_RCX] = 0x00000000;
        ctx->uc_mcontext.gregs[REG_RDX] = 0x00000000;
        break;

    case 0x80000004:
        ctx->uc_mcontext.gregs[REG_RAX] = 0x0;
        ctx->uc_mcontext.gregs[REG_RBX] = 0x0;
        ctx->uc_mcontext.gregs[REG_RCX] = 0x0;
        ctx->uc_mcontext.gregs[REG_RDX] = 0x0;
        break;

    case 0x336933:
        linuwux_log("cpuid 0x336933 arm, TargetSysHandler=%#llx\n",
                    (unsigned long long)ctx->uc_mcontext.gregs[REG_RCX]);
        g_target_sys_handler = (uint64_t)ctx->uc_mcontext.gregs[REG_RCX];
        linuwux_patch_kuser_shared_data();
        linuwux_set_hwprofile_guid();
        ctx->uc_mcontext.gregs[REG_RAX] = 0x0;
        ctx->uc_mcontext.gregs[REG_RBX] = 0x0;
        ctx->uc_mcontext.gregs[REG_RCX] = 0x0;
        ctx->uc_mcontext.gregs[REG_RDX] = 0x0;
        break;

    case 0x336967:
        linuwux_set_faketime((long long)ctx->uc_mcontext.gregs[REG_RCX]);
        ctx->uc_mcontext.gregs[REG_RAX] = 0x0;
        ctx->uc_mcontext.gregs[REG_RBX] = 0x0;
        ctx->uc_mcontext.gregs[REG_RCX] = 0x0;
        ctx->uc_mcontext.gregs[REG_RDX] = 0x0;
        break;

    default:
        syscall(SYS_arch_prctl, ARCH_SET_CPUID, 1);
        __asm__ volatile(
            "cpuid"
            : "=a"(ctx->uc_mcontext.gregs[REG_RAX]),
              "=b"(ctx->uc_mcontext.gregs[REG_RBX]),
              "=c"(ctx->uc_mcontext.gregs[REG_RCX]),
              "=d"(ctx->uc_mcontext.gregs[REG_RDX])
            : "a"(spoof_leaf), "c"(spoof_subleaf)
            : "memory");
        syscall(SYS_arch_prctl, ARCH_SET_CPUID, 0);
    }

    ctx->uc_mcontext.gregs[REG_RIP] += 2;
    return 1;
}

/* ------------------------------------------------------------------ */
/* Wine-system RIP scope filter                                        */
/* ------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------ */
/* Syscall User Dispatch: learn the selector address from Wine's own   */
/* real prctl() call, instead of guessing amd64_thread_data's layout.  */
/* ------------------------------------------------------------------ */

static long g_sud_teb_offset = -1;  /* -1 == not learned yet / no SUD on this tree */

static void linuwux_rearm_sud(void)
{
    if (g_sud_teb_offset < 0)
        return;
    unsigned char *teb = (unsigned char *)linuwux_get_teb();
    teb[g_sud_teb_offset] = 1;  /* SYSCALL_DISPATCH_FILTER_BLOCK */
}

/* ------------------------------------------------------------------ */
/* SIGSYS redirect (ported from linuwux_sigsys_route())                */
/* ------------------------------------------------------------------ */

static int linuwux_sigsys_route(ucontext_t *ctx)
{
    __uint128_t *xmm_regs = (__uint128_t *)ctx->uc_mcontext.fpregs->_xmm;
    unsigned long long syscall_nr, rip, resume;
    unsigned char *ip, b0, b1;

    if (g_target_sys_handler == 0 ||
        (xmm_regs[5] & 0xFFFFFFFFFFFFFFFFULL) == 0x1337133713371337ULL)
        goto not_ours;

    syscall_nr = (unsigned long long)ctx->uc_mcontext.gregs[REG_RAX];
    rip = (unsigned long long)ctx->uc_mcontext.gregs[REG_RIP];

    if (!linuwux_redirect_all_enabled() && linuwux_rip_is_wine_system(rip))
        return 0;   /* not a fault we redirect; let Wine's real handler run */

    ip = (unsigned char *)(uintptr_t)rip;
    b0 = ip[0];
    b1 = ip[1];
    resume = (b0 == 0x0f && b1 == 0x05) ? rip + 2 : rip;

    linuwux_log("sigsys redirect rax=%llx rip=%llx resume=%llx -> %#llx\n",
                syscall_nr, rip, resume, (unsigned long long)g_target_sys_handler);

    xmm_regs[4] = (xmm_regs[4] & ~(__uint128_t)0xFFFFFFFFULL) | (syscall_nr & 0xFFFFFFFF);
    ctx->uc_mcontext.gregs[REG_RAX] = (long long)resume;
    ctx->uc_mcontext.gregs[REG_RCX] = (long long)g_target_sys_handler;
    ctx->uc_mcontext.gregs[REG_RIP] = (long long)g_target_sys_handler;

    linuwux_rearm_sud();
    return 1;

not_ours:
    if ((xmm_regs[5] & 0xFFFFFFFFFFFFFFFFULL) == 0x1337133713371337ULL)
        xmm_regs[5] = 0;
    return 0;
}

/* dlsym(RTLD_DEFAULT, ...) only searches the process's GLOBAL symbol
 * scope -- which does NOT include a library loaded via plain dlopen()
 * without RTLD_GLOBAL (glibc's dlopen() default is RTLD_LOCAL). Wine's
 * own PE/unix-module loader loads ntdll.so's unix backend via its own
 * internal dlopen() call, not as an ordinary linked dependency, so
 * NtCreateKey/NtSetValueKey/NtClose -- confirmed present via `nm -D
 * ntdll.so` against a real build -- are invisible to RTLD_DEFAULT even
 * though they genuinely exist. Fix: find ntdll.so's real on-disk path
 * from /proc/self/maps (it's already loaded by the time any of our code
 * runs), then dlopen(path, RTLD_NOLOAD) to get a handle to that SAME
 * already-loaded object without a second load, and dlsym() on that
 * specific handle -- handle-based dlsym() always finds the symbol
 * regardless of the object's RTLD_LOCAL/RTLD_GLOBAL scope. Verified
 * against a synthetic RTLD_LOCAL dlopen() before relying on it here. */
static void *linuwux_find_ntdll_symbol(const char *name)
{
    static void *ntdll_handle;
    static int tried;

    if (!ntdll_handle && !tried)
    {
        FILE *f;
        char line[4096], path[4096];

        tried = 1;
        path[0] = '\0';
        f = fopen("/proc/self/maps", "r");
        if (f)
        {
            while (fgets(line, sizeof(line), f))
            {
                size_t len = strlen(line);
                const char *field;
                int i;

                if (len && line[len - 1] == '\n')
                    line[--len] = '\0';

                /* /proc/self/maps: "addr perms offset dev inode  pathname"
                 * -- pathname is the 6th whitespace-delimited field, but,
                 * unlike the five before it, is never itself re-tokenized
                 * by the kernel: real install paths routinely contain
                 * spaces (e.g. Steam's own "Proton 11.0" directory), so
                 * finding the *last* space on the line -- as this used to
                 * -- lands inside such a pathname instead of at its
                 * start. Skip exactly five fields by hand instead. */
                field = line;
                for (i = 0; i < 5 && field; i++)
                {
                    field = strchr(field, ' ');
                    if (field)
                        while (*field == ' ')
                            field++;
                }
                if (!field || !*field)
                    continue;

                len = strlen(field);
                if (len > 9 && strcmp(field + len - 9, "/ntdll.so") == 0)
                {
                    snprintf(path, sizeof(path), "%s", field);
                    break;
                }
            }
            fclose(f);
        }
        if (path[0])
        {
            ntdll_handle = dlopen(path, RTLD_NOW | RTLD_NOLOAD);
            linuwux_log("linuwux_find_ntdll_symbol: ntdll.so at %s -> handle=%p\n", path, ntdll_handle);
        }
        else
            linuwux_log("linuwux_find_ntdll_symbol: could not find ntdll.so in /proc/self/maps\n");
    }

    return ntdll_handle ? dlsym(ntdll_handle, name) : NULL;
}

/* ------------------------------------------------------------------ */
/* HwProfileGuid: written via the real NT registry API, not a wine.inf */
/* content-insert -- no source patch or rebuild required.              */
/* ------------------------------------------------------------------ */

/* Matches the real NT structures field-for-field (winternl.h) -- same
 * compiler, same target ABI, so this lays out identically. ULONG is
 * always 32 bits on Windows (unlike `unsigned long`, which is 64 on
 * Linux x86_64), hence uint32_t rather than a native-width type. */
struct linuwux_unicode_string
{
    uint16_t Length;
    uint16_t MaximumLength;
    uint16_t *Buffer;
};

struct linuwux_object_attributes
{
    uint32_t Length;
    void *RootDirectory;
    struct linuwux_unicode_string *ObjectName;
    uint32_t Attributes;
    void *SecurityDescriptor;
    void *SecurityQualityOfService;
};

#define LINUWUX_OBJ_CASE_INSENSITIVE 0x00000040
#define LINUWUX_KEY_ALL_ACCESS       0x001F003F
#define LINUWUX_REG_SZ               1

/* NtCreateKey/NtSetValueKey/NtClose are confirmed genuine ELF exports of
 * ntdll.so (`nm -D` against a real build), same as wine_server_call --
 * their unix-side implementations (dlls/ntdll/unix/registry.c) are
 * declared WINAPI/__stdcall, but that attribute is a no-op for GCC on
 * x86_64 (stdcall only means anything on 32-bit x86), so the compiled
 * symbols use plain SysV ABI, directly callable via a normal C function
 * pointer -- no ms_abi/PE-export-table work needed, unlike calling into
 * genuinely PE-side code would require. Internally these still do a real
 * wine_server_call() (SERVER_START_REQ(create_key)/(set_key_value)), but
 * since we call the *wrapper* functions rather than hand-building the
 * request ourselves, none of the wire-protocol/struct-layout reverse
 * engineering the old faketime implementation needed applies here --
 * the wrapper handles all of that. */
typedef int32_t (*nt_create_key_fn)(void **key, uint32_t access, const struct linuwux_object_attributes *attr,
                                     uint32_t index, const struct linuwux_unicode_string *class,
                                     uint32_t options, uint32_t *disposition);
typedef int32_t (*nt_set_value_key_fn)(void *key, const struct linuwux_unicode_string *name, uint32_t index,
                                        uint32_t type, const void *data, uint32_t count);
typedef int32_t (*nt_close_fn)(void *handle);

static void linuwux_ascii_to_utf16(const char *src, uint16_t *dst, size_t count)
{
    size_t i;
    for (i = 0; i < count; i++)
        dst[i] = (uint16_t)(unsigned char)src[i];
}

/* Same key/value the old wine.inf content-insert set (patches/base/
 * hwprofile_guid.reg), but written live via wineserver instead of baked
 * into a freshly-booted prefix's registry defaults at Wine build time --
 * works on a prefix this project never patched or rebuilt. Called from
 * the 0x336933 (arm) case in linuwux_cpuid_spoof()
 * -- see the forward declaration above for why that timing, rather than
 * "first wineserver connection", is what makes NtCreateKey's own nested
 * wine_server_call() safe here. */
static void linuwux_set_hwprofile_guid(void)
{
    static int done;
    nt_create_key_fn nt_create_key;
    nt_set_value_key_fn nt_set_value_key;
    nt_close_fn nt_close;
    struct linuwux_unicode_string value_name;
    struct linuwux_object_attributes attr;
    void *cur, *next;
    uint16_t value_name_buf[16];
    uint16_t data_buf[48];
    size_t i;
    /* Same key as the old wine.inf content-insert (patches/base/
     * hwprofile_guid.reg) split into its individual path components --
     * see the loop below for why this can't just be one string. */
    static const char *const path_components[] = {
        "\\Registry", "Machine", "System", "CurrentControlSet",
        "Control", "IDConfigDB", "Hardware Profiles", "0001"
    };
    static const char value_name_str[] = "HwProfileGuid";
    static const char data_str[] = "{12345678-1234-1234-1234-123456789012}";

    if (done)
        return;
    done = 1;

    nt_create_key = (nt_create_key_fn)linuwux_find_ntdll_symbol("NtCreateKey");
    nt_set_value_key = (nt_set_value_key_fn)linuwux_find_ntdll_symbol("NtSetValueKey");
    nt_close = (nt_close_fn)linuwux_find_ntdll_symbol("NtClose");
    if (!nt_create_key || !nt_set_value_key || !nt_close)
    {
        linuwux_log("hwprofile_guid: could not resolve NtCreateKey/NtSetValueKey/NtClose -- skipping\n");
        return;
    }

    /* NtCreateKey only ever auto-creates the LAST missing component of
     * whatever ObjectName it's given -- wineserver's generic object-
     * namespace walk (server/object.c: lookup_named_object(), confirmed
     * against real Wine source) fails the whole call with
     * STATUS_OBJECT_NAME_NOT_FOUND the instant an INTERMEDIATE component
     * is missing, rather than creating it along the way. A single
     * NtCreateKey call for the full multi-level path therefore only ever
     * worked on a prefix that already happened to have "Control\
     * IDConfigDB\Hardware Profiles" -- which Wine's own default registry
     * doesn't ship (confirmed the hard way: NtCreateKey failing on a real
     * Proton 11.0 + Steam Linux Runtime launch). RegCreateKeyEx gets away
     * with a multi-level path because it walks and creates each
     * component itself; do the same here, threading each level's handle
     * in as the next call's RootDirectory. */
    cur = NULL;
    for (i = 0; i < sizeof(path_components) / sizeof(path_components[0]); i++)
    {
        const char *comp = path_components[i];
        size_t comp_len = strlen(comp);
        uint16_t comp_buf[32];
        struct linuwux_unicode_string comp_name;

        linuwux_ascii_to_utf16(comp, comp_buf, comp_len + 1);
        comp_name.Length = (uint16_t)(comp_len * sizeof(uint16_t));
        comp_name.MaximumLength = (uint16_t)((comp_len + 1) * sizeof(uint16_t));
        comp_name.Buffer = comp_buf;

        attr.Length = sizeof(attr);
        attr.RootDirectory = cur;
        attr.ObjectName = &comp_name;
        attr.Attributes = LINUWUX_OBJ_CASE_INSENSITIVE;
        attr.SecurityDescriptor = NULL;
        attr.SecurityQualityOfService = NULL;

        next = NULL;
        if (nt_create_key(&next, LINUWUX_KEY_ALL_ACCESS, &attr, 0, NULL, 0, NULL) < 0 || !next)
        {
            linuwux_log("hwprofile_guid: NtCreateKey(\"%s\") failed -- skipping\n", comp);
            if (cur)
                nt_close(cur);
            return;
        }
        if (cur)
            nt_close(cur);
        cur = next;
    }

    linuwux_ascii_to_utf16(value_name_str, value_name_buf, sizeof(value_name_str));
    value_name.Length = (uint16_t)((sizeof(value_name_str) - 1) * sizeof(uint16_t));
    value_name.MaximumLength = (uint16_t)(sizeof(value_name_str) * sizeof(uint16_t));
    value_name.Buffer = value_name_buf;

    linuwux_ascii_to_utf16(data_str, data_buf, sizeof(data_str));

    if (nt_set_value_key(cur, &value_name, 0, LINUWUX_REG_SZ, data_buf,
                          (uint32_t)(sizeof(data_str) * sizeof(uint16_t))) < 0)
        linuwux_log("hwprofile_guid: NtSetValueKey failed\n");
    else
        linuwux_log("hwprofile_guid: HwProfileGuid registry value set\n");

    nt_close(cur);
}

/* ------------------------------------------------------------------ */
/* Faketime: client-side clock_gettime()/gettimeofday() interposition  */
/* ------------------------------------------------------------------ */

#define LINUWUX_TICKS_PER_SEC      10000000LL
#define LINUWUX_TICKS_1601_TO_1970 116444736000000000LL

/* Windows FILETIME-style ticks (100ns since 1601-01-01), matching the
 * unit wineserver's own current_time used -- keeps the offset formula
 * below identical to what the old server-side patch computed. */
static int64_t linuwux_unix_to_ticks(time_t sec, long nsec)
{
    return (int64_t)sec * LINUWUX_TICKS_PER_SEC + nsec / 100 + LINUWUX_TICKS_1601_TO_1970;
}

static void linuwux_ticks_to_unix(int64_t ticks, time_t *sec, long *nsec)
{
    int64_t unix_ticks = ticks - LINUWUX_TICKS_1601_TO_1970;
    if (unix_ticks < 0)
        unix_ticks = 0;
    *sec = (time_t)(unix_ticks / LINUWUX_TICKS_PER_SEC);
    *nsec = (long)(unix_ticks % LINUWUX_TICKS_PER_SEC) * 100;
}

/* 0 means "not set" -- clock_gettime()/gettimeofday() pass real time
 * through unmodified until the CPUID leaf below sets this at least once.
 * A real offset can validly be 0 too (target time == real time at the
 * moment it was set), so this needs its own has-it-been-set flag rather
 * than treating 0 as "unset". */
static _Atomic int64_t g_faketime_offset;
static _Atomic int g_faketime_active;

typedef int (*clock_gettime_fn)(clockid_t, struct timespec *);
static clock_gettime_fn real_clock_gettime;

int clock_gettime(clockid_t id, struct timespec *ts)
{
    int ret;

    if (!real_clock_gettime)
        real_clock_gettime = (clock_gettime_fn)dlsym(RTLD_NEXT, "clock_gettime");

    ret = real_clock_gettime(id, ts);

    if (ret == 0 && atomic_load(&g_faketime_active) &&
        (id == CLOCK_REALTIME
#ifdef CLOCK_REALTIME_COARSE
         || id == CLOCK_REALTIME_COARSE
#endif
        ))
    {
        int64_t offset = atomic_load(&g_faketime_offset);
        int64_t ticks = linuwux_unix_to_ticks(ts->tv_sec, ts->tv_nsec) - offset;
        linuwux_ticks_to_unix(ticks, &ts->tv_sec, &ts->tv_nsec);
    }

    return ret;
}

typedef int (*gettimeofday_fn)(struct timeval *, void *);
static gettimeofday_fn real_gettimeofday;

int gettimeofday(struct timeval *tv, void *tz)
{
    int ret;

    if (!real_gettimeofday)
        real_gettimeofday = (gettimeofday_fn)dlsym(RTLD_NEXT, "gettimeofday");

    ret = real_gettimeofday(tv, tz);

    if (ret == 0 && atomic_load(&g_faketime_active))
    {
        int64_t offset = atomic_load(&g_faketime_offset);
        int64_t ticks = linuwux_unix_to_ticks(tv->tv_sec, tv->tv_usec * 1000) - offset;
        time_t sec;
        long nsec;
        linuwux_ticks_to_unix(ticks, &sec, &nsec);
        tv->tv_sec = sec;
        tv->tv_usec = nsec / 1000;
    }

    return ret;
}

/* Same formula the old wineserver-side patch used:
 * faketime_offset = ((current_time_ticks >> 32) - requested_value) << 32
 * -- computed once, here, from real time at the moment the leaf fires
 * (via real_clock_gettime() directly -- NOT the bare clock_gettime()
 * name, which would recurse into our own wrapper above and apply any
 * *existing* offset before computing the new one, compounding instead
 * of resetting), then applied as a constant shift to every future
 * CLOCK_REALTIME/CLOCK_REALTIME_COARSE query. Matching the formula
 * exactly means a real trampoline's call produces the same real-world
 * time shift regardless of whether this client-side path or the old
 * wineserver-side one is behind it. */
static void linuwux_set_faketime(long long requested)
{
    struct timespec ts;
    int64_t now_ticks, high32, offset;

    if (!real_clock_gettime)
        real_clock_gettime = (clock_gettime_fn)dlsym(RTLD_NEXT, "clock_gettime");

    if (real_clock_gettime(CLOCK_REALTIME, &ts) != 0)
    {
        linuwux_log("faketime: clock_gettime(CLOCK_REALTIME) failed: %s -- skipping\n", strerror(errno));
        return;
    }

    now_ticks = linuwux_unix_to_ticks(ts.tv_sec, ts.tv_nsec);
    high32 = now_ticks >> 32;
    offset = (high32 - requested) << 32;

    atomic_store(&g_faketime_offset, offset);
    atomic_store(&g_faketime_active, 1);
    linuwux_log("faketime: requested=%llx now_ticks_hi32=%llx -> offset=%llx\n",
                requested, (unsigned long long)high32, (unsigned long long)offset);
}

/* ------------------------------------------------------------------ */
/* sigaction()/prctl() interposition                                   */
/* ------------------------------------------------------------------ */

typedef int (*sigaction_fn)(int, const struct sigaction *, struct sigaction *);
typedef long (*prctl_fn)(int, unsigned long, unsigned long, unsigned long, unsigned long);

static sigaction_fn real_sigaction;
static prctl_fn real_prctl;

static struct sigaction s_real_segv;
static struct sigaction s_real_sys;
static int s_have_real_segv;
static int s_have_real_sys;

static void linuwux_segv_wrapper(int sig, siginfo_t *info, void *uctx);
static void linuwux_sigsys_wrapper(int sig, siginfo_t *info, void *uctx);

static void linuwux_chain_segv(int sig, siginfo_t *info, void *uctx)
{
    if (s_have_real_segv && s_real_segv.sa_sigaction)
        s_real_segv.sa_sigaction(sig, info, uctx);
    else {
        /* No real handler captured -- don't silently swallow a genuine
         * fault. Restore default disposition and re-raise. */
        signal(SIGSEGV, SIG_DFL);
        raise(SIGSEGV);
    }
}

static void linuwux_chain_sigsys(int sig, siginfo_t *info, void *uctx)
{
    if (s_have_real_sys && s_real_sys.sa_sigaction)
        s_real_sys.sa_sigaction(sig, info, uctx);
}

static void linuwux_segv_wrapper(int sig, siginfo_t *info, void *uctx)
{
    ucontext_t *ctx = (ucontext_t *)uctx;
    if (linuwux_cpuid_spoof(ctx))
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

/*
 * Enable CPUID faulting -- deliberately NOT done in the library constructor.
 * Constructors run before Wine (or anything else in the process) has
 * registered a real SIGSEGV handler; a stray cpuid instruction executed by
 * libc/ld.so startup code in that window would fault with no handler
 * installed at all yet (not even Wine's own), default disposition, instant
 * process death with no log line and nothing to debug. Confirmed the hard
 * way: an earlier version enabled this in the constructor and killed the
 * game process before it ever got as far as registering its own handlers.
 * Safe here, called right after our SIGSEGV wrapper is confirmed installed
 * as the active handler for this thread.
 *
 * Known scope caveat: ARCH_SET_CPUID is a per-thread setting and this
 * only fires once, for whichever thread first registers a SIGSEGV
 * handler -- other threads in the same process don't get CPUID faulting
 * enabled automatically.
 */
static void linuwux_enable_cpuid_fault(void)
{
    static int done;
    if (done)
        return;
    done = 1;
    syscall(SYS_arch_prctl, ARCH_SET_CPUID, 0);
    linuwux_log("CPUID faulting enabled (tid=%d)\n", (int)syscall(SYS_gettid));
}

int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
{
    if (!real_sigaction)
        real_sigaction = (sigaction_fn)dlsym(RTLD_NEXT, "sigaction");

    if (act && signum == SIGSEGV && act->sa_sigaction != linuwux_segv_wrapper) {
        s_real_segv = *act;
        s_have_real_segv = 1;
        struct sigaction ours = *act;
        ours.sa_sigaction = linuwux_segv_wrapper;
        int r = real_sigaction(signum, &ours, oldact);
        if (r == 0) {
            linuwux_log("intercepted Wine's sigaction(SIGSEGV, ...)\n");
            linuwux_enable_cpuid_fault();
        }
        return r;
    }
    if (act && signum == SIGSYS && act->sa_sigaction != linuwux_sigsys_wrapper) {
        s_real_sys = *act;
        s_have_real_sys = 1;
        struct sigaction ours = *act;
        ours.sa_sigaction = linuwux_sigsys_wrapper;
        linuwux_log("intercepted Wine's sigaction(SIGSYS, ...)\n");
        return real_sigaction(signum, &ours, oldact);
    }
    return real_sigaction(signum, act, oldact);
}

/* glibc declares prctl() variadic (int prctl(int, ...)); match that
 * exactly here to avoid a conflicting-types error against <sys/prctl.h>.
 * Calling the real prctl through a fixed 5-arg function pointer is still
 * ABI-safe on x86_64 System V -- it's the same trick used to interpose
 * open()/fcntl()/ioctl(), all similarly variadic in their headers. */
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

    if (ret >= 0 && option == PR_SET_SYSCALL_USER_DISPATCH && a2 == PR_SYS_DISPATCH_ON) {
        unsigned char *selector_addr = (unsigned char *)a5;
        unsigned char *teb = (unsigned char *)linuwux_get_teb();
        g_sud_teb_offset = selector_addr - teb;
        linuwux_log("learned SUD selector: teb-offset=%#lx (teb=%p selector=%p)\n",
                    g_sud_teb_offset, (void *)teb, (void *)selector_addr);
    }
    return (int)ret;
}

__attribute__((constructor))
static void linuwux_preload_init(void)
{
    char overrides[512];
    const char *existing;

    linuwux_detect_cpu_vendor();

    /* WINEDLLOVERRIDES: append our required native-DLL overrides,
     * skipping any the user/launcher already specified (never override
     * explicit user intent). Wine reads this via a plain getenv() on the
     * first load-order decision (dlls/ntdll/unix/loadorder.c:
     * init_load_order()), which only happens deep inside the unix-side
     * loader's module-loading logic -- well after all ELF constructors,
     * including this one, have already run. Duplicate entries for the
     * same module produce unspecified bsearch() behavior in Wine's own
     * parser (its override list is sorted then bsearched, with no
     * defined tie-break for duplicate keys), so skipping ones already
     * set isn't just politeness -- it avoids genuinely undefined
     * behavior. */
    existing = getenv("WINEDLLOVERRIDES");
    overrides[0] = '\0';
    if (existing)
        snprintf(overrides, sizeof(overrides), "%s", existing);

    if (!existing || !strstr(existing, "winmm="))
        strncat(overrides, overrides[0] ? ";winmm=n,b" : "winmm=n,b", sizeof(overrides) - strlen(overrides) - 1);
    if (!existing || !strstr(existing, "version="))
        strncat(overrides, overrides[0] ? ";version=n,b" : "version=n,b", sizeof(overrides) - strlen(overrides) - 1);
    if (!existing || !strstr(existing, "reflex="))
        strncat(overrides, overrides[0] ? ";reflex=n,b" : "reflex=n,b", sizeof(overrides) - strlen(overrides) - 1);

    setenv("WINEDLLOVERRIDES", overrides, 1);
    linuwux_log("WINEDLLOVERRIDES=\"%s\"\n", overrides);

    /* Prefer stock steamclient over Proton's lsteamclient -- some
     * DenuvOwO packs need this, since they dislike lsteamclient's
     * translation layer. Known tradeoff: the Steam Overlay's own
     * in-game activation goes through lsteamclient too, so this also
     * silences the overlay (confirmed against a real Steam + GE-Proton
     * launch; tried leaving it unset by default, but that broke the
     * bypass, which matters more). Set PROTON_DISABLE_LSTEAMCLIENT=0
     * yourself via launch options if you'd rather keep the overlay and
     * your pack doesn't need this. */
    setenv("PROTON_DISABLE_LSTEAMCLIENT", "1", 0);

    linuwux_log("liblinuwux_preload.so loaded (pid=%d)\n", getpid());
}
