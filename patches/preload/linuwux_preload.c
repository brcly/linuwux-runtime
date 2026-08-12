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
 * linuwux-preload (EXPERIMENTAL)
 *
 * LD_PRELOAD alternative to patches/base/linuwux_hooks.c. Instead of
 * splicing #include/call-stub text into Wine's own signal_x86_64.c
 * (fragile to upstream reordering/reformatting -- see the GE 11-3 -> 11-5
 * SIGSYS anchor breakage this was built to stop recurring), this
 * interposes the two libc calls Wine itself makes to set up signal
 * delivery -- sigaction() and prctl() -- and wraps around whatever Wine
 * registers, without touching ntdll's source at all.
 *
 * Verified against a real GE-Proton 11-5 tree before building this:
 * Wine's SIGSEGV/SIGSYS registration (signal_init_process()) and its
 * Syscall User Dispatch registration (init_syscall_frame(), called once
 * per thread) both go through the plain libc sigaction()/prctl() symbols,
 * not a raw syscall() that would bypass LD_PRELOAD interposition.
 *
 * Faketime (CPUID leaf 0x336967) talks to wineserver via wine_server_call(),
 * same as the ntdll-side version -- but without an exact, per-build-known
 * struct layout, that call is dangerous to fake blind: wine_server_call()
 * reads fields (data_count/reply_data/data[]/name) at offsets fixed by
 * sizeof(union generic_request), which varies by wine version/patch chain
 * and isn't guessable. Two things had to be nailed down, neither by
 * touching wine's source:
 *   - REQ_set_faketime's numeric ID is positionally generated (depends on
 *     every request defined before it in protocol.def) -- extracted at
 *     *our* build time from the tree's own already-generated
 *     server_protocol.h (build_preload_library() in lib/apply-preload.sh),
 *     baked in via -DLINUWUX_REQ_SET_FAKETIME. Reading a build artifact,
 *     not modifying one.
 *   - sizeof(union generic_request) is learned at runtime by observing
 *     Wine's own real traffic. wine_server_receive_fd() is what hands a
 *     thread its request_fd, but `nm -D ntdll.so` against a real build
 *     shows it is NOT an exported ELF dynamic symbol (unlike
 *     wine_server_call/wine_server_send_fd, which are) -- it's
 *     static/internal, so it can't be interposed directly. Its entire
 *     job, though, is one recvmsg() call with SCM_RIGHTS ancillary data
 *     to receive that fd via fd-passing, and recvmsg() itself is a
 *     genuine libc symbol -- ntdll.so calling into libc.so always
 *     crosses the ELF boundary, regardless of how wine_server_receive_fd
 *     itself is scoped. Intercepting recvmsg() and reading the SCM_RIGHTS
 *     control message gives the same fd. The first write()/writev() to
 *     that fd is then, by construction of Wine's own client protocol code
 *     (dlls/ntdll/unix/server.c: send_request()), always exactly
 *     sizeof(union generic_request) bytes. See the recvmsg()/write()/
 *     writev() interposition below.
 *
 * Enable event tracing with LINUWUX_DEBUG=1 (same variable as the ntdll
 * hooks, deliberately -- this is a drop-in alternative, not a different
 * feature).
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
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <ucontext.h>
#include <unistd.h>

/* Set by build_preload_library() (lib/apply-preload.sh) from the wine
 * tree's own generated include/wine/server_protocol.h. -1 means "could not
 * be determined at build time" -- checked at runtime, faketime just logs
 * and no-ops rather than sending a request with a bogus type ID. */
#ifndef LINUWUX_REQ_SET_FAKETIME
#define LINUWUX_REQ_SET_FAKETIME (-1)
#endif

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
/* CPUID spoofing (ported from patches/base/linuwux_hooks.c)           */
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

/* Defined below (needs the wine_server_call() plumbing); forward-declared
 * here so the 0x336967 (faketime) case in linuwux_cpuid_spoof() can call it. */
static void linuwux_set_faketime(long long faketime);

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
/* Wine-system RIP scope filter (same rationale as linuwux_hooks.c)    */
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

/* ------------------------------------------------------------------ */
/* Faketime: wine_server_call() with a runtime-learned request size    */
/* ------------------------------------------------------------------ */

/* Matches the real, generated struct set_faketime_request exactly (byte
 * for byte -- verified against tools/make_requests' actual output for our
 * own set_faketime.protocol addition): 12-byte header, 4 bytes padding to
 * align the 8-byte timeout_t, then the value itself. */
struct linuwux_request_header
{
    int          req;
    unsigned int request_size;
    unsigned int reply_size;
};

struct linuwux_set_faketime_request
{
    struct linuwux_request_header header;
    char __pad[4];
    long long faketime;
};

/* Mirrors struct __server_request_info's tail in wine/server.h, field for
 * field -- same compiler, same target ABI, same types and order, so this
 * lays out identically. Only the union in front of it (which this trailer
 * must sit immediately after) has a size wine_server_call() decides at
 * ntdll's own compile time and doesn't tell us; that's g_generic_request_size,
 * learned below rather than assumed. */
struct linuwux_server_iovec { const void *ptr; unsigned int size; };
struct linuwux_request_trailer
{
    unsigned int data_count;
    void *reply_data;
    struct linuwux_server_iovec data[5];
    const char *name;
};

static _Atomic int g_request_fd_candidate = -1;
static _Atomic size_t g_generic_request_size = 0;

typedef ssize_t (*recvmsg_fn)(int, struct msghdr *, int);
static recvmsg_fn real_recvmsg;

ssize_t recvmsg(int fd, struct msghdr *msg, int flags)
{
    ssize_t ret;

    if (!real_recvmsg)
        real_recvmsg = (recvmsg_fn)dlsym(RTLD_NEXT, "recvmsg");

    ret = real_recvmsg(fd, msg, flags);

    if (ret >= 0 && atomic_load(&g_request_fd_candidate) == -1 && msg && msg->msg_control)
    {
        struct cmsghdr *cmsg;
        for (cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg))
        {
            if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS &&
                cmsg->cmsg_len >= CMSG_LEN(sizeof(int)))
            {
                int received_fd, expected = -1;
                memcpy(&received_fd, CMSG_DATA(cmsg), sizeof(received_fd));
                if (received_fd >= 0 &&
                    atomic_compare_exchange_strong(&g_request_fd_candidate, &expected, received_fd))
                    linuwux_log("candidate request_fd=%d (first SCM_RIGHTS via recvmsg)\n", received_fd);
                break;
            }
        }
    }

    return ret;
}

typedef ssize_t (*write_fn)(int, const void *, size_t);
typedef ssize_t (*writev_fn)(int, const struct iovec *, int);
static write_fn real_write;
static writev_fn real_writev;

/* Fast path once learned: one atomic load, no further work -- both
 * functions are far too hot in a normal process to carry any real
 * overhead past the learning window. */
ssize_t write(int fd, const void *buf, size_t count)
{
    if (!real_write)
        real_write = (write_fn)dlsym(RTLD_NEXT, "write");

    if (atomic_load(&g_generic_request_size) == 0 &&
        fd == atomic_load(&g_request_fd_candidate) && count > 0)
    {
        size_t expected = 0;
        if (atomic_compare_exchange_strong(&g_generic_request_size, &expected, count))
            linuwux_log("learned sizeof(union generic_request)=%zu (via write)\n", count);
    }
    return real_write(fd, buf, count);
}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt)
{
    if (!real_writev)
        real_writev = (writev_fn)dlsym(RTLD_NEXT, "writev");

    if (atomic_load(&g_generic_request_size) == 0 &&
        fd == atomic_load(&g_request_fd_candidate) && iovcnt > 0 && iov[0].iov_len > 0)
    {
        size_t expected = 0;
        size_t sz = iov[0].iov_len;
        if (atomic_compare_exchange_strong(&g_generic_request_size, &expected, sz))
            linuwux_log("learned sizeof(union generic_request)=%zu (via writev)\n", sz);
    }
    return real_writev(fd, iov, iovcnt);
}

typedef unsigned int (*wine_server_call_fn)(void *);

/* dlsym(RTLD_DEFAULT, ...) only searches the process's GLOBAL symbol
 * scope -- which does NOT include a library loaded via plain dlopen()
 * without RTLD_GLOBAL (glibc's dlopen() default is RTLD_LOCAL). Wine's
 * own PE/unix-module loader loads ntdll.so's unix backend via its own
 * internal dlopen() call, not as an ordinary linked dependency, so
 * wine_server_call -- confirmed present via `nm -D ntdll.so` against a
 * real build -- is invisible to RTLD_DEFAULT even though it genuinely
 * exists. Fix: find ntdll.so's real on-disk path from /proc/self/maps
 * (it's already loaded by the time any of our code runs), then
 * dlopen(path, RTLD_NOLOAD) to get a handle to that SAME already-loaded
 * object without a second load, and dlsym() on that specific handle --
 * handle-based dlsym() always finds the symbol regardless of the
 * object's RTLD_LOCAL/RTLD_GLOBAL scope. Verified against a synthetic
 * RTLD_LOCAL dlopen() before relying on it here. */
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
                if (len && line[len - 1] == '\n')
                    line[--len] = '\0';
                if (len > 9 && strcmp(line + len - 9, "/ntdll.so") == 0)
                {
                    const char *sp = strrchr(line, ' ');
                    if (sp)
                        snprintf(path, sizeof(path), "%s", sp + 1);
                    break;
                }
            }
            fclose(f);
        }
        if (path[0])
        {
            ntdll_handle = dlopen(path, RTLD_NOW | RTLD_NOLOAD);
            linuwux_log("faketime: ntdll.so at %s -> handle=%p\n", path, ntdll_handle);
        }
        else
            linuwux_log("faketime: could not find ntdll.so in /proc/self/maps\n");
    }

    return ntdll_handle ? dlsym(ntdll_handle, name) : NULL;
}

static void linuwux_set_faketime(long long faketime)
{
    static wine_server_call_fn real_wine_server_call;
    size_t union_size = atomic_load(&g_generic_request_size);
    unsigned char *buf;
    struct linuwux_set_faketime_request *req;
    struct linuwux_request_trailer *trailer;

    if (LINUWUX_REQ_SET_FAKETIME < 0)
    {
        linuwux_log("faketime: REQ_set_faketime unknown (not found in this tree's "
                    "server_protocol.h at build time) -- skipping\n");
        return;
    }
    if (!union_size)
    {
        linuwux_log("faketime: sizeof(union generic_request) not learned yet "
                    "(no wineserver traffic observed on the request fd) -- skipping\n");
        return;
    }
    if (!real_wine_server_call)
        real_wine_server_call = (wine_server_call_fn)linuwux_find_ntdll_symbol("wine_server_call");
    if (!real_wine_server_call)
    {
        linuwux_log("faketime: wine_server_call not resolvable -- skipping\n");
        return;
    }

    buf = calloc(1, union_size + sizeof(struct linuwux_request_trailer));
    if (!buf)
        return;

    req = (struct linuwux_set_faketime_request *)buf;
    req->header.req = LINUWUX_REQ_SET_FAKETIME;
    req->header.request_size = 0;
    req->header.reply_size = 0;
    req->faketime = faketime;

    trailer = (struct linuwux_request_trailer *)(buf + union_size);
    trailer->data_count = 0;
    trailer->reply_data = NULL;
    trailer->name = "set_faketime";

    real_wine_server_call(buf);
    linuwux_log("faketime: sent set_faketime=%llx via wine_server_call\n", faketime);
    free(buf);
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
 * Same scope caveat as the ntdll-side variant either way: ARCH_SET_CPUID is
 * a per-thread setting and this only fires once, for whichever thread
 * first registers a SIGSEGV handler -- not a regression, just an existing
 * limitation neither variant currently solves.
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
    linuwux_detect_cpu_vendor();
    linuwux_log("liblinuwux_preload.so loaded (pid=%d)\n", getpid());
}
