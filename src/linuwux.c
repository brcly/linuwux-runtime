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
 * linuwux — LD_PRELOAD library for DenuvOwO/LinUwUx under Wine/Proton.
 *
 * Hooks: sigaction, prctl, clock_gettime, gettimeofday.
 * Provides: CPUID spoof, SIGSYS redirect, HwProfileGuid, DLL overrides, faketime.
 * Debug: LINUWUX_DEBUG=1
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stddef.h>
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

/* From -DLINUWUX_VERSION; "dev" if built by hand. */
#ifndef LINUWUX_VERSION
#define LINUWUX_VERSION "dev"
#endif

/* Kept for `strings` / `linuwux --version`. */
static const char linuwux_version_tag[] __attribute__((used)) =
    "linuwux " LINUWUX_VERSION;

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

/* Win64 TEB: %gs:0x30 (NtTib.Self). */
static inline void *linuwux_get_teb(void)
{
    void *teb;
    __asm__ volatile ("movq %%gs:0x30, %0" : "=r"(teb));
    return teb;
}

/* --- CPUID spoof --- */

/* Set on arm leaf; read from all threads. */
static _Atomic uint64_t g_target_sys_handler = 0;

/* Filled once in the constructor before any other thread exists. */
static unsigned int g_spoof_leaf1_eax, g_spoof_leaf1_ebx, g_spoof_leaf1_ecx, g_spoof_leaf1_edx;
static unsigned int g_spoof_leaf40000000_eax, g_spoof_leaf40000000_ebx, g_spoof_leaf40000000_ecx, g_spoof_leaf40000000_edx;
static unsigned int g_spoof_leaf40000001_eax, g_spoof_leaf40000001_ebx, g_spoof_leaf40000001_ecx, g_spoof_leaf40000001_edx;

static void linuwux_detect_cpu_vendor(void)
{
    unsigned int eax, ebx, ecx, edx;
    int avx = 0;
    if (getenv("PROTON_AVX") != NULL && strcmp(getenv("PROTON_AVX"), "1") == 0)
        avx = 1;

    __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(0) : "memory");

    if (ebx == 0x756E6547 && edx == 0x49656E69 && ecx == 0x6C65746E) {
        /* GenuineIntel */
        g_spoof_leaf1_eax = 0x000A0655;
        g_spoof_leaf1_ebx = 0x00200800;
        g_spoof_leaf1_ecx = avx ? 0x7BFAFBFF : 0x01FAEBFF;
        g_spoof_leaf1_edx = 0xBFEBFBFF;
        g_spoof_leaf40000000_eax = 0x40000001;
        g_spoof_leaf40000000_ebx = 0x65707948;
        g_spoof_leaf40000000_ecx = 0x67624472;
        g_spoof_leaf40000000_edx = 0;
        g_spoof_leaf40000001_eax = 0x30237648;
        g_spoof_leaf40000001_ebx = 0;
        g_spoof_leaf40000001_ecx = 0;
        g_spoof_leaf40000001_edx = 0;
        linuwux_log("detect_cpu_vendor: Intel (avx=%d)\n", avx);
    } else if (ebx == 0x68747541 && edx == 0x69746E65 && ecx == 0x444D4163) {
        /* AuthenticAMD */
        g_spoof_leaf1_eax = 0x00A20F12;
        g_spoof_leaf1_ebx = 0x00100800;
        g_spoof_leaf1_ecx = avx ? 0x7AD8320B : 0x00F8220B;
        g_spoof_leaf1_edx = 0x178BFBFF;
        g_spoof_leaf40000000_eax = 0x40000001;
        g_spoof_leaf40000000_ebx = 0x706D6953;
        g_spoof_leaf40000000_ecx = 0x7653656C;
        g_spoof_leaf40000000_edx = 0x2020206D;
        g_spoof_leaf40000001_eax = 0x30237648;
        g_spoof_leaf40000001_ebx = 0;
        g_spoof_leaf40000001_ecx = 0;
        g_spoof_leaf40000001_edx = 0;
        linuwux_log("detect_cpu_vendor: AMD (avx=%d)\n", avx);
    } else {
        linuwux_log("detect_cpu_vendor: unknown vendor ebx=%08x edx=%08x ecx=%08x\n", ebx, edx, ecx);
    }
}

#define LINUWUX_KUSER_SHARED_DATA_ADDR 0x000000007FFE0000UL

static void linuwux_patch_kuser_shared_data(void)
{
    uint8_t *kuser = (uint8_t *)LINUWUX_KUSER_SHARED_DATA_ADDR;
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    void *page_start = (void *)((uintptr_t)LINUWUX_KUSER_SHARED_DATA_ADDR & ~(page_size - 1));

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

static void linuwux_set_faketime(long long faketime);
static void linuwux_set_hwprofile_guid(void);

/* DenuvOwO protocol leaves (not real CPUID leaves). */
#define LINUWUX_CPUID_LEAF_ARM      0x336933
#define LINUWUX_CPUID_LEAF_FAKETIME 0x336967

/* Handle a CPUID fault. Returns 1 if handled. */
static int linuwux_cpuid_spoof(ucontext_t *ctx)
{
    unsigned int spoof_leaf, spoof_subleaf;
    unsigned char *rip = (unsigned char *)ctx->uc_mcontext.gregs[REG_RIP];

    spoof_leaf = (unsigned int)ctx->uc_mcontext.gregs[REG_RAX];
    spoof_subleaf = (unsigned int)ctx->uc_mcontext.gregs[REG_RCX];

    if (!(rip[0] == 0x0F && rip[1] == 0xA2))
        return 0;

    switch (spoof_leaf) {
    case 1:
        ctx->uc_mcontext.gregs[REG_RAX] = g_spoof_leaf1_eax;
        ctx->uc_mcontext.gregs[REG_RBX] = g_spoof_leaf1_ebx;
        ctx->uc_mcontext.gregs[REG_RCX] = g_spoof_leaf1_ecx | (atomic_load(&g_target_sys_handler) ? 0 : (0x1 << 31));
        ctx->uc_mcontext.gregs[REG_RDX] = g_spoof_leaf1_edx;
        break;

    case 0x40000000:
        ctx->uc_mcontext.gregs[REG_RAX] = g_spoof_leaf40000000_eax;
        ctx->uc_mcontext.gregs[REG_RBX] = g_spoof_leaf40000000_ebx;
        ctx->uc_mcontext.gregs[REG_RCX] = g_spoof_leaf40000000_ecx;
        ctx->uc_mcontext.gregs[REG_RDX] = g_spoof_leaf40000000_edx;
        break;

    case 0x40000001:
        ctx->uc_mcontext.gregs[REG_RAX] = g_spoof_leaf40000001_eax;
        ctx->uc_mcontext.gregs[REG_RBX] = g_spoof_leaf40000001_ebx;
        ctx->uc_mcontext.gregs[REG_RCX] = g_spoof_leaf40000001_ecx;
        ctx->uc_mcontext.gregs[REG_RDX] = g_spoof_leaf40000001_edx;
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

    case LINUWUX_CPUID_LEAF_ARM:
        linuwux_log("cpuid arm leaf, TargetSysHandler=%#llx\n",
                    (unsigned long long)ctx->uc_mcontext.gregs[REG_RCX]);
        atomic_store(&g_target_sys_handler, (uint64_t)ctx->uc_mcontext.gregs[REG_RCX]);
        linuwux_patch_kuser_shared_data();
        linuwux_set_hwprofile_guid();
        ctx->uc_mcontext.gregs[REG_RAX] = 0x0;
        ctx->uc_mcontext.gregs[REG_RBX] = 0x0;
        ctx->uc_mcontext.gregs[REG_RCX] = 0x0;
        ctx->uc_mcontext.gregs[REG_RDX] = 0x0;
        break;

    case LINUWUX_CPUID_LEAF_FAKETIME:
        linuwux_set_faketime((long long)ctx->uc_mcontext.gregs[REG_RCX]);
        ctx->uc_mcontext.gregs[REG_RAX] = 0x0;
        ctx->uc_mcontext.gregs[REG_RBX] = 0x0;
        ctx->uc_mcontext.gregs[REG_RCX] = 0x0;
        ctx->uc_mcontext.gregs[REG_RDX] = 0x0;
        break;

    default:
        /* Pass through real CPUID while faulting is briefly disabled. */
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

/* --- SIGSYS redirect --- */

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

static void linuwux_rearm_sud(void)
{
    ptrdiff_t teb_offset = atomic_load(&g_sud_teb_offset);
    if (teb_offset < 0)
        return;
    unsigned char *teb = (unsigned char *)linuwux_get_teb();
    teb[teb_offset] = 1;  /* BLOCK */
}

/* Redirect blocked syscalls into TargetSysHandler after arm. Returns 1 if handled. */
static int linuwux_sigsys_route(ucontext_t *ctx)
{
    __uint128_t *xmm_regs;
    unsigned long long syscall_nr, rip, resume, target_sys_handler;
    unsigned char *fault_ip, opcode0, opcode1;

    if (!ctx->uc_mcontext.fpregs)
        return 0;
    xmm_regs = (__uint128_t *)ctx->uc_mcontext.fpregs->_xmm;

    target_sys_handler = atomic_load(&g_target_sys_handler);
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

/*
 * Resolve a symbol from ntdll.so (not visible via RTLD_DEFAULT).
 * Path comes from /proc/self/maps + RTLD_NOLOAD.
 * May run under SIGSEGV (arm -> hwprofile); fopen/dlopen are not AS-safe.
 * Late callers do not wait on a stuck resolver — return NULL instead.
 */
enum { LINUWUX_NTDLL_NOT_STARTED = 0, LINUWUX_NTDLL_IN_PROGRESS = 1, LINUWUX_NTDLL_DONE = 2 };

static void *linuwux_find_ntdll_symbol(const char *name)
{
    static _Atomic(void *) ntdll_handle;
    static _Atomic int state;
    int expected_state = LINUWUX_NTDLL_NOT_STARTED;
    void *handle;

    if (atomic_compare_exchange_strong(&state, &expected_state, LINUWUX_NTDLL_IN_PROGRESS))
    {
        FILE *f;
        char line[4096], path[4096];

        handle = NULL;
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

                /* Pathname is field 6; may contain spaces. */
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
            handle = dlopen(path, RTLD_NOW | RTLD_NOLOAD);
            linuwux_log("linuwux_find_ntdll_symbol: ntdll.so at %s -> handle=%p\n", path, handle);
        }
        else
            linuwux_log("linuwux_find_ntdll_symbol: could not find ntdll.so in /proc/self/maps\n");

        atomic_store_explicit(&ntdll_handle, handle, memory_order_release);
        atomic_store_explicit(&state, LINUWUX_NTDLL_DONE, memory_order_release);
    }

    handle = atomic_load_explicit(&ntdll_handle, memory_order_acquire);
    return handle ? dlsym(handle, name) : NULL;
}

/* --- HwProfileGuid via NT registry API --- */

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

/* Write Hardware Profiles\\0001\\HwProfileGuid once (arm leaf). */
static void linuwux_set_hwprofile_guid(void)
{
    static _Atomic int done;
    int expected_done = 0;
    nt_create_key_fn nt_create_key;
    nt_set_value_key_fn nt_set_value_key;
    nt_close_fn nt_close;
    struct linuwux_unicode_string value_name;
    struct linuwux_object_attributes attr;
    void *cur, *next;
    uint16_t value_name_buf[16];
    uint16_t data_buf[48];
    size_t i;
    static const char *const path_components[] = {
        "\\Registry", "Machine", "System", "CurrentControlSet",
        "Control", "IDConfigDB", "Hardware Profiles", "0001"
    };
    static const char value_name_str[] = "HwProfileGuid";
    static const char data_str[] = "{12345678-1234-1234-1234-123456789012}";

    _Static_assert(sizeof(value_name_str) <= sizeof(value_name_buf) / sizeof(value_name_buf[0]),
                   "value_name_buf too small for value_name_str");
    _Static_assert(sizeof(data_str) <= sizeof(data_buf) / sizeof(data_buf[0]),
                   "data_buf too small for data_str");

    if (!atomic_compare_exchange_strong(&done, &expected_done, 1))
        return;

    nt_create_key = (nt_create_key_fn)linuwux_find_ntdll_symbol("NtCreateKey");
    nt_set_value_key = (nt_set_value_key_fn)linuwux_find_ntdll_symbol("NtSetValueKey");
    nt_close = (nt_close_fn)linuwux_find_ntdll_symbol("NtClose");
    if (!nt_create_key || !nt_set_value_key || !nt_close)
    {
        linuwux_log("hwprofile_guid: could not resolve NtCreateKey/NtSetValueKey/NtClose -- skipping\n");
        return;
    }

    /* NtCreateKey only creates the last component — walk path level by level. */
    cur = NULL;
    for (i = 0; i < sizeof(path_components) / sizeof(path_components[0]); i++)
    {
        const char *comp = path_components[i];
        size_t comp_len = strlen(comp);
        uint16_t comp_buf[32];
        struct linuwux_unicode_string comp_name;

        if (comp_len + 1 > sizeof(comp_buf) / sizeof(comp_buf[0]))
        {
            linuwux_log("hwprofile_guid: path component \"%s\" too long for comp_buf -- skipping\n", comp);
            if (cur)
                nt_close(cur);
            return;
        }
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

/* --- Faketime (REALTIME clocks only) --- */

#define LINUWUX_TICKS_PER_SEC      10000000LL
#define LINUWUX_TICKS_1601_TO_1970 116444736000000000LL

/* FILETIME-style: 100ns ticks since 1601-01-01. */
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

/* offset = ((now >> 32) - requested) << 32; uses real_clock_gettime to avoid recursion. */
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

/* --- Signal / prctl interpose --- */

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

int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
{
    if (!real_sigaction)
        real_sigaction = (sigaction_fn)dlsym(RTLD_NEXT, "sigaction");

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
        ptrdiff_t teb_offset = selector_addr - teb;
        atomic_store(&g_sud_teb_offset, teb_offset);
        linuwux_log("learned SUD selector: teb-offset=%#tx (teb=%p selector=%p)\n",
                    teb_offset, (void *)teb, (void *)selector_addr);
    }
    return (int)ret;
}

static void linuwux_append_override(char *buf, size_t bufsize, const char *entry)
{
    size_t len = strlen(buf);
    int n;

    if (len >= bufsize)
        return;

    n = snprintf(buf + len, bufsize - len, "%s%s", len ? ";" : "", entry);
    if (n < 0 || len + (size_t)n >= bufsize)
        linuwux_log("WINEDLLOVERRIDES: not enough room to append \"%s\" -- skipping\n", entry);
}

__attribute__((constructor))
static void linuwux_init(void)
{
    char overrides[4096];
    const char *existing;
    int n;

    linuwux_detect_cpu_vendor();

    /* Append our DLL overrides without clobbering user-set keys. */
    existing = getenv("WINEDLLOVERRIDES");
    n = snprintf(overrides, sizeof(overrides), "%s", existing ? existing : "");
    if (existing && (n < 0 || (size_t)n >= sizeof(overrides)))
        linuwux_log("WINEDLLOVERRIDES: existing value (%zu bytes) doesn't fit our %zu-byte buffer -- truncated\n",
                     strlen(existing), sizeof(overrides));

    if (!existing || !strstr(existing, "winmm="))
        linuwux_append_override(overrides, sizeof(overrides), "winmm=n,b");
    if (!existing || !strstr(existing, "version="))
        linuwux_append_override(overrides, sizeof(overrides), "version=n,b");
    if (!existing || !strstr(existing, "reflex="))
        linuwux_append_override(overrides, sizeof(overrides), "reflex=n,b");

    setenv("WINEDLLOVERRIDES", overrides, 1);
    linuwux_log("WINEDLLOVERRIDES=\"%s\"\n", overrides);

    /* Default on for DenuvOwO; user can set 0. Overlay does not need lsteamclient. */
    setenv("PROTON_DISABLE_LSTEAMCLIENT", "1", 0);

    /* Always print version (not only under LINUWUX_DEBUG) for bug reports. */
    fprintf(stderr, "[linuwux] v%s loaded (pid=%d)\n", LINUWUX_VERSION, getpid());
}
