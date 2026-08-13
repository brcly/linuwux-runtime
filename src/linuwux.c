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
 * linuwux
 *
 * Installs LinUwUx's CPUID spoofing, SIGSYS/DenuvOwO redirect,
 * HwProfileGuid, DLL overrides, and faketime via LD_PRELOAD. Interposes
 * sigaction()/prctl() and clock_gettime()/gettimeofday().
 *
 * LINUWUX_DEBUG=1 enables event tracing.
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

/* Set via build.sh's -DLINUWUX_VERSION; "dev" for an ad hoc gcc build. */
#ifndef LINUWUX_VERSION
#define LINUWUX_VERSION "dev"
#endif

/* Unreferenced but kept live by __attribute__((used)) -- readable
 * without running anything: `strings liblinuwux.so | grep linuwux`,
 * or `linuwux --version` against an installed copy. */
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

/* TEB via the %gs self-pointer (Win64 NtTib.Self, offset 0x30). */
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

/* Defined below; called from the faketime CPUID leaf case. */
static void linuwux_set_faketime(long long faketime);

/* Defined below; called from the arm CPUID leaf case, not from
 * recvmsg() -- calling it there instead nests a second
 * wine_server_call() inside an unfinished one and corrupts
 * wineserver's protocol state. */
static void linuwux_set_hwprofile_guid(void);

/* DenuvOwO's custom CPUID leaves: not real Intel/AMD leaves, they're
 * how the hypervisor bypass signals arm/faketime requests through the
 * trapped CPUID instruction. */
#define LINUWUX_CPUID_LEAF_ARM      0x336933
#define LINUWUX_CPUID_LEAF_FAKETIME 0x336967

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
        ctx->uc_mcontext.gregs[REG_RAX] = g_spoof_leaf1_eax;
        ctx->uc_mcontext.gregs[REG_RBX] = g_spoof_leaf1_ebx;
        ctx->uc_mcontext.gregs[REG_RCX] = g_spoof_leaf1_ecx | (g_target_sys_handler ? 0 : (0x1 << 31));
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
        g_target_sys_handler = (uint64_t)ctx->uc_mcontext.gregs[REG_RCX];
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
/* Syscall User Dispatch: learn the selector from Wine's own prctl().  */
/* ------------------------------------------------------------------ */

static ptrdiff_t g_sud_teb_offset = -1;  /* -1 == not learned yet / no SUD on this tree */

static void linuwux_rearm_sud(void)
{
    if (g_sud_teb_offset < 0)
        return;
    unsigned char *teb = (unsigned char *)linuwux_get_teb();
    teb[g_sud_teb_offset] = 1;  /* SYSCALL_DISPATCH_FILTER_BLOCK */
}

/* ------------------------------------------------------------------ */
/* SIGSYS redirect: DenuvOwO's blocked-syscall handoff                 */
/* ------------------------------------------------------------------ */

static int linuwux_sigsys_route(ucontext_t *ctx)
{
    __uint128_t *xmm_regs = (__uint128_t *)ctx->uc_mcontext.fpregs->_xmm;
    unsigned long long syscall_nr, rip, resume;
    unsigned char *fault_ip, opcode0, opcode1;

    if (g_target_sys_handler == 0 ||
        (xmm_regs[5] & 0xFFFFFFFFFFFFFFFFULL) == 0x1337133713371337ULL)
        goto not_ours;

    syscall_nr = (unsigned long long)ctx->uc_mcontext.gregs[REG_RAX];
    rip = (unsigned long long)ctx->uc_mcontext.gregs[REG_RIP];

    if (!linuwux_redirect_all_enabled() && linuwux_rip_is_wine_system(rip))
        return 0;   /* not a fault we redirect; let Wine's real handler run */

    /* If the fault is on the `syscall` instruction itself (0f 05),
     * resume past it -- otherwise resume at the fault site unchanged. */
    fault_ip = (unsigned char *)(uintptr_t)rip;
    opcode0 = fault_ip[0];
    opcode1 = fault_ip[1];
    resume = (opcode0 == 0x0f && opcode1 == 0x05) ? rip + 2 : rip;

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

/* dlsym(RTLD_DEFAULT) can't see ntdll.so's exports (Wine loads it via
 * its own dlopen(), not RTLD_GLOBAL). Find its real path via
 * /proc/self/maps and dlopen(path, RTLD_NOLOAD) instead. */
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

                /* Skip 5 whitespace-delimited fields to reach the
                 * pathname -- it can contain spaces (e.g. "Proton
                 * 11.0"), so don't split on the last space. */
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

/* Matches winternl.h layout; ULONG is always 32-bit on Windows. */
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

/* Genuine ELF exports of ntdll.so; WINAPI/__stdcall is a no-op for GCC
 * on x86_64, so plain C function pointers work. */
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

/* Same key the old wine.inf content-insert set. Called from the
 * LINUWUX_CPUID_LEAF_ARM case (see forward declaration above). */
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
    static const char *const path_components[] = {
        "\\Registry", "Machine", "System", "CurrentControlSet",
        "Control", "IDConfigDB", "Hardware Profiles", "0001"
    };
    static const char value_name_str[] = "HwProfileGuid";
    static const char data_str[] = "{12345678-1234-1234-1234-123456789012}";

    /* Catch a too-small buffer at compile time if either string above
     * ever grows past what value_name_buf/data_buf can hold. */
    _Static_assert(sizeof(value_name_str) <= sizeof(value_name_buf) / sizeof(value_name_buf[0]),
                   "value_name_buf too small for value_name_str");
    _Static_assert(sizeof(data_str) <= sizeof(data_buf) / sizeof(data_buf[0]),
                   "data_buf too small for data_str");

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

    /* NtCreateKey only auto-creates the last path component, so walk
     * the path one level at a time, threading each handle in as the
     * next call's RootDirectory. */
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

/* ------------------------------------------------------------------ */
/* Faketime: client-side clock_gettime()/gettimeofday() interposition  */
/* ------------------------------------------------------------------ */

#define LINUWUX_TICKS_PER_SEC      10000000LL
#define LINUWUX_TICKS_1601_TO_1970 116444736000000000LL

/* Windows FILETIME ticks: 100ns since 1601-01-01. */
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

/* 0 is a valid offset, so track "is it set" separately from the value. */
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

/* offset = ((now_ticks >> 32) - requested) << 32. Uses
 * real_clock_gettime() directly, not clock_gettime(), to avoid
 * recursing into our own wrapper above. */
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
        /* No real handler -- restore default and re-raise. */
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

/* Not called from the constructor -- a stray CPUID before any SIGSEGV
 * handler exists would kill the process outright. Per-thread; only
 * the first thread to register SIGSEGV gets this. */
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

/* prctl() is declared variadic in glibc; match that to avoid a
 * conflicting-types error. */
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
        linuwux_log("learned SUD selector: teb-offset=%#tx (teb=%p selector=%p)\n",
                    g_sud_teb_offset, (void *)teb, (void *)selector_addr);
    }
    return (int)ret;
}

/* Safe append -- avoids strncat()'s hand-computed remaining-length
 * arithmetic, which silently no-ops near the buffer's end. */
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

    /* Append required overrides, skipping any the user already set --
     * duplicate keys are unspecified in Wine's own parser. */
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

    /* Bypasses Steam DRM/Steamworks checks some DenuvOwO packs trip on.
     * The Steam Overlay still works fine with LD_PRELOAD appended
     * correctly -- it doesn't go through lsteamclient. */
    setenv("PROTON_DISABLE_LSTEAMCLIENT", "1", 0);

    /* Not gated by LINUWUX_DEBUG -- always identify what's loaded and
     * which build, so it lands in whatever log gets pasted for a bug
     * report without needing LINUWUX_DEBUG set in advance. */
    fprintf(stderr, "[linuwux] v%s loaded (pid=%d)\n", LINUWUX_VERSION, getpid());
}
