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
 * linuwux -- CPUID spoofing, KUSER_SHARED_DATA patch, and the
 * DenuvOwO arm/faketime handshake leaves.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "linuwux.h"
#include "cpuid.h"
#include "faketime.h"
#include "registry.h"

/* Set on arm leaf; read from all threads. */
static _Atomic uint64_t g_target_sys_handler = 0;

/* Filled once in the constructor before any other thread exists. */
static unsigned int g_spoof_leaf1_eax, g_spoof_leaf1_ebx, g_spoof_leaf1_ecx, g_spoof_leaf1_edx;
static unsigned int g_spoof_leaf40000000_eax, g_spoof_leaf40000000_ebx, g_spoof_leaf40000000_ecx, g_spoof_leaf40000000_edx;
static unsigned int g_spoof_leaf40000001_eax, g_spoof_leaf40000001_ebx, g_spoof_leaf40000001_ecx, g_spoof_leaf40000001_edx;

uint64_t linuwux_cpuid_target_sys_handler(void)
{
    return atomic_load(&g_target_sys_handler);
}

void linuwux_detect_cpu_vendor(void)
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

/* Real CPUID with faulting briefly disabled. */
static void linuwux_cpuid_passthrough(ucontext_t *ctx, unsigned int leaf, unsigned int subleaf)
{
    syscall(SYS_arch_prctl, ARCH_SET_CPUID, 1);
    __asm__ volatile(
        "cpuid"
        : "=a"(ctx->uc_mcontext.gregs[REG_RAX]),
          "=b"(ctx->uc_mcontext.gregs[REG_RBX]),
          "=c"(ctx->uc_mcontext.gregs[REG_RCX]),
          "=d"(ctx->uc_mcontext.gregs[REG_RDX])
        : "a"(leaf), "c"(subleaf)
        : "memory");
    syscall(SYS_arch_prctl, ARCH_SET_CPUID, 0);
}

/* DenuvOwO protocol leaves (not real CPUID leaves). */
#define LINUWUX_CPUID_LEAF_ARM      0x336933
#define LINUWUX_CPUID_LEAF_FAKETIME 0x336967

int linuwux_cpuid_spoof(siginfo_t *info, ucontext_t *ctx)
{
    unsigned int spoof_leaf, spoof_subleaf;
    unsigned char *rip = (unsigned char *)ctx->uc_mcontext.gregs[REG_RIP];

    spoof_leaf = (unsigned int)ctx->uc_mcontext.gregs[REG_RAX];
    spoof_subleaf = (unsigned int)ctx->uc_mcontext.gregs[REG_RCX];

    if (!(rip[0] == 0x0F && rip[1] == 0xA2))
        return 0;

    if (!info || info->si_code != SI_KERNEL)
        return 0;

    if (!linuwux_redirect_all_enabled() && linuwux_rip_is_wine_system((unsigned long long)(uintptr_t)rip)) {
        /* Wine system PE range — real CPUID, not spoof. */
        linuwux_cpuid_passthrough(ctx, spoof_leaf, spoof_subleaf);
        ctx->uc_mcontext.gregs[REG_RIP] += 2;
        return 1;
    }

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
        linuwux_cpuid_passthrough(ctx, spoof_leaf, spoof_subleaf);
    }

    ctx->uc_mcontext.gregs[REG_RIP] += 2;
    return 1;
}
