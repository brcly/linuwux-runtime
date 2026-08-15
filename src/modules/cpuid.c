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

enum linuwux_protocol {
    LINUWUX_PROTO_NONE = 0,
    LINUWUX_PROTO_MODERN = 1,
    LINUWUX_PROTO_LEGACY_SINGLE = 2,
    LINUWUX_PROTO_LEGACY_DUAL = 3,
};

/*
 * Single protocol control block. All CPUID arm/query leaves and SIGSYS
 * routing read/write here instead of scattered atomics.
 */
struct linuwux_protocol_state {
    _Atomic int protocol;
    _Atomic int rax_is_resume;      /* 1 modern trampoline; 0 legacy keep RCX */
    _Atomic uint64_t handler;       /* modern TargetSysHandler or legacy single */
    _Atomic uint64_t full_handler;  /* legacy dual only */
    _Atomic uint32_t system_id;     /* legacy dual syscall id -> single handler */
    _Atomic uint32_t full_id;       /* legacy dual syscall id -> full handler */
};

static struct linuwux_protocol_state g_proto = {
    .protocol = LINUWUX_PROTO_NONE,
    .rax_is_resume = 1,
    .handler = 0,
    .full_handler = 0,
    .system_id = 0xffffffffu,
    .full_id = 0xffffffffu,
};

void linuwux_cpuid_hint_denuvowo(void)
{
    if (atomic_load(&g_proto.protocol) != LINUWUX_PROTO_NONE)
        return;

    /* DenuvOwO's 0x69696969 leaf is a target marker; its actual
     * 0x336933 handshake uses the modern SimpleSvm trampoline. */
    atomic_store(&g_proto.protocol, LINUWUX_PROTO_MODERN);
    linuwux_log("selected DenuvOwO SimpleSvm identity from marker\n");
}

/* Spoofed CPUID identity, filled once in the constructor. */
struct linuwux_cpuid_regs {
    unsigned int eax, ebx, ecx, edx;
};

static struct linuwux_cpuid_regs g_spoof_leaf1;              /* standard feature leaf */
static struct linuwux_cpuid_regs g_spoof_hypervisor_info;    /* 0x40000000 max leaf + vendor */
static struct linuwux_cpuid_regs g_spoof_hypervisor_feat;    /* 0x40000001 features */

/* CPUID leaf 0 vendor string chunks (EBX/EDX/ECX order). */
#define CPUID_VENDOR_INTEL_EBX  0x756E6547u  /* "Genu" */
#define CPUID_VENDOR_INTEL_EDX  0x49656E69u  /* "ineI" */
#define CPUID_VENDOR_INTEL_ECX  0x6C65746Eu  /* "ntel" */
#define CPUID_VENDOR_AMD_EBX    0x68747541u  /* "Auth" */
#define CPUID_VENDOR_AMD_EDX    0x69746E65u  /* "enti" */
#define CPUID_VENDOR_AMD_ECX    0x444D4163u  /* "cAMD" */

/* Leaf 1 feature ECX masks — with / without AVX exposure. */
#define CPUID_LEAF1_ECX_INTEL_AVX     0x7BFAFBFFu
#define CPUID_LEAF1_ECX_INTEL_NO_AVX  0x01FAEBFFu
#define CPUID_LEAF1_ECX_AMD_AVX       0x7AD8320Bu
#define CPUID_LEAF1_ECX_AMD_NO_AVX    0x00F8220Bu

uint64_t linuwux_cpuid_target_sys_handler(void)
{
    return atomic_load(&g_proto.handler);
}

static int linuwux_protocol_is_legacy(int protocol)
{
    return protocol == LINUWUX_PROTO_LEGACY_SINGLE ||
           protocol == LINUWUX_PROTO_LEGACY_DUAL;
}

int linuwux_cpuid_legacy_active(void)
{
    return linuwux_protocol_is_legacy(atomic_load(&g_proto.protocol));
}

/* Pick TargetSys / legacy handler for this SIGSYS; 0 = not ours. */
static uint64_t linuwux_proto_pick_handler(ucontext_t *ctx)
{
    int protocol = atomic_load(&g_proto.protocol);
    uint64_t handler, full_handler, rax, rcx;
    uint32_t system_id, full_id;

    if (protocol == LINUWUX_PROTO_MODERN)
        return atomic_load(&g_proto.handler);

    if (!ctx)
        return 0;

    handler = atomic_load(&g_proto.handler);
    rax = (uint64_t)ctx->uc_mcontext.gregs[REG_RAX];
    rcx = (uint64_t)ctx->uc_mcontext.gregs[REG_RCX];

    if (protocol == LINUWUX_PROTO_LEGACY_SINGLE) {
        if (!handler || (rax != 0x13371337u && rax != 0x13371338u) ||
            rcx > 0x7fffffffffffULL)
            return 0;
        return handler;
    }

    if (protocol == LINUWUX_PROTO_LEGACY_DUAL) {
        system_id = atomic_load(&g_proto.system_id);
        full_handler = atomic_load(&g_proto.full_handler);
        full_id = atomic_load(&g_proto.full_id);

        if (handler && system_id != 0xffffffffu &&
            (uint32_t)rax == system_id && rcx <= 0x7fffffffffffULL &&
            ctx->uc_mcontext.gregs[REG_R10] == 0)
            return handler;

        if (full_handler && full_id != 0xffffffffu &&
            (uint32_t)rax == full_id && rcx <= 0x7fffffffffffULL)
            return full_handler;
    }

    return 0;
}

int linuwux_cpuid_syscall_route(ucontext_t *ctx, struct linuwux_syscall_route *out)
{
    uint64_t handler;

    if (!out)
        return 0;

    handler = linuwux_proto_pick_handler(ctx);
    if (!handler)
        return 0;

    out->handler = handler;
    out->rax_is_resume = atomic_load(&g_proto.rax_is_resume);
    return 1;
}

void linuwux_detect_cpu_vendor(void)
{
    unsigned int eax, ebx, ecx, edx;
    int want_avx = (getenv("PROTON_AVX") != NULL && strcmp(getenv("PROTON_AVX"), "1") == 0);

    __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(0) : "memory");

    if (ebx == CPUID_VENDOR_INTEL_EBX &&
        edx == CPUID_VENDOR_INTEL_EDX &&
        ecx == CPUID_VENDOR_INTEL_ECX) {
        /* GenuineIntel */
        g_spoof_leaf1.eax = 0x000A0655;
        g_spoof_leaf1.ebx = 0x00200800;
        g_spoof_leaf1.ecx = want_avx ? CPUID_LEAF1_ECX_INTEL_AVX : CPUID_LEAF1_ECX_INTEL_NO_AVX;
        g_spoof_leaf1.edx = 0xBFEBFBFF;

        g_spoof_hypervisor_info.eax = 0x40000001;
        g_spoof_hypervisor_info.ebx = 0x65707948; /* "Hype" */
        g_spoof_hypervisor_info.ecx = 0x67624472; /* "rdBg" */
        g_spoof_hypervisor_info.edx = 0;

        g_spoof_hypervisor_feat.eax = 0x30237648;
        g_spoof_hypervisor_feat.ebx = 0;
        g_spoof_hypervisor_feat.ecx = 0;
        g_spoof_hypervisor_feat.edx = 0;

        linuwux_log("detect_cpu_vendor: Intel (avx=%d)\n", want_avx);
    } else if (ebx == CPUID_VENDOR_AMD_EBX &&
               edx == CPUID_VENDOR_AMD_EDX &&
               ecx == CPUID_VENDOR_AMD_ECX) {
        /* AuthenticAMD */
        g_spoof_leaf1.eax = 0x00A20F12;
        g_spoof_leaf1.ebx = 0x00100800;
        g_spoof_leaf1.ecx = want_avx ? CPUID_LEAF1_ECX_AMD_AVX : CPUID_LEAF1_ECX_AMD_NO_AVX;
        g_spoof_leaf1.edx = 0x178BFBFF;

        g_spoof_hypervisor_info.eax = 0x40000001;
        g_spoof_hypervisor_info.ebx = 0x706D6953; /* "Simp" */
        g_spoof_hypervisor_info.ecx = 0x7653656C; /* "leSv" */
        g_spoof_hypervisor_info.edx = 0x2020206D; /* "m   " */

        g_spoof_hypervisor_feat.eax = 0x30237648;
        g_spoof_hypervisor_feat.ebx = 0;
        g_spoof_hypervisor_feat.ecx = 0;
        g_spoof_hypervisor_feat.edx = 0;

        linuwux_log("detect_cpu_vendor: AMD (avx=%d)\n", want_avx);
    } else {
        linuwux_log("detect_cpu_vendor: unknown vendor ebx=%08x edx=%08x ecx=%08x\n", ebx, edx, ecx);
    }
}

#define LINUWUX_KUSER_SHARED_DATA_ADDR 0x000000007FFE0000UL

/*
 * Table-driven KUSER profiles.
 *
 * Modern and legacy single/dual all share one apply path: mprotect
 * once, run ops in order, done. Adding a protocol is a new table + profile
 * pointer, not a second hand-written store list.
 */
enum {
    LINUWUX_KUSER_STORE = 0, /* write value of size 1/4/8 at off */
    LINUWUX_KUSER_ZERO  = 1, /* memset length bytes at off */
};

struct linuwux_kuser_op {
    uint16_t off;
    uint8_t kind;
    uint8_t size;     /* STORE: 1, 4, or 8 */
    uint32_t length;  /* ZERO: byte count */
    uint64_t value;   /* STORE: value (host endian) */
};

struct linuwux_kuser_profile {
    const char *name;
    const struct linuwux_kuser_op *ops;
    size_t op_count;
    int write_nt_system_root; /* NtSystemRoot WCHAR[] at 0x30 */
    int clear_avx_unless_proton_avx;
};

/*
 * Named KUSER_SHARED_DATA field offsets (user-mode view at 0x7FFE0000).
 * Values match public ntddk / ReactOS layouts for the fields we touch.
 * Multi-byte stores that intentionally span adjacent fields keep the
 * start-offset name; comments note the span.
 */
#define KUSER_NtBuildNumber               0x260
#define KUSER_NtProductType               0x264
#define KUSER_ProductTypeIsValid          0x268
#define KUSER_NativeProcessorArchitecture 0x26A
#define KUSER_NtMajorVersion              0x26C
#define KUSER_NtMinorVersion              0x270
#define KUSER_ProcessorFeatures           0x274  /* BOOLEAN[64] */
#define KUSER_SuiteMask                   0x2D0  /* + KdDebuggerEnabled @ +4 */
#define KUSER_KdDebuggerEnabled           0x2D4
#define KUSER_NumberOfPhysicalPages       0x2E8
#define KUSER_SafeBootMode                0x2EC
#define KUSER_SharedDataFlags             0x2F0
#define KUSER_QpcInterruptTimeSpan        0x36C  /* QPC increment fields */
#define KUSER_ActiveProcessorCount        0x3C0
#define KUSER_TimeZoneBiasEffectiveStart  0x3C8
#define KUSER_TimeZoneBiasEffectiveEnd    0x3D0
#define KUSER_XState                      0x3D8  /* XSTATE_CONFIGURATION region */
#define KUSER_FeatureConfig               0x5F0
#define KUSER_UserSharedDataPadding       0x808
#define KUSER_CookieMagic                 0xFFC  /* protocol magic 0x13371337 */

/* ProcessorFeatures[] indices we clear (offset = base + index). */
#define KUSER_PF_XSAVE                   (KUSER_ProcessorFeatures + 17)  /* 0x285 */
#define KUSER_PF_MONITORX                (KUSER_ProcessorFeatures + 28)  /* 0x290 */
#define KUSER_PF_RDTSCP                  (KUSER_ProcessorFeatures + 32)  /* 0x294 */
#define KUSER_PF_RDPID                   (KUSER_ProcessorFeatures + 33)  /* 0x295 */
#define KUSER_PF_RDRAND                  (KUSER_ProcessorFeatures + 35)  /* 0x297 */
#define KUSER_PF_AVX                     (KUSER_ProcessorFeatures + 39)  /* 0x29B */
#define KUSER_PF_AVX2                    (KUSER_ProcessorFeatures + 40)  /* 0x29C */

#define KUSER_STORE1(off, val) { (uint16_t)(off), LINUWUX_KUSER_STORE, 1, 0, (uint64_t)(val) }
#define KUSER_STORE4(off, val) { (uint16_t)(off), LINUWUX_KUSER_STORE, 4, 0, (uint64_t)(val) }
#define KUSER_STORE8(off, val) { (uint16_t)(off), LINUWUX_KUSER_STORE, 8, 0, (uint64_t)(val) }
#define KUSER_ZERO(off, len)   { (uint16_t)(off), LINUWUX_KUSER_ZERO,  0, (uint32_t)(len), 0 }

/*
 * Modern profile write values. Protocol-facing constants are named;
 * ProcessorFeatures bulk is the known working pattern (then PF_* clears).
 */
#define KUSER_VAL_NT_BUILD_PRODUCT     0x0100006658ULL   /* NtBuildNumber + product bytes */
#define KUSER_VAL_PRODUCT_TYPE_VALID   0x090001ULL
#define KUSER_VAL_NT_MAJOR_WIN10       0x0AULL           /* Windows 10/11 */
#define KUSER_VAL_NT_MINOR_WIN10       0x00ULL
#define KUSER_VAL_SUITE_KD_BLOB        0x320A0000000110ULL /* SuiteMask + KdDebugger lane */
#define KUSER_VAL_PHYS_PAGES_BLOB      0x0100007FB10BULL
#define KUSER_VAL_ACTIVE_PROC_BLOB     0x83000100000010ULL
#define KUSER_VAL_COOKIE_MAGIC         0x13371337ULL     /* DenuvOwO cookie */

/* Current modern DenuvOwO / reflex.dll blob. Order matters where offsets overlap. */
static const struct linuwux_kuser_op kuser_ops_modern[] = {
    /* Version / product identity */
    KUSER_STORE8(KUSER_NtBuildNumber,       KUSER_VAL_NT_BUILD_PRODUCT),
    KUSER_STORE4(KUSER_ProductTypeIsValid,  KUSER_VAL_PRODUCT_TYPE_VALID),
    KUSER_STORE4(KUSER_NtMajorVersion,      KUSER_VAL_NT_MAJOR_WIN10),
    KUSER_STORE4(KUSER_NtMinorVersion,      KUSER_VAL_NT_MINOR_WIN10),

    /* ProcessorFeatures[64] — bulk then selective disables */
    KUSER_STORE4(KUSER_ProcessorFeatures + 0x00, 0x01010000ULL),
    KUSER_STORE4(KUSER_ProcessorFeatures + 0x04, 0x010000ULL),
    KUSER_STORE4(KUSER_ProcessorFeatures + 0x08, 0x010101ULL),
    KUSER_STORE4(KUSER_ProcessorFeatures + 0x0C, 0x010101ULL),
    KUSER_STORE4(KUSER_ProcessorFeatures + 0x10, 0x0100ULL),
    KUSER_STORE4(KUSER_ProcessorFeatures + 0x14, 0x01010101ULL),
    KUSER_STORE4(KUSER_ProcessorFeatures + 0x18, 0x0ULL),
    KUSER_STORE4(KUSER_ProcessorFeatures + 0x1C, 0x01ULL),
    KUSER_STORE4(KUSER_ProcessorFeatures + 0x20, 0x01000101ULL),
    KUSER_STORE4(KUSER_ProcessorFeatures + 0x24, 0x01010101ULL),
    KUSER_STORE4(KUSER_ProcessorFeatures + 0x28, 0x010001ULL),
    KUSER_STORE4(KUSER_ProcessorFeatures + 0x2C, 0x0ULL),
    KUSER_STORE4(KUSER_ProcessorFeatures + 0x30, 0x0ULL),
    KUSER_STORE4(KUSER_ProcessorFeatures + 0x34, 0x0ULL),
    KUSER_STORE4(KUSER_ProcessorFeatures + 0x38, 0x0ULL),
    KUSER_STORE4(KUSER_ProcessorFeatures + 0x3C, 0x1ULL),
    KUSER_STORE1(KUSER_PF_MONITORX, 0),
    KUSER_STORE1(KUSER_PF_RDTSCP, 0),
    KUSER_STORE1(KUSER_PF_RDPID, 0),
    KUSER_STORE1(KUSER_PF_RDRAND, 0),

    /* XSTATE / feature config / padding regions */
    KUSER_STORE8(KUSER_XState, 0),
    KUSER_STORE8(KUSER_XState + 8, 0),
    KUSER_STORE4(KUSER_XState + 0x14, 0),
    KUSER_ZERO  (KUSER_XState + 0x18, 0x200),
    KUSER_STORE8(KUSER_FeatureConfig, 0),
    KUSER_STORE8(KUSER_FeatureConfig + 8, 0),
    KUSER_ZERO  (KUSER_FeatureConfig + 0x14, 0x200),
    KUSER_STORE8(KUSER_UserSharedDataPadding, 0),
    KUSER_STORE8(KUSER_UserSharedDataPadding + 8, 0),

    /* Suite / debugger / phys pages / misc */
    KUSER_STORE8(KUSER_SuiteMask,             KUSER_VAL_SUITE_KD_BLOB),
    KUSER_STORE8(KUSER_NumberOfPhysicalPages, KUSER_VAL_PHYS_PAGES_BLOB),
    KUSER_STORE4(KUSER_SharedDataFlags + 4,   0),
    KUSER_STORE8(KUSER_QpcInterruptTimeSpan,  0),
    KUSER_STORE8(KUSER_QpcInterruptTimeSpan + 8, 0),
    KUSER_STORE4(KUSER_QpcInterruptTimeSpan + 0x10, 1),
    KUSER_STORE8(KUSER_ActiveProcessorCount,  KUSER_VAL_ACTIVE_PROC_BLOB),
    KUSER_STORE4(KUSER_CookieMagic,           KUSER_VAL_COOKIE_MAGIC),
};

static const struct linuwux_kuser_profile kuser_profile_modern = {
    .name = "modern",
    .ops = kuser_ops_modern,
    .op_count = sizeof(kuser_ops_modern) / sizeof(kuser_ops_modern[0]),
    .write_nt_system_root = 1,
    .clear_avx_unless_proton_avx = 1,
};

/* Legacy Reflex profiles; overlapping stores intentionally remain ordered. */
#define KUSER_CyclesPerYield             0x2D6
#define KUSER_TickCountLowPad            0x378  /* near TickCount region */

static const struct linuwux_kuser_op kuser_ops_legacy_single[] = {
    KUSER_STORE4(KUSER_CyclesPerYield, 0x00010034),
    KUSER_STORE4(KUSER_NumberOfPhysicalPages, 0x00BF9C8F),
    KUSER_STORE4(KUSER_ActiveProcessorCount, 0x00000010),
    KUSER_STORE4(KUSER_ProcessorFeatures + 0x14, 0x01010101),
    KUSER_STORE4(KUSER_ProductTypeIsValid, 0x00090001),
    KUSER_STORE4(KUSER_SharedDataFlags + 4, 0),
    KUSER_STORE4(KUSER_NtProductType, 0x1),
    KUSER_STORE4(KUSER_SuiteMask, 0x00000310),
    KUSER_STORE4(KUSER_NtBuildNumber, 0x00006658),
    KUSER_STORE4(KUSER_NtMajorVersion, 0x0A),
    KUSER_STORE4(KUSER_NtMinorVersion, 0),
};

static const struct linuwux_kuser_op kuser_ops_legacy_dual[] = {
    KUSER_STORE8(KUSER_NativeProcessorArchitecture + 4, 0), /* 0x26E span */
    KUSER_STORE8(KUSER_ProcessorFeatures + 0x0F, 0x0101010000010000ULL),
    KUSER_STORE8(KUSER_ProcessorFeatures + 0x14, 0x01010101ULL),
    KUSER_STORE8(KUSER_ProductTypeIsValid, 0x0A00090001ULL),
    KUSER_STORE8(KUSER_NtBuildNumber + 1, 0x0100000001000066ULL),
    KUSER_STORE8(KUSER_NtMinorVersion + 2, 0x010100000000ULL),
    KUSER_STORE4(KUSER_ActiveProcessorCount, 0x10),
    KUSER_STORE8(KUSER_NtBuildNumber, 0x0100006658ULL),
    KUSER_STORE8(KUSER_ProcessorFeatures + 0x0E, 0x0101000001000001ULL),
    KUSER_STORE4(KUSER_SuiteMask, 0x0110),
    KUSER_STORE4(KUSER_NumberOfPhysicalPages, 0x7FB10B),
    KUSER_STORE4(KUSER_TickCountLowPad, 0),
    KUSER_STORE8(KUSER_NumberOfPhysicalPages, 0x0100007FB10BULL),
    KUSER_STORE8(KUSER_ProcessorFeatures - 1, 0x0100000101000000ULL), /* 0x273 */
    KUSER_STORE8(KUSER_SuiteMask, KUSER_VAL_SUITE_KD_BLOB),
    KUSER_STORE8(0x000, 0x0FA0000000000000ULL), /* TickCountLowDeprecated area */
    KUSER_STORE8(KUSER_ProcessorFeatures + 0x0D, 0x0100000100000101ULL),
    KUSER_STORE8(KUSER_TickCountLowPad, 0x0100000000ULL),
    KUSER_STORE8(KUSER_ActiveProcessorCount, KUSER_VAL_ACTIVE_PROC_BLOB),
    KUSER_STORE8(KUSER_NtMajorVersion, 0x0A),
    KUSER_STORE4(KUSER_SharedDataFlags + 4, 0),
    KUSER_STORE4(KUSER_NtProductType, 0x1),
    KUSER_STORE4(KUSER_NtMinorVersion, 0),
};

static const struct linuwux_kuser_profile kuser_profile_legacy_single = {
    .name = "legacy-single",
    .ops = kuser_ops_legacy_single,
    .op_count = sizeof(kuser_ops_legacy_single) / sizeof(kuser_ops_legacy_single[0]),
};

static const struct linuwux_kuser_profile kuser_profile_legacy_dual = {
    .name = "legacy-dual",
    .ops = kuser_ops_legacy_dual,
    .op_count = sizeof(kuser_ops_legacy_dual) / sizeof(kuser_ops_legacy_dual[0]),
};

static const struct linuwux_kuser_profile *
linuwux_kuser_profile_for(int protocol)
{
    switch (protocol) {
    case LINUWUX_PROTO_MODERN:
        return &kuser_profile_modern;
    case LINUWUX_PROTO_LEGACY_DUAL:
        return &kuser_profile_legacy_dual;
    case LINUWUX_PROTO_LEGACY_SINGLE:
        return &kuser_profile_legacy_single;
    default:
        return NULL;
    }
}

static void linuwux_kuser_apply(const struct linuwux_kuser_profile *profile)
{
    uint8_t *kuser = (uint8_t *)LINUWUX_KUSER_SHARED_DATA_ADDR;
    long page_size_long = sysconf(_SC_PAGESIZE);
    size_t page_size, i;
    void *page_start;

    if (!profile || !profile->ops || profile->op_count == 0)
        return;

    if (page_size_long <= 0) {
        linuwux_log("kuser_shared_data: sysconf(_SC_PAGESIZE) failed\n");
        return;
    }
    page_size = (size_t)page_size_long;
    page_start = (void *)((uintptr_t)LINUWUX_KUSER_SHARED_DATA_ADDR & ~(page_size - 1));

    if (mprotect(page_start, page_size, PROT_READ | PROT_WRITE) == -1) {
        linuwux_log("kuser_shared_data: mprotect failed: %s\n", strerror(errno));
        return;
    }

    if (profile->write_nt_system_root) {
        static const unsigned short nt_system_root[] = {
            'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', 0
        };
        memcpy(kuser + 0x30, nt_system_root, sizeof(nt_system_root));
    }

    for (i = 0; i < profile->op_count; i++) {
        const struct linuwux_kuser_op *op = &profile->ops[i];

        if (op->kind == LINUWUX_KUSER_ZERO) {
            memset(kuser + op->off, 0, op->length);
            continue;
        }

        switch (op->size) {
        case 1:
            *(uint8_t *)(kuser + op->off) = (uint8_t)op->value;
            break;
        case 4:
            *(uint32_t *)(kuser + op->off) = (uint32_t)op->value;
            break;
        case 8:
            *(uint64_t *)(kuser + op->off) = op->value;
            break;
        default:
            break;
        }
    }

    if (profile->clear_avx_unless_proton_avx) {
        const char *avx = getenv("PROTON_AVX");
        if (avx == NULL || strcmp(avx, "1") != 0) {
            *(uint8_t *)(kuser + KUSER_PF_XSAVE) = 0;
            *(uint8_t *)(kuser + KUSER_PF_AVX) = 0;
            *(uint8_t *)(kuser + KUSER_PF_AVX2) = 0;
        }
    }

    linuwux_log("kuser_shared_data: patched (%s)\n", profile->name);
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

static void linuwux_cpuid_zero_regs(ucontext_t *ctx)
{
    ctx->uc_mcontext.gregs[REG_RAX] = 0;
    ctx->uc_mcontext.gregs[REG_RBX] = 0;
    ctx->uc_mcontext.gregs[REG_RCX] = 0;
    ctx->uc_mcontext.gregs[REG_RDX] = 0;
}

/*
 * Protocol leaves (DenuvOwO / legacy) vs static identity spoof leaves.
 *
 * Action leaves mutate runtime state (handler, KUSER, faketime). Static leaves
 * only fill EAX–EDX. Adding a protocol is a new action entry and profile.
 */
#define LINUWUX_CPUID_LEAF_ARM      0x336933u
#define LINUWUX_CPUID_LEAF_FAKETIME 0x336967u
#define LINUWUX_CPUID_LEAF_LEGACY_INIT 0x69696969u
#define LINUWUX_CPUID_LEAF_LEGACY_KUSER 0x1337u
#define LINUWUX_CPUID_LEAF_LEGACY_QUERY_SYSTEM_ID 0x336943u
#define LINUWUX_CPUID_LEAF_LEGACY_QUERY_FULL_HANDLER 0x336934u
#define LINUWUX_CPUID_LEAF_LEGACY_QUERY_FULL_ID 0x336944u

/* ---- action leaves ---- */

static int linuwux_cpuid_action_arm(unsigned int leaf, ucontext_t *ctx)
{
    uint64_t handler = (uint64_t)ctx->uc_mcontext.gregs[REG_RCX];
    int protocol = atomic_load(&g_proto.protocol);

    (void)leaf;

    atomic_store(&g_proto.handler, handler);

    if (linuwux_protocol_is_legacy(protocol)) {
        /* KUSER applied on LEGACY_KUSER leaf. */
        linuwux_log("cpuid arm leaf, protocol=legacy handler=%#llx\n",
                    (unsigned long long)handler);
        linuwux_set_hwprofile_guid();
        linuwux_cpuid_zero_regs(ctx);
        return 1;
    }

    atomic_store(&g_proto.protocol, LINUWUX_PROTO_MODERN);
    atomic_store(&g_proto.rax_is_resume, 1);
    linuwux_log("cpuid arm leaf, protocol=modern TargetSysHandler=%#llx\n",
                (unsigned long long)handler);
    linuwux_kuser_apply(linuwux_kuser_profile_for(LINUWUX_PROTO_MODERN));
    linuwux_set_hwprofile_guid();
    linuwux_cpuid_zero_regs(ctx);
    return 1;
}

static int linuwux_cpuid_action_faketime(unsigned int leaf, ucontext_t *ctx)
{
    (void)leaf;
    linuwux_set_faketime((long long)ctx->uc_mcontext.gregs[REG_RCX]);
    linuwux_cpuid_zero_regs(ctx);
    return 1;
}

static int linuwux_cpuid_action_legacy_init(unsigned int leaf, ucontext_t *ctx)
{
    int protocol = atomic_load(&g_proto.protocol);

    (void)leaf;

    if (protocol == LINUWUX_PROTO_MODERN)
        return 0;

    if (protocol == LINUWUX_PROTO_NONE) {
        atomic_store(&g_proto.protocol, LINUWUX_PROTO_LEGACY_SINGLE);
        atomic_store(&g_proto.rax_is_resume, 0);
    }
    linuwux_log("initialized legacy Reflex CPUID protocol\n");
    linuwux_cpuid_zero_regs(ctx);
    return 1;
}

static int linuwux_cpuid_action_legacy_kuser(unsigned int leaf, ucontext_t *ctx)
{
    int protocol = atomic_load(&g_proto.protocol);
    const struct linuwux_kuser_profile *profile;

    (void)leaf;

    if (!linuwux_protocol_is_legacy(protocol))
        return 0;

    profile = linuwux_kuser_profile_for(protocol);
    if (profile &&
        (protocol == LINUWUX_PROTO_LEGACY_DUAL || atomic_load(&g_proto.handler)))
        linuwux_kuser_apply(profile);
    else
        linuwux_log("legacy KUSER_SHARED_DATA leaf arrived before handler registration\n");
    linuwux_cpuid_zero_regs(ctx);
    return 1;
}

static int linuwux_cpuid_action_legacy_query(unsigned int leaf, ucontext_t *ctx)
{
    int protocol = atomic_load(&g_proto.protocol);

    if (!linuwux_protocol_is_legacy(protocol))
        return 0;

    atomic_store(&g_proto.protocol, LINUWUX_PROTO_LEGACY_DUAL);
    switch (leaf) {
    case LINUWUX_CPUID_LEAF_LEGACY_QUERY_SYSTEM_ID:
        atomic_store(&g_proto.system_id, (uint32_t)ctx->uc_mcontext.gregs[REG_RCX]);
        break;
    case LINUWUX_CPUID_LEAF_LEGACY_QUERY_FULL_HANDLER:
        atomic_store(&g_proto.full_handler, (uint64_t)ctx->uc_mcontext.gregs[REG_RCX]);
        break;
    case LINUWUX_CPUID_LEAF_LEGACY_QUERY_FULL_ID:
        atomic_store(&g_proto.full_id, (uint32_t)ctx->uc_mcontext.gregs[REG_RCX]);
        break;
    default:
        return 0;
    }
    linuwux_cpuid_zero_regs(ctx);
    return 1;
}

typedef int (*linuwux_cpuid_action_fn)(unsigned int leaf, ucontext_t *ctx);

struct linuwux_cpuid_action_leaf {
    unsigned int leaf;
    linuwux_cpuid_action_fn action;
};

static const struct linuwux_cpuid_action_leaf cpuid_action_leaves[] = {
    { LINUWUX_CPUID_LEAF_ARM,      linuwux_cpuid_action_arm },
    { LINUWUX_CPUID_LEAF_FAKETIME, linuwux_cpuid_action_faketime },
    { LINUWUX_CPUID_LEAF_LEGACY_INIT, linuwux_cpuid_action_legacy_init },
    { LINUWUX_CPUID_LEAF_LEGACY_KUSER, linuwux_cpuid_action_legacy_kuser },
    { LINUWUX_CPUID_LEAF_LEGACY_QUERY_SYSTEM_ID, linuwux_cpuid_action_legacy_query },
    { LINUWUX_CPUID_LEAF_LEGACY_QUERY_FULL_HANDLER, linuwux_cpuid_action_legacy_query },
    { LINUWUX_CPUID_LEAF_LEGACY_QUERY_FULL_ID, linuwux_cpuid_action_legacy_query },
};

/* ---- static identity spoof leaves ---- */

enum {
    LINUWUX_CPUID_STATIC_ECX_OR_UNARMED_BIT31 = 1 << 0, /* leaf 1: bit31 until armed */
};

enum linuwux_cpuid_static_profile {
    LINUWUX_CPUID_STATIC_ANY = 0,
    LINUWUX_CPUID_STATIC_MODERN,
    LINUWUX_CPUID_STATIC_LEGACY,
};

struct linuwux_cpuid_static_leaf {
    unsigned int leaf;
    int profile;
    unsigned int flags;
    /* Non-NULL => read live spoof regs from vendor detect; else use constants. */
    unsigned int *eax, *ebx, *ecx, *edx;
    unsigned int c_eax, c_ebx, c_ecx, c_edx;
};

static const struct linuwux_cpuid_static_leaf cpuid_static_leaves[] = {
    {
        .leaf = 1,
        .profile = LINUWUX_CPUID_STATIC_MODERN,
        .flags = LINUWUX_CPUID_STATIC_ECX_OR_UNARMED_BIT31,
        .eax = &g_spoof_leaf1.eax, .ebx = &g_spoof_leaf1.ebx,
        .ecx = &g_spoof_leaf1.ecx, .edx = &g_spoof_leaf1.edx,
    },
    {
        /* Shared across protocols — not identity-sensitive brand strings. */
        .leaf = 0x40000000,
        .profile = LINUWUX_CPUID_STATIC_ANY,
        .eax = &g_spoof_hypervisor_info.eax, .ebx = &g_spoof_hypervisor_info.ebx,
        .ecx = &g_spoof_hypervisor_info.ecx, .edx = &g_spoof_hypervisor_info.edx,
    },
    {
        .leaf = 0x40000001,
        .profile = LINUWUX_CPUID_STATIC_ANY,
        .eax = &g_spoof_hypervisor_feat.eax, .ebx = &g_spoof_hypervisor_feat.ebx,
        .ecx = &g_spoof_hypervisor_feat.ecx, .edx = &g_spoof_hypervisor_feat.edx,
    },
    /* Brand string: "DenuvoOwO CPU @ 1337GHz" style constants. */
    {
        .leaf = 0x80000002,
        .profile = LINUWUX_CPUID_STATIC_MODERN,
        .c_eax = 0x756E6544, .c_ebx = 0x4F774F76,
        .c_ecx = 0x55504320, .c_edx = 0x31204020,
    },
    {
        .leaf = 0x80000003,
        .profile = LINUWUX_CPUID_STATIC_MODERN,
        .c_eax = 0x20373333, .c_ebx = 0x007A4847,
        .c_ecx = 0x00000000, .c_edx = 0x00000000,
    },
    {
        .leaf = 0x80000004,
        .profile = LINUWUX_CPUID_STATIC_MODERN,
        .c_eax = 0, .c_ebx = 0, .c_ecx = 0, .c_edx = 0,
    },
    /* Legacy profile: AMD Ryzen 9 5900X 12-Core Processor. */
    {
        .leaf = 1,
        .profile = LINUWUX_CPUID_STATIC_LEGACY,
        .c_eax = 0x00A20F10, .c_ebx = 0x00180800,
        .c_ecx = 0x7AD8320B, .c_edx = 0x178BFBFF,
    },
    {
        .leaf = 0x80000002,
        .profile = LINUWUX_CPUID_STATIC_LEGACY,
        .c_eax = 0x20444D41, .c_ebx = 0x657A7952,
        .c_ecx = 0x2039206E, .c_edx = 0x30303935,
    },
    {
        .leaf = 0x80000003,
        .profile = LINUWUX_CPUID_STATIC_LEGACY,
        .c_eax = 0x32312058, .c_ebx = 0x726F432D,
        .c_ecx = 0x72502065, .c_edx = 0x7365636F,
    },
    {
        .leaf = 0x80000004,
        .profile = LINUWUX_CPUID_STATIC_LEGACY,
        .c_eax = 0x20726F73, .c_ebx = 0x20202020,
        .c_ecx = 0x20202020, .c_edx = 0x00202020,
    },
};

static int linuwux_cpuid_static_profile_matches(int profile)
{
    int protocol = atomic_load(&g_proto.protocol);

    if (profile == LINUWUX_CPUID_STATIC_ANY)
        return 1;
    if (profile == LINUWUX_CPUID_STATIC_LEGACY)
        return linuwux_protocol_is_legacy(protocol);
    return !linuwux_protocol_is_legacy(protocol);
}

static int linuwux_cpuid_dispatch_action(unsigned int leaf, ucontext_t *ctx)
{
    size_t i;

    for (i = 0; i < sizeof(cpuid_action_leaves) / sizeof(cpuid_action_leaves[0]); i++) {
        if (cpuid_action_leaves[i].leaf == leaf) {
            return cpuid_action_leaves[i].action(leaf, ctx);
        }
    }
    return 0;
}

static int linuwux_cpuid_dispatch_static(unsigned int leaf, ucontext_t *ctx)
{
    size_t i;

    for (i = 0; i < sizeof(cpuid_static_leaves) / sizeof(cpuid_static_leaves[0]); i++) {
        const struct linuwux_cpuid_static_leaf *s = &cpuid_static_leaves[i];
        unsigned int eax, ebx, ecx, edx;

        if (s->leaf != leaf)
            continue;
        if (!linuwux_cpuid_static_profile_matches(s->profile))
            continue;

        if (s->eax) {
            eax = *s->eax;
            ebx = *s->ebx;
            ecx = *s->ecx;
            edx = *s->edx;
        } else {
            eax = s->c_eax;
            ebx = s->c_ebx;
            ecx = s->c_ecx;
            edx = s->c_edx;
        }

        if (s->flags & LINUWUX_CPUID_STATIC_ECX_OR_UNARMED_BIT31) {
            if (!atomic_load(&g_proto.handler))
                ecx |= (1u << 31);
        }

        ctx->uc_mcontext.gregs[REG_RAX] = eax;
        ctx->uc_mcontext.gregs[REG_RBX] = ebx;
        ctx->uc_mcontext.gregs[REG_RCX] = ecx;
        ctx->uc_mcontext.gregs[REG_RDX] = edx;
        return 1;
    }
    return 0;
}

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

    if (!linuwux_redirect_all_enabled() &&
        linuwux_rip_is_wine_system((unsigned long long)(uintptr_t)rip)) {
        linuwux_cpuid_passthrough(ctx, spoof_leaf, spoof_subleaf);
        ctx->uc_mcontext.gregs[REG_RIP] += 2;
        return 1;
    }

    if (linuwux_cpuid_dispatch_action(spoof_leaf, ctx) ||
        linuwux_cpuid_dispatch_static(spoof_leaf, ctx)) {
        ctx->uc_mcontext.gregs[REG_RIP] += 2;
        return 1;
    }

    linuwux_cpuid_passthrough(ctx, spoof_leaf, spoof_subleaf);
    ctx->uc_mcontext.gregs[REG_RIP] += 2;
    return 1;
}
