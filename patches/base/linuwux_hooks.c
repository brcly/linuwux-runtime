/* linuwux-hooks
 *
 * All LinUwUx unix-side helpers for ntdll. Copied next to signal_x86_64.c and
 * pulled in via #include so we stay in the same TU (REG_* macros, server
 * protocol, etc.) without dumping a large blob into the signal file itself.
 *
 * Enable tracing with LINUWUX_DEBUG=1.
 */
#ifndef LINUWUX_HOOKS_INCLUDED
#define LINUWUX_HOOKS_INCLUDED

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

    /* NtSystemRoot – stable "C:\Windows" (unsigned short, not WCHAR/L""). */
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

    if (TargetSysHandler != 0 &&
        (xmm_regs[5] & 0xFFFFFFFFFFFFFFFF) != 0x1337133713371337) {
        linuwux_log("sigsys redirect rax=%llx → TargetSysHandler=%p\n",
                    (unsigned long long)ctx->uc_mcontext.gregs[REG_RAX],
                    (void *)TargetSysHandler);
        xmm_regs[4] = ctx->uc_mcontext.gregs[REG_RAX] & 0xFFFFFFFF;
        ctx->uc_mcontext.gregs[REG_RAX] = ctx->uc_mcontext.gregs[REG_RCX];
        ctx->uc_mcontext.gregs[REG_RCX] = TargetSysHandler;
        ctx->uc_mcontext.gregs[REG_RIP] = TargetSysHandler;
        return 1;
    }

    if ((xmm_regs[5] & 0xFFFFFFFFFFFFFFFF) == 0x1337133713371337)
        xmm_regs[5] = 0;

    return 0;
}

#endif /* LINUWUX_HOOKS_INCLUDED */
