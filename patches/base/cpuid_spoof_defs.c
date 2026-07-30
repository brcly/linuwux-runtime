// This will point to the games memory region where syscall spoofing is happening
uint64_t TargetSysHandler = 0;
uint64_t SyscallBypassMagic = 0x1337133713371337;

// Spoofed CPUID values - will be set based on CPU vendor
unsigned int spoof_leaf1_eax, spoof_leaf1_ebx, spoof_leaf1_ecx, spoof_leaf1_edx;
unsigned int spoof_leaf40000000_eax, spoof_leaf40000000_ebx, spoof_leaf40000000_ecx, spoof_leaf40000000_edx;
unsigned int spoof_leaf40000001_eax, spoof_leaf40000001_ebx, spoof_leaf40000001_ecx, spoof_leaf40000001_edx;

// Function to detect CPU vendor at startup
static void detect_cpu_vendor(void) {
    unsigned int eax, ebx, ecx, edx;
    int avx = 0;
    if (getenv("PROTON_AVX") != NULL && strcmp(getenv("PROTON_AVX"), "1") == 0) avx = 1;

    // Try to get CPUID(0) to detect vendor
    __asm__ volatile(
        "cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(0)
        : "memory"
    );

    // Check vendor string
    if (ebx == 0x756E6547 && edx == 0x49656E69 && ecx == 0x6C65746E) {
        // "GenuineIntel" - Intel CPU

        // Set Intel-specific spoofed values
        spoof_leaf1_eax = 0x000A0655;
        spoof_leaf1_ebx = 0x00200800;
        if (avx) {
            spoof_leaf1_ecx = 0x7BFAFBFF;
        } else spoof_leaf1_ecx = 0x01FAEBFF;
        spoof_leaf1_edx = 0xBFEBFBFF;

        spoof_leaf40000000_eax = 0x40000001;
        spoof_leaf40000000_ebx = 0x65707948; // 'epyH'
        spoof_leaf40000000_ecx = 0x67624472; // 'gbDr'
        spoof_leaf40000000_edx = 0;

        spoof_leaf40000001_eax = 0x30237648; // '0#vH'
        spoof_leaf40000001_ebx = 0;
        spoof_leaf40000001_ecx = 0;
        spoof_leaf40000001_edx = 0;

    } else if (ebx == 0x68747541 && edx == 0x69746E65 && ecx == 0x444D4163) {
        // "AuthenticAMD" - AMD CPU

        // Set AMD-specific spoofed values
        spoof_leaf1_eax = 0x00A20F12;
        spoof_leaf1_ebx = 0x00100800;
        if (avx) {
            spoof_leaf1_ecx = 0x7AD8320B;
        } else spoof_leaf1_ecx = 0x00F8220B;
        spoof_leaf1_edx = 0x178BFBFF;

        spoof_leaf40000000_eax = 0x40000001;
        spoof_leaf40000000_ebx = 0x706D6953; // 'pmiS'
        spoof_leaf40000000_ecx = 0x7653656C; // 'vSel'
        spoof_leaf40000000_edx = 0x2020206D; // '   m'

        spoof_leaf40000001_eax = 0x30237648; // '0#vH'
        spoof_leaf40000001_ebx = 0;
        spoof_leaf40000001_ecx = 0;
        spoof_leaf40000001_edx = 0;
    }
    // Sorry Zhaoxin/Hygon CPU owners :(
}
