/**
 * Patch KUSER_SHARED_DATA with spoofed values.
 * Called from the special CPUID leaf 0x336933 path.
 */
static void patch_kuser_shared_data(void) {
    UINT8 *kuser = (UINT8 *)0x000000007FFE0000UL;

    // Make memory writable
    size_t page_size = sysconf(_SC_PAGESIZE);
    void *page_start = (void *)((uintptr_t)0x000000007FFE0000UL & ~(page_size - 1));

    if (mprotect(page_start, page_size, PROT_READ | PROT_WRITE) == -1) {
        MESSAGE("Failed to make kuser_shared_data writable: %s\n", strerror(errno));
        return;
    }

    /* NtSystemRoot – force a stable "C:\Windows" so games that fingerprint
       the system root always see the same value. */
    {
        static const WCHAR nt_system_root[] = L"C:\\Windows";
        memset(kuser + 0x30, 0, 0x104);                 /* clear whole buffer */
        memcpy(kuser + 0x30, nt_system_root, sizeof(nt_system_root));
    }

    *(UINT64*)(kuser + 0x260) = 0x0100006658;
    *(UINT32*)(kuser + 0x268) = 0x090001;
    *(UINT32*)(kuser + 0x26C) = 0x0A;
    *(UINT32*)(kuser + 0x270) = 0x00;

    // ProcessorFeatures
    *(UINT32*)(kuser + 0x274) = 0x01010000;
    *(UINT32*)(kuser + 0x278) = 0x010000;
    *(UINT32*)(kuser + 0x27C) = 0x010101;
    *(UINT32*)(kuser + 0x280) = 0x010101;
    *(UINT32*)(kuser + 0x284) = 0x0100;
    *(UINT32*)(kuser + 0x288) = 0x01010101;
    *(UINT32*)(kuser + 0x28C) = 0x0;
    *(UINT32*)(kuser + 0x290) = 0x01;
    *(UINT32*)(kuser + 0x294) = 0x01000101;
    *(UINT32*)(kuser + 0x298) = 0x01010101;
    *(UINT32*)(kuser + 0x29C) = 0x010001;
    *(UINT32*)(kuser + 0x2A0) = 0x0;
    *(UINT32*)(kuser + 0x2A4) = 0x0;
    *(UINT32*)(kuser + 0x2A8) = 0x0;
    *(UINT32*)(kuser + 0x2AC) = 0x0;
    *(UINT32*)(kuser + 0x2B0) = 0x1;

    // Disable specific features (byte-level patches)
    *(UINT8*)(kuser + 0x290) = 0x0;    // Disable MONITORX support
    *(UINT8*)(kuser + 0x294) = 0x0;    // Disable RDTSCP support
    *(UINT8*)(kuser + 0x295) = 0x0;    // Disable RDPID support
    *(UINT8*)(kuser + 0x297) = 0x0;    // Disable RDRAND support

    if (getenv("PROTON_AVX") == NULL || (getenv("PROTON_AVX") != NULL && strcmp(getenv("PROTON_AVX"), "1")) != 0){
        // XSAVE related stuff
        *(UINT8*)(kuser + 0x285) = 0x0;    // Disable XSAVE support
        *(UINT8*)(kuser + 0x29B) = 0x0;    // Disable AVX support
        *(UINT8*)(kuser + 0x29C) = 0x0;    // Disable AVX2 support
    }

    *(UINT64*)(kuser + 0x3D8) = 0x0;   // EnabledFeatures
    *(UINT64*)(kuser + 0x3E0) = 0x0;   // EnabledVolatileFeatures
    *(UINT32*)(kuser + 0x3EC) = 0x0;   // ControlFlags
    memset((void*)(kuser + 0x3F0), 0x00, 0x200);   // Features
    *(UINT64*)(kuser + 0x5F0) = 0x0;   // EnabledSupervisorFeatures
    *(UINT64*)(kuser + 0x5F8) = 0x0;   // AlignedFeatures
    memset((void*)(kuser + 0x604), 0x00, 0x200);   // AllFeatures
    *(UINT64*)(kuser + 0x808) = 0x0;   // EnabledUserVisibleSupervisorFeatures
    *(UINT64*)(kuser + 0x810) = 0x0;   // ExtendedFeatureDisableFeatures

    *(UINT64*)(kuser + 0x2D0) = 0x320A0000000110;
    *(UINT64*)(kuser + 0x2E8) = 0x0100007FB10B;
    *(UINT32*)(kuser + 0x2F4) = 0x0;
    *(UINT64*)(kuser + 0x36C) = 0x0;
    *(UINT64*)(kuser + 0x374) = 0x0;
    *(UINT32*)(kuser + 0x37C) = 0x1;
    *(UINT64*)(kuser + 0x3C0) = 0x83000100000010;

    *(UINT32*)(kuser + 0xFFC) = 0x13371337;

    // Patch usage of syscalls
    // 0 = syscalls take slow route, everything gets hooked
    // 1 = syscalls take fast route unless ntdll.dll gets modified (default)
    //user_shared_data[0x308] = 1;
}
