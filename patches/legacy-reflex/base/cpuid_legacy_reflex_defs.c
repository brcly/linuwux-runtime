/* Legacy Reflex registers two independent synthetic syscall targets. */
uint64_t LegacyQuerySystemInformationHandler = 0;
uint64_t LegacyQueryFullAttributesFileHandler = 0;
uint32_t LegacyQuerySystemInformationId = 0xffffffff;
uint32_t LegacyQueryFullAttributesFileId = 0xffffffff;
int LegacyTargetInitialized = 0;

/* Apply the legacy SimpleSvm KUSER_SHARED_DATA writes in their original order.
 * The overlapping unaligned stores are intentional. */
static void patch_legacy_kuser_shared_data(void) {
    UINT8 *kuser = (UINT8 *)0x000000007ffe0000UL;
    size_t size = sysconf(_SC_PAGESIZE);

    if (mprotect(kuser, size, PROT_READ | PROT_WRITE) == -1) {
        MESSAGE("Failed to make legacy KUSER_SHARED_DATA writable: %s\n", strerror(errno));
        return;
    }

    *(UINT64 *)(kuser + 0x26e) = 0;
    *(UINT64 *)(kuser + 0x283) = 0x0101010000010000ULL;
    *(UINT64 *)(kuser + 0x288) = 0x01010101ULL;
    *(UINT64 *)(kuser + 0x268) = 0x0a00090001ULL;
    *(UINT64 *)(kuser + 0x261) = 0x0100000001000066ULL;
    *(UINT64 *)(kuser + 0x272) = 0x010100000000ULL;
    *(UINT32 *)(kuser + 0x3c0) = 0x10;
    *(UINT64 *)(kuser + 0x260) = 0x0100006658ULL;
    *(UINT64 *)(kuser + 0x282) = 0x0101000001000001ULL;
    *(UINT32 *)(kuser + 0x2d0) = 0x0110;
    *(UINT32 *)(kuser + 0x2e8) = 0x7fb10b;
    *(UINT32 *)(kuser + 0x378) = 0;
    *(UINT64 *)(kuser + 0x2e8) = 0x0100007fb10bULL;
    *(UINT64 *)(kuser + 0x273) = 0x0100000101000000ULL;
    *(UINT64 *)(kuser + 0x2d0) = 0x320a0000000110ULL;
    *(UINT64 *)(kuser + 0x000) = 0x0fa0000000000000ULL;
    *(UINT64 *)(kuser + 0x281) = 0x0100000100000101ULL;
    *(UINT64 *)(kuser + 0x378) = 0x0100000000ULL;
    *(UINT64 *)(kuser + 0x3c0) = 0x83000100000010ULL;
    *(UINT64 *)(kuser + 0x26c) = 0x0a;
    *(UINT32 *)(kuser + 0x2f4) = 0;
    *(UINT32 *)(kuser + 0x264) = 1;
    *(UINT32 *)(kuser + 0x270) = 0;

    MESSAGE("Initialized legacy Reflex KUSER_SHARED_DATA profile.\n");
}
