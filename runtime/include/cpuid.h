#ifndef CPUID_H
#define CPUID_H
#include <signal.h>
#include <stdint.h>

struct cpuid_regs {
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
};

enum cpuid_vendor_profile {
    CPUID_VENDOR_UNKNOWN = 0,
    CPUID_VENDOR_INTEL = 1,
    CPUID_VENDOR_AMD = 2,
};

void cpuid_sigsegv_handler(int sig, siginfo_t *info, void *context);
void cpuid_configure_profile(enum cpuid_vendor_profile vendor, int avx_enabled);
void cpuid_activate_legacy_profile(void);
int cpuid_get_fixed_reply(uint32_t leaf, struct cpuid_regs *result);
void detect_cpu_vendor(void);

#endif
