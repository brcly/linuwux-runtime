#ifndef REFLEX_H
#define REFLEX_H

#include <stdint.h>
#include <ucontext.h>

#define REFLEX_CPUID_REGISTER_TARGET UINT32_C(0x336933)
#define REFLEX_CPUID_SET_TIME UINT32_C(0x336967)
#define REFLEX_CPUID_LEGACY_QUERY_SYSTEM_ID UINT32_C(0x336943)
#define REFLEX_CPUID_LEGACY_QUERY_ATTRIBUTES_TARGET UINT32_C(0x336934)
#define REFLEX_CPUID_LEGACY_QUERY_ATTRIBUTES_ID UINT32_C(0x336944)
#define REFLEX_CPUID_LEGACY_INIT UINT32_C(0x69696969)
#define REFLEX_CPUID_KUSER_PROBE UINT32_C(0x1337)
#define REFLEX_SYSCALL_BYPASS_MAGIC UINT64_C(0x1337133713371337)

enum reflex_cpuid_action {
    REFLEX_CPUID_NATIVE = 0,
    REFLEX_CPUID_CONSUMED = 1,
};

enum reflex_cpuid_action reflex_handle_cpuid(uint32_t leaf, uint64_t argument);
int reflex_route_syscall(const ucontext_t *context, uint64_t *target);

#endif
