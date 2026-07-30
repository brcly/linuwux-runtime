    detect_cpu_vendor();
    syscall(SYS_arch_prctl, ARCH_SET_CPUID, 0);
