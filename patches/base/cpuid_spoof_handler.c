    unsigned int leaf;
    unsigned int subleaf;
    ucontext_t *uc;
    unsigned char *rip;

    uc = (ucontext_t *)sigcontext;
    rip = (unsigned char *)uc->uc_mcontext.gregs[REG_RIP];
    leaf = ucontext->uc_mcontext.gregs[REG_RAX];
    subleaf = ucontext->uc_mcontext.gregs[REG_RCX];
    if ((siginfo->si_code == SI_KERNEL || leaf == 0x336933) && rip[0] == 0x0F && rip[1] == 0xA2) {
        // Spoof CPUID results based on leaf
        switch (leaf) {
            case 1:
                uc->uc_mcontext.gregs[REG_RAX] = spoof_leaf1_eax;
                uc->uc_mcontext.gregs[REG_RBX] = spoof_leaf1_ebx;
                uc->uc_mcontext.gregs[REG_RCX] = spoof_leaf1_ecx | (TargetSysHandler ? 0 : (0x1 << 31));
                uc->uc_mcontext.gregs[REG_RDX] = spoof_leaf1_edx;
                break;

            case 0x40000000:
                uc->uc_mcontext.gregs[REG_RAX] = spoof_leaf40000000_eax;
                uc->uc_mcontext.gregs[REG_RBX] = spoof_leaf40000000_ebx;
                uc->uc_mcontext.gregs[REG_RCX] = spoof_leaf40000000_ecx;
                uc->uc_mcontext.gregs[REG_RDX] = spoof_leaf40000000_edx;
                break;

            case 0x40000001:
                uc->uc_mcontext.gregs[REG_RAX] = spoof_leaf40000001_eax;
                uc->uc_mcontext.gregs[REG_RBX] = spoof_leaf40000001_ebx;
                uc->uc_mcontext.gregs[REG_RCX] = spoof_leaf40000001_ecx;
                uc->uc_mcontext.gregs[REG_RDX] = spoof_leaf40000001_edx;
                break;

            case 0x80000002:
                uc->uc_mcontext.gregs[REG_RAX] = 0x756E6544;
                uc->uc_mcontext.gregs[REG_RBX] = 0x4F774F76;
                uc->uc_mcontext.gregs[REG_RCX] = 0x55504320;
                uc->uc_mcontext.gregs[REG_RDX] = 0x31204020;
                break;

            case 0x80000003:
                uc->uc_mcontext.gregs[REG_RAX] = 0x20373333;
                uc->uc_mcontext.gregs[REG_RBX] = 0x007A4847;
                uc->uc_mcontext.gregs[REG_RCX] = 0x00000000;
                uc->uc_mcontext.gregs[REG_RDX] = 0x00000000;
                break;

            case 0x80000004:
                uc->uc_mcontext.gregs[REG_RAX] = 0x0;
                uc->uc_mcontext.gregs[REG_RBX] = 0x0;
                uc->uc_mcontext.gregs[REG_RCX] = 0x0;
                uc->uc_mcontext.gregs[REG_RDX] = 0x0;
                break;

            case 0x336933:
                MESSAGE("Spoofing CPUID leaf %x\n", leaf);
                TargetSysHandler = uc->uc_mcontext.gregs[REG_RCX];
                patch_kuser_shared_data();
                uc->uc_mcontext.gregs[REG_RAX] = 0x0;
                uc->uc_mcontext.gregs[REG_RBX] = 0x0;
                uc->uc_mcontext.gregs[REG_RCX] = 0x0;
                uc->uc_mcontext.gregs[REG_RDX] = 0x0;
                break;

            case 0x336967:
                MESSAGE("Setting Faketime to %llx... \n", uc->uc_mcontext.gregs[REG_RCX]);
                SERVER_START_REQ( set_faketime )
                {
                    req->faketime = uc->uc_mcontext.gregs[REG_RCX];
                    wine_server_call( req );
                }
                SERVER_END_REQ;
                uc->uc_mcontext.gregs[REG_RAX] = 0x0;
                uc->uc_mcontext.gregs[REG_RBX] = 0x0;
                uc->uc_mcontext.gregs[REG_RCX] = 0x0;
                uc->uc_mcontext.gregs[REG_RDX] = 0x0;
                break;

            default:
                // Should implement caching for optimization
                // Disable CPUID faulting for real CPUID call
                syscall(SYS_arch_prctl, ARCH_SET_CPUID, 1);
                __asm__ volatile(
                        "cpuid"
                        : "=a"(uc->uc_mcontext.gregs[REG_RAX]),
                          "=b"(uc->uc_mcontext.gregs[REG_RBX]),
                          "=c"(uc->uc_mcontext.gregs[REG_RCX]),
                          "=d"(uc->uc_mcontext.gregs[REG_RDX])
                        : "a"(leaf), "c"(subleaf)
                        : "memory"
                    );
                // Enable CPUID faulting again
                syscall(SYS_arch_prctl, ARCH_SET_CPUID, 0);
        }

        // Skip the CPUID instruction (2 bytes: 0F A2)
        uc->uc_mcontext.gregs[REG_RIP] += 2;
        return;
    }
