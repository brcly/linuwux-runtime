    /* linuwux-cpuid-handler */
    {
        unsigned int spoof_leaf;
        unsigned int spoof_subleaf;
        ucontext_t *spoof_uc;
        unsigned char *spoof_rip;

        spoof_uc = (ucontext_t *)sigcontext;
        spoof_rip = (unsigned char *)spoof_uc->uc_mcontext.gregs[REG_RIP];
        /* leaf/subleaf from the init_handler-initialized ucontext */
        spoof_leaf = ucontext->uc_mcontext.gregs[REG_RAX];
        spoof_subleaf = ucontext->uc_mcontext.gregs[REG_RCX];
        if ((siginfo->si_code == SI_KERNEL || spoof_leaf == 0x336933) && spoof_rip[0] == 0x0F && spoof_rip[1] == 0xA2) {
            // Spoof CPUID results based on leaf
            switch (spoof_leaf) {
                case 1:
                    if (LegacyTargetInitialized) {
                        spoof_uc->uc_mcontext.gregs[REG_RAX] = 0x00a20f10;
                        spoof_uc->uc_mcontext.gregs[REG_RBX] = 0x00180800;
                        spoof_uc->uc_mcontext.gregs[REG_RCX] = 0x7ad8320b;
                        spoof_uc->uc_mcontext.gregs[REG_RDX] = 0x178bfbff;
                    } else {
                        spoof_uc->uc_mcontext.gregs[REG_RAX] = spoof_leaf1_eax;
                        spoof_uc->uc_mcontext.gregs[REG_RBX] = spoof_leaf1_ebx;
                        spoof_uc->uc_mcontext.gregs[REG_RCX] = spoof_leaf1_ecx |
                                                            (TargetSysHandler ? 0 : (0x1 << 31));
                        spoof_uc->uc_mcontext.gregs[REG_RDX] = spoof_leaf1_edx;
                    }
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
                    if (LegacyTargetInitialized) {
                        spoof_uc->uc_mcontext.gregs[REG_RAX] = 0x20444d41;
                        spoof_uc->uc_mcontext.gregs[REG_RBX] = 0x657a7952;
                        spoof_uc->uc_mcontext.gregs[REG_RCX] = 0x2039206e;
                        spoof_uc->uc_mcontext.gregs[REG_RDX] = 0x30303935;
                    } else {
                        spoof_uc->uc_mcontext.gregs[REG_RAX] = 0x756E6544;
                        spoof_uc->uc_mcontext.gregs[REG_RBX] = 0x4F774F76;
                        spoof_uc->uc_mcontext.gregs[REG_RCX] = 0x55504320;
                        spoof_uc->uc_mcontext.gregs[REG_RDX] = 0x31204020;
                    }
                    break;

                case 0x80000003:
                    if (LegacyTargetInitialized) {
                        spoof_uc->uc_mcontext.gregs[REG_RAX] = 0x32312058;
                        spoof_uc->uc_mcontext.gregs[REG_RBX] = 0x726f432d;
                        spoof_uc->uc_mcontext.gregs[REG_RCX] = 0x72502065;
                        spoof_uc->uc_mcontext.gregs[REG_RDX] = 0x7365636f;
                    } else {
                        spoof_uc->uc_mcontext.gregs[REG_RAX] = 0x20373333;
                        spoof_uc->uc_mcontext.gregs[REG_RBX] = 0x007A4847;
                        spoof_uc->uc_mcontext.gregs[REG_RCX] = 0x00000000;
                        spoof_uc->uc_mcontext.gregs[REG_RDX] = 0x00000000;
                    }
                    break;

                case 0x80000004:
                    if (LegacyTargetInitialized) {
                        spoof_uc->uc_mcontext.gregs[REG_RAX] = 0x20726f73;
                        spoof_uc->uc_mcontext.gregs[REG_RBX] = 0x20202020;
                        spoof_uc->uc_mcontext.gregs[REG_RCX] = 0x20202020;
                        spoof_uc->uc_mcontext.gregs[REG_RDX] = 0x00202020;
                    } else {
                        spoof_uc->uc_mcontext.gregs[REG_RAX] = 0x0;
                        spoof_uc->uc_mcontext.gregs[REG_RBX] = 0x0;
                        spoof_uc->uc_mcontext.gregs[REG_RCX] = 0x0;
                        spoof_uc->uc_mcontext.gregs[REG_RDX] = 0x0;
                    }
                    break;

                case 0x69696969:
                    LegacyTargetInitialized = 1;
                    MESSAGE("Initialized legacy Reflex CPUID protocol.\n");
                    break;

                case 0x336933:
                    if (LegacyTargetInitialized) {
                        LegacyQuerySystemInformationHandler = spoof_uc->uc_mcontext.gregs[REG_RCX];
                        MESSAGE("Registered legacy QuerySystemInformation handler %p.\n",
                                (void *)LegacyQuerySystemInformationHandler);
                    } else {
                        MESSAGE("Spoofing CPUID leaf %x\n", spoof_leaf);
                        TargetSysHandler = spoof_uc->uc_mcontext.gregs[REG_RCX];
                        patch_kuser_shared_data();
                        spoof_uc->uc_mcontext.gregs[REG_RAX] = 0x0;
                        spoof_uc->uc_mcontext.gregs[REG_RBX] = 0x0;
                        spoof_uc->uc_mcontext.gregs[REG_RCX] = 0x0;
                        spoof_uc->uc_mcontext.gregs[REG_RDX] = 0x0;
                    }
                    break;

                case 0x336943:
                    LegacyQuerySystemInformationId = spoof_uc->uc_mcontext.gregs[REG_RCX];
                    MESSAGE("Registered legacy QuerySystemInformation syscall %#x.\n",
                            LegacyQuerySystemInformationId);
                    break;

                case 0x336934:
                    LegacyQueryFullAttributesFileHandler = spoof_uc->uc_mcontext.gregs[REG_RCX];
                    MESSAGE("Registered legacy QueryFullAttributesFile handler %p.\n",
                            (void *)LegacyQueryFullAttributesFileHandler);
                    break;

                case 0x336944:
                    LegacyQueryFullAttributesFileId = spoof_uc->uc_mcontext.gregs[REG_RCX];
                    MESSAGE("Registered legacy QueryFullAttributesFile syscall %#x.\n",
                            LegacyQueryFullAttributesFileId);
                    break;

                case 0x1337:
                    if (LegacyTargetInitialized) {
                        patch_legacy_kuser_shared_data();
                        break;
                    }
                    /* Modern Reflex also emits this leaf; use normal CPUID then. */
                    goto native_cpuid;

                case 0x336967:
                    MESSAGE("Setting Faketime to %llx... \n", spoof_uc->uc_mcontext.gregs[REG_RCX]);
                    SERVER_START_REQ( set_faketime )
                    {
                        req->faketime = spoof_uc->uc_mcontext.gregs[REG_RCX];
                        wine_server_call( req );
                    }
                    SERVER_END_REQ;
                    spoof_uc->uc_mcontext.gregs[REG_RAX] = 0x0;
                    spoof_uc->uc_mcontext.gregs[REG_RBX] = 0x0;
                    spoof_uc->uc_mcontext.gregs[REG_RCX] = 0x0;
                    spoof_uc->uc_mcontext.gregs[REG_RDX] = 0x0;
                    break;

                default:
                native_cpuid:
                    // Should implement caching for optimization
                    // Disable CPUID faulting for real CPUID call
                    syscall(SYS_arch_prctl, ARCH_SET_CPUID, 1);
                    __asm__ volatile(
                            "cpuid"
                            : "=a"(spoof_uc->uc_mcontext.gregs[REG_RAX]),
                              "=b"(spoof_uc->uc_mcontext.gregs[REG_RBX]),
                              "=c"(spoof_uc->uc_mcontext.gregs[REG_RCX]),
                              "=d"(spoof_uc->uc_mcontext.gregs[REG_RDX])
                            : "a"(spoof_leaf), "c"(spoof_subleaf)
                            : "memory"
                        );
                    // Enable CPUID faulting again
                    syscall(SYS_arch_prctl, ARCH_SET_CPUID, 0);
            }

            // Skip the CPUID instruction (2 bytes: 0F A2)
            spoof_uc->uc_mcontext.gregs[REG_RIP] += 2;
            return;
        }
    }
