    if (LegacyTargetInitialized) {
        uint64_t target = 0;
        uint32_t syscall_id = ctx->uc_mcontext.gregs[REG_RAX];

        if (syscall_id == LegacyQuerySystemInformationId &&
            ctx->uc_mcontext.gregs[REG_RCX] <= 0x7fffffffffffULL &&
            !ctx->uc_mcontext.gregs[REG_R10])
            target = LegacyQuerySystemInformationHandler;
        else if (syscall_id == LegacyQueryFullAttributesFileId &&
                 ctx->uc_mcontext.gregs[REG_RCX] <= 0x7fffffffffffULL)
            target = LegacyQueryFullAttributesFileHandler;

        if (target) {
            xmm_regs[4] = syscall_id;
            ctx->uc_mcontext.gregs[REG_RAX] = ctx->uc_mcontext.gregs[REG_RCX];
            ctx->uc_mcontext.gregs[REG_RCX] = target;
            ctx->uc_mcontext.gregs[REG_RIP] = target;
            return;
        }
    } else
