    /* linuwux-sigsys-handler */
    ucontext_t *ctx = sigcontext;
    __uint128_t *xmm_regs = (__uint128_t *)ctx->uc_mcontext.fpregs->_xmm;
    if (TargetSysHandler != 0 && (xmm_regs[5] & 0xFFFFFFFFFFFFFFFF) != 0x1337133713371337) {
        xmm_regs[4] = ctx->uc_mcontext.gregs[REG_RAX] & 0xFFFFFFFF;
        ctx->uc_mcontext.gregs[REG_RAX] = ctx->uc_mcontext.gregs[REG_RCX];
        ctx->uc_mcontext.gregs[REG_RCX] = TargetSysHandler;
        ctx->uc_mcontext.gregs[REG_RIP] = TargetSysHandler;
        return;
    }
    if ((xmm_regs[5] & 0xFFFFFFFFFFFFFFFF) == 0x1337133713371337) {
        xmm_regs[5] = 0;
    }
