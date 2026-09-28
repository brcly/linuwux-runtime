//! The magic CPUID leaf numbers and register values Reflex's control
//! protocol uses as commands rather than real CPUID leaves — see
//! `docs/protocol/game-quirks.md`'s "Reflex protocol" table for which
//! titles send which of these, in which order. [`state`](super::state)
//! interprets them; this file is just the constant vocabulary.
pub const ARM_TARGET_CR3: u32 = 0x6969_6969;
pub const REGISTER_RESUME_HANDLER: u32 = 0x0033_6933;
pub const SET_TIME: u32 = 0x0033_6967;
pub const REGISTER_SYSTEM_SYSCALL_ID: u32 = 0x0033_6943;
pub const REGISTER_ATTRIBUTES_HANDLER: u32 = 0x0033_6934;
pub const REGISTER_ATTRIBUTES_SYSCALL_ID: u32 = 0x0033_6944;
pub const CLIENT_SESSION_MARKER: u32 = 0x0069_3369;
pub const REGISTER_TARGET_PID: u32 = 0x1337;
pub const SYSCALL_BYPASS_MAGIC: u64 = 0x1337_1337_1337_1337;

pub(super) const SINGLE_DISPATCH_SELECTORS: [u64; 2] = [0x1337_1337, 0x1337_1338];
pub(super) const USER_RCX_MAX: u64 = 0x7fff_ffff_ffff;
pub(super) const DISPATCH_BYPASS_SYSCALL: u64 = 0x7fff_ffff_ffff;
