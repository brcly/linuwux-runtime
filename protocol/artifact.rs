//! Experimental AMD Artifact registration, readiness and CPU presentation.
//!
//! Unlike the older Reflex ordering, PID registration precedes the syscall
//! handler, and a separate, one-shot CPUID acknowledges KUSER preparation.
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::cpuid::Registers;

pub const REGISTER_PROCESS: u32 = 0x1337;
pub const KUSER_READY: u32 = 0x1338;
pub const REGISTER_HANDLER: u32 = 0x336933;
pub const SYSCALL_BYPASS_MAGIC: u64 = 0x6969_6969_6969_6969;

/// Process-local registration and one-shot readiness. A failed preparation
/// stays retryable; concurrent polls never acknowledge a half-applied page.
pub struct AmdSession {
    pid: AtomicU64,
    readiness: AtomicU32,
}

impl Default for AmdSession {
    fn default() -> Self {
        Self::new()
    }
}

impl AmdSession {
    pub const fn new() -> Self {
        Self {
            pid: AtomicU64::new(0),
            readiness: AtomicU32::new(0),
        }
    }

    pub fn register(&self, pid: u64) {
        if pid != 0 {
            let _ = self
                .pid
                .compare_exchange(0, pid, Ordering::AcqRel, Ordering::Acquire);
        }
    }

    pub fn pid(&self) -> u64 {
        self.pid.load(Ordering::Acquire)
    }

    /// Returns true exactly once, and only after `prepare` succeeds.
    pub fn take_ready(&self, prepare: impl FnOnce() -> bool) -> bool {
        if self.pid() == 0
            || self
                .readiness
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return false;
        }
        let ready = prepare();
        self.readiness
            .store(if ready { 2 } else { 0 }, Ordering::Release);
        ready
    }
}

/// Target-process replies from the newer AMD SimpleSvm profile. `None`
/// explicitly means native pass-through, including the topology leaves.
/// The runtime adds the native APIC ID to leaf 1 EBX.
pub fn amd_reply(leaf: u32, subleaf: u32) -> Option<Registers> {
    let words = match (leaf, subleaf) {
        (REGISTER_PROCESS | KUSER_READY | REGISTER_HANDLER | 0xb | 0x8000_001e, _) => return None,
        (0, _) => [0x10, 0x6874_7541, 0x444d_4163, 0x6974_6e65],
        (1, _) => [0x00a2_0f12, 0x0010_0800, 0x7ef8_320b, 0x178b_fbff],
        (5, _) => [0x40, 0x40, 3, 0x11],
        (6, _) => [4, 0, 1, 0],
        (7, 0) => [0, 0x219c_97a9, 0x0040_068c, 0x10],
        (0xd, 0) => [0x207, 0x340, 0x988, 0],
        (0xd, 1) => [0xf, 0x350, 0x1800, 0],
        (0xd, 2) => [0x100, 0x240, 0, 0],
        (0xd, 9) => [8, 0x980, 0, 0],
        (0xd, 0xb) => [0x10, 0, 1, 0],
        (0xd, 0xc) => [0x18, 0, 1, 0],
        (0xf, 0) => [0, 0xff, 0, 2],
        (0xf, 1) => [0, 0x40, 0xff, 7],
        (0x10, 0) => [0, 2, 0, 0],
        (0x10, 1) => [0xf, 0, 4, 0xf],
        (0x8000_0000, _) => [0x8000_0023, 0x6874_7541, 0x444d_4163, 0x6974_6e65],
        (0x8000_0001, _) => [0x00a2_0f12, 0x2000_0000, 0x75c2_37ff, 0x2fd3_fbff],
        (0x8000_0002, _) => [0x3230_4744, 0x4254_5253, 0x464d_3450, 0x2020_2041],
        (0x8000_0003, _) => [0x2020_2020; 4],
        (0x8000_0004, _) => [0x2020_2020, 0x2020_2020, 0x2020_2020, 0x0020_2020],
        (0x8000_0005, _) => [0xff40_ff40, 0xff40_ff40, 0x2008_0140, 0x2008_0140],
        (0x8000_0006, _) => [0x4800_2200, 0x6800_4200, 0x0200_6140, 0x0100_9140],
        (0x8000_0007, _) => [0, 0x3b, 0, 0x6799],
        (0x8000_0008, _) => [0x3030, 0x111e_f657, 0x400f, 0x1_0000],
        (0x8000_000a, _) => [1, 0x8000, 0, 0x101b_bcff],
        (0x8000_0019, _) => [0xf040_f040, 0xf040_0000, 0, 0],
        (0x8000_001a, _) => [6, 0, 0, 0],
        (0x8000_001b, _) => [0x3ff, 0, 0, 0],
        (0x8000_001d, 0) => [0x4121, 0x01c0_003f, 0x3f, 0],
        (0x8000_001d, 1) => [0x4122, 0x01c0_003f, 0x3f, 0],
        (0x8000_001d, 2) => [0x4143, 0x01c0_003f, 0x3ff, 2],
        (0x8000_001d, 3) => [0x0003_c163, 0x03c0_003f, 0x7fff, 1],
        (0x8000_001f, _) => [0x0001_780f, 0x173, 0x1fd, 1],
        (0x8000_0020, 0) => [0, 2, 0, 0],
        (0x8000_0020, 1) => [0xb, 0, 0, 0xf],
        (0x8000_0021, _) => [0x4d, 0, 0, 0],
        _ => [0; 4],
    };
    Some(Registers::new(words[0], words[1], words[2], words[3]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readiness_requires_registration_and_success_and_is_one_shot() {
        let state = AmdSession::new();
        assert!(!state.take_ready(|| panic!("unregistered poll must not prepare")));
        state.register(0);
        assert_eq!(state.pid(), 0);
        state.register(0x134);
        assert!(!state.take_ready(|| false));
        assert!(state.take_ready(|| {
            assert!(!state.take_ready(|| panic!("nested poll must not prepare")));
            true
        }));
        state.register(0x999);
        assert_eq!(state.pid(), 0x134);
        assert!(!state.take_ready(|| panic!("duplicate registration must not rearm")));
    }

    #[test]
    fn subleaves_do_not_leak_host_avx512_or_unknown_features() {
        let features = amd_reply(7, 0).unwrap();
        assert_eq!(features.ebx & (1 << 16), 0);
        assert_eq!(features.edx & (1 << 14), 0);
        for (leaf, subleaf) in [(7, 1), (0xd, 7), (0x8000_001d, 4), (0x8000_0023, 0)] {
            assert_eq!(amd_reply(leaf, subleaf), Some(Registers::default()));
        }
        assert_eq!(amd_reply(0xd, 0).unwrap().eax, 0x207);
        assert_eq!(amd_reply(0xd, 2).unwrap().ebx, 0x240);
        for leaf in [
            REGISTER_PROCESS,
            REGISTER_HANDLER,
            KUSER_READY,
            0xb,
            0x8000_001e,
        ] {
            assert_eq!(amd_reply(leaf, 0), None);
        }
    }
}
