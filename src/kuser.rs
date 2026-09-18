use core::sync::atomic::{AtomicU32, Ordering};

pub const PAGE_SIZE: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Profile {
    ResumeTarget = 0,
    DualDispatch = 1,
    SingleDispatch = 2,
}

impl Profile {
    pub const fn from_raw(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::ResumeTarget),
            1 => Some(Self::DualDispatch),
            2 => Some(Self::SingleDispatch),
            _ => None,
        }
    }

    pub fn visit_writes(self, avx_enabled: bool, mut write: impl FnMut(usize, u8)) {
        let ops: &[(usize, usize, u64)] = match self {
            Self::SingleDispatch => SINGLE_DISPATCH_OPS,
            Self::DualDispatch => DUAL_DISPATCH_OPS,
            Self::ResumeTarget => {
                for (index, byte) in b"C:\\Windows\0".iter().copied().enumerate() {
                    write(0x30 + index * 2, byte);
                    write(0x31 + index * 2, 0);
                }
                RESUME_TARGET_OPS
            }
        };
        for &(offset, size, value) in ops {
            for (index, byte) in value.to_le_bytes()[..size].iter().copied().enumerate() {
                write(offset + index, byte);
            }
        }
        if self == Self::ResumeTarget {
            for offset in [0x290, 0x294, 0x295, 0x297] {
                write(offset, 0);
            }
            if !avx_enabled {
                for offset in [0x285, 0x29b, 0x29c] {
                    write(offset, 0);
                }
            }
            for offset in (0x3f0..0x5f0).chain(0x604..0x804) {
                write(offset, 0);
            }
        }
    }
}

const RESUME_TARGET_OPS: &[(usize, usize, u64)] = &[
    (0x260, 8, 0x0000000100006658),
    (0x268, 4, 0x00090001),
    (0x26c, 4, 0x0000000a),
    (0x270, 4, 0),
    (0x274, 4, 0x01010000),
    (0x278, 4, 0x00010000),
    (0x27c, 4, 0x00010101),
    (0x280, 4, 0x00010101),
    (0x284, 4, 0x00000100),
    (0x288, 4, 0x01010101),
    (0x28c, 4, 0),
    (0x290, 4, 1),
    (0x294, 4, 0x01000101),
    (0x298, 4, 0x01010101),
    (0x29c, 4, 0x00010001),
    (0x2a0, 4, 0),
    (0x2a4, 4, 0),
    (0x2a8, 4, 0),
    (0x2ac, 4, 0),
    (0x2b0, 4, 1),
    (0x3d8, 8, 0),
    (0x3e0, 8, 0),
    (0x3ec, 4, 0),
    (0x5f0, 8, 0),
    (0x5f8, 8, 0),
    (0x808, 8, 0),
    (0x810, 8, 0),
    (0x2d0, 8, 0x00320A0000000110),
    (0x2e8, 8, 0x00000100007FB10B),
    (0x2f4, 4, 0),
    (0x36c, 8, 0),
    (0x374, 8, 0),
    (0x37c, 4, 1),
    (0x3c0, 8, 0x0083000100000010),
    (0xffc, 4, 0x13371337),
];

const SINGLE_DISPATCH_OPS: &[(usize, usize, u64)] = &[
    (0x2d6, 4, 0x0001_0034),
    (0x2e8, 4, 0x00bf_9c8f),
    (0x3c0, 4, 0x0000_0010),
    (0x288, 4, 0x0101_0101),
    (0x268, 4, 0x0009_0001),
    (0x2f4, 4, 0),
    (0x264, 4, 1),
    (0x2d0, 4, 0x0000_0310),
    (0x260, 4, 0x0000_6658),
    (0x26c, 4, 0x0a),
    (0x270, 4, 0),
    (0xffc, 4, 0x1337_1337),
];

const DUAL_DISPATCH_OPS: &[(usize, usize, u64)] = &[
    (0x26e, 8, 0),
    (0x288, 8, 0x0000000001010101),
    (0x268, 8, 0x0000000A00090001),
    (0x261, 8, 0x0100000001000066),
    (0x272, 8, 0x0000010100000000),
    (0x3c0, 4, 0x10),
    (0x260, 8, 0x0000000100006658),
    (0x2d0, 4, 0x0110),
    (0x2e8, 4, 0x007FB10B),
    (0x378, 4, 0),
    (0x2e8, 8, 0x00000100007FB10B),
    (0x273, 8, 0x0100000101000000),
    (0x2d0, 8, 0x00320A0000000110),
    (0x000, 8, 0x0FA0000000000000),
    (0x378, 8, 0x0000000100000000),
    (0x3c0, 8, 0x0083000100000010),
    (0x26c, 8, 0x000000000000000A),
    (0x2f4, 4, 0),
    (0x264, 4, 1),
    (0x270, 4, 0),
    (0x281, 4, 0x00000101),
    (0x286, 4, 0x01010000),
    (0x287, 4, 0x01010100),
    (0x285, 1, 1),
    (0xffc, 4, 0x1337_1337),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PatchError {
    Conflict,
    ApplyFailed,
}

const PATCH_UNAPPLIED: u32 = 0;
const PATCH_RESUME_TARGET_APPLYING: u32 = 1;
const PATCH_RESUME_TARGET_READY: u32 = 2;
const PATCH_RESUME_TARGET_FAILED: u32 = 3;
const PATCH_SINGLE_DISPATCH_APPLYING: u32 = 4;
const PATCH_SINGLE_DISPATCH_READY: u32 = 5;
const PATCH_SINGLE_DISPATCH_FAILED: u32 = 6;
const PATCH_DUAL_DISPATCH_APPLYING: u32 = 7;
const PATCH_DUAL_DISPATCH_READY: u32 = 8;
const PATCH_DUAL_DISPATCH_FAILED: u32 = 9;
const PATCH_WAIT_LIMIT: u32 = 4096;

#[derive(Debug, Default)]
pub struct PatchState(AtomicU32);

impl PatchState {
    pub const fn new() -> Self {
        Self(AtomicU32::new(PATCH_UNAPPLIED))
    }

    pub fn recover_after_fork(&self) {
        let _ = self
            .0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |state| match state {
                PATCH_RESUME_TARGET_APPLYING => Some(PATCH_RESUME_TARGET_FAILED),
                PATCH_SINGLE_DISPATCH_APPLYING => Some(PATCH_SINGLE_DISPATCH_FAILED),
                PATCH_DUAL_DISPATCH_APPLYING => Some(PATCH_DUAL_DISPATCH_FAILED),
                _ => None,
            });
    }

    pub fn patch(
        &self,
        profile: Profile,
        apply: impl FnOnce() -> bool,
        mut wait: impl FnMut(),
    ) -> Result<(), PatchError> {
        let (applying_state, ready_state, failed_state) = match profile {
            Profile::ResumeTarget => (
                PATCH_RESUME_TARGET_APPLYING,
                PATCH_RESUME_TARGET_READY,
                PATCH_RESUME_TARGET_FAILED,
            ),
            Profile::SingleDispatch => (
                PATCH_SINGLE_DISPATCH_APPLYING,
                PATCH_SINGLE_DISPATCH_READY,
                PATCH_SINGLE_DISPATCH_FAILED,
            ),
            Profile::DualDispatch => (
                PATCH_DUAL_DISPATCH_APPLYING,
                PATCH_DUAL_DISPATCH_READY,
                PATCH_DUAL_DISPATCH_FAILED,
            ),
        };
        let mut completion_state = failed_state;
        let mut waits = 0;
        loop {
            let current = self.0.load(Ordering::Acquire);
            if current == ready_state {
                return Ok(());
            }
            let another_dispatch_apply = matches!(
                current,
                PATCH_SINGLE_DISPATCH_APPLYING | PATCH_DUAL_DISPATCH_APPLYING
            );
            if another_dispatch_apply && current != applying_state {
                if waits == PATCH_WAIT_LIMIT {
                    return Err(PatchError::Conflict);
                }
                waits += 1;
                wait();
                continue;
            }
            if current != PATCH_UNAPPLIED && !(applying_state..=failed_state).contains(&current) {
                let can_transition_from_dispatch =
                    matches!(profile, Profile::DualDispatch | Profile::SingleDispatch)
                        && matches!(
                            current,
                            PATCH_RESUME_TARGET_READY
                                | PATCH_SINGLE_DISPATCH_READY
                                | PATCH_SINGLE_DISPATCH_FAILED
                                | PATCH_DUAL_DISPATCH_READY
                                | PATCH_DUAL_DISPATCH_FAILED
                        );
                if !can_transition_from_dispatch {
                    return Err(PatchError::Conflict);
                }
                completion_state = current;
            }
            if current == applying_state {
                if waits == PATCH_WAIT_LIMIT {
                    return Err(PatchError::Conflict);
                }
                waits += 1;
                wait();
                continue;
            }
            if self
                .0
                .compare_exchange_weak(current, applying_state, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break;
            }
        }
        struct Completion<'a> {
            patch_state: &'a AtomicU32,
            completion_state: u32,
        }
        impl Drop for Completion<'_> {
            fn drop(&mut self) {
                self.patch_state
                    .store(self.completion_state, Ordering::Release);
            }
        }
        let mut completion = Completion {
            patch_state: &self.0,
            completion_state,
        };
        if apply() {
            completion.completion_state = ready_state;
            Ok(())
        } else {
            Err(PatchError::ApplyFailed)
        }
    }
}
