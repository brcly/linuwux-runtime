use core::fmt;
use core::sync::atomic::{AtomicU32, Ordering};

pub const PAGE_SIZE: usize = 4096;

pub const SHARED_TIME_OFFSET: usize = 0x7f8;
pub const SHARED_TIME_PUBLISHED: usize = SHARED_TIME_OFFSET + 8;
pub const SHARED_TIME_PUBLISHED_MARKER: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum Profile {
    Modern = 0,
    Legacy = 1,
}

impl Profile {
    pub const fn from_raw(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::Modern),
            1 => Some(Self::Legacy),
            _ => None,
        }
    }

    pub fn visit_writes(self, avx_enabled: bool, mut write: impl FnMut(usize, u8)) {
        let ops: &[(usize, usize, u64)] = match self {
            Self::Legacy => LEGACY_OPS,
            Self::Modern => {
                for (index, byte) in b"C:\\Windows\0".iter().copied().enumerate() {
                    write(0x30 + index * 2, byte);
                    write(0x31 + index * 2, 0);
                }
                MODERN_OPS
            }
        };
        for &(offset, size, value) in ops {
            for (index, byte) in value.to_le_bytes()[..size].iter().copied().enumerate() {
                write(offset + index, byte);
            }
        }
        if self == Self::Modern {
            for offset in [0x290, 0x294, 0x295, 0x297] {
                write(offset, 0);
            }
            if !avx_enabled {
                for offset in [0x285, 0x29b, 0x29c] {
                    write(offset, 0);
                }
            }
            for offset in (0x3f0..0x5f0)
                .chain(0x604..SHARED_TIME_OFFSET)
                .chain(SHARED_TIME_PUBLISHED + 1..0x804)
            {
                write(offset, 0);
            }
        }
    }

    pub fn apply_to_buffer(self, page: &mut [u8], avx_enabled: bool) -> Result<(), BufferTooSmall> {
        if page.len() < PAGE_SIZE {
            return Err(BufferTooSmall);
        }
        self.visit_writes(avx_enabled, |offset, byte| page[offset] = byte);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BufferTooSmall;

impl fmt::Display for BufferTooSmall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KUSER buffer must contain at least 4096 bytes")
    }
}

impl core::error::Error for BufferTooSmall {}

const MODERN_OPS: &[(usize, usize, u64)] = &[
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

const LEGACY_OPS: &[(usize, usize, u64)] = &[
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
];

const _: () = {
    assert!(
        SHARED_TIME_OFFSET.is_multiple_of(8),
        "value cell must be 8-byte aligned"
    );
    assert!(SHARED_TIME_PUBLISHED < PAGE_SIZE);
    let reserved_end = SHARED_TIME_PUBLISHED + 1;
    let tables = [MODERN_OPS, LEGACY_OPS];
    let mut table = 0;
    while table < tables.len() {
        let mut i = 0;
        while i < tables[table].len() {
            let (offset, size, _) = tables[table][i];
            assert!(size <= 8 && offset <= PAGE_SIZE && size <= PAGE_SIZE - offset);
            let disjoint = offset + size <= SHARED_TIME_OFFSET || offset >= reserved_end;
            assert!(
                disjoint,
                "patch table write collides with the shared faketime cell"
            );
            i += 1;
        }
        table += 1;
    }
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PatchError {
    Conflict,
    ApplyFailed,
}

const PATCH_UNAPPLIED: u32 = 0;
const PATCH_MODERN_APPLYING: u32 = 1;
const PATCH_MODERN_READY: u32 = 2;
const PATCH_MODERN_FAILED: u32 = 3;
const PATCH_LEGACY_APPLYING: u32 = 4;
const PATCH_LEGACY_READY: u32 = 5;
const PATCH_LEGACY_FAILED: u32 = 6;

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
                PATCH_MODERN_APPLYING => Some(PATCH_MODERN_FAILED),
                PATCH_LEGACY_APPLYING => Some(PATCH_LEGACY_FAILED),
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
            Profile::Modern => (
                PATCH_MODERN_APPLYING,
                PATCH_MODERN_READY,
                PATCH_MODERN_FAILED,
            ),
            Profile::Legacy => (
                PATCH_LEGACY_APPLYING,
                PATCH_LEGACY_READY,
                PATCH_LEGACY_FAILED,
            ),
        };
        let mut completion_state = failed_state;
        loop {
            let current = self.0.load(Ordering::Acquire);
            if current == ready_state {
                return Ok(());
            }
            if current != PATCH_UNAPPLIED && !(applying_state..=failed_state).contains(&current) {
                if profile != Profile::Legacy || current != PATCH_MODERN_READY {
                    return Err(PatchError::Conflict);
                }
                completion_state = current;
            }
            if current == applying_state {
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
