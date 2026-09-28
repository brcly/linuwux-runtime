//! Decodes the `jmp [rip+2]`-style trampolines Reflex writes into IAT and
//! export slots. Shared by [`super::kuser_dispatch`] and
//! [`super::unixlib_repair`].

use crate::procmem::read_memory;

/// Reflex's IAT/export hooks are all the same `jmp [rip+2]`-style trampoline:
/// `ff 25 02 00 00 00 00 00`, destination stored at offset 8.
pub(super) const TRAMPOLINE_HEAD: [u8; 8] = [0xff, 0x25, 0x02, 0, 0, 0, 0, 0];

pub(super) fn trampoline_destination(slot: u64) -> Option<u64> {
    let mut bytes = [0; 16];
    if !read_memory(slot, &mut bytes) {
        return None;
    }
    decode_trampoline(&bytes)
}

pub(super) fn decode_trampoline(bytes: &[u8; 16]) -> Option<u64> {
    (bytes[..8] == TRAMPOLINE_HEAD).then(|| u64::from_le_bytes(bytes[8..].try_into().unwrap()))
}

#[cfg(all(test, not(miri)))]
mod tests {
    use super::trampoline_destination;

    // `trampoline_destination` calls `read_memory`, which calls
    // `process_vm_readv` — not in Miri's foreign-function shim list at all.
    #[test]
    fn reflex_iat_trampoline_decoder_accepts_only_the_observed_indirect_jump() {
        let mut code = [0u8; 16];
        code[..8].copy_from_slice(&super::TRAMPOLINE_HEAD);
        code[8..].copy_from_slice(&0x1234_5678_9abc_def0u64.to_le_bytes());
        assert_eq!(
            trampoline_destination(code.as_ptr() as u64),
            Some(0x1234_5678_9abc_def0)
        );

        code[2] = 1;
        assert_eq!(trampoline_destination(code.as_ptr() as u64), None);
    }
}
