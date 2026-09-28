//! Low-level, out-of-process-style memory access shared by [`super::kuser_dispatch`]
//! and [`super::unixlib_repair`]. Both read PE structures (headers, export
//! tables, IAT slots) that live in this same process's own address space but
//! are not necessarily backed by valid mappings at every address they probe,
//! so every access goes through `process_vm_readv`/`process_vm_writev`
//! rather than a raw pointer dereference: a bad address becomes a failed
//! syscall instead of a segfault.

use core::ffi::c_void;

pub(super) fn read_memory(address: u64, output: &mut [u8]) -> bool {
    if address == 0 || output.is_empty() {
        return false;
    }
    let local = libc::iovec {
        iov_base: output.as_mut_ptr().cast(),
        iov_len: output.len(),
    };
    let remote = libc::iovec {
        iov_base: address as *mut c_void,
        iov_len: output.len(),
    };
    unsafe {
        libc::syscall(
            libc::SYS_process_vm_readv,
            libc::syscall(libc::SYS_getpid),
            &local as *const libc::iovec,
            1usize,
            &remote as *const libc::iovec,
            1usize,
            0usize,
        ) == output.len() as libc::c_long
    }
}

pub(super) fn write_u64(address: u64, value: u64) -> bool {
    let bytes = value.to_le_bytes();
    let local = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    let remote = libc::iovec {
        iov_base: address as *mut c_void,
        iov_len: bytes.len(),
    };
    unsafe {
        libc::syscall(
            libc::SYS_process_vm_writev,
            libc::syscall(libc::SYS_getpid),
            &local as *const libc::iovec,
            1usize,
            &remote as *const libc::iovec,
            1usize,
            0usize,
        ) == bytes.len() as libc::c_long
    }
}

pub(super) fn write_u32(address: u64, value: u32) -> bool {
    let bytes = value.to_le_bytes();
    let local = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    let remote = libc::iovec {
        iov_base: address as *mut c_void,
        iov_len: bytes.len(),
    };
    unsafe {
        libc::syscall(
            libc::SYS_process_vm_writev,
            libc::syscall(libc::SYS_getpid),
            &local as *const libc::iovec,
            1usize,
            &remote as *const libc::iovec,
            1usize,
            0usize,
        ) == bytes.len() as libc::c_long
    }
}

pub(super) fn read_u64(address: u64) -> Option<u64> {
    let mut bytes = [0; 8];
    read_memory(address, &mut bytes).then(|| u64::from_le_bytes(bytes))
}

pub(super) fn read_u32(address: u64) -> Option<u32> {
    let mut bytes = [0; 4];
    read_memory(address, &mut bytes).then(|| u32::from_le_bytes(bytes))
}

pub(super) fn read_u16(address: u64) -> Option<u16> {
    let mut bytes = [0; 2];
    read_memory(address, &mut bytes).then(|| u16::from_le_bytes(bytes))
}

pub(super) fn parse_hex(value: &[u8]) -> Option<u64> {
    if value.is_empty() {
        return None;
    }
    value.iter().try_fold(0u64, |result, &byte| {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return None,
        };
        result.checked_mul(16)?.checked_add(u64::from(digit))
    })
}

/// Reflex's IAT/export hooks are all the same `jmp [rip+2]`-style trampoline:
/// `ff 25 02 00 00 00 00 00`, destination stored at offset 8.
pub(super) const TRAMPOLINE_HEAD: [u8; 8] = [0xff, 0x25, 0x02, 0, 0, 0, 0, 0];

pub(super) fn trampoline_destination(slot: u64) -> Option<u64> {
    let mut bytes = [0; 16];
    if !read_memory(slot, &mut bytes) || bytes[..8] != TRAMPOLINE_HEAD {
        return None;
    }
    Some(u64::from_le_bytes(bytes[8..].try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::trampoline_destination;

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
