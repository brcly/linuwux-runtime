//! Reads and writes this process's own memory through
//! `process_vm_readv`/`process_vm_writev`, so probing an address that may not
//! be mapped fails a syscall instead of faulting. Safe to use from the
//! SIGSEGV/SIGSYS handlers.
#![cfg_attr(
    not(all(feature = "syscall", feature = "kuser", feature = "reflex")),
    allow(dead_code)
)]

use core::ffi::c_void;
#[cfg(feature = "hooks")]
use core::sync::atomic::{AtomicI32, Ordering};

// glibc no longer caches getpid(), so every access would otherwise cost a
// second syscall. The cache is only sound while a fork child resets it, which
// `hooks.rs` does from its `pthread_atfork` handler.
#[cfg(feature = "hooks")]
static PID: AtomicI32 = AtomicI32::new(0);

#[cfg(feature = "hooks")]
fn pid() -> libc::pid_t {
    let cached = PID.load(Ordering::Relaxed);
    if cached != 0 {
        return cached;
    }
    let pid = unsafe { libc::getpid() };
    PID.store(pid, Ordering::Relaxed);
    pid
}

#[cfg(not(feature = "hooks"))]
fn pid() -> libc::pid_t {
    unsafe { libc::getpid() }
}

#[cfg(feature = "hooks")]
pub(crate) fn forget_pid_after_fork() {
    PID.store(0, Ordering::Relaxed);
}

pub(crate) fn read_memory(address: u64, output: &mut [u8]) -> bool {
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
    unsafe { libc::process_vm_readv(pid(), &local, 1, &remote, 1, 0) == output.len() as isize }
}

fn write_memory(address: u64, bytes: &[u8]) -> bool {
    let local = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    let remote = libc::iovec {
        iov_base: address as *mut c_void,
        iov_len: bytes.len(),
    };
    unsafe { libc::process_vm_writev(pid(), &local, 1, &remote, 1, 0) == bytes.len() as isize }
}

pub(crate) fn write_u64(address: u64, value: u64) -> bool {
    write_memory(address, &value.to_le_bytes())
}

pub(crate) fn write_u32(address: u64, value: u32) -> bool {
    write_memory(address, &value.to_le_bytes())
}

pub(crate) fn read_u64(address: u64) -> Option<u64> {
    let mut bytes = [0; 8];
    read_memory(address, &mut bytes).then(|| u64::from_le_bytes(bytes))
}

/// Fills `output` with consecutive u64s starting at `address` in one read,
/// falling back to one read per value when the span is not fully readable.
/// Returns how many leading values were read.
pub(crate) fn read_u64s(address: u64, output: &mut [u64; 64], count: usize) -> usize {
    let count = count.min(output.len());
    let mut bytes = [0u8; 64 * 8];
    if read_memory(address, &mut bytes[..count * 8]) {
        for (value, chunk) in output.iter_mut().zip(bytes[..count * 8].as_chunks::<8>().0) {
            *value = u64::from_le_bytes(*chunk);
        }
        return count;
    }
    for (index, value) in output[..count].iter_mut().enumerate() {
        match address.checked_add(index as u64 * 8).and_then(read_u64) {
            Some(read) => *value = read,
            None => return index,
        }
    }
    count
}

pub(crate) fn read_u32(address: u64) -> Option<u32> {
    let mut bytes = [0; 4];
    read_memory(address, &mut bytes).then(|| u32::from_le_bytes(bytes))
}

pub(crate) fn read_u16(address: u64) -> Option<u16> {
    let mut bytes = [0; 2];
    read_memory(address, &mut bytes).then(|| u16::from_le_bytes(bytes))
}
