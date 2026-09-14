use super::{ADDRESS, PAGE_GEOMETRY_SUPPORTED, PAGE_SIZE, log};
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering, fence};
use linuwux::kuser::{SHARED_TIME_OFFSET, SHARED_TIME_PUBLISHED, SHARED_TIME_PUBLISHED_MARKER};

static VERIFIED: AtomicBool = AtomicBool::new(false);
static PROBE_COUNT: AtomicU32 = AtomicU32::new(0);

const PROBE_INTERVAL: u32 = 4096;

fn wine_mapping(line: &[u8]) -> bool {
    let mut fields = line
        .split(|b| b.is_ascii_whitespace())
        .filter(|s| !s.is_empty());
    let Some(range) = fields.next() else {
        return false;
    };
    let Some(permissions) = fields.next() else {
        return false;
    };
    let mut bounds = range.split(|&b| b == b'-');
    let parse = |bytes: &[u8]| {
        core::str::from_utf8(bytes)
            .ok()
            .and_then(|s| usize::from_str_radix(s, 16).ok())
    };
    let (Some(start), Some(end)) = (bounds.next().and_then(parse), bounds.next().and_then(parse))
    else {
        return false;
    };
    let _offset = fields.next();
    let _device = fields.next();
    let inode = fields.next();
    start == ADDRESS
        && end >= ADDRESS + PAGE_SIZE
        && matches!(permissions, b"r--s" | b"rw-s")
        && inode.is_some_and(|v| v != b"0")
        && fields.next() == Some(b"/memfd:wine-mapping".as_slice())
}

fn mapped_page_present() -> bool {
    let mut resident = 0;
    unsafe { libc::mincore(ADDRESS as *mut libc::c_void, PAGE_SIZE, &mut resident) == 0 }
}

fn verify_shared_page() -> bool {
    if !PAGE_GEOMETRY_SUPPORTED.load(Ordering::Acquire) {
        return false;
    }
    let _errno = crate::errno::Errno::save();
    if !mapped_page_present() {
        return false;
    }
    let fd = unsafe {
        libc::open(
            c"/proc/self/maps".as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return false;
    }
    let mut chunk = [0u8; 4096];
    let mut line = [0u8; 1024];
    let mut length = 0;
    let mut overflow = false;
    let mut found = false;
    'chunks: loop {
        let count = unsafe { libc::read(fd, chunk.as_mut_ptr().cast(), chunk.len()) };
        if count <= 0 {
            break;
        }
        for &byte in &chunk[..count as usize] {
            if byte == b'\n' {
                if !overflow && wine_mapping(&line[..length]) {
                    found = true;
                    break 'chunks;
                }
                length = 0;
                overflow = false;
            } else if length < line.len() {
                line[length] = byte;
                length += 1;
            } else {
                overflow = true;
            }
        }
    }
    unsafe { libc::close(fd) };
    found
}

pub(crate) fn shared_page_available() -> bool {
    if VERIFIED.load(Ordering::Acquire) {
        return true;
    }
    if !PROBE_COUNT
        .fetch_add(1, Ordering::Relaxed)
        .is_multiple_of(PROBE_INTERVAL)
    {
        return false;
    }
    let verified = verify_shared_page();
    VERIFIED.store(verified, Ordering::Release);
    verified
}

pub(crate) fn shared_page_available_for_write() -> bool {
    let verified = verify_shared_page();
    VERIFIED.store(verified, Ordering::Release);
    PROBE_COUNT.store(0, Ordering::Relaxed);
    verified
}

pub(crate) fn read_shared_time_offset() -> Option<u64> {
    if !shared_page_available() {
        return None;
    }
    unsafe {
        let flag = &*((ADDRESS + SHARED_TIME_PUBLISHED) as *const AtomicU8);
        if flag.load(Ordering::Relaxed) != SHARED_TIME_PUBLISHED_MARKER {
            return None;
        }
        fence(Ordering::Acquire);
        let cell = &*((ADDRESS + SHARED_TIME_OFFSET) as *const AtomicU64);
        let value = cell.load(Ordering::Relaxed);
        fence(Ordering::Acquire);
        Some(value)
    }
}

pub(crate) enum PublishError {
    Unavailable,
    ProtectionRestore,
}

pub(crate) fn write_shared_time_offset(
    value: u64,
    _guard: &crate::page_guard::PageGuard,
) -> Result<(), PublishError> {
    if !shared_page_available_for_write() {
        return Err(PublishError::Unavailable);
    }
    let page = ptr::with_exposed_provenance_mut::<libc::c_void>(ADDRESS);
    if unsafe {
        libc::syscall(
            libc::SYS_mprotect,
            page,
            PAGE_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
        )
    } != 0
    {
        log(c"failed to make KUSER_SHARED_DATA writable for the faketime cell");
        return Err(PublishError::Unavailable);
    }
    unsafe {
        AtomicU64::from_ptr((ADDRESS + SHARED_TIME_OFFSET) as *mut u64)
            .store(value, Ordering::Release);
        AtomicU8::from_ptr((ADDRESS + SHARED_TIME_PUBLISHED) as *mut u8)
            .store(SHARED_TIME_PUBLISHED_MARKER, Ordering::Release);
    }
    if unsafe { libc::syscall(libc::SYS_mprotect, page, PAGE_SIZE, libc::PROT_READ) } != 0 {
        log(c"failed to restore KUSER_SHARED_DATA read-only protection");
        return Err(PublishError::ProtectionRestore);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_readable_shared_wine_mappings_are_accepted() {
        assert!(wine_mapping(
            b"7ffe0000-7ffe1000 r--s 00000000 00:01 123 /memfd:wine-mapping (deleted)"
        ));
        for line in [
            b"7ffe0000-7ffe1000 rw-p 00000000 00:00 0".as_slice(),
            b"7ffe0000-7ffe1000 ---s 00000000 00:01 123 /memfd:wine-mapping (deleted)",
            b"7ffe0000-7ffe1000 r--s 00000000 00:01 123 /memfd:unrelated (deleted)",
            b"7ffe0000-7ffe0001 r--s 00000000 00:01 123 /memfd:wine-mapping (deleted)",
            b"invalid",
        ] {
            assert!(!wine_mapping(line));
        }
    }
}
