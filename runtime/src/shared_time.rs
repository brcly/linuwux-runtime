use super::{ADDRESS, PAGE_GEOMETRY_SUPPORTED, PAGE_SIZE};
use core::sync::atomic::{AtomicBool, Ordering};

static VERIFIED: AtomicBool = AtomicBool::new(false);

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

pub(crate) fn prepare_shared_page() -> bool {
    let verified = verify_shared_page();
    VERIFIED.store(verified, Ordering::Release);
    verified
}

fn ensure_verified() -> bool {
    if VERIFIED.load(Ordering::Acquire) {
        return true;
    }
    let verified = verify_shared_page();
    if verified {
        VERIFIED.store(true, Ordering::Release);
    }
    verified
}

pub(crate) fn shared_page_available_for_write() -> bool {
    ensure_verified()
}
