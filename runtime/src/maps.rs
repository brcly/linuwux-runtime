//! The one `/proc/self/maps` reader. It uses a raw `read` syscall, so it is
//! safe inside the SIGSEGV/SIGSYS handlers and never re-enters this library's
//! own exported `read` interposer.
#[cfg(all(
    feature = "cpuid",
    feature = "syscall",
    feature = "kuser",
    feature = "environment"
))]
use core::sync::atomic::{AtomicU64, Ordering};

const LINE_CAPACITY: usize = 1024;

/// One parsed `/proc/self/maps` line. `path` is everything after the inode,
/// spaces included (Steam library paths often contain them).
#[cfg_attr(not(feature = "kuser"), allow(dead_code))]
pub(crate) struct Mapping<'a> {
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) permissions: &'a [u8],
    pub(crate) inode: &'a [u8],
    pub(crate) path: &'a [u8],
}

pub(crate) fn parse_hex(value: &[u8]) -> Option<u64> {
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

fn next_field<'a>(line: &'a [u8], position: &mut usize) -> Option<&'a [u8]> {
    while line.get(*position).is_some_and(u8::is_ascii_whitespace) {
        *position += 1;
    }
    let start = *position;
    while line
        .get(*position)
        .is_some_and(|byte| !byte.is_ascii_whitespace())
    {
        *position += 1;
    }
    (*position > start).then(|| &line[start..*position])
}

pub(crate) fn parse(line: &[u8]) -> Option<Mapping<'_>> {
    let mut position = 0;
    let range = next_field(line, &mut position)?;
    let permissions = next_field(line, &mut position)?;
    let _offset = next_field(line, &mut position)?;
    let _device = next_field(line, &mut position)?;
    let inode = next_field(line, &mut position)?;
    let mut bounds = range.split(|&byte| byte == b'-');
    let start = parse_hex(bounds.next()?)?;
    let end = parse_hex(bounds.next()?)?;
    if bounds.next().is_some() {
        return None;
    }
    while line.get(position).is_some_and(u8::is_ascii_whitespace) {
        position += 1;
    }
    Some(Mapping {
        start,
        end,
        permissions,
        inode,
        path: line.get(position..).unwrap_or_default(),
    })
}

/// Calls `visit` with each line of `/proc/self/maps` (newline stripped) until
/// it returns `true`, and reports whether it did. Lines too long for the
/// fixed buffer are skipped rather than truncated.
pub(crate) fn find_line(mut visit: impl FnMut(&[u8]) -> bool) -> bool {
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
    let mut line = [0u8; LINE_CAPACITY];
    let mut length = 0;
    let mut overflow = false;
    let mut found = false;
    'read: loop {
        let count = unsafe {
            libc::syscall(
                libc::SYS_read,
                fd as libc::c_long,
                chunk.as_mut_ptr(),
                chunk.len(),
            )
        };
        if count <= 0 {
            break;
        }
        for &byte in &chunk[..count as usize] {
            if byte == b'\n' {
                if !overflow && visit(&line[..length]) {
                    found = true;
                    break 'read;
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
    if !found && length != 0 && !overflow {
        found = visit(&line[..length]);
    }
    unsafe { libc::close(fd) };
    found
}

/// Counts file-backed mappings made through this library's `mmap`
/// interposer, so a caller can skip rescanning `/proc/self/maps` when no new
/// file can have appeared in it since its last look.
#[cfg(all(
    feature = "cpuid",
    feature = "syscall",
    feature = "kuser",
    feature = "environment"
))]
static FILE_MAPPINGS: AtomicU64 = AtomicU64::new(0);

#[cfg(all(
    feature = "cpuid",
    feature = "syscall",
    feature = "kuser",
    feature = "environment"
))]
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn note_file_mapping() {
    FILE_MAPPINGS.fetch_add(1, Ordering::Relaxed);
}

#[cfg(all(
    feature = "cpuid",
    feature = "syscall",
    feature = "kuser",
    feature = "environment"
))]
pub(crate) fn file_mapping_generation() -> u64 {
    FILE_MAPPINGS.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::{find_line, parse};

    #[test]
    fn parses_paths_with_spaces_and_anonymous_mappings() {
        let line = b"7f100000-7f101000 r-xp 00000000 08:01 456   /home/user/Steam Library/a b.dll";
        let mapping = parse(line).unwrap();
        assert_eq!((mapping.start, mapping.end), (0x7f10_0000, 0x7f10_1000));
        assert_eq!(mapping.permissions, b"r-xp");
        assert_eq!(mapping.inode, b"456");
        assert_eq!(mapping.path, b"/home/user/Steam Library/a b.dll");

        let anonymous = parse(b"7f100000-7f101000 rwxp 00000000 00:00 0").unwrap();
        assert_eq!(anonymous.path, b"");
        assert!(parse(b"7f100000-7f101000-1 r-xp 0 0 0").is_none());
        assert!(parse(b"garbage").is_none());
    }

    #[cfg(not(miri))]
    #[test]
    fn finds_this_process_stack() {
        assert!(find_line(
            |line| parse(line).is_some_and(|m| m.path == b"[stack]")
        ));
    }
}
