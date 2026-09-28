//! Show Windows-layout syscall stubs in whole-file reads of Wine builtin PE
//! images.
//!
//! With KUSER `SystemCall` set, real Windows ntdll takes an `int 2e` branch
//! instead of `syscall`. Wine's own thunks replace that branch with a call
//! through a Wine-invented dispatcher slot instead, since Linux has no IDT
//! gate for vector 0x2e. Anti-tamper code that reads a clean copy of
//! `ntdll.dll`/`win32u.dll` from disk and pattern-matches it against real
//! Windows bytes (TopSpin's Denuvo build does this) does not recognize Wine's
//! tail, and can fall back to a wrong address. This rewrites the tail of every
//! syscall thunk found in a whole-file PE read to the real Windows bytes, so
//! that pattern-matching resolves the export correctly; the caller then jumps
//! to `base + RVA`, reaching Wine's actual, unmodified, working thunk in
//! memory. Mapped images are never touched.
//!
//! The rewrite does not try to match Wine's own tail bytes: those are Wine's
//! implementation choice, not part of the Windows ABI, and are free to differ
//! across Wine/Proton forks and versions. Instead it recognizes a thunk by its
//! head and `SystemCall` test/branch, which are the part of Windows' own
//! syscall stub Wine must reproduce byte-for-byte to have the same semantics,
//! and unconditionally replaces whatever tail follows. This works against any
//! Wine build's chosen tail without needing to know it, and is a no-op if the
//! tail already matches (for example on a second read of the same file).
//!
//! Active for the whole session in the selected game process; no environment
//! variable is required. Each rewrite is logged once per file when
//! `LINUWUX_DEBUG=1` is set, capped at [`LOG_LIMIT`] events.

// File-backed mmap integration tests are native-only, leaving this path unused in Miri.
#![cfg_attr(miri, allow(dead_code))]

use core::ffi::{c_int, c_void};
#[cfg(not(test))]
use core::ptr;
#[cfg(not(test))]
use core::sync::atomic::AtomicPtr;
use core::sync::atomic::{AtomicU64, Ordering};

const THUNK_LEN: usize = 0x20;
const SERVICE_OFFSET: usize = 4;
const BRANCH_OFFSET: usize = 8;
const TAIL_OFFSET: usize = 0x15;
/// `mov r10, rcx; mov eax, imm32`. Real Windows ntdll/win32u syscall stubs
/// open every export with this sequence; the service number is a wildcard.
const THUNK_HEAD: [u8; SERVICE_OFFSET] = [0x4c, 0x8b, 0xd1, 0xb8];
/// `test byte [0x7ffe0308], 1; jne +3; syscall; ret`. This tests
/// `KUSER_SHARED_DATA.SystemCall` at its fixed, OS-defined offset; Wine
/// reproduces it exactly because the check itself (not what follows it) is
/// what must match Windows' semantics. Fully constrained together with the
/// head, these 17 bytes are the signature this module keys on.
const THUNK_BRANCH: [u8; TAIL_OFFSET - BRANCH_OFFSET] = [
    0xf6, 0x04, 0x25, 0x08, 0x03, 0xfe, 0x7f, 0x01, 0x75, 0x03, 0x0f, 0x05, 0xc3,
];
/// Real Windows: `int 2e; ret; nop dword [rax + rax]`. This is what a clean
/// Windows ntdll actually contains, so it is safe to hardcode: it is the
/// thing being restored, not a guess about any particular Wine build.
const WINDOWS_TAIL: [u8; THUNK_LEN - TAIL_OFFSET] = [
    0xcd, 0x2e, 0xc3, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Smallest read considered a whole-file PE read. Wine's own header reads
/// while mapping an image are smaller than this.
const MIN_FILE_READ: isize = 0x1000;
/// Smallest file-backed mapping considered a whole-file PE data view. Wine maps
/// a PE image's header and each of its sections separately, so an image
/// mapping never covers a whole DLL; a real DLL is far larger than this.
#[cfg(not(test))]
const MIN_FILE_VIEW: usize = 0x4000;
#[cfg(all(not(test), feature = "debug"))]
const LOG_LIMIT: u64 = 8;

#[cfg(all(not(test), feature = "debug"))]
static EVENTS: AtomicU64 = AtomicU64::new(0);
#[cfg(not(test))]
static REAL_READ: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
#[cfg(not(test))]
static REAL_PREAD: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
#[cfg(not(test))]
static REAL_MMAP: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

#[cfg(all(not(test), feature = "debug"))]
unsafe extern "C" {
    fn debug_log(message: *const core::ffi::c_char);
    fn debug_log_hex(prefix: *const core::ffi::c_char, value: u64);
    fn debug_enabled() -> c_int;
}

#[cfg(not(test))]
type Read = unsafe extern "C" fn(c_int, *mut c_void, usize) -> isize;
#[cfg(not(test))]
type Pread = unsafe extern "C" fn(c_int, *mut c_void, usize, libc::off_t) -> isize;
type Mmap =
    unsafe extern "C" fn(*mut c_void, usize, c_int, c_int, c_int, libc::off_t) -> *mut c_void;

/// Whether `bytes` opens with a syscall thunk's head and `SystemCall`
/// test/branch. This does not look at the tail: it is what follows this
/// signature, is Wine's own implementation choice, and is exactly what gets
/// replaced.
fn is_syscall_thunk_head(bytes: &[u8]) -> bool {
    bytes.len() >= THUNK_LEN
        && bytes[..SERVICE_OFFSET] == THUNK_HEAD
        && bytes[BRANCH_OFFSET..TAIL_OFFSET] == THUNK_BRANCH
}

/// Replace the tail of every complete syscall thunk in `buffer` with the real
/// Windows bytes, regardless of what is currently there. The head, the
/// embedded service number, and the direct `syscall` branch are unchanged.
/// Returns the number of thunks whose tail actually changed; a thunk already
/// carrying the Windows tail is left untouched and not counted.
fn rewrite_syscall_thunk_tails(buffer: &mut [u8]) -> usize {
    let mut rewritten = 0;
    let mut offset = 0;
    while offset + THUNK_LEN <= buffer.len() {
        if is_syscall_thunk_head(&buffer[offset..]) {
            let tail = &mut buffer[offset + TAIL_OFFSET..offset + THUNK_LEN];
            if tail != WINDOWS_TAIL {
                tail.copy_from_slice(&WINDOWS_TAIL);
                rewritten += 1;
            }
            offset += THUNK_LEN;
        } else {
            offset += 1;
        }
    }
    rewritten
}

/// Number of thunks in `buffer` whose tail is not already the Windows tail.
fn count_pending_thunk_tails(buffer: &[u8]) -> usize {
    let mut pending = 0;
    let mut offset = 0;
    while offset + THUNK_LEN <= buffer.len() {
        if is_syscall_thunk_head(&buffer[offset..]) {
            if buffer[offset + TAIL_OFFSET..offset + THUNK_LEN] != WINDOWS_TAIL {
                pending += 1;
            }
            offset += THUNK_LEN;
        } else {
            offset += 1;
        }
    }
    pending
}

fn looks_like_pe_file(buffer: &[u8]) -> bool {
    if buffer.len() < 0x40 || buffer[..2] != *b"MZ" {
        return false;
    }
    let pe_offset = u32::from_le_bytes(buffer[0x3c..0x40].try_into().unwrap()) as usize;
    pe_offset
        .checked_add(4)
        .and_then(|end| buffer.get(pe_offset..end))
        .is_some_and(|signature| signature == b"PE\0\0")
}

#[cfg(not(test))]
fn resolve(slot: &AtomicPtr<c_void>, name: &core::ffi::CStr) -> *mut c_void {
    let mut symbol = slot.load(Ordering::Acquire);
    if symbol.is_null() {
        symbol = unsafe { libc::dlsym(libc::RTLD_NEXT, name.as_ptr()) };
        if !symbol.is_null() {
            slot.store(symbol, Ordering::Release);
        }
    }
    symbol
}

/// Interpose `read`, forwarding the operation and normalizing PE syscall stub
/// tails in qualifying game-process file buffers.
///
/// # Safety
/// The caller must satisfy the same pointer and buffer requirements as libc's
/// `read` function.
///
/// Excluded from test builds: nothing in this crate calls it by Rust path —
/// it exists only as LD_PRELOAD ABI surface for external callers — and
/// exporting it under the same symbol name as `libc::read` self-shadows any
/// test that calls `libc::read` directly (harmless at runtime, since it
/// forwards through, but an unresolvable symbol clash under Miri).
#[cfg(not(test))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn read(fd: c_int, buffer: *mut c_void, count: usize) -> isize {
    let real = {
        let _errno = crate::errno::Errno::save();
        resolve(&REAL_READ, c"read")
    };
    let result = if real.is_null() {
        unsafe { libc::syscall(libc::SYS_read, fd as libc::c_long, buffer, count) as isize }
    } else {
        unsafe { core::mem::transmute::<*mut c_void, Read>(real)(fd, buffer, count) }
    };
    #[cfg(feature = "debug")]
    if result > 0 {
        unsafe { trace_system_dll_read(c"read", fd, result as usize, -1) };
    }
    unsafe { after_file_read(fd, buffer, result) };
    result
}

/// Interpose `pread`, forwarding the operation and normalizing PE syscall stub
/// tails when a qualifying file read begins at offset zero.
///
/// # Safety
/// The caller must satisfy the same pointer and buffer requirements as libc's
/// `pread` function.
///
/// Excluded from test builds: see the same note on [`read`] above.
#[cfg(not(test))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pread(
    fd: c_int,
    buffer: *mut c_void,
    count: usize,
    offset: libc::off_t,
) -> isize {
    let real = {
        let _errno = crate::errno::Errno::save();
        resolve(&REAL_PREAD, c"pread")
    };
    let result = if real.is_null() {
        unsafe {
            libc::syscall(libc::SYS_pread64, fd as libc::c_long, buffer, count, offset) as isize
        }
    } else {
        unsafe { core::mem::transmute::<*mut c_void, Pread>(real)(fd, buffer, count, offset) }
    };
    #[cfg(feature = "debug")]
    if result > 0 {
        unsafe { trace_system_dll_read(c"pread", fd, result as usize, offset) };
    }
    if offset == 0 {
        unsafe { after_file_read(fd, buffer, result) };
    }
    result
}

/// Rewrite syscall thunk tails in a completed read that starts at a PE file's
/// first byte. Everything but the size and the `MZ` check is kept off the
/// path taken by ordinary reads.
///
/// # Safety
/// For `result >= 0`, `buffer` must be valid for `result` writable bytes, as
/// required by the completed read operation.
#[cfg(not(test))]
unsafe fn after_file_read(fd: c_int, buffer: *mut c_void, result: isize) {
    if result < MIN_FILE_READ {
        return;
    }
    let bytes = buffer.cast::<u8>();
    if unsafe { bytes.read() != b'M' || bytes.add(1).read() != b'Z' } {
        return;
    }
    let _errno = crate::errno::Errno::save();
    #[cfg(feature = "environment")]
    if !crate::environment::game_process() {
        return;
    }
    let mut status = core::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, status.as_mut_ptr()) } != 0
        || unsafe { status.assume_init_ref() }.st_mode & libc::S_IFMT != libc::S_IFREG
    {
        return;
    }
    let file = unsafe { core::slice::from_raw_parts_mut(bytes, result as usize) };
    let _rewritten = rewrite_complete_pe_read(file);
    #[cfg(feature = "debug")]
    if _rewritten > 0 && EVENTS.fetch_add(1, Ordering::Relaxed) < LOG_LIMIT {
        unsafe {
            log_rewrite(
                c"PE syscall thunk tails rewritten in file-read buffer",
                fd,
                _rewritten,
            )
        };
    }
}

/// Interpose `mmap`. Anti-tamper code can also read a clean copy of a system
/// DLL by mapping the file as a data view (`NtCreateSection` +
/// `NtMapViewOfSection`) instead of reading it, so give such views the same
/// Windows-layout thunk tails that file reads get.
///
/// # Safety
/// The caller must satisfy the same requirements as libc's `mmap`.
///
/// Excluded from test builds: see the same note on [`read`] above. This is
/// the one that actually surfaced the problem — Miri's own `mmap` shim
/// handles the real function call but not a raw `syscall(SYS_mmap, ...)`, so
/// routing a test helper through the raw syscall to dodge the symbol clash
/// just traded one Miri failure for another; removing the clash at its root
/// (this export not existing in a test binary at all) is the actual fix.
#[cfg(not(test))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mmap(
    addr: *mut c_void,
    length: usize,
    prot: c_int,
    flags: c_int,
    fd: c_int,
    offset: libc::off_t,
) -> *mut c_void {
    let real = {
        let _errno = crate::errno::Errno::save();
        resolve(&REAL_MMAP, c"mmap")
    };
    let result = if real.is_null() {
        unsafe {
            libc::syscall(
                libc::SYS_mmap,
                addr,
                length,
                prot as libc::c_long,
                flags as libc::c_long,
                fd as libc::c_long,
                offset as libc::c_long,
            ) as *mut c_void
        }
    } else {
        unsafe {
            core::mem::transmute::<*mut c_void, Mmap>(real)(addr, length, prot, flags, fd, offset)
        }
    };
    #[cfg(feature = "debug")]
    if result != libc::MAP_FAILED && fd >= 0 && flags & libc::MAP_ANONYMOUS == 0 {
        unsafe { trace_system_dll_map(fd, result, length, prot, flags, offset) };
    }
    if result != libc::MAP_FAILED
        && fd >= 0
        && flags & libc::MAP_ANONYMOUS == 0
        && prot & libc::PROT_READ != 0
    {
        // Wine maps a PE image's header and then each of its sections
        // (`MAP_FIXED | MAP_PRIVATE`, initially writable); everything else,
        // at offset zero and DLL-sized, is a data view.
        if flags & libc::MAP_FIXED != 0 && flags & libc::MAP_PRIVATE != 0 {
            unsafe { after_image_map(fd, result, length, prot, offset) };
        }
        // Executable mappings are never data views.
        if offset == 0 && length >= MIN_FILE_VIEW && prot & libc::PROT_EXEC == 0 {
            unsafe { after_file_map(fd, result, length, prot, real) };
        }
    }
    result
}

/// Where a PE image mapped in this process came from. Wine loads each system
/// DLL once at startup; anti-tamper code that maps a second, private image of
/// the same file (to read its syscall stubs unhooked) is the copy that needs
/// Windows-layout thunk tails, so the first header mapping of a file is left
/// alone and only later ones are treated as copies.
struct ImageCopies {
    device: [AtomicU64; IMAGE_TRACK_SLOTS],
    inode: [AtomicU64; IMAGE_TRACK_SLOTS],
    copy_start: [AtomicU64; IMAGE_TRACK_SLOTS],
    copy_end: [AtomicU64; IMAGE_TRACK_SLOTS],
}

const IMAGE_TRACK_SLOTS: usize = 64;

static IMAGE_COPIES: ImageCopies = ImageCopies {
    device: [const { AtomicU64::new(0) }; IMAGE_TRACK_SLOTS],
    inode: [const { AtomicU64::new(0) }; IMAGE_TRACK_SLOTS],
    copy_start: [const { AtomicU64::new(0) }; IMAGE_TRACK_SLOTS],
    copy_end: [const { AtomicU64::new(0) }; IMAGE_TRACK_SLOTS],
};

impl ImageCopies {
    fn slot(&self, device: u64, inode: u64) -> Option<usize> {
        (0..IMAGE_TRACK_SLOTS).find(|&index| {
            self.inode[index].load(Ordering::Acquire) == inode
                && self.device[index].load(Ordering::Relaxed) == device
        })
    }

    /// Record the header mapping of a PE image. Returns `true` if this file
    /// already had an image mapped in this process, that is, this is a copy.
    fn note_header(&self, device: u64, inode: u64, base: u64, image_size: u64) -> bool {
        if let Some(index) = self.slot(device, inode) {
            self.copy_start[index].store(base, Ordering::Relaxed);
            self.copy_end[index].store(base.saturating_add(image_size), Ordering::Release);
            return true;
        }
        for index in 0..IMAGE_TRACK_SLOTS {
            if self.inode[index]
                .compare_exchange(0, inode, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                self.device[index].store(device, Ordering::Relaxed);
                self.copy_start[index].store(0, Ordering::Relaxed);
                self.copy_end[index].store(0, Ordering::Release);
                return false;
            }
        }
        false
    }

    /// Whether `[address, address + length)` lies inside the most recent copy
    /// mapped of this file.
    fn in_copy(&self, device: u64, inode: u64, address: u64, length: u64) -> bool {
        let Some(index) = self.slot(device, inode) else {
            return false;
        };
        let start = self.copy_start[index].load(Ordering::Acquire);
        let end = self.copy_end[index].load(Ordering::Acquire);
        start != 0 && address >= start && address.saturating_add(length) <= end
    }
}

/// `SizeOfImage` from a PE header that `looks_like_pe_file` accepted.
fn pe_size_of_image(header: &[u8]) -> Option<u64> {
    let pe_offset = u32::from_le_bytes(header.get(0x3c..0x40)?.try_into().ok()?) as usize;
    // Optional header starts 24 bytes after `PE\0\0`; `SizeOfImage` is 56 in.
    let field = pe_offset.checked_add(24 + 56)?;
    Some(u64::from(u32::from_le_bytes(
        header.get(field..field + 4)?.try_into().ok()?,
    )))
}

/// Give Windows-layout thunk tails to the sections of a second private image
/// of a PE file, leaving the process's own load of it untouched.
///
/// # Safety
/// `view` must be a live mapping of `length` bytes of `fd` at `offset`.
#[cfg(not(test))]
unsafe fn after_image_map(
    fd: c_int,
    view: *mut c_void,
    length: usize,
    prot: c_int,
    offset: libc::off_t,
) {
    let _errno = crate::errno::Errno::save();
    #[cfg(feature = "environment")]
    if !crate::environment::game_process() {
        return;
    }
    let mut status = core::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, status.as_mut_ptr()) } != 0 {
        return;
    }
    let status = unsafe { status.assume_init() };
    if status.st_mode & libc::S_IFMT != libc::S_IFREG || (status.st_size as usize) < MIN_FILE_VIEW {
        return;
    }
    let (device, inode) = (status.st_dev, status.st_ino);
    if offset == 0 {
        // A header mapping is only the first page or so of the file.
        if length > MIN_FILE_VIEW {
            return;
        }
        let header = unsafe { core::slice::from_raw_parts(view.cast::<u8>(), length.min(0x1000)) };
        if !looks_like_pe_file(header) {
            return;
        }
        let Some(image_size) = pe_size_of_image(header) else {
            return;
        };
        let _is_copy = IMAGE_COPIES.note_header(device, inode, view as u64, image_size);
        #[cfg(feature = "debug")]
        if _is_copy && EVENTS.fetch_add(1, Ordering::Relaxed) < LOG_LIMIT {
            unsafe { log_rewrite(c"second PE image mapped; rewriting its thunks", fd, 0) };
        }
        return;
    }
    if !IMAGE_COPIES.in_copy(device, inode, view as u64, length as u64) {
        return;
    }
    // Only the part of the mapping the file backs is safe to read.
    let backed = (status.st_size as usize).saturating_sub(offset as usize);
    let scan_length = length.min(backed);
    if scan_length < THUNK_LEN {
        return;
    }
    let writable = prot & libc::PROT_WRITE != 0;
    if !writable && unsafe { libc::mprotect(view, length, prot | libc::PROT_WRITE) } != 0 {
        return;
    }
    let bytes = unsafe { core::slice::from_raw_parts_mut(view.cast::<u8>(), scan_length) };
    let _rewritten = rewrite_syscall_thunk_tails(bytes);
    if !writable {
        unsafe { libc::mprotect(view, length, prot) };
    }
    #[cfg(feature = "debug")]
    if _rewritten > 0 && EVENTS.fetch_add(1, Ordering::Relaxed) < LOG_LIMIT {
        unsafe {
            log_rewrite(
                c"PE syscall thunk tails rewritten in image copy",
                fd,
                _rewritten,
            )
        };
    }
}

/// Give a completed whole-file PE data view Windows-layout thunk tails.
///
/// # Safety
/// `view` must be a live, readable mapping of `length` bytes of `fd` from
/// offset zero, and `real_mmap` either null or libc's `mmap`.
#[cfg(not(test))]
unsafe fn after_file_map(
    fd: c_int,
    view: *mut c_void,
    length: usize,
    prot: c_int,
    real_mmap: *mut c_void,
) {
    let _errno = crate::errno::Errno::save();
    #[cfg(feature = "environment")]
    if !crate::environment::game_process() {
        return;
    }
    let mut status = core::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, status.as_mut_ptr()) } != 0 {
        return;
    }
    let status = unsafe { status.assume_init() };
    if status.st_mode & libc::S_IFMT != libc::S_IFREG || (status.st_size as usize) < MIN_FILE_VIEW {
        return;
    }
    // Only the part of the view that the file actually backs is safe to read.
    let scan_length = length.min(status.st_size as usize);
    let _rewritten = unsafe { rewrite_pe_view(fd, view, length, scan_length, prot, real_mmap) };
    #[cfg(feature = "debug")]
    if _rewritten > 0 && EVENTS.fetch_add(1, Ordering::Relaxed) < LOG_LIMIT {
        unsafe {
            log_rewrite(
                c"PE syscall thunk tails rewritten in file view",
                fd,
                _rewritten,
            )
        };
    }
}

/// Rewrite the thunk tails visible through a data view of a PE file. Returns
/// the number of thunks changed, or 0 if the file is not a PE, has nothing to
/// change, or the view could not be replaced.
///
/// The view is replaced by a private copy-on-write mapping of the same file,
/// so the file on disk, other mappings of it, and Wine's own loaded images are
/// unaffected.
///
/// # Safety
/// As for [`after_file_map`]; `scan_length <= length`.
unsafe fn rewrite_pe_view(
    fd: c_int,
    view: *mut c_void,
    length: usize,
    scan_length: usize,
    prot: c_int,
    real_mmap: *mut c_void,
) -> usize {
    let bytes = unsafe { core::slice::from_raw_parts(view.cast::<u8>(), scan_length) };
    if !looks_like_pe_file(bytes) || count_pending_thunk_tails(bytes) == 0 {
        return 0;
    }
    let replaced = if real_mmap.is_null() {
        unsafe {
            libc::syscall(
                libc::SYS_mmap,
                view,
                length,
                (prot | libc::PROT_WRITE) as libc::c_long,
                (libc::MAP_PRIVATE | libc::MAP_FIXED) as libc::c_long,
                fd as libc::c_long,
                0 as libc::c_long,
            ) as *mut c_void
        }
    } else {
        unsafe {
            core::mem::transmute::<*mut c_void, Mmap>(real_mmap)(
                view,
                length,
                prot | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_FIXED,
                fd,
                0,
            )
        }
    };
    if replaced != view {
        return 0;
    }
    let bytes = unsafe { core::slice::from_raw_parts_mut(view.cast::<u8>(), scan_length) };
    let rewritten = rewrite_syscall_thunk_tails(bytes);
    unsafe { libc::mprotect(view, length, prot) };
    rewritten
}

/// Path behind `fd` from `/proc/self/fd`, NUL-terminated in `path`; returns its
/// length (0 if unavailable).
///
/// # Safety
/// Only calls libc.
#[cfg(all(not(test), feature = "debug"))]
unsafe fn fd_path(fd: c_int, path: &mut [u8; 256]) -> usize {
    let mut link = *b"/proc/self/fd/\0\0\0\0\0\0\0\0\0\0\0\0";
    let mut digits = [0u8; 10];
    let mut value = fd.max(0) as u32;
    let mut start = digits.len();
    loop {
        start -= 1;
        digits[start] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    let prefix = b"/proc/self/fd/".len();
    link[prefix..prefix + digits.len() - start].copy_from_slice(&digits[start..]);
    let length = unsafe {
        libc::readlink(
            link.as_ptr().cast(),
            path.as_mut_ptr().cast(),
            path.len() - 1,
        )
    };
    if length <= 0 {
        return 0;
    }
    path[length as usize] = 0;
    length as usize
}

/// Bounded trace of every file mapping of `ntdll.dll`/`win32u.dll` in the game
/// process, with the mapping's protection and flags. This shows how
/// anti-tamper code obtains its copy of a system DLL (read, data view, image
/// view) and separates it from Wine's own image mappings.
///
/// # Safety
/// Only calls libc and the runtime's exported debug logger.
#[cfg(all(not(test), feature = "debug"))]
unsafe fn trace_system_dll_map(
    fd: c_int,
    view: *mut c_void,
    length: usize,
    prot: c_int,
    flags: c_int,
    offset: libc::off_t,
) {
    static MAP_EVENTS: AtomicU64 = AtomicU64::new(0);
    if unsafe { debug_enabled() } == 0 {
        return;
    }
    #[cfg(feature = "environment")]
    if !crate::environment::game_process() {
        return;
    }
    let _errno = crate::errno::Errno::save();
    let mut path = [0u8; 256];
    let length_of_path = unsafe { fd_path(fd, &mut path) };
    let path_bytes = &path[..length_of_path];
    if !(path_bytes.ends_with(b"/ntdll.dll") || path_bytes.ends_with(b"/win32u.dll")) {
        return;
    }
    if MAP_EVENTS.fetch_add(1, Ordering::Relaxed) >= 64 {
        return;
    }
    unsafe {
        debug_log(c"system DLL file mapping".as_ptr());
        debug_log(path.as_ptr().cast());
        debug_log_hex(c"system DLL map view=".as_ptr(), view as u64);
        debug_log_hex(c"system DLL map length=".as_ptr(), length as u64);
        debug_log_hex(c"system DLL map offset=".as_ptr(), offset as u64);
        debug_log_hex(c"system DLL map prot=".as_ptr(), prot as u64);
        debug_log_hex(c"system DLL map flags=".as_ptr(), flags as u64);
    }
}

/// Bounded trace of reads of `ntdll.dll`/`win32u.dll` in the game process.
///
/// # Safety
/// Only calls libc and the runtime's exported debug logger.
#[cfg(all(not(test), feature = "debug"))]
unsafe fn trace_system_dll_read(
    kind: &'static core::ffi::CStr,
    fd: c_int,
    length: usize,
    offset: i64,
) {
    static READ_EVENTS: AtomicU64 = AtomicU64::new(0);
    if unsafe { debug_enabled() } == 0 || length < 0x100 {
        return;
    }
    #[cfg(feature = "environment")]
    if !crate::environment::game_process() {
        return;
    }
    let _errno = crate::errno::Errno::save();
    let mut path = [0u8; 256];
    let length_of_path = unsafe { fd_path(fd, &mut path) };
    let path_bytes = &path[..length_of_path];
    if !(path_bytes.ends_with(b"/ntdll.dll") || path_bytes.ends_with(b"/win32u.dll")) {
        return;
    }
    if READ_EVENTS.fetch_add(1, Ordering::Relaxed) >= 32 {
        return;
    }
    unsafe {
        debug_log(c"system DLL file read".as_ptr());
        debug_log(kind.as_ptr());
        debug_log(path.as_ptr().cast());
        debug_log_hex(c"system DLL read length=".as_ptr(), length as u64);
        debug_log_hex(c"system DLL read offset=".as_ptr(), offset as u64);
    }
}

/// Log a rewrite with the path behind `fd` (from `/proc/self/fd`).
///
/// # Safety
/// Only calls libc and the runtime's exported debug logger.
#[cfg(all(not(test), feature = "debug"))]
unsafe fn log_rewrite(kind: &'static core::ffi::CStr, fd: c_int, rewritten: usize) {
    let mut link = *b"/proc/self/fd/\0\0\0\0\0\0\0\0\0\0\0\0";
    let mut digits = [0u8; 10];
    let mut value = fd.max(0) as u32;
    let mut start = digits.len();
    loop {
        start -= 1;
        digits[start] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    let prefix = b"/proc/self/fd/".len();
    link[prefix..prefix + digits.len() - start].copy_from_slice(&digits[start..]);
    let mut path = [0u8; 256];
    let length = unsafe {
        libc::readlink(
            link.as_ptr().cast(),
            path.as_mut_ptr().cast(),
            path.len() - 1,
        )
    };
    unsafe {
        debug_log(kind.as_ptr());
        if length > 0 {
            path[length as usize] = 0;
            debug_log(path.as_ptr().cast());
        }
        debug_log_hex(c"thunks rewritten=".as_ptr(), rewritten as u64);
    }
}

fn rewrite_complete_pe_read(buffer: &mut [u8]) -> usize {
    if buffer.len() < MIN_FILE_READ as usize || !looks_like_pe_file(buffer) {
        return 0;
    }
    rewrite_syscall_thunk_tails(buffer)
}

#[cfg(test)]
mod tests {
    #[cfg(not(miri))]
    use super::rewrite_pe_view;
    use super::{IMAGE_COPIES, IMAGE_TRACK_SLOTS, ImageCopies, pe_size_of_image};
    use super::{
        MIN_FILE_READ, THUNK_LEN, WINDOWS_TAIL, count_pending_thunk_tails, looks_like_pe_file,
        rewrite_complete_pe_read, rewrite_syscall_thunk_tails,
    };
    use core::sync::atomic::AtomicU64;
    #[cfg(not(miri))]
    use std::io::Write;
    #[cfg(not(miri))]
    use std::os::fd::AsRawFd;

    /// A syscall thunk head + SystemCall branch (the OS-ABI-level part every
    /// Wine build must reproduce), followed by an arbitrary `tail` standing
    /// in for whatever a given Wine/Proton build chooses to put there.
    fn thunk(service: u32, tail: &[u8; THUNK_LEN - 0x15]) -> [u8; THUNK_LEN] {
        let mut bytes = [0u8; THUNK_LEN];
        bytes[..4].copy_from_slice(&[0x4c, 0x8b, 0xd1, 0xb8]);
        bytes[4..8].copy_from_slice(&service.to_le_bytes());
        bytes[8..0x15].copy_from_slice(&[
            0xf6, 0x04, 0x25, 0x08, 0x03, 0xfe, 0x7f, 0x01, 0x75, 0x03, 0x0f, 0x05, 0xc3,
        ]);
        bytes[0x15..].copy_from_slice(tail);
        bytes
    }

    fn windows_stub(service: u32) -> [u8; THUNK_LEN] {
        thunk(service, &WINDOWS_TAIL)
    }

    /// Distinct, made-up tails representing different Wine/Proton builds'
    /// own choice of "what replaces INT 2E". None of these are matched
    /// against by name; the rewrite must work on all of them purely from the
    /// head+branch signature.
    const WINE_11_7_TAIL: [u8; THUNK_LEN - 0x15] = [
        0xeb, 0x01, 0xc3, 0xff, 0x14, 0x25, 0x00, 0x10, 0xfe, 0x7f, 0xc3,
    ];
    const HYPOTHETICAL_OTHER_BUILD_TAIL: [u8; THUNK_LEN - 0x15] = [
        0xff, 0x25, 0x00, 0x20, 0xfe, 0x7f, 0x00, 0x90, 0x90, 0x90, 0x90,
    ];

    #[test]
    fn any_wine_builds_tail_is_rewritten_to_the_windows_tail() {
        for tail in [
            WINE_11_7_TAIL,
            HYPOTHETICAL_OTHER_BUILD_TAIL,
            [0xcc; THUNK_LEN - 0x15],
        ] {
            for service in [0x10, 0xf, 0x6] {
                let mut bytes = thunk(service, &tail);
                assert_eq!(rewrite_syscall_thunk_tails(&mut bytes), 1);
                assert_eq!(bytes, windows_stub(service));
            }
        }
    }

    #[test]
    fn a_thunk_already_carrying_the_windows_tail_is_left_alone_and_not_counted() {
        let mut bytes = windows_stub(0x10);
        let original = bytes;
        assert_eq!(rewrite_syscall_thunk_tails(&mut bytes), 0);
        assert_eq!(bytes, original);
    }

    #[test]
    fn rewriting_is_idempotent() {
        let mut bytes = thunk(0x10, &WINE_11_7_TAIL);
        assert_eq!(rewrite_syscall_thunk_tails(&mut bytes), 1);
        assert_eq!(rewrite_syscall_thunk_tails(&mut bytes), 0);
        assert_eq!(bytes, windows_stub(0x10));
    }

    #[test]
    fn adjacent_thunks_with_different_tails_are_all_rewritten() {
        let mut bytes = [0x90u8; 0x100];
        let thunks: [(usize, u32, &[u8; THUNK_LEN - 0x15]); 3] = [
            (0x13, 0x6, &WINE_11_7_TAIL),
            (0x33, 0x7, &HYPOTHETICAL_OTHER_BUILD_TAIL),
            (0x80, 0x10, &WINDOWS_TAIL),
        ];
        for &(offset, service, tail) in &thunks {
            bytes[offset..offset + THUNK_LEN].copy_from_slice(&thunk(service, tail));
        }
        let mut expected = bytes;
        for &(offset, service, _) in &thunks {
            expected[offset..offset + THUNK_LEN].copy_from_slice(&windows_stub(service));
        }
        // Only the first two actually change; the third already carries the
        // Windows tail.
        assert_eq!(rewrite_syscall_thunk_tails(&mut bytes), 2);
        assert_eq!(bytes, expected);
    }

    #[test]
    fn near_misses_are_left_alone() {
        let mut wrong_branch = thunk(0x10, &WINE_11_7_TAIL);
        wrong_branch[0x11] = 0x04;
        let original = wrong_branch;
        assert_eq!(rewrite_syscall_thunk_tails(&mut wrong_branch), 0);
        assert_eq!(wrong_branch, original);

        let mut wrong_head = thunk(0x10, &WINE_11_7_TAIL);
        wrong_head[0] = 0x90;
        assert_eq!(rewrite_syscall_thunk_tails(&mut wrong_head), 0);

        let mut truncated = thunk(0x10, &WINE_11_7_TAIL)[..THUNK_LEN - 1].to_vec();
        let original = truncated.clone();
        assert_eq!(rewrite_syscall_thunk_tails(&mut truncated), 0);
        assert_eq!(truncated, original);
    }

    #[test]
    fn pe_file_detection_requires_a_contained_pe_signature() {
        let mut image = vec![0u8; 0x200];
        image[..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        image[0x80..0x84].copy_from_slice(b"PE\0\0");
        assert!(looks_like_pe_file(&image));

        assert!(!looks_like_pe_file(&image[..0x3f]));
        assert!(!looks_like_pe_file(&image[..0x82]));
        let mut bad_offset = image.clone();
        bad_offset[0x3c..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(!looks_like_pe_file(&bad_offset));
        let mut not_mz = image.clone();
        not_mz[0] = b'X';
        assert!(!looks_like_pe_file(&not_mz));
        let mut not_pe = image;
        not_pe[0x81] = b'X';
        assert!(!looks_like_pe_file(&not_pe));
    }

    #[test]
    fn only_complete_pe_reads_rewrite_thunk_tails() {
        let mut full_read = vec![0u8; MIN_FILE_READ as usize];
        full_read[..2].copy_from_slice(b"MZ");
        full_read[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        full_read[0x80..0x84].copy_from_slice(b"PE\0\0");
        let offset = 0x200;
        full_read[offset..offset + THUNK_LEN].copy_from_slice(&thunk(0x6, &WINE_11_7_TAIL));

        assert_eq!(rewrite_complete_pe_read(&mut full_read), 1);
        assert_eq!(&full_read[offset..offset + THUNK_LEN], &windows_stub(0x6));

        let mut partial = full_read[..MIN_FILE_READ as usize - 1].to_vec();
        partial[offset..offset + THUNK_LEN].copy_from_slice(&thunk(0x6, &WINE_11_7_TAIL));
        let original = partial.clone();
        assert_eq!(rewrite_complete_pe_read(&mut partial), 0);
        assert_eq!(partial, original);

        let mut non_pe = vec![0u8; MIN_FILE_READ as usize];
        non_pe[offset..offset + THUNK_LEN].copy_from_slice(&thunk(0x6, &WINE_11_7_TAIL));
        let original = non_pe.clone();
        assert_eq!(rewrite_complete_pe_read(&mut non_pe), 0);
        assert_eq!(non_pe, original);
    }

    /// A minimal PE file (`MZ`, `e_lfanew`, `PE\0\0`) with Wine-tailed thunks.
    fn fake_dll(size: usize, thunk_offsets: &[usize]) -> Vec<u8> {
        let mut image = vec![0u8; size];
        image[..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        image[0x80..0x84].copy_from_slice(b"PE\0\0");
        for (index, &offset) in thunk_offsets.iter().enumerate() {
            image[offset..offset + THUNK_LEN]
                .copy_from_slice(&thunk(0x10 + index as u32, &WINE_11_7_TAIL));
        }
        image
    }

    #[cfg(not(miri))]
    fn map_file(file: &std::fs::File, length: usize, prot: libc::c_int) -> *mut libc::c_void {
        let view = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                length,
                prot,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                0,
            )
        };
        assert_ne!(view, libc::MAP_FAILED);
        view
    }

    #[test]
    fn pending_count_ignores_thunks_that_already_have_the_windows_tail() {
        let mut image = fake_dll(0x8000, &[0x1000, 0x2000]);
        assert_eq!(count_pending_thunk_tails(&image), 2);
        image[0x2000..0x2000 + THUNK_LEN].copy_from_slice(&windows_stub(0x11));
        assert_eq!(count_pending_thunk_tails(&image), 1);
    }

    // Miri's default isolation intentionally forbids filesystem I/O and
    // cannot model the file-backed mmap used by this integration test.
    #[cfg(not(miri))]
    #[test]
    fn data_view_gets_windows_tails_without_touching_the_file() {
        let image = fake_dll(0x8000, &[0x1000, 0x2400]);
        let path = std::env::temp_dir().join(format!("linuwux-pe-view-{}.dll", std::process::id()));
        std::fs::File::create(&path)
            .unwrap()
            .write_all(&image)
            .unwrap();
        let file = std::fs::File::open(&path).unwrap();

        let view = map_file(&file, image.len(), libc::PROT_READ);
        let rewritten = unsafe {
            rewrite_pe_view(
                file.as_raw_fd(),
                view,
                image.len(),
                image.len(),
                libc::PROT_READ,
                core::ptr::null_mut(),
            )
        };
        assert_eq!(rewritten, 2);
        let mapped = unsafe { core::slice::from_raw_parts(view.cast::<u8>(), image.len()) };
        assert_eq!(&mapped[0x1000..0x1000 + THUNK_LEN], &windows_stub(0x10));
        assert_eq!(&mapped[0x2400..0x2400 + THUNK_LEN], &windows_stub(0x11));
        // The rest of the view is untouched, and the file on disk is unchanged.
        assert_eq!(&mapped[..0x1000], &image[..0x1000]);
        assert_eq!(std::fs::read(&path).unwrap(), image);
        unsafe { libc::munmap(view, image.len()) };

        // A second view of the same file is unaffected by the first.
        let again = map_file(&file, image.len(), libc::PROT_READ);
        let untouched = unsafe { core::slice::from_raw_parts(again.cast::<u8>(), image.len()) };
        assert_eq!(untouched, &image[..]);
        unsafe { libc::munmap(again, image.len()) };
        std::fs::remove_file(path).ok();
    }

    #[cfg(not(miri))]
    #[test]
    fn data_view_of_a_non_pe_or_clean_file_is_left_mapped_as_is() {
        let path = std::env::temp_dir().join(format!("linuwux-not-pe-{}.bin", std::process::id()));
        let mut data = fake_dll(0x8000, &[0x1000]);
        data[0] = b'X';
        std::fs::File::create(&path)
            .unwrap()
            .write_all(&data)
            .unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let view = map_file(&file, data.len(), libc::PROT_READ);
        let rewritten = unsafe {
            rewrite_pe_view(
                file.as_raw_fd(),
                view,
                data.len(),
                data.len(),
                libc::PROT_READ,
                core::ptr::null_mut(),
            )
        };
        assert_eq!(rewritten, 0);
        unsafe { libc::munmap(view, data.len()) };

        let clean = fake_dll(0x8000, &[]);
        std::fs::File::create(&path)
            .unwrap()
            .write_all(&clean)
            .unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let view = map_file(&file, clean.len(), libc::PROT_READ);
        let rewritten = unsafe {
            rewrite_pe_view(
                file.as_raw_fd(),
                view,
                clean.len(),
                clean.len(),
                libc::PROT_READ,
                core::ptr::null_mut(),
            )
        };
        assert_eq!(rewritten, 0);
        unsafe { libc::munmap(view, clean.len()) };
        std::fs::remove_file(path).ok();
    }

    fn fresh_tracker() -> ImageCopies {
        ImageCopies {
            device: [const { AtomicU64::new(0) }; IMAGE_TRACK_SLOTS],
            inode: [const { AtomicU64::new(0) }; IMAGE_TRACK_SLOTS],
            copy_start: [const { AtomicU64::new(0) }; IMAGE_TRACK_SLOTS],
            copy_end: [const { AtomicU64::new(0) }; IMAGE_TRACK_SLOTS],
        }
    }

    #[test]
    fn first_image_of_a_file_is_the_process_own_load_and_later_ones_are_copies() {
        let images = fresh_tracker();
        // Wine's own load: not a copy, and its sections are never rewritten.
        assert!(!images.note_header(7, 100, 0x6fff_ffef_0000, 0xb9000));
        assert!(!images.in_copy(7, 100, 0x6fff_ffef_1000, 0x77000));
        // A second private image of the same file is a copy; only addresses
        // inside it qualify, and a different device or inode never does.
        assert!(images.note_header(7, 100, 0x7fff_ff06_0000, 0xb9000));
        assert!(images.in_copy(7, 100, 0x7fff_ff0d_8000, 0x5000));
        assert!(!images.in_copy(7, 100, 0x6fff_ffef_1000, 0x77000));
        assert!(!images.in_copy(7, 100, 0x7fff_ff11_8000, 0x9000));
        assert!(!images.in_copy(8, 100, 0x7fff_ff0d_8000, 0x5000));
        assert!(!images.in_copy(7, 101, 0x7fff_ff0d_8000, 0x5000));
        // Mapping another copy moves the tracked range to the new one.
        assert!(images.note_header(7, 100, 0x7fff_fee0_0000, 0xb9000));
        assert!(!images.in_copy(7, 100, 0x7fff_ff0d_8000, 0x5000));
        assert!(images.in_copy(7, 100, 0x7fff_fee7_8000, 0x5000));
    }

    #[test]
    fn size_of_image_is_read_from_the_optional_header() {
        let mut header = fake_dll(0x1000, &[]);
        header[0x80 + 24 + 56..0x80 + 24 + 60].copy_from_slice(&0xb9000u32.to_le_bytes());
        assert_eq!(pe_size_of_image(&header), Some(0xb9000));
        assert_eq!(pe_size_of_image(&header[..0x40]), None);
        let _ = &IMAGE_COPIES;
    }
}
