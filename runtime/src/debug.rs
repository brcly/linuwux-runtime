use core::ffi::{CStr, c_char, c_int};
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use linuwux::debug::Line;

static ENABLED: AtomicBool = AtomicBool::new(false);
static LOG_FD: AtomicI32 = AtomicI32::new(-1);
static OPEN_ERRNO: AtomicI32 = AtomicI32::new(0);
static STDERR_SUPPORTED: AtomicBool = AtomicBool::new(false);

#[cfg_attr(not(test), unsafe(no_mangle))]
pub extern "C" fn debug_enabled() -> c_int {
    c_int::from(ENABLED.load(Ordering::Acquire))
}

fn new_line() -> Line {
    let (tid, pid) = unsafe { (libc::syscall(libc::SYS_gettid), libc::getpid()) };
    Line::new(pid as u64, (tid > 0).then_some(tid as u64))
}

unsafe fn append_text(line: &mut Line, mut text: *const c_char) {
    if text.is_null() {
        return;
    }
    while line.remaining() != 0 {
        let byte = unsafe { text.read() as u8 };
        if byte == 0 {
            break;
        }
        line.push(byte);
        text = unsafe { text.add(1) };
    }
}

fn emit(bytes: &[u8]) {
    if debug_enabled() == 0 || bytes.is_empty() {
        return;
    }
    let fd = LOG_FD.load(Ordering::Acquire);
    unsafe {
        if fd >= 0 {
            libc::write(fd, bytes.as_ptr().cast(), bytes.len());
        }
        if STDERR_SUPPORTED.load(Ordering::Acquire) {
            libc::write(libc::STDERR_FILENO, bytes.as_ptr().cast(), bytes.len());
        }
    }
}

fn regular_file(fd: c_int) -> bool {
    let mut status = MaybeUninit::<libc::stat>::uninit();
    unsafe {
        libc::fstat(fd, status.as_mut_ptr()) == 0
            && (status.assume_init().st_mode & libc::S_IFMT) == libc::S_IFREG
    }
}

fn supported_stderr() -> bool {
    let mut status = MaybeUninit::<libc::stat>::uninit();
    unsafe {
        libc::fstat(libc::STDERR_FILENO, status.as_mut_ptr()) == 0
            && matches!(
                status.assume_init().st_mode & libc::S_IFMT,
                libc::S_IFREG | libc::S_IFCHR
            )
    }
}

unsafe fn open_log(path: *const c_char) -> c_int {
    let fd = unsafe {
        libc::open(
            path,
            libc::O_WRONLY
                | libc::O_CREAT
                | libc::O_APPEND
                | libc::O_CLOEXEC
                | libc::O_NOFOLLOW
                | libc::O_NONBLOCK,
            0o600 as libc::mode_t,
        )
    };
    if fd < 0 {
        return -1;
    }
    if !regular_file(fd) {
        unsafe {
            libc::close(fd);
            *libc::__errno_location() = libc::EINVAL;
        }
        return -1;
    }
    if unsafe { libc::fchmod(fd, 0o600 as libc::mode_t) } != 0 {
        let error = unsafe { *libc::__errno_location() };
        unsafe {
            libc::close(fd);
            *libc::__errno_location() = error;
        }
        return -1;
    }
    fd
}

#[cfg_attr(not(test), unsafe(no_mangle))]
pub unsafe extern "C" fn debug_log(message: *const c_char) {
    let _errno = crate::errno::Errno::save();
    if debug_enabled() == 0 || message.is_null() {
        return;
    }
    let mut line = new_line();
    unsafe { append_text(&mut line, message) };
    emit(line.finish(false));
}

#[cfg_attr(not(test), unsafe(no_mangle))]
pub unsafe extern "C" fn debug_log_hex(prefix: *const c_char, value: u64) {
    let _errno = crate::errno::Errno::save();
    if debug_enabled() == 0 {
        return;
    }
    let mut line = new_line();
    unsafe { append_text(&mut line, prefix) };
    line.append(b"0x");
    line.number(value, true);
    emit(line.finish(true));
}

#[cfg_attr(not(test), unsafe(no_mangle))]
pub unsafe extern "C" fn debug_log_dec(prefix: *const c_char, value: u64) {
    let _errno = crate::errno::Errno::save();
    if debug_enabled() == 0 {
        return;
    }
    let mut line = new_line();
    unsafe { append_text(&mut line, prefix) };
    line.number(value, false);
    emit(line.finish(true));
}

#[cfg_attr(not(test), unsafe(no_mangle))]
pub extern "C" fn debug_runtime_activated() {
    unsafe {
        debug_log(c"safe debug logging enabled".as_ptr());
        if LOG_FD.load(Ordering::Acquire) >= 0 {
            debug_log(c"dedicated debug log enabled".as_ptr());
        } else {
            let error = OPEN_ERRNO.load(Ordering::Acquire);
            if error != 0 {
                debug_log_dec(c"dedicated debug log open errno=".as_ptr(), error as u64);
            }
        }
    }
}

#[cfg_attr(not(test), unsafe(no_mangle))]
pub unsafe extern "C" fn linuwux_setup_debug() {
    unsafe {
        let value = libc::getenv(c"LINUWUX_DEBUG".as_ptr());
        let path = libc::getenv(c"LINUWUX_LOG".as_ptr());
        let enabled = linuwux::debug::enabled(if value.is_null() {
            None
        } else {
            Some(CStr::from_ptr(value).to_bytes())
        });
        if !enabled {
            return;
        }
        STDERR_SUPPORTED.store(supported_stderr(), Ordering::Release);
        if !path.is_null() && path.read() != 0 {
            let fd = open_log(path);
            LOG_FD.store(fd, Ordering::Release);
            if fd < 0 {
                OPEN_ERRNO.store(*libc::__errno_location(), Ordering::Release);
            }
        }
        ENABLED.store(true, Ordering::Release);
    }
}

#[cfg(not(test))]
#[used]
#[unsafe(link_section = ".init_array.00102")]
static INITIALIZE: unsafe extern "C" fn() = linuwux_setup_debug;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_message_does_not_read_past_capacity() {
        let mut line = Line::new(1, None);
        let bytes = vec![b'x'; line.remaining()];
        unsafe { append_text(&mut line, bytes.as_ptr().cast()) };
        assert_eq!(line.finish(false).len(), 512);
    }
}
