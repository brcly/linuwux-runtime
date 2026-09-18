use core::ffi::{c_char, c_int, c_void};
use core::mem::{MaybeUninit, size_of};
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering};
use linuwux::faketime::{apply_offset, offset_from_filetime};

// 1337 is outside the default max file descriptors :(
const OFFSET_RECV_FD: c_int = 67;
const OFFSET_SEND_FD: c_int = 69;
static SOCKETPAIR_INITIALIZED: AtomicBool = AtomicBool::new(false);
// Only set once init_socketpair() has confirmed the fds are safe to use as
// our own socket pair; gates every later read/write so a fd collision with
// something unrelated never gets clobbered or corrupted.
static SOCKETPAIR_READY: AtomicBool = AtomicBool::new(false);

type Gettimeofday = unsafe extern "C" fn(*mut libc::timeval, *mut c_void) -> c_int;
static REAL_GETTIMEOFDAY: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static OFFSET: AtomicU64 = AtomicU64::new(0);

unsafe extern "C" {
    fn debug_log(message: *const c_char);
    fn debug_log_hex(prefix: *const c_char, value: u64);
}

static LOGGED_CURRENT_OFFSET: AtomicBool = AtomicBool::new(false);
static LOGGED_APPLY: AtomicBool = AtomicBool::new(false);

fn resolve_real_gettimeofday() -> Option<Gettimeofday> {
    let mut symbol = REAL_GETTIMEOFDAY.load(Ordering::Acquire);
    if symbol.is_null() {
        symbol = unsafe { libc::dlsym(libc::RTLD_NEXT, c"gettimeofday".as_ptr()) };
        if symbol.is_null() {
            unsafe { *libc::__errno_location() = libc::ENOSYS };
            return None;
        }
        REAL_GETTIMEOFDAY.store(symbol, Ordering::Release);
    }
    Some(unsafe { core::mem::transmute::<*mut c_void, Gettimeofday>(symbol) })
}

fn loaded_real_gettimeofday() -> Option<Gettimeofday> {
    let symbol = REAL_GETTIMEOFDAY.load(Ordering::Acquire);
    (!symbol.is_null())
        .then(|| unsafe { core::mem::transmute::<*mut c_void, Gettimeofday>(symbol) })
}

fn fd_is_socket(fd: c_int) -> bool {
    let mut socket_type: c_int = 0;
    let mut len = size_of::<c_int>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&raw mut socket_type).cast(),
            &raw mut len,
        )
    };
    result == 0
}

fn fd_is_open(fd: c_int) -> bool {
    unsafe { libc::fcntl(fd, libc::F_GETFD) != -1 }
}

// Only init sockets once; if fds 67/69 are already valid sockets (inherited
// from a parent across fork/exec), reuse them instead of creating new ones.
// If either fd is already open for something unrelated, leave it alone
// entirely rather than risk stealing/corrupting someone else's descriptor.
fn init_socketpair() {
    if SOCKETPAIR_INITIALIZED.swap(true, Ordering::AcqRel) {
        return;
    }
    let recv_is_socket = fd_is_socket(OFFSET_RECV_FD);
    let send_is_socket = fd_is_socket(OFFSET_SEND_FD);
    if recv_is_socket && send_is_socket {
        SOCKETPAIR_READY.store(true, Ordering::Release);
        return;
    }
    if (!recv_is_socket && fd_is_open(OFFSET_RECV_FD))
        || (!send_is_socket && fd_is_open(OFFSET_SEND_FD))
    {
        unsafe {
            debug_log(
                c"faketime socketpair fds already in use by something else; skipping".as_ptr(),
            )
        };
        return;
    }
    let mut fds = [0 as c_int; 2];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK,
            0,
            fds.as_mut_ptr(),
        )
    } == -1
    {
        return;
    }
    let [recv_fd, send_fd] = fds;
    if unsafe { libc::dup2(recv_fd, OFFSET_RECV_FD) } == -1
        || unsafe { libc::dup2(send_fd, OFFSET_SEND_FD) } == -1
    {
        unsafe {
            libc::close(recv_fd);
            libc::close(send_fd);
        }
        return;
    }
    if recv_fd != OFFSET_RECV_FD && recv_fd != OFFSET_SEND_FD {
        unsafe { libc::close(recv_fd) };
    }
    if send_fd != OFFSET_RECV_FD && send_fd != OFFSET_SEND_FD {
        unsafe { libc::close(send_fd) };
    }
    SOCKETPAIR_READY.store(true, Ordering::Release);
}

fn current_offset() -> u64 {
    let local = OFFSET.load(Ordering::Acquire);
    if local != 0 {
        return local;
    }
    if !SOCKETPAIR_READY.load(Ordering::Acquire) {
        if !LOGGED_CURRENT_OFFSET.swap(true, Ordering::AcqRel) {
            unsafe {
                debug_log(
                    c"faketime current_offset source=local (socketpair unavailable)".as_ptr(),
                );
                debug_log_hex(c"faketime current_offset value=".as_ptr(), local);
            }
        }
        return local;
    }
    let mut received: u64 = 0;
    let result = unsafe {
        libc::recv(
            OFFSET_RECV_FD,
            (&raw mut received).cast(),
            size_of::<u64>(),
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
    };
    if result == size_of::<u64>() as isize {
        OFFSET.store(received, Ordering::Release);
        if !LOGGED_CURRENT_OFFSET.swap(true, Ordering::AcqRel) {
            unsafe {
                debug_log(c"faketime current_offset source=socketpair".as_ptr());
                debug_log_hex(c"faketime current_offset value=".as_ptr(), received);
            }
        }
        return received;
    }
    if !LOGGED_CURRENT_OFFSET.swap(true, Ordering::AcqRel) {
        unsafe {
            debug_log(c"faketime current_offset source=local (no socket value)".as_ptr());
            debug_log_hex(c"faketime current_offset value=".as_ptr(), local);
        }
    }
    local
}

unsafe fn adjust_seconds(tv: *mut libc::timeval, offset: u64) {
    unsafe {
        let seconds = ptr::addr_of_mut!((*tv).tv_sec);
        seconds.write(apply_offset(seconds.read(), offset));
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn gettimeofday(tv: *mut libc::timeval, tz: *mut c_void) -> c_int {
    let Some(real) = resolve_real_gettimeofday() else {
        return -1;
    };
    let result = unsafe { real(tv, tz) };
    if result != 0 || tv.is_null() {
        return result;
    }
    let _errno = crate::errno::Errno::save();
    let offset = current_offset();
    let log_this_call = offset != 0 && !LOGGED_APPLY.swap(true, Ordering::AcqRel);
    let real_secs = log_this_call.then(|| unsafe { ptr::addr_of!((*tv).tv_sec).read() });
    unsafe { adjust_seconds(tv, offset) };
    if let Some(real_secs) = real_secs {
        unsafe {
            debug_log_hex(
                c"faketime gettimeofday real_secs=".as_ptr(),
                real_secs as u64,
            );
            debug_log_hex(c"faketime gettimeofday applied_offset=".as_ptr(), offset);
            debug_log_hex(
                c"faketime gettimeofday adjusted_secs=".as_ptr(),
                ptr::addr_of!((*tv).tv_sec).read() as u64,
            );
        }
    }
    result
}

#[unsafe(no_mangle)]
pub extern "C" fn set_offset(filetime: u64) {
    let _errno = crate::errno::Errno::save();
    let Some(_guard) = crate::page_guard::PageGuard::acquire() else {
        unsafe { debug_log(c"faketime update busy; retry the command".as_ptr()) };
        return;
    };
    let Some(real) = loaded_real_gettimeofday() else {
        unsafe { debug_log(c"failed to read faketime clock".as_ptr()) };
        return;
    };
    let mut now = MaybeUninit::<libc::timeval>::uninit();
    if unsafe { real(now.as_mut_ptr(), ptr::null_mut()) } != 0 {
        unsafe { debug_log(c"failed to read faketime clock".as_ptr()) };
        return;
    }
    let seconds = unsafe { ptr::addr_of!((*now.as_ptr()).tv_sec).read() };
    unsafe {
        debug_log_hex(c"faketime set_offset filetime=".as_ptr(), filetime);
        debug_log_hex(
            c"faketime set_offset real_now_secs=".as_ptr(),
            seconds as u64,
        );
    }
    let offset = offset_from_filetime(seconds, filetime);
    unsafe { debug_log_hex(c"faketime set_offset computed_offset=".as_ptr(), offset) };
    OFFSET.store(offset, Ordering::Release);
    if !SOCKETPAIR_READY.load(Ordering::Acquire) {
        unsafe {
            debug_log(
                c"faketime set_offset socketpair unavailable; offset stays local-only".as_ptr(),
            )
        };
        return;
    }
    let written = unsafe {
        libc::write(
            OFFSET_SEND_FD,
            (&raw const offset).cast::<c_void>(),
            size_of::<u64>(),
        )
    };
    unsafe {
        debug_log(if written == size_of::<u64>() as isize {
            c"faketime set_offset published via socketpair".as_ptr()
        } else {
            c"faketime set_offset socketpair publish failed".as_ptr()
        })
    };
}

#[unsafe(no_mangle)]
pub extern "C" fn linuwux_setup_faketime() {
    let _ = resolve_real_gettimeofday();
    init_socketpair();
}

#[used]
#[unsafe(link_section = ".init_array.00202")]
static INITIALIZE: extern "C" fn() = linuwux_setup_faketime;
