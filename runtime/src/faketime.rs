use core::ffi::{c_char, c_int, c_void};
use core::mem::MaybeUninit;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering};
use linuwux::faketime::{apply_offset, offset_from_filetime};

use crate::kuser::{PublishError, read_shared_time_offset, write_shared_time_offset};

type Gettimeofday = unsafe extern "C" fn(*mut libc::timeval, *mut c_void) -> c_int;
static REAL_GETTIMEOFDAY: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static OFFSET: AtomicU64 = AtomicU64::new(0);
static FAILED_SHARED: AtomicU64 = AtomicU64::new(0);
static LOCAL_OVERRIDE: AtomicBool = AtomicBool::new(false);

unsafe extern "C" {
    fn debug_log(message: *const c_char);
}

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

fn current_offset() -> u64 {
    let Some(shared) = read_shared_time_offset() else {
        return OFFSET.load(Ordering::Acquire);
    };
    if !LOCAL_OVERRIDE.load(Ordering::Acquire) {
        return shared;
    }
    if shared == FAILED_SHARED.load(Ordering::Acquire) {
        return OFFSET.load(Ordering::Acquire);
    }
    if let Some(_guard) = crate::page_guard::PageGuard::acquire()
        && let Some(latest) = read_shared_time_offset()
        && latest != FAILED_SHARED.load(Ordering::Acquire)
    {
        LOCAL_OVERRIDE.store(false, Ordering::Release);
        return latest;
    }
    shared
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
    unsafe { adjust_seconds(tv, current_offset()) };
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
    let offset = offset_from_filetime(seconds, filetime);
    FAILED_SHARED.store(read_shared_time_offset().unwrap_or(0), Ordering::Release);
    OFFSET.store(offset, Ordering::Release);
    let published = write_shared_time_offset(offset, &_guard);
    LOCAL_OVERRIDE.store(
        matches!(published, Err(PublishError::Unavailable)),
        Ordering::Release,
    );
    if let Err(error) = published {
        unsafe {
            debug_log(match error {
                PublishError::Unavailable => {
                    c"failed to publish faketime offset to other processes".as_ptr()
                }
                PublishError::ProtectionRestore => {
                    c"faketime offset published; read-only protection restore failed".as_ptr()
                }
            })
        };
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn linuwux_setup_faketime() {
    let _ = resolve_real_gettimeofday();
}

#[cfg(not(test))]
#[used]
#[unsafe(link_section = ".init_array.00202")]
static INITIALIZE: extern "C" fn() = linuwux_setup_faketime;
