use core::ffi::{CStr, c_char, c_int};
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};
use linuwux::kuser::{PAGE_SIZE, PatchError, PatchState, Profile};

const ADDRESS: usize = 0x7ffe_0000;
static PAGE_GEOMETRY_SUPPORTED: AtomicBool = AtomicBool::new(false);
static AVX_ENABLED: AtomicBool = AtomicBool::new(false);
static PATCH_STATE: PatchState = PatchState::new();

pub(crate) fn recover_patch_after_fork() {
    PATCH_STATE.recover_after_fork();
}

#[cfg(feature = "faketime")]
#[path = "shared_time.rs"]
mod shared_time;
#[cfg(feature = "faketime")]
pub(crate) use shared_time::{PublishError, read_shared_time_offset, write_shared_time_offset};

unsafe extern "C" {
    fn debug_log(message: *const c_char);
}

fn log(message: &'static CStr) {
    unsafe { debug_log(message.as_ptr()) };
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn kuser_apply_to_buffer(
    page: *mut u8,
    length: usize,
    profile: c_int,
    avx_enabled: c_int,
) -> c_int {
    if page.is_null() || length < PAGE_SIZE {
        return -1;
    }
    let Some(profile) = Profile::from_raw(profile) else {
        return -1;
    };
    profile.visit_writes(avx_enabled != 0, |offset, byte| {
        unsafe { page.add(offset).write_volatile(byte) };
    });
    0
}

unsafe fn apply_profile_to_shared_page(
    profile: Profile,
    _guard: &crate::page_guard::PageGuard,
) -> bool {
    if !PAGE_GEOMETRY_SUPPORTED.load(Ordering::Acquire) {
        log(c"KUSER patch requires a 4096-byte base page");
        return false;
    }
    #[cfg(feature = "faketime")]
    if !shared_time::shared_page_available_for_write() {
        log(c"KUSER patch requires Wine's shared KUSER mapping");
        return false;
    }
    let page = ptr::with_exposed_provenance_mut::<u8>(ADDRESS);
    if unsafe {
        libc::syscall(
            libc::SYS_mprotect,
            page,
            PAGE_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
        )
    } == -1
    {
        log(c"failed to make KUSER_SHARED_DATA writable");
        return false;
    }
    let apply_result = unsafe {
        kuser_apply_to_buffer(
            page,
            PAGE_SIZE,
            profile as c_int,
            AVX_ENABLED.load(Ordering::Acquire) as c_int,
        )
    };
    if unsafe { libc::syscall(libc::SYS_mprotect, page, PAGE_SIZE, libc::PROT_READ) } == -1 {
        log(c"failed to restore KUSER_SHARED_DATA read-only protection");
        return false;
    }
    if apply_result == -1 {
        log(c"failed to apply KUSER_SHARED_DATA profile");
    }
    apply_result == 0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn patch_kuser_shared_data_profile(profile: c_int) -> c_int {
    let Some(profile) = Profile::from_raw(profile) else {
        return -1;
    };
    let _errno = crate::errno::Errno::save();
    let Some(_guard) = crate::page_guard::PageGuard::acquire() else {
        return -1;
    };
    match PATCH_STATE.patch(
        profile,
        || unsafe { apply_profile_to_shared_page(profile, &_guard) },
        || {
            unsafe { libc::syscall(libc::SYS_sched_yield) };
        },
    ) {
        Ok(()) => 0,
        Err(PatchError::ApplyFailed) => -1,
        Err(PatchError::Conflict) => {
            log(c"KUSER profile conflicts with the selected protocol");
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn patch_kuser_shared_data() -> c_int {
    unsafe { patch_kuser_shared_data_profile(Profile::Modern as c_int) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn linuwux_setup_kuser() {
    let avx = unsafe {
        let avx_value = libc::getenv(c"PROTON_AVX".as_ptr());
        !avx_value.is_null() && CStr::from_ptr(avx_value).to_bytes() == b"1"
    };
    let supported = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } == PAGE_SIZE as libc::c_long;
    PAGE_GEOMETRY_SUPPORTED.store(supported, Ordering::Release);
    AVX_ENABLED.store(avx, Ordering::Release);
}

#[cfg(not(test))]
#[used]
#[unsafe(link_section = ".init_array.00204")]
static INITIALIZE: unsafe extern "C" fn() = linuwux_setup_kuser;
