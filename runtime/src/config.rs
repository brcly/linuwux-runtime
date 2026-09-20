use core::ffi::CStr;
use core::sync::atomic::{AtomicBool, Ordering};

static REDIRECT_ALL: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "cpuid")]
static LEGACY_PROFILE: AtomicBool = AtomicBool::new(false);

pub(crate) fn redirect_all() -> bool {
    REDIRECT_ALL.load(Ordering::Acquire)
}

#[cfg(feature = "cpuid")]
pub(crate) fn legacy_profile_forced() -> bool {
    LEGACY_PROFILE.load(Ordering::Acquire)
}

fn env_flag_set(name: &CStr) -> bool {
    let value = unsafe { libc::getenv(name.as_ptr()) };
    !value.is_null()
        && linuwux::cpuid::redirect_all_enabled(Some(unsafe { CStr::from_ptr(value) }.to_bytes()))
}

unsafe extern "C" fn initialize() {
    REDIRECT_ALL.store(env_flag_set(c"LINUWUX_REDIRECT_ALL"), Ordering::Release);
    #[cfg(feature = "cpuid")]
    LEGACY_PROFILE.store(env_flag_set(c"LINUWUX_LEGACY_PROFILE"), Ordering::Release);
}

#[used]
#[unsafe(link_section = ".init_array.00202")]
static INITIALIZE: unsafe extern "C" fn() = initialize;
