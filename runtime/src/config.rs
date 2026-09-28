//! `LINUWUX_LEGACY_PROFILE` handling: a process-wide flag, read once at
//! startup, that forces the legacy CPU/KUSER presentation for the whole
//! process rather than letting `cpuid.rs`'s per-caller Reflex-image
//! detection decide it. Kept in its own tiny module (rather than inline in
//! `cpuid.rs`) because it's read from an `.init_array` constructor before
//! most other runtime state exists.
#[cfg(feature = "cpuid")]
use core::ffi::CStr;
#[cfg(feature = "cpuid")]
use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(feature = "cpuid")]
static LEGACY_PROFILE: AtomicBool = AtomicBool::new(false);

#[cfg(feature = "cpuid")]
pub(crate) fn legacy_profile_forced() -> bool {
    LEGACY_PROFILE.load(Ordering::Acquire)
}

#[cfg(feature = "cpuid")]
fn env_flag_set(name: &CStr) -> bool {
    let value = unsafe { libc::getenv(name.as_ptr()) };
    !value.is_null() && unsafe { CStr::from_ptr(value) }.to_bytes() == b"1"
}

unsafe extern "C" fn initialize() {
    #[cfg(feature = "cpuid")]
    LEGACY_PROFILE.store(env_flag_set(c"LINUWUX_LEGACY_PROFILE"), Ordering::Release);
}

#[used]
#[unsafe(link_section = ".init_array.00202")]
static INITIALIZE: unsafe extern "C" fn() = initialize;
