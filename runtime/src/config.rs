use core::sync::atomic::{AtomicBool, Ordering};

static REDIRECT_ALL: AtomicBool = AtomicBool::new(false);

pub(crate) fn redirect_all() -> bool {
    REDIRECT_ALL.load(Ordering::Acquire)
}

unsafe extern "C" fn initialize() {
    let value = unsafe { libc::getenv(c"LINUWUX_REDIRECT_ALL".as_ptr()) };
    let enabled = !value.is_null()
        && linuwux::cpuid::redirect_all_enabled(Some(
            unsafe { core::ffi::CStr::from_ptr(value) }.to_bytes(),
        ));
    REDIRECT_ALL.store(enabled, Ordering::Release);
}

#[used]
#[unsafe(link_section = ".init_array.00202")]
static INITIALIZE: unsafe extern "C" fn() = initialize;
