use core::ffi::CStr;
use core::sync::atomic::{AtomicBool, Ordering};

static REDIRECT_ALL: AtomicBool = AtomicBool::new(false);
static SINGLE_DISPATCH: AtomicBool = AtomicBool::new(false);

pub(crate) fn redirect_all() -> bool {
    REDIRECT_ALL.load(Ordering::Acquire)
}

// Some titles (e.g. SMT5V's reflex64.dll) use the single-dispatch protocol
// but send an identical CPUID handshake to resume-target titles like FC6 -
// confirmed byte-for-byte identical handshake and driver-side redirect
// mechanism, so there's no observable signal to classify them correctly.
// Until a real trigger turns up, this is an explicit per-title opt-in set
// alongside the game's launch command, the same way LINUWUX_SYSCALL_HACK is.
pub(crate) fn single_dispatch_forced() -> bool {
    SINGLE_DISPATCH.load(Ordering::Acquire)
}

fn env_flag_set(name: &CStr) -> bool {
    let value = unsafe { libc::getenv(name.as_ptr()) };
    !value.is_null()
        && linuwux::cpuid::redirect_all_enabled(Some(
            unsafe { CStr::from_ptr(value) }.to_bytes(),
        ))
}

unsafe extern "C" fn initialize() {
    REDIRECT_ALL.store(env_flag_set(c"LINUWUX_REDIRECT_ALL"), Ordering::Release);
    SINGLE_DISPATCH.store(
        env_flag_set(c"LINUWUX_SINGLE_DISPATCH"),
        Ordering::Release,
    );
}

#[used]
#[unsafe(link_section = ".init_array.00202")]
static INITIALIZE: unsafe extern "C" fn() = initialize;
