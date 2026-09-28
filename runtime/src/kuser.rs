//! Owns the live `KUSER_SHARED_DATA` page at `ADDRESS`: applies the byte
//! recipes the safe core describes (`protocol/kuser.rs::Recipe`) under a
//! `crate::page_guard::PageGuard`, and — separately — the legacy
//! `LINUWUX_SYSCALL_HACK` mechanism (see below).
use core::ffi::{CStr, c_char, c_int};
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};
use linuwux::kuser::{PAGE_SIZE, PatchError, PatchState, Recipe};

const ADDRESS: usize = 0x7ffe_0000;
/// `KUSER_SHARED_DATA.SystemCall`: nonzero routes Wine's ntdll syscall
/// stubs through the KUSER dispatcher slot (the target design — see
/// `docs/protocol/syscall-routing.md`); the legacy `LINUWUX_SYSCALL_HACK`
/// path clears it so stubs take the direct `syscall` branch instead. This is
/// meant to be removed, not extended: it stays only because one supported
/// title (TopSpin) still crashes without it and the root cause isn't found
/// yet, tracked in `docs/protocol/topspin-investigation.md`. Do not add new
/// callers of `syscall_hack_enabled()`; the dispatcher bridge
/// (`syscall/kuser_dispatch.rs`) is the mechanism new code should rely on.
const SYSTEM_CALL_OFFSET: usize = 0x308;
const SYSCALL_HACK_ENV: &CStr = c"LINUWUX_SYSCALL_HACK";
static PAGE_GEOMETRY_SUPPORTED: AtomicBool = AtomicBool::new(false);
static AVX_ENABLED: AtomicBool = AtomicBool::new(false);
static SYSCALL_HACK_ENABLED: AtomicBool = AtomicBool::new(false);
static SYSCALL_HACK_APPLIED: AtomicBool = AtomicBool::new(false);
static PATCH_STATE: PatchState = PatchState::new();

pub(crate) fn recover_patch_after_fork() {
    PATCH_STATE.recover_after_fork();
}

#[path = "shared_time.rs"]
mod shared_time;

pub(crate) fn prepare_shared_page() {
    shared_time::prepare_shared_page();
}

unsafe extern "C" {
    fn debug_log(message: *const c_char);
}

fn log(message: &'static CStr) {
    unsafe { debug_log(message.as_ptr()) };
}

fn restore_read_only(page: *mut libc::c_void) -> bool {
    for _ in 0..2 {
        if unsafe { libc::mprotect(page, PAGE_SIZE, libc::PROT_READ) } == 0 {
            return true;
        }
    }
    false
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn kuser_apply_to_buffer(
    page: *mut u8,
    length: usize,
    recipe: c_int,
    avx_enabled: c_int,
) -> c_int {
    if page.is_null() || length < PAGE_SIZE {
        return -1;
    }
    let Some(recipe) = Recipe::from_raw(recipe) else {
        return -1;
    };
    recipe.visit_writes(avx_enabled != 0, |offset, byte| {
        unsafe { page.add(offset).write_volatile(byte) };
    });
    0
}

unsafe fn apply_recipe_to_shared_page(
    recipe: Recipe,
    _guard: &crate::page_guard::PageGuard,
) -> bool {
    if !PAGE_GEOMETRY_SUPPORTED.load(Ordering::Acquire) {
        log(c"KUSER patch requires a 4096-byte base page");
        return false;
    }
    if !shared_time::shared_page_available_for_write() {
        log(c"KUSER patch requires Wine's shared KUSER mapping");
        return false;
    }
    let page = ptr::with_exposed_provenance_mut::<u8>(ADDRESS);
    if unsafe { libc::mprotect(page.cast(), PAGE_SIZE, libc::PROT_READ | libc::PROT_WRITE) } == -1 {
        log(c"failed to make KUSER_SHARED_DATA writable");
        return false;
    }
    let apply_result = unsafe {
        kuser_apply_to_buffer(
            page,
            PAGE_SIZE,
            recipe as c_int,
            AVX_ENABLED.load(Ordering::Acquire) as c_int,
        )
    };
    if syscall_hack_enabled() {
        unsafe { page.add(SYSTEM_CALL_OFFSET).write_volatile(0) };
    }
    if !restore_read_only(page.cast()) {
        log(c"failed to restore KUSER_SHARED_DATA read-only protection");
        return false;
    }
    if syscall_hack_enabled() {
        SYSCALL_HACK_APPLIED.store(true, Ordering::Release);
    }
    if apply_result == -1 {
        log(c"failed to apply KUSER_SHARED_DATA recipe");
    }
    apply_result == 0
}

fn syscall_hack_enabled() -> bool {
    if !SYSCALL_HACK_ENABLED.load(Ordering::Acquire) {
        return false;
    }
    #[cfg(feature = "environment")]
    {
        crate::environment::game_process()
    }
    #[cfg(not(feature = "environment"))]
    true
}

#[cfg(feature = "hooks")]
pub(crate) fn force_direct_syscall() {
    if !syscall_hack_enabled()
        || SYSCALL_HACK_APPLIED.load(Ordering::Acquire)
        || !PAGE_GEOMETRY_SUPPORTED.load(Ordering::Acquire)
    {
        return;
    }
    if !shared_time::shared_page_available_for_write() {
        log(c"KUSER patch requires Wine's shared KUSER mapping");
        return;
    }
    let Some(_guard) = crate::page_guard::PageGuard::acquire() else {
        return;
    };
    if SYSCALL_HACK_APPLIED.load(Ordering::Acquire) {
        return;
    }
    let page = ptr::with_exposed_provenance_mut::<u8>(ADDRESS);
    if unsafe { libc::mprotect(page.cast(), PAGE_SIZE, libc::PROT_READ | libc::PROT_WRITE) } == -1 {
        return;
    }
    unsafe { page.add(SYSTEM_CALL_OFFSET).write_volatile(0) };
    if !restore_read_only(page.cast()) {
        log(c"failed to restore KUSER_SHARED_DATA read-only protection");
        return;
    }
    SYSCALL_HACK_APPLIED.store(true, Ordering::Release);
    log(c"KUSER_SHARED_DATA SystemCall forced to direct syscall");
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn patch_kuser_shared_data_recipe(recipe: c_int) -> c_int {
    let Some(recipe) = Recipe::from_raw(recipe) else {
        return -1;
    };
    let _errno = crate::errno::Errno::save();
    let Some(_guard) = crate::page_guard::PageGuard::acquire() else {
        return -1;
    };
    let result = PATCH_STATE.patch(
        recipe,
        || unsafe { apply_recipe_to_shared_page(recipe, &_guard) },
        || {
            unsafe { libc::sched_yield() };
        },
    );
    drop(_guard);
    #[cfg(all(feature = "syscall", feature = "reflex"))]
    if result.is_ok() && !crate::syscall::install_wine_syscall_dispatcher_bridge() {
        log(c"failed to install Wine syscall dispatcher bridge");
        return -1;
    }
    match result {
        Ok(()) => 0,
        Err(PatchError::ApplyFailed) => -1,
        Err(PatchError::Conflict) => {
            log(c"KUSER recipe conflicts with the selected protocol");
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn patch_kuser_shared_data() -> c_int {
    unsafe { patch_kuser_shared_data_recipe(Recipe::Resume as c_int) }
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
    let syscall_hack = unsafe {
        let value = libc::getenv(SYSCALL_HACK_ENV.as_ptr());
        !value.is_null() && CStr::from_ptr(value).to_bytes() == b"1"
    };
    SYSCALL_HACK_ENABLED.store(syscall_hack, Ordering::Release);
    prepare_shared_page();
    // Install before Reflex loads in the game process so its initial IAT
    // protection writes are visible to the bridge. The KUSER patch handshake
    // retries installation later if Wine has not populated its dispatcher yet.
    #[cfg(all(
        feature = "syscall",
        feature = "reflex",
        feature = "environment",
        feature = "hooks"
    ))]
    if crate::environment::game_process() {
        let _ = crate::syscall::install_wine_syscall_dispatcher_bridge();
    }
}

#[used]
#[unsafe(link_section = ".init_array.00204")]
static INITIALIZE: unsafe extern "C" fn() = linuwux_setup_kuser;
