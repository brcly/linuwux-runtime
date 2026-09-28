//! The C ABI other modules call to reach the safe core's Reflex state
//! machine (`protocol/reflex/state.rs::State`), and `RuntimeHost`, this
//! process's single implementation of its `Host` trait — the seam where the
//! safe core's pure decisions turn into real `mprotect`/CPUID-presentation/
//! logging side effects. `cpuid.rs` calls [`reflex_handle_cpuid`] from the
//! CPUID trap handler; `syscall/sigsys_router.rs` calls
//! [`reflex_route_syscall`] from the SIGSYS handler.
use core::ffi::{CStr, c_char, c_int};
use core::ptr;
use libc::ucontext_t;
use linuwux::reflex::{Host, KuserRecipe, State};

static REFLEX_STATE: State = State::new();
struct RuntimeHost;

unsafe extern "C" {
    fn cpuid_activate_legacy_profile();
    fn cpuid_kuser_recipe() -> c_int;
    fn set_offset(filetime: u64);
    fn patch_kuser_shared_data_recipe(recipe: c_int) -> c_int;
    fn debug_log(message: *const c_char);
    fn debug_log_hex(prefix: *const c_char, value: u64);
}

impl Host for RuntimeHost {
    fn set_offset(&self, filetime: u64) {
        unsafe { set_offset(filetime) };
    }
    fn select_legacy_presentation(&self) {
        unsafe { cpuid_activate_legacy_profile() };
    }
    fn legacy_presentation_active(&self) -> bool {
        unsafe { cpuid_kuser_recipe() != KuserRecipe::Resume as c_int }
    }
    fn selector_kuser_recipe(&self) -> KuserRecipe {
        match unsafe { cpuid_kuser_recipe() } {
            2 => KuserRecipe::Dispatch,
            _ => KuserRecipe::Selector,
        }
    }
    fn patch_kuser(&self, recipe: KuserRecipe) -> bool {
        unsafe { patch_kuser_shared_data_recipe(recipe as c_int) == 0 }
    }
    fn set_hwprofile_guid(&self) {
        #[cfg(feature = "environment")]
        crate::registry::set_hwprofile_guid();
    }
    fn yield_thread(&self) {
        unsafe { libc::syscall(libc::SYS_sched_yield) };
    }
    fn log(&self, message: &'static CStr) {
        unsafe { debug_log(message.as_ptr()) };
    }
    fn log_hex(&self, prefix: &'static CStr, value: u64) {
        unsafe { debug_log_hex(prefix.as_ptr(), value) };
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn reflex_handle_cpuid(leaf: u32, rcx: u64, rdx: u64) -> c_int {
    REFLEX_STATE.handle_cpuid(leaf, rcx, rdx, &RuntimeHost) as c_int
}

#[unsafe(no_mangle)]
pub extern "C" fn reflex_resume_identity_unarmed() -> c_int {
    c_int::from(REFLEX_STATE.resume_identity_unarmed())
}

#[unsafe(no_mangle)]
pub extern "C" fn reflex_target_process_registered() -> c_int {
    c_int::from(REFLEX_STATE.has_registered_target_process())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn reflex_route_syscall(
    context: *const ucontext_t,
    target: *mut u64,
    rax_is_resume: *mut c_int,
) -> c_int {
    if context.is_null() || target.is_null() || rax_is_resume.is_null() {
        return 0;
    }
    let (number, r10, rcx) = unsafe {
        let gregs = ptr::addr_of!((*context).uc_mcontext.gregs).cast::<libc::greg_t>();
        (
            gregs.add(libc::REG_RAX as usize).read() as u64,
            gregs.add(libc::REG_R10 as usize).read(),
            gregs.add(libc::REG_RCX as usize).read() as u64,
        )
    };
    match REFLEX_STATE.route_syscall(number, r10, rcx) {
        Some(route) => {
            unsafe {
                target.write(route.target);
                rax_is_resume.write(c_int::from(route.rax_is_resume));
            }
            1
        }
        None => 0,
    }
}
