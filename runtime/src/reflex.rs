use core::ffi::{CStr, c_char, c_int};
use core::ptr;
use libc::ucontext_t;
use linuwux::reflex::{Host, KuserProfile, State};

static REFLEX_STATE: State = State::new();
struct RuntimeHost;

unsafe extern "C" {
    fn cpuid_activate_dispatch_profile();
    fn set_offset(filetime: u64);
    fn patch_kuser_shared_data_profile(profile: c_int) -> c_int;
    fn debug_log(message: *const c_char);
    fn debug_log_hex(prefix: *const c_char, value: u64);
}

impl Host for RuntimeHost {
    fn activate_dispatch_cpuid(&self) {
        unsafe { cpuid_activate_dispatch_profile() };
    }
    fn set_offset(&self, filetime: u64) {
        unsafe { set_offset(filetime) };
    }
    fn patch_kuser(&self, profile: KuserProfile) -> bool {
        unsafe { patch_kuser_shared_data_profile(profile as c_int) == 0 }
    }
    fn set_hwprofile_guid(&self) {
        #[cfg(feature = "environment")]
        crate::registry::set_hwprofile_guid();
    }
    fn single_dispatch_forced(&self) -> bool {
        crate::config::single_dispatch_forced()
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
pub extern "C" fn reflex_handle_cpuid(leaf: u32, argument: u64) -> c_int {
    REFLEX_STATE.handle_cpuid(leaf, argument, &RuntimeHost) as c_int
}

#[unsafe(no_mangle)]
pub extern "C" fn reflex_resume_identity_unarmed() -> c_int {
    c_int::from(REFLEX_STATE.resume_identity_unarmed())
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
