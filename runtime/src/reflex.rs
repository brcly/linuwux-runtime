use core::ffi::{CStr, c_char, c_int};
use core::ptr;
use libc::ucontext_t;
use linuwux::reflex::{Host, KuserProfile, State};

static REFLEX_STATE: State = State::new();
struct RuntimeHost;

unsafe extern "C" {
    fn cpuid_activate_legacy_profile();
    fn set_offset(filetime: u64);
    fn patch_kuser_shared_data_profile(profile: c_int) -> c_int;
    fn debug_log(message: *const c_char);
    fn debug_log_hex(prefix: *const c_char, value: u64);
}

impl Host for RuntimeHost {
    fn activate_legacy_cpuid(&self) {
        unsafe { cpuid_activate_legacy_profile() };
    }
    fn set_offset(&self, filetime: u64) {
        unsafe { set_offset(filetime) };
    }
    fn patch_kuser(&self, profile: KuserProfile) -> bool {
        unsafe { patch_kuser_shared_data_profile(profile as c_int) == 0 }
    }
    fn log(&self, message: &'static CStr) {
        unsafe { debug_log(message.as_ptr()) };
    }
    fn log_hex(&self, prefix: &'static CStr, value: u64) {
        unsafe { debug_log_hex(prefix.as_ptr(), value) };
    }
}

#[cfg_attr(not(test), unsafe(no_mangle))]
pub extern "C" fn reflex_handle_cpuid(leaf: u32, argument: u64) -> c_int {
    REFLEX_STATE.handle_cpuid(leaf, argument, &RuntimeHost) as c_int
}

#[cfg_attr(not(test), unsafe(no_mangle))]
pub unsafe extern "C" fn reflex_route_syscall(
    context: *const ucontext_t,
    target: *mut u64,
) -> c_int {
    if context.is_null() || target.is_null() {
        return 0;
    }
    let (number, r10) = unsafe {
        let gregs = ptr::addr_of!((*context).uc_mcontext.gregs).cast::<libc::greg_t>();
        (
            gregs.add(libc::REG_RAX as usize).read() as u64,
            gregs.add(libc::REG_R10 as usize).read(),
        )
    };
    match REFLEX_STATE.route_syscall(number, r10) {
        Some(selected) => {
            unsafe { target.write(selected) };
            1
        }
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::MaybeUninit;
    use linuwux::reflex::{LEGACY_QUERY_SYSTEM_ID, REGISTER_TARGET};

    struct NoEffects;
    impl Host for NoEffects {
        fn activate_legacy_cpuid(&self) {}
        fn set_offset(&self, _: u64) {}
        fn patch_kuser(&self, _: KuserProfile) -> bool {
            true
        }
        fn log(&self, _: &'static CStr) {}
        fn log_hex(&self, _: &'static CStr, _: u64) {}
    }

    #[test]
    fn route_ffi_reads_only_required_registers_and_initialises_output() {
        REFLEX_STATE.handle_cpuid(REGISTER_TARGET, 0x1234, &NoEffects);
        let mut context = MaybeUninit::<ucontext_t>::uninit();
        let mut target = MaybeUninit::<u64>::uninit();
        unsafe {
            let gregs =
                ptr::addr_of_mut!((*context.as_mut_ptr()).uc_mcontext.gregs).cast::<libc::greg_t>();
            gregs.add(libc::REG_RAX as usize).write(42);
            gregs.add(libc::REG_R10 as usize).write(-1);
            assert_eq!(reflex_route_syscall(ptr::null(), target.as_mut_ptr()), 0);
            assert_eq!(reflex_route_syscall(context.as_ptr(), ptr::null_mut()), 0);
            assert_eq!(
                reflex_route_syscall(context.as_ptr(), target.as_mut_ptr()),
                1
            );
            assert_eq!(target.assume_init(), 0x1234);
            REFLEX_STATE.handle_cpuid(LEGACY_QUERY_SYSTEM_ID, 43, &NoEffects);
            assert_eq!(
                reflex_route_syscall(context.as_ptr(), target.as_mut_ptr()),
                0
            );
            assert_eq!(target.assume_init(), 0x1234);
        }
    }
}
