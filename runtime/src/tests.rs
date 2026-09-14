use core::ffi::{c_char, c_int, c_void};
use core::mem::{MaybeUninit, align_of, offset_of, size_of};
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

use libc::{siginfo_t, ucontext_t};
use linuwux::cpuid::{Profile, Registers};

use crate::cpuid::{cpuid_configure_profile, cpuid_get_fixed_reply, cpuid_sigsegv_handler};

static FORWARDED: AtomicUsize = AtomicUsize::new(0);

#[unsafe(no_mangle)]
extern "C" fn debug_log(_: *const c_char) {
    panic!("pointer tests must not reach logging");
}

#[unsafe(no_mangle)]
extern "C" fn forward_signal(_: c_int, _: *mut siginfo_t, _: *mut c_void) {
    FORWARDED.fetch_add(1, Ordering::Relaxed);
}

#[unsafe(no_mangle)]
extern "C" fn reflex_handle_cpuid(_: u32, _: u64) -> c_int {
    panic!("pointer tests must not reach Reflex");
}

#[test]
fn ffi_writes_uninitialised_output_and_handles_null() {
    assert_eq!(size_of::<Registers>(), 16);
    assert_eq!(align_of::<Registers>(), 4);
    assert_eq!(offset_of!(Registers, eax), 0);
    assert_eq!(offset_of!(Registers, ebx), 4);
    assert_eq!(offset_of!(Registers, ecx), 8);
    assert_eq!(offset_of!(Registers, edx), 12);
    cpuid_configure_profile(1, -7);
    let mut result = MaybeUninit::<Registers>::uninit();
    assert_eq!(unsafe { cpuid_get_fixed_reply(1, result.as_mut_ptr()) }, 1);
    let initialised = unsafe { result.assume_init() };
    assert_eq!(initialised, Profile::IntelAvx.fixed_reply(1).unwrap());
    unsafe {
        assert_eq!(cpuid_get_fixed_reply(1, ptr::null_mut()), 0);
        assert_eq!(cpuid_get_fixed_reply(0, result.as_mut_ptr()), 0);
        assert_eq!(result.assume_init(), Registers::default());
    }
}

#[test]
fn forwarding_only_reads_the_required_frame_fields() {
    let mut info = MaybeUninit::<siginfo_t>::uninit();
    let mut context = MaybeUninit::<ucontext_t>::uninit();
    let info_ptr = info.as_mut_ptr();
    let context_ptr = context.as_mut_ptr();
    unsafe {
        ptr::addr_of_mut!((*info_ptr).si_code).write(libc::SI_KERNEL);
        let gregs = ptr::addr_of_mut!((*context_ptr).uc_mcontext.gregs).cast::<libc::greg_t>();
        gregs.add(libc::REG_TRAPNO as usize).write(14);
        cpuid_sigsegv_handler(libc::SIGSEGV, info_ptr, context_ptr.cast());
        cpuid_sigsegv_handler(libc::SIGSEGV, ptr::null_mut(), context_ptr.cast());
        cpuid_sigsegv_handler(libc::SIGSEGV, info_ptr, ptr::null_mut());
        gregs.add(libc::REG_TRAPNO as usize).write(13);
        ptr::addr_of_mut!((*info_ptr).si_code).write(1);
        cpuid_sigsegv_handler(libc::SIGSEGV, info_ptr, context_ptr.cast());
        ptr::addr_of_mut!((*info_ptr).si_code).write(libc::SI_KERNEL);
        gregs.add(libc::REG_RIP as usize).write(0);
        cpuid_sigsegv_handler(libc::SIGSEGV, info_ptr, context_ptr.cast());
    }
    assert_eq!(FORWARDED.load(Ordering::Relaxed), 5);
}
