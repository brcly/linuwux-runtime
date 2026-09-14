use core::ffi::{c_int, c_void};
use core::ptr;
use libc::{siginfo_t, ucontext_t};
use linuwux::reflex::SYSCALL_BYPASS_MAGIC;

const SYS_SECCOMP: c_int = 1;
const SYS_USER_DISPATCH: c_int = 2;

unsafe extern "C" {
    fn forward_signal(sig: c_int, info: *mut siginfo_t, context: *mut c_void);
    fn reflex_route_syscall(context: *const ucontext_t, target: *mut u64) -> c_int;
}

#[cfg_attr(not(test), unsafe(no_mangle))]
pub unsafe extern "C" fn syscallhook(sig: c_int, info: *mut siginfo_t, context: *mut c_void) {
    let _errno = crate::errno::Errno::save();
    let handled = unsafe {
        redirect(info, context.cast(), |ctx| {
            let mut target = 0;
            (reflex_route_syscall(ctx, &mut target) != 0).then_some(target)
        })
    };
    if !handled {
        unsafe { forward_signal(sig, info, context) };
    }
}

unsafe fn redirect(
    info: *const siginfo_t,
    context: *mut ucontext_t,
    route: impl FnOnce(*const ucontext_t) -> Option<u64>,
) -> bool {
    if info.is_null() || context.is_null() {
        return false;
    }
    let fpregs = unsafe { ptr::addr_of!((*context).uc_mcontext.fpregs).read() };
    if fpregs.is_null() {
        return false;
    }
    let code = unsafe { ptr::addr_of!((*info).si_code).read() };
    if !matches!(code, SYS_SECCOMP | SYS_USER_DISPATCH) {
        return false;
    }
    let Some(target) = route(context) else {
        return false;
    };
    unsafe {
        let xmm = ptr::addr_of_mut!((*fpregs)._xmm).cast::<[u8; 16]>();
        let low_xmm5 = xmm.add(5).cast::<[u8; 8]>().read();
        if u64::from_le_bytes(low_xmm5) == SYSCALL_BYPASS_MAGIC {
            xmm.add(5).write([0; 16]);
            return false;
        }
        let gregs = ptr::addr_of_mut!((*context).uc_mcontext.gregs).cast::<libc::greg_t>();
        let selector = gregs.add(libc::REG_RAX as usize).read() as u32;
        let mut xmm4 = [0; 16];
        xmm4[..4].copy_from_slice(&selector.to_le_bytes());
        xmm.add(4).write(xmm4);
        let rcx = gregs.add(libc::REG_RCX as usize).read();
        gregs.add(libc::REG_RAX as usize).write(rcx);
        gregs
            .add(libc::REG_RCX as usize)
            .write(target as libc::greg_t);
        gregs
            .add(libc::REG_RIP as usize)
            .write(target as libc::greg_t);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{MaybeUninit, size_of};

    #[test]
    fn partial_frame_and_fpstate_without_u128_alignment() {
        #[repr(C, align(16))]
        struct Storage([MaybeUninit<u8>; size_of::<libc::_libc_fpstate>() + 8]);
        let mut storage = Storage([MaybeUninit::uninit(); size_of::<libc::_libc_fpstate>() + 8]);
        let mut context = MaybeUninit::<ucontext_t>::uninit();
        let mut info = MaybeUninit::<siginfo_t>::uninit();
        unsafe {
            let fp = storage.0.as_mut_ptr().add(8).cast::<libc::_libc_fpstate>();
            let ctx = context.as_mut_ptr();
            ptr::addr_of_mut!((*ctx).uc_mcontext.fpregs).write(fp);
            ptr::addr_of_mut!((*info.as_mut_ptr()).si_code).write(SYS_SECCOMP);
            let xmm = ptr::addr_of_mut!((*fp)._xmm).cast::<[u8; 16]>();
            xmm.add(5).cast::<u64>().write(0);
            let gregs = ptr::addr_of_mut!((*ctx).uc_mcontext.gregs).cast::<libc::greg_t>();
            gregs.add(libc::REG_RAX as usize).write(-1);
            gregs.add(libc::REG_RCX as usize).write(0x5678);
            assert!(redirect(info.as_ptr(), ctx, |_| Some(u64::MAX)));
            assert_eq!(
                xmm.add(4).read(),
                [255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
            );
            assert_eq!(gregs.add(libc::REG_RAX as usize).read(), 0x5678);
            assert_eq!(gregs.add(libc::REG_RCX as usize).read(), -1);
            assert_eq!(gregs.add(libc::REG_RIP as usize).read(), -1);
            xmm.add(5).cast::<u64>().write(SYSCALL_BYPASS_MAGIC);
            assert!(!redirect(info.as_ptr(), ctx, |_| Some(42)));
            assert_eq!(xmm.add(5).read(), [0; 16]);
            assert!(!redirect(ptr::null(), ctx, |_| panic!("must not route")));
            ptr::addr_of_mut!((*ctx).uc_mcontext.fpregs).write(ptr::null_mut());
            assert!(!redirect(info.as_ptr(), ctx, |_| panic!("must not route")));
        }
    }
}
