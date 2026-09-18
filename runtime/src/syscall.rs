use core::ffi::{c_int, c_void};
use core::ptr;
use libc::{siginfo_t, ucontext_t};
use linuwux::cpuid::is_wine_system_rip;
use linuwux::reflex::SYSCALL_BYPASS_MAGIC;

const SYS_SECCOMP: c_int = 1;
const SYS_USER_DISPATCH: c_int = 2;

unsafe extern "C" {
    fn forward_signal(sig: c_int, info: *mut siginfo_t, context: *mut c_void);
    fn reflex_route_syscall(
        context: *const ucontext_t,
        target: *mut u64,
        rax_is_resume: *mut c_int,
    ) -> c_int;
}

#[derive(Clone, Copy)]
struct Route {
    target: u64,
    rax_is_resume: bool,
}

fn redirect_all() -> bool {
    crate::config::redirect_all()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn syscallhook(sig: c_int, info: *mut siginfo_t, context: *mut c_void) {
    let _errno = crate::errno::Errno::save();
    let handled = unsafe {
        redirect(info, context.cast(), |ctx| {
            let mut target = 0;
            let mut rax_is_resume = 0;
            (reflex_route_syscall(ctx, &mut target, &mut rax_is_resume) != 0).then_some(Route {
                target,
                rax_is_resume: rax_is_resume != 0,
            })
        })
    };
    if !handled {
        unsafe { forward_signal(sig, info, context) };
    }
}

unsafe fn redirect(
    info: *const siginfo_t,
    context: *mut ucontext_t,
    route: impl FnOnce(*const ucontext_t) -> Option<Route>,
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
    let Some(selected_route) = route(context) else {
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
        let rip = gregs.add(libc::REG_RIP as usize).read() as u64;
        if !redirect_all() && is_wine_system_rip(rip) {
            return false;
        }
        let selector = gregs.add(libc::REG_RAX as usize).read() as u32;
        let mut xmm4 = xmm.add(4).read();
        xmm4[..4].copy_from_slice(&selector.to_le_bytes());
        xmm.add(4).write(xmm4);
        let rcx = gregs.add(libc::REG_RCX as usize).read() as u64;
        let rax = if selected_route.rax_is_resume {
            syscall_resume(rip, rcx)
        } else {
            rcx
        };
        gregs.add(libc::REG_RAX as usize).write(rax as libc::greg_t);
        gregs
            .add(libc::REG_RCX as usize)
            .write(selected_route.target as libc::greg_t);
        gregs
            .add(libc::REG_RIP as usize)
            .write(selected_route.target as libc::greg_t);
    }
    true
}

unsafe fn syscall_resume(rip: u64, rcx: u64) -> u64 {
    let instruction = unsafe { ptr::read(rip as *const [u8; 2]) };
    if instruction == [0x0f, 0x05] {
        rip.wrapping_add(2)
    } else {
        rcx
    }
}
