//! The SIGSYS boundary: LinUwUx's own syscall-trap handler, installed by
//! `hooks.rs` alongside the CPUID SIGSEGV handler. Given a trapped syscall,
//! this decides whether to forward it to Wine's previously-installed SIGSYS
//! handler unchanged, or — for a call [`super::kuser_dispatch`] evidenced and
//! replayed raw, or a direct syscall from a process registered with Reflex —
//! hand it to `linuwux::reflex::State::route_syscall` and jump to the
//! selected Reflex handler instead.
//!
//! This module is always compiled, independent of the `kuser`/`reflex`
//! features: without them, every call simply falls through to Wine's
//! handler, which is the correct behavior when there is no bridge or Reflex
//! state to consult. The marker bookkeeping this boundary reads
//! ([`super::reflex_markers`]) lives in its own file because it needs that
//! narrower feature gate; this file owns the decision, not the storage.

use core::ffi::{c_int, c_void};
use core::ptr;
use libc::{siginfo_t, ucontext_t};
use linuwux::reflex::SYSCALL_BYPASS_MAGIC;

const SYS_SECCOMP: c_int = 1;
const SYS_USER_DISPATCH: c_int = 2;

#[cfg(feature = "debug")]
unsafe extern "C" {
    fn debug_log(message: *const core::ffi::c_char);
    fn debug_log_hex(prefix: *const core::ffi::c_char, value: u64);
}

/// Bounded trace of Reflex selector routing: the syscall number, thread and
/// caller for each SIGSYS offered to Reflex, and for each bypass replay Reflex
/// hands back. A selector route with no following bypass on the same thread
/// was answered by Reflex itself; one followed by a bypass went to Wine.
#[cfg(feature = "debug")]
fn trace_reflex_hop(
    kind: &'static core::ffi::CStr,
    tid: u64,
    rip: u64,
    gregs: *const libc::greg_t,
) {
    use core::sync::atomic::{AtomicU64, Ordering};
    static EVENTS: AtomicU64 = AtomicU64::new(0);
    if EVENTS.fetch_add(1, Ordering::Relaxed) >= 96 {
        return;
    }
    let register = |index: libc::c_int| unsafe { gregs.add(index as usize).read() as u64 };
    unsafe {
        debug_log(kind.as_ptr());
        debug_log_hex(c"reflex hop tid=".as_ptr(), tid);
        debug_log_hex(c"reflex hop RIP=".as_ptr(), rip);
        debug_log_hex(c"reflex hop RAX=".as_ptr(), register(libc::REG_RAX));
        debug_log_hex(c"reflex hop R10=".as_ptr(), register(libc::REG_R10));
        debug_log_hex(c"reflex hop RDX=".as_ptr(), register(libc::REG_RDX));
        debug_log_hex(c"reflex hop R8=".as_ptr(), register(libc::REG_R8));
    }
}

/// Keep a separate, small budget for the window-list service: the general
/// Reflex trace is usually exhausted before game initialization reaches it.
/// The seventh and eighth Windows arguments live on the caller's stack.
#[cfg(all(feature = "debug", feature = "kuser", feature = "reflex"))]
fn trace_window_list(kind: &'static core::ffi::CStr, gregs: *const libc::greg_t) {
    use core::sync::atomic::{AtomicU64, Ordering};
    static EVENTS: AtomicU64 = AtomicU64::new(0);
    let register = |index: libc::c_int| unsafe { gregs.add(index as usize).read() as u64 };
    if register(libc::REG_RAX) != 0x132d || EVENTS.fetch_add(1, Ordering::Relaxed) >= 16 {
        return;
    }
    let rsp = register(libc::REG_RSP);
    unsafe {
        debug_log(kind.as_ptr());
        debug_log_hex(c"window list RIP=".as_ptr(), register(libc::REG_RIP));
        debug_log_hex(c"window list RSP=".as_ptr(), rsp);
        debug_log_hex(c"window list R10=".as_ptr(), register(libc::REG_R10));
        debug_log_hex(c"window list RDX=".as_ptr(), register(libc::REG_RDX));
        debug_log_hex(c"window list R8=".as_ptr(), register(libc::REG_R8));
        debug_log_hex(c"window list R9=".as_ptr(), register(libc::REG_R9));
        if let Some(value) = super::mem::read_u64(rsp.saturating_add(0x38)) {
            debug_log_hex(c"window list stack+0x38=".as_ptr(), value);
        }
        if let Some(value) = super::mem::read_u64(rsp.saturating_add(0x40)) {
            debug_log_hex(c"window list stack+0x40=".as_ptr(), value);
        }
    }
}

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

fn is_bypass(xmm5: &[u8; 16]) -> bool {
    u64::from_le_bytes(xmm5[..8].try_into().unwrap()) == SYSCALL_BYPASS_MAGIC
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
    let xmm = unsafe { ptr::addr_of_mut!((*fpregs)._xmm).cast::<[u8; 16]>() };
    let xmm5 = unsafe { xmm.add(5).read() };
    let gregs = unsafe { ptr::addr_of_mut!((*context).uc_mcontext.gregs).cast::<libc::greg_t>() };
    let rip = unsafe { gregs.add(libc::REG_RIP as usize).read() as u64 };
    // Every branch below needs the current thread id at least once, and some
    // need it two or three times; `gettid` is a real syscall (not the cached
    // libc wrapper), so query it once per event rather than per use.
    let tid = unsafe { libc::gettid() as u64 };
    // Every use below is gated by some combination of `kuser`/`reflex`/
    // `debug`; with all three off, `tid` itself would otherwise be unused.
    let _ = tid;
    #[cfg(all(feature = "debug", feature = "environment", feature = "hooks"))]
    let trace_event = {
        let register = |index: libc::c_int| unsafe { gregs.add(index as usize).read() as u64 };
        super::diagnostics::event(
            tid,
            code as u64,
            super::diagnostics::Disposition::Forwarded,
            [
                rip,
                register(libc::REG_RSP),
                register(libc::REG_RAX),
                register(libc::REG_R10),
                register(libc::REG_RCX),
                register(libc::REG_RDX),
                register(libc::REG_R8),
                register(libc::REG_R9),
                register(libc::REG_R13),
                u64::from_le_bytes(xmm5[..8].try_into().unwrap()),
            ],
        )
    };
    // `bridged` only exists under kuser+reflex (its type, `reflex_markers::
    // Phase`, is only compiled then) — every read of it below is gated by
    // the same features, so it is simply not declared otherwise, rather
    // than given a placeholder `None` with no type for the compiler to
    // infer from unused dead code.
    #[cfg(all(feature = "kuser", feature = "reflex"))]
    let bridged = super::reflex_markers::consume(
        tid,
        unsafe { gregs.add(libc::REG_RSP as usize).read() as u64 },
        rip,
        unsafe { xmm.add(4).read() },
        xmm5,
        unsafe { gregs.add(libc::REG_R11 as usize).read() as u64 },
        unsafe { gregs.add(libc::REG_EFL as usize).read() as u64 },
    );
    #[cfg(all(feature = "kuser", feature = "reflex"))]
    if let Some(super::reflex_markers::Phase::Replay(saved)) = bridged {
        unsafe {
            xmm.add(4).write(saved.xmm4);
            xmm.add(5).write(saved.xmm5);
            gregs
                .add(libc::REG_R11 as usize)
                .write(saved.r11 as libc::greg_t);
            gregs
                .add(libc::REG_EFL as usize)
                .write(saved.eflags as libc::greg_t);
        }
        #[cfg(all(feature = "debug", feature = "environment", feature = "hooks"))]
        super::diagnostics::record_game_event(
            trace_event.with_disposition(super::diagnostics::Disposition::BridgeReplayRestored),
        );
        return false;
    }
    if is_bypass(&xmm5) {
        #[cfg(all(feature = "debug", feature = "kuser", feature = "reflex"))]
        trace_window_list(c"window list Reflex bypass", gregs);
        #[cfg(feature = "debug")]
        trace_reflex_hop(c"reflex bypass replay", tid, rip, gregs);
        #[cfg(all(feature = "kuser", feature = "reflex"))]
        if matches!(bridged, Some(super::reflex_markers::Phase::Route)) {
            unsafe {
                super::reflex_markers::cancel(
                    tid,
                    gregs.add(libc::REG_RSP as usize).read() as u64,
                    rip,
                );
            }
        }
        unsafe { xmm.add(5).write([0; 16]) };
        #[cfg(all(feature = "kuser", feature = "reflex"))]
        if code == SYS_USER_DISPATCH && super::win32u_zero_list::maybe_complete_bypass(gregs) {
            #[cfg(all(feature = "debug", feature = "environment", feature = "hooks"))]
            super::diagnostics::record_game_event(
                trace_event.with_disposition(super::diagnostics::Disposition::LocallyCompleted),
            );
            return true;
        }
        #[cfg(all(feature = "debug", feature = "environment", feature = "hooks"))]
        super::diagnostics::record_game_event(
            trace_event.with_disposition(super::diagnostics::Disposition::ReflexBypassForwarded),
        );
        return false;
    }
    let is_bridged_route = {
        #[cfg(all(feature = "kuser", feature = "reflex"))]
        {
            matches!(bridged, Some(super::reflex_markers::Phase::Route))
        }
        #[cfg(not(all(feature = "kuser", feature = "reflex")))]
        {
            false
        }
    };
    #[cfg(all(feature = "kuser", feature = "reflex"))]
    let is_target_process_route = if is_bridged_route {
        false
    } else {
        let service = unsafe { gregs.add(libc::REG_RAX as usize).read() as u64 };
        super::reflex_markers::is_registered_target_process(rip, service)
    };
    #[cfg(not(all(feature = "kuser", feature = "reflex")))]
    let is_target_process_route = false;
    if !is_bridged_route && !is_target_process_route {
        #[cfg(all(feature = "debug", feature = "kuser", feature = "reflex"))]
        trace_window_list(c"window list direct Wine route", gregs);
        #[cfg(all(feature = "debug", feature = "environment", feature = "hooks"))]
        super::diagnostics::record_game_event(trace_event);
        return false;
    }
    let Some(selected_route) = route(context) else {
        #[cfg(all(feature = "debug", feature = "kuser", feature = "reflex"))]
        trace_window_list(c"window list unselected Wine route", gregs);
        #[cfg(all(feature = "debug", feature = "environment", feature = "hooks"))]
        super::diagnostics::record_game_event(
            trace_event.with_disposition(super::diagnostics::Disposition::ReflexRouteDeclined),
        );
        #[cfg(all(feature = "kuser", feature = "reflex"))]
        if is_bridged_route {
            unsafe {
                super::reflex_markers::cancel(
                    tid,
                    gregs.add(libc::REG_RSP as usize).read() as u64,
                    rip,
                );
            }
        }
        return false;
    };
    #[cfg(all(feature = "debug", feature = "kuser", feature = "reflex"))]
    trace_window_list(c"window list Reflex route", gregs);
    #[cfg(feature = "debug")]
    trace_reflex_hop(
        if is_bridged_route {
            c"reflex route (bridged)"
        } else {
            c"reflex route (target process)"
        },
        tid,
        rip,
        gregs,
    );
    #[cfg(all(feature = "debug", feature = "environment", feature = "hooks"))]
    super::diagnostics::record_game_event(
        trace_event.with_disposition(super::diagnostics::Disposition::ReflexRedirected),
    );
    unsafe {
        // `syscall` clears bits out of EFLAGS per the CPU's SFMASK before
        // this trap is even delivered, stashing the true pre-call value in
        // R11 (the ISA guarantee `sysret` relies on to restore it later). A
        // real `int 2e` never touches EFLAGS at all, so Reflex's own
        // hooked-syscall entry point — reverse-engineered to expect exactly
        // what `int 2e` would hand it — needs that true value here, on the
        // way in, not only restored on the bridged marker's `Phase::Replay`
        // return trip above. See syscall-routing.md's "preserve ...
        // R11/EFLAGS" invariant: it applies to both hops, not just one.
        let r11 = gregs.add(libc::REG_R11 as usize).read();
        gregs.add(libc::REG_EFL as usize).write(r11);

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
