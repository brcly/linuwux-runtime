use core::ffi::{CStr, c_char, c_int, c_void};
use core::mem::{MaybeUninit, size_of};
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, Ordering};

use libc::{sigaction as Sigaction, siginfo_t, sigset_t};

type RealSigaction = unsafe extern "C" fn(c_int, *const Sigaction, *mut Sigaction) -> c_int;
type Snapshot = MaybeUninit<Sigaction>;

struct SignalSlot {
    current: AtomicPtr<Snapshot>,
    readers: AtomicU32,
    owned: AtomicBool,
}

impl SignalSlot {
    const fn new() -> Self {
        Self {
            current: AtomicPtr::new(ptr::null_mut()),
            readers: AtomicU32::new(0),
            owned: AtomicBool::new(false),
        }
    }

    fn copy_saved_action(&self) -> Snapshot {
        self.readers.fetch_add(1, Ordering::SeqCst);
        let snapshot = self.current.load(Ordering::SeqCst);
        let action = if snapshot.is_null() {
            MaybeUninit::zeroed()
        } else {
            unsafe { snapshot.read() }
        };
        self.readers.fetch_sub(1, Ordering::SeqCst);
        action
    }

    unsafe fn release_snapshot(&self, snapshot: *mut Snapshot) {
        if snapshot.is_null() {
            return;
        }
        while self.readers.load(Ordering::SeqCst) != 0 {
            yield_thread();
        }
        unsafe { libc::free(snapshot.cast()) };
    }
}

static SIGSEGV_SLOT: SignalSlot = SignalSlot::new();
static SIGSYS_SLOT: SignalSlot = SignalSlot::new();
static SIGNAL_UPDATE_LOCK: AtomicBool = AtomicBool::new(false);
static REAL_SIGACTION: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static FORK_REGISTERED: AtomicBool = AtomicBool::new(false);

extern "C" fn after_fork() {
    SIGNAL_UPDATE_LOCK.store(false, Ordering::Release);
    SIGSEGV_SLOT.readers.store(0, Ordering::SeqCst);
    SIGSYS_SLOT.readers.store(0, Ordering::SeqCst);
}

unsafe extern "C" {
    fn cpuid_sigsegv_handler(sig: c_int, info: *mut siginfo_t, context: *mut c_void);
    fn syscallhook(sig: c_int, info: *mut siginfo_t, context: *mut c_void);
    fn detect_cpu_vendor();
    fn debug_runtime_activated();
    fn debug_log(message: *const c_char);
}

fn errno() -> c_int {
    unsafe { *libc::__errno_location() }
}

fn set_errno(value: c_int) {
    unsafe { *libc::__errno_location() = value };
}

fn yield_thread() {
    #[cfg(miri)]
    std::thread::yield_now();
    #[cfg(not(miri))]
    unsafe {
        libc::syscall(libc::SYS_sched_yield)
    };
}

fn resolve_real_sigaction() -> Option<RealSigaction> {
    let mut symbol = REAL_SIGACTION.load(Ordering::Acquire);
    if symbol.is_null() {
        symbol = unsafe { libc::dlsym(libc::RTLD_NEXT, c"sigaction".as_ptr()) };
        if symbol.is_null() {
            set_errno(libc::ENOSYS);
            return None;
        }
        REAL_SIGACTION.store(symbol, Ordering::Release);
    }
    Some(unsafe { core::mem::transmute::<*mut c_void, RealSigaction>(symbol) })
}

fn slot_for(sig: c_int) -> Option<&'static SignalSlot> {
    match sig {
        libc::SIGSEGV => Some(&SIGSEGV_SLOT),
        libc::SIGSYS => Some(&SIGSYS_SLOT),
        _ => None,
    }
}

fn bridge_handler(sig: c_int) -> usize {
    match sig {
        libc::SIGSEGV => cpuid_sigsegv_handler as *const () as usize,
        libc::SIGSYS => syscallhook as *const () as usize,
        _ => 0,
    }
}

unsafe fn action_is_bridge(sig: c_int, action: *const Sigaction) -> bool {
    unsafe {
        !action.is_null()
            && (*action).sa_flags & libc::SA_SIGINFO != 0
            && bridge_handler(sig) != 0
            && (*action).sa_sigaction == bridge_handler(sig)
    }
}

unsafe fn handler_is_from_wine_ntdll(action: *const Sigaction) -> bool {
    if action.is_null() {
        return false;
    }
    let handler = unsafe { (*action).sa_sigaction };
    if handler == libc::SIG_DFL || handler == libc::SIG_IGN {
        return false;
    }
    let mut info = MaybeUninit::<libc::Dl_info>::uninit();
    if unsafe { libc::dladdr(handler as *const c_void, info.as_mut_ptr()) } == 0 {
        return false;
    }
    let name = unsafe { (*info.as_ptr()).dli_fname };
    if name.is_null() {
        return false;
    }
    let name = unsafe { CStr::from_ptr(name) }.to_bytes();
    let basename = name.rsplit(|&byte| byte == b'/').next().unwrap_or(name);
    basename == b"ntdll.so" || basename == b"ntdll.dll.so"
}

#[repr(C)]
struct KernelSigaction {
    handler: usize,
    flags: libc::c_ulong,
    restorer: usize,
    mask: libc::c_ulong,
}

fn terminate_from_signal(sig: c_int) -> ! {
    let status = 128i32.wrapping_add(sig);
    unsafe {
        libc::syscall(libc::SYS_exit_group, status);
        libc::_exit(status);
    }
}

fn restore_default_and_raise(sig: c_int) {
    let disposition = KernelSigaction {
        handler: libc::SIG_DFL,
        flags: 0,
        restorer: 0,
        mask: 0,
    };
    let result = unsafe {
        libc::syscall(
            libc::SYS_rt_sigaction,
            sig,
            &disposition as *const KernelSigaction,
            ptr::null_mut::<KernelSigaction>(),
            size_of::<libc::c_ulong>(),
        )
    };
    if result == -1 {
        terminate_from_signal(sig);
    }
    let (process_id, thread_id) = unsafe {
        (
            libc::syscall(libc::SYS_getpid),
            libc::syscall(libc::SYS_gettid),
        )
    };
    if process_id <= 0 || thread_id <= 0 {
        terminate_from_signal(sig);
    }
    if unsafe { libc::syscall(libc::SYS_tgkill, process_id, thread_id, sig) } == -1 {
        terminate_from_signal(sig);
    }
}

#[cfg_attr(not(test), unsafe(no_mangle))]
pub unsafe extern "C" fn forward_signal(sig: c_int, info: *mut siginfo_t, context: *mut c_void) {
    let Some(slot) = slot_for(sig) else {
        restore_default_and_raise(sig);
        return;
    };
    let saved = slot.copy_saved_action();
    let (handler, flags) = unsafe { ((*saved.as_ptr()).sa_sigaction, (*saved.as_ptr()).sa_flags) };
    if handler == libc::SIG_DFL {
        restore_default_and_raise(sig);
    } else if handler != libc::SIG_IGN {
        if flags & libc::SA_SIGINFO != 0 {
            let callback = unsafe {
                core::mem::transmute::<
                    usize,
                    unsafe extern "C" fn(c_int, *mut siginfo_t, *mut c_void),
                >(handler)
            };
            unsafe { callback(sig, info, context) };
        } else {
            let callback =
                unsafe { core::mem::transmute::<usize, unsafe extern "C" fn(c_int)>(handler) };
            unsafe { callback(sig) };
        }
    }
}

struct UpdateGuard {
    previous_mask: MaybeUninit<sigset_t>,
}

impl UpdateGuard {
    fn acquire() -> Option<Self> {
        let mut blocked = MaybeUninit::<sigset_t>::uninit();
        let mut previous_mask = MaybeUninit::<sigset_t>::uninit();
        if unsafe {
            libc::sigfillset(blocked.as_mut_ptr()) == -1
                || libc::sigprocmask(
                    libc::SIG_BLOCK,
                    blocked.as_ptr(),
                    previous_mask.as_mut_ptr(),
                ) == -1
        } {
            return None;
        }
        while SIGNAL_UPDATE_LOCK.swap(true, Ordering::Acquire) {
            yield_thread();
        }
        Some(Self { previous_mask })
    }
}

impl Drop for UpdateGuard {
    fn drop(&mut self) {
        let saved_errno = errno();
        SIGNAL_UPDATE_LOCK.store(false, Ordering::Release);
        unsafe {
            libc::sigprocmask(
                libc::SIG_SETMASK,
                self.previous_mask.as_ptr(),
                ptr::null_mut(),
            )
        };
        set_errno(saved_errno);
    }
}

unsafe fn install_bridge(
    slot: &SignalSlot,
    sig: c_int,
    requested: *const Sigaction,
    oldact: *mut Sigaction,
    real: RealSigaction,
) -> c_int {
    let first_install = !slot.owned.load(Ordering::Acquire);
    let mut previous = MaybeUninit::<Sigaction>::uninit();
    if unsafe { real(sig, ptr::null(), previous.as_mut_ptr()) } == -1 {
        return -1;
    }
    if unsafe { action_is_bridge(sig, requested) } {
        if !oldact.is_null() {
            unsafe { ptr::copy_nonoverlapping(previous.as_ptr(), oldact, 1) };
        }
        return 0;
    }
    let mut bridge = MaybeUninit::<Sigaction>::uninit();
    unsafe {
        ptr::copy_nonoverlapping(requested, bridge.as_mut_ptr(), 1);
        (*bridge.as_mut_ptr()).sa_flags =
            ((*requested).sa_flags | libc::SA_SIGINFO) & !libc::SA_RESETHAND;
        (*bridge.as_mut_ptr()).sa_sigaction = bridge_handler(sig);
    }
    let snapshot = unsafe { libc::malloc(size_of::<Snapshot>()) }.cast::<Snapshot>();
    if snapshot.is_null() {
        return -1;
    }
    unsafe { ptr::copy_nonoverlapping(requested.cast::<Snapshot>(), snapshot, 1) };
    let previous_snapshot = slot.current.swap(snapshot, Ordering::SeqCst);
    if unsafe { real(sig, bridge.as_ptr(), ptr::null_mut()) } == -1 {
        let failed = slot.current.swap(previous_snapshot, Ordering::SeqCst);
        unsafe { slot.release_snapshot(failed) };
        return -1;
    }
    unsafe { slot.release_snapshot(previous_snapshot) };
    slot.owned.store(true, Ordering::Release);
    if !oldact.is_null() {
        unsafe { ptr::copy_nonoverlapping(previous.as_ptr(), oldact, 1) };
    }
    if sig == libc::SIGSEGV {
        if first_install {
            unsafe {
                detect_cpu_vendor();
                debug_runtime_activated();
                debug_log(c"signal interposition initialized".as_ptr());
            }
        }
        let failed =
            unsafe { libc::syscall(libc::SYS_arch_prctl, 0x1012 as c_int, 0 as libc::c_ulong) }
                == -1;
        unsafe {
            debug_log(if failed {
                c"ARCH_SET_CPUID faulting enable failed".as_ptr()
            } else {
                c"CPUID faulting enabled for Wine process".as_ptr()
            })
        };
    }
    0
}

#[cfg_attr(not(test), unsafe(no_mangle))]
pub unsafe extern "C" fn sigaction(
    signum: c_int,
    act: *const Sigaction,
    oldact: *mut Sigaction,
) -> c_int {
    let Some(real) = resolve_real_sigaction() else {
        return -1;
    };
    let Some(slot) = slot_for(signum) else {
        return unsafe { real(signum, act, oldact) };
    };
    if act.is_null() {
        return unsafe { real(signum, act, oldact) };
    }
    let Some(_guard) = UpdateGuard::acquire() else {
        return -1;
    };
    if !slot.owned.load(Ordering::Acquire) && !unsafe { handler_is_from_wine_ntdll(act) } {
        unsafe { real(signum, act, oldact) }
    } else {
        unsafe { install_bridge(slot, signum, act, oldact, real) }
    }
}

#[cfg_attr(not(test), unsafe(no_mangle))]
pub extern "C" fn linuwux_setup_hooks() {
    let _ = resolve_real_sigaction();
    if FORK_REGISTERED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
        && unsafe { libc::pthread_atfork(None, None, Some(after_fork)) } != 0
    {
        FORK_REGISTERED.store(false, Ordering::Release);
    }
}

#[cfg(not(test))]
#[used]
#[unsafe(link_section = ".init_array.00203")]
static INITIALIZE: extern "C" fn() = linuwux_setup_hooks;

#[cfg(test)]
mod tests {
    use super::*;

    fn allocation(marker: c_int) -> *mut Snapshot {
        unsafe {
            let snapshot = libc::malloc(size_of::<Snapshot>()).cast::<Snapshot>();
            assert!(!snapshot.is_null());
            let action = snapshot.cast::<Sigaction>();
            ptr::addr_of_mut!((*action).sa_sigaction).write(marker as usize);
            ptr::addr_of_mut!((*action).sa_flags).write(marker);
            snapshot
        }
    }

    #[cfg(not(miri))]
    #[test]
    fn fork_child_discards_inherited_installation_bookkeeping() {
        linuwux_setup_hooks();
        assert!(FORK_REGISTERED.load(Ordering::Acquire));
        SIGNAL_UPDATE_LOCK.store(true, Ordering::Release);
        SIGSEGV_SLOT.readers.store(7, Ordering::SeqCst);
        SIGSYS_SLOT.readers.store(9, Ordering::SeqCst);
        let child = unsafe {
            let child = libc::fork();
            if child == 0 {
                let reset = !SIGNAL_UPDATE_LOCK.load(Ordering::Acquire)
                    && SIGSEGV_SLOT.readers.load(Ordering::SeqCst) == 0
                    && SIGSYS_SLOT.readers.load(Ordering::SeqCst) == 0;
                libc::_exit(if reset { 0 } else { 1 });
            }
            child
        };
        SIGNAL_UPDATE_LOCK.store(false, Ordering::Release);
        SIGSEGV_SLOT.readers.store(0, Ordering::SeqCst);
        SIGSYS_SLOT.readers.store(0, Ordering::SeqCst);
        assert!(child >= 0);
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn concurrent_snapshot_readers_never_observe_freed_or_mixed_fields() {
        let slot = SignalSlot::new();
        let rounds = if cfg!(miri) { 16 } else { 2000 };
        std::thread::scope(|scope| {
            for _ in 0..2 {
                let slot = &slot;
                scope.spawn(move || {
                    for _ in 0..rounds {
                        let action = slot.copy_saved_action();
                        unsafe {
                            assert_eq!(
                                (*action.as_ptr()).sa_sigaction,
                                (*action.as_ptr()).sa_flags as usize
                            );
                        }
                        std::thread::yield_now();
                    }
                });
            }
            for marker in 1..=rounds {
                let old = slot.current.swap(allocation(marker), Ordering::SeqCst);
                unsafe { slot.release_snapshot(old) };
                std::thread::yield_now();
            }
        });
        let old = slot.current.swap(ptr::null_mut(), Ordering::SeqCst);
        unsafe { slot.release_snapshot(old) };
    }
}
