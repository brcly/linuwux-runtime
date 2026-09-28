//! Two unrelated interposition jobs that both need to run before anything
//! else touches signals or allocation:
//!
//! - `sigaction`/`forward_signal`: lets Wine and the game install their own
//!   `SIGSEGV`/`SIGSYS` handlers as normal, but keeps LinUwUx's own bridge
//!   handlers (`cpuid_sigsegv_handler`, `syscallhook`) in the chain ahead of
//!   them, forwarding to whatever was previously installed when LinUwUx
//!   doesn't consume the signal itself. `linuwux_setup_hooks` is the
//!   `.init_array` constructor that resolves the real `sigaction`/`free`/
//!   `malloc` symbols and registers the post-fork recovery handler.
//! - `malloc`/`free`: works around a Wine `win32u` bug where the same
//!   pointer can reach `free()` twice on the same thread with no
//!   intervening allocation; the second call is always a bug (never a
//!   legitimate reallocation-and-refree), so it's unconditionally
//!   suppressed rather than gated behind an opt-in. A small bootstrap pool
//!   serves allocations that arrive before `dlsym` can resolve the real
//!   `malloc` (chicken-and-egg: resolving a symbol can itself allocate).
use core::cell::UnsafeCell;
use core::ffi::{CStr, c_char, c_int, c_void};
use core::mem::{MaybeUninit, size_of};
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicUsize, Ordering};

use libc::{sigaction as Sigaction, siginfo_t, sigset_t};

type RealSigaction = unsafe extern "C" fn(c_int, *const Sigaction, *mut Sigaction) -> c_int;
type RealFree = unsafe extern "C" fn(*mut c_void);
type RealMalloc = unsafe extern "C" fn(usize) -> *mut c_void;
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

    fn copy_saved_action(&self) -> (Snapshot, *mut Snapshot) {
        self.readers.fetch_add(1, Ordering::SeqCst);
        let snapshot = self.current.load(Ordering::SeqCst);
        let action = if snapshot.is_null() {
            MaybeUninit::zeroed()
        } else {
            unsafe { snapshot.read() }
        };
        self.readers.fetch_sub(1, Ordering::SeqCst);
        (action, snapshot)
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
static REAL_FREE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static WIN32U_START: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static WIN32U_END: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static FORK_REGISTERED: AtomicBool = AtomicBool::new(false);
static RESOLVING_FREE_KEY: AtomicU32 = AtomicU32::new(u32::MAX);
static REAL_MALLOC: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static RESOLVING_MALLOC_KEY: AtomicU32 = AtomicU32::new(u32::MAX);

const BOOTSTRAP_POOL_SIZE: usize = 1 << 16;

struct BootstrapPool(UnsafeCell<[u8; BOOTSTRAP_POOL_SIZE]>);
unsafe impl Sync for BootstrapPool {}

static BOOTSTRAP_POOL: BootstrapPool = BootstrapPool(UnsafeCell::new([0; BOOTSTRAP_POOL_SIZE]));
static BOOTSTRAP_OFFSET: AtomicUsize = AtomicUsize::new(0);

fn bootstrap_alloc(size: usize) -> *mut c_void {
    const ALIGN: usize = 16;
    let aligned = (size.max(1) + ALIGN - 1) & !(ALIGN - 1);
    let offset = BOOTSTRAP_OFFSET.fetch_add(aligned, Ordering::SeqCst);
    if offset + aligned > BOOTSTRAP_POOL_SIZE {
        return ptr::null_mut();
    }
    unsafe { BOOTSTRAP_POOL.0.get().cast::<u8>().add(offset).cast() }
}

fn is_bootstrap_ptr(candidate: *mut c_void) -> bool {
    let start = BOOTSTRAP_POOL.0.get() as usize;
    let end = start + BOOTSTRAP_POOL_SIZE;
    let addr = candidate as usize;
    addr >= start && addr < end
}

const WIN32U_PENDING_FREE_CAP: usize = 1024;
static WIN32U_PENDING_FREE_LOCK: AtomicBool = AtomicBool::new(false);
static WIN32U_PENDING_FREE_LEN: AtomicU32 = AtomicU32::new(0);
static WIN32U_PENDING_FREE_NEXT: AtomicU32 = AtomicU32::new(0);
static WIN32U_PENDING_FREE_PTRS: [AtomicPtr<c_void>; WIN32U_PENDING_FREE_CAP] =
    [const { AtomicPtr::new(ptr::null_mut()) }; WIN32U_PENDING_FREE_CAP];

fn with_pending_free_lock<R>(f: impl FnOnce() -> R) -> R {
    while WIN32U_PENDING_FREE_LOCK
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    let result = f();
    WIN32U_PENDING_FREE_LOCK.store(false, Ordering::Release);
    result
}

fn win32u_free_seen_or_mark(ptr: *mut c_void) -> bool {
    with_pending_free_lock(|| {
        let len = WIN32U_PENDING_FREE_LEN.load(Ordering::Relaxed) as usize;
        let found = WIN32U_PENDING_FREE_PTRS
            .iter()
            .take(len)
            .any(|slot| slot.load(Ordering::Relaxed) == ptr);
        if !found {
            let index = (WIN32U_PENDING_FREE_NEXT.load(Ordering::Relaxed) as usize)
                % WIN32U_PENDING_FREE_CAP;
            WIN32U_PENDING_FREE_PTRS[index].store(ptr, Ordering::Relaxed);
            WIN32U_PENDING_FREE_NEXT.store(
                ((index + 1) % WIN32U_PENDING_FREE_CAP) as u32,
                Ordering::Relaxed,
            );
            if len < WIN32U_PENDING_FREE_CAP {
                WIN32U_PENDING_FREE_LEN.store((len + 1) as u32, Ordering::Relaxed);
            }
        }
        found
    })
}

fn win32u_free_consume_if_pending(candidate: *mut c_void) -> bool {
    if candidate.is_null() {
        return false;
    }
    with_pending_free_lock(|| {
        let len = WIN32U_PENDING_FREE_LEN.load(Ordering::Relaxed) as usize;
        for slot in WIN32U_PENDING_FREE_PTRS.iter().take(len) {
            if slot.load(Ordering::Relaxed) == candidate {
                slot.store(ptr::null_mut(), Ordering::Relaxed);
                return true;
            }
        }
        false
    })
}

fn resolve_real_malloc() -> Option<RealMalloc> {
    if !tls_ptr(&RESOLVING_MALLOC_KEY).is_null() {
        return None;
    }
    let mut symbol = REAL_MALLOC.load(Ordering::Acquire);
    if symbol.is_null() {
        set_tls_ptr(&RESOLVING_MALLOC_KEY, ptr::dangling_mut());
        symbol = unsafe { libc::dlsym(libc::RTLD_NEXT, c"malloc".as_ptr()) };
        set_tls_ptr(&RESOLVING_MALLOC_KEY, ptr::null_mut());
        if symbol.is_null() {
            return None;
        }
        REAL_MALLOC.store(symbol, Ordering::Release);
    }
    Some(unsafe { core::mem::transmute::<*mut c_void, RealMalloc>(symbol) })
}

unsafe extern "C" fn malloc_inner(size: usize, caller: *mut c_void) -> *mut c_void {
    let Some(real) = resolve_real_malloc() else {
        return bootstrap_alloc(size);
    };
    let allocated = unsafe { real(size) };
    if game_process() && caller_from_win32u(caller) {
        win32u_free_consume_if_pending(allocated);
    }
    allocated
}

#[cfg(not(miri))]
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub unsafe extern "C" fn malloc(_size: usize) -> *mut c_void {
    core::arch::naked_asm!(
        "mov rsi, qword ptr [rsp]",
        "jmp {inner}",
        inner = sym malloc_inner,
    );
}
fn pthread_key(slot: &AtomicU32) -> Option<libc::pthread_key_t> {
    let existing = slot.load(Ordering::Acquire);
    if existing != u32::MAX {
        return Some(existing);
    }
    let mut created: libc::pthread_key_t = 0;
    if unsafe { libc::pthread_key_create(&mut created, None) } != 0 {
        return None;
    }
    match slot.compare_exchange(u32::MAX, created, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => Some(created),
        Err(current) => {
            unsafe { libc::pthread_key_delete(created) };
            Some(current)
        }
    }
}

fn tls_ptr(slot: &AtomicU32) -> *mut c_void {
    pthread_key(slot).map_or(ptr::null_mut(), |key| unsafe {
        libc::pthread_getspecific(key)
    })
}

fn set_tls_ptr(slot: &AtomicU32, value: *mut c_void) {
    if let Some(key) = pthread_key(slot) {
        unsafe { libc::pthread_setspecific(key, value) };
    }
}

extern "C" fn after_fork() {
    SIGNAL_UPDATE_LOCK.store(false, Ordering::Release);
    SIGSEGV_SLOT.readers.store(0, Ordering::SeqCst);
    SIGSYS_SLOT.readers.store(0, Ordering::SeqCst);
    set_tls_ptr(&RESOLVING_FREE_KEY, ptr::null_mut());
    set_tls_ptr(&RESOLVING_MALLOC_KEY, ptr::null_mut());
    WIN32U_PENDING_FREE_LOCK.store(false, Ordering::Release);
    unsafe { cpuid_disable_faulting() };
}

unsafe extern "C" {
    fn cpuid_sigsegv_handler(sig: c_int, info: *mut siginfo_t, context: *mut c_void);
    fn cpuid_disable_faulting();
    fn syscallhook(sig: c_int, info: *mut siginfo_t, context: *mut c_void);
    fn detect_cpu_vendor();
    fn debug_runtime_activated();
    fn debug_log(message: *const c_char);
    fn debug_log_hex(prefix: *const c_char, value: u64);
}

fn errno() -> c_int {
    unsafe { *libc::__errno_location() }
}

fn set_errno(value: c_int) {
    unsafe { *libc::__errno_location() = value };
}

fn game_process() -> bool {
    #[cfg(feature = "environment")]
    {
        crate::environment::game_process()
    }
    #[cfg(not(feature = "environment"))]
    false
}

fn resolve_real_free() -> Option<RealFree> {
    if !tls_ptr(&RESOLVING_FREE_KEY).is_null() {
        return None;
    }
    let mut symbol = REAL_FREE.load(Ordering::Acquire);
    if symbol.is_null() {
        set_tls_ptr(&RESOLVING_FREE_KEY, ptr::dangling_mut());
        symbol = unsafe { libc::dlsym(libc::RTLD_NEXT, c"free".as_ptr()) };
        set_tls_ptr(&RESOLVING_FREE_KEY, ptr::null_mut());
        if symbol.is_null() {
            return None;
        }
        REAL_FREE.store(symbol, Ordering::Release);
    }
    Some(unsafe { core::mem::transmute::<*mut c_void, RealFree>(symbol) })
}

unsafe extern "C" fn record_win32u(
    info: *mut libc::dl_phdr_info,
    _size: usize,
    _data: *mut c_void,
) -> c_int {
    if info.is_null() {
        return 0;
    }
    let name = unsafe { (*info).dlpi_name };
    if name.is_null() {
        return 0;
    }
    let name = unsafe { CStr::from_ptr(name) }.to_bytes();
    let basename = name.rsplit(|&byte| byte == b'/').next().unwrap_or(name);
    if basename != b"win32u.so" && basename != b"win32u.dll.so" {
        return 0;
    }
    let base = unsafe { (*info).dlpi_addr } as usize;
    let mut end = base;
    let phnum = unsafe { (*info).dlpi_phnum } as usize;
    let phdr = unsafe { (*info).dlpi_phdr };
    for index in 0..phnum {
        let ph = unsafe { &*phdr.add(index) };
        if ph.p_type != libc::PT_LOAD {
            continue;
        }
        let segment_end = base
            .wrapping_add(ph.p_vaddr as usize)
            .wrapping_add(ph.p_memsz as usize);
        if segment_end > end {
            end = segment_end;
        }
    }
    WIN32U_START.store(base as *mut c_void, Ordering::Release);
    WIN32U_END.store(end as *mut c_void, Ordering::Release);
    1
}

fn caller_from_win32u(caller: *mut c_void) -> bool {
    if caller.is_null() {
        return false;
    }
    let mut start = WIN32U_START.load(Ordering::Acquire) as usize;
    let mut end = WIN32U_END.load(Ordering::Acquire) as usize;
    if start == 0 || end <= start {
        unsafe { libc::dl_iterate_phdr(Some(record_win32u), ptr::null_mut()) };
        start = WIN32U_START.load(Ordering::Acquire) as usize;
        end = WIN32U_END.load(Ordering::Acquire) as usize;
        if start == 0 || end <= start {
            return false;
        }
        unsafe {
            debug_log_hex(c"win32u base=".as_ptr(), start as u64);
            debug_log_hex(c"win32u end=".as_ptr(), end as u64);
        }
    }
    let addr = caller as usize;
    addr >= start && addr < end
}

unsafe extern "C" fn free_inner(ptr: *mut c_void, caller: *mut c_void) {
    if is_bootstrap_ptr(ptr) {
        return;
    }
    let Some(real) = resolve_real_free() else {
        return;
    };
    if game_process()
        && !ptr.is_null()
        && caller_from_win32u(caller)
        && win32u_free_seen_or_mark(ptr)
    {
        return;
    }
    unsafe { real(ptr) };
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
    basename == b"ntdll.so" || basename == b"ntdll.dll.so" || basename == b"ntdll.dll"
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

#[unsafe(no_mangle)]
pub unsafe extern "C" fn forward_signal(sig: c_int, info: *mut siginfo_t, context: *mut c_void) {
    let Some(slot) = slot_for(sig) else {
        restore_default_and_raise(sig);
        return;
    };
    let (saved, saved_snapshot) = slot.copy_saved_action();
    let (handler, flags) = unsafe { ((*saved.as_ptr()).sa_sigaction, (*saved.as_ptr()).sa_flags) };
    if handler == libc::SIG_DFL {
        restore_default_and_raise(sig);
    } else if handler != libc::SIG_IGN {
        if flags & libc::SA_RESETHAND != 0 {
            let _ = slot.current.compare_exchange(
                saved_snapshot,
                ptr::null_mut(),
                Ordering::SeqCst,
                Ordering::SeqCst,
            );
        }
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
    let mut previous_logical = MaybeUninit::<Sigaction>::uninit();
    let have_previous_logical = !previous_snapshot.is_null();
    if have_previous_logical {
        unsafe {
            ptr::copy_nonoverlapping(
                previous_snapshot.cast::<Sigaction>(),
                previous_logical.as_mut_ptr(),
                1,
            )
        };
    }
    if unsafe { real(sig, bridge.as_ptr(), ptr::null_mut()) } == -1 {
        let failed = slot.current.swap(previous_snapshot, Ordering::SeqCst);
        unsafe { slot.release_snapshot(failed) };
        return -1;
    }
    unsafe { slot.release_snapshot(previous_snapshot) };
    slot.owned.store(true, Ordering::Release);
    if !oldact.is_null() {
        let source = if have_previous_logical {
            previous_logical.as_ptr()
        } else {
            previous.as_ptr()
        };
        unsafe { ptr::copy_nonoverlapping(source, oldact, 1) };
    }
    #[cfg(feature = "kuser")]
    crate::kuser::force_direct_syscall();
    if sig == libc::SIGSEGV {
        #[cfg(feature = "kuser")]
        crate::kuser::prepare_shared_page();
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

#[cfg(not(miri))]
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub unsafe extern "C" fn free(_ptr: *mut c_void) {
    // SAFETY: SysV `free` receives the pointer in `rdi`. The return address is
    // still at `[rsp]`; copying it into `rsi` and jumping keeps the original
    // frame so `free_inner` returns to the caller.
    core::arch::naked_asm!(
        "mov rsi, qword ptr [rsp]",
        "jmp {inner}",
        inner = sym free_inner,
    );
}

#[unsafe(no_mangle)]
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

#[unsafe(no_mangle)]
pub extern "C" fn linuwux_setup_hooks() {
    let _ = resolve_real_sigaction();
    let _ = resolve_real_free();
    let _ = resolve_real_malloc();
    if FORK_REGISTERED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
        && unsafe { libc::pthread_atfork(None, None, Some(after_fork)) } != 0
    {
        FORK_REGISTERED.store(false, Ordering::Release);
    }
}

#[used]
#[unsafe(link_section = ".init_array.00203")]
static INITIALIZE: extern "C" fn() = linuwux_setup_hooks;
