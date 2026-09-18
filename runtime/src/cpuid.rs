use core::arch::x86_64::__cpuid_count;
use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use libc::{greg_t, siginfo_t, ucontext_t};
use linuwux::cpuid::{ActiveProfile, Registers, Vendor, is_wine_system_rip, proton_avx_enabled};

const ARCH_SET_CPUID: c_int = 0x1012;
const REFLEX_CPUID_CONSUMED: c_int = 1;
static ACTIVE_PROFILE: ActiveProfile = ActiveProfile::new();

unsafe extern "C" {
    fn debug_log(message: *const c_char);
    fn forward_signal(sig: c_int, info: *mut siginfo_t, context: *mut c_void);
    fn reflex_handle_cpuid(leaf: u32, value: u64) -> c_int;
    fn reflex_resume_identity_unarmed() -> c_int;
}

fn native_cpuid(leaf: u32, subleaf: u32) -> Registers {
    let result = __cpuid_count(leaf, subleaf);
    Registers {
        eax: result.eax,
        ebx: result.ebx,
        ecx: result.ecx,
        edx: result.edx,
    }
}

const NATIVE_CACHE_CAP: usize = 32;

struct NativeCache {
    lock: AtomicBool,
    len: AtomicU32,
    keys: [AtomicU64; NATIVE_CACHE_CAP],
    eax: [AtomicU32; NATIVE_CACHE_CAP],
    ebx: [AtomicU32; NATIVE_CACHE_CAP],
    ecx: [AtomicU32; NATIVE_CACHE_CAP],
    edx: [AtomicU32; NATIVE_CACHE_CAP],
}

impl NativeCache {
    const fn new() -> Self {
        Self {
            lock: AtomicBool::new(false),
            len: AtomicU32::new(0),
            keys: [const { AtomicU64::new(0) }; NATIVE_CACHE_CAP],
            eax: [const { AtomicU32::new(0) }; NATIVE_CACHE_CAP],
            ebx: [const { AtomicU32::new(0) }; NATIVE_CACHE_CAP],
            ecx: [const { AtomicU32::new(0) }; NATIVE_CACHE_CAP],
            edx: [const { AtomicU32::new(0) }; NATIVE_CACHE_CAP],
        }
    }

    fn lookup(&self, leaf: u32, subleaf: u32) -> Option<Registers> {
        let key = u64::from(leaf) << 32 | u64::from(subleaf);
        let len = self.len.load(Ordering::Acquire) as usize;
        for index in 0..len.min(NATIVE_CACHE_CAP) {
            if self.keys[index].load(Ordering::Acquire) == key {
                return Some(Registers {
                    eax: self.eax[index].load(Ordering::Acquire),
                    ebx: self.ebx[index].load(Ordering::Acquire),
                    ecx: self.ecx[index].load(Ordering::Acquire),
                    edx: self.edx[index].load(Ordering::Acquire),
                });
            }
        }
        None
    }

    fn insert(&self, leaf: u32, subleaf: u32, regs: Registers) {
        let key = u64::from(leaf) << 32 | u64::from(subleaf);
        while self
            .lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        let len = self.len.load(Ordering::Relaxed) as usize;
        if len < NATIVE_CACHE_CAP {
            self.keys[len].store(key, Ordering::Release);
            self.eax[len].store(regs.eax, Ordering::Release);
            self.ebx[len].store(regs.ebx, Ordering::Release);
            self.ecx[len].store(regs.ecx, Ordering::Release);
            self.edx[len].store(regs.edx, Ordering::Release);
            self.len.store((len + 1) as u32, Ordering::Release);
        }
        self.lock.store(false, Ordering::Release);
    }
}

static NATIVE_CACHE: NativeCache = NativeCache::new();

fn fixed_reply(leaf: u32) -> Option<Registers> {
    let mut reply = ACTIVE_PROFILE.fixed_reply(leaf)?;
    if leaf == 1 && unsafe { reflex_resume_identity_unarmed() } != 0 {
        reply.ecx |= 1 << 31;
    }
    Some(reply)
}

#[unsafe(no_mangle)]
pub extern "C" fn cpuid_disable_faulting() {
    let _ = unsafe { libc::syscall(libc::SYS_arch_prctl, ARCH_SET_CPUID, 1 as libc::c_ulong) };
}

#[unsafe(no_mangle)]
pub extern "C" fn cpuid_configure_profile(vendor: c_int, avx_enabled: c_int) {
    let vendor = match vendor {
        1 => Vendor::Intel,
        2 => Vendor::Amd,
        _ => Vendor::Unknown,
    };
    ACTIVE_PROFILE.configure(vendor, avx_enabled != 0);
}

#[unsafe(no_mangle)]
pub extern "C" fn cpuid_activate_dispatch_profile() {
    ACTIVE_PROFILE.activate_legacy();
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cpuid_get_fixed_reply(leaf: u32, result: *mut Registers) -> c_int {
    if result.is_null() {
        return 0;
    }
    let reply = fixed_reply(leaf);
    unsafe { result.write(reply.unwrap_or_default()) };
    c_int::from(reply.is_some())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn detect_cpu_vendor() {
    let vendor = Vendor::from_leaf0(native_cpuid(0, 0));
    let value = unsafe { libc::getenv(c"PROTON_AVX".as_ptr()) };
    let avx = if value.is_null() {
        false
    } else {
        proton_avx_enabled(Some(unsafe { CStr::from_ptr(value) }.to_bytes()))
    };
    ACTIVE_PROFILE.configure(vendor, avx);
}

fn is_cpuid_instruction_at(address: usize) -> bool {
    if address == 0 {
        return false;
    }
    let mut instruction = [0u8; 2];
    let local = libc::iovec {
        iov_base: instruction.as_mut_ptr().cast(),
        iov_len: instruction.len(),
    };
    let remote = libc::iovec {
        iov_base: address as *mut c_void,
        iov_len: instruction.len(),
    };
    let result = unsafe {
        libc::syscall(
            libc::SYS_process_vm_readv,
            libc::syscall(libc::SYS_getpid),
            &local as *const libc::iovec,
            1 as libc::c_ulong,
            &remote as *const libc::iovec,
            1 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    result == 2 && instruction == [0x0f, 0xa2]
}

fn redirect_all() -> bool {
    crate::config::redirect_all()
}

fn leaf_varies_per_core(leaf: u32) -> bool {
    leaf == 0xb || leaf == 0x1f
}

fn native_reply(leaf: u32, subleaf: u32) -> Registers {
    let cacheable = !leaf_varies_per_core(leaf);
    if cacheable && let Some(cached) = NATIVE_CACHE.lookup(leaf, subleaf) {
        return cached;
    }
    if unsafe { libc::syscall(libc::SYS_arch_prctl, ARCH_SET_CPUID, 1 as libc::c_ulong) } == -1 {
        unsafe { debug_log(c"CPUID native pass-through enable failed; returning zeros".as_ptr()) };
        return Registers::default();
    }

    let result = native_cpuid(leaf, subleaf);
    if unsafe { libc::syscall(libc::SYS_arch_prctl, ARCH_SET_CPUID, 0 as libc::c_ulong) } == -1 {
        unsafe {
            debug_log(c"CPUID faulting re-arm failed; terminating".as_ptr());
            libc::syscall(libc::SYS_exit_group, 127 as c_int);
            libc::_exit(127);
        }
    }
    if cacheable {
        NATIVE_CACHE.insert(leaf, subleaf, result);
    }
    result
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cpuid_sigsegv_handler(
    sig: c_int,
    info: *mut siginfo_t,
    context: *mut c_void,
) {
    let _errno = crate::errno::Errno::save();
    let context_ptr = context.cast::<ucontext_t>();
    if context_ptr.is_null() || info.is_null() {
        unsafe { forward_signal(sig, info, context) };
        return;
    }

    let gregs = unsafe { ptr::addr_of_mut!((*context_ptr).uc_mcontext.gregs).cast::<greg_t>() };
    let is_cpuid_fault = unsafe {
        gregs.add(libc::REG_TRAPNO as usize).read() == 13 && (*info).si_code == libc::SI_KERNEL
    };
    if !is_cpuid_fault {
        unsafe { forward_signal(sig, info, context) };
        return;
    }

    let rip = unsafe { gregs.add(libc::REG_RIP as usize).read() };
    if !is_cpuid_instruction_at(rip as usize) {
        unsafe { forward_signal(sig, info, context) };
        return;
    }

    let (leaf, control) = unsafe {
        (
            gregs.add(libc::REG_RAX as usize).read() as u32,
            gregs.add(libc::REG_RCX as usize).read() as u64,
        )
    };
    let reply = if !redirect_all() && is_wine_system_rip(rip as u64) {
        native_reply(leaf, control as u32)
    } else {
        match fixed_reply(leaf) {
            Some(reply) => reply,
            None => {
                if unsafe { reflex_handle_cpuid(leaf, control) } == REFLEX_CPUID_CONSUMED {
                    Registers::default()
                } else {
                    native_reply(leaf, control as u32)
                }
            }
        }
    };

    unsafe {
        gregs
            .add(libc::REG_RAX as usize)
            .write(i64::from(reply.eax));
        gregs
            .add(libc::REG_RBX as usize)
            .write(i64::from(reply.ebx));
        gregs
            .add(libc::REG_RCX as usize)
            .write(i64::from(reply.ecx));
        gregs
            .add(libc::REG_RDX as usize)
            .write(i64::from(reply.edx));
        gregs.add(libc::REG_RIP as usize).write(rip.wrapping_add(2));
    }
}
