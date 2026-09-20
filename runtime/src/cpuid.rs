use core::arch::x86_64::__cpuid_count;
use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use libc::{greg_t, siginfo_t, ucontext_t};
use linuwux::cpuid::{
    ActiveCpuIdentity, CpuPresentation, Registers, Vendor, is_wine_system_rip, proton_avx_enabled,
};
use linuwux::kuser::Recipe;

const ARCH_SET_CPUID: c_int = 0x1012;
const REFLEX_CPUID_CONSUMED: c_int = 1;
static ACTIVE_IDENTITY: ActiveCpuIdentity = ActiveCpuIdentity::new();
static REFLEX64_PRESENTATION_SELECTED: AtomicBool = AtomicBool::new(false);

const CALLER_CACHE_CAP: usize = 16;

struct CallerCache {
    lock: AtomicBool,
    len: AtomicU32,
    starts: [AtomicU64; CALLER_CACHE_CAP],
    ends: [AtomicU64; CALLER_CACHE_CAP],
    reflex64: [AtomicBool; CALLER_CACHE_CAP],
}

impl CallerCache {
    const fn new() -> Self {
        Self {
            lock: AtomicBool::new(false),
            len: AtomicU32::new(0),
            starts: [const { AtomicU64::new(0) }; CALLER_CACHE_CAP],
            ends: [const { AtomicU64::new(0) }; CALLER_CACHE_CAP],
            reflex64: [const { AtomicBool::new(false) }; CALLER_CACHE_CAP],
        }
    }

    fn lookup(&self, address: u64) -> Option<bool> {
        let len = self.len.load(Ordering::Acquire) as usize;
        for index in 0..len.min(CALLER_CACHE_CAP) {
            let start = self.starts[index].load(Ordering::Acquire);
            let end = self.ends[index].load(Ordering::Acquire);
            if (start..end).contains(&address) {
                return Some(self.reflex64[index].load(Ordering::Acquire));
            }
        }
        None
    }

    fn insert(&self, start: u64, end: u64, reflex64: bool) {
        while self
            .lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        let len = self.len.load(Ordering::Relaxed) as usize;
        if len < CALLER_CACHE_CAP {
            self.starts[len].store(start, Ordering::Relaxed);
            self.ends[len].store(end, Ordering::Relaxed);
            self.reflex64[len].store(reflex64, Ordering::Relaxed);
            self.len.store((len + 1) as u32, Ordering::Release);
        }
        self.lock.store(false, Ordering::Release);
    }
}

static CALLER_CACHE: CallerCache = CallerCache::new();

unsafe extern "C" {
    fn debug_log(message: *const c_char);
    fn forward_signal(sig: c_int, info: *mut siginfo_t, context: *mut c_void);
    fn reflex_handle_cpuid(leaf: u32, value: u64) -> c_int;
    fn reflex_resume_identity_unarmed() -> c_int;
}

fn is_identity_leaf(leaf: u32) -> bool {
    matches!(leaf, 1 | 0x4000_0000..=0x4000_0001 | 0x8000_0002..=0x8000_0004)
}

fn parse_hex(value: &[u8]) -> Option<u64> {
    if value.is_empty() {
        return None;
    }
    value.iter().try_fold(0u64, |result, &byte| {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return None,
        };
        result.checked_mul(16)?.checked_add(u64::from(digit))
    })
}

fn read_memory(address: u64, output: &mut [u8]) -> bool {
    if address == 0 || output.is_empty() {
        return false;
    }
    let local = libc::iovec {
        iov_base: output.as_mut_ptr().cast(),
        iov_len: output.len(),
    };
    let remote = libc::iovec {
        iov_base: address as *mut c_void,
        iov_len: output.len(),
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
    result == output.len() as libc::c_long
}

fn little_endian_u16(bytes: &[u8]) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(..2)?.try_into().ok()?))
}

fn little_endian_u32(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?))
}

fn reflex64_export_name(base: u64) -> bool {
    let mut dos = [0u8; 64];
    if !read_memory(base, &mut dos) || dos.get(..2) != Some(b"MZ") {
        return false;
    }
    let Some(header_offset) = little_endian_u32(&dos[0x3c..]) else {
        return false;
    };
    let header_address = match base.checked_add(u64::from(header_offset)) {
        Some(address) => address,
        None => return false,
    };
    let mut header = [0u8; 160];
    if !read_memory(header_address, &mut header)
        || header.get(..4) != Some(b"PE\0\0")
        || little_endian_u16(&header[24..]) != Some(0x20b)
    {
        return false;
    }
    let Some(export_rva) = little_endian_u32(&header[136..]) else {
        return false;
    };
    let export_address = match base.checked_add(u64::from(export_rva)) {
        Some(address) => address,
        None => return false,
    };
    let mut export = [0u8; 16];
    if !read_memory(export_address, &mut export) {
        return false;
    }
    let Some(name_rva) = little_endian_u32(&export[12..]) else {
        return false;
    };
    let name_address = match base.checked_add(u64::from(name_rva)) {
        Some(address) => address,
        None => return false,
    };
    let mut name = [0u8; 13];
    read_memory(name_address, &mut name) && name == *b"reflex64.dll\0"
}

fn reflex64_pe_image(address: u64) -> bool {
    const ALLOCATION_GRANULARITY: u64 = 0x1_0000;
    const SEARCH_DISTANCE: u64 = 0x10_00000;
    let aligned = address & !(ALLOCATION_GRANULARITY - 1);
    for offset in (0..=SEARCH_DISTANCE).step_by(ALLOCATION_GRANULARITY as usize) {
        let Some(base) = aligned.checked_sub(offset) else {
            break;
        };
        if reflex64_export_name(base) {
            return true;
        }
    }
    false
}

fn reflex64_mapping(line: &[u8], address: u64) -> Option<(u64, u64, bool)> {
    let mut fields = line
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty());
    let range = fields.next()?;
    let mut bounds = range.split(|&byte| byte == b'-');
    let start = parse_hex(bounds.next()?)?;
    let end = parse_hex(bounds.next()?)?;
    if bounds.next().is_some() || !(start..end).contains(&address) {
        return None;
    }
    let _permissions = fields.next()?;
    let _offset = fields.next()?;
    let _device = fields.next()?;
    let _inode = fields.next()?;
    let pathname = fields.next().unwrap_or_default();
    let filename = pathname
        .rsplit(|&byte| byte == b'/')
        .next()
        .unwrap_or_default();
    Some((
        start,
        end,
        matches!(filename, b"reflex64.dll" | b"reflex64.dll.so"),
    ))
}

fn classify_caller(address: u64) -> Option<bool> {
    if let Some(reflex64) = CALLER_CACHE.lookup(address) {
        return Some(reflex64);
    }

    let fd = unsafe {
        libc::open(
            c"/proc/self/maps".as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return None;
    }

    let mut chunk = [0u8; 4096];
    let mut line = [0u8; 1024];
    let mut length = 0;
    let mut overflow = false;
    let mut result = None;
    'chunks: loop {
        let count = unsafe { libc::read(fd, chunk.as_mut_ptr().cast(), chunk.len()) };
        if count <= 0 {
            break;
        }
        for &byte in &chunk[..count as usize] {
            if byte == b'\n' {
                if !overflow && let Some(mapping) = reflex64_mapping(&line[..length], address) {
                    result = Some(mapping);
                    break 'chunks;
                }
                length = 0;
                overflow = false;
            } else if length < line.len() {
                line[length] = byte;
                length += 1;
            } else {
                overflow = true;
            }
        }
    }
    unsafe { libc::close(fd) };

    let (start, end, filename_matches) = result?;
    let reflex64 = filename_matches || reflex64_pe_image(address);
    CALLER_CACHE.insert(start, end, reflex64);
    Some(reflex64)
}

fn select_caller_presentation(leaf: u32, rip: u64) {
    if !is_identity_leaf(leaf)
        || REFLEX64_PRESENTATION_SELECTED.load(Ordering::Acquire)
        || ACTIVE_IDENTITY.load().presentation() == CpuPresentation::Legacy
    {
        return;
    }
    if classify_caller(rip) == Some(true) {
        ACTIVE_IDENTITY.select_legacy_presentation();
        REFLEX64_PRESENTATION_SELECTED.store(true, Ordering::Release);
        unsafe { debug_log(c"cpuid presentation selected: reflex64 caller".as_ptr()) };
    }
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

fn fixed_reply(leaf: u32, rip: Option<u64>) -> Option<Registers> {
    if let Some(rip) = rip {
        select_caller_presentation(leaf, rip);
    }
    let mut reply = ACTIVE_IDENTITY.fixed_reply(leaf)?;
    if leaf == 1 && unsafe { reflex_resume_identity_unarmed() } != 0 {
        reply.ecx |= 1 << 31;
    }
    Some(reply)
}

fn configure_identity(vendor: Vendor, avx_enabled: bool) {
    ACTIVE_IDENTITY.configure_host(vendor, avx_enabled);
    if crate::config::legacy_profile_forced() {
        ACTIVE_IDENTITY.select_legacy_presentation();
        unsafe { debug_log(c"cpuid presentation selected: legacy override".as_ptr()) };
    }
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
    configure_identity(vendor, avx_enabled != 0);
}

#[unsafe(no_mangle)]
pub extern "C" fn cpuid_activate_legacy_profile() {
    unsafe { debug_log(c"cpuid presentation selected: legacy protocol".as_ptr()) };
    ACTIVE_IDENTITY.select_legacy_presentation();
}

#[unsafe(no_mangle)]
pub extern "C" fn cpuid_kuser_recipe() -> c_int {
    let identity = ACTIVE_IDENTITY.load();
    match (identity.presentation(), identity.vendor()) {
        (CpuPresentation::Legacy, Vendor::Intel) => Recipe::Dispatch as c_int,
        (CpuPresentation::Legacy, Vendor::Amd | Vendor::Unknown) => Recipe::Selector as c_int,
        (CpuPresentation::Denuvo, _) => Recipe::Resume as c_int,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cpuid_get_fixed_reply(leaf: u32, result: *mut Registers) -> c_int {
    if result.is_null() {
        return 0;
    }
    let reply = fixed_reply(leaf, None);
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
    unsafe {
        debug_log(
            match vendor {
                Vendor::Intel => c"cpuid host vendor=intel",
                Vendor::Amd => c"cpuid host vendor=amd",
                Vendor::Unknown => c"cpuid host vendor=unknown",
            }
            .as_ptr(),
        );
        debug_log(if avx {
            c"cpuid host avx=enabled".as_ptr()
        } else {
            c"cpuid host avx=disabled".as_ptr()
        });
    }
    configure_identity(vendor, avx);
}

fn is_cpuid_instruction_at(address: usize) -> bool {
    let mut instruction = [0u8; 2];
    read_memory(address as u64, &mut instruction) && instruction == [0x0f, 0xa2]
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
        match fixed_reply(leaf, Some(rip as u64)) {
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
