//! The SIGSEGV handler for CPUID traps (Linux `ARCH_SET_CPUID` faulting) and
//! everything it needs: per-caller image detection (`reflex64.dll` selects
//! the legacy presentation; `artifact.dll` selects host-specific CPU identity
//! replies),
//! native-CPUID pass-through and caching for leaves LinUwUx doesn't own, and
//! the `.init_array` constructor that detects the host vendor at startup.
//! Reply *content* for a given [`linuwux::cpuid::CpuIdentity`] lives in the
//! safe core (`protocol/cpuid.rs`); this file owns the trap itself and the
//! process-local decisions about which identity applies to which caller.
use core::arch::x86_64::__cpuid_count;
use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering, fence};

use crate::maps;
use crate::procmem::read_memory;
use libc::{greg_t, siginfo_t, ucontext_t};
use linuwux::cpuid::{
    ActiveCpuIdentity, CpuPresentation, Registers, Vendor, artifact_amd_reply,
    artifact_intel_reply, is_wine_system_rip, proton_avx_enabled,
};
use linuwux::kuser::Recipe;

const ARCH_SET_CPUID: c_int = 0x1012;
const REFLEX_CPUID_CONSUMED: c_int = 1;
static ACTIVE_IDENTITY: ActiveCpuIdentity = ActiveCpuIdentity::new();
static REFLEX64_PRESENTATION_SELECTED: AtomicBool = AtomicBool::new(false);
static ARTIFACT_PROFILE_SELECTED: AtomicBool = AtomicBool::new(false);
/// Set once Reflex's registration leaf (`0x336933`, the same handshake the
/// pre-Rust runtime called "arm") has fired at least once, for either the
/// legacy or modern protocol — both set the resume handler from this leaf,
/// so it fires regardless of which protocol variant a title uses. Once a
/// session has reached this point, `classify_caller`'s brute-force
/// `pe_image_named` fallback (for a caller whose mapping has no recognized
/// DLL path — a reflectively-loaded Reflex64/Artifact, or equally, a
/// Denuvo-style VM handler at some never-before-seen code address) is no
/// longer worth paying for: Reflex is confirmably active in this process
/// either way, and every further identity-leaf trap from an address that
/// genuinely isn't Reflex64/Artifact would otherwise re-run that same
/// expensive search forever, for the rest of the session.
static PROTOCOL_ESTABLISHED: AtomicBool = AtomicBool::new(false);
#[cfg(all(
    feature = "debug",
    feature = "environment",
    feature = "hooks",
    feature = "kuser"
))]
static FORWARDED_GAME_FAULTS_LOGGED: AtomicU64 = AtomicU64::new(0);

const CALLER_CACHE_CAP: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
enum CallerKind {
    Ordinary = 0,
    Reflex64 = 1,
    Artifact = 2,
}

impl CallerKind {
    fn from_raw(value: u32) -> Self {
        match value {
            1 => Self::Reflex64,
            2 => Self::Artifact,
            _ => Self::Ordinary,
        }
    }
}

/// Mapping ranges already classified, so a repeat caller skips the
/// `/proc/self/maps` scan. Entries are replaced round-robin once full; each
/// has a seqlock so a reader never pairs one entry's start with another's end.
struct CallerCache {
    lock: AtomicBool,
    next: AtomicU32,
    sequences: [AtomicU32; CALLER_CACHE_CAP],
    starts: [AtomicU64; CALLER_CACHE_CAP],
    ends: [AtomicU64; CALLER_CACHE_CAP],
    kinds: [AtomicU32; CALLER_CACHE_CAP],
}

impl CallerCache {
    const fn new() -> Self {
        Self {
            lock: AtomicBool::new(false),
            next: AtomicU32::new(0),
            sequences: [const { AtomicU32::new(0) }; CALLER_CACHE_CAP],
            starts: [const { AtomicU64::new(0) }; CALLER_CACHE_CAP],
            ends: [const { AtomicU64::new(0) }; CALLER_CACHE_CAP],
            kinds: [const { AtomicU32::new(CallerKind::Ordinary as u32) }; CALLER_CACHE_CAP],
        }
    }

    fn lookup(&self, address: u64) -> Option<CallerKind> {
        for index in 0..CALLER_CACHE_CAP {
            let before = self.sequences[index].load(Ordering::Acquire);
            if before & 1 != 0 {
                continue;
            }
            let start = self.starts[index].load(Ordering::Relaxed);
            let end = self.ends[index].load(Ordering::Relaxed);
            let kind = self.kinds[index].load(Ordering::Relaxed);
            fence(Ordering::Acquire);
            if self.sequences[index].load(Ordering::Relaxed) == before
                && (start..end).contains(&address)
            {
                return Some(CallerKind::from_raw(kind));
            }
        }
        None
    }

    /// Skips caching rather than spinning if another insert is in progress:
    /// this runs inside the SIGSEGV handler, possibly on top of that insert.
    fn insert(&self, start: u64, end: u64, kind: CallerKind) {
        if self
            .lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let index = self.next.load(Ordering::Relaxed) as usize % CALLER_CACHE_CAP;
        self.next.store((index + 1) as u32, Ordering::Relaxed);
        let sequence = self.sequences[index].load(Ordering::Relaxed);
        self.sequences[index].store(sequence.wrapping_add(1), Ordering::Relaxed);
        fence(Ordering::Release);
        self.starts[index].store(start, Ordering::Relaxed);
        self.ends[index].store(end, Ordering::Relaxed);
        self.kinds[index].store(kind as u32, Ordering::Relaxed);
        self.sequences[index].store(sequence.wrapping_add(2), Ordering::Release);
        self.lock.store(false, Ordering::Release);
    }
}

static CALLER_CACHE: CallerCache = CallerCache::new();

unsafe extern "C" {
    fn debug_log(message: *const c_char);
    #[cfg(all(
        feature = "debug",
        feature = "environment",
        feature = "hooks",
        feature = "kuser"
    ))]
    fn debug_log_hex(prefix: *const c_char, value: u64);
    fn forward_signal(sig: c_int, info: *mut siginfo_t, context: *mut c_void);
    fn reflex_handle_cpuid(leaf: u32, rcx: u64, rdx: u64) -> c_int;
    fn reflex_resume_identity_unarmed() -> c_int;
}

fn is_identity_leaf(leaf: u32) -> bool {
    matches!(leaf, 1 | 0x4000_0000..=0x4000_0001 | 0x8000_0002..=0x8000_0004)
}

fn little_endian_u16(bytes: &[u8]) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(..2)?.try_into().ok()?))
}

fn little_endian_u32(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?))
}

fn pe_export_name(base: u64, expected: &[u8]) -> bool {
    if expected.len() >= 32 {
        return false;
    }
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
    let mut name = [0u8; 32];
    let length = expected.len() + 1;
    read_memory(name_address, &mut name[..length])
        && name[..expected.len()] == *expected
        && name[expected.len()] == 0
}

fn pe_image_named(address: u64, expected: &[u8]) -> bool {
    const ALLOCATION_GRANULARITY: u64 = 0x1_0000;
    const SEARCH_DISTANCE: u64 = 0x10_00000;
    let aligned = address & !(ALLOCATION_GRANULARITY - 1);
    for offset in (0..=SEARCH_DISTANCE).step_by(ALLOCATION_GRANULARITY as usize) {
        let Some(base) = aligned.checked_sub(offset) else {
            break;
        };
        if pe_export_name(base, expected) {
            return true;
        }
    }
    false
}

fn caller_mapping(line: &[u8], address: u64) -> Option<(u64, u64, CallerKind)> {
    let mapping = maps::parse(line)?;
    (mapping.start..mapping.end)
        .contains(&address)
        .then(|| (mapping.start, mapping.end, path_kind(mapping.path)))
}

#[cfg(test)]
fn mapping_path_kind(line: &[u8]) -> CallerKind {
    maps::parse(line).map_or(CallerKind::Ordinary, |mapping| path_kind(mapping.path))
}

fn path_kind(pathname: &[u8]) -> CallerKind {
    let pathname = pathname.strip_suffix(b" (deleted)").unwrap_or(pathname);
    let filename = pathname
        .rsplit(|&byte| byte == b'/')
        .next()
        .unwrap_or_default();
    if matches!(filename, b"reflex64.dll" | b"reflex64.dll.so") {
        CallerKind::Reflex64
    } else if matches!(filename, b"artifact.dll" | b"artifact.dll.so") {
        CallerKind::Artifact
    } else {
        CallerKind::Ordinary
    }
}

fn artifact_module_mapped() -> bool {
    maps::find_line(|line| {
        maps::parse(line).is_some_and(|mapping| path_kind(mapping.path) == CallerKind::Artifact)
    })
}

/// A negative `artifact_module_mapped` result stays valid until a new file
/// mapping appears. This library's `mmap` interposer counts those; mappings
/// made without it (such as by the dynamic loader) are caught by rescanning
/// at least every [`ARTIFACT_RESCAN_INTERVAL_MS`].
const ARTIFACT_RESCAN_INTERVAL_MS: u64 = 1000;
static ARTIFACT_SCAN_GENERATION: AtomicU64 = AtomicU64::new(u64::MAX);
static ARTIFACT_SCAN_MILLISECONDS: AtomicU64 = AtomicU64::new(0);

fn mapping_generation() -> Option<u64> {
    #[cfg(all(feature = "syscall", feature = "kuser", feature = "environment"))]
    return Some(maps::file_mapping_generation());
    #[cfg(not(all(feature = "syscall", feature = "kuser", feature = "environment")))]
    None
}

fn artifact_module_newly_mapped() -> bool {
    let Some(generation) = mapping_generation() else {
        return artifact_module_mapped();
    };
    let now = crate::clock::coarse_milliseconds();
    if generation == ARTIFACT_SCAN_GENERATION.load(Ordering::Relaxed)
        && now.wrapping_sub(ARTIFACT_SCAN_MILLISECONDS.load(Ordering::Relaxed))
            < ARTIFACT_RESCAN_INTERVAL_MS
    {
        return false;
    }
    let found = artifact_module_mapped();
    if !found {
        ARTIFACT_SCAN_MILLISECONDS.store(now, Ordering::Relaxed);
        ARTIFACT_SCAN_GENERATION.store(generation, Ordering::Relaxed);
    }
    found
}

fn classify_caller(address: u64) -> Option<CallerKind> {
    if let Some(kind) = CALLER_CACHE.lookup(address) {
        return Some(kind);
    }
    let mut result = None;
    maps::find_line(|line| {
        result = caller_mapping(line, address);
        result.is_some()
    });
    let (start, end, mapped_kind) = result?;
    // Once Reflex's registration handshake has fired, a caller this scan
    // couldn't classify by path is confirmably not worth a brute-force
    // search for: Reflex is already known to be active in this process
    // either way, and paying ~80us to keep re-confirming that fact on every
    // future identity-leaf trap from any address it hasn't already seen
    // buys nothing. See `PROTOCOL_ESTABLISHED`'s doc comment.
    let still_searching =
        mapped_kind == CallerKind::Ordinary && !PROTOCOL_ESTABLISHED.load(Ordering::Acquire);
    let kind = match mapped_kind {
        CallerKind::Ordinary if still_searching && pe_image_named(address, b"reflex64.dll") => {
            CallerKind::Reflex64
        }
        CallerKind::Ordinary if still_searching && pe_image_named(address, b"artifact.dll") => {
            CallerKind::Artifact
        }
        kind => kind,
    };
    CALLER_CACHE.insert(start, end, kind);
    Some(kind)
}

fn select_caller_presentation(leaf: u32, rip: u64) -> CallerKind {
    if !is_identity_leaf(leaf) {
        return CallerKind::Ordinary;
    }
    let kind = classify_caller(rip).unwrap_or(CallerKind::Ordinary);
    if kind == CallerKind::Reflex64
        && !REFLEX64_PRESENTATION_SELECTED.load(Ordering::Acquire)
        && ACTIVE_IDENTITY.load().presentation() != CpuPresentation::Legacy
    {
        ACTIVE_IDENTITY.select_legacy_presentation();
        REFLEX64_PRESENTATION_SELECTED.store(true, Ordering::Release);
        unsafe { debug_log(c"cpuid presentation selected: reflex64 caller".as_ptr()) };
    }
    kind
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

fn artifact_reply(vendor: Vendor, leaf: u32) -> Option<Registers> {
    match vendor {
        Vendor::Intel => artifact_intel_reply(leaf),
        Vendor::Amd => artifact_amd_reply(leaf),
        Vendor::Unknown => None,
    }
}

fn with_native_apic_id(mut reply: Registers, native_ebx: u32) -> Registers {
    reply.ebx |= native_ebx & 0xff00_0000;
    reply
}

fn fixed_reply(leaf: u32, rip: Option<u64>) -> Option<Registers> {
    let caller = rip
        .map(|rip| select_caller_presentation(leaf, rip))
        .unwrap_or(CallerKind::Ordinary);
    let vendor = ACTIVE_IDENTITY.load().vendor();
    let artifact_leaf = artifact_reply(vendor, leaf);
    if artifact_leaf.is_some() {
        let artifact_present = caller == CallerKind::Artifact
            || ARTIFACT_PROFILE_SELECTED.load(Ordering::Acquire)
            || artifact_module_newly_mapped();
        if artifact_present
            && ARTIFACT_PROFILE_SELECTED
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            unsafe {
                debug_log(
                    match vendor {
                        Vendor::Intel => c"cpuid profile selected: Intel artifact.dll",
                        Vendor::Amd => c"cpuid profile selected: AMD artifact.dll",
                        Vendor::Unknown => c"cpuid profile selected: artifact.dll",
                    }
                    .as_ptr(),
                );
            }
        }
    }
    let artifact_profile = ARTIFACT_PROFILE_SELECTED.load(Ordering::Acquire)
        && matches!(vendor, Vendor::Intel | Vendor::Amd);
    let mut reply = if artifact_profile {
        artifact_leaf.or_else(|| ACTIVE_IDENTITY.fixed_reply(leaf))?
    } else {
        ACTIVE_IDENTITY.fixed_reply(leaf)?
    };
    if artifact_profile && leaf == 1 {
        reply = with_native_apic_id(reply, native_reply(1, 0).ebx);
    }
    if !artifact_profile && leaf == 1 && unsafe { reflex_resume_identity_unarmed() } != 0 {
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
    let _ = unsafe {
        libc::syscall(
            libc::SYS_arch_prctl,
            ARCH_SET_CPUID as libc::c_long,
            1 as libc::c_ulong,
        )
    };
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

#[cfg(all(
    feature = "debug",
    feature = "environment",
    feature = "hooks",
    feature = "kuser"
))]
fn trace_forwarded_game_fault(info: *const siginfo_t, gregs: *const greg_t) {
    if !crate::environment::game_process()
        || FORWARDED_GAME_FAULTS_LOGGED.fetch_add(1, Ordering::Relaxed) >= 8
    {
        return;
    }
    // SAFETY: the caller has checked both signal-frame pointers non-null.
    let rip = unsafe { gregs.add(libc::REG_RIP as usize).read() as u64 };
    let mut opcode = [0; 2];
    let opcode = if read_memory(rip, &mut opcode) {
        u16::from_le_bytes(opcode)
    } else {
        u16::MAX
    };
    // SAFETY: the signal frame remains live until we forward this fault.
    let (trap, code, address) = unsafe {
        (
            gregs.add(libc::REG_TRAPNO as usize).read() as u64,
            (*info).si_code as u64,
            (*info).si_addr() as u64,
        )
    };
    // SAFETY: the debug logger is already used from this signal handler.
    unsafe {
        debug_log(c"game SIGSEGV forwarded to Wine".as_ptr());
        debug_log_hex(c"game fault RIP=".as_ptr(), rip);
        debug_log_hex(c"game fault trap=".as_ptr(), trap);
        debug_log_hex(c"game fault si_code=".as_ptr(), code);
        debug_log_hex(c"game fault address=".as_ptr(), address);
        debug_log_hex(c"game fault opcode=".as_ptr(), u64::from(opcode));
    }
}

fn leaf_varies_per_core(leaf: u32) -> bool {
    leaf == 0xb || leaf == 0x1f
}

fn native_reply(leaf: u32, subleaf: u32) -> Registers {
    let cacheable = !leaf_varies_per_core(leaf);
    if cacheable && let Some(cached) = NATIVE_CACHE.lookup(leaf, subleaf) {
        return cached;
    }
    if unsafe {
        libc::syscall(
            libc::SYS_arch_prctl,
            ARCH_SET_CPUID as libc::c_long,
            1 as libc::c_ulong,
        )
    } == -1
    {
        unsafe { debug_log(c"CPUID native pass-through enable failed; returning zeros".as_ptr()) };
        return Registers::default();
    }

    let result = native_cpuid(leaf, subleaf);
    if unsafe {
        libc::syscall(
            libc::SYS_arch_prctl,
            ARCH_SET_CPUID as libc::c_long,
            0 as libc::c_ulong,
        )
    } == -1
    {
        unsafe {
            debug_log(c"CPUID faulting re-arm failed; terminating".as_ptr());
            libc::syscall(libc::SYS_exit_group, 127 as libc::c_long);
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
    // `int 2e` is identifiable from its faulting opcode and #GP trap number.
    // Handle it before the CPUID-specific si_code check; that condition is
    // not needed to identify a guest `int 2e` instruction.
    #[cfg(feature = "kuser")]
    if unsafe { crate::syscall::skip_int2e_fault(context_ptr) } {
        return;
    }
    let is_cpuid_fault = unsafe {
        gregs.add(libc::REG_TRAPNO as usize).read() == 13 && (*info).si_code == libc::SI_KERNEL
    };
    if !is_cpuid_fault {
        #[cfg(all(
            feature = "debug",
            feature = "environment",
            feature = "hooks",
            feature = "kuser"
        ))]
        trace_forwarded_game_fault(info, gregs);
        #[cfg(all(feature = "debug", feature = "environment", feature = "hooks"))]
        {
            // SAFETY: `info` and `context_ptr` were checked non-null above and
            // are the live signal frame supplied by the kernel.
            let address = unsafe { (*info).si_addr() as usize };
            // SAFETY: the checked context points to the live signal frame.
            let fault_rip =
                unsafe { (*context_ptr).uc_mcontext.gregs[libc::REG_RIP as usize] as u64 };
            // SAFETY: gettid has no pointer arguments and is safe to issue in
            // this signal handler.
            let tid = unsafe { libc::gettid() as u64 };
            crate::syscall::trace_null_fault(address, fault_rip, tid);
        }
        unsafe { forward_signal(sig, info, context) };
        return;
    }

    let rip = unsafe { gregs.add(libc::REG_RIP as usize).read() };
    if !is_cpuid_instruction_at(rip as usize) {
        #[cfg(all(
            feature = "debug",
            feature = "environment",
            feature = "hooks",
            feature = "kuser"
        ))]
        trace_forwarded_game_fault(info, gregs);
        unsafe { forward_signal(sig, info, context) };
        return;
    }

    let (leaf, control, payload) = unsafe {
        (
            gregs.add(libc::REG_RAX as usize).read() as u32,
            gregs.add(libc::REG_RCX as usize).read() as u64,
            gregs.add(libc::REG_RDX as usize).read() as u64,
        )
    };
    #[cfg(all(feature = "syscall", feature = "kuser", feature = "reflex"))]
    if leaf == 0x0033_6933 {
        crate::syscall::register_reflex_dispatch_handler(control);
        PROTOCOL_ESTABLISHED.store(true, Ordering::Release);
    }
    let reply = if is_wine_system_rip(rip as u64) {
        native_reply(leaf, control as u32)
    } else {
        match fixed_reply(leaf, Some(rip as u64)) {
            Some(reply) => reply,
            None => {
                if unsafe { reflex_handle_cpuid(leaf, control, payload) } == REFLEX_CPUID_CONSUMED {
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

#[cfg(test)]
mod caller_image_tests {
    use super::{CallerKind, caller_mapping, mapping_path_kind};

    #[test]
    fn maps_reflex_and_artifact_images_even_when_the_library_path_has_spaces() {
        let reflex =
            b"7f000000-7f001000 r-xp 00000000 08:01 123 /home/user/Steam Library/reflex64.dll";
        let artifact =
            b"7f100000-7f101000 r-xp 00000000 08:01 456 /home/user/Steam Library/artifact.dll";

        assert_eq!(
            caller_mapping(reflex, 0x7f00_0100),
            Some((0x7f00_0000, 0x7f00_1000, CallerKind::Reflex64))
        );
        assert_eq!(
            caller_mapping(artifact, 0x7f10_0100),
            Some((0x7f10_0000, 0x7f10_1000, CallerKind::Artifact))
        );
        assert_eq!(mapping_path_kind(artifact), CallerKind::Artifact);
    }
}

// `PROTOCOL_ESTABLISHED` is a one-way, process-global switch (matching the
// real handshake it models), so this is the only test allowed to set it —
// doing so anywhere else would leak into every other test in this binary.
#[cfg(all(test, not(miri)))]
mod protocol_established_tests {
    use super::{CallerKind, PROTOCOL_ESTABLISHED, classify_caller};
    use core::sync::atomic::Ordering;

    /// A reflectively-loaded (anonymous, no file path) fake PE image whose
    /// export directory names itself, at a 64KB-aligned address — matching
    /// what `pe_image_named`'s search actually probes for, unlike a
    /// synthetic `/proc/self/maps` line.
    struct FakeReflectiveDll {
        block: *mut u8,
        block_len: usize,
        header: u64,
    }

    impl FakeReflectiveDll {
        fn new(name: &[u8]) -> Self {
            const ALLOCATION_GRANULARITY: usize = 0x1_0000;
            let block_len = ALLOCATION_GRANULARITY * 2;
            let block = unsafe {
                libc::mmap(
                    core::ptr::null_mut(),
                    block_len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            assert_ne!(block, libc::MAP_FAILED);
            let block = block.cast::<u8>();
            let base = block as u64;
            let header =
                (base + ALLOCATION_GRANULARITY as u64 - 1) & !(ALLOCATION_GRANULARITY as u64 - 1);
            let write = |offset: u64, bytes: &[u8]| unsafe {
                core::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    block.add((header - base + offset) as usize),
                    bytes.len(),
                );
            };
            write(0, b"MZ");
            write(0x3c, &0x80u32.to_le_bytes());
            write(0x80, b"PE\0\0");
            write(0x80 + 24, &0x20bu16.to_le_bytes()); // PE32+ magic
            write(0x80 + 136, &0x200u32.to_le_bytes()); // export directory RVA
            write(0x200 + 12, &0x300u32.to_le_bytes()); // IMAGE_EXPORT_DIRECTORY.Name
            write(0x300, name);
            write(0x300 + name.len() as u64, &[0]);
            Self {
                block,
                block_len,
                header,
            }
        }
    }

    impl Drop for FakeReflectiveDll {
        fn drop(&mut self) {
            unsafe { libc::munmap(self.block.cast(), self.block_len) };
        }
    }

    #[test]
    fn stops_the_brute_force_dll_search_once_the_handshake_leaf_has_fired() {
        let before = FakeReflectiveDll::new(b"artifact.dll");
        assert_eq!(
            classify_caller(before.header),
            Some(CallerKind::Artifact),
            "a reflectively-loaded artifact.dll must still be found before the handshake"
        );

        PROTOCOL_ESTABLISHED.store(true, Ordering::Release);

        let after = FakeReflectiveDll::new(b"artifact.dll");
        assert_eq!(
            classify_caller(after.header),
            Some(CallerKind::Ordinary),
            "once established, a never-before-seen address is classified from \
             its /proc/self/maps path alone, without the brute-force search"
        );
    }
}

#[cfg(test)]
mod artifact_profile_tests {
    use super::{artifact_reply, with_native_apic_id};
    use linuwux::cpuid::{CpuIdentity, Registers, Vendor};

    #[test]
    fn selects_artifact_reply_by_host_vendor() {
        assert_eq!(
            artifact_reply(Vendor::Intel, 1),
            Some(Registers::new(
                0x000a_0655,
                0x0020_0800,
                0x01fa_ebff,
                0xbfeb_fbff,
            ))
        );
        assert_eq!(
            artifact_reply(Vendor::Amd, 1),
            Some(Registers::new(
                0x00a2_0f12,
                0x0010_0800,
                0x00f8_220b,
                0x178b_fbff,
            ))
        );
        assert_eq!(artifact_reply(Vendor::Unknown, 1), None);
        assert_eq!(artifact_reply(Vendor::Intel, 7), None);
        assert_ne!(
            artifact_reply(Vendor::Intel, 1),
            CpuIdentity::denuvo(Vendor::Intel, true).fixed_reply(1),
            "Artifact must clear AVX features even when PROTON_AVX=1"
        );
    }

    #[test]
    fn artifact_leaf_one_preserves_native_apic_id() {
        let reply = artifact_reply(Vendor::Intel, 1).unwrap();
        assert_eq!(
            with_native_apic_id(reply, 0xabcd_ef01),
            Registers::new(0x000a_0655, 0xab20_0800, 0x01fa_ebff, 0xbfeb_fbff)
        );
    }
}

#[cfg(all(test, feature = "kuser", not(miri)))]
mod int2e_signal_tests {
    use super::cpuid_sigsegv_handler;
    use core::mem::MaybeUninit;
    use libc::{siginfo_t, ucontext_t};

    // Reaches `int2e.rs`'s `skip_int2e_fault`, whose `read_memory` calls
    // `process_vm_readv` — not in Miri's foreign-function shim list at all
    // (confirmed: "can't call foreign function `process_vm_readv`").
    #[test]
    fn handles_int2e_even_when_signal_code_is_not_si_kernel() {
        let page = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                0x1000,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(page, libc::MAP_FAILED);
        let code = [0x0f, 0x05, 0xc3, 0xcd, 0x2e];
        unsafe { core::ptr::copy_nonoverlapping(code.as_ptr(), page.cast::<u8>(), code.len()) };
        // No `mprotect(PROT_EXEC)`: this RIP lands on the rewind path
        // (`preceding_direct_syscall`), which only reads these bytes back via
        // `process_vm_readv` — it never executes them and never reaches
        // `patch_to_syscall`'s `/proc/self/maps` executable-mapping check, so
        // the page never actually needs to be executable. Miri doesn't
        // support mmap/mprotect protections beyond PROT_READ|PROT_WRITE, so
        // this also keeps the test runnable there.
        let mut context = unsafe { MaybeUninit::<ucontext_t>::zeroed().assume_init() };
        let mut info = unsafe { MaybeUninit::<siginfo_t>::zeroed().assume_init() };
        let direct = page as u64;
        context.uc_mcontext.gregs[libc::REG_TRAPNO as usize] = 13;
        context.uc_mcontext.gregs[libc::REG_RIP as usize] = (direct + 3) as libc::greg_t;
        info.si_code = 1; // Deliberately differs from SI_KERNEL.

        unsafe {
            cpuid_sigsegv_handler(
                libc::SIGSEGV,
                &mut info,
                (&mut context as *mut ucontext_t).cast(),
            );
        }

        assert_eq!(
            context.uc_mcontext.gregs[libc::REG_RIP as usize] as u64,
            direct
        );
        assert_eq!(unsafe { libc::munmap(page, 0x1000) }, 0);
    }
}

// Not a correctness test: measures `classify_caller`'s actual wall-clock cost
// under two workloads, to check a hypothesis about a reported fps regression
// (Monster Hunter Wilds, 160->90fps) rather than reason about it further from
// first principles. `#[ignore]` since it's a manual diagnostic, not part of
// the normal suite; run with `cargo test -p linuwux-runtime --lib
// classify_caller_bench -- --ignored --nocapture`.
#[cfg(all(test, not(miri)))]
mod classify_caller_bench {
    use super::classify_caller;
    use std::time::Instant;

    fn anon_page() -> *mut libc::c_void {
        let ptr = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                0x1000,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(ptr, libc::MAP_FAILED);
        ptr
    }

    #[test]
    #[ignore]
    fn classify_caller_cost_hit_vs_miss() {
        const ITERS: usize = 5_000;

        // Inflate this process's own /proc/self/maps to a size closer to a
        // real game process (hundreds of mapped DLLs/files/heaps), not a
        // bare `cargo test` binary's much shorter one.
        let padding: Vec<_> = (0..500).map(|_| anon_page()).collect();

        // Cache-hit workload: the same call site every time, as a title with
        // stable (non-virtualized) CPUID call sites would produce.
        let stable = anon_page() as u64;
        let _ = classify_caller(stable); // warm the cache
        let start = Instant::now();
        for _ in 0..ITERS {
            let _ = classify_caller(stable);
        }
        let hit = start.elapsed() / ITERS as u32;

        // Cache-miss workload: a fresh mapping every call, standing in for
        // Denuvo-style VM handlers that relocate their call site on every
        // invocation specifically to defeat this kind of address caching.
        let mut rotating = Vec::with_capacity(ITERS);
        let start = Instant::now();
        for _ in 0..ITERS {
            let page = anon_page();
            let _ = classify_caller(page as u64);
            rotating.push(page);
        }
        let miss = start.elapsed() / ITERS as u32;

        eprintln!("classify_caller cache-hit:              {hit:?}/call");
        eprintln!("classify_caller cache-miss (pre-handshake):  {miss:?}/call");

        // Same rotating-address workload, after the handshake leaf has
        // fired: the brute-force DLL search is skipped for every one of
        // these misses.
        super::PROTOCOL_ESTABLISHED.store(true, core::sync::atomic::Ordering::Release);
        let mut rotating_established = Vec::with_capacity(ITERS);
        let start = Instant::now();
        for _ in 0..ITERS {
            let page = anon_page();
            let _ = classify_caller(page as u64);
            rotating_established.push(page);
        }
        let miss_established = start.elapsed() / ITERS as u32;
        eprintln!("classify_caller cache-miss (post-handshake): {miss_established:?}/call");
        eprintln!(
            "post-handshake speedup: {:.1}x",
            miss.as_nanos() as f64 / miss_established.as_nanos().max(1) as f64
        );

        for page in rotating {
            unsafe { libc::munmap(page, 0x1000) };
        }
        for page in rotating_established {
            unsafe { libc::munmap(page, 0x1000) };
        }
        for page in padding {
            unsafe { libc::munmap(page, 0x1000) };
        }
        unsafe { libc::munmap(stable as *mut libc::c_void, 0x1000) };
    }

    // Checks the actual question this was written to answer: does a
    // `classify_caller` miss get progressively more expensive purely because
    // this process has accumulated more of its own mappings over a session
    // (asset streaming, DLL loads, etc.) — every miss re-scans the *entire*
    // current `/proc/self/maps`, unconditionally, forever; there's no cap and
    // no negative-cache. Run with `cargo test -p linuwux-runtime --lib
    // classify_caller_cost_scales_with_map_size -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn classify_caller_cost_scales_with_map_size() {
        const ITERS: usize = 2_000;
        let mut total_mapped = 0usize;
        let mut all_padding = Vec::new();

        for &target in &[200usize, 1_000, 3_000, 6_000, 10_000] {
            let grow = target - total_mapped;
            all_padding.extend((0..grow).map(|_| anon_page()));
            total_mapped = target;

            let mut rotating = Vec::with_capacity(ITERS);
            let start = Instant::now();
            for _ in 0..ITERS {
                let page = anon_page();
                let _ = classify_caller(page as u64);
                rotating.push(page);
            }
            let miss = start.elapsed() / ITERS as u32;
            eprintln!("~{total_mapped:>6} mappings -> classify_caller miss: {miss:?}/call");
            for page in rotating {
                unsafe { libc::munmap(page, 0x1000) };
            }
        }

        for page in all_padding {
            unsafe { libc::munmap(page, 0x1000) };
        }
    }

    // Isolates the two pieces of a `classify_caller` miss to find which one
    // actually dominates the ~81us measured above: the `/proc/self/maps`
    // scan itself (`caller_mapping`, via `maps::find_line`), or the
    // brute-force nearby-PE-header probe (`pe_image_named`) that runs
    // afterward for any address whose mapping has no recognized DLL path —
    // true for every anonymous, reflectively-loaded, or JIT/VM-generated
    // code page, which is exactly what a Denuvo-style virtualized handler is.
    #[test]
    #[ignore]
    fn classify_caller_miss_cost_breakdown() {
        const ITERS: usize = 2_000;
        let padding: Vec<_> = (0..500).map(|_| anon_page()).collect();

        let mut scan_only = Vec::with_capacity(ITERS);
        let start = Instant::now();
        for _ in 0..ITERS {
            let page = anon_page();
            let mut result = None;
            crate::maps::find_line(|line| {
                result = super::caller_mapping(line, page as u64);
                result.is_some()
            });
            let _ = result;
            scan_only.push(page);
        }
        let scan_cost = start.elapsed() / ITERS as u32;

        let mut pe_probe = Vec::with_capacity(ITERS);
        let start = Instant::now();
        for _ in 0..ITERS {
            let page = anon_page();
            let _ = super::pe_image_named(page as u64, b"reflex64.dll");
            pe_probe.push(page);
        }
        let pe_cost = start.elapsed() / ITERS as u32;

        eprintln!("maps-scan only (caller_mapping):        {scan_cost:?}/call");
        eprintln!("pe_image_named (one DLL name):           {pe_cost:?}/call");

        for page in scan_only.into_iter().chain(pe_probe).chain(padding) {
            unsafe { libc::munmap(page, 0x1000) };
        }
    }
}
