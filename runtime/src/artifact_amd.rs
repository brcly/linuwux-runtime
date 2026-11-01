//! Wine loader adaptations for the recognized AMD Artifact image.
//! Enabled only with LINUWUX_ARTIFACT_AMD_V2=1; unknown layouts are untouched.
use crate::procmem::{read_memory, read_u32, read_u64, write_u32, write_u64};
use core::ffi::{CStr, c_void};
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
static ENABLED: AtomicBool = AtomicBool::new(false);
static STARTED: AtomicBool = AtomicBool::new(false);
static PREPARING: AtomicBool = AtomicBool::new(false);
static BASE: AtomicU64 = AtomicU64::new(0);
static PEB: AtomicU64 = AtomicU64::new(0);
static ORIGINAL_LDR: AtomicU64 = AtomicU64::new(0);
const XGETBV_HELPER: [u8; 13] = [
    0x31, 0xc9, 0x0f, 0x01, 0xd0, 0x48, 0xc1, 0xe2, 0x20, 0x48, 0x09, 0xd0, 0xc3,
];
fn log(message: &'static CStr) {
    unsafe extern "C" {
        fn debug_log(message: *const core::ffi::c_char);
    }
    unsafe { debug_log(message.as_ptr()) };
}

fn matches(address: u64, expected: &[u8]) -> bool {
    let mut bytes = [0; 16];
    expected.len() <= bytes.len()
        && read_memory(address, &mut bytes[..expected.len()])
        && bytes[..expected.len()] == *expected
}

pub(crate) fn start() {
    #[cfg(feature = "environment")]
    let game_process = crate::environment::game_process();
    #[cfg(not(feature = "environment"))]
    let game_process = false;
    let on = crate::config::artifact_amd_v2_enabled() && game_process;
    ENABLED.store(on, Ordering::Release);
    if !on || STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    let mut thread = 0;
    // This runs in a constructor, never in a signal handler. The worker is
    // bounded and only repairs a fully validated cached detour pointer.
    if unsafe { libc::pthread_create(&mut thread, ptr::null(), repair_worker, ptr::null_mut()) }
        == 0
    {
        unsafe { libc::pthread_detach(thread) };
    } else {
        log(c"AMD Artifact: could not start detour observer");
    }
}

extern "C" fn repair_worker(_: *mut c_void) -> *mut c_void {
    for _ in 0..15_000 {
        let base = BASE.load(Ordering::Acquire);
        if base != 0 && repair_getproc(base) {
            log(c"AMD Artifact: cached GetProcAddress now uses original trampoline");
            break;
        }
        let delay = libc::timespec {
            tv_sec: 0,
            tv_nsec: 2_000_000,
        };
        unsafe { libc::nanosleep(&delay, ptr::null_mut()) };
    }
    ptr::null_mut()
}

fn repair_getproc(base: u64) -> bool {
    let Some(getproc) = read_u64(base + 0x42138) else {
        return false;
    };
    let mut jump = [0; 5];
    if !read_memory(getproc, &mut jump) || jump[0] != 0xe9 {
        return false;
    }
    let relay = getproc
        .wrapping_add(5)
        .wrapping_add_signed(i32::from_le_bytes(jump[1..].try_into().unwrap()) as i64);
    let Some(trampoline) = relay.checked_sub(19) else {
        return false;
    };
    if !matches(relay, &[0xff, 0x25, 0, 0, 0, 0])
        || read_u64(relay + 6) != Some(base + 0x11d58)
        || !matches(trampoline, &[0x48, 0x55, 0x48, 0x89, 0xe5])
        || !matches(trampoline + 5, &[0xff, 0x25, 0, 0, 0, 0])
        || read_u64(trampoline + 11) != Some(getproc + 5)
    {
        return false;
    }
    write_u64(base + 0x42138, trampoline)
}

pub(crate) fn before_cpuid(leaf: u32) {
    if !ENABLED.load(Ordering::Acquire) {
        return;
    }
    if BASE.load(Ordering::Acquire) == 0 {
        prepare();
    }
    if leaf == linuwux::artifact::REGISTER_PROCESS && BASE.load(Ordering::Acquire) != 0 {
        repair_loader_lists();
    }
}
fn prepare() {
    if PREPARING.swap(true, Ordering::AcqRel) {
        return;
    }
    struct Preparing;
    impl Drop for Preparing {
        fn drop(&mut self) {
            PREPARING.store(false, Ordering::Release);
        }
    }
    let _preparing = Preparing;
    if BASE.load(Ordering::Acquire) != 0 {
        return;
    }
    let mut base = 0;
    crate::maps::find_line(|line| {
        let Some(m) = crate::maps::parse(line) else {
            return false;
        };
        if m.path.ends_with(b"/artifact.dll") && matches(m.start, b"MZ") {
            base = m.start;
            true
        } else {
            false
        }
    });
    if base == 0 || read_u32(base + 0x3c).is_none() {
        return;
    }
    let pe = u64::from(read_u32(base + 0x3c).unwrap());
    if pe > 0x1000
        || !matches(base + pe, b"PE\0\0")
        || read_u32(base + pe + 0x50) != Some(0x11e000)
        || !matches(base + 0x14090, &XGETBV_HELPER)
        || !matches(
            base + 0x13123,
            &[0x50, 0x66, 0x31, 0xc9, 0x66, 0xba, 0x82, 0],
        )
    {
        return;
    }
    let mut gs = 0u64;
    if unsafe { libc::syscall(libc::SYS_arch_prctl, 0x1004, &mut gs as *mut u64) } != 0 {
        return;
    }
    let Some(peb) = read_u64(gs + 0x60) else {
        return;
    };
    let Some(ldr) = read_u64(peb + 0x18) else {
        return;
    };
    let Some(image) = read_u64(peb + 0x10) else {
        return;
    };
    if !matches(image, b"MZ") || !matches(ldr, &[0x58, 0, 0, 0]) {
        return;
    }
    let low: u32;
    let high: u32;
    unsafe {
        core::arch::asm!("xgetbv", in("ecx") 0u32, out("eax") low, out("edx") high, options(nostack, preserves_flags));
    }
    let native_xcr0 = (u64::from(high) << 32) | u64::from(low);
    if native_xcr0 != 7 {
        log(c"AMD Artifact requires native XCR0=7; loader preparation skipped");
        return;
    }
    if !prepare_heap_array(peb) {
        log(c"AMD Artifact: unable to materialize native process heaps");
        return;
    }
    PEB.store(peb, Ordering::Relaxed);
    ORIGINAL_LDR.store(ldr, Ordering::Relaxed);
    BASE.store(base, Ordering::Release);
    log(c"AMD Artifact loader preparation ready");
}

fn prepare_heap_array(peb: u64) -> bool {
    // Wine keeps this list in its heap implementation, leaving PEB.ProcessHeaps
    // null. Artifact assumes Windows' materialized array and clones a page.
    if read_u64(peb + 0xf0) != Some(0) {
        return true;
    }
    let Some(ntdll) = crate::syscall::pe_export::module_base(b"ntdll.dll") else {
        return false;
    };
    let Some(address) = crate::syscall::pe_export::export_address(ntdll, b"RtlGetProcessHeaps")
    else {
        return false;
    };
    let storage = unsafe {
        libc::syscall(
            libc::SYS_mmap,
            ptr::null_mut::<c_void>(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    } as *mut u64;
    if storage.cast::<c_void>() == libc::MAP_FAILED {
        return false;
    }
    let query: unsafe extern "win64" fn(u32, *mut u64) -> u32 =
        unsafe { core::mem::transmute(address) };
    let count = unsafe { query(512, storage) };
    let main_heap = read_u64(peb + 0x30).filter(|heap| *heap != 0);
    if count == 0 || count > 512 || main_heap.is_none() || read_u64(storage as u64) != main_heap {
        unsafe { libc::munmap(storage.cast(), 4096) };
        return false;
    }
    let ready = write_u32(peb + 0xe8, count)
        && write_u32(peb + 0xec, 512)
        && write_u64(peb + 0xf0, storage as u64);
    if ready {
        log(c"AMD Artifact: PEB.ProcessHeaps populated from RtlGetProcessHeaps");
    }
    ready
}

/// Plan only the boundary writes needed to move three circular list heads.
/// The cloned header already contains the original first/last pointers. Wine
/// traverses via PEB->Ldr, so retain the actual nodes and make the clone the
/// sentinel reached by traversal. Validate all lists before touching any one.
fn loader_head_repairs(
    old: u64,
    new: u64,
    read: impl Fn(u64) -> Option<u64>,
) -> Option<[(u64, u64, u64); 6]> {
    if old == 0 || new == 0 || old == new {
        return None;
    }
    let mut writes = [(0, 0, 0); 6];
    for (index, offset) in [0x10, 0x20, 0x30].into_iter().enumerate() {
        let original = old.checked_add(offset)?;
        let cloned = new.checked_add(offset)?;
        let first = read(original)?;
        let last = read(original.checked_add(8)?)?;
        if read(cloned)? != first || read(cloned.checked_add(8)?)? != last {
            return None;
        }
        if first == original && last == original {
            writes[index * 2] = (cloned, original, cloned);
            writes[index * 2 + 1] = (cloned + 8, original, cloned);
            continue;
        }
        if first == original || last == original || read(first.checked_add(8)?)? != original {
            return None;
        }
        let mut node = first;
        let mut previous = original;
        let mut count = 0;
        while node != original {
            if count == 512 || read(node.checked_add(8)?)? != previous {
                return None;
            }
            previous = node;
            node = read(node)?;
            count += 1;
        }
        if previous != last {
            return None;
        }
        writes[index * 2] = (first + 8, original, cloned);
        writes[index * 2 + 1] = (last, original, cloned);
    }
    Some(writes)
}

fn repair_loader_lists() {
    let peb = PEB.load(Ordering::Relaxed);
    let old = ORIGINAL_LDR.load(Ordering::Relaxed);
    let Some(new) = read_u64(peb + 0x18) else {
        return;
    };
    if new == old {
        return;
    }
    // Restoring PEB->Ldr to Wine's original ntdll data creates a different
    // module identity from Artifact's GetModuleHandleA shadow. Phantom Blade Zero derives
    // the containing PE base from this field and XORs the two identities.
    // Keep Artifact's location, repairing only the copied-head mismatch.
    if read_u32(new) != Some(0x58) {
        log(c"AMD Artifact: cloned loader header validation failed");
        return;
    }
    let Some(writes) = loader_head_repairs(old, new, read_u64) else {
        log(c"AMD Artifact: loader-list validation failed; leaving it untouched");
        return;
    };
    for (index, &(address, before, after)) in writes.iter().enumerate() {
        if read_u64(address) != Some(before) || !write_u64(address, after) {
            for &(address, before, _) in writes[..index].iter().rev() {
                write_u64(address, before);
            }
            log(c"AMD Artifact: loader-list repair failed; prior writes rolled back");
            return;
        }
    }
    log(c"AMD Artifact: live loader lists reanchored to Artifact cloned heads");
    repair_shadow_thread_notifications(new);
}

#[derive(Clone, Copy, Default)]
struct LoaderModule {
    node: u64,
    base: u64,
    size: u64,
    entry: u64,
    flags: u32,
    tls: u16,
}

impl LoaderModule {
    fn contains_entry(self) -> bool {
        self.entry >= self.base && self.entry - self.base < self.size
    }
}

/// Artifact copies user32's loader record, including its real entry point.
/// Wine then calls the same thread cleanup twice, freeing the same win32u
/// per-thread state. Keep the real module's notifications and mark only the
/// validated shadow record LDR_NO_DLL_CALLS (Wine's thread-notification flag).
fn shadow_thread_flag(modules: [LoaderModule; 2]) -> Option<(u64, u32, u32)> {
    let [a, b] = modules;
    let (real, shadow) = match (a.contains_entry(), b.contains_entry()) {
        (true, false) => (a, b),
        (false, true) => (b, a),
        _ => return None,
    };
    if real.node == shadow.node
        || real.base == shadow.base
        || real.entry == 0
        || real.entry != shadow.entry
        || real.flags != shadow.flags
        || real.tls != 0
        || shadow.tls != 0
        || shadow.size != 0x201000
        || shadow.flags & 0xc0000 != 0x80000
    {
        return None;
    }
    Some((
        shadow.node.checked_add(0x68)?,
        shadow.flags,
        shadow.flags | 0x40000,
    ))
}

fn repair_shadow_thread_notifications(ldr: u64) {
    let head = ldr + 0x10;
    let mut node = read_u64(head).unwrap_or(0);
    let mut modules = [LoaderModule::default(); 2];
    let mut found = 0;
    let mut visited = 0;
    while node != head {
        if node == 0 || visited == 512 {
            return;
        }
        visited += 1;
        let mut data = [0u8; 0x70];
        if !read_memory(node, &mut data) {
            return;
        }
        let qword = |offset| u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
        let dword = |offset| u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        let word = |offset| u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap());
        let mut name = [0u8; 20];
        if word(0x58) == 20
            && read_memory(qword(0x60), &mut name)
            && name
                .as_chunks::<2>()
                .0
                .iter()
                .zip(b"user32.dll")
                .all(|(pair, expected)| pair[1] == 0 && pair[0].eq_ignore_ascii_case(expected))
        {
            if found == modules.len() {
                return;
            }
            modules[found] = LoaderModule {
                node,
                base: qword(0x30),
                size: u64::from(dword(0x40)),
                entry: qword(0x38),
                flags: dword(0x68),
                tls: word(0x6e),
            };
            found += 1;
        }
        node = qword(0);
    }
    if found == 2
        && let Some((address, before, after)) = shadow_thread_flag(modules)
        && read_u32(address) == Some(before)
        && write_u32(address, after)
    {
        log(c"AMD Artifact: duplicate shadow user32 thread notifications disabled");
    } else {
        log(c"AMD Artifact: shadow user32 callback validation failed; flags unchanged");
    }
}

#[cfg(test)]
mod loader_tests {
    use super::{LoaderModule, loader_head_repairs, shadow_thread_flag};
    use std::collections::BTreeMap;

    fn lists() -> BTreeMap<u64, u64> {
        let mut memory = BTreeMap::new();
        for offset in [0x10, 0x20, 0x30] {
            let head = 0x1000 + offset;
            let clone = 0x2000 + offset;
            let first = 0x3000 + offset;
            let last = 0x4000 + offset;
            memory.extend([
                (head, first),
                (head + 8, last),
                (clone, first),
                (clone + 8, last),
                (first, last),
                (first + 8, head),
                (last, head),
                (last + 8, first),
            ]);
        }
        memory
    }

    #[test]
    fn copied_heads_close_on_clone_without_copying_nodes() {
        let mut memory = lists();
        let writes = loader_head_repairs(0x1000, 0x2000, |a| memory.get(&a).copied()).unwrap();
        for (address, before, after) in writes {
            assert_eq!(memory.insert(address, after), Some(before));
        }
        for offset in [0x10, 0x20, 0x30] {
            let head = 0x2000 + offset;
            let first = memory[&head];
            let last = memory[&(head + 8)];
            assert_eq!(memory[&(first + 8)], head);
            assert_eq!(memory[&last], head);
            assert_eq!(memory[&first], last);
            assert_eq!(memory[&(last + 8)], first);
        }
    }

    #[test]
    fn rejects_stale_clone_or_broken_interior_before_writes() {
        for (address, value) in [(0x2020, 0x9999), (0x4038, 0x9999), (0x4030, 0x3030)] {
            let mut memory = lists();
            memory.insert(address, value);
            assert!(loader_head_repairs(0x1000, 0x2000, |a| memory.get(&a).copied()).is_none());
        }
    }

    #[test]
    fn empty_copied_lists_are_reinitialized_at_clone() {
        let mut memory = lists();
        for address in [0x1010, 0x1018, 0x2010, 0x2018] {
            memory.insert(address, 0x1010);
        }
        let writes = loader_head_repairs(0x1000, 0x2000, |a| memory.get(&a).copied()).unwrap();
        assert_eq!(writes[0], (0x2010, 0x1010, 0x2010));
        assert_eq!(writes[1], (0x2018, 0x1010, 0x2010));
    }

    #[test]
    fn only_duplicate_callback_outside_shadow_is_disabled() {
        let real = LoaderModule {
            node: 0x1000,
            base: 0x10000,
            size: 0x10000,
            entry: 0x12340,
            flags: 0x80080004,
            tls: 0,
        };
        let shadow = LoaderModule {
            node: 0x2000,
            base: 0x500000,
            size: 0x201000,
            ..real
        };
        let expected = Some((0x2068, 0x80080004, 0x800c0004));
        assert_eq!(shadow_thread_flag([real, shadow]), expected);
        assert_eq!(shadow_thread_flag([shadow, real]), expected);
        for changed in [
            LoaderModule {
                entry: 0x501000,
                ..shadow
            },
            LoaderModule {
                tls: u16::MAX,
                ..shadow
            },
            LoaderModule {
                flags: 0x800c0004,
                ..shadow
            },
            LoaderModule {
                size: 0x300000,
                ..shadow
            },
            LoaderModule {
                node: real.node,
                ..shadow
            },
        ] {
            assert!(shadow_thread_flag([real, changed]).is_none());
        }
        assert!(shadow_thread_flag([real, real]).is_none());
    }
}
