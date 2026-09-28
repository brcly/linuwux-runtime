//! Fixes a Reflex-specific side effect that is unrelated to syscall routing:
//! Reflex clones `ntdll.dll` and hooks every export as a `jmp`-style
//! trampoline (`ff 25 02 00 00 00 00 00`, destination at +8), including the
//! small set of Wine-only *data* exports — `__wine_unix_call_dispatcher` and
//! `__wine_unixlib_handle` — that don't exist on real Windows and hold a raw
//! function-pointer value rather than code. Wine's own `win32u.dll` resolves
//! those two symbols against whichever module the PEB currently calls
//! "ntdll.dll" — which Reflex has swapped for this clone, to hide its hooks
//! from anything that walks the loader list — and dereferences the result
//! once, expecting the real pointer value. Reading the trampoline's own `jmp`
//! instruction bytes there instead (`0xff 0x25 0x02 0x00 0x00 0x00 0x00 0x00`
//! == 0x225ff) is a real Wine/Windows divergence: these two symbols simply
//! don't exist in Microsoft's ntdll, so Reflex's blanket "hook every export"
//! approach never has anything to go wrong there on Windows.
//!
//! The fix does not touch the hook mechanism BL4 depends on. The clone's
//! trampoline for a data export still carries the address of the real
//! variable in the genuine, loaded ntdll.so as its embedded "destination"
//! (Reflex resolved that correctly when building the hook); the bug is only
//! that dereferencing the trampoline's own address yields code bytes instead
//! of the value stored there. Once found, the trampoline's first qword is
//! replaced with the live value already sitting at that destination, so
//! reading it yields data again. Everything else Reflex hooked — every real
//! Windows API — is left exactly as Reflex built it.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::mem::trampoline_destination;
use crate::procmem::{read_memory, read_u32, write_u64};

const WINE_UNIX_CALL_DISPATCHER_EXPORT: &[u8] = b"__wine_unix_call_dispatcher";
const WINE_UNIXLIB_HANDLE_EXPORT: &[u8] = b"__wine_unixlib_handle";
const WINE_UNIXLIB_REPAIR_RETRY_INTERVAL: u64 = 4;
const WINE_UNIXLIB_REPAIR_MAX_ATTEMPTS: u64 = 256;

static WINE_UNIXLIB_REPAIR_DONE: AtomicBool = AtomicBool::new(false);
static WINE_UNIXLIB_REPAIR_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static WINE_UNIXLIB_REPAIR_LOGGED: AtomicBool = AtomicBool::new(false);

unsafe extern "C" {
    fn debug_log(message: *const core::ffi::c_char);
    fn debug_log_dec(prefix: *const core::ffi::c_char, value: u64);
}

fn log(message: &'static core::ffi::CStr) {
    unsafe { debug_log(message.as_ptr()) };
}

fn log_dec(prefix: &'static core::ffi::CStr, value: u64) {
    unsafe { debug_log_dec(prefix.as_ptr(), value) };
}

/// Called on every KUSER dispatcher hit and every registered-target-process
/// syscall until it succeeds once, since the repair can only run after
/// Reflex has built its ntdll clone (retried rather than triggered by a
/// specific event, to stay independent of Reflex's exact init ordering).
pub(super) fn maybe_repair_wine_unixlib_exports() {
    if WINE_UNIXLIB_REPAIR_DONE.load(Ordering::Acquire) {
        return;
    }
    let attempt = WINE_UNIXLIB_REPAIR_ATTEMPTS.fetch_add(1, Ordering::AcqRel);
    if attempt >= WINE_UNIXLIB_REPAIR_MAX_ATTEMPTS {
        return;
    }
    if attempt != 0 && !attempt.is_multiple_of(WINE_UNIXLIB_REPAIR_RETRY_INTERVAL) {
        return;
    }
    let mut repaired = 0usize;
    for_each_anonymous_executable_pe_image(|base| {
        repaired += repair_module_wine_unixlib_exports(base);
    });
    if repaired > 0 {
        WINE_UNIXLIB_REPAIR_DONE.store(true, Ordering::Release);
        if !WINE_UNIXLIB_REPAIR_LOGGED.swap(true, Ordering::AcqRel) {
            log(c"reflex ntdll clone: repaired Wine-internal data exports hooked as code");
            log_dec(c"reflex ntdll clone: exports repaired=", repaired as u64);
        }
    }
}

/// Every anonymous (not file-backed), writable-and-executable mapping in this
/// process whose first two bytes are `MZ`. The genuine, loaded `ntdll.dll` is
/// file-backed and is never visited; only in-memory PE clones like Reflex's
/// are candidates.
fn for_each_anonymous_executable_pe_image(mut visit: impl FnMut(u64)) {
    crate::maps::find_line(|line| {
        let Some(mapping) = crate::maps::parse(line) else {
            return false;
        };
        let permissions = mapping.permissions;
        let mut dos = [0u8; 2];
        if permissions.len() >= 3
            && permissions[1] == b'w'
            && permissions[2] == b'x'
            && mapping.path.is_empty()
            && read_memory(mapping.start, &mut dos)
            && dos == *b"MZ"
        {
            visit(mapping.start);
        }
        false
    });
}

struct ExportDirectory {
    name_count: u32,
    functions_rva: u32,
    names_rva: u32,
    ordinals_rva: u32,
}

fn read_export_directory(base: u64) -> Option<ExportDirectory> {
    let mut dos = [0u8; 0x40];
    if !read_memory(base, &mut dos) || dos[..2] != *b"MZ" {
        return None;
    }
    let pe_offset = u32::from_le_bytes(dos[0x3c..0x40].try_into().unwrap()) as u64;
    let mut signature = [0u8; 4];
    if pe_offset > 0x1000
        || !read_memory(base.checked_add(pe_offset)?, &mut signature)
        || signature != *b"PE\0\0"
    {
        return None;
    }
    let export_rva = read_u32(base + pe_offset + 0x88)?;
    if export_rva == 0 {
        return None;
    }
    let directory = base + u64::from(export_rva);
    Some(ExportDirectory {
        name_count: read_u32(directory + 0x18)?,
        functions_rva: read_u32(directory + 0x1c)?,
        names_rva: read_u32(directory + 0x20)?,
        ordinals_rva: read_u32(directory + 0x24)?,
    })
}

fn find_export_ordinal(base: u64, export: &ExportDirectory, name: &[u8]) -> Option<u32> {
    for index in 0..export.name_count {
        let name_rva = read_u32(base + u64::from(export.names_rva) + u64::from(index) * 4)?;
        let mut candidate = [0u8; 40];
        if !read_memory(base + u64::from(name_rva), &mut candidate) {
            continue;
        }
        let length = candidate
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(candidate.len());
        if candidate[..length] == *name {
            let mut ordinal = [0u8; 2];
            if read_memory(
                base + u64::from(export.ordinals_rva) + u64::from(index) * 2,
                &mut ordinal,
            ) {
                return Some(u16::from_le_bytes(ordinal) as u32);
            }
        }
    }
    None
}

/// If `name`'s function-table entry in this module has been overwritten with
/// a trampoline, restore it to the live value already sitting at the
/// trampoline's own recorded destination (the real symbol's address in the
/// genuine, loaded module). Returns `false`, harmlessly, if the name is
/// absent or was never hooked as a trampoline in the first place.
fn repair_named_export(base: u64, export: &ExportDirectory, name: &[u8]) -> bool {
    let Some(ordinal) = find_export_ordinal(base, export, name) else {
        return false;
    };
    let slot = base + u64::from(export.functions_rva) + u64::from(ordinal) * 4;
    let Some(function_rva) = read_u32(slot) else {
        return false;
    };
    let record = base + u64::from(function_rva);
    let Some(destination) = trampoline_destination(record) else {
        return false;
    };
    let Some(value) = crate::procmem::read_u64(destination) else {
        return false;
    };
    write_u64(record, value)
}

fn repair_module_wine_unixlib_exports(base: u64) -> usize {
    let Some(export) = read_export_directory(base) else {
        return 0;
    };
    [WINE_UNIX_CALL_DISPATCHER_EXPORT, WINE_UNIXLIB_HANDLE_EXPORT]
        .into_iter()
        .filter(|name| repair_named_export(base, &export, name))
        .count()
}

#[cfg(all(test, not(miri)))]
mod tests {
    use super::{find_export_ordinal, read_export_directory, read_memory, repair_named_export};

    /// A minimal PE image with a real export table, real memory backing it
    /// (`process_vm_readv`/`writev` validate against the process's actual
    /// page tables, so a plain byte buffer won't do), holding one export
    /// whose function-table entry has been overwritten with a Reflex-style
    /// trampoline. Layout is arbitrary but self-consistent; only the RVAs
    /// wired up here are read.
    struct FakePeExport {
        base: u64,
        length: usize,
    }

    impl FakePeExport {
        fn new(name: &[u8], hooked: bool) -> Self {
            let length = 0x1000;
            let base = unsafe {
                libc::mmap(
                    core::ptr::null_mut(),
                    length,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            } as u64;
            assert_ne!(base, u64::MAX, "mmap failed");
            let write = |offset: usize, bytes: &[u8]| unsafe {
                core::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    (base as *mut u8).add(offset),
                    bytes.len(),
                );
            };
            // DOS header: e_lfanew -> 0x80.
            write(0, b"MZ");
            write(0x3c, &0x80u32.to_le_bytes());
            // PE header, export directory RVA at +0x88 -> 0x200.
            write(0x80, b"PE\0\0");
            write(0x80 + 0x88, &0x200u32.to_le_bytes());
            // Export directory occupies 0x200..0x228; every table it points
            // at lives past that so none of these writes overlap each other.
            write(0x200 + 0x18, &1u32.to_le_bytes()); // NumberOfNames
            write(0x200 + 0x1c, &0x300u32.to_le_bytes()); // AddressOfFunctions
            write(0x200 + 0x20, &0x320u32.to_le_bytes()); // AddressOfNames
            write(0x200 + 0x24, &0x340u32.to_le_bytes()); // AddressOfNameOrdinals
            write(0x300, &0x500u32.to_le_bytes()); // functions[0] -> 0x500
            write(0x320, &0x360u32.to_le_bytes()); // names[0] -> the string
            write(0x340, &0u16.to_le_bytes()); // ordinals[0] -> 0
            write(0x360, name);
            write(0x360 + name.len(), &[0]);
            // The "real" value a correctly resolved data export would hold.
            write(0x600, &0xdead_beef_cafe_f00du64.to_le_bytes());
            if hooked {
                write(0x500, &super::super::mem::TRAMPOLINE_HEAD);
                // The embedded destination is an absolute address (as Reflex
                // writes it), not an RVA, so it must be `base`-relative here.
                write(0x500 + 8, &(base + 0x600).to_le_bytes());
            } else {
                write(0x500, &0xdead_beef_cafe_f00du64.to_le_bytes());
            }
            Self { base, length }
        }
    }

    impl Drop for FakePeExport {
        fn drop(&mut self) {
            unsafe { libc::munmap(self.base as *mut libc::c_void, self.length) };
        }
    }

    // `read_export_directory`/`repair_named_export`/`read_memory` all read
    // through `super::mem`, which calls `process_vm_readv` — not in Miri's
    // foreign-function shim list at all.
    #[cfg(not(miri))]
    #[test]
    fn repair_replaces_a_hooked_data_exports_trampoline_with_its_real_value() {
        let name = b"__wine_unix_call_dispatcher";
        let image = FakePeExport::new(name, true);
        let export = read_export_directory(image.base).expect("export directory parses");

        assert_eq!(find_export_ordinal(image.base, &export, name), Some(0));
        assert_eq!(
            find_export_ordinal(image.base, &export, b"not_present"),
            None
        );

        assert!(repair_named_export(image.base, &export, name));
        let mut repaired = [0u8; 8];
        assert!(read_memory(image.base + 0x500, &mut repaired));
        assert_eq!(u64::from_le_bytes(repaired), 0xdead_beef_cafe_f00d);

        // Idempotent: once repaired, the slot no longer looks like a
        // trampoline, so a second pass is a harmless no-op.
        assert!(!repair_named_export(image.base, &export, name));
    }

    // Same as above: goes through `super::mem`'s `process_vm_readv`-based
    // reads, which Miri doesn't emulate at all.
    #[cfg(not(miri))]
    #[test]
    fn repair_leaves_an_unhooked_data_export_alone() {
        let name = b"__wine_unixlib_handle";
        let image = FakePeExport::new(name, false);
        let export = read_export_directory(image.base).expect("export directory parses");

        assert!(!repair_named_export(image.base, &export, name));
        let mut untouched = [0u8; 8];
        assert!(read_memory(image.base + 0x500, &mut untouched));
        assert_eq!(u64::from_le_bytes(untouched), 0xdead_beef_cafe_f00d);
    }
}
