//! Resolve a loaded PE module's base address (by walking the PEB's loader
//! list) and a named export's syscall service number (by walking its export
//! table), without assuming any fixed address or syscall number. Used by
//! [`super::win32u_zero_list`], which needs this because a Proton update can
//! reorder syscall IDs or move where a system DLL loads.

use crate::procmem::{read_memory, read_u16, read_u32, read_u64};

const PE_HEADER_LIMIT: u32 = 0x1000;
const MODULE_LIMIT: usize = 256;
const EXPORT_LIMIT: u32 = 4096;

fn offset(base: u64, amount: u64) -> Option<u64> {
    base.checked_add(amount)
}

fn rva(base: u64, image_size: u32, value: u32) -> Option<u64> {
    (value < image_size).then_some(())?;
    offset(base, u64::from(value))
}

/// Longest module name this lookup supports (in UTF-16 code units); every
/// real system DLL name is well under this.
const MAX_MODULE_NAME_UNITS: usize = 32;

fn module_name_matches(entry: u64, name: &[u8]) -> bool {
    if name.len() > MAX_MODULE_NAME_UNITS {
        return false;
    }
    // Wine's 64-bit LDR_DATA_TABLE_ENTRY has BaseDllName at +0x58.
    let Some(length) = offset(entry, 0x58).and_then(read_u16) else {
        return false;
    };
    if usize::from(length) != name.len() * 2 {
        return false;
    }
    let Some(base_name) = offset(entry, 0x60).and_then(read_u64) else {
        return false;
    };
    let mut bytes = [0u8; MAX_MODULE_NAME_UNITS * 2];
    let bytes = &mut bytes[..name.len() * 2];
    if !read_memory(base_name, bytes) {
        return false;
    }
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .zip(name)
        .all(|(unit, &ascii)| unit[0].eq_ignore_ascii_case(&ascii) && unit[1] == 0)
}

fn base_from_peb(peb: u64, name: &[u8]) -> Option<u64> {
    let ldr = offset(peb, 0x18).and_then(read_u64)?;
    let head = offset(ldr, 0x10)?;
    let mut entry = read_u64(head)?;
    for _ in 0..MODULE_LIMIT {
        if entry == head || entry == 0 {
            return None;
        }
        if module_name_matches(entry, name) {
            // InLoadOrderLinks is the first field; DllBase is at +0x30.
            return offset(entry, 0x30).and_then(read_u64);
        }
        entry = read_u64(entry)?;
    }
    None
}

/// Base address of the module named `name` (ASCII, e.g. `b"ntdll.dll"`) as
/// loaded into this process's own PEB loader list, or `None` if it is not
/// loaded or the PEB cannot be walked.
pub(super) fn module_base(name: &[u8]) -> Option<u64> {
    let mut gs_base = 0u64;
    // SAFETY: ARCH_GET_GS writes one u64 to our own stack; a failed syscall
    // is handled by returning None.
    if unsafe { libc::syscall(libc::SYS_arch_prctl, 0x1004i64, &mut gs_base as *mut u64) } != 0 {
        return None;
    }
    let peb = offset(gs_base, 0x60).and_then(read_u64)?;
    base_from_peb(peb, name)
}

/// Syscall service number embedded in the named export of the PE image at
/// `base` (`mov r10, rcx; mov eax, imm32`, which every real syscall stub
/// opens with), found by walking the export table rather than assuming a
/// fixed ordinal or RVA.
pub(super) fn export_service(base: u64, export_name: &[u8]) -> Option<u32> {
    let mut dos = [0u8; 0x40];
    if !read_memory(base, &mut dos) || dos[..2] != *b"MZ" {
        return None;
    }
    let pe_offset = u32::from_le_bytes(dos[0x3c..0x40].try_into().ok()?);
    if pe_offset > PE_HEADER_LIMIT {
        return None;
    }
    let pe = offset(base, u64::from(pe_offset))?;
    let mut signature = [0u8; 4];
    if !read_memory(pe, &mut signature) || signature != *b"PE\0\0" {
        return None;
    }
    let optional = offset(pe, 24)?;
    if offset(optional, 0).and_then(read_u16)? != 0x20b {
        return None;
    }
    let image_size = offset(optional, 56).and_then(read_u32)?;
    let export_rva = offset(optional, 112).and_then(read_u32)?;
    let export = rva(base, image_size, export_rva)?;
    let function_count = offset(export, 0x14).and_then(read_u32)?;
    let name_count = offset(export, 0x18).and_then(read_u32)?;
    let functions = offset(export, 0x1c).and_then(read_u32)?;
    let names = offset(export, 0x20).and_then(read_u32)?;
    let ordinals = offset(export, 0x24).and_then(read_u32)?;
    if name_count == 0 || name_count > EXPORT_LIMIT || function_count > EXPORT_LIMIT {
        return None;
    }

    // PE export names are sorted. Binary search keeps this signal-path
    // discovery bounded even for a large export table.
    let mut low = 0u32;
    let mut high = name_count;
    while low < high {
        let mid = low + (high - low) / 2;
        let name_slot = rva(base, image_size, names.checked_add(mid.checked_mul(4)?)?)?;
        let name_rva = read_u32(name_slot)?;
        let name_address = rva(base, image_size, name_rva)?;
        let mut candidate = [0u8; 32];
        if !read_memory(name_address, &mut candidate) {
            return None;
        }
        let end = candidate
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(candidate.len());
        match candidate[..end].cmp(export_name) {
            core::cmp::Ordering::Less => low = mid + 1,
            core::cmp::Ordering::Greater => high = mid,
            core::cmp::Ordering::Equal => {
                let ordinal_slot =
                    rva(base, image_size, ordinals.checked_add(mid.checked_mul(2)?)?)?;
                let ordinal = u32::from(read_u16(ordinal_slot)?);
                if ordinal >= function_count {
                    return None;
                }
                let function_slot = rva(
                    base,
                    image_size,
                    functions.checked_add(ordinal.checked_mul(4)?)?,
                )?;
                let function_rva = read_u32(function_slot)?;
                let function = rva(base, image_size, function_rva)?;
                let mut head = [0u8; 8];
                if !read_memory(function, &mut head) || head[..4] != [0x4c, 0x8b, 0xd1, 0xb8] {
                    return None;
                }
                return Some(u32::from_le_bytes(head[4..8].try_into().ok()?));
            }
        }
    }
    None
}

#[cfg(all(test, not(miri)))]
mod tests {
    use super::{base_from_peb, export_service};

    // `base_from_peb` reads through `read_u16`/`read_u64` (`super::mem`),
    // which call `process_vm_readv` — not in Miri's foreign-function shim
    // list at all.
    #[cfg(not(miri))]
    #[test]
    fn finds_a_module_in_the_windows_loader_list() {
        let mut peb = [0u8; 0x30];
        let mut ldr = [0u8; 0x30];
        let mut entry = [0u8; 0x70];
        let name: Vec<u16> = "WiN32u.DlL".encode_utf16().collect();
        let head = ldr.as_ptr() as u64 + 0x10;
        peb[0x18..0x20].copy_from_slice(&(ldr.as_ptr() as u64).to_le_bytes());
        ldr[0x10..0x18].copy_from_slice(&(entry.as_ptr() as u64).to_le_bytes());
        entry[0..8].copy_from_slice(&head.to_le_bytes());
        entry[0x30..0x38].copy_from_slice(&0x1234_0000u64.to_le_bytes());
        entry[0x58..0x5a].copy_from_slice(&((name.len() * 2) as u16).to_le_bytes());
        entry[0x60..0x68].copy_from_slice(&(name.as_ptr() as u64).to_le_bytes());
        assert_eq!(
            base_from_peb(peb.as_ptr() as u64, b"win32u.dll"),
            Some(0x1234_0000)
        );
        assert_eq!(base_from_peb(peb.as_ptr() as u64, b"ntdll.dll"), None);
    }

    // `export_service` reads through `read_u16`/`read_u32`/`read_memory`
    // (`super::mem`), which call `process_vm_readv` — not in Miri's
    // foreign-function shim list at all.
    #[cfg(not(miri))]
    #[test]
    fn discovers_a_service_from_a_pe_export_instead_of_a_fixed_number() {
        let mut image = vec![0u8; 0x1000];
        image[..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        image[0x80..0x84].copy_from_slice(b"PE\0\0");
        image[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
        image[0xd0..0xd4].copy_from_slice(&0x1000u32.to_le_bytes());
        image[0x108..0x10c].copy_from_slice(&0x200u32.to_le_bytes());
        image[0x214..0x218].copy_from_slice(&1u32.to_le_bytes());
        image[0x218..0x21c].copy_from_slice(&1u32.to_le_bytes());
        image[0x21c..0x220].copy_from_slice(&0x300u32.to_le_bytes());
        image[0x220..0x224].copy_from_slice(&0x340u32.to_le_bytes());
        image[0x224..0x228].copy_from_slice(&0x360u32.to_le_bytes());
        image[0x300..0x304].copy_from_slice(&0x400u32.to_le_bytes());
        image[0x340..0x344].copy_from_slice(&0x380u32.to_le_bytes());
        image[0x380..0x394].copy_from_slice(b"NtUserBuildHwndList\0");
        image[0x400..0x408].copy_from_slice(&[0x4c, 0x8b, 0xd1, 0xb8, 0x5a, 0x13, 0, 0]);
        assert_eq!(
            export_service(image.as_ptr() as u64, b"NtUserBuildHwndList"),
            Some(0x135a)
        );
        assert_eq!(
            export_service(image.as_ptr() as u64, b"NtQueryVirtualMemory"),
            None
        );
    }
}
