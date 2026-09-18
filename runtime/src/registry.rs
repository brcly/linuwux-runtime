#[cfg(feature = "debug")]
use core::ffi::c_char;
use core::ffi::{CStr, c_void};

const REGISTRY_NAME: &CStr = c"/system.reg";
const DONE_ENV: &CStr = c"LINUWUX_HWPROFILE";
const WINE_REGISTRY_MAGIC: &[u8] = b"WINE REGISTRY";
const PROFILE_MARKER: &[u8] = b"Hardware Profiles\\\\0001";
const GUID_MARKER: &[u8] = b"HwProfileGuid";
const REGISTRY_SECTION: &CStr = c"\n[System\\\\CurrentControlSet\\\\Control\\\\IDConfigDB\\\\Hardware Profiles\\\\0001]\n\"HwProfileGuid\"=\"{12345678-1234-1234-1234-123456789012}\"\n";

#[cfg(feature = "debug")]
unsafe extern "C" {
    fn debug_log(message: *const c_char);
}

fn log(message: &CStr) {
    #[cfg(feature = "debug")]
    unsafe {
        debug_log(message.as_ptr());
    }
    #[cfg(not(feature = "debug"))]
    let _ = message;
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn registry_file_is_valid(file: *mut libc::FILE) -> bool {
    let mut header = [0u8; 64];
    unsafe { libc::rewind(file) };
    let read = unsafe { libc::fread(header.as_mut_ptr().cast::<c_void>(), 1, header.len(), file) };
    read >= WINE_REGISTRY_MAGIC.len() && header.starts_with(WINE_REGISTRY_MAGIC)
}

fn registry_already_present(file: *mut libc::FILE) -> bool {
    let mut buffer = [0u8; 4096];
    let mut window = [0u8; 64];
    let mut window_len = 0usize;
    let mut in_profile = false;
    unsafe { libc::rewind(file) };
    loop {
        let read =
            unsafe { libc::fread(buffer.as_mut_ptr().cast::<c_void>(), 1, buffer.len(), file) };
        if read == 0 {
            break;
        }
        for &byte in &buffer[..read] {
            if window_len == window.len() {
                window.copy_within(1.., 0);
                window_len -= 1;
            }
            window[window_len] = byte;
            window_len += 1;
            let filled = &window[..window_len];
            if !in_profile {
                if contains(filled, PROFILE_MARKER) {
                    in_profile = true;
                    window_len = 0;
                }
                continue;
            }
            if contains(filled, GUID_MARKER) {
                return true;
            }
        }
    }
    false
}

/// Appends `HwProfileGuid` to an existing Wine `system.reg`.
///
/// Does not create the file: wineserver must write a valid hive first.
/// Safe from `.init_array`; not for use in a signal handler.
fn mark_done() {
    unsafe { libc::setenv(DONE_ENV.as_ptr(), c"1".as_ptr(), 1) };
}

pub(crate) fn init_registry() {
    let done = unsafe { libc::getenv(DONE_ENV.as_ptr()) };
    if !done.is_null() {
        return;
    }
    let prefix = unsafe { libc::getenv(c"WINEPREFIX".as_ptr()) };
    if prefix.is_null() {
        return;
    }
    let prefix = unsafe { CStr::from_ptr(prefix) }.to_bytes();
    let mut path = [0u8; libc::PATH_MAX as usize];
    if prefix.len() + REGISTRY_NAME.to_bytes_with_nul().len() > path.len() {
        return;
    }
    path[..prefix.len()].copy_from_slice(prefix);
    path[prefix.len()..prefix.len() + REGISTRY_NAME.to_bytes_with_nul().len()]
        .copy_from_slice(REGISTRY_NAME.to_bytes_with_nul());
    if unsafe { libc::access(path.as_ptr().cast(), libc::F_OK) } != 0 {
        return;
    }
    let file = unsafe { libc::fopen(path.as_ptr().cast(), c"r+".as_ptr()) };
    if file.is_null() {
        log(c"hwprofile_guid: could not open system.reg");
        return;
    }
    if unsafe { libc::flock(libc::fileno(file), libc::LOCK_EX) } != 0 {
        unsafe { libc::fclose(file) };
        return;
    }
    if !registry_file_is_valid(file) {
        log(c"hwprofile_guid: system.reg is not a Wine registry file; skipping");
        unsafe {
            libc::flock(libc::fileno(file), libc::LOCK_UN);
            libc::fclose(file);
        }
        return;
    }
    if registry_already_present(file) {
        unsafe {
            libc::flock(libc::fileno(file), libc::LOCK_UN);
            libc::fclose(file);
        }
        mark_done();
        return;
    }
    if unsafe { libc::fseek(file, 0, libc::SEEK_END) } != 0 {
        unsafe {
            libc::flock(libc::fileno(file), libc::LOCK_UN);
            libc::fclose(file);
        }
        return;
    }
    let written = unsafe {
        libc::fwrite(
            REGISTRY_SECTION.as_ptr().cast::<c_void>(),
            1,
            REGISTRY_SECTION.to_bytes().len(),
            file,
        )
    };
    unsafe {
        libc::fflush(file);
        libc::flock(libc::fileno(file), libc::LOCK_UN);
        libc::fclose(file);
    }
    if written == REGISTRY_SECTION.to_bytes().len() {
        mark_done();
        log(c"hwprofile_guid: wrote HwProfileGuid into system.reg");
    } else {
        log(c"hwprofile_guid: failed to write HwProfileGuid into system.reg");
    }
}

#[cfg(feature = "reflex")]
pub(crate) fn set_hwprofile_guid() {}
