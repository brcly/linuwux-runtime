//! The `WINEDLLOVERRIDES` string manipulation LinUwUx needs to force native
//! DLL overrides for a detected game process: which DLLs to override, and
//! how to parse/extend the existing `;`-delimited value without duplicating
//! an entry. Pure byte-slice logic so it can be unit tested without libc;
//! `runtime/src/environment.rs` owns reading/writing the actual environment
//! variable and deciding whether the current process is a game process.
use core::ffi::CStr;

pub const OVERRIDES: [&CStr; 16] = [
    c"winmm",
    c"version",
    c"reflex",
    c"reflex64",
    c"DenuvOwO",
    c"artifact",
    c"d3d9",
    c"d3d10",
    c"d3d11",
    c"d3d12",
    c"dinput8",
    c"dsound",
    c"dxgi",
    c"hid",
    c"wininet",
    c"winhttp",
];

pub fn already_present(existing: &[u8], dll: &[u8]) -> bool {
    dll.is_empty()
        || existing
            .split(|&byte| byte == b';')
            .any(|entry| entry.split(|&byte| byte == b'=').next() == Some(dll))
}

pub fn override_capacity(existing: Option<usize>, dll_length: usize) -> Option<usize> {
    let prefix = match existing {
        Some(length) => length.checked_add(1)?,
        None => 0,
    };
    prefix.checked_add(dll_length)?.checked_add(5)
}

#[cfg(test)]
mod tests {
    use super::OVERRIDES;

    #[test]
    fn artifact_is_forced_native_for_game_processes() {
        assert!(OVERRIDES.iter().any(|dll| dll.to_bytes() == b"artifact"));
    }
}
