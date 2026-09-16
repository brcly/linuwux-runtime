use core::ffi::CStr;

pub const OVERRIDES: [&CStr; 14] = [
    c"winmm",
    c"version",
    c"reflex",
    c"reflex64",
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
