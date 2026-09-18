use core::ffi::{CStr, c_char, c_int};
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};
use linuwux::environment::{OVERRIDES, already_present, override_capacity};

static GAME_PROCESS: AtomicBool = AtomicBool::new(false);

#[cfg(feature = "hooks")]
pub(crate) fn game_process() -> bool {
    GAME_PROCESS.load(Ordering::Acquire)
}

unsafe fn add_override(dll: &CStr) {
    let pointer = unsafe { libc::getenv(c"WINEDLLOVERRIDES".as_ptr()) };
    let existing = if pointer.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(pointer) })
    };
    if existing.is_some_and(|value| already_present(value.to_bytes(), dll.to_bytes())) {
        return;
    }
    let Some(capacity) = override_capacity(
        existing.map(|value| value.to_bytes().len()),
        dll.to_bytes().len(),
    ) else {
        unsafe { *libc::__errno_location() = libc::ENOMEM };
        return;
    };
    let output = unsafe { libc::malloc(capacity).cast::<c_char>() };
    if output.is_null() {
        return;
    }
    unsafe {
        fill_override(output, existing, dll);
        libc::setenv(c"WINEDLLOVERRIDES".as_ptr(), output, 1);
        libc::free(output.cast());
    }
}

unsafe fn fill_override(output: *mut c_char, existing: Option<&CStr>, dll: &CStr) {
    let prefix = existing.map_or(b"".as_slice(), CStr::to_bytes);
    unsafe {
        let mut position = 0;
        if !prefix.is_empty() {
            ptr::copy_nonoverlapping(prefix.as_ptr().cast(), output, prefix.len());
            position = prefix.len();
            output.add(position).write(b';' as c_char);
            position += 1;
        }
        ptr::copy_nonoverlapping(dll.as_ptr(), output.add(position), dll.to_bytes().len());
        position += dll.to_bytes().len();
        ptr::copy_nonoverlapping(c"=n,b".as_ptr(), output.add(position), 5);
    }
}

fn equal_name(actual: &[u8], expected: &[u8]) -> bool {
    actual.len() == expected.len()
        && actual
            .iter()
            .zip(expected)
            .all(|(&left, &right)| left.eq_ignore_ascii_case(&right))
}

fn is_exe(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && equal_name(&bytes[bytes.len() - 4..], b".exe")
}

fn is_helper_basename(executable: &[u8]) -> bool {
    let basename = executable
        .rsplit(|&byte| byte == b'/' || byte == b'\\')
        .next()
        .unwrap_or(executable);
    const HELPERS: [&[u8]; 10] = [
        b"steam.exe",
        b"steamwebhelper.exe",
        b"crashhandler.exe",
        b"winecfg.exe",
        b"start.exe",
        b"rundll32.exe",
        b"dllhost.exe",
        b"conhost.exe",
        b"explorer.exe",
        b"xalia.exe",
    ];
    HELPERS.iter().any(|name| equal_name(basename, name))
}

fn is_system32_helper(executable: &[u8]) -> bool {
    let mut lowered = [0u8; 512];
    if executable.len() >= lowered.len() {
        return false;
    }
    for (index, &byte) in executable.iter().enumerate() {
        lowered[index] = if byte == b'\\' {
            b'/'
        } else {
            byte.to_ascii_lowercase()
        };
    }
    let path = &lowered[..executable.len()];
    path.windows(b"/windows/system32/".len())
        .any(|window| window == b"/windows/system32/")
        || path
            .windows(b"/windows/syswow64/".len())
            .any(|window| window == b"/windows/syswow64/")
}

fn argv0_is_unix_loader(bytes: &[u8]) -> bool {
    bytes
        .windows(b"wine-preloader".len())
        .any(|window| window == b"wine-preloader")
        || bytes
            .windows(b"wine64-preloader".len())
            .any(|window| window == b"wine64-preloader")
        || bytes
            .windows(b"wineserver".len())
            .any(|window| window == b"wineserver")
        || bytes
            .windows(b"pressure-vessel".len())
            .any(|window| window == b"pressure-vessel")
}

fn game_executable_argument(argc: c_int, argv: *const *const c_char) -> Option<*const c_char> {
    if argc < 1 || argv.is_null() {
        return None;
    }
    let argv0 = unsafe { *argv };
    if !argv0.is_null() && argv0_is_unix_loader(unsafe { CStr::from_ptr(argv0) }.to_bytes()) {
        // Preloader/wineserver may mention the game path without being the PE.
        // Only count a Windows-drive .exe that is not a system helper.
        let mut windows_game = None;
        for index in 1..argc as usize {
            let candidate = unsafe { *argv.add(index) };
            if candidate.is_null() {
                continue;
            }
            let bytes = unsafe { CStr::from_ptr(candidate) }.to_bytes();
            if !is_exe(bytes) {
                continue;
            }
            if bytes.len() < 2 || bytes[1] != b':' {
                continue;
            }
            if is_system32_helper(bytes) || is_helper_basename(bytes) {
                return None;
            }
            windows_game = Some(candidate);
        }
        return windows_game;
    }
    let mut windows_game = None;
    let mut unix_game = None;
    let mut windows_helper = false;
    for index in 0..argc as usize {
        let candidate = unsafe { *argv.add(index) };
        if candidate.is_null() {
            continue;
        }
        let bytes = unsafe { CStr::from_ptr(candidate) }.to_bytes();
        if !is_exe(bytes) {
            continue;
        }
        if is_system32_helper(bytes) || is_helper_basename(bytes) {
            windows_helper = true;
            continue;
        }
        if bytes.len() >= 2 && bytes[1] == b':' {
            windows_game = Some(candidate);
        } else if bytes.starts_with(b"/") {
            unix_game = Some(candidate);
        }
    }
    windows_game.or(if windows_helper { None } else { unix_game })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn linuwux_setup_environment(
    argc: c_int,
    argv: *const *const c_char,
    _envp: *const *const c_char,
) {
    unsafe {
        crate::registry::init_registry();
        let game_process = game_executable_argument(argc, argv).is_some();
        GAME_PROCESS.store(game_process, Ordering::Release);
        if libc::getenv(c"LinUwUx".as_ptr()).is_null() {
            libc::setenv(c"LinUwUx".as_ptr(), c"1".as_ptr(), 0);
            let value = libc::getenv(c"PROTON_DISABLE_LSTEAMCLIENT".as_ptr());
            if value.is_null() || value.read() == 0 {
                libc::setenv(c"PROTON_DISABLE_LSTEAMCLIENT".as_ptr(), c"1".as_ptr(), 0);
            }
        }
        if game_process {
            for dll in OVERRIDES {
                add_override(dll);
            }
        }
    }
}

#[used]
#[unsafe(link_section = ".init_array.00201")]
static INITIALIZE: unsafe extern "C" fn(c_int, *const *const c_char, *const *const c_char) =
    linuwux_setup_environment;
