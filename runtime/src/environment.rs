use core::ffi::{CStr, c_char, c_int};
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};
use linuwux::environment::{OVERRIDES, already_present, override_capacity};

const DENUVOWO_ENV: &CStr = c"LINUWUX_DENUVOWODLL";
const DENUVOWO_DLL: &CStr = c"DenuvOwO";
static DENUVOWO_PROCESS: AtomicBool = AtomicBool::new(false);

#[cfg(all(feature = "reflex", feature = "hooks"))]
pub(crate) fn denuvowo_process() -> bool {
    DENUVOWO_PROCESS.load(Ordering::Acquire)
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

unsafe fn denuvowo_enabled() -> bool {
    let value = unsafe { libc::getenv(DENUVOWO_ENV.as_ptr()) };
    !value.is_null() && unsafe { CStr::from_ptr(value) }.to_bytes() == b"1"
}

unsafe fn denuvowo_dll_in_directory(argc: c_int, argv: *const *const c_char) -> bool {
    if argc < 2 || argv.is_null() {
        return false;
    }
    let mut executable = ptr::null();
    for index in 0..argc as usize {
        let candidate = unsafe { *argv.add(index) };
        if candidate.is_null() {
            continue;
        }
        let bytes = unsafe { CStr::from_ptr(candidate) }.to_bytes();
        if bytes.len() >= 2 && bytes[1] == b':' {
            executable = candidate;
            break;
        }
    }
    if executable.is_null() {
        return false;
    }
    let executable = unsafe { CStr::from_ptr(executable) }.to_bytes();
    let prefix = unsafe { libc::getenv(c"WINEPREFIX".as_ptr()) };
    let mut path = [0u8; libc::PATH_MAX as usize];
    let mut length;
    if executable[0].eq_ignore_ascii_case(&b'z') {
        let source = &executable[2..];
        if source.len() >= path.len() {
            return false;
        }
        path[..source.len()].copy_from_slice(source);
        length = source.len();
    } else {
        let Some(prefix) =
            (!prefix.is_null()).then(|| unsafe { CStr::from_ptr(prefix) }.to_bytes())
        else {
            return false;
        };
        let drive = executable[0].to_ascii_lowercase();
        let rest = &executable[2..];
        let Some(required) = prefix
            .len()
            .checked_add(14)
            .and_then(|length| length.checked_add(rest.len()))
        else {
            return false;
        };
        if required >= path.len() {
            return false;
        }
        path[..prefix.len()].copy_from_slice(prefix);
        length = prefix.len();
        path[length..length + 12].copy_from_slice(b"/dosdevices/");
        length += 12;
        path[length] = drive;
        length += 1;
        path[length] = b':';
        length += 1;
        path[length..length + rest.len()].copy_from_slice(rest);
        length += rest.len();
    }
    for byte in &mut path[..length] {
        if *byte == b'\\' {
            *byte = b'/';
        }
    }
    let Some(slash) = path[..length].iter().rposition(|&byte| byte == b'/') else {
        return false;
    };
    length = slash + 1;
    let marker = b"DenuvOwO.dll\0";
    if length
        .checked_add(marker.len())
        .is_none_or(|end| end > path.len())
    {
        return false;
    }
    path[length..length + marker.len()].copy_from_slice(marker);
    unsafe { libc::access(path.as_ptr().cast(), libc::F_OK) == 0 }
}

unsafe fn hint_denuvowo() {
    #[cfg(feature = "reflex")]
    unsafe extern "C" {
        fn reflex_hint_denuvowo();
    }
    #[cfg(feature = "reflex")]
    unsafe {
        reflex_hint_denuvowo();
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn linuwux_setup_environment(
    argc: c_int,
    argv: *const *const c_char,
    _envp: *const *const c_char,
) {
    unsafe {
        let denuvowo_enabled = denuvowo_enabled();
        let denuvowo_process = denuvowo_enabled && denuvowo_dll_in_directory(argc, argv);
        DENUVOWO_PROCESS.store(denuvowo_process, Ordering::Release);
        if libc::getenv(c"LinUwUx".as_ptr()).is_null() {
            libc::setenv(c"LinUwUx".as_ptr(), c"1".as_ptr(), 0);
            let value = libc::getenv(c"PROTON_DISABLE_LSTEAMCLIENT".as_ptr());
            if value.is_null() || value.read() == 0 {
                libc::setenv(c"PROTON_DISABLE_LSTEAMCLIENT".as_ptr(), c"1".as_ptr(), 0);
            }
            for dll in OVERRIDES {
                add_override(dll);
            }
        }
        if denuvowo_enabled {
            add_override(DENUVOWO_DLL);
        }
        if denuvowo_process {
            hint_denuvowo();
        }
    }
}

#[cfg(not(test))]
#[used]
#[unsafe(link_section = ".init_array.00201")]
static INITIALIZE: unsafe extern "C" fn(c_int, *const *const c_char, *const *const c_char) =
    linuwux_setup_environment;
