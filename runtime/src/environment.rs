use core::ffi::{CStr, c_char};
use core::ptr;
use linuwux::environment::{OVERRIDES, already_present, override_capacity};

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

#[unsafe(no_mangle)]
pub unsafe extern "C" fn linuwux_setup_environment() {
    unsafe {
        if !libc::getenv(c"LinUwUx".as_ptr()).is_null() {
            return;
        }
        libc::setenv(c"LinUwUx".as_ptr(), c"1".as_ptr(), 0);
        let value = libc::getenv(c"PROTON_DISABLE_LSTEAMCLIENT".as_ptr());
        if value.is_null() || value.read() == 0 {
            libc::setenv(c"PROTON_DISABLE_LSTEAMCLIENT".as_ptr(), c"1".as_ptr(), 0);
        }
        for dll in OVERRIDES {
            add_override(dll);
        }
    }
}

#[cfg(not(test))]
#[used]
#[unsafe(link_section = ".init_array.00201")]
static INITIALIZE: unsafe extern "C" fn() = linuwux_setup_environment;
