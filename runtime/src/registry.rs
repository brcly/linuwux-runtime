use core::ffi::{CStr, c_char, c_int, c_void};
use core::mem::{align_of, size_of};
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use linuwux::registry::{
    HW_PROFILE_KEY_PATH, HW_PROFILE_VALUE, HW_PROFILE_VALUE_NAME, utf16_nul_encode,
};

const KEY_ALL_ACCESS: u32 = 0x001f_003f;
const THREAD_ALL_ACCESS: u32 = 0x001f_03ff;
const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
const REG_SZ: u32 = 1;

const REQUEST_IDLE: u32 = 0;
const REQUEST_PENDING: u32 = 1;
const REQUEST_RUNNING: u32 = 2;
const REQUEST_DONE: u32 = 3;
const FUTEX_WAIT_PRIVATE: c_int = 128;
const FUTEX_WAKE_PRIVATE: c_int = 129;

static WORKER_STARTED: AtomicBool = AtomicBool::new(false);
static REQUEST: AtomicU32 = AtomicU32::new(REQUEST_IDLE);

pub(crate) fn after_fork() {
    WORKER_STARTED.store(false, Ordering::Release);
    REQUEST.store(REQUEST_IDLE, Ordering::Release);
}

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: *mut c_void,
    object_name: *const UnicodeString,
    attributes: u32,
    security_descriptor: *mut c_void,
    security_quality_of_service: *mut c_void,
}

type NtCreateKey = unsafe extern "C" fn(
    key: *mut *mut c_void,
    access: u32,
    attributes: *const ObjectAttributes,
    title_index: u32,
    class: *const UnicodeString,
    create_options: u32,
    disposition: *mut u32,
) -> i32;

type NtSetValueKey = unsafe extern "C" fn(
    key: *mut c_void,
    value_name: *const UnicodeString,
    title_index: u32,
    value_type: u32,
    data: *const c_void,
    data_size: u32,
) -> i32;

type NtClose = unsafe extern "C" fn(handle: *mut c_void) -> i32;

type NtCreateThreadEx = unsafe extern "C" fn(
    thread: *mut *mut c_void,
    access: u32,
    attributes: *mut c_void,
    process: *mut c_void,
    start: *mut c_void,
    argument: *mut c_void,
    flags: u32,
    zero_bits: usize,
    stack_commit: usize,
    stack_reserve: usize,
    attribute_list: *mut c_void,
) -> i32;

const _: () = {
    assert!(size_of::<UnicodeString>() == 16);
    assert!(align_of::<UnicodeString>() == 8);
    assert!(size_of::<ObjectAttributes>() == 48);
    assert!(align_of::<ObjectAttributes>() == 8);
};

unsafe extern "C" {
    fn debug_log(message: *const c_char);
}

fn log(message: &'static CStr) {
    unsafe { debug_log(message.as_ptr()) };
}

fn denuvowo_process() -> bool {
    #[cfg(feature = "environment")]
    {
        crate::environment::denuvowo_process()
    }
    #[cfg(not(feature = "environment"))]
    false
}

fn write_hwprofile_guid() {
    let handle = find_ntdll_handle();
    if handle.is_null() {
        log(c"hwprofile_guid: ntdll.so not loaded; skipping");
        return;
    }
    let create = resolve_symbol(handle, c"NtCreateKey");
    let set_value = resolve_symbol(handle, c"NtSetValueKey");
    let close = resolve_symbol(handle, c"NtClose");
    let (Some(create), Some(set_value), Some(close)) = (create, set_value, close) else {
        log(c"hwprofile_guid: could not resolve NtCreateKey/NtSetValueKey/NtClose; skipping");
        return;
    };
    let create: NtCreateKey = unsafe { core::mem::transmute::<*mut c_void, NtCreateKey>(create) };
    let set_value: NtSetValueKey =
        unsafe { core::mem::transmute::<*mut c_void, NtSetValueKey>(set_value) };
    let close: NtClose = unsafe { core::mem::transmute::<*mut c_void, NtClose>(close) };
    let key = unsafe { open_hwprofile_key(create, close) };
    if key.is_null() {
        log(c"hwprofile_guid: could not open the hardware profile key");
        return;
    }
    unsafe { write_hwprofile_value(set_value, close, key) };
}

unsafe fn futex_wait(expected: u32, timeout: *const libc::timespec) {
    let address = ptr::addr_of!(REQUEST).cast::<u32>().cast_mut();
    unsafe {
        libc::syscall(
            libc::SYS_futex,
            address,
            FUTEX_WAIT_PRIVATE,
            expected,
            timeout,
            0,
            0,
        );
    }
}

unsafe fn futex_wake() {
    let address = ptr::addr_of!(REQUEST).cast::<u32>().cast_mut();
    unsafe {
        libc::syscall(libc::SYS_futex, address, FUTEX_WAKE_PRIVATE, 1, 0, 0, 0);
    }
}

extern "C" fn registry_worker(_: *mut c_void) -> u32 {
    loop {
        let state = REQUEST.load(Ordering::Acquire);
        if state == REQUEST_DONE {
            return 0;
        }
        if state != REQUEST_PENDING {
            unsafe { futex_wait(state, ptr::null()) };
            continue;
        }
        if REQUEST
            .compare_exchange(
                REQUEST_PENDING,
                REQUEST_RUNNING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            continue;
        }
        write_hwprofile_guid();
        REQUEST.store(REQUEST_DONE, Ordering::Release);
        unsafe { futex_wake() };
        return 0;
    }
}

pub(crate) extern "C" fn setup_registry_worker() {
    if !denuvowo_process() || WORKER_STARTED.load(Ordering::Acquire) {
        return;
    }
    let handle = find_ntdll_handle();
    if handle.is_null() {
        log(c"hwprofile_guid: ntdll.so not loaded; registry worker unavailable");
        return;
    }
    let create = resolve_symbol(handle, c"NtCreateThreadEx");
    let close = resolve_symbol(handle, c"NtClose");
    let (Some(create), Some(close)) = (create, close) else {
        log(c"hwprofile_guid: could not resolve NtCreateThreadEx/NtClose");
        return;
    };
    let create: NtCreateThreadEx =
        unsafe { core::mem::transmute::<*mut c_void, NtCreateThreadEx>(create) };
    let close: NtClose = unsafe { core::mem::transmute::<*mut c_void, NtClose>(close) };
    let mut thread = ptr::null_mut();
    let status = unsafe {
        create(
            &mut thread,
            THREAD_ALL_ACCESS,
            ptr::null_mut(),
            (-1isize) as *mut c_void,
            registry_worker as *const () as *mut c_void,
            ptr::null_mut(),
            0,
            0,
            0,
            0,
            ptr::null_mut(),
        )
    };
    if status < 0 || thread.is_null() {
        log(c"hwprofile_guid: registry worker could not start");
        return;
    }
    WORKER_STARTED.store(true, Ordering::Release);
    unsafe {
        close(thread);
    }
}

pub(crate) fn set_hwprofile_guid() {
    if !denuvowo_process() || !WORKER_STARTED.load(Ordering::Acquire) {
        return;
    }
    if REQUEST
        .compare_exchange(
            REQUEST_IDLE,
            REQUEST_PENDING,
            Ordering::AcqRel,
            Ordering::Relaxed,
        )
        .is_ok()
    {
        unsafe { futex_wake() };
    }
    let timeout = libc::timespec {
        tv_sec: 0,
        tv_nsec: 10_000_000,
    };
    for _ in 0..200 {
        match REQUEST.load(Ordering::Acquire) {
            REQUEST_DONE => return,
            REQUEST_PENDING | REQUEST_RUNNING => {
                let state = REQUEST.load(Ordering::Acquire);
                if state == REQUEST_PENDING || state == REQUEST_RUNNING {
                    unsafe { futex_wait(state, &timeout) };
                }
            }
            _ => return,
        }
    }
}

fn resolve_symbol(handle: *mut c_void, name: &'static CStr) -> Option<*mut c_void> {
    let raw = unsafe { libc::dlsym(handle, name.as_ptr()) };
    (!raw.is_null()).then_some(raw)
}

fn find_ntdll_handle() -> *mut c_void {
    let handle = unsafe { libc::dlopen(c"ntdll.so".as_ptr(), libc::RTLD_NOW | libc::RTLD_NOLOAD) };
    if !handle.is_null() {
        return handle;
    }

    let mut path = [0u8; libc::PATH_MAX as usize + 1];
    let Some(length) = loaded_ntdll_path(&mut path) else {
        return ptr::null_mut();
    };
    path[length] = 0;
    unsafe { libc::dlopen(path.as_ptr().cast(), libc::RTLD_NOW | libc::RTLD_NOLOAD) }
}

fn loaded_ntdll_path(out: &mut [u8]) -> Option<usize> {
    struct Search {
        out: *mut u8,
        capacity: usize,
        length: usize,
    }

    unsafe extern "C" fn visit(
        info: *mut libc::dl_phdr_info,
        _size: usize,
        data: *mut c_void,
    ) -> c_int {
        let search = unsafe { &mut *data.cast::<Search>() };
        let name = unsafe { (*info).dlpi_name };
        if name.is_null() {
            return 0;
        }
        let name = unsafe { CStr::from_ptr(name) }.to_bytes();
        if !name.ends_with(b"/ntdll.so") || name.len() >= search.capacity {
            return 0;
        }
        unsafe {
            ptr::copy_nonoverlapping(name.as_ptr(), search.out, name.len());
            search.out.add(name.len()).write(0);
        }
        search.length = name.len();
        1
    }

    let mut search = Search {
        out: out.as_mut_ptr(),
        capacity: out.len(),
        length: 0,
    };
    unsafe {
        libc::dl_iterate_phdr(Some(visit), (&mut search as *mut Search).cast());
    }
    if search.length > 0 {
        return Some(search.length);
    }

    let file = unsafe { libc::fopen(c"/proc/self/maps".as_ptr(), c"r".as_ptr()) };
    if file.is_null() {
        return None;
    }
    let mut line = [0u8; 4096];
    while unsafe { !libc::fgets(line.as_mut_ptr().cast(), line.len() as c_int, file).is_null() } {
        let bytes = unsafe { CStr::from_ptr(line.as_ptr().cast()) }.to_bytes();
        let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
        let mut start = 0;
        while let Some(offset) = bytes[start..].iter().position(|&byte| byte == b'/') {
            start += offset;
            let candidate = &bytes[start..];
            if candidate.ends_with(b"/ntdll.so") && candidate.len() < out.len() {
                unsafe {
                    ptr::copy_nonoverlapping(candidate.as_ptr(), out.as_mut_ptr(), candidate.len());
                }
                unsafe { *out.as_mut_ptr().add(candidate.len()) = 0 };
                unsafe { libc::fclose(file) };
                return Some(candidate.len());
            }
            start += 1;
            if start >= bytes.len() {
                break;
            }
        }
    }
    unsafe { libc::fclose(file) };
    None
}

fn utf16_string(ascii: &[u8], buffer: &mut [u16], string: &mut UnicodeString) -> bool {
    let Some(units) = utf16_nul_encode(ascii, buffer) else {
        return false;
    };
    string.length = (ascii.len() * 2) as u16;
    string.maximum_length = (units * 2) as u16;
    string.buffer = buffer.as_mut_ptr();
    true
}

unsafe fn open_hwprofile_key(create: NtCreateKey, close: NtClose) -> *mut c_void {
    let mut current: *mut c_void = ptr::null_mut();
    for &component in HW_PROFILE_KEY_PATH {
        let mut name_buffer = [0u16; 32];
        let mut name = UnicodeString {
            length: 0,
            maximum_length: 0,
            buffer: ptr::null_mut(),
        };
        if !utf16_string(component, &mut name_buffer, &mut name) {
            if !current.is_null() {
                unsafe { close(current) };
            }
            return ptr::null_mut();
        }
        let attributes = ObjectAttributes {
            length: size_of::<ObjectAttributes>() as u32,
            root_directory: current,
            object_name: &name,
            attributes: OBJ_CASE_INSENSITIVE,
            security_descriptor: ptr::null_mut(),
            security_quality_of_service: ptr::null_mut(),
        };
        let mut next: *mut c_void = ptr::null_mut();
        let status = unsafe {
            create(
                &mut next,
                KEY_ALL_ACCESS,
                &attributes,
                0,
                ptr::null(),
                0,
                ptr::null_mut(),
            )
        };
        if status < 0 || next.is_null() {
            if !current.is_null() {
                unsafe { close(current) };
            }
            return ptr::null_mut();
        }
        if !current.is_null() {
            unsafe { close(current) };
        }
        current = next;
    }
    current
}

unsafe fn write_hwprofile_value(set_value: NtSetValueKey, close: NtClose, key: *mut c_void) {
    let mut name_buffer = [0u16; 32];
    let mut value_name = UnicodeString {
        length: 0,
        maximum_length: 0,
        buffer: ptr::null_mut(),
    };
    if !utf16_string(HW_PROFILE_VALUE_NAME, &mut name_buffer, &mut value_name) {
        unsafe { close(key) };
        return;
    }
    let mut data_buffer = [0u16; 48];
    let Some(units) = utf16_nul_encode(HW_PROFILE_VALUE, &mut data_buffer) else {
        unsafe { close(key) };
        return;
    };
    let status = unsafe {
        set_value(
            key,
            &value_name,
            0,
            REG_SZ,
            data_buffer.as_ptr().cast(),
            (units * 2) as u32,
        )
    };
    if status < 0 {
        log(c"hwprofile_guid: NtSetValueKey failed");
    } else {
        log(c"hwprofile_guid: HwProfileGuid registry value set");
    }
    unsafe { close(key) };
}
