use core::cell::UnsafeCell;
use core::ffi::{CStr, c_char, c_int, c_void};
use core::mem::MaybeUninit;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use linuwux::gamescope::{ANCESTRY_LIMIT, is_gamescope_path, preload_has_path, preserved_length};

const PATH_MAX: usize = libc::PATH_MAX as usize;
type Setenv = unsafe extern "C" fn(*const c_char, *const c_char, c_int) -> c_int;
static REAL_SETENV: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
static ENABLED: AtomicBool = AtomicBool::new(false);
struct StartupPath(UnsafeCell<[c_char; PATH_MAX]>);
unsafe impl Sync for StartupPath {}
static SELF_PATH: StartupPath = StartupPath(UnsafeCell::new([0; PATH_MAX]));

fn set_errno(value: c_int) {
    unsafe { *libc::__errno_location() = value };
}

fn resolve_real_setenv() -> Option<Setenv> {
    let mut symbol = REAL_SETENV.load(Ordering::Acquire);
    if symbol.is_null() {
        symbol = unsafe { libc::dlsym(libc::RTLD_NEXT, c"setenv".as_ptr()) };
        if symbol.is_null() {
            set_errno(libc::ENOSYS);
            return None;
        }
        REAL_SETENV.store(symbol, Ordering::Release);
    }
    Some(unsafe { core::mem::transmute::<*mut c_void, Setenv>(symbol) })
}

fn proc_path(pid: libc::pid_t, suffix: &str) -> [u8; 64] {
    struct Writer<'a>(&'a mut [u8]);

    impl core::fmt::Write for Writer<'_> {
        fn write_str(&mut self, text: &str) -> core::fmt::Result {
            if text.len() > self.0.len() {
                return Err(core::fmt::Error);
            }
            let (output, rest) = core::mem::take(&mut self.0).split_at_mut(text.len());
            output.copy_from_slice(text.as_bytes());
            self.0 = rest;
            Ok(())
        }
    }

    let mut path = [0; 64];
    let _ = core::fmt::write(
        &mut Writer(&mut path[..63]),
        format_args!("/proc/{pid}/{suffix}"),
    );
    path
}

fn process_is_gamescope(pid: libc::pid_t) -> bool {
    let path = proc_path(pid, "exe");
    let mut executable = [0u8; PATH_MAX];
    let length = unsafe {
        libc::readlink(
            path.as_ptr().cast(),
            executable.as_mut_ptr().cast(),
            PATH_MAX - 1,
        )
    };
    if length <= 0 || length as usize >= PATH_MAX {
        return false;
    }
    let bytes = &executable[..length as usize];
    is_gamescope_path(bytes.split(|&b| b == 0).next().unwrap_or_default())
}

fn parent_process_id(pid: libc::pid_t) -> libc::pid_t {
    let path = proc_path(pid, "status");
    let file = unsafe { libc::fopen(path.as_ptr().cast(), c"r".as_ptr()) };
    if file.is_null() {
        return -1;
    }
    let mut line = [0; 128];
    let mut parent = -1;
    unsafe {
        while !libc::fgets(line.as_mut_ptr(), line.len() as c_int, file).is_null() {
            if let Some(value) =
                linuwux::gamescope::parent_process_id(CStr::from_ptr(line.as_ptr()).to_bytes())
            {
                parent = value;
                break;
            }
            if let Some(tail) = CStr::from_ptr(line.as_ptr())
                .to_bytes()
                .strip_prefix(b"PPid:")
            {
                let mut tail = tail;
                while tail
                    .first()
                    .is_some_and(|b| matches!(*b, b' ' | b'\t'..=b'\r'))
                {
                    tail = &tail[1..];
                }
                let digits = tail
                    .strip_prefix(b"-")
                    .or_else(|| tail.strip_prefix(b"+"))
                    .unwrap_or(tail);
                if digits.first().is_some_and(u8::is_ascii_digit) {
                    break;
                }
            }
        }
        libc::fclose(file);
    }
    parent
}

fn has_gamescope_ancestor() -> bool {
    let mut pid = unsafe { libc::getpid() };
    for _ in 0..ANCESTRY_LIMIT {
        if pid <= 0 {
            break;
        }
        if process_is_gamescope(pid) {
            return true;
        }
        if pid == 1 {
            break;
        }
        let parent = parent_process_id(pid);
        if parent <= 0 || parent == pid {
            break;
        }
        pid = parent;
    }
    false
}

unsafe fn resolve_self_path() -> bool {
    let mut info = MaybeUninit::<libc::Dl_info>::uninit();
    if unsafe { libc::dladdr(SELF_PATH.0.get().cast(), info.as_mut_ptr()) } == 0 {
        return false;
    }
    let filename = unsafe { ptr::addr_of!((*info.as_ptr()).dli_fname).read() };
    if filename.is_null() {
        return false;
    }
    let mut resolved = [0; PATH_MAX];
    let success = unsafe { !libc::realpath(filename, resolved.as_mut_ptr()).is_null() };
    let source = unsafe { CStr::from_ptr(if success { resolved.as_ptr() } else { filename }) };
    if (!success && !source.to_bytes().starts_with(b"/")) || source.to_bytes().len() >= PATH_MAX {
        return false;
    }
    unsafe {
        ptr::copy_nonoverlapping(
            source.as_ptr(),
            SELF_PATH.0.get().cast::<c_char>(),
            source.to_bytes_with_nul().len(),
        )
    };
    true
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn linuwux_setup_gamescope() {
    if !has_gamescope_ancestor() || resolve_real_setenv().is_none() {
        return;
    }
    if unsafe { resolve_self_path() } {
        ENABLED.store(true, Ordering::Release);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn setenv(
    name: *const c_char,
    value: *const c_char,
    overwrite: c_int,
) -> c_int {
    let Some(real) = resolve_real_setenv() else {
        return -1;
    };
    let should_check = ENABLED.load(Ordering::Acquire)
        && unsafe { CStr::from_ptr(name) }.to_bytes() == b"LD_PRELOAD";
    if !should_check {
        return unsafe { real(name, value, overwrite) };
    }
    let path = unsafe { CStr::from_ptr(SELF_PATH.0.get().cast()) };
    let contents = unsafe { CStr::from_ptr(value) };
    let present = preload_has_path(contents.to_bytes(), path.to_bytes(), |byte| unsafe {
        libc::isspace(c_int::from(byte)) != 0
    });
    if present || (overwrite == 0 && unsafe { !libc::getenv(name).is_null() }) {
        return unsafe { real(name, value, overwrite) };
    }
    let Some(length) = preserved_length(contents.to_bytes().len(), path.to_bytes().len()) else {
        set_errno(libc::ENOMEM);
        return -1;
    };
    let preserved = unsafe { libc::malloc(length).cast::<c_char>() };
    if preserved.is_null() {
        return -1;
    }
    unsafe {
        fill_preserved(preserved, contents, path);
        let result = real(name, preserved, overwrite);
        libc::free(preserved.cast());
        result
    }
}

unsafe fn fill_preserved(destination: *mut c_char, value: &CStr, path: &CStr) {
    let length = value.to_bytes().len();
    unsafe {
        if length != 0 {
            ptr::copy_nonoverlapping(value.as_ptr(), destination, length);
            destination.add(length).write(b':' as c_char);
        }
        ptr::copy_nonoverlapping(
            path.as_ptr(),
            destination.add(length + usize::from(length != 0)),
            path.to_bytes_with_nul().len(),
        );
    }
}

#[cfg(not(test))]
#[used]
#[unsafe(link_section = ".init_array.00103")]
static INITIALIZE: unsafe extern "C" fn() = linuwux_setup_gamescope;
