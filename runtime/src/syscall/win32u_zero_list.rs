//! Wine's `NtUserBuildHwndList` needs one output slot for `HWND_BOTTOM` even
//! when the server reports no windows. Some Wine builds report success for a
//! zero-capacity size probe and then write that terminator through a null
//! buffer. Complete only that probe with `STATUS_BUFFER_TOO_SMALL` and a
//! minimum size of one, after Reflex has chosen to bypass the syscall.
//!
//! The service ID comes from the loaded Wine `win32u.dll` export, so a Proton
//! update can reorder syscall IDs without turning another service into this
//! workaround. Failed discovery or an unreadable request falls through to
//! Wine unchanged.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use super::mem::{read_u32, read_u64, write_u32};

const STATUS_BUFFER_TOO_SMALL: u32 = 0xc000_0023;
const EXPORT_NAME: &[u8] = b"NtUserBuildHwndList";
const MODULE_NAME: &[u8] = b"win32u.dll";
const RESOLVE_ATTEMPT_LIMIT: u32 = 16;

fn offset(base: u64, amount: u64) -> Option<u64> {
    base.checked_add(amount)
}

static WINDOW_LIST_SERVICE: AtomicU32 = AtomicU32::new(0);
static RESOLVE_ATTEMPTS: AtomicU32 = AtomicU32::new(0);
#[cfg(feature = "debug")]
static FIX_LOGGED: AtomicBool = AtomicBool::new(false);

#[cfg(feature = "debug")]
unsafe extern "C" {
    fn debug_log(message: *const core::ffi::c_char);
    fn debug_log_hex(prefix: *const core::ffi::c_char, value: u64);
}

fn window_list_service() -> Option<u32> {
    let known = WINDOW_LIST_SERVICE.load(Ordering::Acquire);
    if known != 0 {
        return Some(known);
    }
    let attempt = RESOLVE_ATTEMPTS.fetch_add(1, Ordering::AcqRel);
    if attempt >= RESOLVE_ATTEMPT_LIMIT {
        #[cfg(feature = "debug")]
        if attempt == RESOLVE_ATTEMPT_LIMIT {
            unsafe { debug_log(c"win32u window list service discovery unavailable".as_ptr()) };
        }
        let known = WINDOW_LIST_SERVICE.load(Ordering::Acquire);
        return (known != 0).then_some(known);
    }
    let found = super::pe_export::module_base(MODULE_NAME)
        .and_then(|base| super::pe_export::export_service(base, EXPORT_NAME))
        .filter(|&number| number != 0);
    if let Some(number) = found {
        WINDOW_LIST_SERVICE.store(number, Ordering::Release);
        #[cfg(feature = "debug")]
        unsafe {
            debug_log_hex(
                c"win32u window list service discovered=".as_ptr(),
                u64::from(number),
            )
        };
    }
    found.or_else(|| {
        let known = WINDOW_LIST_SERVICE.load(Ordering::Acquire);
        (known != 0).then_some(known)
    })
}

fn complete_zero_capacity(gregs: *mut libc::greg_t, service: u32) -> bool {
    let register = |index: libc::c_int| unsafe { gregs.add(index as usize).read() as u64 };
    if register(libc::REG_RAX) != u64::from(service) {
        return false;
    }
    let rsp = register(libc::REG_RSP);
    // Windows x64: arguments 6, 7 and 8 are at RSP+0x30, +0x38 and +0x40.
    let Some(count) = offset(rsp, 0x30).and_then(read_u32) else {
        return false;
    };
    let Some(buffer) = offset(rsp, 0x38).and_then(read_u64) else {
        return false;
    };
    let Some(size) = offset(rsp, 0x40).and_then(read_u64) else {
        return false;
    };
    if count != 0 || buffer != 0 || size == 0 || !write_u32(size, 1) {
        return false;
    }
    // SIGSYS reports RIP after the two-byte syscall. Leave RIP, RCX, R11,
    // flags, stack and all other arguments unchanged, as Wine's successful
    // syscall return would; only the status and required size are outputs.
    unsafe {
        gregs
            .add(libc::REG_RAX as usize)
            .write(STATUS_BUFFER_TOO_SMALL as libc::greg_t)
    };
    #[cfg(feature = "debug")]
    if !FIX_LOGGED.swap(true, Ordering::AcqRel) {
        unsafe {
            debug_log(
                c"win32u zero-capacity window list probe returned STATUS_BUFFER_TOO_SMALL".as_ptr(),
            );
            debug_log_hex(c"win32u window list service=".as_ptr(), u64::from(service));
        }
    }
    true
}

/// Complete the one Wine-buggy buffer-size probe after Reflex requested a
/// bypass. All other calls still reach Wine's original SIGSYS handler.
pub(super) fn maybe_complete_bypass(gregs: *mut libc::greg_t) -> bool {
    if gregs.is_null() {
        return false;
    }
    let number = unsafe { gregs.add(libc::REG_RAX as usize).read() as u64 };
    // Wine reserves this service-table range for win32u. It also keeps
    // ntdll's much more frequent calls from triggering PE export discovery.
    if number & 0xf000 != 0x1000 {
        return false;
    }
    let Some(service) = window_list_service() else {
        return false;
    };
    complete_zero_capacity(gregs, service)
}

#[cfg(test)]
mod tests {
    use super::{STATUS_BUFFER_TOO_SMALL, complete_zero_capacity};

    #[test]
    fn completes_only_the_null_zero_capacity_probe() {
        let mut size = 0u32;
        let mut stack = [0u64; 9];
        stack[8] = (&mut size as *mut u32) as u64;
        let mut gregs = [0 as libc::greg_t; 32];
        gregs[libc::REG_RAX as usize] = 0x132d;
        gregs[libc::REG_RSP as usize] = stack.as_ptr() as libc::greg_t;
        gregs[libc::REG_RIP as usize] = 0x6802_2002;
        gregs[libc::REG_RCX as usize] = 0x6802_2002;
        gregs[libc::REG_R11 as usize] = 0x246;
        assert!(!complete_zero_capacity(gregs.as_mut_ptr(), 0x135a));
        assert!(complete_zero_capacity(gregs.as_mut_ptr(), 0x132d));
        assert_eq!(size, 1);
        assert_eq!(
            gregs[libc::REG_RAX as usize],
            STATUS_BUFFER_TOO_SMALL as i64
        );
        assert_eq!(gregs[libc::REG_RIP as usize], 0x6802_2002);
        assert_eq!(gregs[libc::REG_RCX as usize], 0x6802_2002);
        assert_eq!(gregs[libc::REG_R11 as usize], 0x246);

        gregs[libc::REG_RAX as usize] = 0x132d;
        stack[6] = 1;
        assert!(!complete_zero_capacity(gregs.as_mut_ptr(), 0x132d));
        stack[6] = 0;
        stack[7] = 0x1234;
        assert_eq!(stack[7], 0x1234);
        assert!(!complete_zero_capacity(gregs.as_mut_ptr(), 0x132d));
    }
}
