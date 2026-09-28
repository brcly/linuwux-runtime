//! Emulates Windows' `int 2e` syscall gate, which Linux has no equivalent
//! trap for. Called from `cpuid.rs`'s SIGSEGV handler (an `int 2e` fault
//! looks the same as a CPUID fault at the trap level) before it tries to
//! interpret the faulting instruction as CPUID. Unrelated to the KUSER
//! dispatcher bridge in `kuser_dispatch.rs`/`sigsys_router.rs`: this file
//! only makes Windows' *other* syscall entry point work, without touching
//! Reflex routing at all.
use core::arch::asm;
use core::ffi::{c_int, c_void};
use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};
use libc::ucontext_t;

const INT2E_INSTRUCTION: [u8; 2] = [0xcd, 0x2e];
const SYSCALL_INSTRUCTION: [u8; 2] = [0x0f, 0x05];
/// Distinct inline `int 2e` call sites this process can ever have a private
/// trampoline for. Once the table is full, `skip_int2e_fault` falls back to
/// patching the opcode in place at the game's own call site — observed in a
/// real TopSpin session (GE-Proton 11-7, several minutes of gameplay past the
/// original 1024 cap) to start firing after the table filled, mutating bytes
/// inside Denuvo-virtualized code that the game may hash or verify. Each slot
/// costs one MAP_32BIT page (4 KiB) only once its site is actually used, so a
/// generous capacity is cheap insurance against exhausting it mid-session.
const TRAMPOLINE_CAPACITY: usize = 16384;
const TRAMPOLINE_LENGTH: usize = 26;
static TRAMPOLINE_SITES: [AtomicU64; TRAMPOLINE_CAPACITY] =
    [const { AtomicU64::new(0) }; TRAMPOLINE_CAPACITY];
static TRAMPOLINE_TARGETS: [AtomicU64; TRAMPOLINE_CAPACITY] =
    [const { AtomicU64::new(0) }; TRAMPOLINE_CAPACITY];
/// Windows' syscall thunks are `test [SystemCall], 1; jne +3; syscall; ret;
/// int 2e; ret`: the `int 2e` sits directly after the direct path's
/// `syscall; ret`, which `jne +3` skips when `SystemCall` is set.
const DIRECT_SYSCALL_THUNK: [u8; 3] = [0x0f, 0x05, 0xc3];
/// EFLAGS bits defined by `TEST`: CF, SF and OF are cleared, ZF and PF are set
/// by the zero result of `test [SystemCall], 1` on the direct path.
const TEST_ZERO_CLEAR_FLAGS: u64 = 0x881;
const TEST_ZERO_SET_FLAGS: u64 = 0x44;
// Each int2e-handling strategy gets its own bounded log budget (rather than
// one shared counter) so a rare, important event — patch_to_syscall
// mutating the game's own code, the strategy most likely to trip
// anti-tamper — can't be drowned out of the log by the common, expected
// rewind case (fires on essentially every syscall in a hack-off session)
// exhausting a shared budget first. See docs/protocol/topspin-investigation.md
// for why this matters: correlating exactly how often each strategy fires
// is the next evidence needed there.
#[cfg(feature = "debug")]
static REWIND_LOGGED: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "debug")]
static PRIVATE_TRAMPOLINES_LOGGED: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "debug")]
static PATCHED_LOGGED: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "debug")]
static FALLBACK_SKIP_LOGGED: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "debug")]
unsafe extern "C" {
    fn debug_log_hex(prefix: *const core::ffi::c_char, value: u64);
}
#[cfg(all(feature = "debug", feature = "reflex"))]
unsafe extern "C" {
    fn debug_log(message: *const core::ffi::c_char);
}

/// Capture the same window-list request before it enters our private syscall
/// trampoline, so its arguments can be compared with the SIGSYS-side trace.
#[cfg(all(feature = "debug", feature = "reflex"))]
fn trace_window_list_entry(gregs: *const libc::greg_t) {
    static EVENTS: AtomicU64 = AtomicU64::new(0);
    let register = |index: libc::c_int| unsafe { gregs.add(index as usize).read() as u64 };
    if register(libc::REG_RAX) != 0x132d || EVENTS.fetch_add(1, Ordering::Relaxed) >= 16 {
        return;
    }
    let rsp = register(libc::REG_RSP);
    unsafe {
        debug_log(c"window list before INT 2E emulation".as_ptr());
        debug_log_hex(
            c"window list original RIP=".as_ptr(),
            register(libc::REG_RIP),
        );
        debug_log_hex(c"window list original RSP=".as_ptr(), rsp);
        debug_log_hex(
            c"window list original R10=".as_ptr(),
            register(libc::REG_R10),
        );
        debug_log_hex(
            c"window list original RDX=".as_ptr(),
            register(libc::REG_RDX),
        );
        debug_log_hex(c"window list original R8=".as_ptr(), register(libc::REG_R8));
        debug_log_hex(c"window list original R9=".as_ptr(), register(libc::REG_R9));
        if let Some(value) = super::mem::read_u64(rsp.saturating_add(0x38)) {
            debug_log_hex(c"window list original stack+0x38=".as_ptr(), value);
        }
        if let Some(value) = super::mem::read_u64(rsp.saturating_add(0x40)) {
            debug_log_hex(c"window list original stack+0x40=".as_ptr(), value);
        }
    }
}

fn read_memory(address: u64, output: &mut [u8]) -> bool {
    if address == 0 || output.is_empty() {
        return false;
    }
    let local = libc::iovec {
        iov_base: output.as_mut_ptr().cast(),
        iov_len: output.len(),
    };
    let remote = libc::iovec {
        iov_base: address as *mut c_void,
        iov_len: output.len(),
    };
    let result = unsafe {
        libc::syscall(
            libc::SYS_process_vm_readv,
            libc::syscall(libc::SYS_getpid),
            &local as *const libc::iovec,
            1 as libc::c_ulong,
            &remote as *const libc::iovec,
            1 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    result == output.len() as libc::c_long
}

fn next_instruction(rip: u64) -> Option<u64> {
    rip.checked_add(INT2E_INSTRUCTION.len() as u64)
}

/// Address of the direct-path `syscall` that immediately precedes an `int 2e`
/// in a Windows syscall thunk, if `rip` sits in one.
fn preceding_direct_syscall(rip: u64) -> Option<u64> {
    let start = rip.checked_sub(DIRECT_SYSCALL_THUNK.len() as u64)?;
    let mut bytes = [0u8; 3];
    (read_memory(start, &mut bytes) && bytes == DIRECT_SYSCALL_THUNK).then_some(start)
}

/// EFLAGS as the thunk's `test [SystemCall], 1` leaves them when `SystemCall`
/// is zero, which is the state the direct path would have been entered with.
fn direct_path_eflags(eflags: u64) -> u64 {
    (eflags & !TEST_ZERO_CLEAR_FLAGS) | TEST_ZERO_SET_FLAGS
}

/// Execute an inline `int 2e` through a private `syscall` without changing
/// the protected application's code. After Wine returns, restore the RCX
/// value a syscall at the original site would leave and jump to its successor.
fn private_syscall_trampoline(site: u64) -> Option<u64> {
    let next = next_instruction(site)?;
    let first = (site as usize >> 1) % TRAMPOLINE_CAPACITY;
    for offset in 0..TRAMPOLINE_CAPACITY {
        let index = (first + offset) % TRAMPOLINE_CAPACITY;
        loop {
            let stored_site = TRAMPOLINE_SITES[index].load(Ordering::Acquire);
            if stored_site == site {
                return build_or_reuse_private_trampoline(index, site, next);
            }
            if stored_site != 0 {
                break;
            }
            if TRAMPOLINE_SITES[index]
                .compare_exchange(0, site, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                // Another thread may have claimed this same site. Recheck
                // the slot rather than creating a duplicate in the next one.
                continue;
            }
            return build_or_reuse_private_trampoline(index, site, next);
        }
    }
    None
}

fn build_or_reuse_private_trampoline(index: usize, site: u64, next: u64) -> Option<u64> {
    let existing = TRAMPOLINE_TARGETS[index].load(Ordering::Acquire);
    if existing != 0 {
        return Some(existing);
    }
    // Another thread may be constructing this site, or may have been doing
    // so when the process forked. Build independently rather than waiting on
    // a constructor that might no longer exist in the child.
    let built = build_private_trampoline(site, next)?;
    match TRAMPOLINE_TARGETS[index].compare_exchange(0, built, Ordering::AcqRel, Ordering::Acquire)
    {
        Ok(_) => Some(built),
        Err(existing) => {
            unsafe {
                libc::syscall(
                    libc::SYS_munmap,
                    built as *mut c_void,
                    linuwux::kuser::PAGE_SIZE,
                )
            };
            Some(existing)
        }
    }
}

fn build_private_trampoline(site: u64, next: u64) -> Option<u64> {
    let page_size = linuwux::kuser::PAGE_SIZE;
    let page = site & !(page_size as u64 - 1);
    executable_mapping_protection(page, page_size as u64)?;
    let _errno = crate::errno::Errno::save();
    let memory = unsafe {
        libc::syscall(
            libc::SYS_mmap,
            ptr::null_mut::<c_void>(),
            page_size,
            libc::PROT_READ | libc::PROT_WRITE,
            // Wine must see this as guest code: a syscall from the host's
            // native-code range may bypass its SIGSYS dispatcher entirely.
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_32BIT,
            -1,
            0,
        )
    };
    if memory == -1 {
        return None;
    }
    let mut code = [0u8; TRAMPOLINE_LENGTH];
    code[..2].copy_from_slice(&SYSCALL_INSTRUCTION);
    code[2..4].copy_from_slice(&[0x48, 0xb9]); // movabs rcx, next
    code[4..12].copy_from_slice(&next.to_le_bytes());
    code[12..18].copy_from_slice(&[0xff, 0x25, 0, 0, 0, 0]); // jmp [rip]
    code[18..].copy_from_slice(&next.to_le_bytes());
    unsafe { ptr::copy_nonoverlapping(code.as_ptr(), memory as *mut u8, code.len()) };
    if unsafe {
        libc::syscall(
            libc::SYS_mprotect,
            memory as *mut c_void,
            page_size,
            libc::PROT_READ | libc::PROT_EXEC,
        )
    } != 0
    {
        unsafe { libc::syscall(libc::SYS_munmap, memory as *mut c_void, page_size) };
        return None;
    }
    Some(memory as u64)
}

/// Handle a faulting `int 2e`. Linux has no such gate, so run the thunk's own
/// direct path instead, exactly as it would run with `SystemCall` clear: resume
/// at the `syscall; ret` directly before the `int 2e`. This leaves the code
/// bytes untouched, so anything that hashes or compares them still sees the
/// original instructions. For inline `int 2e` sites, use a private executable
/// thunk with the same syscall ABI and return address. Only if the thunk
/// cannot be built do we patch the opcode in place, then as a last resort
/// advance past it to avoid repeatedly faulting on the unsupported vector.
///
/// # Safety
/// `context` must point to the live `ucontext_t` supplied to the SIGSEGV
/// handler, with writable general registers.
pub(crate) unsafe fn skip_int2e_fault(context: *mut ucontext_t) -> bool {
    if context.is_null() {
        return false;
    }
    let gregs = unsafe { ptr::addr_of_mut!((*context).uc_mcontext.gregs).cast::<libc::greg_t>() };
    let trap = unsafe { gregs.add(libc::REG_TRAPNO as usize).read() as u64 };
    if trap != 13 {
        return false;
    }
    let rip = unsafe { gregs.add(libc::REG_RIP as usize).read() as u64 };
    let mut instruction = [0u8; 2];
    if !read_memory(rip, &mut instruction) || instruction != INT2E_INSTRUCTION {
        return false;
    }

    #[cfg(all(feature = "debug", feature = "reflex"))]
    trace_window_list_entry(gregs);

    if let Some(syscall_rip) = preceding_direct_syscall(rip) {
        unsafe {
            let eflags = gregs.add(libc::REG_EFL as usize);
            eflags.write(direct_path_eflags(eflags.read() as u64) as libc::greg_t);
            gregs
                .add(libc::REG_RIP as usize)
                .write(syscall_rip as libc::greg_t);
        }
        #[cfg(feature = "debug")]
        log_bounded(
            &REWIND_LOGGED,
            8,
            c"Wine INT 2E rewound to direct syscall RIP=".as_ptr(),
            rip,
        );
        return true;
    }

    if let Some(thunk) = private_syscall_trampoline(rip) {
        unsafe {
            gregs
                .add(libc::REG_RIP as usize)
                .write(thunk as libc::greg_t)
        };
        #[cfg(feature = "debug")]
        log_bounded(
            &PRIVATE_TRAMPOLINES_LOGGED,
            8,
            c"Wine INT 2E private syscall thunk for RIP=".as_ptr(),
            rip,
        );
        return true;
    }

    if patch_to_syscall(rip) {
        #[cfg(feature = "debug")]
        log_bounded(
            &PATCHED_LOGGED,
            64,
            c"Wine INT 2E patched to syscall RIP=".as_ptr(),
            rip,
        );
        return true;
    }

    let Some(next_rip) = next_instruction(rip) else {
        return false;
    };
    unsafe {
        gregs
            .add(libc::REG_RIP as usize)
            .write(next_rip as libc::greg_t)
    };
    #[cfg(feature = "debug")]
    log_bounded(
        &FALLBACK_SKIP_LOGGED,
        8,
        c"Wine INT 2E patch unavailable; advanced RIP=".as_ptr(),
        next_rip,
    );
    true
}

/// Log at most `cap` occurrences of one int2e-handling strategy, so a
/// frequent, expected one never drowns out a rare, important one sharing
/// the same debug log — see the per-strategy counters above.
#[cfg(feature = "debug")]
fn log_bounded(counter: &AtomicU64, cap: u64, prefix: *const core::ffi::c_char, value: u64) {
    if counter.fetch_add(1, Ordering::Relaxed) < cap {
        unsafe { debug_log_hex(prefix, value) };
    }
}

fn patch_to_syscall(address: u64) -> bool {
    let mut original = [0u8; 2];
    if !read_memory(address, &mut original) || original != INT2E_INSTRUCTION {
        return false;
    }
    let page_size = linuwux::kuser::PAGE_SIZE as u64;
    let page = address & !(page_size - 1);
    let Some(second_byte) = address.checked_add(1) else {
        return false;
    };
    if second_byte >= page.saturating_add(page_size) {
        return false;
    }
    let Some(original_protection) = executable_mapping_protection(page, page_size) else {
        return false;
    };
    let Some(_guard) = crate::page_guard::PageGuard::acquire() else {
        return false;
    };
    let _errno = crate::errno::Errno::save();
    if unsafe {
        libc::syscall(
            libc::SYS_mprotect,
            page as *mut c_void,
            page_size as libc::size_t,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        )
    } != 0
    {
        return false;
    }

    let expected = u16::from_le_bytes(INT2E_INSTRUCTION);
    let replacement = u16::from_le_bytes(SYSCALL_INSTRUCTION);
    // A single locked compare-exchange prevents another thread from executing
    // a half-written instruction, and avoids overwriting a concurrent change.
    // SAFETY: /proc/self/maps confirmed an executable mapping and mprotect
    // enabled writes. The two-byte instruction is wholly within this page.
    let patched = unsafe {
        let mut observed = expected;
        asm!(
            "lock cmpxchg word ptr [{address}], {replacement:x}",
            address = in(reg) address,
            replacement = in(reg) replacement,
            inout("ax") observed,
            options(nostack),
        );
        observed == expected
    };

    let restored = unsafe {
        libc::syscall(
            libc::SYS_mprotect,
            page as *mut c_void,
            page_size as libc::size_t,
            original_protection,
        )
    } == 0;
    if !restored || !patched {
        return false;
    }

    let mut observed = [0u8; 2];
    read_memory(address, &mut observed) && observed == SYSCALL_INSTRUCTION
}

fn executable_mapping_protection(page: u64, page_size: u64) -> Option<c_int> {
    // Use raw syscalls here because this lookup runs inside SIGSEGV handling;
    // going through the exported `read` interposer could trigger lazy dlsym.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat,
            libc::AT_FDCWD,
            c"/proc/self/maps".as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
            0,
        ) as c_int
    };
    if fd < 0 {
        return None;
    }
    let mut chunk = [0u8; 1024];
    let mut line = [0u8; 512];
    let mut length = 0usize;
    let mut overflow = false;
    let mut protection = None;
    'read: loop {
        let count =
            unsafe { libc::syscall(libc::SYS_read, fd, chunk.as_mut_ptr(), chunk.len()) as isize };
        if count <= 0 {
            break;
        }
        for &byte in &chunk[..count as usize] {
            if byte == b'\n' {
                if !overflow
                    && let Some(found) = executable_mapping_line(&line[..length], page, page_size)
                {
                    protection = Some(found);
                    break 'read;
                }
                length = 0;
                overflow = false;
            } else if length < line.len() {
                line[length] = byte;
                length += 1;
            } else {
                overflow = true;
            }
        }
    }
    if protection.is_none()
        && !overflow
        && let Some(found) = executable_mapping_line(&line[..length], page, page_size)
    {
        protection = Some(found);
    }
    unsafe { libc::syscall(libc::SYS_close, fd) };
    protection
}

fn executable_mapping_line(line: &[u8], page: u64, page_size: u64) -> Option<c_int> {
    let mut fields = line
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|field| !field.is_empty());
    let mut bounds = fields.next()?.split(|&byte| byte == b'-');
    let start = parse_hex(bounds.next()?)?;
    let end = parse_hex(bounds.next()?)?;
    let permissions = fields.next()?;
    if start > page
        || end < page.checked_add(page_size)?
        || permissions.len() != 4
        || permissions[0] != b'r'
        || permissions[2] != b'x'
    {
        return None;
    }
    Some(libc::PROT_READ | libc::PROT_EXEC)
}

fn parse_hex(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    bytes.iter().try_fold(0u64, |result, &byte| {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return None,
        };
        result.checked_mul(16)?.checked_add(u64::from(digit))
    })
}

#[cfg(test)]
mod tests {
    use super::{
        DIRECT_SYSCALL_THUNK, INT2E_INSTRUCTION, SYSCALL_INSTRUCTION, direct_path_eflags,
        executable_mapping_protection, next_instruction, patch_to_syscall, skip_int2e_fault,
    };
    use core::mem::MaybeUninit;
    use libc::ucontext_t;
    use std::sync::Mutex;

    const PAGE_SIZE: usize = 0x1000;
    static PATCH_TEST_LOCK: Mutex<()> = Mutex::new(());

    struct CodePage(*mut u8);

    impl CodePage {
        fn new(offset: usize, executable: bool) -> Self {
            let page = unsafe {
                libc::mmap(
                    core::ptr::null_mut(),
                    PAGE_SIZE,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            assert_ne!(page, libc::MAP_FAILED);
            let page = page.cast::<u8>();
            unsafe {
                core::ptr::write_bytes(page, 0x90, PAGE_SIZE);
                core::ptr::copy_nonoverlapping(INT2E_INSTRUCTION.as_ptr(), page.add(offset), 2);
            }
            if executable {
                let result = unsafe {
                    libc::mprotect(page.cast(), PAGE_SIZE, libc::PROT_READ | libc::PROT_EXEC)
                };
                assert_eq!(result, 0);
            }
            Self(page)
        }

        fn address(&self, offset: usize) -> u64 {
            unsafe { self.0.add(offset) as u64 }
        }

        fn bytes(&self, offset: usize) -> [u8; 2] {
            let mut bytes = [0; 2];
            assert!(super::read_memory(self.address(offset), &mut bytes));
            bytes
        }
    }

    impl Drop for CodePage {
        fn drop(&mut self) {
            unsafe { libc::munmap(self.0.cast(), PAGE_SIZE) };
        }
    }

    fn context_at(rip: u64, trap: u64) -> Box<ucontext_t> {
        let mut context = Box::new(unsafe { MaybeUninit::<ucontext_t>::zeroed().assume_init() });
        unsafe {
            let gregs = core::ptr::addr_of_mut!(context.uc_mcontext.gregs).cast::<libc::greg_t>();
            gregs.add(libc::REG_RIP as usize).write(rip as libc::greg_t);
            gregs
                .add(libc::REG_TRAPNO as usize)
                .write(trap as libc::greg_t);
        }
        context
    }

    #[test]
    fn patches_int2e_at_even_and_odd_addresses_and_restores_rx() {
        let _serial = PATCH_TEST_LOCK.lock().unwrap();
        for offset in [0x10, 0x11] {
            let page = CodePage::new(offset, true);
            assert!(patch_to_syscall(page.address(offset)));
            assert_eq!(page.bytes(offset), SYSCALL_INSTRUCTION);
            assert_eq!(
                executable_mapping_protection(
                    page.address(offset) & !((PAGE_SIZE as u64) - 1),
                    PAGE_SIZE as u64,
                ),
                Some(libc::PROT_READ | libc::PROT_EXEC)
            );
            assert!(!patch_to_syscall(page.address(offset)));
        }
    }

    #[test]
    fn inline_int2e_uses_private_thunk_without_changing_game_code() {
        let _serial = PATCH_TEST_LOCK.lock().unwrap();
        let page = CodePage::new(0x10, true);
        let rip = page.address(0x10);
        let mut context = context_at(rip, 13);

        assert!(unsafe { skip_int2e_fault(&mut *context) });
        let thunk = context.uc_mcontext.gregs[libc::REG_RIP as usize] as u64;
        assert_ne!(thunk, rip);
        assert!(thunk < 0x8000_0000);
        assert_eq!(page.bytes(0x10), INT2E_INSTRUCTION);
        let mut bytes = [0u8; super::TRAMPOLINE_LENGTH];
        assert!(super::read_memory(thunk, &mut bytes));
        assert_eq!(&bytes[..2], &SYSCALL_INSTRUCTION);
        assert_eq!(
            u64::from_le_bytes(bytes[4..12].try_into().unwrap()),
            rip + 2
        );
        assert_eq!(u64::from_le_bytes(bytes[18..].try_into().unwrap()), rip + 2);
        let mut repeat = context_at(rip, 13);
        assert!(unsafe { skip_int2e_fault(&mut *repeat) });
        assert_eq!(
            repeat.uc_mcontext.gregs[libc::REG_RIP as usize] as u64,
            thunk
        );
    }

    #[test]
    fn private_thunk_executes_syscall_and_restores_guest_rcx() {
        let _serial = PATCH_TEST_LOCK.lock().unwrap();
        let page = CodePage::new(0x10, false);
        let rip = page.address(0x10);
        unsafe { page.0.add(0x12).write(0xc3) }; // guest successor returns
        assert_eq!(
            unsafe { libc::mprotect(page.0.cast(), PAGE_SIZE, libc::PROT_READ | libc::PROT_EXEC,) },
            0
        );
        let thunk = super::private_syscall_trampoline(rip).unwrap();
        let mut result = libc::SYS_getpid as u64;
        let guest_rcx: u64;
        unsafe {
            core::arch::asm!(
                "call {entry}",
                entry = in(reg) thunk,
                inlateout("rax") result,
                lateout("rcx") guest_rcx,
                lateout("r11") _,
                clobber_abi("C"),
            );
        }
        assert_eq!(result, unsafe { libc::getpid() as u64 });
        assert_eq!(guest_rcx, rip + 2);
        assert_eq!(page.bytes(0x10), INT2E_INSTRUCTION);
    }

    #[test]
    fn fault_handler_runs_the_thunks_direct_path_without_modifying_code() {
        let _serial = PATCH_TEST_LOCK.lock().unwrap();
        let page = CodePage::new(0x13, true);
        // Rebuild the Windows thunk tail: `syscall; ret` directly before the
        // `int 2e`, reachable only through the `jne +3` skip.
        unsafe {
            let code = page.0.add(0x10);
            libc::mprotect(page.0.cast(), PAGE_SIZE, libc::PROT_READ | libc::PROT_WRITE);
            core::ptr::copy_nonoverlapping(DIRECT_SYSCALL_THUNK.as_ptr(), code, 3);
            libc::mprotect(page.0.cast(), PAGE_SIZE, libc::PROT_READ | libc::PROT_EXEC);
        }
        let rip = page.address(0x13);
        let mut context = context_at(rip, 13);
        context.uc_mcontext.gregs[libc::REG_EFL as usize] = 0x8c1;

        assert!(unsafe { skip_int2e_fault(&mut *context) });
        assert_eq!(
            context.uc_mcontext.gregs[libc::REG_RIP as usize] as u64,
            page.address(0x10)
        );
        assert_eq!(context.uc_mcontext.gregs[libc::REG_EFL as usize], 0x44);
        assert_eq!(page.bytes(0x13), INT2E_INSTRUCTION);
        assert_eq!(page.bytes(0x10), SYSCALL_INSTRUCTION);
    }

    #[test]
    fn direct_path_flags_match_test_of_zero() {
        // TEST clears CF/SF/OF, sets ZF/PF, and leaves the rest alone.
        assert_eq!(direct_path_eflags(0x8c1), 0x44);
        assert_eq!(direct_path_eflags(0x202), 0x246);
        assert_eq!(direct_path_eflags(0x246), 0x246);
    }

    #[test]
    fn fault_handler_advances_when_instruction_is_not_patchable() {
        let page = CodePage::new(0x10, false);
        let rip = page.address(0x10);
        let mut context = context_at(rip, 13);

        assert!(unsafe { skip_int2e_fault(&mut *context) });
        assert_eq!(
            context.uc_mcontext.gregs[libc::REG_RIP as usize] as u64,
            rip + 2
        );
        assert_eq!(page.bytes(0x10), INT2E_INSTRUCTION);
    }

    #[test]
    fn fault_handler_ignores_other_faults_and_instructions() {
        let page = CodePage::new(0x10, true);
        let rip = page.address(0x10);
        let mut wrong_trap = context_at(rip, 6);
        assert!(!unsafe { skip_int2e_fault(&mut *wrong_trap) });
        assert_eq!(
            wrong_trap.uc_mcontext.gregs[libc::REG_RIP as usize] as u64,
            rip
        );

        let mut wrong_instruction = context_at(rip + 2, 13);
        assert!(!unsafe { skip_int2e_fault(&mut *wrong_instruction) });
        assert_eq!(
            wrong_instruction.uc_mcontext.gregs[libc::REG_RIP as usize] as u64,
            rip + 2
        );
        assert_eq!(page.bytes(0x10), INT2E_INSTRUCTION);
    }

    #[test]
    fn instruction_advance_is_checked() {
        assert_eq!(next_instruction(0x1000), Some(0x1002));
        assert_eq!(next_instruction(u64::MAX - 1), None);
    }
}
