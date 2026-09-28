//! Installs LinUwUx's own handler in Wine's KUSER dispatcher slot and
//! classifies every call that arrives through it.
//!
//! This boundary answers exactly one question per call: is this evidenced as
//! Reflex's own copied syscall stub (found by scanning the main PE image's
//! IAT for Reflex's trampolines), or is it an ordinary call on Wine's own
//! dispatcher? It does not decide anything about Reflex protocol semantics
//! (selectors, registration, routing) — that happens afterward, at the
//! SIGSYS boundary in [`super::sigsys_router`], once the classified call has
//! either been left on Wine's dispatcher or replayed as a raw syscall.
//!
//! See `docs/protocol/syscall-routing.md` for how this fits into the overall
//! design, and [`should_replay_raw`] for the actual classification rule.

use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::mem::{read_u32, read_u64, trampoline_destination};

const WINE_DISPATCHER_SLOT: u64 = 0x7ffe_1000;
const THUNK_RETURN_OFFSET: u64 = 0x1f;
const IAT_CAPACITY: usize = 4096;
const RAW_TARGET_TAG: u64 = 1 << 63;
const SYSCALL_INSTRUCTION: [u8; 2] = [0x0f, 0x05];
const PEB_IMAGE_BASE_OFFSET: u64 = 0x10;
const TEB_PEB_OFFSET: u64 = 0x60;
const IAT_SCAN_RETRY_INTERVAL: u64 = 2;

static ORIGINAL_DISPATCHER: AtomicU64 = AtomicU64::new(0);
static BRIDGE_INSTALLED: AtomicBool = AtomicBool::new(false);
static BRIDGE_INSTALL_SUCCESS_LOGGED: AtomicBool = AtomicBool::new(false);
static BRIDGE_INSTALL_FAILURE_LOGGED: AtomicBool = AtomicBool::new(false);
static REFLEX_IMAGE_START: AtomicU64 = AtomicU64::new(0);
static REFLEX_IMAGE_END: AtomicU64 = AtomicU64::new(0);
static IAT_STUB_COUNT: AtomicU64 = AtomicU64::new(0);
static IAT_SCAN_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static IAT_SCAN_SUCCESS_LOGGED: AtomicBool = AtomicBool::new(false);
static IAT_SCAN_MISS_LOGGED: AtomicBool = AtomicBool::new(false);
static IAT_SCAN_LOCK: AtomicBool = AtomicBool::new(false);
static IAT_STUBS: [AtomicU64; IAT_CAPACITY] = [const { AtomicU64::new(0) }; IAT_CAPACITY];

unsafe extern "C" {
    fn debug_log(message: *const core::ffi::c_char);
    fn debug_log_hex(prefix: *const core::ffi::c_char, value: u64);
    fn debug_log_dec(prefix: *const core::ffi::c_char, value: u64);
}

fn log(message: &'static core::ffi::CStr) {
    unsafe { debug_log(message.as_ptr()) };
}

fn log_hex(prefix: &'static core::ffi::CStr, value: u64) {
    unsafe { debug_log_hex(prefix.as_ptr(), value) };
}

fn log_dec(prefix: &'static core::ffi::CStr, value: u64) {
    unsafe { debug_log_dec(prefix.as_ptr(), value) };
}

fn log_install_failure() {
    if !BRIDGE_INSTALL_FAILURE_LOGGED.swap(true, Ordering::AcqRel) {
        log(c"reflex bridge install failed; will retry at KUSER handshake");
    }
}

#[cfg(feature = "cpuid")]
pub(super) fn register_reflex_dispatch_handler(handler: u64) {
    register_reflex_image(handler);
}

/// Locate the loaded PE image containing `handler` (Reflex's registered
/// resume/dispatch target) by walking backward from its page in
/// `0x1000`-sized steps looking for a `MZ`/`PE` header whose `SizeOfImage`
/// covers it. Reflex's own image range, once known, lets
/// [`should_replay_raw`]'s caller-evidence check exclude Reflex's *internal*
/// calls (which are never syscall stubs) from the replay path.
#[cfg(feature = "cpuid")]
fn register_reflex_image(handler: u64) {
    if handler == 0 || REFLEX_IMAGE_START.load(Ordering::Acquire) != 0 {
        return;
    }
    let first_page = handler & !0xfff;
    for offset in (0..=0x10_0000).step_by(0x1000) {
        let Some(base) = first_page.checked_sub(offset) else {
            break;
        };
        let mut dos = [0u8; 0x40];
        if !super::mem::read_memory(base, &mut dos) || dos[..2] != *b"MZ" {
            continue;
        }
        let pe_offset = u32::from_le_bytes(dos[0x3c..0x40].try_into().unwrap()) as u64;
        if pe_offset > 0x1000 {
            continue;
        }
        let mut headers = [0u8; 0x60];
        if !super::mem::read_memory(base + pe_offset, &mut headers) || headers[..4] != *b"PE\0\0" {
            continue;
        }
        let image_size = u32::from_le_bytes(headers[80..84].try_into().unwrap()) as u64;
        let Some(end) = base.checked_add(image_size) else {
            continue;
        };
        if image_size != 0 && (base..end).contains(&handler) {
            REFLEX_IMAGE_END.store(end, Ordering::Relaxed);
            REFLEX_IMAGE_START.store(base, Ordering::Release);
            return;
        }
    }
}

fn is_reflex_address(address: u64) -> bool {
    let start = REFLEX_IMAGE_START.load(Ordering::Acquire);
    let end = REFLEX_IMAGE_END.load(Ordering::Acquire);
    start != 0 && (start..end).contains(&address)
}

fn remember_stub(address: u64) -> bool {
    if address == 0 {
        return false;
    }
    let count = IAT_STUB_COUNT
        .load(Ordering::Acquire)
        .min(IAT_CAPACITY as u64) as usize;
    if IAT_STUBS[..count]
        .iter()
        .any(|entry| entry.load(Ordering::Relaxed) == address)
    {
        return false;
    }
    let index = IAT_STUB_COUNT.fetch_add(1, Ordering::AcqRel) as usize;
    if index < IAT_CAPACITY {
        IAT_STUBS[index].store(address, Ordering::Release);
        return true;
    }
    false
}

/// Scan the current process's mapped main-image IAT for Reflex-style
/// trampolines. This uses PE import descriptors to bound the scan, so syscall
/// routing does not depend on observing Reflex's individual protection calls.
/// The scan is retried until Reflex has populated the IAT.
fn scan_main_image_iat() -> usize {
    if IAT_SCAN_LOCK
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return 0;
    }
    let found = scan_main_image_iat_locked();
    IAT_SCAN_LOCK.store(false, Ordering::Release);
    if found == 0 && !IAT_SCAN_MISS_LOGGED.swap(true, Ordering::AcqRel) {
        log(c"main PE IAT scan found no Reflex trampolines yet");
    }
    found
}

fn scan_main_image_iat_locked() -> usize {
    let mut gs_base = 0u64;
    // Wine's x86-64 TEB is the thread GS base; TEB+0x60 points to the PEB.
    // Use arch_prctl rather than reading a compiler/platform-specific GS
    // intrinsic from this shared library.
    let got_gs = unsafe {
        libc::syscall(
            libc::SYS_arch_prctl,
            0x1004, // ARCH_GET_GS
            &mut gs_base as *mut u64,
        )
    } == 0;
    if !got_gs || gs_base == 0 {
        return 0;
    }
    let Some(peb) = read_u64(gs_base.saturating_add(TEB_PEB_OFFSET)) else {
        return 0;
    };
    let Some(image_base) = read_u64(peb.saturating_add(PEB_IMAGE_BASE_OFFSET)) else {
        return 0;
    };
    if image_base == 0 {
        return 0;
    }

    let Some(mz) = read_u32(image_base) else {
        return 0;
    };
    if mz as u16 != 0x5a4d {
        return 0;
    }
    let Some(pe_offset) = read_u32(image_base.saturating_add(0x3c)) else {
        return 0;
    };
    if pe_offset > 0x1000 {
        return 0;
    }
    let Some(pe_signature) = read_u32(image_base.saturating_add(pe_offset as u64)) else {
        return 0;
    };
    if pe_signature != u32::from_le_bytes(*b"PE\0\0") {
        return 0;
    }

    let optional = image_base
        .saturating_add(pe_offset as u64)
        .saturating_add(24);
    let Some(magic) = read_u32(optional) else {
        return 0;
    };
    if magic as u16 != 0x20b {
        return 0;
    }
    let Some(image_size) = read_u32(optional.saturating_add(56)) else {
        return 0;
    };
    let Some(import_rva) = read_u32(optional.saturating_add(120)) else {
        return 0;
    };
    if image_size == 0 || import_rva == 0 || import_rva >= image_size {
        return 0;
    }

    let mut found = 0usize;
    let max_descriptors = ((image_size - import_rva) / 20).min(4096);
    for index in 0..max_descriptors {
        let descriptor = image_base
            .saturating_add(import_rva as u64)
            .saturating_add(u64::from(index) * 20);
        let Some(name_rva) = read_u32(descriptor.saturating_add(12)) else {
            break;
        };
        if name_rva == 0 {
            break;
        }
        let Some(iat_rva) = read_u32(descriptor.saturating_add(16)) else {
            break;
        };
        let Some(original_thunk_rva) = read_u32(descriptor) else {
            break;
        };
        if iat_rva == 0 || iat_rva >= image_size {
            continue;
        }

        // Count imports through the original lookup table, as Reflex does.
        // This avoids scanning gaps between unrelated IAT runs in a merged
        // range; if OriginalFirstThunk is absent, the IAT retains its zero
        // terminator after Reflex replaces its non-null entries.
        let lookup_rva = if original_thunk_rva == 0 {
            iat_rva
        } else {
            original_thunk_rva
        };
        if lookup_rva >= image_size {
            continue;
        }
        let max_thunks = (image_size.saturating_sub(lookup_rva) / 8).min(65_536);
        for thunk in 0..max_thunks {
            let lookup = image_base
                .saturating_add(lookup_rva as u64)
                .saturating_add(u64::from(thunk) * 8);
            let Some(import_value) = read_u64(lookup) else {
                break;
            };
            if import_value == 0 {
                break;
            }
            let slot = image_base
                .saturating_add(iat_rva as u64)
                .saturating_add(u64::from(thunk) * 8);
            let Some(value) = read_u64(slot) else {
                break;
            };
            if value == 0 {
                break;
            }
            if let Some(destination) = trampoline_destination(value)
                && remember_stub(destination)
            {
                found += 1;
            }
        }
    }
    if found != 0 && !IAT_SCAN_SUCCESS_LOGGED.swap(true, Ordering::AcqRel) {
        log(c"reflex IAT trampolines discovered from main PE import table");
        log_hex(c"reflex main image base=", image_base);
        log_dec(
            c"reflex IAT trampoline targets discovered=",
            IAT_STUB_COUNT.load(Ordering::Acquire),
        );
    }
    found
}

pub(super) fn maybe_scan_main_image_iat() {
    if IAT_STUB_COUNT.load(Ordering::Acquire) != 0
        || REFLEX_IMAGE_START.load(Ordering::Acquire) == 0
    {
        return;
    }
    let attempt = IAT_SCAN_ATTEMPTS.fetch_add(1, Ordering::AcqRel);
    if attempt == 0 || attempt.is_multiple_of(IAT_SCAN_RETRY_INTERVAL) {
        let _ = scan_main_image_iat();
    }
}

fn matches_iat_stub(return_address: u64) -> bool {
    let count = IAT_STUB_COUNT
        .load(Ordering::Acquire)
        .min(IAT_CAPACITY as u64) as usize;
    IAT_STUBS[..count]
        .iter()
        .any(|entry| return_matches_stub(return_address, entry.load(Ordering::Acquire)))
}

fn return_matches_stub(return_address: u64, stub: u64) -> bool {
    return_address.checked_sub(THUNK_RETURN_OFFSET) == Some(stub)
}

fn find_raw_syscall_instruction(code: &[u8], code_address: u64, service: u64) -> Option<u64> {
    for syscall_offset in (2..=code.len()).rev() {
        if code[syscall_offset - 2..syscall_offset] != SYSCALL_INSTRUCTION {
            continue;
        }
        if syscall_service_before(code, syscall_offset) == Some(service) {
            return code_address.checked_add((syscall_offset - 2) as u64);
        }
    }
    None
}

fn syscall_service_before(code: &[u8], syscall_offset: usize) -> Option<u64> {
    let start = syscall_offset.saturating_sub(26);
    (start..syscall_offset.saturating_sub(8))
        .rev()
        .find(|&offset| code[offset..offset + 3] == [0x4c, 0x8b, 0xd1] && code[offset + 3] == 0xb8)
        .map(|offset| u32::from_le_bytes(code[offset + 4..offset + 8].try_into().unwrap()) as u64)
}

fn find_syscall(return_address: u64, service: u64) -> Option<u64> {
    for window in [0x80usize, 0x40, 0x20] {
        let Some(start) = return_address.checked_sub(window as u64) else {
            continue;
        };
        let mut bytes = [0u8; 0x80];
        if !super::mem::read_memory(start, &mut bytes[..window]) {
            continue;
        }
        if let Some(address) = find_raw_syscall_instruction(&bytes[..window], start, service) {
            return Some(address);
        }
    }
    None
}

/// The evidence `dispatcher_target` gathers for one KUSER dispatcher call,
/// in the order it becomes available (cheapest first, so the expensive
/// `find_syscall` memory scan is only attempted once the cheaper checks
/// already passed).
#[derive(Clone, Copy)]
struct DispatchEvidence {
    /// Wine's own dispatcher has been observed (the bridge is fully armed).
    original_dispatcher_known: bool,
    /// The return address matches a stub the IAT scan found Reflex hooking.
    stub_match: bool,
    /// The caller is inside Reflex's own image, not a copied stub calling in
    /// from outside it.
    caller_is_reflex_image: bool,
    /// A raw `syscall` instruction for this service was found near the
    /// return address.
    raw_syscall_found: bool,
}

/// The actual routing rule: replay this call as a raw syscall only when it
/// is evidenced as Reflex's own copied stub — matched by the IAT scan,
/// called from outside Reflex's own image, with a raw syscall instruction to
/// replay. Anything else stays on Wine's original dispatcher. This is the
/// one piece of `dispatcher_target`'s classification with no pointers or
/// I/O, so it is what `docs/protocol/syscall-routing.md` invariant 2 (route
/// from runtime evidence, not fixed addresses) and the tests below can pin
/// down directly.
fn should_replay_raw(evidence: DispatchEvidence) -> bool {
    evidence.original_dispatcher_known
        && evidence.stub_match
        && !evidence.caller_is_reflex_image
        && evidence.raw_syscall_found
}

/// The KUSER dispatcher bridge's Rust selector, called from
/// [`dispatcher_bridge`]'s naked-asm trampoline on Wine's own stack. Returns
/// the target to jump to: either the original Wine dispatcher, or a raw
/// syscall address tagged in bit 63 (cleared and consumed by the trampoline
/// itself before it jumps there — see the frame-layout comment on
/// `dispatcher_bridge`).
unsafe extern "C" fn dispatcher_target(
    return_address: u64,
    service: u64,
    r10: u64,
    _process_handle: u64,
    _xmm5: u64,
    entry_rsp: u64,
) -> u64 {
    let _ = r10;
    let original = ORIGINAL_DISPATCHER.load(Ordering::Acquire);
    maybe_scan_main_image_iat();
    super::unixlib_repair::maybe_repair_wine_unixlib_exports();
    let tid = unsafe { libc::syscall(libc::SYS_gettid) as u64 };
    let trap_rsp = entry_rsp.saturating_add(8);
    super::reflex_markers::retire_markers(tid, trap_rsp);

    let stub_match = matches_iat_stub(return_address);
    if original == 0 || !stub_match {
        return original;
    }
    let caller = read_u64(entry_rsp.saturating_add(8)).unwrap_or(0);
    let caller_is_reflex_image = is_reflex_address(caller);
    if caller_is_reflex_image {
        return original;
    }
    let raw = find_syscall(return_address, service);
    if !should_replay_raw(DispatchEvidence {
        original_dispatcher_known: true,
        stub_match: true,
        caller_is_reflex_image,
        raw_syscall_found: raw.is_some(),
    }) {
        return original;
    }
    let raw = raw.expect("raw_syscall_found was checked above");
    let trap_rip = raw.saturating_add(2);
    if !super::reflex_markers::remember_marker(tid, trap_rsp, trap_rip) {
        return original;
    }
    raw | RAW_TARGET_TAG
}

/// Private stacks for the bridge's Rust selector, one slot per Windows thread
/// id (`TEB.ClientId.UniqueThread`, a multiple of four). The first word of a
/// slot is a spin lock, so two threads that share a slot only serialize. The
/// array lives in `.bss`, so only the pages a thread actually uses are ever
/// committed.
const BRIDGE_STACK_SLOTS: usize = 1024;
const BRIDGE_STACK_SHIFT: usize = 15;

#[repr(C, align(4096))]
struct BridgeStacks([u8; BRIDGE_STACK_SLOTS << BRIDGE_STACK_SHIFT]);

static mut BRIDGE_STACKS: BridgeStacks =
    BridgeStacks([0; BRIDGE_STACK_SLOTS << BRIDGE_STACK_SHIFT]);

/// Wine's KUSER dispatcher slot trampoline. Saves every register a Windows
/// syscall stub's caller could observe, runs [`dispatcher_target`] on a
/// private per-thread stack (see the field comment on `BRIDGE_STACKS`), and
/// restores everything before jumping to the chosen target. Reviewed as its
/// own pass in Stage 6 of the syscall redesign plan; see
/// `docs/protocol/syscall-routing.md` invariant 4 for the ABI parity this
/// must hold on the direct-replay path.
#[cfg(feature = "kuser")]
#[unsafe(naked)]
unsafe extern "C" fn dispatcher_bridge() {
    core::arch::naked_asm!(
        "lea rsp, [rsp - 0x108]",
        "movdqu [rsp + 0x00], xmm0", "movdqu [rsp + 0x10], xmm1", "movdqu [rsp + 0x20], xmm2", "movdqu [rsp + 0x30], xmm3",
        "movdqu [rsp + 0x40], xmm4", "movdqu [rsp + 0x50], xmm5", "movdqu [rsp + 0x60], xmm6", "movdqu [rsp + 0x70], xmm7",
        "movdqu [rsp + 0x80], xmm8", "movdqu [rsp + 0x90], xmm9", "movdqu [rsp + 0xa0], xmm10", "movdqu [rsp + 0xb0], xmm11",
        "movdqu [rsp + 0xc0], xmm12", "movdqu [rsp + 0xd0], xmm13", "movdqu [rsp + 0xe0], xmm14", "movdqu [rsp + 0xf0], xmm15",
        "pushfq", "push rax", "push rbx", "push rcx", "push rdx", "push rsi", "push rdi", "push rbp", "push r8", "push r9", "push r10", "push r11", "push r12", "push r13", "push r14", "push r15",
        "mov rbx, rsp",
        "mov rdi, [rbx + 0x188]", "lea r9, [rbx + 0x188]", "mov rsi, [rbx + 0x70]", "mov rdx, [rbx + 0x28]", "mov rcx, [rbx + 0x60]", "mov r8, [rbx + 0xd0]",
        // Run the Rust selector on a private per-thread stack. Everything
        // above this point is spilled to the Windows stack inside a fixed
        // 0x190-byte frame, like the Reflex handler itself; the selector's
        // much deeper call frames must not scribble further below the caller's
        // stack pointer, which Denuvo's VM reads back as scratch. A syscall
        // never touches user stack on Windows. All registers are already saved
        // in the frame, so RAX and R15 are free (R15 is callee-saved and holds
        // the stack slot across the call).
        "lea r15, [rip + {stacks}]",
        "mov rax, gs:[0x48]",
        "shr rax, 2",
        "and eax, {slot_mask}",
        "shl rax, {slot_shift}",
        "add r15, rax",
        "3:",
        "lock bts dword ptr [r15], 0",
        "jnc 4f",
        "pause",
        "jmp 3b",
        "4:",
        "lea rsp, [r15 + {slot_size}]",
        "call {target}",
        "mov dword ptr [r15], 0",
        "mov rsp, rbx", "mov [rsp + 0x180], rax",
        "mov r15, [rsp + 0x00]", "mov r14, [rsp + 0x08]", "mov r13, [rsp + 0x10]", "mov r12, [rsp + 0x18]", "mov r11, [rsp + 0x20]", "mov r10, [rsp + 0x28]", "mov r9, [rsp + 0x30]", "mov r8, [rsp + 0x38]", "mov rbp, [rsp + 0x40]", "mov rdi, [rsp + 0x48]", "mov rsi, [rsp + 0x50]", "mov rdx, [rsp + 0x58]", "mov rcx, [rsp + 0x60]", "mov rbx, [rsp + 0x68]", "mov rax, [rsp + 0x70]",
        "push qword ptr [rsp + 0x78]", "popfq",
        "movdqu xmm0, [rsp + 0x80]", "movdqu xmm1, [rsp + 0x90]", "movdqu xmm2, [rsp + 0xa0]", "movdqu xmm3, [rsp + 0xb0]", "movdqu xmm4, [rsp + 0xc0]", "movdqu xmm5, [rsp + 0xd0]", "movdqu xmm6, [rsp + 0xe0]", "movdqu xmm7, [rsp + 0xf0]", "movdqu xmm8, [rsp + 0x100]", "movdqu xmm9, [rsp + 0x110]", "movdqu xmm10, [rsp + 0x120]", "movdqu xmm11, [rsp + 0x130]", "movdqu xmm12, [rsp + 0x140]", "movdqu xmm13, [rsp + 0x150]", "movdqu xmm14, [rsp + 0x160]", "movdqu xmm15, [rsp + 0x170]",
        // The two exits below land rsp one word apart (0x190 vs. 0x188) on
        // purpose — this is syscall-routing.md invariant 4's "account for
        // the KUSER call's extra stack word". `[rsp+0x188]` here is
        // `entry_rsp`: the value RSP held at the moment this trampoline was
        // entered, which is where the ntdll stub's own `call
        // [dispatcher_slot]` pushed its return address (call it
        // RET_ADDR — the address of the stub's own trailing `ret`).
        // `[entry_rsp+8]` is one call frame further out: whatever the stub
        // itself would eventually return to, once *its* `ret` runs.
        //
        // Ordinary path (2:, target = Wine's real dispatcher): this is a
        // tail call, so RSP must be exactly `entry_rsp` with RET_ADDR still
        // at `[rsp]` — Wine's dispatcher runs as a normal called function,
        // eventually does its own `ret`, consumes RET_ADDR, and lands back
        // on the stub's trailing `ret`, which then consumes `[entry_rsp+8]`
        // and returns to the stub's real caller. Two `ret`s total, matching
        // a real `call [dispatcher]; ret` sequence.
        //
        // Tagged path (target = a raw `syscall` instruction found by
        // `find_syscall`, tag bit cleared above): there is no dispatcher
        // call to unwind here — the whole point is to emulate the direct
        // route, where the stub's own inline `test;jne;syscall;ret` runs
        // with no KUSER dispatcher call in between at all. The instruction
        // right after any such `syscall` is always that same `ret` (it's
        // part of the fixed head+branch signature `pe_stub_layout.rs`
        // matches on, so this holds for Reflex's copied stub too). For that
        // one `ret` to consume `[entry_rsp+8]` directly — skipping RET_ADDR
        // entirely, since in the direct route it never existed — RSP must
        // already be `entry_rsp+8` before the jump. Hence `0x190`/`-0x10`
        // instead of `0x188`/`-8`: one extra word, for the one dispatcher
        // call this path never actually makes.
        "bt qword ptr [rsp + 0x180], 63", "jnc 2f", "btr qword ptr [rsp + 0x180], 63",
        "and qword ptr [rsp + 0x78], {clear_flags}", "or qword ptr [rsp + 0x78], {set_flags}", "push qword ptr [rsp + 0x78]", "popfq",
        "lea rsp, [rsp + 0x190]", "jmp qword ptr [rsp - 0x10]",
        "2:", "push qword ptr [rsp + 0x78]", "popfq", "lea rsp, [rsp + 0x188]", "jmp qword ptr [rsp - 8]",
        target = sym dispatcher_target,
        stacks = sym BRIDGE_STACKS,
        slot_mask = const BRIDGE_STACK_SLOTS - 1,
        slot_shift = const BRIDGE_STACK_SHIFT,
        slot_size = const 1usize << BRIDGE_STACK_SHIFT,
        clear_flags = const -0x882i32,
        set_flags = const 0x44u32,
    );
}

/// Swap Wine's KUSER dispatcher slot for [`dispatcher_bridge`]. Idempotent;
/// safe to call repeatedly until Wine has populated the slot (see the retry
/// note in `kuser.rs::linuwux_setup_kuser`).
pub(super) fn install() -> bool {
    if BRIDGE_INSTALLED.load(Ordering::Acquire) {
        return true;
    }
    let Some(_guard) = crate::page_guard::PageGuard::acquire() else {
        log_install_failure();
        return false;
    };
    if BRIDGE_INSTALLED.load(Ordering::Acquire) {
        return true;
    }
    let page = WINE_DISPATCHER_SLOT & !(linuwux::kuser::PAGE_SIZE as u64 - 1);
    // Wine owns this shared KUSER page. Temporarily make it writable to swap
    // the dispatcher slot, then restore the page's read-only protection.
    if unsafe {
        libc::syscall(
            libc::SYS_mprotect,
            page as *mut c_void,
            linuwux::kuser::PAGE_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
        )
    } == -1
    {
        log_install_failure();
        return false;
    }
    // The slot is readable, and the page was made writable above.
    let slot = WINE_DISPATCHER_SLOT as *mut u64;
    let original = unsafe { slot.read_volatile() };
    let bridge = dispatcher_bridge as *const () as u64;
    let installed = original != 0 && original != bridge;
    let already_installed = original == bridge && ORIGINAL_DISPATCHER.load(Ordering::Acquire) != 0;
    if installed {
        ORIGINAL_DISPATCHER.store(original, Ordering::Release);
        unsafe { slot.write_volatile(bridge) };
    }
    let restored = unsafe {
        libc::syscall(
            libc::SYS_mprotect,
            page as *mut c_void,
            linuwux::kuser::PAGE_SIZE,
            libc::PROT_READ,
        )
    } != -1;
    if (installed || already_installed) && restored {
        BRIDGE_INSTALLED.store(true, Ordering::Release);
        if !BRIDGE_INSTALL_SUCCESS_LOGGED.swap(true, Ordering::AcqRel) {
            log(c"reflex bridge installed");
            log_hex(
                c"reflex bridge original Wine dispatcher=",
                ORIGINAL_DISPATCHER.load(Ordering::Acquire),
            );
        }
        true
    } else {
        log_install_failure();
        false
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DispatchEvidence, find_raw_syscall_instruction, return_matches_stub, should_replay_raw,
    };

    #[test]
    fn copied_stub_lookup_requires_the_requested_service_number() {
        let code = [0x4c, 0x8b, 0xd1, 0xb8, 0x46, 0x02, 0x00, 0x00, 0x0f, 0x05];
        assert_eq!(
            find_raw_syscall_instruction(&code, 0x1234_5000, 0x246),
            Some(0x1234_5008)
        );
        assert_eq!(
            find_raw_syscall_instruction(&code, 0x1234_5000, 0x206),
            None
        );
    }

    #[test]
    fn dispatcher_return_must_match_the_discovered_stub_entry() {
        assert!(return_matches_stub(0x10001f, 0x100000));
        assert!(!return_matches_stub(0x100020, 0x100000));
        assert!(!return_matches_stub(0x10, 0x100000));
    }

    #[test]
    fn replays_raw_only_when_all_evidence_lines_up() {
        let all_true = DispatchEvidence {
            original_dispatcher_known: true,
            stub_match: true,
            caller_is_reflex_image: false,
            raw_syscall_found: true,
        };
        assert!(should_replay_raw(all_true));

        assert!(!should_replay_raw(DispatchEvidence {
            original_dispatcher_known: false,
            ..all_true
        }));
        assert!(!should_replay_raw(DispatchEvidence {
            stub_match: false,
            ..all_true
        }));
        assert!(!should_replay_raw(DispatchEvidence {
            caller_is_reflex_image: true,
            ..all_true
        }));
        assert!(!should_replay_raw(DispatchEvidence {
            raw_syscall_found: false,
            ..all_true
        }));
    }

    #[test]
    fn bridge_stack_slots_are_power_of_two_and_thread_id_indexable() {
        assert!(super::BRIDGE_STACK_SLOTS.is_power_of_two());
        // Windows thread ids advance by four, so shifting by two and masking
        // gives each of the first SLOTS threads its own stack.
        let slot = |tid: u64| (tid >> 2) as usize & (super::BRIDGE_STACK_SLOTS - 1);
        assert_ne!(slot(0x150), slot(0x154));
        assert_eq!(
            slot(0x150),
            slot(0x150 + 4 * super::BRIDGE_STACK_SLOTS as u64)
        );
        // Slots are 16-byte aligned and hold room for the selector's frames.
        const { assert!(1usize << super::BRIDGE_STACK_SHIFT >= 0x4000) };
    }

    extern "C" fn returning_dispatcher() {}

    #[test]
    fn bridge_selector_runs_off_the_callers_stack() {
        // The bridge reads the Windows thread id from gs:[0x48], so give this
        // thread a fake TEB. GS is per-thread and unused by the test harness.
        let result = std::thread::spawn(|| {
            let mut teb = [0u64; 0x20];
            teb[0x48 / 8] = 0x154;
            assert_eq!(
                unsafe { libc::syscall(libc::SYS_arch_prctl, 0x1001, teb.as_mut_ptr()) },
                0
            );
            super::ORIGINAL_DISPATCHER.store(
                returning_dispatcher as *const () as u64,
                core::sync::atomic::Ordering::SeqCst,
            );
            let bridge = super::dispatcher_bridge as *const () as u64;
            let mut untouched: u64;
            // Canary the 0x1000 bytes below the stack pointer, call the bridge
            // as a Windows syscall stub would, and check that only its own
            // fixed frame (0x190 bytes, plus the call's return address)
            // changed.
            unsafe {
                core::arch::asm!(
                    "sub rsp, 0x1000",
                    "mov rdi, rsp",
                    "mov ecx, 0x200",
                    "mov rax, 0xa5a5a5a5a5a5a5a5",
                    "cld",
                    "rep stosq",
                    "add rsp, 0x1000",
                    "mov eax, 0x19",
                    "call {bridge}",
                    "lea rdi, [rsp - 0x800]",
                    "mov ecx, 0xc0",
                    "mov rax, 0xa5a5a5a5a5a5a5a5",
                    "xor r8d, r8d",
                    "repe scasq",
                    "sete r8b",
                    bridge = in(reg) bridge,
                    out("r8") untouched,
                    out("rax") _,
                    out("rcx") _,
                    out("rdi") _,
                    clobber_abi("C"),
                );
            }
            let lock_released = unsafe {
                core::ptr::addr_of!(super::BRIDGE_STACKS)
                    .cast::<u32>()
                    .add((0x154 / 4) << 13)
                    .read_volatile()
            };
            assert_eq!(
                unsafe { libc::syscall(libc::SYS_arch_prctl, 0x1001, 0usize) },
                0
            );
            (untouched, lock_released)
        })
        .join()
        .unwrap();
        assert_eq!(
            result.0, 1,
            "the caller's stack below the frame was written"
        );
        assert_eq!(result.1, 0, "the slot lock was not released");
    }
}
