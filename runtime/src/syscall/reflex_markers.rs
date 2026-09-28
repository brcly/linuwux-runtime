//! Marker lifecycle for the Route/Replay handoff between
//! [`super::kuser_dispatch`] (which arms a marker when it decides a call is
//! Reflex-evidenced) and [`super::sigsys_router`] (which consumes it when the
//! resulting raw syscall traps, and again when Reflex replays the same
//! syscall back to Wine). A marker is keyed by thread id, raw-syscall stack
//! pointer, and raw-syscall RIP, and must be consumed at most twice: once as
//! [`Phase::Route`] (deliver the call to Reflex) and once as
//! [`Phase::Replay`] (restore the caller-visible state captured at the first
//! trap and forward to Wine). This file owns only that lifecycle; it does not
//! decide *whether* a call is Reflex-evidenced (that's `kuser_dispatch`) or
//! *what* Wine/Reflex does with it (that's `sigsys_router`).
//!
//! [`is_registered_target_process`] is a separate, simpler routing signal:
//! direct syscalls from a process that has completed Reflex's own `0x1337`
//! target-PID registration (mirroring Reflex's CR3/DR3 identity gate) are
//! routed without needing a bridge marker at all.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

const MARKER_CAPACITY: usize = 256;

static ACTIVE_MARKERS: AtomicU32 = AtomicU32::new(0);
static MARKER_STACKS: [AtomicU64; MARKER_CAPACITY] = [const { AtomicU64::new(0) }; MARKER_CAPACITY];
static MARKER_TIDS: [AtomicU64; MARKER_CAPACITY] = [const { AtomicU64::new(0) }; MARKER_CAPACITY];
static MARKER_RIPS: [AtomicU64; MARKER_CAPACITY] = [const { AtomicU64::new(0) }; MARKER_CAPACITY];
static MARKER_PHASES: [AtomicU64; MARKER_CAPACITY] = [const { AtomicU64::new(0) }; MARKER_CAPACITY];
static MARKER_XMM4: [[AtomicU64; 2]; MARKER_CAPACITY] =
    [const { [const { AtomicU64::new(0) }; 2] }; MARKER_CAPACITY];
static MARKER_XMM5: [[AtomicU64; 2]; MARKER_CAPACITY] =
    [const { [const { AtomicU64::new(0) }; 2] }; MARKER_CAPACITY];
static MARKER_R11: [AtomicU64; MARKER_CAPACITY] = [const { AtomicU64::new(0) }; MARKER_CAPACITY];
static MARKER_EFLAGS: [AtomicU64; MARKER_CAPACITY] = [const { AtomicU64::new(0) }; MARKER_CAPACITY];

static TARGET_PROCESS_ROUTE_LOGGED: AtomicBool = AtomicBool::new(false);

pub(super) fn has_active_markers() -> bool {
    ACTIVE_MARKERS.load(Ordering::Acquire) != 0
}

unsafe extern "C" {
    fn debug_log(message: *const core::ffi::c_char);
    fn debug_log_hex(prefix: *const core::ffi::c_char, value: u64);
    fn reflex_target_process_registered() -> libc::c_int;
}

fn log(message: &'static core::ffi::CStr) {
    unsafe { debug_log(message.as_ptr()) };
}

fn log_hex(prefix: &'static core::ffi::CStr, value: u64) {
    unsafe { debug_log_hex(prefix.as_ptr(), value) };
}

#[derive(Clone, Copy)]
pub(super) struct SavedContext {
    pub xmm4: [u8; 16],
    pub xmm5: [u8; 16],
    pub r11: u64,
    pub eflags: u64,
}

#[derive(Clone, Copy)]
pub(super) enum Phase {
    Route,
    Replay(SavedContext),
}

fn marker_slot(stack: u64) -> usize {
    ((stack >> 4) as usize) % MARKER_CAPACITY
}

/// Arm a marker for a raw syscall about to be replayed at `rip` on thread
/// `tid`'s stack. Called by `kuser_dispatch::dispatcher_target` once it has
/// decided a call is Reflex-evidenced.
pub(super) fn remember_marker(tid: u64, stack: u64, rip: u64) -> bool {
    if tid == 0 || stack == 0 || rip == 0 {
        return false;
    }
    let start = marker_slot(stack);
    for offset in 0..MARKER_CAPACITY {
        let index = (start + offset) % MARKER_CAPACITY;
        if MARKER_STACKS[index]
            .compare_exchange(0, u64::MAX, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            // Count the reserved slot before publishing its stack value, so
            // the fast path cannot skip a visible marker.
            ACTIVE_MARKERS.fetch_add(1, Ordering::AcqRel);
            MARKER_TIDS[index].store(tid, Ordering::Relaxed);
            MARKER_RIPS[index].store(rip, Ordering::Relaxed);
            MARKER_PHASES[index].store(0, Ordering::Relaxed);
            MARKER_STACKS[index].store(stack, Ordering::Release);
            return true;
        }
    }
    false
}

fn release_marker(index: usize, stack: u64) {
    if MARKER_STACKS[index]
        .compare_exchange(stack, u64::MAX, Ordering::AcqRel, Ordering::Relaxed)
        .is_err()
    {
        return;
    }
    MARKER_TIDS[index].store(0, Ordering::Relaxed);
    MARKER_RIPS[index].store(0, Ordering::Relaxed);
    MARKER_PHASES[index].store(0, Ordering::Relaxed);
    for half in 0..2 {
        MARKER_XMM4[index][half].store(0, Ordering::Relaxed);
        MARKER_XMM5[index][half].store(0, Ordering::Relaxed);
    }
    MARKER_R11[index].store(0, Ordering::Relaxed);
    MARKER_EFLAGS[index].store(0, Ordering::Relaxed);
    MARKER_STACKS[index].store(0, Ordering::Release);
    ACTIVE_MARKERS.fetch_sub(1, Ordering::AcqRel);
}

/// Drop any marker on `tid`'s stack at a depth at or below `stack` (i.e. a
/// caller that has since returned past it). Called once per SIGSYS so a
/// marker never leaks into a later syscall at a reused stack depth.
pub(super) fn retire_markers(tid: u64, stack: u64) {
    if tid == 0 || !has_active_markers() {
        return;
    }
    for index in 0..MARKER_CAPACITY {
        if MARKER_TIDS[index].load(Ordering::Relaxed) != tid {
            continue;
        }
        let recorded = MARKER_STACKS[index].load(Ordering::Acquire);
        // A nested Reflex syscall grows downward and must leave its outer
        // marker alive. Reaching the marker's depth again means it returned.
        if recorded == 0
            || recorded == u64::MAX
            || recorded > stack
            || MARKER_TIDS[index].load(Ordering::Relaxed) != tid
        {
            continue;
        }
        release_marker(index, recorded);
    }
}

/// Consume the marker for (`tid`, `stack`, `rip`), if any. The first call
/// arms the route (recording caller-visible state to restore later) and
/// returns [`Phase::Route`]; the second returns [`Phase::Replay`] with that
/// saved state and releases the marker. Called by `sigsys_router::redirect`.
pub(super) fn consume(
    tid: u64,
    stack: u64,
    rip: u64,
    xmm4: [u8; 16],
    xmm5: [u8; 16],
    r11: u64,
    eflags: u64,
) -> Option<Phase> {
    if tid == 0 || stack == 0 || rip == 0 || !has_active_markers() {
        return None;
    }
    let start = marker_slot(stack);
    let index = (0..MARKER_CAPACITY)
        .map(|offset| (start + offset) % MARKER_CAPACITY)
        .find(|&i| {
            MARKER_STACKS[i].load(Ordering::Acquire) == stack
                && MARKER_TIDS[i].load(Ordering::Relaxed) == tid
                && MARKER_RIPS[i].load(Ordering::Relaxed) == rip
        })?;
    if MARKER_PHASES[index]
        .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed)
        .is_ok()
    {
        for half in 0..2 {
            MARKER_XMM4[index][half].store(
                u64::from_le_bytes(xmm4[half * 8..half * 8 + 8].try_into().unwrap()),
                Ordering::Relaxed,
            );
            MARKER_XMM5[index][half].store(
                u64::from_le_bytes(xmm5[half * 8..half * 8 + 8].try_into().unwrap()),
                Ordering::Relaxed,
            );
        }
        MARKER_R11[index].store(r11, Ordering::Relaxed);
        MARKER_EFLAGS[index].store(eflags, Ordering::Relaxed);
        return Some(Phase::Route);
    }
    if MARKER_PHASES[index]
        .compare_exchange(1, 2, Ordering::AcqRel, Ordering::Relaxed)
        .is_ok()
    {
        let mut saved = SavedContext {
            xmm4: [0; 16],
            xmm5: [0; 16],
            r11: MARKER_R11[index].load(Ordering::Relaxed),
            eflags: MARKER_EFLAGS[index].load(Ordering::Relaxed),
        };
        for half in 0..2 {
            saved.xmm4[half * 8..half * 8 + 8].copy_from_slice(
                &MARKER_XMM4[index][half]
                    .load(Ordering::Relaxed)
                    .to_le_bytes(),
            );
            saved.xmm5[half * 8..half * 8 + 8].copy_from_slice(
                &MARKER_XMM5[index][half]
                    .load(Ordering::Relaxed)
                    .to_le_bytes(),
            );
        }
        release_marker(index, stack);
        return Some(Phase::Replay(saved));
    }
    release_marker(index, stack);
    None
}

/// Drop the marker for (`tid`, `stack`, `rip`) without treating it as
/// consumed. Called by `sigsys_router::redirect` when a call it identified as
/// bridge-evidenced turns out not to have a route (e.g. a bypass replay, or
/// the route callback declines it) — the marker must not linger for a later
/// syscall to accidentally match.
pub(super) fn cancel(tid: u64, stack: u64, rip: u64) {
    if !has_active_markers() {
        return;
    }
    let start = marker_slot(stack);
    if let Some(index) = (0..MARKER_CAPACITY)
        .map(|offset| (start + offset) % MARKER_CAPACITY)
        .find(|&i| {
            MARKER_STACKS[i].load(Ordering::Acquire) == stack
                && MARKER_TIDS[i].load(Ordering::Relaxed) == tid
                && MARKER_RIPS[i].load(Ordering::Relaxed) == rip
        })
    {
        release_marker(index, stack);
    }
}

/// Whether this process has completed Reflex's `0x1337` target-PID
/// registration — i.e. whether it *is* the registered Windows process, not
/// merely a caller reachable through Reflex's imported API surface. This is
/// process-local and does not depend on the IAT/caller evidence
/// `kuser_dispatch` uses for the bridge marker path.
pub(super) fn is_registered_target_process(rip: u64, service: u64) -> bool {
    let matches = unsafe { reflex_target_process_registered() != 0 };
    if matches {
        super::unixlib_repair::maybe_repair_wine_unixlib_exports();
    }
    if matches && !TARGET_PROCESS_ROUTE_LOGGED.swap(true, Ordering::AcqRel) {
        log(c"first direct syscall routed by registered Windows process identity");
        log_hex(c"target process syscall service=", service);
        log_hex(c"target process syscall RIP=", rip);
    }
    matches
}

#[cfg(test)]
mod tests {
    use super::{Phase, cancel, consume, remember_marker, retire_markers};

    #[test]
    fn bridged_marker_allows_one_reflex_route_then_restores_the_original_state() {
        let tid = 0x71_001;
        let rsp = 0x7fff_1234_5678;
        let rip = 0x6fff_1234_0002;
        assert!(remember_marker(tid, rsp, rip));
        let xmm4 = [0x44; 16];
        let xmm5 = [0x55; 16];
        assert!(consume(tid + 1, rsp, rip, xmm4, xmm5, 0x1111, 0x2222).is_none());
        assert!(matches!(
            consume(tid, rsp, rip, xmm4, xmm5, 0x1111, 0x2222),
            Some(Phase::Route)
        ));
        let Some(Phase::Replay(saved)) = consume(tid, rsp, rip, [0; 16], [0; 16], 0, 0) else {
            panic!("expected replay marker");
        };
        assert_eq!(saved.xmm4, xmm4);
        assert_eq!(saved.xmm5, xmm5);
        assert_eq!(saved.r11, 0x1111);
        assert_eq!(saved.eflags, 0x2222);
        assert!(consume(tid, rsp, rip, xmm4, xmm5, 0, 0).is_none());
    }

    #[test]
    fn nested_dispatcher_depth_does_not_retire_an_outer_marker() {
        let tid = 0x71_002;
        let rsp = 0x7fff_1234_9878;
        let rip = 0x6fff_1234_1002;
        assert!(remember_marker(tid, rsp, rip));
        retire_markers(tid, rsp - 0x100);
        assert!(matches!(
            consume(tid, rsp, rip, [0x44; 16], [0x55; 16], 0x11, 0x22),
            Some(Phase::Route)
        ));
        cancel(tid, rsp, rip);
    }
}
