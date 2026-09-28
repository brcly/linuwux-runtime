//! Bounded syscall history used to diagnose game-process null-read faults.
//!
//! The SIGSYS handler records only fixed-size atomic data. The history is
//! emitted from the SIGSEGV path only when Wine is about to receive a fault
//! whose address is null, keeping routine syscall logging quiet.

use core::sync::atomic::{AtomicU64, Ordering};

const HISTORY_CAPACITY: usize = 32;
const FIELD_COUNT: usize = 13;
const WRITING_BIT: u64 = 1 << 63;
const NULL_FAULT_DUMP_LIMIT: u64 = 4;

#[repr(u64)]
#[derive(Clone, Copy)]
pub(super) enum Disposition {
    Forwarded = 0,
    #[cfg(all(feature = "kuser", feature = "reflex"))]
    BridgeReplayRestored = 1,
    ReflexBypassForwarded = 2,
    #[cfg(all(feature = "kuser", feature = "reflex"))]
    LocallyCompleted = 3,
    ReflexRouteDeclined = 4,
    ReflexRedirected = 5,
}

#[derive(Clone, Copy)]
pub(super) struct Event {
    pub(super) fields: [u64; FIELD_COUNT],
}

impl Event {
    pub(super) const fn with_disposition(mut self, disposition: Disposition) -> Self {
        self.fields[2] = disposition as u64;
        self
    }
}

struct Slot {
    sequence: AtomicU64,
    fields: [AtomicU64; FIELD_COUNT],
}

impl Slot {
    const fn new() -> Self {
        Self {
            sequence: AtomicU64::new(0),
            fields: [const { AtomicU64::new(0) }; FIELD_COUNT],
        }
    }
}

struct History {
    next: AtomicU64,
    slots: [Slot; HISTORY_CAPACITY],
}

impl History {
    const fn new() -> Self {
        Self {
            next: AtomicU64::new(0),
            slots: [const { Slot::new() }; HISTORY_CAPACITY],
        }
    }

    fn record(&self, event: Event) {
        let ticket = self.next.fetch_add(1, Ordering::Relaxed);
        let slot = &self.slots[ticket as usize % HISTORY_CAPACITY];
        let sequence = ticket.wrapping_add(1);
        loop {
            let current = slot.sequence.load(Ordering::Acquire);
            // If another writer owns this slot, or a newer wrapped ticket
            // already replaced this one, drop this sample instead of
            // publishing a mixed record from concurrent signal handlers.
            if current & WRITING_BIT != 0 || current > sequence {
                return;
            }
            if slot
                .sequence
                .compare_exchange(
                    current,
                    sequence | WRITING_BIT,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                break;
            }
        }
        for (target, value) in slot.fields.iter().zip(event.fields) {
            target.store(value, Ordering::Relaxed);
        }
        slot.sequence.store(sequence, Ordering::Release);
    }

    fn visit_recent(&self, mut visit: impl FnMut(u64, Event)) {
        let end = self.next.load(Ordering::Acquire);
        let start = end.saturating_sub(HISTORY_CAPACITY as u64);
        for ticket in start..end {
            let slot = &self.slots[ticket as usize % HISTORY_CAPACITY];
            let expected = ticket.wrapping_add(1);
            if slot.sequence.load(Ordering::Acquire) != expected {
                continue;
            }
            let mut fields = [0; FIELD_COUNT];
            for (target, source) in fields.iter_mut().zip(&slot.fields) {
                *target = source.load(Ordering::Relaxed);
            }
            if slot.sequence.load(Ordering::Acquire) == expected {
                visit(ticket, Event { fields });
            }
        }
    }
}

static HISTORY: History = History::new();
static NULL_FAULT_DUMPS: AtomicU64 = AtomicU64::new(0);

unsafe extern "C" {
    fn debug_enabled() -> libc::c_int;
    fn debug_log(message: *const core::ffi::c_char);
    fn debug_log_hex(prefix: *const core::ffi::c_char, value: u64);
}

pub(super) const fn event(
    tid: u64,
    signal_code: u64,
    disposition: Disposition,
    registers: [u64; 10],
) -> Event {
    Event {
        fields: [
            tid,
            signal_code,
            disposition as u64,
            registers[0],
            registers[1],
            registers[2],
            registers[3],
            registers[4],
            registers[5],
            registers[6],
            registers[7],
            registers[8],
            registers[9],
        ],
    }
}

pub(super) fn record_game_event(event: Event) {
    // This history is only ever emitted through debug_log after a fault.
    // Avoid the ring's atomic writes on every ordinary SIGSYS when logging
    // is disabled for a normal game run.
    if unsafe { debug_enabled() } != 0 && crate::environment::game_process() {
        HISTORY.record(event);
    }
}

pub(super) fn dump_on_null_fault(address: usize, rip: u64, tid: u64) {
    if address != 0
        || !crate::environment::game_process()
        || NULL_FAULT_DUMPS.fetch_add(1, Ordering::AcqRel) >= NULL_FAULT_DUMP_LIMIT
    {
        return;
    }

    // The debug logger uses bounded writes and is already used from both
    // signal handlers; the history itself requires no allocation or locks.
    unsafe {
        debug_log(c"NBA null-address SIGSEGV; recent SIGSYS history follows".as_ptr());
        debug_log_hex(c"NBA fault tid=".as_ptr(), tid);
        debug_log_hex(c"NBA fault RIP=".as_ptr(), rip);
    }
    HISTORY.visit_recent(|sequence, event| unsafe {
        debug_log(c"NBA SIGSYS history event".as_ptr());
        debug_log_hex(c"NBA SIGSYS sequence=".as_ptr(), sequence);
        debug_log_hex(c"NBA SIGSYS tid=".as_ptr(), event.fields[0]);
        debug_log_hex(c"NBA SIGSYS signal_code=".as_ptr(), event.fields[1]);
        debug_log_hex(c"NBA SIGSYS disposition=".as_ptr(), event.fields[2]);
        debug_log_hex(c"NBA SIGSYS RIP=".as_ptr(), event.fields[3]);
        debug_log_hex(c"NBA SIGSYS RSP=".as_ptr(), event.fields[4]);
        debug_log_hex(c"NBA SIGSYS RAX=".as_ptr(), event.fields[5]);
        debug_log_hex(c"NBA SIGSYS R10=".as_ptr(), event.fields[6]);
        debug_log_hex(c"NBA SIGSYS RCX=".as_ptr(), event.fields[7]);
        debug_log_hex(c"NBA SIGSYS RDX=".as_ptr(), event.fields[8]);
        debug_log_hex(c"NBA SIGSYS R8=".as_ptr(), event.fields[9]);
        debug_log_hex(c"NBA SIGSYS R9=".as_ptr(), event.fields[10]);
        debug_log_hex(c"NBA SIGSYS R13=".as_ptr(), event.fields[11]);
        debug_log_hex(c"NBA SIGSYS XMM5 low=".as_ptr(), event.fields[12]);
    });
}

#[cfg(test)]
mod tests {
    use super::{Event, HISTORY_CAPACITY, History};

    #[test]
    fn history_keeps_only_the_most_recent_events_in_order() {
        let history = History::new();
        let total = HISTORY_CAPACITY as u64 + 3;
        for sequence in 0..total {
            history.record(Event {
                fields: [sequence, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            });
        }

        let mut seen = Vec::new();
        history.visit_recent(|sequence, event| {
            seen.push((sequence, event.fields[0]));
        });

        assert_eq!(seen.len(), HISTORY_CAPACITY);
        assert_eq!(seen[0], (3, 3));
        assert_eq!(seen[HISTORY_CAPACITY - 1], (total - 1, total - 1));
    }
}
