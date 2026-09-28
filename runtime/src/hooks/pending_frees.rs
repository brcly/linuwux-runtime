//! Fixed-capacity duplicate-free history for unix `win32u` allocations.
//! The ring retains the previous 1,024-entry eviction behavior; a hash index
//! makes ordinary lookup and removal independent of the ring's length.

use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, Ordering};

const CAPACITY: usize = 1024;
const BUCKET_COUNT: usize = 4096;
const NO_ENTRY: u16 = u16::MAX;

#[derive(Clone, Copy)]
struct Entry {
    address: usize,
    next: u16,
    prev: u16,
}

impl Entry {
    const EMPTY: Self = Self {
        address: 0,
        next: NO_ENTRY,
        prev: NO_ENTRY,
    };
}

struct History {
    entries: [Entry; CAPACITY],
    buckets: [u16; BUCKET_COUNT],
    next_index: usize,
}

impl History {
    const fn new() -> Self {
        Self {
            entries: [Entry::EMPTY; CAPACITY],
            buckets: [NO_ENTRY; BUCKET_COUNT],
            next_index: 0,
        }
    }

    fn bucket(address: usize) -> usize {
        let mixed = (address >> 4).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        mixed >> (usize::BITS as usize - BUCKET_COUNT.trailing_zeros() as usize)
    }

    fn find(&self, address: usize) -> Option<usize> {
        let mut index = self.buckets[Self::bucket(address)];
        while index != NO_ENTRY {
            let entry = self.entries[index as usize];
            if entry.address == address {
                return Some(index as usize);
            }
            index = entry.next;
        }
        None
    }

    fn remove(&mut self, index: usize) {
        let entry = self.entries[index];
        if entry.prev == NO_ENTRY {
            self.buckets[Self::bucket(entry.address)] = entry.next;
        } else {
            self.entries[entry.prev as usize].next = entry.next;
        }
        if entry.next != NO_ENTRY {
            self.entries[entry.next as usize].prev = entry.prev;
        }
        self.entries[index] = Entry::EMPTY;
    }

    fn seen_or_mark(&mut self, address: usize) -> bool {
        if self.find(address).is_some() {
            return true;
        }
        let index = self.next_index;
        if self.entries[index].address != 0 {
            self.remove(index);
        }
        let bucket = Self::bucket(address);
        let head = self.buckets[bucket];
        self.entries[index] = Entry {
            address,
            next: head,
            prev: NO_ENTRY,
        };
        if head != NO_ENTRY {
            self.entries[head as usize].prev = index as u16;
        }
        self.buckets[bucket] = index as u16;
        self.next_index = (index + 1) % CAPACITY;
        false
    }

    fn consume(&mut self, address: usize) -> bool {
        if let Some(index) = self.find(address) {
            self.remove(index);
            return true;
        }
        false
    }
}

struct SharedHistory(UnsafeCell<History>);

// SAFETY: every access to the cell is serialized by LOCK. The fork handler
// replaces the copied state after all other threads have ceased to exist.
unsafe impl Sync for SharedHistory {}

static LOCK: AtomicBool = AtomicBool::new(false);
static HISTORY: SharedHistory = SharedHistory(UnsafeCell::new(History::new()));

fn with_history<R>(f: impl FnOnce(&mut History) -> R) -> R {
    while LOCK
        .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    // SAFETY: LOCK excludes all concurrent accesses to HISTORY.
    let result = f(unsafe { &mut *HISTORY.0.get() });
    LOCK.store(false, Ordering::Release);
    result
}

pub(super) fn seen_or_mark(ptr: *mut c_void) -> bool {
    if ptr.is_null() {
        return false;
    }
    with_history(|history| history.seen_or_mark(ptr.addr()))
}

pub(super) fn consume_if_pending(ptr: *mut c_void) -> bool {
    if ptr.is_null() {
        return false;
    }
    with_history(|history| history.consume(ptr.addr()))
}

pub(super) fn after_fork() {
    // SAFETY: a fork child has only the calling thread. Clearing the copied
    // state also discards any partially updated chain held by a vanished one.
    unsafe { *HISTORY.0.get() = History::new() };
    LOCK.store(false, Ordering::Release);
}

#[cfg(test)]
mod tests {
    use super::{CAPACITY, History};

    struct Reference {
        entries: [Option<usize>; CAPACITY],
        next_index: usize,
    }

    impl Reference {
        fn new() -> Self {
            Self {
                entries: [None; CAPACITY],
                next_index: 0,
            }
        }

        fn seen_or_mark(&mut self, address: usize) -> bool {
            if self.entries.contains(&Some(address)) {
                return true;
            }
            self.entries[self.next_index] = Some(address);
            self.next_index = (self.next_index + 1) % CAPACITY;
            false
        }

        fn consume(&mut self, address: usize) -> bool {
            if let Some(slot) = self.entries.iter_mut().find(|slot| **slot == Some(address)) {
                *slot = None;
                return true;
            }
            false
        }
    }

    #[test]
    fn indexed_history_matches_ring_across_collisions_reuse_and_eviction() {
        let mut indexed = History::new();
        let mut reference = Reference::new();
        let mut random = 0x91a2_b3c4_d5e6_f701u64;
        for step in 0..20_000 {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            let address = (((random as usize) % 1600) + 1) << 4;
            if step % 3 == 0 {
                assert_eq!(indexed.consume(address), reference.consume(address));
            } else {
                assert_eq!(
                    indexed.seen_or_mark(address),
                    reference.seen_or_mark(address)
                );
            }
        }
        for address in (1..=1600).map(|value| value << 4) {
            assert_eq!(indexed.consume(address), reference.consume(address));
        }
    }
}
