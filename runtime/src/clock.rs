//! Millisecond timestamps for rate-limiting rescans. `CLOCK_MONOTONIC_COARSE`
//! is served from the vDSO without a syscall and is async-signal-safe.

/// Coarse monotonic milliseconds, or 0 if the clock is unavailable.
pub(crate) fn coarse_milliseconds() -> u64 {
    let mut now = core::mem::MaybeUninit::<libc::timespec>::uninit();
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_COARSE, now.as_mut_ptr()) } != 0 {
        return 0;
    }
    let now = unsafe { now.assume_init() };
    (now.tv_sec as u64)
        .wrapping_mul(1000)
        .wrapping_add(now.tv_nsec as u64 / 1_000_000)
}
