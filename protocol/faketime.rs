//! Windows FILETIME <-> Unix time conversion math for the `gettimeofday`
//! offset Reflex's `SET_TIME` control leaf applies (see
//! `runtime/src/faketime.rs`, which owns the actual clock interposition and
//! offset storage). Wrapping arithmetic throughout is deliberate: an offset
//! is a difference of two clocks that can each wrap independently, not a
//! value that should ever panic in a signal-adjacent path.
pub const TICKS_PER_SECOND: u64 = 10_000_000;
pub const SECONDS_1601_TO_1970: u64 = 86_400 * (369 * 365 + 89);

pub const fn offset_from_filetime(now_seconds: i64, filetime: u64) -> u64 {
    let requested = (filetime / TICKS_PER_SECOND).wrapping_sub(SECONDS_1601_TO_1970);
    (now_seconds as u64).wrapping_sub(requested)
}

pub const fn apply_offset(seconds: i64, offset: u64) -> i64 {
    (seconds as u64).wrapping_sub(offset) as i64
}
