//! LinUwUx's safe protocol core: the pure, `no_std`, unsafe-forbidden
//! decision logic for the Reflex/Denuvo compatibility protocol, with no
//! knowledge of libc, signals, or process memory. `runtime/` is the unsafe
//! FFI/signal-handling shell that drives this crate through the `Host`
//! trait pattern (see `reflex::Host`) and calls its pure functions directly
//! elsewhere (CPUID reply tables, KUSER patch recipes, environment/gamescope
//! string parsing). See `docs/ARCHITECTURE.md` for how the two crates fit
//! together, and `docs/protocol/syscall-routing.md` for the protocol this
//! module implements.
#![forbid(unsafe_code)]
#![no_std]

pub mod cpuid;
pub mod debug;
pub mod environment;
pub mod faketime;
pub mod gamescope;
pub mod kuser;
pub mod quirks;
pub mod reflex;
