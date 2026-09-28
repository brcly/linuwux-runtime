//! LinUwUx's unsafe runtime shell: the libc/signal/syscall interposition
//! that drives the safe `linuwux` (`protocol/`) crate's decision logic. Each
//! module here is feature-gated independently (see the `[features]` table
//! in `Cargo.toml`) so `xtask` and CI can build and lint every supported
//! subset; `docs/ARCHITECTURE.md` has the full module map and
//! `docs/protocol/` has the protocol design each module implements.
//! Compiled to a static library and linked into `LinUwUx.so` by `xtask`,
//! with the exported C ABI surface and linker hardening it verifies.
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::missing_safety_doc)]
#![cfg_attr(all(not(debug_assertions), panic = "abort"), no_std)]

#[cfg(all(not(debug_assertions), panic = "abort"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    unsafe { libc::abort() }
}

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64"
)))]
compile_error!("linuwux-runtime requires Linux x86_64 with glibc and 64-bit pointers");

#[cfg(any(feature = "cpuid", feature = "faketime"))]
mod clock;
#[cfg(any(feature = "cpuid", feature = "syscall"))]
mod config;
#[cfg(any(
    feature = "cpuid",
    feature = "syscall",
    feature = "debug",
    feature = "kuser"
))]
mod errno;
#[cfg(any(feature = "cpuid", feature = "kuser"))]
mod maps;
#[cfg(feature = "kuser")]
mod page_guard;
#[cfg(any(feature = "cpuid", feature = "syscall"))]
mod procmem;

#[cfg(feature = "cpuid")]
pub mod cpuid;
#[cfg(feature = "debug")]
pub mod debug;
#[cfg(feature = "environment")]
pub mod environment;
#[cfg(feature = "faketime")]
pub mod faketime;
#[cfg(feature = "gamescope")]
pub mod gamescope;
#[cfg(feature = "hooks")]
pub mod hooks;
#[cfg(feature = "kuser")]
pub mod kuser;
#[cfg(feature = "reflex")]
pub mod reflex;
#[cfg(feature = "environment")]
pub mod registry;
#[cfg(feature = "syscall")]
pub mod syscall;
