#![deny(unsafe_op_in_unsafe_fn)]
#![allow(clippy::missing_safety_doc)]
#![cfg_attr(all(not(test), not(debug_assertions), panic = "abort"), no_std)]

#[cfg(all(not(test), not(debug_assertions), panic = "abort"))]
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

#[cfg(any(
    feature = "cpuid",
    feature = "syscall",
    feature = "debug",
    feature = "kuser"
))]
mod errno;
#[cfg(feature = "kuser")]
mod page_guard;

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
#[cfg(feature = "syscall")]
pub mod syscall;

#[cfg(all(test, feature = "cpuid"))]
mod tests;
