//! Saves and restores `errno` across a block of LinUwUx's own libc calls, so
//! interposed functions (`malloc`, `free`, `gettimeofday`, ...) never leak
//! their internal syscalls' errno into the caller's. Construct at the top of
//! a function with `let _errno = Errno::save();`; the restore happens in
//! `Drop`, on every return path including early ones.
pub(crate) struct Errno(core::ffi::c_int);

impl Errno {
    pub(crate) fn save() -> Self {
        Self(unsafe { *libc::__errno_location() })
    }
}

impl Drop for Errno {
    fn drop(&mut self) {
        unsafe { *libc::__errno_location() = self.0 };
    }
}
