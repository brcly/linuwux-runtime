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
