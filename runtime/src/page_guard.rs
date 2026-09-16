use core::mem::MaybeUninit;
use core::ptr;
use core::sync::atomic::{AtomicI32, Ordering};

static OWNER: AtomicI32 = AtomicI32::new(0);

pub(crate) struct PageGuard {
    mask: MaybeUninit<libc::sigset_t>,
    _thread: core::marker::PhantomData<*mut ()>,
}

impl PageGuard {
    pub(crate) fn acquire() -> Option<Self> {
        let _errno = crate::errno::Errno::save();
        let mut blocked = MaybeUninit::<libc::sigset_t>::uninit();
        let mut previous = MaybeUninit::<libc::sigset_t>::uninit();
        let result = unsafe {
            libc::sigemptyset(blocked.as_mut_ptr());
            libc::sigaddset(blocked.as_mut_ptr(), libc::SIGSEGV);
            libc::sigaddset(blocked.as_mut_ptr(), libc::SIGSYS);
            libc::sigprocmask(libc::SIG_BLOCK, blocked.as_ptr(), previous.as_mut_ptr())
        };
        if result != 0 {
            return None;
        }
        let mask = previous;
        let pid = unsafe { libc::getpid() };
        let owner = OWNER.load(Ordering::Acquire);
        if owner == pid
            || OWNER
                .compare_exchange(owner, pid, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
        {
            unsafe { libc::sigprocmask(libc::SIG_SETMASK, mask.as_ptr(), ptr::null_mut()) };
            return None;
        }
        if owner != 0 {
            crate::kuser::recover_patch_after_fork();
        }
        Some(Self {
            mask,
            _thread: core::marker::PhantomData,
        })
    }
}

impl Drop for PageGuard {
    fn drop(&mut self) {
        let _errno = crate::errno::Errno::save();
        OWNER.store(0, Ordering::Release);
        unsafe { libc::sigprocmask(libc::SIG_SETMASK, self.mask.as_ptr(), ptr::null_mut()) };
    }
}
