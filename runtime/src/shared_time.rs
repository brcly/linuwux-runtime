//! Verifies that the live `KUSER_SHARED_DATA` page at [`super::ADDRESS`] is
//! actually Wine's own shared mapping (`/memfd:wine-mapping`, writable,
//! present) before `kuser.rs` attempts to patch it — patching an unmapped or
//! wrong page would silently do nothing, or write into whatever else
//! happens to be there. Declared as a submodule of `kuser.rs` via
//! `#[path = "shared_time.rs"] mod shared_time;` (rather than nested in a
//! `kuser/` directory) so it can reach that module's private constants
//! through `super::`.
use super::{ADDRESS, PAGE_GEOMETRY_SUPPORTED, PAGE_SIZE};
use core::sync::atomic::{AtomicBool, Ordering};

static VERIFIED: AtomicBool = AtomicBool::new(false);

fn wine_mapping(line: &[u8]) -> bool {
    crate::maps::parse(line).is_some_and(|mapping| {
        let path = mapping
            .path
            .strip_suffix(b" (deleted)")
            .unwrap_or(mapping.path);
        mapping.start == ADDRESS as u64
            && mapping.end >= (ADDRESS + PAGE_SIZE) as u64
            && matches!(mapping.permissions, b"r--s" | b"rw-s")
            && mapping.inode != b"0"
            && path == b"/memfd:wine-mapping"
    })
}

fn mapped_page_present() -> bool {
    let mut resident = 0;
    unsafe { libc::mincore(ADDRESS as *mut libc::c_void, PAGE_SIZE, &mut resident) == 0 }
}

fn verify_shared_page() -> bool {
    if !PAGE_GEOMETRY_SUPPORTED.load(Ordering::Acquire) {
        return false;
    }
    let _errno = crate::errno::Errno::save();
    mapped_page_present() && crate::maps::find_line(wine_mapping)
}

pub(crate) fn prepare_shared_page() -> bool {
    let verified = verify_shared_page();
    VERIFIED.store(verified, Ordering::Release);
    verified
}

fn ensure_verified() -> bool {
    if VERIFIED.load(Ordering::Acquire) {
        return true;
    }
    let verified = verify_shared_page();
    if verified {
        VERIFIED.store(true, Ordering::Release);
    }
    verified
}

pub(crate) fn shared_page_available_for_write() -> bool {
    ensure_verified()
}

#[cfg(test)]
mod tests {
    use super::{ADDRESS, PAGE_SIZE, wine_mapping};

    // Regression test: `/proc/self/maps` reports a `memfd`-backed mapping's
    // path with a trailing " (deleted)" (its `memfd_create` file has no real
    // link), which an earlier rewrite of this check compared for exact
    // equality against `/memfd:wine-mapping` and so never matched — silently
    // failing `shared_page_available_for_write` for every process and
    // breaking the KUSER patch for every game.
    #[test]
    fn recognizes_the_wine_mapping_even_with_the_kernels_deleted_suffix() {
        let line = format!(
            "{:x}-{:x} rw-s 00000000 00:01 123 /memfd:wine-mapping (deleted)",
            ADDRESS,
            ADDRESS + PAGE_SIZE
        );
        assert!(wine_mapping(line.as_bytes()));

        let without_suffix = format!(
            "{:x}-{:x} rw-s 00000000 00:01 123 /memfd:wine-mapping",
            ADDRESS,
            ADDRESS + PAGE_SIZE
        );
        assert!(wine_mapping(without_suffix.as_bytes()));

        let wrong_path = format!(
            "{:x}-{:x} rw-s 00000000 00:01 123 /memfd:something-else (deleted)",
            ADDRESS,
            ADDRESS + PAGE_SIZE
        );
        assert!(!wine_mapping(wrong_path.as_bytes()));
    }
}
