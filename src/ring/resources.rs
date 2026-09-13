//! Shared ring resource ownership and setup-time cleanup.
//!
//! Two owners here, both concerned with releasing the same three things —
//! the ring fd and its mmap'd SQ ring, CQ ring, and SQE array — but at
//! different points in a ring's life:
//!
//! - [`SetupGuard`] unwinds a *partially constructed* ring: everything
//!   `IoUring::from_params` has mapped so far, freed if any later step in
//!   setup fails before the ring is usable.
//! - [`RingResources`] owns a *fully constructed* ring's resources for its
//!   entire life, refcounted so [`Submitter`](super::Submitter) and
//!   [`Completer`](super::Completer) can each hold a share after
//!   [`split`](super::IoUring::split) and free the underlying resources
//!   only once both halves (and, per Q-05, any [`ProvidedBufferRing`
//!   ](super::ProvidedBufferRing) registered against the ring) are gone.

use crate::error::Error;
use crate::syscall;
use crate::types::{MapFlags, Prot, RawFd};
use core::sync::atomic::{AtomicUsize, Ordering};

/// Mapped memory region, for cleanup in `Drop`.
#[derive(Clone, Copy)]
pub(super) struct MappedRegion {
    pub(super) addr: usize,
    pub(super) len: usize,
}

impl MappedRegion {
    pub(super) const fn new(addr: usize, len: usize) -> Self {
        Self { addr, len }
    }
}

/// Cleanup guard for partially-initialized ring resources.
///
/// Tracks resources acquired during `from_params` so that *any* error
/// path can just `drop(guard)` instead of manually unwinding each
/// prior allocation. Call `disarm()` on success to prevent cleanup.
pub(super) struct SetupGuard {
    pub(super) fd: RawFd,
    pub(super) sq_ring: MappedRegion,
    pub(super) cq_ring: MappedRegion,
    pub(super) sqes: MappedRegion,
}

impl SetupGuard {
    pub(super) const fn new(fd: RawFd) -> Self {
        Self {
            fd,
            sq_ring: MappedRegion { addr: 0, len: 0 },
            cq_ring: MappedRegion { addr: 0, len: 0 },
            sqes: MappedRegion { addr: 0, len: 0 },
        }
    }

    /// Consume the guard without running cleanup. Call after all
    /// resources have been moved into the final `IoUring` struct.
    pub(super) const fn disarm(self) {
        core::mem::forget(self);
    }
}

impl Drop for SetupGuard {
    fn drop(&mut self) {
        // Safety: this guard uniquely owns each region until `disarm`
        // hands them off, so each is unmapped exactly once here.
        if self.sqes.len > 0 {
            let _ = unsafe { syscall::munmap(self.sqes.addr, self.sqes.len) };
        }
        if self.cq_ring.len > 0 {
            let _ = unsafe { syscall::munmap(self.cq_ring.addr, self.cq_ring.len) };
        }
        if self.sq_ring.len > 0 {
            let _ = unsafe { syscall::munmap(self.sq_ring.addr, self.sq_ring.len) };
        }
        let _ = syscall::close(self.fd);
    }
}

/// Shared ownership of the kernel resources that both `Submitter` and
/// `Completer` need to keep alive: the ring fd and the three mmap regions.
///
/// The refcount and the resource fields are stored in a single anonymous
/// mmap page so that no heap allocator is required. The page is allocated
/// in `RingResources::alloc` and freed (along with the ring's own mmaps and
/// fd) when the last reference is dropped.
pub(super) struct RingResources {
    refcount: AtomicUsize,
    fd: RawFd,
    sq_ring: MappedRegion,
    cq_ring: MappedRegion,
    sqes_region: MappedRegion,
    /// The mmap page that holds `self`. Freed last in `release`.
    self_page: MappedRegion,
}

impl RingResources {
    /// Allocate one anonymous page, write `self` into it, and return a
    /// raw pointer. The caller owns the only reference (refcount = 1).
    pub(super) fn alloc(
        fd: RawFd,
        sq_ring: MappedRegion,
        cq_ring: MappedRegion,
        sqes_region: MappedRegion,
    ) -> Result<*mut Self, Error> {
        let page_size = 4096usize;
        let len = core::mem::size_of::<Self>().next_multiple_of(page_size);
        // Safety: `addr` 0 and `MapFlags::ANONYMOUS` mean the kernel picks a
        // fresh, unused range; nothing existing can be clobbered.
        let addr = unsafe {
            syscall::mmap(
                0,
                len,
                Prot::READ | Prot::WRITE,
                MapFlags::PRIVATE | MapFlags::ANONYMOUS,
                usize::MAX,
                0,
            )
        }?;
        let ptr = addr as *mut Self;
        unsafe {
            ptr.write(Self {
                refcount: AtomicUsize::new(1),
                fd,
                sq_ring,
                cq_ring,
                sqes_region,
                self_page: MappedRegion::new(addr, len),
            });
        }
        Ok(ptr)
    }

    /// Increment the refcount. Called when producing a second owner.
    pub(super) unsafe fn retain(ptr: *mut Self) {
        unsafe { &(*ptr).refcount }.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns the ring fd these resources were allocated for.
    ///
    /// Reading this does not require holding a reference beyond the
    /// pointer's own validity: the fd field never changes after `alloc`.
    pub(super) const unsafe fn fd(ptr: *const Self) -> RawFd {
        unsafe { (*ptr).fd }
    }

    /// Decrement the refcount. When it reaches zero, unmaps ring memory,
    /// closes the fd, and finally unmaps the page that holds `self`.
    pub(super) unsafe fn release(ptr: *mut Self) {
        // AcqRel so that any writes in the dying half are visible to
        // whoever runs the cleanup (mirrors std::Arc drop semantics).
        if unsafe { &(*ptr).refcount }.fetch_sub(1, Ordering::AcqRel) != 1 {
            return;
        }
        // We are the last owner — clean up.
        // SAFETY: no other references exist at this point.
        let res = unsafe { &*ptr };
        // Safety: this is the last owner (refcount just hit zero), so
        // every mapping and the fd below are ours alone to release, each
        // released exactly once here.
        let _ = unsafe { syscall::munmap(res.sqes_region.addr, res.sqes_region.len) };
        if res.cq_ring.len > 0 {
            let _ = unsafe { syscall::munmap(res.cq_ring.addr, res.cq_ring.len) };
        }
        let _ = unsafe { syscall::munmap(res.sq_ring.addr, res.sq_ring.len) };
        let _ = syscall::close(res.fd);
        // Free the page last — `res` must not be used after this point.
        let self_page = MappedRegion::new(res.self_page.addr, res.self_page.len);
        let _ = unsafe { syscall::munmap(self_page.addr, self_page.len) };
    }
}
