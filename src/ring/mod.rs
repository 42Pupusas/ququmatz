//! `io_uring` ring management: setup, submission, completion, and split.
//!
//! Submodules:
//! - [`builder`] — fluent setup configuration
//! - [`ops`] — `do_*` convenience methods (push + submit + complete)
//! - [`register`] — `register_*` resource registration (non-pbuf)
//! - [`pbuf`] — provided-buffer ring

use crate::error::{CompletionError, Errno, Error, InvalidArgKind, SetupError, SubmitError};
use crate::op::Sqe;
use crate::syscall;
use crate::types::{
    CqeFlags, EnterFlags, Features, IoUringCqe, IoUringParams, IoUringSqe, MapFlags, Prot, RawFd,
    RingOffset, SetupFlags,
};
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

mod builder;
mod ops;
mod pbuf;
mod probe;
mod register;

pub use builder::IoUringBuilder;
pub use pbuf::{BufferConsumer, ProvidedBufferRing};
pub use probe::Probe;

// ---------------------------------------------------------------------------
// Shared ring resources — refcounted without alloc
// ---------------------------------------------------------------------------

/// Shared ownership of the kernel resources that both `Submitter` and
/// `Completer` need to keep alive: the ring fd and the three mmap regions.
///
/// The refcount and the resource fields are stored in a single anonymous
/// mmap page so that no heap allocator is required. The page is allocated
/// in `RingResources::alloc` and freed (along with the ring's own mmaps and
/// fd) when the last reference is dropped.
struct RingResources {
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
    fn alloc(
        fd: RawFd,
        sq_ring: MappedRegion,
        cq_ring: MappedRegion,
        sqes_region: MappedRegion,
    ) -> Result<*mut Self, Error> {
        let page_size = 4096usize;
        let len = core::mem::size_of::<Self>().next_multiple_of(page_size);
        let addr = syscall::mmap(
            0,
            len,
            Prot::READ | Prot::WRITE,
            MapFlags::PRIVATE | MapFlags::ANONYMOUS,
            usize::MAX,
            0,
        )?;
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
    unsafe fn retain(ptr: *mut Self) {
        unsafe { &(*ptr).refcount }.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement the refcount. When it reaches zero, unmaps ring memory,
    /// closes the fd, and finally unmaps the page that holds `self`.
    unsafe fn release(ptr: *mut Self) {
        // AcqRel so that any writes in the dying half are visible to
        // whoever runs the cleanup (mirrors std::Arc drop semantics).
        if unsafe { &(*ptr).refcount }.fetch_sub(1, Ordering::AcqRel) != 1 {
            return;
        }
        // We are the last owner — clean up.
        // SAFETY: no other references exist at this point.
        let res = unsafe { &*ptr };
        let _ = syscall::munmap(res.sqes_region.addr, res.sqes_region.len);
        if res.cq_ring.len > 0 {
            let _ = syscall::munmap(res.cq_ring.addr, res.cq_ring.len);
        }
        let _ = syscall::munmap(res.sq_ring.addr, res.sq_ring.len);
        let _ = syscall::close(res.fd);
        // Free the page last — `res` must not be used after this point.
        let self_page = MappedRegion::new(res.self_page.addr, res.self_page.len);
        let _ = syscall::munmap(self_page.addr, self_page.len);
    }
}

/// A completed `io_uring` operation.
#[derive(Debug, Clone, Copy)]
pub struct Completion {
    /// The `user_data` value from the original submission.
    pub user_data: u64,
    /// The raw result code from the kernel. Interpretation is operation-specific:
    /// for read/write it is the byte count, for accept it is a new fd, for
    /// timeout expiry it is `-ETIME`, etc. Negative values are negated errno
    /// codes. Use [`into_result`](Self::into_result) for the common
    /// "non-negative value or error" pattern.
    pub result: i32,
    /// Kernel-set flags (multishot, buffer selection, etc.).
    pub flags: CqeFlags,
}

impl Completion {
    /// Convert the raw result into a `Result<u32, Error>`.
    ///
    /// This is a convenience for the common "non-negative value or error"
    /// pattern (e.g., byte count from read/write, fd from accept). For
    /// operations where a negative result has specific meaning beyond an
    /// error (e.g., `IORING_OP_TIMEOUT` returns `-ETIME` on normal expiry),
    /// inspect [`result`](Self::result) directly instead.
    ///
    /// This method borrows rather than consuming so that `user_data` and
    /// `flags` (e.g., `CqeFlags::MORE` for multishot) remain accessible.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Completion`] wrapping a [`CompletionError::Failed`]
    /// when the kernel reported a negative errno in this CQE.
    #[allow(clippy::cast_sign_loss)]
    pub const fn into_result(&self) -> Result<u32, Error> {
        if self.result < 0 {
            Err(Error::Completion(CompletionError::Failed(Errno(
                -self.result,
            ))))
        } else {
            Ok(self.result as u32)
        }
    }

    /// Returns `true` if the result is a negative errno.
    #[must_use]
    pub const fn is_err(&self) -> bool {
        self.result < 0
    }

    /// Returns the buffer id chosen from a provided-buffer ring, if any.
    ///
    /// Decodes the upper 16 bits of the CQE flags when `CqeFlags::BUFFER`
    /// is set. Only meaningful for completions of SQEs submitted with
    /// [`Sqe::buffer_select`](crate::op::Sqe::buffer_select).
    #[must_use]
    pub const fn buffer_id(&self) -> Option<u16> {
        if self.flags.contains(CqeFlags::BUFFER) {
            #[allow(clippy::cast_possible_truncation)]
            Some((self.flags.bits() >> 16) as u16)
        } else {
            None
        }
    }
}

/// Mapped memory region, for cleanup in `Drop`.
struct MappedRegion {
    addr: usize,
    len: usize,
}

impl MappedRegion {
    const fn new(addr: usize, len: usize) -> Self {
        Self { addr, len }
    }
}

/// Cleanup guard for partially-initialized ring resources.
///
/// Tracks resources acquired during `from_params` so that *any* error
/// path can just `drop(guard)` instead of manually unwinding each
/// prior allocation. Call `disarm()` on success to prevent cleanup.
struct SetupGuard {
    fd: RawFd,
    sq_ring: MappedRegion,
    cq_ring: MappedRegion,
    sqes: MappedRegion,
}

impl SetupGuard {
    const fn new(fd: RawFd) -> Self {
        Self {
            fd,
            sq_ring: MappedRegion { addr: 0, len: 0 },
            cq_ring: MappedRegion { addr: 0, len: 0 },
            sqes: MappedRegion { addr: 0, len: 0 },
        }
    }

    /// Consume the guard without running cleanup. Call after all
    /// resources have been moved into the final `IoUring` struct.
    const fn disarm(self) {
        core::mem::forget(self);
    }
}

impl Drop for SetupGuard {
    fn drop(&mut self) {
        if self.sqes.len > 0 {
            let _ = syscall::munmap(self.sqes.addr, self.sqes.len);
        }
        if self.cq_ring.len > 0 {
            let _ = syscall::munmap(self.cq_ring.addr, self.cq_ring.len);
        }
        if self.sq_ring.len > 0 {
            let _ = syscall::munmap(self.sq_ring.addr, self.sq_ring.len);
        }
        let _ = syscall::close(self.fd);
    }
}

/// Safe wrapper around a Linux `io_uring` instance.
///
/// # Thread Safety
///
/// `IoUring` is `!Send` and `!Sync` (due to raw pointers into mmap'd memory).
/// This is intentional — the ring's mmap'd regions and cached indices are not
/// safe to share across threads without external synchronization. Create one
/// ring per thread, or wrap in a `Mutex` if you must share.
///
/// To split submission and completion across threads, use
/// [`split`](Self::split) to obtain a [`Submitter`] and a [`Completer`],
/// both of which are `Send`. `split` refuses to run — returning the ring
/// back unchanged — on setup-flag combinations that restrict submission or
/// `GETEVENTS` waits to the ring's creating thread; see
/// [`can_split`](Self::can_split) and [`split`](Self::split) for details.
///
/// # Drop Behavior
///
/// When dropped, any SQEs that have been [`push`](Self::push)ed but not yet
/// submitted via [`submit`](Self::submit) or [`submit_and_wait`](Self::submit_and_wait)
/// are **silently discarded**. The drop implementation flushes the CQ head
/// (so the kernel can reuse completed CQ slots), unmaps ring memory, and
/// closes the ring fd. It does *not* call `io_uring_enter` to flush pending
/// submissions. Always submit before dropping if you need those operations
/// to execute.
pub struct IoUring {
    pub(super) fd: RawFd,

    // SQ ring pointers (into mmap'd memory)
    sq_head: *const AtomicU32,
    sq_tail: *const AtomicU32,
    sq_mask: u32,
    sq_flags: *const AtomicU32,

    // SQE array
    sqes: *mut IoUringSqe,
    sq_tail_local: u32,
    /// Last `sq_tail_local` value that was submitted to the kernel via
    /// `io_uring_enter`. Used to compute `to_submit` without racing the
    /// kernel's `sq_head` after `flush_sq_tail()`.
    sq_submitted: u32,

    // CQ ring pointers (into mmap'd memory)
    cq_head: *const AtomicU32,
    cq_tail: *const AtomicU32,
    cq_mask: u32,
    cqes: *const IoUringCqe,
    cq_head_local: u32,

    // Kernel-reported features
    features: Features,

    /// Raw setup flags this ring was created with. Kept so [`split`](Self::split)
    /// and [`can_split`](Self::can_split) can check thread-affinity
    /// restrictions (`SINGLE_ISSUER` without `SQPOLL`, `DEFER_TASKRUN`)
    /// without needing the caller to remember and re-supply them.
    setup_flags: u32,

    // Shared cleanup resources
    resources: *mut RingResources,
}

// ---------------------------------------------------------------------------
// Submitter / Completer — Send halves produced by IoUring::split
// ---------------------------------------------------------------------------

/// The submission half of a split `io_uring`.
///
/// Produced by [`IoUring::split`]. Owns exclusive access to the submission
/// queue and is `Send`, so it can be moved to a dedicated IO submission thread.
///
/// # Drop
///
/// Dropping the `Submitter` releases its share of the ring resources. The
/// kernel mmaps and fd are freed only when both the `Submitter` and the
/// paired [`Completer`] have been dropped.
pub struct Submitter {
    fd: RawFd,

    sq_head: *const AtomicU32,
    sq_tail: *const AtomicU32,
    sq_mask: u32,
    sq_flags: *const AtomicU32,

    sqes: *mut IoUringSqe,
    sq_tail_local: u32,
    sq_submitted: u32,

    features: Features,

    resources: *mut RingResources,
}

/// The completion half of a split `io_uring`.
///
/// Produced by [`IoUring::split`]. Owns exclusive access to the completion
/// queue and is `Send`, so it can be moved to a dedicated IO completion thread.
///
/// # Waiting for completions
///
/// [`complete`](Self::complete) and [`completions`](Self::completions) are
/// non-blocking: they return what is already in the CQ ring without calling
/// into the kernel. To block until at least `n` completions are ready, use
/// [`wait`](Self::wait), which issues `io_uring_enter(GETEVENTS)` directly.
/// The paired [`Submitter`] does not need to be involved.
///
/// # Drop
///
/// Dropping the `Completer` flushes the CQ head to the kernel and releases its
/// share of the ring resources. The kernel mmaps and fd are freed only when
/// both the paired [`Submitter`] and the `Completer` have been dropped.
pub struct Completer {
    fd: RawFd,

    cq_head: *const AtomicU32,
    cq_tail: *const AtomicU32,
    cq_mask: u32,
    cqes: *const IoUringCqe,
    cq_head_local: u32,

    resources: *mut RingResources,
}

// SAFETY: Submitter owns exclusive access to the SQ-side fields (sq_tail_local,
// sq_submitted) and writes to kernel-shared atomics only through Release stores.
// The raw pointers into mmap'd memory are stable for the lifetime of the ring.
// No other type aliases these fields concurrently without synchronization.
unsafe impl Send for Submitter {}

// SAFETY: Same reasoning for the CQ side. cq_head_local is exclusively owned
// by Completer; the kernel-shared CQ tail is read-only from userspace.
unsafe impl Send for Completer {}

impl Submitter {
    /// Push a prepared SQE onto the submission queue.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Submit`] with [`SubmitError::QueueFull`] when the
    /// submission queue has no free slot.
    #[inline]
    #[allow(clippy::needless_pass_by_value)]
    pub fn push(&mut self, sqe: Sqe) -> Result<(), Error> {
        let head = unsafe { &*self.sq_head }.load(Ordering::Acquire);
        let next_tail = self.sq_tail_local.wrapping_add(1);
        if next_tail.wrapping_sub(head) > self.sq_mask + 1 {
            return Err(SubmitError::QueueFull.into());
        }
        let idx = self.sq_tail_local & self.sq_mask;
        unsafe { *self.sqes.add(idx as usize) = sqe.0 };
        self.sq_tail_local = next_tail;
        Ok(())
    }

    /// Push a NOP onto the submission queue.
    ///
    /// # Errors
    ///
    /// Returns `EAGAIN` if the submission queue is full.
    pub fn push_nop(&mut self, user_data: u64) -> Result<(), Error> {
        self.push(Sqe::nop().user_data(user_data))
    }

    /// Publish the local SQ tail to the kernel-visible atomic.
    #[inline]
    pub fn flush_sq_tail(&self) {
        unsafe { &*self.sq_tail }.store(self.sq_tail_local, Ordering::Release);
    }

    /// Check if the SQPOLL kernel thread needs a wakeup.
    #[must_use]
    pub fn sq_need_wakeup(&self) -> bool {
        const IORING_SQ_NEED_WAKEUP: u32 = 1 << 0;
        let flags = unsafe { &*self.sq_flags }.load(Ordering::Acquire);
        flags & IORING_SQ_NEED_WAKEUP != 0
    }

    /// Returns the feature flags reported by the kernel.
    #[must_use]
    pub const fn features(&self) -> Features {
        self.features
    }

    /// Returns the ring's file descriptor.
    #[must_use]
    pub const fn raw_fd(&self) -> RawFd {
        self.fd
    }

    /// Returns the total number of SQ slots (always a power of two).
    #[must_use]
    pub const fn sq_capacity(&self) -> u32 {
        self.sq_mask + 1
    }

    /// Returns the number of SQ slots available for new submissions.
    #[must_use]
    pub fn sq_space_left(&self) -> u32 {
        let head = unsafe { &*self.sq_head }.load(Ordering::Acquire);
        self.sq_capacity() - self.sq_tail_local.wrapping_sub(head)
    }

    // ── Raw pointer accessors ──────────────────────────────────────

    /// Returns a raw pointer to the SQE array in the mmap'd region.
    #[must_use]
    pub const fn sqe_array_ptr(&self) -> *const IoUringSqe {
        self.sqes
    }

    /// Returns a mutable raw pointer to the SQE array.
    #[must_use]
    pub const fn sqe_array_ptr_mut(&self) -> *mut IoUringSqe {
        self.sqes
    }

    /// Returns a raw pointer to the kernel-shared SQ head atomic.
    #[must_use]
    pub const fn sq_head_ptr(&self) -> *const AtomicU32 {
        self.sq_head
    }

    /// Returns a raw pointer to the kernel-shared SQ tail atomic.
    #[must_use]
    pub const fn sq_tail_ptr(&self) -> *const AtomicU32 {
        self.sq_tail
    }

    /// Returns the SQ ring mask.
    #[must_use]
    pub const fn sq_mask(&self) -> u32 {
        self.sq_mask
    }

    /// Returns a raw pointer to the SQ flags atomic.
    #[must_use]
    pub const fn sq_flags_ptr(&self) -> *const AtomicU32 {
        self.sq_flags
    }

    /// Submit all queued entries to the kernel.
    ///
    /// # Errors
    ///
    /// Returns an error if the kernel rejects the submission.
    #[inline]
    #[allow(clippy::cast_possible_truncation)]
    pub fn submit(&mut self) -> Result<u32, Error> {
        let to_submit = self.sq_tail_local.wrapping_sub(self.sq_submitted);
        self.flush_sq_tail();
        if to_submit == 0 {
            return Ok(0);
        }
        let ret = syscall::io_uring_enter(self.fd, to_submit, 0, EnterFlags::default())?;
        // The kernel may consume fewer than `to_submit` entries in one
        // enter() call (Linux permits partial submission). Advance only
        // by what was actually consumed so the remainder is retried by a
        // later submit() instead of being silently dropped from tracking.
        let consumed = ret as u32;
        self.sq_submitted = self.sq_submitted.wrapping_add(consumed);
        Ok(consumed)
    }

    /// Submit all queued entries and wait for at least `min_complete` completions.
    ///
    /// # Errors
    ///
    /// Returns an error if the kernel rejects the submission.
    #[inline]
    #[allow(clippy::cast_possible_truncation)]
    pub fn submit_and_wait(&mut self, min_complete: u32) -> Result<u32, Error> {
        let to_submit = self.sq_tail_local.wrapping_sub(self.sq_submitted);
        self.flush_sq_tail();
        let ret = syscall::io_uring_enter(self.fd, to_submit, min_complete, EnterFlags::GETEVENTS)?;
        // See `submit`: track actual consumption, not the request size.
        let consumed = ret as u32;
        self.sq_submitted = self.sq_submitted.wrapping_add(consumed);
        Ok(consumed)
    }

    /// Submit in SQPOLL mode, waking the kernel thread if necessary.
    ///
    /// # Errors
    ///
    /// Returns an error if the wakeup syscall fails.
    #[inline]
    pub fn submit_sqpoll(&mut self) -> Result<(), Error> {
        self.flush_sq_tail();
        self.sq_submitted = self.sq_tail_local;
        if self.sq_need_wakeup() {
            syscall::io_uring_enter(self.fd, 0, 0, EnterFlags::SQ_WAKEUP)?;
        }
        Ok(())
    }
}

impl Drop for Submitter {
    fn drop(&mut self) {
        unsafe { RingResources::release(self.resources) };
    }
}

impl Completer {
    /// Returns the ring's file descriptor.
    #[must_use]
    pub const fn raw_fd(&self) -> RawFd {
        self.fd
    }

    /// Returns the total number of CQ slots (always a power of two).
    #[must_use]
    pub const fn cq_capacity(&self) -> u32 {
        self.cq_mask + 1
    }

    // ── Raw pointer accessors ──────────────────────────────────────

    /// Returns a raw pointer to the CQE array in the mmap'd region.
    ///
    /// Each entry is 16 bytes. The array has [`cq_capacity`](Self::cq_capacity) entries.
    #[must_use]
    pub const fn cqe_array_ptr(&self) -> *const IoUringCqe {
        self.cqes
    }

    /// Returns a raw pointer to the kernel-shared CQ head atomic.
    ///
    /// Userspace publishes the head to tell the kernel which CQEs have been consumed.
    #[must_use]
    pub const fn cq_head_ptr(&self) -> *const AtomicU32 {
        self.cq_head
    }

    /// Returns a raw pointer to the kernel-shared CQ tail atomic.
    ///
    /// The kernel advances this as it posts completions.
    #[must_use]
    pub const fn cq_tail_ptr(&self) -> *const AtomicU32 {
        self.cq_tail
    }

    /// Returns the CQ ring mask (`cq_capacity() - 1`).
    #[must_use]
    pub const fn cq_mask(&self) -> u32 {
        self.cq_mask
    }

    /// Reap one completion from the completion queue, if available.
    #[inline]
    #[must_use]
    pub fn complete(&mut self) -> Option<Completion> {
        let tail = unsafe { &*self.cq_tail }.load(Ordering::Acquire);
        if self.cq_head_local == tail {
            return None;
        }
        let idx = self.cq_head_local & self.cq_mask;
        let cqe = unsafe { &*self.cqes.add(idx as usize) };
        let completion = Completion {
            user_data: cqe.user_data,
            result: cqe.res,
            flags: CqeFlags::from_raw(cqe.flags),
        };
        self.cq_head_local = self.cq_head_local.wrapping_add(1);
        Some(completion)
    }

    /// Publish consumed CQ slots back to the kernel.
    #[inline]
    pub fn sync_cq(&self) {
        unsafe { &*self.cq_head }.store(self.cq_head_local, Ordering::Release);
    }

    /// Return an iterator that drains all currently available completions.
    pub const fn completions(&mut self) -> SplitCompletions<'_> {
        SplitCompletions { completer: self }
    }

    /// Block until at least `min_complete` completions are available.
    ///
    /// Issues `io_uring_enter(GETEVENTS)` directly — no submission occurs.
    /// Use this on the completion thread when you want to sleep in the kernel
    /// rather than spin-poll [`complete`](Self::complete).
    ///
    /// After `wait` returns, drain completions with [`complete`](Self::complete)
    /// or [`completions`](Self::completions), then call [`sync_cq`](Self::sync_cq)
    /// to publish the updated head back to the kernel.
    ///
    /// # Errors
    ///
    /// Returns an error if the kernel rejects the `io_uring_enter` call.
    #[inline]
    pub fn wait(&mut self, min_complete: u32) -> Result<(), Error> {
        self.sync_cq();
        syscall::io_uring_enter(self.fd, 0, min_complete, EnterFlags::GETEVENTS)?;
        Ok(())
    }
}

impl Drop for Completer {
    fn drop(&mut self) {
        // Flush CQ head so the kernel can reuse completed slots.
        self.sync_cq();
        unsafe { RingResources::release(self.resources) };
    }
}

/// Iterator over completions from a [`Completer`].
pub struct SplitCompletions<'a> {
    completer: &'a mut Completer,
}

impl Iterator for SplitCompletions<'_> {
    type Item = Completion;

    fn next(&mut self) -> Option<Self::Item> {
        self.completer.complete()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let tail = unsafe { &*self.completer.cq_tail }.load(Ordering::Acquire);
        let pending = tail.wrapping_sub(self.completer.cq_head_local) as usize;
        (pending, None)
    }
}

// ---------------------------------------------------------------------------
// Private helpers extracted from IoUring::from_params to keep it short.
// ---------------------------------------------------------------------------

/// Compute the byte size of a ring region: a base `offset` (the kernel's
/// position of the trailing array within the ring) plus `count` elements of
/// `elem_size` bytes.
///
/// This is the one audited place where the kernel's `u32` ABI fields are
/// widened to `usize` for size arithmetic. The widening is always lossless:
/// `u32` fits in `usize` on every supported target (`usize` is 32 bits on
/// `arm`, 64 on the rest), so a plain `as usize` cannot truncate. Centralizing
/// it here keeps the size formulas free of inline casts.
#[allow(clippy::cast_possible_truncation)]
const fn ring_bytes(offset: u32, count: u32, elem_size: usize) -> usize {
    offset as usize + count as usize * elem_size
}

/// Map the SQ ring, CQ ring, and SQE array for a freshly set-up ring fd.
///
/// Returns `(sq_ring_ptr, mmap_sz, cq_ring_ptr, cq_ring_region, sqes_ptr, sqes_sz)`.
/// On success the caller owns all three mappings; on error the `guard` cleans them up.
#[allow(clippy::cast_ptr_alignment)]
fn map_rings(
    fd: RawFd,
    params: &IoUringParams,
    features: Features,
    guard: &mut SetupGuard,
) -> Result<(usize, usize, usize, MappedRegion, usize, usize), Error> {
    let prot = Prot::READ | Prot::WRITE;
    let map = MapFlags::SHARED | MapFlags::POPULATE;

    let sq_ring_sz = ring_bytes(
        params.sq_off.array,
        params.sq_entries,
        core::mem::size_of::<u32>(),
    );
    let cq_ring_sz = ring_bytes(
        params.cq_off.cqes,
        params.cq_entries,
        core::mem::size_of::<IoUringCqe>(),
    );

    let single_mmap = features.contains(Features::SINGLE_MMAP);
    let mmap_sz = if single_mmap {
        sq_ring_sz.max(cq_ring_sz)
    } else {
        sq_ring_sz
    };

    let sq_ring_ptr = syscall::mmap(
        0,
        mmap_sz,
        prot,
        map,
        fd.as_usize(),
        RingOffset::SqRing.into(),
    )?;
    guard.sq_ring = MappedRegion::new(sq_ring_ptr, mmap_sz);

    let (cq_ring_ptr, cq_ring_region) = if single_mmap {
        (sq_ring_ptr, MappedRegion::new(0, 0))
    } else {
        let ptr = syscall::mmap(
            0,
            cq_ring_sz,
            prot,
            map,
            fd.as_usize(),
            RingOffset::CqRing.into(),
        )?;
        guard.cq_ring = MappedRegion::new(ptr, cq_ring_sz);
        (ptr, MappedRegion::new(ptr, cq_ring_sz))
    };

    let sqes_sz = ring_bytes(0, params.sq_entries, core::mem::size_of::<IoUringSqe>());
    let sqes_ptr = syscall::mmap(
        0,
        sqes_sz,
        prot,
        map,
        fd.as_usize(),
        RingOffset::Sqes.into(),
    )?;
    guard.sqes = MappedRegion::new(sqes_ptr, sqes_sz);

    Ok((
        sq_ring_ptr,
        mmap_sz,
        cq_ring_ptr,
        cq_ring_region,
        sqes_ptr,
        sqes_sz,
    ))
}

/// Parse SQ-side pointers out of the mapped SQ ring region.
///
/// Returns `(sq_head, sq_tail, sq_mask, sq_flags, sqes, sq_tail_local)`.
///
/// # Safety
///
/// `sq_ring_ptr` must point to a valid SQ ring mmap and `sqes_ptr` to the SQE array mmap,
/// both sized according to `params`. Pointers remain valid for the life of the ring.
#[allow(clippy::cast_ptr_alignment, clippy::type_complexity)]
unsafe fn parse_sq(
    sq_ring_ptr: usize,
    sqes_ptr: usize,
    params: &IoUringParams,
) -> (
    *const AtomicU32,
    *const AtomicU32,
    u32,
    *const AtomicU32,
    *mut IoUringSqe,
    u32,
) {
    let base = sq_ring_ptr as *const u8;
    let sq_head = unsafe { base.add(params.sq_off.head as usize) }.cast::<AtomicU32>();
    let sq_tail = unsafe { base.add(params.sq_off.tail as usize) }.cast::<AtomicU32>();
    let sq_mask = unsafe { *base.add(params.sq_off.ring_mask as usize).cast::<u32>() };
    let sq_flags = unsafe { base.add(params.sq_off.flags as usize) }.cast::<AtomicU32>();
    let sq_array = unsafe { base.add(params.sq_off.array as usize) } as *mut u32;

    debug_assert!(sq_head.is_aligned(), "sq_head not aligned");
    debug_assert!(sq_tail.is_aligned(), "sq_tail not aligned");
    debug_assert!(sq_flags.is_aligned(), "sq_flags not aligned");
    debug_assert!(sq_array.is_aligned(), "sq_array not aligned");

    // Pre-fill sq_array with identity mapping (sq_array[i] = i).
    //
    // The kernel reads sq_array[tail & mask] to find which SQE slot to
    // consume. Because push() always writes sqes[tail & mask] and the
    // identity mapping means sq_array[j] == j for all j < sq_entries,
    // the kernel always picks up the right slot without us ever
    // touching sq_array again.
    //
    // SAFETY: this invariant breaks if push() ever writes to a slot
    // other than (tail & mask), or if SQE reordering is added later.
    for i in 0..params.sq_entries {
        unsafe { sq_array.add(i as usize).write(i) };
    }

    let sq_tail_local = unsafe { &*sq_tail }.load(Ordering::Acquire);
    let sqes = sqes_ptr as *mut IoUringSqe;

    (sq_head, sq_tail, sq_mask, sq_flags, sqes, sq_tail_local)
}

/// Parse CQ-side pointers out of the mapped CQ ring region.
///
/// Returns `(cq_head, cq_tail, cq_mask, cqes, cq_head_local)`.
///
/// # Safety
///
/// `cq_ring_ptr` must point to a valid CQ ring mmap sized according to `params`.
#[allow(clippy::cast_ptr_alignment, clippy::type_complexity)]
unsafe fn parse_cq(
    cq_ring_ptr: usize,
    params: &IoUringParams,
) -> (
    *const AtomicU32,
    *const AtomicU32,
    u32,
    *const IoUringCqe,
    u32,
) {
    let base = cq_ring_ptr as *const u8;
    let cq_head = unsafe { base.add(params.cq_off.head as usize) }.cast::<AtomicU32>();
    let cq_tail = unsafe { base.add(params.cq_off.tail as usize) }.cast::<AtomicU32>();
    let cq_mask = unsafe { *base.add(params.cq_off.ring_mask as usize).cast::<u32>() };
    let cqes = unsafe { base.add(params.cq_off.cqes as usize) }.cast::<IoUringCqe>();

    debug_assert!(cq_head.is_aligned(), "cq_head not aligned");
    debug_assert!(cq_tail.is_aligned(), "cq_tail not aligned");
    debug_assert!(cqes.is_aligned(), "cqes not aligned");

    let cq_head_local = unsafe { &*cq_head }.load(Ordering::Acquire);
    (cq_head, cq_tail, cq_mask, cqes, cq_head_local)
}

impl IoUring {
    /// Create a new `io_uring` instance with the given queue depth.
    ///
    /// `entries` will be rounded up to the next power of two by the kernel.
    /// For more control over setup parameters, use [`IoUringBuilder`].
    ///
    /// # Errors
    ///
    /// Returns an error if the kernel rejects the setup or memory mapping fails.
    pub fn new(entries: u32) -> Result<Self, Error> {
        IoUringBuilder::new(entries).build()
    }

    /// Start building a configured `io_uring` instance.
    #[must_use]
    pub fn builder(entries: u32) -> IoUringBuilder {
        IoUringBuilder::new(entries)
    }

    /// Returns the feature flags reported by the kernel.
    #[must_use]
    pub const fn features(&self) -> Features {
        self.features
    }

    /// Returns the ring's file descriptor.
    #[must_use]
    pub const fn raw_fd(&self) -> RawFd {
        self.fd
    }

    /// Returns the total number of SQ slots (always a power of two).
    #[must_use]
    pub const fn sq_capacity(&self) -> u32 {
        self.sq_mask + 1
    }

    /// Returns the number of SQ slots available for new submissions.
    #[must_use]
    pub fn sq_space_left(&self) -> u32 {
        let head = unsafe { &*self.sq_head }.load(Ordering::Acquire);
        self.sq_capacity() - self.sq_tail_local.wrapping_sub(head)
    }

    // ── Raw pointer accessors ──────────────────────────────────────
    //
    // Expose the mmap'd ring memory so external lock-free protocols
    // (e.g. quetzalcoatl-uring) can operate directly on the kernel-
    // shared buffers. The pointers are valid for the lifetime of the
    // ring (guaranteed by the `RingResources` refcount).

    /// Returns a raw pointer to the SQE array in the mmap'd region.
    ///
    /// Each entry is 64 bytes. The array has [`sq_capacity`](Self::sq_capacity) entries.
    #[must_use]
    pub const fn sqe_array_ptr(&self) -> *const IoUringSqe {
        self.sqes
    }

    /// Returns a mutable raw pointer to the SQE array.
    #[must_use]
    pub const fn sqe_array_ptr_mut(&self) -> *mut IoUringSqe {
        self.sqes
    }

    /// Returns a raw pointer to the kernel-shared SQ head atomic.
    ///
    /// The kernel advances this as it consumes SQEs.
    #[must_use]
    pub const fn sq_head_ptr(&self) -> *const AtomicU32 {
        self.sq_head
    }

    /// Returns a raw pointer to the kernel-shared SQ tail atomic.
    ///
    /// Userspace publishes the tail to tell the kernel which SQEs are ready.
    #[must_use]
    pub const fn sq_tail_ptr(&self) -> *const AtomicU32 {
        self.sq_tail
    }

    /// Returns the SQ ring mask (`sq_capacity() - 1`).
    #[must_use]
    pub const fn sq_mask(&self) -> u32 {
        self.sq_mask
    }

    /// Returns a raw pointer to the SQ flags atomic.
    #[must_use]
    pub const fn sq_flags_ptr(&self) -> *const AtomicU32 {
        self.sq_flags
    }

    /// Returns the total number of CQ slots (always a power of two).
    #[must_use]
    pub const fn cq_capacity(&self) -> u32 {
        self.cq_mask + 1
    }

    /// Check if the CQ ring has overflowed.
    ///
    /// This happens when the kernel has more completions than the CQ can hold.
    /// When this returns `true`, completions may have been lost. Drain the CQ
    /// and call [`submit_and_wait`](Self::submit_and_wait) to flush the backlog.
    #[must_use]
    pub fn cq_overflow(&self) -> bool {
        const IORING_SQ_CQ_OVERFLOW: u32 = 1 << 1;
        let flags = unsafe { &*self.sq_flags }.load(Ordering::Acquire);
        flags & IORING_SQ_CQ_OVERFLOW != 0
    }

    /// Returns a raw pointer to the CQE array in the mmap'd region.
    ///
    /// Each entry is 16 bytes. The array has [`cq_capacity`](Self::cq_capacity) entries.
    #[must_use]
    pub const fn cqe_array_ptr(&self) -> *const IoUringCqe {
        self.cqes
    }

    /// Returns a raw pointer to the kernel-shared CQ head atomic.
    ///
    /// Userspace publishes the head to tell the kernel which CQEs have been consumed.
    #[must_use]
    pub const fn cq_head_ptr(&self) -> *const AtomicU32 {
        self.cq_head
    }

    /// Returns a raw pointer to the kernel-shared CQ tail atomic.
    ///
    /// The kernel advances this as it posts completions.
    #[must_use]
    pub const fn cq_tail_ptr(&self) -> *const AtomicU32 {
        self.cq_tail
    }

    /// Returns the CQ ring mask (`cq_capacity() - 1`).
    #[must_use]
    pub const fn cq_mask(&self) -> u32 {
        self.cq_mask
    }

    /// Check if the SQPOLL kernel thread needs a wakeup.
    ///
    /// Only meaningful when the ring was created with [`IoUringBuilder::sqpoll`].
    /// When this returns `true`, call [`submit_sqpoll`](Self::submit_sqpoll) or
    /// use `io_uring_enter` with `SQ_WAKEUP` to kick the kernel thread.
    #[must_use]
    pub fn sq_need_wakeup(&self) -> bool {
        const IORING_SQ_NEED_WAKEUP: u32 = 1 << 0;
        let flags = unsafe { &*self.sq_flags }.load(Ordering::Acquire);
        flags & IORING_SQ_NEED_WAKEUP != 0
    }

    pub(super) fn from_params(entries: u32, params: &mut IoUringParams) -> Result<Self, Error> {
        let unsupported = params.flags & !SetupFlags::SUPPORTED_MASK.bits();
        if unsupported != 0 {
            return Err(
                SetupError::InvalidArg(InvalidArgKind::UnsupportedSetupFlags(unsupported)).into(),
            );
        }

        let setup_flags = params.flags;

        let fd = syscall::io_uring_setup(entries, &raw mut *params)?;
        let mut guard = SetupGuard::new(fd);

        let features = Features::from_raw(params.features);
        let (sq_ring_ptr, mmap_sz, cq_ring_ptr, cq_ring_region, sqes_ptr, sqes_sz) =
            map_rings(fd, params, features, &mut guard)?;

        let (sq_head, sq_tail, sq_mask, sq_flags, sqes, sq_tail_local) =
            // SAFETY: sq_ring_ptr points to a valid mmap of at least sq_ring_sz bytes.
            unsafe { parse_sq(sq_ring_ptr, sqes_ptr, params) };

        let (cq_head, cq_tail, cq_mask, cqes, cq_head_local) =
            // SAFETY: cq_ring_ptr points to a valid mmap of at least cq_ring_sz bytes.
            unsafe { parse_cq(cq_ring_ptr, params) };

        // Keep `guard` armed across `RingResources::alloc`: it already
        // tracks the CQ mapping correctly (set by `map_rings` only in the
        // non-`SINGLE_MMAP` fallback layout, where the CQ is a separate
        // mmap from the SQ ring), so an allocation failure here is cleaned
        // up by `guard`'s own `Drop` rather than by a second, easy-to-miss
        // manual unwind that would otherwise have to duplicate that same
        // single-vs-dual-mapping distinction.
        let resources = RingResources::alloc(
            fd,
            MappedRegion::new(sq_ring_ptr, mmap_sz),
            cq_ring_region,
            MappedRegion::new(sqes_ptr, sqes_sz),
        )?;

        // Resources are now owned by the refcounted `RingResources` page;
        // `guard` must not free them a second time.
        guard.disarm();

        Ok(Self {
            fd,
            sq_head,
            sq_tail,
            sq_mask,
            sq_flags,
            sqes,
            sq_tail_local,
            sq_submitted: sq_tail_local,
            cq_head,
            cq_tail,
            cq_mask,
            cqes,
            cq_head_local,
            features,
            setup_flags,
            resources,
        })
    }

    /// Push a prepared SQE onto the submission queue.
    ///
    /// The SQE is not visible to the kernel until [`submit`](Self::submit) or
    /// [`submit_and_wait`](Self::submit_and_wait) is called. Pushed SQEs are
    /// silently lost if the ring is dropped without submitting.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Submit`] with [`SubmitError::QueueFull`] when the
    /// submission queue has no free slot.
    #[inline]
    #[allow(clippy::needless_pass_by_value)]
    pub fn push(&mut self, sqe: Sqe) -> Result<(), Error> {
        let head = unsafe { &*self.sq_head }.load(Ordering::Acquire);
        let next_tail = self.sq_tail_local.wrapping_add(1);

        if next_tail.wrapping_sub(head) > self.sq_mask + 1 {
            return Err(SubmitError::QueueFull.into());
        }

        let idx = self.sq_tail_local & self.sq_mask;

        unsafe { *self.sqes.add(idx as usize) = sqe.0 };

        self.sq_tail_local = next_tail;

        Ok(())
    }

    /// Push a NOP operation onto the submission queue.
    ///
    /// Convenience wrapper around `push(Sqe::nop().user_data(user_data))`.
    ///
    /// # Errors
    ///
    /// Returns `EAGAIN` if the submission queue is full.
    pub fn push_nop(&mut self, user_data: u64) -> Result<(), Error> {
        self.push(Sqe::nop().user_data(user_data))
    }

    /// Publish the local SQ tail to the kernel-visible atomic tail.
    ///
    /// Called automatically by `submit`, `submit_and_wait`, and `submit_sqpoll`.
    /// Call directly only if you need fine-grained control in SQPOLL mode.
    #[inline]
    pub fn flush_sq_tail(&self) {
        unsafe { &*self.sq_tail }.store(self.sq_tail_local, Ordering::Release);
    }

    /// Submit all queued entries to the kernel.
    ///
    /// Returns the number of entries actually consumed by this call, which
    /// can be less than the number pushed since the kernel is allowed to
    /// submit a short batch (e.g. if one entry in the middle errors and the
    /// ring was not created with `IORING_SETUP_SUBMIT_ALL`). Entries beyond
    /// the returned count remain queued and are retried by the next call to
    /// [`submit`](Self::submit) or [`submit_and_wait`](Self::submit_and_wait)
    /// — they are not lost, but they also do not execute until a later call
    /// picks them up.
    ///
    /// **SQPOLL note:** In SQPOLL mode the kernel thread consumes SQEs
    /// asynchronously. This method issues a plain `io_uring_enter` which
    /// may not wake a sleeping SQPOLL thread. Use
    /// [`submit_sqpoll`](Self::submit_sqpoll) instead.
    ///
    /// # Errors
    ///
    /// Returns an error if the kernel rejects the submission.
    #[inline]
    #[allow(clippy::cast_possible_truncation)]
    pub fn submit(&mut self) -> Result<u32, Error> {
        // Snapshot the count *before* publishing the tail. After
        // flush_sq_tail() the kernel may start consuming entries
        // immediately, advancing sq_head — reading head after the
        // flush would race and undercount.
        let to_submit = self.sq_tail_local.wrapping_sub(self.sq_submitted);
        self.flush_sq_tail();
        if to_submit == 0 {
            return Ok(0);
        }
        let ret = syscall::io_uring_enter(self.fd, to_submit, 0, EnterFlags::default())?;
        // The kernel may consume fewer than `to_submit` entries in one
        // enter() call (Linux permits partial submission). Advance only
        // by what was actually consumed so the remainder is retried by a
        // later submit() instead of being silently dropped from tracking.
        let consumed = ret as u32;
        self.sq_submitted = self.sq_submitted.wrapping_add(consumed);
        self.flush_cq_head();
        Ok(consumed)
    }

    /// Submit all queued entries and wait for at least `min_complete` completions.
    ///
    /// Returns the number of entries actually consumed across the enter
    /// call(s) this method makes — see [`submit`](Self::submit) for why that
    /// can be less than what was pushed, and what happens to the remainder.
    ///
    /// **Important:** Unlike [`submit`](Self::submit), this method always calls
    /// `io_uring_enter` — even when no entries have been pushed — because it
    /// needs to wait for `min_complete` completions. If you call this with
    /// `min_complete > 0` and no completions are forthcoming (e.g., you forgot
    /// to push any SQEs), it will block indefinitely.
    ///
    /// **Backpressure safety:** When the CQ is more than 3/4 full this method
    /// first issues a non-blocking `io_uring_enter` (without GETEVENTS) to give
    /// the kernel a chance to flush its internal CQ overflow list into the now-
    /// free slots.  Without this, a thread that holds the ring's only reference
    /// and blocks in GETEVENTS can deadlock: the kernel waits for CQ space, but
    /// CQ space is only freed by the next `sync_cq` + `io_uring_enter` call on
    /// the same thread.
    ///
    /// **SQPOLL note:** In SQPOLL mode the kernel thread consumes SQEs
    /// asynchronously. This method issues a plain `io_uring_enter` which
    /// may not wake a sleeping SQPOLL thread. Use
    /// [`submit_sqpoll`](Self::submit_sqpoll) instead.
    ///
    /// # Errors
    ///
    /// Returns an error if the kernel rejects the submission.
    #[inline]
    #[allow(clippy::cast_possible_truncation)]
    pub fn submit_and_wait(&mut self, min_complete: u32) -> Result<u32, Error> {
        self.flush_cq_head();
        let to_submit = self.sq_tail_local.wrapping_sub(self.sq_submitted);
        self.flush_sq_tail();

        // Backpressure safety valve: if the CQ is more than 3/4 full,
        // issue a non-blocking enter first so the kernel can flush its
        // overflow list into the newly-freed CQ slots before we block.
        let cq_tail = unsafe { &*self.cq_tail }.load(Ordering::Acquire);
        let cq_used = cq_tail.wrapping_sub(self.cq_head_local);
        let cq_cap = self.cq_mask + 1;
        if cq_used > cq_cap - (cq_cap / 4) {
            let first_ret = syscall::io_uring_enter(self.fd, to_submit, 0, EnterFlags::default())?;
            // Track actual consumption, not the request size — and do not
            // discard this call's return value: it is real submission
            // progress and must be reflected in both `sq_submitted` and
            // the count this method reports back to the caller.
            let first_consumed = first_ret as u32;
            self.sq_submitted = self.sq_submitted.wrapping_add(first_consumed);
            // After the non-blocking enter, the kernel has had a
            // chance to flush the overflow list.  Now wait for the
            // completions. `to_submit` is 0 here, so this call normally
            // consumes nothing further, but fold in whatever it reports
            // rather than assuming that.
            let second_ret =
                syscall::io_uring_enter(self.fd, 0, min_complete, EnterFlags::GETEVENTS)?;
            let second_consumed = second_ret as u32;
            self.sq_submitted = self.sq_submitted.wrapping_add(second_consumed);
            return Ok(first_consumed.wrapping_add(second_consumed));
        }

        let ret = syscall::io_uring_enter(self.fd, to_submit, min_complete, EnterFlags::GETEVENTS)?;
        let consumed = ret as u32;
        self.sq_submitted = self.sq_submitted.wrapping_add(consumed);
        Ok(consumed)
    }

    /// Submit queued entries in SQPOLL mode.
    ///
    /// Publishes the SQ tail so the kernel polling thread sees new entries.
    /// If the polling thread has gone to sleep, wakes it with `io_uring_enter`.
    ///
    /// Unlike [`submit`](Self::submit), this avoids a syscall when the kernel
    /// thread is already running.
    ///
    /// # Errors
    ///
    /// Returns an error if the wakeup `io_uring_enter` call fails.
    #[inline]
    pub fn submit_sqpoll(&mut self) -> Result<(), Error> {
        self.flush_sq_tail();
        self.sq_submitted = self.sq_tail_local;
        if self.sq_need_wakeup() {
            syscall::io_uring_enter(self.fd, 0, 0, EnterFlags::SQ_WAKEUP)?;
        }
        Ok(())
    }

    /// Publish the local CQ head to the kernel-visible atomic head.
    ///
    /// Called automatically by [`submit_and_wait`](Self::submit_and_wait)
    /// and `Drop`. Call explicitly after draining completions if you need
    /// the kernel to see freed CQ slots before the next
    /// [`submit`](Self::submit) (which does *not* auto-flush).
    #[inline]
    fn flush_cq_head(&self) {
        unsafe { &*self.cq_head }.store(self.cq_head_local, Ordering::Release);
    }

    /// Reap one completion from the completion queue, if available.
    ///
    /// The CQ head is not published to the kernel until [`flush_cq_head`](Self::flush_cq_head)
    /// is called or the ring is dropped. This avoids a costly Release store on every completion.
    #[inline]
    #[must_use]
    pub fn complete(&mut self) -> Option<Completion> {
        let tail = unsafe { &*self.cq_tail }.load(Ordering::Acquire);

        if self.cq_head_local == tail {
            return None;
        }

        let idx = self.cq_head_local & self.cq_mask;
        let cqe = unsafe { &*self.cqes.add(idx as usize) };
        let completion = Completion {
            user_data: cqe.user_data,
            result: cqe.res,
            flags: CqeFlags::from_raw(cqe.flags),
        };

        self.cq_head_local = self.cq_head_local.wrapping_add(1);

        Some(completion)
    }

    /// Publish the local CQ head to the kernel, making consumed CQ slots
    /// available for new completions.
    ///
    /// Call this after draining completions if you're worried about the CQ
    /// filling up. It's also called automatically in `Drop`.
    #[inline]
    pub fn sync_cq(&self) {
        self.flush_cq_head();
    }

    /// Return an iterator that drains all available completions.
    pub const fn completions(&mut self) -> Completions<'_> {
        Completions { ring: self }
    }

    /// Returns `true` if this ring's setup flags permit [`split`](Self::split).
    ///
    /// `split` hands out `Send` `Submitter`/`Completer` halves, inviting the
    /// caller to move submission and completion to separate OS threads. Two
    /// setup modes make that unsound to promise:
    ///
    /// - `DEFER_TASKRUN` requires every `io_uring_enter(GETEVENTS)` call
    ///   (which `Completer::wait` and both `submit_and_wait` methods issue)
    ///   to run on the thread that created or enabled the ring. A `Completer`
    ///   moved to a different thread would violate that unconditionally.
    /// - `SINGLE_ISSUER` without `SQPOLL` restricts *submission* to a single
    ///   userspace thread; the kernel fails competing submitters with
    ///   `-EEXIST`. With `SQPOLL` this restriction is satisfied by the
    ///   kernel's own polling thread regardless of which userspace thread
    ///   calls `io_uring_enter`, so that combination is fine to split.
    #[must_use]
    pub const fn can_split(&self) -> bool {
        !Self::setup_flags_forbid_split(self.setup_flags)
    }

    /// Shared by `can_split` and `split`'s guard so the rule lives in one place.
    const fn setup_flags_forbid_split(setup_flags: u32) -> bool {
        let sqpoll = setup_flags & SetupFlags::SQPOLL.bits() != 0;
        let single_issuer = setup_flags & SetupFlags::SINGLE_ISSUER.bits() != 0;
        let defer_taskrun = setup_flags & SetupFlags::DEFER_TASKRUN.bits() != 0;
        defer_taskrun || (single_issuer && !sqpoll)
    }

    /// Split the ring into a [`Submitter`] and a [`Completer`].
    ///
    /// Both halves are `Send` and can be moved to separate threads. The
    /// underlying kernel resources (fd and mmap regions) are freed only
    /// when **both** halves have been dropped.
    ///
    /// `self` is consumed on success — use the returned halves instead of
    /// the original `IoUring`. On rejection `self` is returned back to the
    /// caller unchanged, so a caller that wants to keep using the ring
    /// single-threaded after a failed split does not lose it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Setup`](crate::Error::Setup) wrapping
    /// [`InvalidArgKind::IncompatibleSplit`](crate::InvalidArgKind::IncompatibleSplit)
    /// if the ring's setup flags restrict submission or completion to the
    /// creating thread — see [`can_split`](Self::can_split) for exactly
    /// which combinations that covers.
    pub fn split(self) -> Result<(Submitter, Completer), (Self, Error)> {
        if Self::setup_flags_forbid_split(self.setup_flags) {
            let err =
                SetupError::InvalidArg(InvalidArgKind::IncompatibleSplit(self.setup_flags)).into();
            return Err((self, err));
        }

        // Bump refcount: resources starts at 1 (from IoUring), we need 2.
        unsafe { RingResources::retain(self.resources) };

        let submitter = Submitter {
            fd: self.fd,
            sq_head: self.sq_head,
            sq_tail: self.sq_tail,
            sq_mask: self.sq_mask,
            sq_flags: self.sq_flags,
            sqes: self.sqes,
            sq_tail_local: self.sq_tail_local,
            sq_submitted: self.sq_submitted,
            features: self.features,
            resources: self.resources,
        };

        let completer = Completer {
            fd: self.fd,
            cq_head: self.cq_head,
            cq_tail: self.cq_tail,
            cq_mask: self.cq_mask,
            cqes: self.cqes,
            cq_head_local: self.cq_head_local,
            resources: self.resources,
        };

        // Don't run IoUring's Drop — the two halves now own the resources.
        core::mem::forget(self);

        Ok((submitter, completer))
    }
}

/// An iterator that drains available completions from the ring.
pub struct Completions<'a> {
    ring: &'a mut IoUring,
}

impl Iterator for Completions<'_> {
    type Item = Completion;

    fn next(&mut self) -> Option<Self::Item> {
        self.ring.complete()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let tail = unsafe { &*self.ring.cq_tail }.load(Ordering::Acquire);
        let pending = tail.wrapping_sub(self.ring.cq_head_local) as usize;
        // Lower bound is what's visible now; upper is unknown (more may arrive).
        (pending, None)
    }
}

impl Drop for IoUring {
    fn drop(&mut self) {
        self.flush_cq_head();
        unsafe { RingResources::release(self.resources) };
    }
}
