use crate::error::Error;
use crate::op::Sqe;
use crate::syscall;
use crate::types::{
    CqeFlags, EnterFlags, Features, IoUringCqe, IoUringParams, IoUringSqe, IoVec, MapFlags, Prot,
    RegisterOp, RingOffset, SetupFlags,
};
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

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
    fd: usize,
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
        fd: usize,
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
    /// Returns `Error` when the kernel reported a negative errno.
    #[allow(clippy::cast_sign_loss)]
    pub const fn into_result(&self) -> Result<u32, Error> {
        if self.result < 0 {
            Err(Error(-self.result))
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
    fd: usize,
    sq_ring: MappedRegion,
    cq_ring: MappedRegion,
    sqes: MappedRegion,
}

impl SetupGuard {
    const fn new(fd: usize) -> Self {
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
/// both of which are `Send`.
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
    fd: usize,

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
    fd: usize,

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
/// # Drop
///
/// Dropping the `Completer` flushes the CQ head to the kernel and releases its
/// share of the ring resources. The kernel mmaps and fd are freed only when
/// both the paired [`Submitter`] and the `Completer` have been dropped.
pub struct Completer {
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
    /// Returns `EAGAIN` if the submission queue is full.
    #[inline]
    #[allow(clippy::needless_pass_by_value)]
    pub fn push(&mut self, sqe: Sqe) -> Result<(), Error> {
        let head = unsafe { &*self.sq_head }.load(Ordering::Acquire);
        let next_tail = self.sq_tail_local.wrapping_add(1);
        if next_tail.wrapping_sub(head) > self.sq_mask + 1 {
            return Err(Error::EAGAIN);
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
        self.sq_submitted = self.sq_tail_local;
        Ok(ret as u32)
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
        self.sq_submitted = self.sq_tail_local;
        Ok(ret as u32)
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

    #[allow(clippy::cast_ptr_alignment)]
    fn from_params(entries: u32, params: &mut IoUringParams) -> Result<Self, Error> {
        let prot = Prot::READ | Prot::WRITE;
        let map = MapFlags::SHARED | MapFlags::POPULATE;

        let fd = syscall::io_uring_setup(entries, &raw mut *params)?;
        let mut guard = SetupGuard::new(fd);

        let features = Features::from_raw(params.features);
        let single_mmap = features.contains(Features::SINGLE_MMAP);

        // Compute ring sizes
        let sq_ring_sz =
            params.sq_off.array as usize + params.sq_entries as usize * core::mem::size_of::<u32>();
        let cq_ring_sz = params.cq_off.cqes as usize
            + params.cq_entries as usize * core::mem::size_of::<IoUringCqe>();

        // Map the SQ ring (and CQ ring too if SINGLE_MMAP)
        let mmap_sz = if single_mmap {
            sq_ring_sz.max(cq_ring_sz)
        } else {
            sq_ring_sz
        };
        let sq_ring_ptr = syscall::mmap(0, mmap_sz, prot, map, fd, RingOffset::SqRing.into())?;
        guard.sq_ring = MappedRegion::new(sq_ring_ptr, mmap_sz);

        // Map the CQ ring (reuse SQ mmap if SINGLE_MMAP)
        let (cq_ring_ptr, cq_ring_region) = if single_mmap {
            (sq_ring_ptr, MappedRegion::new(0, 0))
        } else {
            let ptr = syscall::mmap(0, cq_ring_sz, prot, map, fd, RingOffset::CqRing.into())?;
            let region = MappedRegion::new(ptr, cq_ring_sz);
            guard.cq_ring = MappedRegion::new(ptr, cq_ring_sz);
            (ptr, region)
        };

        // Map the SQE array
        let sqes_sz = params.sq_entries as usize * core::mem::size_of::<IoUringSqe>();
        let sqes_ptr = syscall::mmap(0, sqes_sz, prot, map, fd, RingOffset::Sqes.into())?;
        guard.sqes = MappedRegion::new(sqes_ptr, sqes_sz);

        let sq_base = sq_ring_ptr as *const u8;
        let sq_head = unsafe { sq_base.add(params.sq_off.head as usize) }.cast::<AtomicU32>();
        let sq_tail = unsafe { sq_base.add(params.sq_off.tail as usize) }.cast::<AtomicU32>();
        let sq_mask = unsafe { *sq_base.add(params.sq_off.ring_mask as usize).cast::<u32>() };
        let sq_flags = unsafe { sq_base.add(params.sq_off.flags as usize) }.cast::<AtomicU32>();
        let sq_array = unsafe { sq_base.add(params.sq_off.array as usize) } as *mut u32;

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

        let cq_base = cq_ring_ptr as *const u8;
        let cq_head = unsafe { cq_base.add(params.cq_off.head as usize) }.cast::<AtomicU32>();
        let cq_tail = unsafe { cq_base.add(params.cq_off.tail as usize) }.cast::<AtomicU32>();
        let cq_mask = unsafe { *cq_base.add(params.cq_off.ring_mask as usize).cast::<u32>() };
        let cqes = unsafe { cq_base.add(params.cq_off.cqes as usize) }.cast::<IoUringCqe>();

        debug_assert!(cq_head.is_aligned(), "cq_head not aligned");
        debug_assert!(cq_tail.is_aligned(), "cq_tail not aligned");
        debug_assert!(cqes.is_aligned(), "cqes not aligned");

        let sq_tail_local = unsafe { &*sq_tail }.load(Ordering::Acquire);
        let cq_head_local = unsafe { &*cq_head }.load(Ordering::Acquire);

        // All resources acquired — disarm the guard and hand them to
        // RingResources. If alloc fails the guard would have already been
        // disarmed, so we re-clean manually on error.
        guard.disarm();

        let resources = match RingResources::alloc(
            fd,
            MappedRegion::new(sq_ring_ptr, mmap_sz),
            cq_ring_region,
            MappedRegion::new(sqes_ptr, sqes_sz),
        ) {
            Ok(r) => r,
            Err(e) => {
                let _ = syscall::munmap(sqes_ptr, sqes_sz);
                let _ = syscall::munmap(sq_ring_ptr, mmap_sz);
                let _ = syscall::close(fd);
                return Err(e);
            }
        };

        Ok(Self {
            fd,
            sq_head,
            sq_tail,
            sq_mask,
            sq_flags,
            sqes: sqes_ptr as *mut IoUringSqe,
            sq_tail_local,
            sq_submitted: sq_tail_local,
            cq_head,
            cq_tail,
            cq_mask,
            cqes,
            cq_head_local,
            features,
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
    /// Returns `EAGAIN` if the submission queue is full.
    #[inline]
    #[allow(clippy::needless_pass_by_value)]
    pub fn push(&mut self, sqe: Sqe) -> Result<(), Error> {
        let head = unsafe { &*self.sq_head }.load(Ordering::Acquire);
        let next_tail = self.sq_tail_local.wrapping_add(1);

        if next_tail.wrapping_sub(head) > self.sq_mask + 1 {
            return Err(Error::EAGAIN);
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
    /// Returns the number of entries submitted.
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
        self.flush_cq_head();
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
        self.sq_submitted = self.sq_tail_local;
        Ok(ret as u32)
    }

    /// Submit all queued entries and wait for at least `min_complete` completions.
    ///
    /// Returns the number of entries submitted.
    ///
    /// **Important:** Unlike [`submit`](Self::submit), this method always calls
    /// `io_uring_enter` — even when no entries have been pushed — because it
    /// needs to wait for `min_complete` completions. If you call this with
    /// `min_complete > 0` and no completions are forthcoming (e.g., you forgot
    /// to push any SQEs), it will block indefinitely.
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
        let ret = syscall::io_uring_enter(self.fd, to_submit, min_complete, EnterFlags::GETEVENTS)?;
        self.sq_submitted = self.sq_tail_local;
        Ok(ret as u32)
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
        self.flush_cq_head();
        self.flush_sq_tail();
        self.sq_submitted = self.sq_tail_local;
        if self.sq_need_wakeup() {
            syscall::io_uring_enter(self.fd, 0, 0, EnterFlags::SQ_WAKEUP)?;
        }
        Ok(())
    }

    /// Publish the local CQ head to the kernel-visible atomic head.
    ///
    /// Called automatically by `submit`, `submit_and_wait`, `submit_sqpoll`,
    /// and `Drop`. Call explicitly after draining completions if you need the
    /// kernel to see freed CQ slots before the next submission.
    #[inline]
    fn flush_cq_head(&self) {
        unsafe { &*self.cq_head }.store(self.cq_head_local, Ordering::Release);
    }

    /// Reap one completion from the completion queue, if available.
    ///
    /// The CQ head is not published to the kernel until the next `submit`,
    /// `submit_and_wait`, or when the ring is dropped. This avoids a
    /// costly Release store on every completion.
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

    /// Register buffers for zero-copy I/O with `read_fixed`/`write_fixed`.
    ///
    /// # Errors
    ///
    /// Returns an error if registration fails (e.g., too many buffers, already registered).
    #[allow(clippy::cast_possible_truncation)]
    pub fn register_buffers(&mut self, bufs: &[IoVec]) -> Result<(), Error> {
        syscall::io_uring_register(
            self.fd,
            RegisterOp::RegisterBuffers.into(),
            bufs.as_ptr() as usize,
            bufs.len() as u32,
        )?;
        Ok(())
    }

    /// Unregister previously registered buffers.
    ///
    /// # Errors
    ///
    /// Returns an error if no buffers are registered.
    pub fn unregister_buffers(&mut self) -> Result<(), Error> {
        syscall::io_uring_register(self.fd, RegisterOp::UnregisterBuffers.into(), 0, 0)?;
        Ok(())
    }

    /// Register a provided-buffer ring for buffer-selectable operations.
    ///
    /// Allocates a pool of `count` buffers of `buf_size` bytes each, along
    /// with a ring of `count` producer entries, and registers the ring
    /// with the kernel under group id `bgid`. Submitting an SQE with
    /// [`Sqe::buffer_select`](crate::op::Sqe::buffer_select) referencing
    /// the same `bgid` tells the kernel to pick one of these buffers for
    /// the operation; the chosen buffer id is returned in the CQE via
    /// [`Completion::buffer_id`].
    ///
    /// All buffers start in the pool. Call
    /// [`ProvidedBufferRing::recycle`] after consuming a buffer to return
    /// it. Dropping the returned ring unregisters it and frees all
    /// memory.
    ///
    /// `count` must be a power of two (kernel ABI requirement) and both
    /// `count` and `buf_size` must be non-zero.
    ///
    /// # Errors
    ///
    /// Returns an error if `count` is not a power of two, if mmap fails,
    /// or if the kernel rejects registration (e.g. `bgid` already in
    /// use, kernel < 5.19).
    #[allow(clippy::cast_possible_truncation)]
    pub fn register_provided_buffers(
        &mut self,
        bgid: u16,
        count: u32,
        buf_size: u32,
    ) -> Result<ProvidedBufferRing, Error> {
        if count == 0 || buf_size == 0 || !count.is_power_of_two() {
            return Err(Error::EINVAL);
        }

        let prot = Prot::READ | Prot::WRITE;
        let map = MapFlags::PRIVATE | MapFlags::ANONYMOUS;

        // Ring of `count` entries, each 16 bytes (sizeof IoUringBuf).
        let ring_bytes = (count as usize) * core::mem::size_of::<crate::types::IoUringBuf>();
        let ring_addr = syscall::mmap(0, ring_bytes, prot, map, usize::MAX, 0)?;

        // Backing region for the buffers themselves.
        let bufs_bytes = (count as usize) * (buf_size as usize);
        let bufs_addr = match syscall::mmap(0, bufs_bytes, prot, map, usize::MAX, 0) {
            Ok(a) => a,
            Err(e) => {
                let _ = syscall::munmap(ring_addr, ring_bytes);
                return Err(e);
            }
        };

        let mut reg = crate::types::IoUringBufReg {
            ring_addr: ring_addr as u64,
            ring_entries: count,
            bgid,
            flags: 0,
            resv: [0; 3],
        };

        if let Err(e) = syscall::io_uring_register(
            self.fd,
            RegisterOp::RegisterPbufRing.into(),
            core::ptr::from_mut(&mut reg) as usize,
            1,
        ) {
            let _ = syscall::munmap(bufs_addr, bufs_bytes);
            let _ = syscall::munmap(ring_addr, ring_bytes);
            return Err(e);
        }

        let mut pbuf = ProvidedBufferRing {
            fd: self.fd,
            bgid,
            mask: count - 1,
            entries: count,
            ring_addr,
            ring_bytes,
            bufs_addr,
            bufs_bytes,
            buf_size,
            tail_local: 0,
        };

        // Pre-populate the ring with all `count` buffers.
        for i in 0..count {
            // SAFETY: each buffer id `i` maps to the i-th slot in the
            // backing region; `bufs_addr + i*buf_size` is valid for
            // `buf_size` bytes.
            let addr = (bufs_addr + (i as usize) * (buf_size as usize)) as u64;
            #[allow(clippy::cast_possible_truncation)]
            pbuf.recycle_raw(addr, buf_size, i as u16);
        }
        pbuf.commit();

        Ok(pbuf)
    }

    /// Unregister a provided-buffer ring by group id.
    ///
    /// Normally you should just drop the [`ProvidedBufferRing`] — its
    /// `Drop` calls this. Use this method only for the rare case where
    /// you need to unregister without freeing the backing memory.
    ///
    /// # Errors
    ///
    /// Returns an error if no ring is registered under `bgid`.
    pub fn unregister_provided_buffers(&mut self, bgid: u16) -> Result<(), Error> {
        let mut reg = crate::types::IoUringBufReg {
            bgid,
            ..Default::default()
        };
        syscall::io_uring_register(
            self.fd,
            RegisterOp::UnregisterPbufRing.into(),
            core::ptr::from_mut(&mut reg) as usize,
            1,
        )?;
        Ok(())
    }

    /// Register file descriptors for use with `IOSQE_FIXED_FILE`.
    ///
    /// # Errors
    ///
    /// Returns an error if registration fails.
    #[allow(clippy::cast_possible_truncation)]
    pub fn register_files(&mut self, fds: &[i32]) -> Result<(), Error> {
        syscall::io_uring_register(
            self.fd,
            RegisterOp::RegisterFiles.into(),
            fds.as_ptr() as usize,
            fds.len() as u32,
        )?;
        Ok(())
    }

    /// Unregister previously registered file descriptors.
    ///
    /// # Errors
    ///
    /// Returns an error if no files are registered.
    pub fn unregister_files(&mut self) -> Result<(), Error> {
        syscall::io_uring_register(self.fd, RegisterOp::UnregisterFiles.into(), 0, 0)?;
        Ok(())
    }

    /// Update a subset of the registered file table without re-registering everything.
    ///
    /// `fds` replaces `fds.len()` slots starting at `offset`. Use `-1` in the
    /// slice to clear individual slots.
    ///
    /// # Errors
    ///
    /// Returns an error if no file table is registered or the range is invalid.
    #[allow(clippy::cast_possible_truncation)]
    pub fn update_registered_files(&mut self, fds: &[i32], offset: u32) -> Result<(), Error> {
        use crate::types::IoUringFilesUpdate;
        let arg = IoUringFilesUpdate {
            offset,
            resv: 0,
            fds: fds.as_ptr() as u64,
        };
        syscall::io_uring_register(
            self.fd,
            RegisterOp::RegisterFilesUpdate.into(),
            core::ptr::addr_of!(arg) as usize,
            fds.len() as u32,
        )?;
        Ok(())
    }

    /// Register an `eventfd` to be signalled on every new completion.
    ///
    /// After registration the kernel writes to `efd` whenever a CQE is posted,
    /// allowing a thread blocked in `eventfd_read` to wake up without polling.
    ///
    /// # Errors
    ///
    /// Returns an error if registration fails.
    pub fn register_eventfd(&mut self, efd: i32) -> Result<(), Error> {
        syscall::io_uring_register(
            self.fd,
            RegisterOp::RegisterEventFd.into(),
            core::ptr::addr_of!(efd) as usize,
            1,
        )?;
        Ok(())
    }

    /// Like [`register_eventfd`](Self::register_eventfd) but the eventfd is
    /// only signalled for async completions, not for inline completions.
    ///
    /// # Errors
    ///
    /// Returns an error if registration fails.
    pub fn register_eventfd_async(&mut self, efd: i32) -> Result<(), Error> {
        syscall::io_uring_register(
            self.fd,
            RegisterOp::RegisterEventFdAsync.into(),
            core::ptr::addr_of!(efd) as usize,
            1,
        )?;
        Ok(())
    }

    /// Unregister a previously registered eventfd.
    ///
    /// # Errors
    ///
    /// Returns an error if no eventfd is registered.
    pub fn unregister_eventfd(&mut self) -> Result<(), Error> {
        syscall::io_uring_register(self.fd, RegisterOp::UnregisterEventFd.into(), 0, 0)?;
        Ok(())
    }

    /// Cap the number of async worker threads used by this ring.
    ///
    /// `max_bounded` limits threads for bounded workloads (e.g. buffered I/O);
    /// `max_unbounded` limits threads for unbounded workloads (e.g. network).
    /// Pass `0` for either to leave it unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error if the kernel rejects the request.
    pub fn set_iowq_max_workers(
        &mut self,
        max_bounded: u32,
        max_unbounded: u32,
    ) -> Result<(), Error> {
        let mut workers = [max_bounded, max_unbounded];
        syscall::io_uring_register(
            self.fd,
            RegisterOp::RegisterIowqMaxWorkers.into(),
            workers.as_mut_ptr() as usize,
            2,
        )?;
        Ok(())
    }

    /// Register the ring's own fd as a fixed fd (6.0+).
    ///
    /// After registration, pass [`EnterFlags::REGISTERED_RING`] to
    /// `io_uring_enter` to use the fixed fd, saving a file-table lookup
    /// on every syscall. Returns the fixed fd index.
    ///
    /// # Errors
    ///
    /// Returns an error if the kernel rejects the request (e.g. kernel < 6.0).
    pub fn register_ring_fd(&mut self) -> Result<u32, Error> {
        use crate::types::IoUringRsrcUpdate;
        let mut reg = IoUringRsrcUpdate {
            offset: u32::MAX,
            resv: 0,
            data: self.fd as u64,
        };
        syscall::io_uring_register(
            self.fd,
            RegisterOp::RegisterRingFds.into(),
            core::ptr::from_mut(&mut reg) as usize,
            1,
        )?;
        Ok(reg.offset)
    }

    /// Return an iterator that drains all available completions.
    pub const fn completions(&mut self) -> Completions<'_> {
        Completions { ring: self }
    }

    // -----------------------------------------------------------------
    // Scoped convenience methods — fully safe, borrow across submit+wait
    // -----------------------------------------------------------------

    /// Submit a single SQE, wait for its completion, and return the result.
    ///
    /// This is the building block for all `do_*` methods. The `&mut self`
    /// borrow prevents concurrent submissions and ensures any referenced
    /// data in the `Sqe` remains valid for the duration.
    fn run_one(&mut self, sqe: Sqe) -> Result<u32, Error> {
        self.push(sqe)?;
        self.submit_and_wait(1)?;
        self.complete().ok_or(Error::EAGAIN)?.into_result()
    }

    /// Read from `fd` into `buf` at `offset`. Returns the byte count.
    ///
    /// The buffer is borrowed for the entire submit-and-wait cycle, so
    /// this is fully safe — no lifetime concerns.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the submission or the kernel operation fails.
    pub fn do_read(&mut self, fd: i32, buf: &mut [u8], offset: u64) -> Result<u32, Error> {
        self.run_one(Sqe::read(fd, buf, offset))
    }

    /// Write `buf` to `fd` at `offset`. Returns the byte count.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the submission or the kernel operation fails.
    pub fn do_write(&mut self, fd: i32, buf: &[u8], offset: u64) -> Result<u32, Error> {
        self.run_one(Sqe::write(fd, buf, offset))
    }

    /// Open a file relative to `dfd`. Returns the new fd as `u32`.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the submission or the kernel operation fails.
    pub fn do_openat(
        &mut self,
        dfd: i32,
        path: &core::ffi::CStr,
        flags: crate::types::OpenFlags,
        mode: crate::types::FileMode,
    ) -> Result<u32, Error> {
        self.run_one(Sqe::openat(dfd, path, flags, mode))
    }

    /// Close a file descriptor via io\_uring.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the submission or the kernel operation fails.
    pub fn do_close(&mut self, fd: i32) -> Result<u32, Error> {
        self.run_one(Sqe::close(fd))
    }

    /// Send data on a socket. Returns the byte count.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the submission or the kernel operation fails.
    pub fn do_send(
        &mut self,
        fd: i32,
        buf: &[u8],
        flags: crate::types::MsgFlags,
    ) -> Result<u32, Error> {
        self.run_one(Sqe::send(fd, buf, flags))
    }

    /// Receive data from a socket into `buf`. Returns the byte count.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the submission or the kernel operation fails.
    pub fn do_recv(
        &mut self,
        fd: i32,
        buf: &mut [u8],
        flags: crate::types::MsgFlags,
    ) -> Result<u32, Error> {
        self.run_one(Sqe::recv(fd, buf, flags))
    }

    /// Accept a connection (without capturing the peer address). Returns
    /// the new socket fd as `u32`.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the submission or the kernel operation fails.
    pub fn do_accept(&mut self, fd: i32, flags: crate::types::AcceptFlags) -> Result<u32, Error> {
        self.run_one(Sqe::accept(fd, flags))
    }

    /// Stat a file. Populates `statx_buf` and returns 0 on success.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the submission or the kernel operation fails.
    pub fn do_statx(
        &mut self,
        dfd: i32,
        path: &core::ffi::CStr,
        flags: crate::types::StatxFlags,
        mask: crate::types::StatxMask,
        statx_buf: &mut crate::types::Statx,
    ) -> Result<u32, Error> {
        self.run_one(Sqe::statx(dfd, path, flags, mask, statx_buf))
    }

    /// Fsync a file descriptor.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the submission or the kernel operation fails.
    pub fn do_fsync(&mut self, fd: i32, flags: crate::types::FsyncFlags) -> Result<u32, Error> {
        self.run_one(Sqe::fsync(fd, flags))
    }

    /// Split the ring into a [`Submitter`] and a [`Completer`].
    ///
    /// Both halves are `Send` and can be moved to separate threads. The
    /// underlying kernel resources (fd and mmap regions) are freed only
    /// when **both** halves have been dropped.
    ///
    /// `self` is consumed — use the returned halves instead of the original
    /// `IoUring`.
    #[must_use]
    pub fn split(self) -> (Submitter, Completer) {
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
            cq_head: self.cq_head,
            cq_tail: self.cq_tail,
            cq_mask: self.cq_mask,
            cqes: self.cqes,
            cq_head_local: self.cq_head_local,
            resources: self.resources,
        };

        // Don't run IoUring's Drop — the two halves now own the resources.
        core::mem::forget(self);

        (submitter, completer)
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

/// A kernel-registered provided-buffer ring.
///
/// Owns the mmap'd producer ring and the backing buffer region for a
/// group of buffers selectable via
/// [`Sqe::buffer_select`](crate::op::Sqe::buffer_select). Dropping this
/// handle unregisters the ring and unmaps its memory.
///
/// # Thread safety
///
/// Like [`IoUring`], this type is `!Send` and `!Sync`. Recycling a
/// buffer from a thread other than the one draining completions would
/// race on `tail_local` and on the kernel-visible tail atomic.
pub struct ProvidedBufferRing {
    fd: usize,
    bgid: u16,
    mask: u32,
    entries: u32,
    ring_addr: usize,
    ring_bytes: usize,
    bufs_addr: usize,
    bufs_bytes: usize,
    buf_size: u32,
    /// Cached next producer position; published to the ring's `tail`
    /// slot on [`commit`](Self::commit).
    tail_local: u32,
}

impl ProvidedBufferRing {
    /// Returns the group id this ring is registered under.
    #[must_use]
    pub const fn bgid(&self) -> u16 {
        self.bgid
    }

    /// Returns the number of buffers in the pool.
    #[must_use]
    pub const fn entries(&self) -> u32 {
        self.entries
    }

    /// Returns the size of each buffer in bytes.
    #[must_use]
    pub const fn buf_size(&self) -> u32 {
        self.buf_size
    }

    /// Borrow the contents of a completed buffer.
    ///
    /// `len` should be the CQE `result` (byte count) for the completion
    /// that chose buffer `buf_id`. Returns `None` if `buf_id` is out of
    /// range or `len` exceeds [`buf_size`](Self::buf_size).
    #[must_use]
    pub fn buffer(&self, buf_id: u16, len: u32) -> Option<&[u8]> {
        // SAFETY: `bufs_addr` points to a region of `entries * buf_size`
        // bytes that outlives `self`. The helper bounds-checks `buf_id`
        // and `len` before constructing the slice.
        unsafe {
            buffer_slice(
                self.bufs_addr as *const u8,
                self.entries,
                self.buf_size,
                buf_id,
                len,
            )
        }
    }

    /// Mutably borrow a completed buffer.
    ///
    /// Same bounds as [`buffer`](Self::buffer). The `&mut self` borrow
    /// keeps this race-free with [`recycle`](Self::recycle): you can't
    /// hand the same buffer back to the kernel while still writing to
    /// it.
    #[must_use]
    pub fn buffer_mut(&mut self, buf_id: u16, len: u32) -> Option<&mut [u8]> {
        // SAFETY: same region guarantees as `buffer`, plus `&mut self`
        // which rules out any aliasing `&[u8]` / `&mut [u8]` previously
        // handed out.
        unsafe {
            buffer_slice_mut(
                self.bufs_addr as *mut u8,
                self.entries,
                self.buf_size,
                buf_id,
                len,
            )
        }
    }

    /// Return a buffer to the pool so the kernel can reuse it.
    ///
    /// Call this after you've consumed the bytes the kernel wrote into
    /// the buffer. The recycle does not issue a syscall — it just
    /// appends to the producer ring and, on [`commit`](Self::commit),
    /// publishes the tail with a Release store.
    ///
    /// # Panics
    ///
    /// Panics if `buf_id` is out of range.
    pub fn recycle(&mut self, buf_id: u16) {
        assert!(
            u32::from(buf_id) < self.entries,
            "buf_id out of range for provided-buffer ring"
        );
        let off = (buf_id as usize) * (self.buf_size as usize);
        let addr = (self.bufs_addr + off) as u64;
        self.recycle_raw(addr, self.buf_size, buf_id);
    }

    /// Recycle a buffer and immediately publish the tail.
    pub fn recycle_and_commit(&mut self, buf_id: u16) {
        self.recycle(buf_id);
        self.commit();
    }

    /// Publish all pending recycles to the kernel.
    ///
    /// Writes the local tail to the ring's producer tail slot with a
    /// Release store. Call this after one or more
    /// [`recycle`](Self::recycle) calls before the next
    /// submit / wait cycle.
    pub fn commit(&self) {
        // SAFETY: `tail_ptr` points into the mmap'd ring region, aligned
        // at offset 14 inside entry[0] (a u16). The region is live for
        // the lifetime of `self`.
        let tail_ptr = self.tail_ptr();
        #[allow(clippy::cast_possible_truncation)]
        let tail = self.tail_local as u16;
        unsafe { &*tail_ptr }.store(tail, Ordering::Release);
    }

    /// Internal: write a buf descriptor without touching the `resv`
    /// field that aliases the ring tail in entry 0.
    fn recycle_raw(&mut self, addr: u64, len: u32, bid: u16) {
        let idx = self.tail_local & self.mask;
        // SAFETY: `idx < entries`, so the write stays within the mmap'd
        // ring region. We write fields individually rather than a full
        // `IoUringBuf` struct so that entry 0's `resv` (which aliases
        // the producer `tail` half-word) is not clobbered.
        unsafe {
            let entry = (self.ring_addr as *mut crate::types::IoUringBuf).add(idx as usize);
            core::ptr::addr_of_mut!((*entry).addr).write(addr);
            core::ptr::addr_of_mut!((*entry).len).write(len);
            core::ptr::addr_of_mut!((*entry).bid).write(bid);
        }
        self.tail_local = self.tail_local.wrapping_add(1);
    }

    /// Pointer to the ring's producer tail (last 2 bytes of entry 0).
    const fn tail_ptr(&self) -> *const core::sync::atomic::AtomicU16 {
        // `tail` lives at offset 14 within `io_uring_buf_ring`, which
        // aliases `bufs[0].resv`.
        const TAIL_OFFSET: usize = 14;
        (self.ring_addr + TAIL_OFFSET) as *const core::sync::atomic::AtomicU16
    }
}

/// Slice a buffer out of a contiguous `entries × buf_size` backing
/// region given its id and the kernel-reported byte count.
///
/// # Safety
///
/// `base` must point to at least `entries * buf_size` bytes of memory
/// that remains valid for the returned slice's lifetime, and must not
/// be aliased by another live `&mut [u8]` over the chosen range.
unsafe fn buffer_slice<'a>(
    base: *const u8,
    entries: u32,
    buf_size: u32,
    buf_id: u16,
    len: u32,
) -> Option<&'a [u8]> {
    if u32::from(buf_id) >= entries || len > buf_size {
        return None;
    }
    let off = (buf_id as usize) * (buf_size as usize);
    // SAFETY: caller guarantees `base + entries * buf_size` is in-bounds
    // and the bounds check above keeps `off + len` within that region.
    unsafe { Some(core::slice::from_raw_parts(base.add(off), len as usize)) }
}

/// Mutable counterpart of [`buffer_slice`].
///
/// # Safety
///
/// Same as [`buffer_slice`], plus `base` must not be aliased by any
/// other live reference (shared or exclusive) over the chosen range.
unsafe fn buffer_slice_mut<'a>(
    base: *mut u8,
    entries: u32,
    buf_size: u32,
    buf_id: u16,
    len: u32,
) -> Option<&'a mut [u8]> {
    if u32::from(buf_id) >= entries || len > buf_size {
        return None;
    }
    let off = (buf_id as usize) * (buf_size as usize);
    // SAFETY: see caller safety doc; bounds check keeps us inside the region.
    unsafe { Some(core::slice::from_raw_parts_mut(base.add(off), len as usize)) }
}

impl Drop for ProvidedBufferRing {
    fn drop(&mut self) {
        let mut reg = crate::types::IoUringBufReg {
            bgid: self.bgid,
            ..Default::default()
        };
        let _ = syscall::io_uring_register(
            self.fd,
            RegisterOp::UnregisterPbufRing.into(),
            core::ptr::from_mut(&mut reg) as usize,
            1,
        );
        let _ = syscall::munmap(self.bufs_addr, self.bufs_bytes);
        let _ = syscall::munmap(self.ring_addr, self.ring_bytes);
    }
}

/// Builder for configuring an `io_uring` instance before creation.
///
/// ```no_run
/// # use ququmatz::IoUring;
/// let ring = IoUring::builder(32)
///     .cq_entries(64)
///     .clamp()
///     .build()
///     .expect("setup failed");
/// ```
pub struct IoUringBuilder {
    entries: u32,
    params: IoUringParams,
}

impl IoUringBuilder {
    /// Start building an `io_uring` with the given queue depth.
    ///
    /// # Panics
    ///
    /// Panics if `entries` is 0.
    #[must_use]
    pub fn new(entries: u32) -> Self {
        assert!(entries > 0, "io_uring entries must be > 0");
        Self {
            entries,
            params: IoUringParams::default(),
        }
    }

    /// Enable kernel-side SQ polling with the given idle timeout in milliseconds.
    ///
    /// When SQPOLL is active, the kernel polls the SQ for new entries without
    /// requiring `io_uring_enter` calls, reducing syscall overhead.
    #[must_use]
    pub const fn sqpoll(mut self, idle_ms: u32) -> Self {
        self.params.flags |= SetupFlags::SQPOLL.bits();
        self.params.sq_thread_idle = idle_ms;
        self
    }

    /// Pin the SQPOLL thread to a specific CPU.
    #[must_use]
    pub const fn sqpoll_cpu(mut self, cpu: u32) -> Self {
        self.params.flags |= SetupFlags::SQPOLL.bits() | SetupFlags::SQ_AFF.bits();
        self.params.sq_thread_cpu = cpu;
        self
    }

    /// Set a custom CQ ring size (must be >= SQ size).
    #[must_use]
    pub const fn cq_entries(mut self, n: u32) -> Self {
        self.params.flags |= SetupFlags::CQSIZE.bits();
        self.params.cq_entries = n;
        self
    }

    /// Clamp SQ/CQ sizes to kernel implementation limits instead of failing.
    #[must_use]
    pub const fn clamp(mut self) -> Self {
        self.params.flags |= SetupFlags::CLAMP.bits();
        self
    }

    /// Hint that only one thread will submit to this ring (5.18+).
    #[must_use]
    pub const fn single_issuer(mut self) -> Self {
        self.params.flags |= SetupFlags::SINGLE_ISSUER.bits();
        self
    }

    /// Enable cooperative task-run (6.0+).
    ///
    /// The kernel will not force preemption when processing completions,
    /// reducing latency at the cost of fairness under heavy load.
    #[must_use]
    pub const fn coop_taskrun(mut self) -> Self {
        self.params.flags |= SetupFlags::COOP_TASKRUN.bits();
        self
    }

    /// Enable deferred task-run (6.1+).
    ///
    /// Defers all task-work to `io_uring_enter`, giving the application full
    /// control over when completions are processed. Biggest latency win for
    /// single-threaded event loops. Implies `COOP_TASKRUN`.
    #[must_use]
    pub const fn defer_taskrun(mut self) -> Self {
        self.params.flags |= SetupFlags::DEFER_TASKRUN.bits() | SetupFlags::COOP_TASKRUN.bits();
        self
    }

    /// Attach to an existing `io_uring` workqueue (share its worker threads).
    #[must_use]
    pub const fn attach_wq(mut self, wq_fd: u32) -> Self {
        self.params.flags |= SetupFlags::ATTACH_WQ.bits();
        self.params.wq_fd = wq_fd;
        self
    }

    /// Set raw setup flags directly.
    #[must_use]
    pub const fn setup_flags(mut self, flags: SetupFlags) -> Self {
        self.params.flags |= flags.bits();
        self
    }

    /// Build the `io_uring` instance.
    ///
    /// # Errors
    ///
    /// Returns an error if the kernel rejects the parameters.
    pub fn build(mut self) -> Result<IoUring, Error> {
        IoUring::from_params(self.entries, &mut self.params)
    }
}

#[cfg(test)]
mod buffer_slice_tests {
    //! Tests for [`buffer_slice`] / [`buffer_slice_mut`] — the internal
    //! helpers behind [`ProvidedBufferRing::buffer`] and
    //! [`ProvidedBufferRing::buffer_mut`]. These run on a heap
    //! allocation instead of an mmap region so Miri can check them.
    //!
    //! Miri doesn't support the `mmap` syscall, so the real
    //! `ProvidedBufferRing` can't be exercised under Miri. Factoring
    //! the slice construction out into these helpers lets us verify
    //! the provenance / aliasing / bounds logic — which is where the
    //! actual unsafety lives — under Miri regardless.
    extern crate std;
    use std::{vec, vec::Vec};

    use super::{buffer_slice, buffer_slice_mut};

    const ENTRIES: u32 = 4;
    const BUF_SIZE: u32 = 8;

    fn backing() -> Vec<u8> {
        vec![0u8; (ENTRIES * BUF_SIZE) as usize]
    }

    #[test]
    fn round_trip_write_then_read() {
        let mut mem = backing();
        let base = mem.as_mut_ptr();

        // Write distinct patterns into every slot via `buffer_slice_mut`.
        for id in 0..ENTRIES as u16 {
            // SAFETY: `mem` lives for the whole test; no other
            // reference aliases `base` while the returned slice is in
            // use (we drop it before the next iteration).
            let slot =
                unsafe { buffer_slice_mut::<'_>(base, ENTRIES, BUF_SIZE, id, BUF_SIZE) }.unwrap();
            slot.fill(id as u8 + 1);
        }

        // Read them back via the shared variant.
        for id in 0..ENTRIES as u16 {
            // SAFETY: only shared slices are live at once.
            let slot =
                unsafe { buffer_slice::<'_>(base.cast_const(), ENTRIES, BUF_SIZE, id, BUF_SIZE) }
                    .unwrap();
            assert!(slot.iter().all(|&b| b == id as u8 + 1));
        }
    }

    #[test]
    fn partial_len_returns_prefix() {
        let mut mem = backing();
        let base = mem.as_mut_ptr();
        // SAFETY: no aliasing refs live here.
        let slot = unsafe { buffer_slice_mut::<'_>(base, ENTRIES, BUF_SIZE, 2, BUF_SIZE) }.unwrap();
        slot.copy_from_slice(b"ABCDEFGH");

        // CQE reports only 3 bytes were actually filled.
        // SAFETY: prior `&mut` dropped; no aliasing.
        let got =
            unsafe { buffer_slice::<'_>(base.cast_const(), ENTRIES, BUF_SIZE, 2, 3) }.unwrap();
        assert_eq!(got, b"ABC");
        assert_eq!(got.len(), 3);
    }

    #[test]
    fn zero_len_is_empty_slice_not_none() {
        let mut mem = backing();
        let base = mem.as_mut_ptr();
        // SAFETY: no aliasing.
        let slot =
            unsafe { buffer_slice::<'_>(base.cast_const(), ENTRIES, BUF_SIZE, 0, 0) }.unwrap();
        assert!(slot.is_empty());
    }

    #[test]
    fn out_of_range_buf_id_returns_none() {
        let mut mem = backing();
        let base = mem.as_mut_ptr();
        // SAFETY: bounds-check rejects before any pointer arithmetic.
        let got =
            unsafe { buffer_slice::<'_>(base.cast_const(), ENTRIES, BUF_SIZE, ENTRIES as u16, 1) };
        assert!(got.is_none());
    }

    #[test]
    fn len_exceeding_buf_size_returns_none() {
        let mut mem = backing();
        let base = mem.as_mut_ptr();
        // SAFETY: bounds-check rejects before any pointer arithmetic.
        let got =
            unsafe { buffer_slice::<'_>(base.cast_const(), ENTRIES, BUF_SIZE, 0, BUF_SIZE + 1) };
        assert!(got.is_none());
    }

    #[test]
    fn adjacent_slots_are_disjoint() {
        // If two mutable borrows of different slots aliased, Miri's
        // Stacked Borrows would flag it. Write to both simultaneously.
        let mut mem = backing();
        let base = mem.as_mut_ptr();
        // SAFETY: buf_ids 0 and 1 occupy disjoint ranges
        // `[0, 8)` and `[8, 16)` of `mem`; the two slices do not alias.
        let a = unsafe { buffer_slice_mut::<'_>(base, ENTRIES, BUF_SIZE, 0, BUF_SIZE) }.unwrap();
        let b = unsafe { buffer_slice_mut::<'_>(base, ENTRIES, BUF_SIZE, 1, BUF_SIZE) }.unwrap();
        a.fill(0xAA);
        b.fill(0xBB);
        assert!(a.iter().all(|&x| x == 0xAA));
        assert!(b.iter().all(|&x| x == 0xBB));
    }
}
