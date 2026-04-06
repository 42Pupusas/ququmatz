use crate::error::Error;
use crate::op::Sqe;
use crate::syscall;
use crate::types::{
    CqeFlags, EnterFlags, Features, IoUringCqe, IoUringParams, IoUringSqe, IoVec, MapFlags, Prot,
    RegisterOp, RingOffset, SetupFlags,
};
use core::sync::atomic::{AtomicU32, Ordering};

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

    // For cleanup
    sq_ring: MappedRegion,
    cq_ring: MappedRegion,
    sqes_region: MappedRegion,
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

        // All resources acquired — disarm the guard so Drop doesn't
        // clean up what we're about to hand to the IoUring struct.
        guard.disarm();

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
            sq_ring: MappedRegion::new(sq_ring_ptr, mmap_sz),
            cq_ring: cq_ring_region,
            sqes_region: MappedRegion::new(sqes_ptr, sqes_sz),
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
        let _ = syscall::munmap(self.sqes_region.addr, self.sqes_region.len);
        if self.cq_ring.len > 0 {
            let _ = syscall::munmap(self.cq_ring.addr, self.cq_ring.len);
        }
        let _ = syscall::munmap(self.sq_ring.addr, self.sq_ring.len);
        let _ = syscall::close(self.fd);
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
