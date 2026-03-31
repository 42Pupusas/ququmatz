use crate::error::Error;
use crate::op::Sqe;
use crate::syscall;
use crate::types::{
    EnterFlags, Features, IoUringCqe, IoUringParams, IoUringSqe, IoVec, MapFlags, Prot, RegisterOp,
    RingOffset, SetupFlags,
};
use core::sync::atomic::{AtomicU32, Ordering};

/// A completed `io_uring` operation.
#[derive(Debug, Clone, Copy)]
pub struct Completion {
    /// The `user_data` value from the original submission.
    pub user_data: u64,
    /// The result code (bytes transferred on success, negative errno on failure).
    pub result: i32,
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

/// Safe wrapper around a Linux `io_uring` instance.
///
/// # Thread Safety
///
/// `IoUring` is `!Send` and `!Sync` (due to raw pointers into mmap'd memory).
/// This is intentional — the ring's mmap'd regions and cached indices are not
/// safe to share across threads without external synchronization. Create one
/// ring per thread, or wrap in a `Mutex` if you must share.
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

    #[allow(clippy::cast_ptr_alignment)]
    fn from_params(entries: u32, params: &mut IoUringParams) -> Result<Self, Error> {
        let prot = Prot::READ | Prot::WRITE;
        let map = MapFlags::SHARED | MapFlags::POPULATE;

        let fd = syscall::io_uring_setup(entries, &raw mut *params)?;

        let features = Features(params.features);
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
        let sq_ring_ptr = match syscall::mmap(0, mmap_sz, prot, map, fd, RingOffset::SqRing.into()) {
            Ok(ptr) => ptr,
            Err(e) => {
                let _ = syscall::close(fd);
                return Err(e);
            }
        };

        // Map the CQ ring (reuse SQ mmap if SINGLE_MMAP)
        let (cq_ring_ptr, cq_ring_region) = if single_mmap {
            (sq_ring_ptr, MappedRegion::new(0, 0))
        } else {
            match syscall::mmap(0, cq_ring_sz, prot, map, fd, RingOffset::CqRing.into()) {
                Ok(ptr) => (ptr, MappedRegion::new(ptr, cq_ring_sz)),
                Err(e) => {
                    let _ = syscall::munmap(sq_ring_ptr, mmap_sz);
                    let _ = syscall::close(fd);
                    return Err(e);
                }
            }
        };

        // Map the SQE array
        let sqes_sz = params.sq_entries as usize * core::mem::size_of::<IoUringSqe>();
        let sqes_ptr = match syscall::mmap(0, sqes_sz, prot, map, fd, RingOffset::Sqes.into()) {
            Ok(ptr) => ptr,
            Err(e) => {
                if cq_ring_region.len > 0 {
                    let _ = syscall::munmap(cq_ring_region.addr, cq_ring_region.len);
                }
                let _ = syscall::munmap(sq_ring_ptr, mmap_sz);
                let _ = syscall::close(fd);
                return Err(e);
            }
        };

        let sq_base = sq_ring_ptr as *const u8;
        let sq_head = unsafe { sq_base.add(params.sq_off.head as usize) }.cast::<AtomicU32>();
        let sq_tail = unsafe { sq_base.add(params.sq_off.tail as usize) }.cast::<AtomicU32>();
        let sq_mask = unsafe { *sq_base.add(params.sq_off.ring_mask as usize).cast::<u32>() };
        let sq_flags = unsafe { sq_base.add(params.sq_off.flags as usize) }.cast::<AtomicU32>();
        let sq_array = unsafe { sq_base.add(params.sq_off.array as usize) } as *mut u32;

        // Pre-fill sq_array with identity mapping (sqe[i] -> slot i).
        // The kernel reads sq_array to find which SQE slot each submission
        // refers to. With identity mapping we never need to update it again.
        for i in 0..params.sq_entries {
            unsafe { sq_array.add(i as usize).write(i) };
        }

        let cq_base = cq_ring_ptr as *const u8;
        let cq_head = unsafe { cq_base.add(params.cq_off.head as usize) }.cast::<AtomicU32>();
        let cq_tail = unsafe { cq_base.add(params.cq_off.tail as usize) }.cast::<AtomicU32>();
        let cq_mask = unsafe { *cq_base.add(params.cq_off.ring_mask as usize).cast::<u32>() };
        let cqes = unsafe { cq_base.add(params.cq_off.cqes as usize) }.cast::<IoUringCqe>();

        let sq_tail_local = unsafe { &*sq_tail }.load(Ordering::Acquire);
        let cq_head_local = unsafe { &*cq_head }.load(Ordering::Acquire);

        Ok(Self {
            fd,
            sq_head,
            sq_tail,
            sq_mask,
            sq_flags,
            sqes: sqes_ptr as *mut IoUringSqe,
            sq_tail_local,
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
    /// Called automatically by `submit` and `submit_and_wait`; only needed
    /// directly when using SQPOLL mode without explicit submission.
    #[inline]
    fn flush_sq_tail(&self) {
        unsafe { &*self.sq_tail }.store(self.sq_tail_local, Ordering::Release);
    }

    /// Submit all queued entries to the kernel.
    ///
    /// Returns the number of entries submitted.
    ///
    /// # Errors
    ///
    /// Returns an error if the kernel rejects the submission.
    #[inline]
    #[allow(clippy::cast_possible_truncation)]
    pub fn submit(&mut self) -> Result<u32, Error> {
        self.flush_sq_tail();
        let head = unsafe { &*self.sq_head }.load(Ordering::Acquire);
        let to_submit = self.sq_tail_local.wrapping_sub(head);
        if to_submit == 0 {
            return Ok(0);
        }
        let ret = syscall::io_uring_enter(self.fd, to_submit, 0, EnterFlags::default())?;
        self.flush_cq_head();
        Ok(ret as u32)
    }

    /// Submit all queued entries and wait for at least `min_complete` completions.
    ///
    /// Returns the number of entries submitted.
    ///
    /// # Errors
    ///
    /// Returns an error if the kernel rejects the submission.
    #[inline]
    #[allow(clippy::cast_possible_truncation)]
    pub fn submit_and_wait(&mut self, min_complete: u32) -> Result<u32, Error> {
        self.flush_cq_head();
        self.flush_sq_tail();
        let head = unsafe { &*self.sq_head }.load(Ordering::Acquire);
        let to_submit = self.sq_tail_local.wrapping_sub(head);
        let ret = syscall::io_uring_enter(self.fd, to_submit, min_complete, EnterFlags::GETEVENTS)?;
        Ok(ret as u32)
    }

    /// Publish the local CQ head to the kernel-visible atomic head.
    ///
    /// Called automatically by `submit`, `submit_and_wait`, and `Drop`.
    /// Call explicitly after draining completions if you need the kernel to
    /// see freed CQ slots before the next submission.
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
        };

        self.cq_head_local += 1;

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
    pub fn register_buffers(&self, bufs: &[IoVec]) -> Result<(), Error> {
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
    pub fn unregister_buffers(&self) -> Result<(), Error> {
        syscall::io_uring_register(self.fd, RegisterOp::UnregisterBuffers.into(), 0, 0)?;
        Ok(())
    }

    /// Register file descriptors for use with `IOSQE_FIXED_FILE`.
    ///
    /// # Errors
    ///
    /// Returns an error if registration fails.
    #[allow(clippy::cast_possible_truncation)]
    pub fn register_files(&self, fds: &[i32]) -> Result<(), Error> {
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
    pub fn unregister_files(&self) -> Result<(), Error> {
        syscall::io_uring_register(self.fd, RegisterOp::UnregisterFiles.into(), 0, 0)?;
        Ok(())
    }

    /// Return an iterator that drains all available completions.
    pub const fn completions(&mut self) -> Completions<'_> {
        Completions { ring: self }
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
    #[must_use]
    pub fn new(entries: u32) -> Self {
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
