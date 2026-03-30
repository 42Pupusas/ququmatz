use crate::error::Error;
use crate::op::Sqe;
use crate::syscall;
use crate::types::{EnterFlags, IoUringCqe, IoUringParams, IoUringSqe, MapFlags, Prot, RingOffset};
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
pub struct IoUring {
    fd: usize,

    // SQ ring pointers (into mmap'd memory)
    sq_head: *const AtomicU32,
    sq_tail: *const AtomicU32,
    sq_mask: u32,
    sq_array: *mut u32,

    // SQE array
    sqes: *mut IoUringSqe,
    sq_tail_local: u32,

    // CQ ring pointers (into mmap'd memory)
    cq_head: *const AtomicU32,
    cq_tail: *const AtomicU32,
    cq_mask: u32,
    cqes: *const IoUringCqe,
    cq_head_local: u32,

    // For cleanup
    sq_ring: MappedRegion,
    cq_ring: MappedRegion,
    sqes_region: MappedRegion,
}

impl IoUring {
    /// Create a new `io_uring` instance with the given queue depth.
    ///
    /// `entries` will be rounded up to the next power of two by the kernel.
    ///
    /// # Errors
    ///
    /// Returns an error if the kernel rejects the setup or memory mapping fails.
    #[allow(clippy::cast_ptr_alignment)]
    pub fn new(entries: u32) -> Result<Self, Error> {
        let mut params = IoUringParams::default();
        let prot = Prot::READ | Prot::WRITE;
        let map = MapFlags::SHARED | MapFlags::POPULATE;

        let fd = syscall::io_uring_setup(entries, &raw mut params)?;

        // Map the SQ ring
        let sq_ring_sz =
            params.sq_off.array as usize + params.sq_entries as usize * core::mem::size_of::<u32>();
        let sq_ring_ptr = syscall::mmap(0, sq_ring_sz, prot, map, fd, RingOffset::SqRing.into())?;

        // Map the CQ ring
        let cq_ring_sz = params.cq_off.cqes as usize
            + params.cq_entries as usize * core::mem::size_of::<IoUringCqe>();
        let cq_ring_ptr = syscall::mmap(0, cq_ring_sz, prot, map, fd, RingOffset::CqRing.into())?;

        // Map the SQE array
        let sqes_sz = params.sq_entries as usize * core::mem::size_of::<IoUringSqe>();
        let sqes_ptr = syscall::mmap(0, sqes_sz, prot, map, fd, RingOffset::Sqes.into())?;

        let sq_base = sq_ring_ptr as *const u8;
        let sq_head = unsafe { sq_base.add(params.sq_off.head as usize) }.cast::<AtomicU32>();
        let sq_tail = unsafe { sq_base.add(params.sq_off.tail as usize) }.cast::<AtomicU32>();
        let sq_mask = unsafe { *sq_base.add(params.sq_off.ring_mask as usize).cast::<u32>() };
        let sq_array = unsafe { sq_base.add(params.sq_off.array as usize) } as *mut u32;

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
            sq_array,
            sqes: sqes_ptr as *mut IoUringSqe,
            sq_tail_local,
            cq_head,
            cq_tail,
            cq_mask,
            cqes,
            cq_head_local,
            sq_ring: MappedRegion::new(sq_ring_ptr, sq_ring_sz),
            cq_ring: MappedRegion::new(cq_ring_ptr, cq_ring_sz),
            sqes_region: MappedRegion::new(sqes_ptr, sqes_sz),
        })
    }

    /// Push a prepared SQE onto the submission queue.
    ///
    /// # Errors
    ///
    /// Returns `EAGAIN` if the submission queue is full.
    #[allow(clippy::needless_pass_by_value)]
    pub fn push(&mut self, sqe: Sqe) -> Result<(), Error> {
        let head = unsafe { &*self.sq_head }.load(Ordering::Acquire);
        let next_tail = self.sq_tail_local + 1;

        if next_tail - head > self.sq_mask + 1 {
            return Err(Error::EAGAIN);
        }

        let idx = self.sq_tail_local & self.sq_mask;

        unsafe { *self.sqes.add(idx as usize) = sqe.0 };
        unsafe { *self.sq_array.add(idx as usize) = idx };

        self.sq_tail_local = next_tail;
        unsafe { &*self.sq_tail }.store(self.sq_tail_local, Ordering::Release);

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

    /// Submit all queued entries to the kernel.
    ///
    /// Returns the number of entries submitted.
    ///
    /// # Errors
    ///
    /// Returns an error if the kernel rejects the submission.
    #[allow(clippy::cast_possible_truncation)]
    pub fn submit(&mut self) -> Result<u32, Error> {
        let head = unsafe { &*self.sq_head }.load(Ordering::Acquire);
        let to_submit = self.sq_tail_local.wrapping_sub(head);
        if to_submit == 0 {
            return Ok(0);
        }
        let ret = syscall::io_uring_enter(self.fd, to_submit, 0, EnterFlags::default())?;
        Ok(ret as u32)
    }

    /// Submit all queued entries and wait for at least `min_complete` completions.
    ///
    /// Returns the number of entries submitted.
    ///
    /// # Errors
    ///
    /// Returns an error if the kernel rejects the submission.
    #[allow(clippy::cast_possible_truncation)]
    pub fn submit_and_wait(&mut self, min_complete: u32) -> Result<u32, Error> {
        let head = unsafe { &*self.sq_head }.load(Ordering::Acquire);
        let to_submit = self.sq_tail_local.wrapping_sub(head);
        let ret = syscall::io_uring_enter(self.fd, to_submit, min_complete, EnterFlags::GETEVENTS)?;
        Ok(ret as u32)
    }

    /// Reap one completion from the completion queue, if available.
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
        unsafe { &*self.cq_head }.store(self.cq_head_local, Ordering::Release);

        Some(completion)
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
        let _ = syscall::munmap(self.sqes_region.addr, self.sqes_region.len);
        let _ = syscall::munmap(self.cq_ring.addr, self.cq_ring.len);
        let _ = syscall::munmap(self.sq_ring.addr, self.sq_ring.len);
        let _ = syscall::close(self.fd);
    }
}
