//! `IoUring::register_*` methods (non-pbuf): buffers, files, eventfd,
//! workqueue caps, ring-fd registration.

use super::IoUring;
use crate::error::Error;
use crate::syscall;
use crate::types::{
    CancelOutcome, CloneBuffersFlags, IoUringCloneBuffers, IoUringFileIndexRange,
    IoUringFilesUpdate, IoUringRsrcUpdate, IoVec, NapiOp, NapiSettings, NapiTrackingStrategy,
    RawFd, RawNapi, RawSyncCancelReg, RegisterOp, SyncCancelReg,
};

impl IoUring {
    /// Register buffers for zero-copy I/O with `read_fixed`/`write_fixed`.
    ///
    /// # Errors
    ///
    /// Returns an error if registration fails (e.g., too many buffers,
    /// already registered).
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

    /// Restrict fixed-file-index auto-allocation (`IORING_FILE_INDEX_ALLOC`,
    /// e.g. [`Sqe::socket_direct`](crate::Sqe::socket_direct)'s
    /// allocate-for-me form) to the slice `[off, off + len)` of the
    /// registered-file table.
    ///
    /// Without this, the kernel is free to hand back any free slot; setting
    /// a range makes auto-allocation predictable — useful when the rest of
    /// the table is reserved for slots the caller assigns explicitly.
    ///
    /// # Errors
    ///
    /// Returns an error if no file table is registered or the range doesn't
    /// fit within it.
    pub fn register_file_alloc_range(&mut self, off: u32, len: u32) -> Result<(), Error> {
        let arg = IoUringFileIndexRange { off, len, resv: 0 };
        syscall::io_uring_register(
            self.fd,
            RegisterOp::RegisterFileAllocRange.into(),
            core::ptr::addr_of!(arg) as usize,
            0,
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
    pub fn register_eventfd(&mut self, efd: RawFd) -> Result<(), Error> {
        let raw: i32 = efd.as_i32();
        syscall::io_uring_register(
            self.fd,
            RegisterOp::RegisterEventFd.into(),
            core::ptr::addr_of!(raw) as usize,
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
    pub fn register_eventfd_async(&mut self, efd: RawFd) -> Result<(), Error> {
        let raw: i32 = efd.as_i32();
        syscall::io_uring_register(
            self.fd,
            RegisterOp::RegisterEventFdAsync.into(),
            core::ptr::addr_of!(raw) as usize,
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

    /// Pin this ring's io-wq worker threads to the CPUs named by `mask`.
    ///
    /// `mask` is a raw CPU bitmask in the same byte layout as `cpu_set_t`
    /// (bit `n` of byte `n / 8` selects CPU `n`) — this crate makes no
    /// libc calls and has no `cpu_set_t` of its own to offer, so the
    /// kernel's own wire format is exposed directly rather than
    /// reinventing a typed CPU-set wrapper for a single call site. The
    /// kernel truncates `mask` to its own `cpumask_size()` if longer, and
    /// zero-extends it if shorter, matching `sched_setaffinity(2)`'s own
    /// tolerance for a caller-sized mask.
    ///
    /// # Errors
    ///
    /// Returns an error if the kernel rejects the request (e.g. naming no
    /// CPU the process itself may run on).
    #[allow(clippy::cast_possible_truncation)]
    pub fn register_iowq_affinity(&mut self, mask: &[u8]) -> Result<(), Error> {
        syscall::io_uring_register(
            self.fd,
            RegisterOp::RegisterIowqAff.into(),
            mask.as_ptr() as usize,
            mask.len() as u32,
        )?;
        Ok(())
    }

    /// Undo `register_iowq_affinity`, releasing this ring's io-wq threads
    /// back to the submitting process's own CPU affinity.
    ///
    /// # Errors
    ///
    /// Returns an error if the kernel rejects the request.
    pub fn unregister_iowq_affinity(&mut self) -> Result<(), Error> {
        syscall::io_uring_register(self.fd, RegisterOp::UnregisterIowqAff.into(), 0, 0)?;
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
        let mut reg = IoUringRsrcUpdate {
            offset: u32::MAX,
            resv: 0,
            data: self.fd.as_usize() as u64,
        };
        syscall::io_uring_register(
            self.fd,
            RegisterOp::RegisterRingFds.into(),
            core::ptr::from_mut(&mut reg) as usize,
            1,
        )?;
        Ok(reg.offset)
    }

    /// Undo a previous `register_ring_fd`, releasing the fixed-fd slot at
    /// `offset`.
    ///
    /// After this call, `EnterFlags::REGISTERED_RING` must not be passed to
    /// `io_uring_enter` again until a fresh `register_ring_fd` call.
    ///
    /// # Errors
    ///
    /// Returns an error if `offset` names no registered ring fd.
    pub fn unregister_ring_fd(&mut self, offset: u32) -> Result<(), Error> {
        let mut reg = IoUringRsrcUpdate {
            offset,
            resv: 0,
            data: 0,
        };
        syscall::io_uring_register(
            self.fd,
            RegisterOp::UnregisterRingFds.into(),
            core::ptr::from_mut(&mut reg) as usize,
            1,
        )?;
        Ok(())
    }

    /// Start accepting submissions on a ring created with
    /// `SetupFlags::R_DISABLED`.
    ///
    /// A disabled ring rejects `io_uring_enter` until this call runs, which
    /// lets a caller finish registering buffers, files, or other resources
    /// before any request can execute against them.
    ///
    /// # Errors
    ///
    /// Returns an error if the kernel rejects the request (e.g. the ring
    /// was not created disabled).
    pub fn enable_rings(&mut self) -> Result<(), Error> {
        syscall::io_uring_register(self.fd, RegisterOp::RegisterEnableRings.into(), 0, 0)?;
        Ok(())
    }

    /// Cancel a request synchronously, blocking the calling thread until
    /// it is cancelled (or already too late) rather than requiring a
    /// separate `IORING_OP_ASYNC_CANCEL` submission and a poll for its
    /// completion.
    ///
    /// The kernel keeps retrying internally while a match is found but
    /// already completing (`-EALREADY`) until it either succeeds or
    /// [`SyncCancelReg::timeout`] elapses, so this call itself may block
    /// for that whole duration; `-ENOENT` and outright rejection still
    /// return immediately.
    ///
    /// # Errors
    ///
    /// Never returns [`Error::Syscall`] directly for the ordinary racy
    /// outcomes — `-ENOENT`, `-EALREADY` (surfaced as `-ETIME` once a
    /// timeout is set and elapses), and a plain kernel rejection are all
    /// folded into [`CancelOutcome`] instead, the same treatment the
    /// submitted `IORING_OP_ASYNC_CANCEL` path gives them. This can still
    /// return an error if the register syscall itself cannot be issued
    /// (e.g. an invalid fd).
    pub fn sync_cancel(&mut self, reg: SyncCancelReg) -> Result<CancelOutcome, Error> {
        let mut raw: RawSyncCancelReg = reg.as_raw();
        match syscall::io_uring_register(
            self.fd,
            RegisterOp::RegisterSyncCancel.into(),
            core::ptr::from_mut(&mut raw) as usize,
            1,
        ) {
            #[allow(clippy::cast_possible_truncation)]
            Ok(n) => Ok(CancelOutcome::Applied(n as u32)),
            Err(errno) => Ok(CancelOutcome::from_raw(-errno.raw())),
        }
    }

    /// Set this ring's NAPI busy-poll tracking strategy, timeout, and
    /// preference, replacing whatever was configured before (kernel 6.9+,
    /// requires `CONFIG_NET_RX_BUSY_POLL`).
    ///
    /// `busy_poll_timeout_usec` is clamped by the kernel to 10,000
    /// microseconds. Returns the settings that were in effect immediately
    /// before this call took effect, mirroring the kernel's own
    /// before/after-swap contract for this argument.
    ///
    /// Switching `tracking` away from [`NapiTrackingStrategy::Static`]
    /// silently drops any NAPI ids added with
    /// [`napi_add_static_id`](Self::napi_add_static_id).
    ///
    /// # Errors
    ///
    /// Returns an error if the ring was created with `IORING_SETUP_IOPOLL`
    /// (NAPI busy-poll and IOPOLL are mutually exclusive) or the kernel
    /// lacks NAPI support.
    pub fn register_napi(
        &mut self,
        busy_poll_timeout_usec: u32,
        prefer_busy_poll: bool,
        tracking: NapiTrackingStrategy,
    ) -> Result<NapiSettings, Error> {
        let mut raw = RawNapi::register(busy_poll_timeout_usec, prefer_busy_poll, tracking);
        syscall::io_uring_register(
            self.fd,
            RegisterOp::RegisterNapi.into(),
            core::ptr::from_mut(&mut raw) as usize,
            1,
        )?;
        Ok(NapiSettings::from_raw(&raw))
    }

    /// Stop NAPI busy-poll tracking, restoring plain irq-driven completion
    /// and forgetting every tracked NAPI id.
    ///
    /// Returns the settings that were in effect immediately before this
    /// call took effect.
    ///
    /// # Errors
    ///
    /// Returns an error if the kernel rejects the request.
    pub fn unregister_napi(&mut self) -> Result<NapiSettings, Error> {
        let mut raw = RawNapi::default();
        syscall::io_uring_register(
            self.fd,
            RegisterOp::UnregisterNapi.into(),
            core::ptr::from_mut(&mut raw) as usize,
            1,
        )?;
        Ok(NapiSettings::from_raw(&raw))
    }

    /// Add `napi_id` to this ring's statically tracked busy-poll set.
    ///
    /// Only valid once [`register_napi`](Self::register_napi) has set
    /// [`NapiTrackingStrategy::Static`] — with dynamic tracking (the
    /// default) the kernel discovers each socket's NAPI id on its own the
    /// first time the ring polls it, and this call is rejected.
    ///
    /// # Errors
    ///
    /// Returns an error if static tracking is not the current strategy,
    /// `napi_id` names no real NAPI instance, or it is already tracked.
    pub fn napi_add_static_id(&mut self, napi_id: u32) -> Result<(), Error> {
        let mut raw = RawNapi::static_id(NapiOp::StaticAddId, napi_id);
        syscall::io_uring_register(
            self.fd,
            RegisterOp::RegisterNapi.into(),
            core::ptr::from_mut(&mut raw) as usize,
            1,
        )?;
        Ok(())
    }

    /// Remove `napi_id` from this ring's statically tracked busy-poll set.
    ///
    /// # Errors
    ///
    /// Returns an error if static tracking is not the current strategy or
    /// `napi_id` is not currently tracked.
    pub fn napi_remove_static_id(&mut self, napi_id: u32) -> Result<(), Error> {
        let mut raw = RawNapi::static_id(NapiOp::StaticDelId, napi_id);
        syscall::io_uring_register(
            self.fd,
            RegisterOp::RegisterNapi.into(),
            core::ptr::from_mut(&mut raw) as usize,
            1,
        )?;
        Ok(())
    }

    /// Clone another ring's whole registered buffer table into this ring
    /// (kernel 6.12+), instead of re-registering the same buffers a
    /// second time.
    ///
    /// `src` names the source ring by its plain file descriptor. This
    /// ring must have no buffers registered — use
    /// [`clone_registered_buffers_replacing`](Self::clone_registered_buffers_replacing)
    /// if it already does. The two rings must share the same address
    /// space (e.g. two rings created by the same process).
    ///
    /// # Errors
    ///
    /// Returns an error if this ring already has buffers registered, the
    /// source ring has none, or the kernel otherwise rejects the request
    /// (e.g. kernel < 6.12, or the rings do not share an address space).
    pub fn clone_registered_buffers(&mut self, src: RawFd) -> Result<(), Error> {
        self.clone_registered_buffers_raw(src, CloneBuffersFlags::empty(), 0, 0, 0)
    }

    /// Like [`clone_registered_buffers`](Self::clone_registered_buffers),
    /// but permitted even when this ring already has a buffer table: any
    /// slot in the destination range that overlaps the clone is released
    /// and replaced rather than the call failing outright (kernel 6.13+).
    ///
    /// # Errors
    ///
    /// Returns an error if the source ring has no buffers registered or
    /// the kernel otherwise rejects the request.
    pub fn clone_registered_buffers_replacing(&mut self, src: RawFd) -> Result<(), Error> {
        self.clone_registered_buffers_raw(src, CloneBuffersFlags::DST_REPLACE, 0, 0, 0)
    }

    /// Clone only `nr` buffer-table slots, starting at `src_off` in the
    /// source ring's table and landing at `dst_off` in this ring's own
    /// table, with `flags` controlling source-fd lookup and destination
    /// replacement.
    ///
    /// Pass [`CloneBuffersFlags::DST_REPLACE`] to permit overlapping an
    /// existing destination range rather than failing with `-EBUSY`. Pass
    /// [`CloneBuffersFlags::SRC_REGISTERED`] only if `src` names a
    /// registered-ring-fd index (from [`register_ring_fd`](Self::register_ring_fd))
    /// rather than a plain file descriptor.
    ///
    /// # Errors
    ///
    /// Returns an error if the source ring has no buffers registered in
    /// the named range, the destination range is occupied without
    /// `DST_REPLACE`, or the kernel otherwise rejects the request.
    pub fn clone_registered_buffers_raw(
        &mut self,
        src: RawFd,
        flags: CloneBuffersFlags,
        src_off: u32,
        dst_off: u32,
        nr: u32,
    ) -> Result<(), Error> {
        let mut arg = IoUringCloneBuffers {
            src_fd: src.as_i32().cast_unsigned(),
            flags: flags.bits(),
            src_off,
            dst_off,
            nr,
            pad: [0; 3],
        };
        syscall::io_uring_register(
            self.fd,
            RegisterOp::RegisterCloneBuffers.into(),
            core::ptr::from_mut(&mut arg) as usize,
            0,
        )?;
        Ok(())
    }
}
