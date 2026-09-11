//! `IoUring::register_*` methods (non-pbuf): buffers, files, eventfd,
//! workqueue caps, ring-fd registration.

use super::IoUring;
use crate::error::Error;
use crate::syscall;
use crate::types::{
    CancelOutcome, IoUringFilesUpdate, IoUringRsrcUpdate, IoVec, RawFd, RawSyncCancelReg,
    RegisterOp, SyncCancelReg,
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
}
