//! Scoped convenience methods on [`IoUring`]: `do_*` methods that submit a
//! single SQE, wait for completion, and return the result.

use super::IoUring;
use crate::error::{CompletionError, Error};
use crate::op::Sqe;
use crate::types::{
    AcceptFlags, DirFd, FileMode, FsyncFlags, MsgFlags, OpenFlags, RawFd, Statx, StatxFlags,
    StatxMask,
};

impl IoUring {
    /// Submit a single SQE, wait for its completion, and return the result.
    ///
    /// This is the building block for all `do_*` methods. The `&mut self`
    /// borrow prevents concurrent submissions and ensures any referenced
    /// data in the `Sqe` remains valid for the duration.
    fn run_one(&mut self, sqe: Sqe) -> Result<u32, Error> {
        self.push(sqe)?;
        self.submit_and_wait(1)?;
        self.complete()
            .ok_or(Error::Completion(CompletionError::NoCompletion))?
            .into_result()
    }

    /// Read from `fd` into `buf` at `offset`. Returns the byte count.
    ///
    /// `buf` is borrowed for the entire submit-and-wait cycle inside this
    /// call, which upholds `Sqe::read`'s safety contract without the
    /// caller needing an `unsafe` block themselves. See this crate's `Sqe`
    /// documentation for the completion-correlation caveat that still
    /// applies to every synchronous `do_*` helper.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the submission or the kernel operation fails.
    pub fn do_read(&mut self, fd: RawFd, buf: &mut [u8], offset: u64) -> Result<u32, Error> {
        // Safety: `buf` is borrowed by this call for its entire duration —
        // `run_one` submits and waits for the single completion before
        // returning, so the kernel cannot still be accessing `buf` after
        // this method returns.
        self.run_one(unsafe { Sqe::read(fd, buf, offset) })
    }

    /// Write `buf` to `fd` at `offset`. Returns the byte count.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the submission or the kernel operation fails.
    pub fn do_write(&mut self, fd: RawFd, buf: &[u8], offset: u64) -> Result<u32, Error> {
        // Safety: see `do_read` — `buf` outlives the kernel's access to it
        // because `run_one` submits and waits before returning.
        self.run_one(unsafe { Sqe::write(fd, buf, offset) })
    }

    /// Open a file relative to `dfd`. Returns the new fd as `u32`.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the submission or the kernel operation fails.
    pub fn do_openat(
        &mut self,
        dfd: DirFd,
        path: &core::ffi::CStr,
        flags: OpenFlags,
        mode: FileMode,
    ) -> Result<u32, Error> {
        // Safety: see `do_read` — `path` outlives the kernel's access to
        // it because `run_one` submits and waits before returning.
        self.run_one(unsafe { Sqe::openat(dfd, path, flags, mode) })
    }

    /// Close a file descriptor via io\_uring.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the submission or the kernel operation fails.
    pub fn do_close(&mut self, fd: RawFd) -> Result<u32, Error> {
        self.run_one(Sqe::close(fd))
    }

    /// Send data on a socket. Returns the byte count.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the submission or the kernel operation fails.
    pub fn do_send(&mut self, fd: RawFd, buf: &[u8], flags: MsgFlags) -> Result<u32, Error> {
        // Safety: see `do_read` — `buf` outlives the kernel's access to it
        // because `run_one` submits and waits before returning.
        self.run_one(unsafe { Sqe::send(fd, buf, flags) })
    }

    /// Receive data from a socket into `buf`. Returns the byte count.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the submission or the kernel operation fails.
    pub fn do_recv(&mut self, fd: RawFd, buf: &mut [u8], flags: MsgFlags) -> Result<u32, Error> {
        // Safety: see `do_read` — `buf` outlives the kernel's access to it
        // because `run_one` submits and waits before returning.
        self.run_one(unsafe { Sqe::recv(fd, buf, flags) })
    }

    /// Accept a connection (without capturing the peer address). Returns
    /// the new socket fd as `u32`.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the submission or the kernel operation fails.
    pub fn do_accept(&mut self, fd: RawFd, flags: AcceptFlags) -> Result<u32, Error> {
        self.run_one(Sqe::accept(fd, flags))
    }

    /// Stat a file. Populates `statx_buf` and returns 0 on success.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the submission or the kernel operation fails.
    pub fn do_statx(
        &mut self,
        dfd: DirFd,
        path: &core::ffi::CStr,
        flags: StatxFlags,
        mask: StatxMask,
        statx_buf: &mut Statx,
    ) -> Result<u32, Error> {
        // Safety: see `do_read` — `path` and `statx_buf` outlive the
        // kernel's access to them because `run_one` submits and waits
        // before returning.
        self.run_one(unsafe { Sqe::statx(dfd, path, flags, mask, statx_buf) })
    }

    /// Fsync a file descriptor.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the submission or the kernel operation fails.
    pub fn do_fsync(&mut self, fd: RawFd, flags: FsyncFlags) -> Result<u32, Error> {
        self.run_one(Sqe::fsync(fd, flags))
    }
}
