//! Scoped convenience methods on [`IoUring`]: `do_*` methods that submit a
//! single SQE, wait for completion, and return the result.
//!
//! # Why every submission here carries an identity tag
//!
//! A naive `push` + `submit_and_wait(1)` + `complete()` sequence assumes the
//! next CQE the ring produces belongs to the SQE it just pushed. That is not
//! guaranteed: a CQE left over from an earlier submission the caller never
//! drained, or an arrival from a still-armed multishot request, can occupy
//! the completion queue and get reaped first. Taking that CQE's result as
//! this call's outcome would silently return the wrong value and, worse,
//! could report a read/write/statx call as finished while the buffer it
//! actually named is still being written by the kernel.
//!
//! [`run_one`](IoUring::run_one) closes that gap by tagging every
//! synchronous submission with a `user_data` value minted from a private
//! per-ring counter that no other caller of this ring is expected to use,
//! then checking that the very next CQE carries that exact tag before
//! trusting its result. A mismatched CQE is consumed — this crate keeps no
//! stash that could hold it for later redelivery — and reported via
//! [`CompletionError::UnexpectedCompletion`](crate::CompletionError::UnexpectedCompletion)
//! rather than mistaken for this call's own result.

use super::IoUring;
use crate::error::{CompletionError, Error};
use crate::op::Sqe;
use crate::types::{
    AcceptFlags, DirFd, FileMode, FsyncFlags, MsgFlags, OpenFlags, RawFd, Statx, StatxFlags,
    StatxMask,
};

impl IoUring {
    /// High bit set on every tag `run_one` mints, so a `do_*` completion is
    /// recognisable even if it happens to share the low bits of some other
    /// caller's `user_data` scheme. Not a hard guarantee against a caller
    /// who deliberately mints tags in this range themselves — nothing in a
    /// `user_data` field can be forged-proof against that — but `do_*` is
    /// documented as requiring exclusive use of the ring for its call, so
    /// this is a diagnostic aid for the ordinary case (stray leftover CQEs,
    /// armed multishots) rather than a security boundary.
    pub(super) const DO_TAG_MARKER: u64 = 1 << 63;

    /// Mint the next tag for a synchronous `do_*` submission.
    const fn next_do_tag(&mut self) -> u64 {
        let tag = self.do_tag_next;
        self.do_tag_next = Self::DO_TAG_MARKER | (tag.wrapping_add(1) & !Self::DO_TAG_MARKER);
        tag
    }

    /// Submit a single SQE, wait for its completion, and return the result.
    ///
    /// This is the building block for all `do_*` methods. The `&mut self`
    /// borrow prevents concurrent submissions and ensures any referenced
    /// data in the `Sqe` remains valid for the duration.
    ///
    /// `min_complete` on the first `submit_and_wait` is satisfied by *any*
    /// CQE already sitting in the ring, not necessarily this call's own —
    /// a stray leftover completion (or a still-armed multishot arrival)
    /// can wake the kernel call before this SQE has actually finished.
    /// Bailing out on that first mismatch, the way a single `push` +
    /// `submit_and_wait(1)` + `complete()` would, returns while the
    /// pushed SQE is still in flight against the caller's borrowed
    /// buffer — exactly the unsoundness this method exists to close, not
    /// something it can reproduce. So this loops: every mismatched CQE is
    /// drained and discarded (this crate keeps no stash that could hold
    /// one for later redelivery), and only the first tag seen wrong is
    /// kept for the eventual diagnostic, until the tagged completion this
    /// call minted is actually reaped. Only then is it safe to say the
    /// borrow has ended.
    ///
    /// # Errors
    ///
    /// Returns [`CompletionError::UnexpectedCompletion`] once this call's
    /// own completion has been reaped, if any other CQE was drained along
    /// the way — see the module documentation for what that means and why
    /// the mismatched CQEs cannot be recovered afterward.
    fn run_one(&mut self, sqe: Sqe) -> Result<u32, Error> {
        let tag = self.next_do_tag();
        self.push(sqe.user_data(tag))?;
        self.submit_and_wait(1)?;

        let mut stray = None;
        loop {
            let completion = self
                .complete()
                .ok_or(Error::Completion(CompletionError::NoCompletion))?;
            if completion.user_data == tag {
                return stray.map_or_else(
                    || completion.into_result(),
                    |found| {
                        Err(Error::Completion(CompletionError::UnexpectedCompletion {
                            expected: tag,
                            found,
                        }))
                    },
                );
            }
            stray.get_or_insert(completion.user_data);
            // No new SQE to push here -- this call already pushed the one
            // it is waiting on. `submit_and_wait` with nothing queued is
            // a pure wait: `to_submit` computes to 0 and the syscall just
            // blocks for `min_complete` more completions.
            self.submit_and_wait(1)?;
        }
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
