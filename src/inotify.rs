//! Safe wrapper around inotify setup syscalls.
//!
//! Provides an owned [`Inotify`] that closes on drop and exposes safe methods
//! for `add_watch` and `remove_watch`. The raw file descriptor is available
//! via [`Inotify::fd`] for use with io\_uring SQE builders (e.g.
//! `Sqe::read(inotify.fd(), buf, len, 0)`).
//!
//! # Example
//!
//! ```no_run
//! use ququmatz::{Inotify, IoUring, Sqe, WatchMask};
//! use ququmatz::types::InotifyEvent;
//! use core::mem;
//!
//! let ino = Inotify::new().unwrap();
//! let wd = ino.add_watch(c"/tmp".to_bytes_with_nul(), WatchMask::CREATE).unwrap();
//!
//! let mut ring = IoUring::new(4).unwrap();
//! let mut buf = [0u8; 4096];
//! ring.push(
//!     unsafe { Sqe::read(ino.fd(), buf.as_mut_ptr(), buf.len() as u32, 0) }
//!         .user_data(1),
//! ).unwrap();
//! ring.submit_and_wait(1).unwrap();
//!
//! let cqe = ring.complete().unwrap();
//! let event: InotifyEvent =
//!     unsafe { core::ptr::read_unaligned(buf.as_ptr().cast()) };
//! ```

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use crate::error::Error;
use crate::syscall;
use crate::types::{IN_NONBLOCK, RawFd, WatchMask};
use core::mem;

/// An owned inotify file descriptor.
///
/// Closes the underlying fd on drop. Use [`Inotify::fd`] to obtain the raw
/// descriptor for io\_uring read operations.
pub struct Inotify {
    fd: RawFd,
}

impl Inotify {
    /// Create a new inotify instance with `IN_NONBLOCK`.
    ///
    /// The returned fd is set to non-blocking mode so it can be driven by
    /// io\_uring without risking a blocking read.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the `inotify_init1` syscall fails (e.g.
    /// `EMFILE` when the per-process inotify instance limit is reached).
    pub fn new() -> Result<Self, Error> {
        let fd = syscall::inotify_init1(IN_NONBLOCK)? as RawFd;
        Ok(Self { fd })
    }

    /// Return the raw file descriptor.
    ///
    /// The fd remains owned by this `Inotify`; do **not** close it manually.
    #[inline]
    #[must_use]
    pub const fn fd(&self) -> RawFd {
        self.fd
    }

    /// Consume the `Inotify` and return the raw fd **without** closing it.
    ///
    /// The caller assumes ownership and is responsible for closing the fd.
    #[inline]
    #[must_use]
    pub const fn into_fd(self) -> RawFd {
        let fd = self.fd;
        mem::forget(self);
        fd
    }

    /// Add a watch for `path` with the given event `mask`.
    ///
    /// `path` must be a null-terminated byte string (e.g. `c"/tmp"` or a
    /// `CStr`). Returns the watch descriptor, which can be used later with
    /// [`remove_watch`](Self::remove_watch).
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the `inotify_add_watch` syscall fails (e.g.
    /// `ENOENT` if the path does not exist, `EACCES` if the path is not
    /// readable).
    pub fn add_watch(&self, path: &[u8], mask: WatchMask) -> Result<i32, Error> {
        Ok(syscall::inotify_add_watch(self.fd as usize, path.as_ptr(), mask.bits())? as i32)
    }

    /// Remove a previously added watch.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the `inotify_rm_watch` syscall fails (e.g.
    /// `EINVAL` if `wd` is not a valid watch descriptor for this instance).
    pub fn remove_watch(&self, wd: i32) -> Result<(), Error> {
        syscall::inotify_rm_watch(self.fd as usize, wd)
    }
}

impl Drop for Inotify {
    fn drop(&mut self) {
        let _ = syscall::close(self.fd as usize);
    }
}
