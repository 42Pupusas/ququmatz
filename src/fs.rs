//! An owned file descriptor for regular files.
//!
//! The sibling of [`Socket`](crate::net::Socket): both are descriptors this
//! process owns and must close, and both exist so a descriptor produced by
//! an io\_uring completion has an owner from the moment it is read.
//!
//! They are separate types because they are not interchangeable. A
//! [`Socket`](crate::net::Socket) answers `bind`, `listen`, `shutdown` and
//! `getsockname`; none of those mean anything for a file opened by
//! `openat`. Returning a `Socket` from an open would compile and would be
//! a lie, so the open path gets its own owner.

use crate::error::Error;
use crate::syscall;
use crate::types::RawFd;
use core::mem;

/// An owned file descriptor.
///
/// Closes the underlying fd on drop. Use [`File::fd`] to obtain the raw
/// descriptor for io\_uring operations; it stays owned by this `File`.
#[derive(Debug)]
pub struct File {
    fd: RawFd,
}

impl File {
    /// Wrap an existing raw file descriptor.
    ///
    /// # Safety
    ///
    /// `fd` must be a valid, open file descriptor. The caller transfers
    /// ownership — the `File` closes it on drop, so no other owner may
    /// exist.
    #[inline]
    #[must_use]
    pub const unsafe fn from_fd(fd: RawFd) -> Self {
        Self { fd }
    }

    /// Return the raw file descriptor.
    ///
    /// The fd remains owned by this `File`; do **not** close it manually.
    #[inline]
    #[must_use]
    pub const fn fd(&self) -> RawFd {
        self.fd
    }

    /// Consume the `File` and return the raw fd **without** closing it.
    ///
    /// The caller assumes ownership and is responsible for closing the fd.
    #[inline]
    #[must_use]
    pub const fn into_fd(self) -> RawFd {
        let fd = self.fd;
        mem::forget(self);
        fd
    }

    /// Close the file, consuming it and returning any error.
    ///
    /// Unlike [`Drop`], this surfaces the error from `close(2)`.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the `close` syscall fails.
    pub fn close(self) -> Result<(), Error> {
        let fd = self.fd;
        mem::forget(self);
        syscall::close(fd).map_err(Into::into)
    }
}

impl Drop for File {
    fn drop(&mut self) {
        let _ = syscall::close(self.fd);
    }
}
