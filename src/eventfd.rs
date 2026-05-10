//! Safe wrapper around the `eventfd2` syscall.
//!
//! Provides an owned [`EventFd`] that closes on drop. An eventfd holds a
//! `u64` counter managed by the kernel — writes add to it, reads consume
//! it. This makes it ideal as a lightweight signalling primitive between
//! io\_uring completion handlers, threads, or even processes.
//!
//! # Example
//!
//! ```no_run
//! use ququmatz::{EventFd, IoUring};
//!
//! let efd = EventFd::new(0).unwrap();
//!
//! // Signal the eventfd (write the value 1)
//! efd.write(1).unwrap();
//!
//! // Read the counter via io_uring
//! let mut ring = IoUring::new(4).unwrap();
//! let mut buf = [0u8; 8];
//! ring.do_read(efd.fd(), &mut buf, 0).unwrap();
//!
//! let value = u64::from_ne_bytes(buf);
//! assert_eq!(value, 1);
//! ```

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use crate::error::Error;
use crate::syscall;
use crate::types::{EventFdFlags, RawFd};
use core::mem;

/// An owned eventfd file descriptor.
///
/// Closes the underlying fd on drop. Use [`EventFd::fd`] to obtain the raw
/// descriptor for io\_uring read/write operations.
///
/// An eventfd maintains a `u64` counter:
/// - **write**: adds the written `u64` value to the counter.
/// - **read**: returns the counter value and resets it to zero (or
///   decrements by 1 in semaphore mode).
pub struct EventFd {
    fd: RawFd,
}

impl EventFd {
    /// Create a new eventfd with `EFD_NONBLOCK` and the given initial value.
    ///
    /// The returned fd is set to non-blocking mode so it can be driven by
    /// io\_uring without risking a blocking read.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the `eventfd2` syscall fails (e.g. `EMFILE`
    /// when the per-process fd limit is reached).
    pub fn new(initval: u32) -> Result<Self, Error> {
        let fd = syscall::eventfd2(initval, EventFdFlags::NONBLOCK.bits())? as RawFd;
        Ok(Self { fd })
    }

    /// Create a new eventfd with custom flags and the given initial value.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the `eventfd2` syscall fails.
    pub fn with_flags(initval: u32, flags: EventFdFlags) -> Result<Self, Error> {
        let fd = syscall::eventfd2(initval, flags.bits())? as RawFd;
        Ok(Self { fd })
    }

    /// Return the raw file descriptor.
    ///
    /// The fd remains owned by this `EventFd`; do **not** close it manually.
    #[inline]
    #[must_use]
    pub const fn fd(&self) -> RawFd {
        self.fd
    }

    /// Consume the `EventFd` and return the raw fd **without** closing it.
    ///
    /// The caller assumes ownership and is responsible for closing the fd.
    #[inline]
    #[must_use]
    pub const fn into_fd(self) -> RawFd {
        let fd = self.fd;
        mem::forget(self);
        fd
    }

    /// Write a `u64` value to the eventfd, adding it to the counter.
    ///
    /// The value must not be `u64::MAX` (`0xFFFF_FFFF_FFFF_FFFF`), which
    /// is reserved by the kernel.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the write syscall fails (e.g. `EAGAIN` if
    /// the counter would overflow).
    pub fn write(&self, value: u64) -> Result<(), Error> {
        let buf = value.to_ne_bytes();
        syscall::write(self.fd as usize, buf.as_ptr(), 8)?;
        Ok(())
    }

    /// Read the current counter value, resetting it to zero.
    ///
    /// In semaphore mode (`EFD_SEMAPHORE`), returns 1 and decrements the
    /// counter by 1 instead.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the read syscall fails (e.g. `EAGAIN` if
    /// the counter is zero and the fd is non-blocking).
    pub fn read(&self) -> Result<u64, Error> {
        let mut buf = [0u8; 8];
        syscall::read(self.fd as usize, buf.as_mut_ptr(), 8)?;
        Ok(u64::from_ne_bytes(buf))
    }

    /// Close the eventfd, consuming it and returning any error.
    ///
    /// Unlike [`Drop`], this surfaces the error from `close(2)`.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the `close` syscall fails.
    pub fn close(self) -> Result<(), Error> {
        let fd = self.fd;
        mem::forget(self);
        syscall::close(fd as usize).map_err(Into::into)
    }
}

impl Drop for EventFd {
    fn drop(&mut self) {
        let _ = syscall::close(self.fd as usize);
    }
}
