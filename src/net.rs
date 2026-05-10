//! Safe wrappers around socket setup syscalls.
//!
//! Provides an owned [`Socket`] that closes on drop and exposes safe methods
//! for `bind`, `listen`, `setsockopt`, and `getsockname`. The raw file
//! descriptor is available via [`Socket::fd`] for use with io\_uring SQE
//! builders.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use crate::error::Error;
use crate::syscall;
use crate::types::{AcceptFlags, MsgFlags, RawFd, ShutdownHow, SockAddrIn};
use core::mem;

/// An owned socket file descriptor.
///
/// Closes the underlying fd on drop. Use [`Socket::fd`] to obtain the raw
/// descriptor for io\_uring operations.
pub struct Socket {
    fd: RawFd,
}

impl Socket {
    /// Create a new socket.
    ///
    /// `domain`, `sock_type`, and `protocol` are passed directly to the
    /// `socket(2)` syscall. Use the constants in [`crate::types`]
    /// (e.g. `AF_INET`, `SOCK_STREAM | SOCK_NONBLOCK`).
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the `socket` syscall fails.
    pub fn new(domain: i32, sock_type: i32, protocol: i32) -> Result<Self, Error> {
        let fd = syscall::socket(domain, sock_type, protocol)? as RawFd;
        Ok(Self { fd })
    }

    /// Return the raw file descriptor.
    ///
    /// The fd remains owned by this `Socket`; do **not** close it manually.
    #[inline]
    #[must_use]
    pub const fn fd(&self) -> RawFd {
        self.fd
    }

    /// Wrap an existing raw file descriptor in a `Socket`.
    ///
    /// This is the inverse of [`into_fd`](Socket::into_fd). Use it to adopt
    /// fds returned by io\_uring accept SQEs or other sources.
    ///
    /// # Safety
    ///
    /// `fd` must be a valid, open socket file descriptor. The caller
    /// transfers ownership — the `Socket` will close it on drop.
    #[inline]
    #[must_use]
    pub const unsafe fn from_fd(fd: RawFd) -> Self {
        Self { fd }
    }

    /// Consume the `Socket` and return the raw fd **without** closing it.
    ///
    /// The caller assumes ownership and is responsible for closing the fd.
    #[inline]
    #[must_use]
    pub const fn into_fd(self) -> RawFd {
        let fd = self.fd;
        mem::forget(self);
        fd
    }

    /// Bind the socket to `addr`.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the `bind` syscall fails.
    pub fn bind(&self, addr: &SockAddrIn) -> Result<(), Error> {
        syscall::bind(
            self.fd as usize,
            core::ptr::from_ref::<SockAddrIn>(addr).cast(),
            mem::size_of::<SockAddrIn>() as u32,
        )
        .map_err(Into::into)
    }

    /// Connect to a remote address.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the `connect` syscall fails.
    pub fn connect(&self, addr: &SockAddrIn) -> Result<(), Error> {
        syscall::connect(
            self.fd as usize,
            core::ptr::from_ref::<SockAddrIn>(addr).cast(),
            mem::size_of::<SockAddrIn>() as u32,
        )
        .map_err(Into::into)
    }

    /// Accept a connection, returning the new socket and peer address.
    ///
    /// `flags` can set properties on the returned socket (e.g.
    /// `AcceptFlags::NONBLOCK`).
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the `accept4` syscall fails.
    pub fn accept(&self, flags: AcceptFlags) -> Result<(Self, SockAddrIn), Error> {
        let mut addr = SockAddrIn::default();
        let mut len = mem::size_of::<SockAddrIn>() as u32;
        let fd = syscall::accept4(
            self.fd as usize,
            (&raw mut addr).cast(),
            &raw mut len,
            flags.bits() as i32,
        )? as RawFd;
        Ok((Self { fd }, addr))
    }

    /// Mark the socket as a passive listener with the given `backlog`.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the `listen` syscall fails.
    pub fn listen(&self, backlog: i32) -> Result<(), Error> {
        syscall::listen(self.fd as usize, backlog).map_err(Into::into)
    }

    /// Set a socket option.
    ///
    /// `level` and `optname` identify the option (e.g. `SOL_SOCKET`,
    /// `SO_REUSEADDR`). The value is passed by reference and its size is
    /// derived automatically.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the `setsockopt` syscall fails.
    pub fn set_option<T: Sized>(&self, level: i32, optname: i32, value: &T) -> Result<(), Error> {
        syscall::setsockopt(
            self.fd as usize,
            level,
            optname,
            core::ptr::from_ref::<T>(value).cast(),
            mem::size_of::<T>() as u32,
        )
        .map_err(Into::into)
    }

    /// Send data on the socket. Returns the number of bytes sent.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the `sendto` syscall fails.
    pub fn send(&self, buf: &[u8], flags: MsgFlags) -> Result<usize, Error> {
        syscall::sendto(self.fd as usize, buf.as_ptr(), buf.len(), flags.bits()).map_err(Into::into)
    }

    /// Receive data from the socket. Returns the number of bytes read.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the `recvfrom` syscall fails.
    pub fn recv(&self, buf: &mut [u8], flags: MsgFlags) -> Result<usize, Error> {
        syscall::recvfrom(self.fd as usize, buf.as_mut_ptr(), buf.len(), flags.bits())
            .map_err(Into::into)
    }

    /// Shut down part or all of the connection.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the `shutdown` syscall fails.
    pub fn shutdown(&self, how: ShutdownHow) -> Result<(), Error> {
        syscall::shutdown(self.fd as usize, how as u32).map_err(Into::into)
    }

    /// Close the socket, consuming it and returning any error.
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

    /// Retrieve the local address the socket is bound to.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the `getsockname` syscall fails.
    pub fn local_addr(&self) -> Result<SockAddrIn, Error> {
        let mut addr = SockAddrIn::default();
        let mut len = mem::size_of::<SockAddrIn>() as u32;
        syscall::getsockname(self.fd as usize, (&raw mut addr).cast(), &raw mut len)?;
        Ok(addr)
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        let _ = syscall::close(self.fd as usize);
    }
}
