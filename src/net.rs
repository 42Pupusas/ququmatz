//! Safe wrappers around socket setup syscalls.
//!
//! Provides an owned [`Socket`] that closes on drop and exposes safe methods
//! for `bind`, `listen`, `setsockopt`, and `getsockname`. The raw file
//! descriptor is available via [`Socket::fd`] for use with io\_uring SQE
//! builders.

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
    pub fn new(domain: i32, sock_type: i32, protocol: i32) -> Result<Self, Error> {
        let fd = syscall::socket(domain, sock_type, protocol)? as RawFd;
        Ok(Self { fd })
    }

    /// Return the raw file descriptor.
    ///
    /// The fd remains owned by this `Socket`; do **not** close it manually.
    #[inline]
    pub fn fd(&self) -> RawFd {
        self.fd
    }

    /// Consume the `Socket` and return the raw fd **without** closing it.
    ///
    /// The caller assumes ownership and is responsible for closing the fd.
    #[inline]
    pub fn into_fd(self) -> RawFd {
        let fd = self.fd;
        mem::forget(self);
        fd
    }

    /// Bind the socket to `addr`.
    pub fn bind(&self, addr: &SockAddrIn) -> Result<(), Error> {
        syscall::bind(
            self.fd as usize,
            (addr as *const SockAddrIn).cast(),
            mem::size_of::<SockAddrIn>() as u32,
        )
    }

    /// Connect to a remote address.
    pub fn connect(&self, addr: &SockAddrIn) -> Result<(), Error> {
        syscall::connect(
            self.fd as usize,
            (addr as *const SockAddrIn).cast(),
            mem::size_of::<SockAddrIn>() as u32,
        )
    }

    /// Accept a connection, returning the new socket and peer address.
    ///
    /// `flags` can set properties on the returned socket (e.g.
    /// `AcceptFlags::NONBLOCK`).
    pub fn accept(&self, flags: AcceptFlags) -> Result<(Socket, SockAddrIn), Error> {
        let mut addr = SockAddrIn::default();
        let mut len = mem::size_of::<SockAddrIn>() as u32;
        let fd = syscall::accept4(
            self.fd as usize,
            (&raw mut addr).cast(),
            &raw mut len,
            flags.bits() as i32,
        )? as RawFd;
        Ok((Socket { fd }, addr))
    }

    /// Mark the socket as a passive listener with the given `backlog`.
    pub fn listen(&self, backlog: i32) -> Result<(), Error> {
        syscall::listen(self.fd as usize, backlog)
    }

    /// Set a socket option.
    ///
    /// `level` and `optname` identify the option (e.g. `SOL_SOCKET`,
    /// `SO_REUSEADDR`). The value is passed by reference and its size is
    /// derived automatically.
    pub fn set_option<T: Sized>(&self, level: i32, optname: i32, value: &T) -> Result<(), Error> {
        syscall::setsockopt(
            self.fd as usize,
            level,
            optname,
            (value as *const T).cast(),
            mem::size_of::<T>() as u32,
        )
    }

    /// Send data on the socket. Returns the number of bytes sent.
    pub fn send(&self, buf: &[u8], flags: MsgFlags) -> Result<usize, Error> {
        syscall::sendto(self.fd as usize, buf.as_ptr(), buf.len(), flags.bits())
    }

    /// Receive data from the socket. Returns the number of bytes read.
    pub fn recv(&self, buf: &mut [u8], flags: MsgFlags) -> Result<usize, Error> {
        syscall::recvfrom(self.fd as usize, buf.as_mut_ptr(), buf.len(), flags.bits())
    }

    /// Shut down part or all of the connection.
    pub fn shutdown(&self, how: ShutdownHow) -> Result<(), Error> {
        syscall::shutdown(self.fd as usize, how as u32)
    }

    /// Close the socket, consuming it and returning any error.
    ///
    /// Unlike [`Drop`], this surfaces the error from `close(2)`.
    pub fn close(self) -> Result<(), Error> {
        let fd = self.fd;
        mem::forget(self);
        syscall::close(fd as usize)
    }

    /// Retrieve the local address the socket is bound to.
    pub fn local_addr(&self) -> Result<SockAddrIn, Error> {
        let mut addr = SockAddrIn::default();
        let mut len = mem::size_of::<SockAddrIn>() as u32;
        syscall::getsockname(
            self.fd as usize,
            (&raw mut addr).cast(),
            &raw mut len,
        )?;
        Ok(addr)
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        let _ = syscall::close(self.fd as usize);
    }
}
