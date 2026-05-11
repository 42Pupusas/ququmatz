//! Networking types: addresses, msghdr, send/recv flags, socket creation.

use super::buffers::IoVec;

// Raw kernel values. Internal — public callers use the typed `AddressFamily`
// and `SocketType` enums below. The submodule is private; `mod.rs` controls
// crate-level visibility via `pub(crate) use`.
pub const AF_INET: i32 = 2;
pub const AF_INET6: i32 = 10;
pub const SOCK_STREAM: i32 = 1;
pub const SOCK_DGRAM: i32 = 2;
#[cfg(test)]
pub const SOCK_NONBLOCK: i32 = 0o4000;

/// Address family for socket creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum AddressFamily {
    /// IPv4 (`AF_INET`).
    Inet = AF_INET,
    /// IPv6 (`AF_INET6`).
    Inet6 = AF_INET6,
}

impl AddressFamily {
    /// Return the raw kernel value.
    #[must_use]
    pub const fn as_raw(self) -> i32 {
        self as i32
    }
}

/// Socket type for socket creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum SocketType {
    /// Stream socket (`SOCK_STREAM` — TCP).
    Stream = SOCK_STREAM,
    /// Datagram socket (`SOCK_DGRAM` — UDP).
    Dgram = SOCK_DGRAM,
}

impl SocketType {
    /// Return the raw kernel value.
    #[must_use]
    pub const fn as_raw(self) -> i32 {
        self as i32
    }
}

/// Shutdown modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ShutdownHow {
    Read = 0,
    Write = 1,
    Both = 2,
}

impl From<ShutdownHow> for u32 {
    fn from(how: ShutdownHow) -> Self {
        how as Self
    }
}

bitflags! {
    /// Send/recv flags.
    ///
    /// Use `MsgFlags::default()` for no flags.
    pub struct MsgFlags(u32);
    const DONTWAIT = 0x40;
    const NOSIGNAL = 0x4000;
    const WAITALL = 0x100;
}

bitflags! {
    /// Accept flags (same as socket flags that make sense for accept4).
    ///
    /// Use `AcceptFlags::default()` for no flags.
    pub struct AcceptFlags(u32);
    const NONBLOCK = 0o4000;
}

bitflags! {
    /// Flags for `IORING_OP_SOCKET` (passed via `sqe.rw_flags`).
    ///
    /// These modify the created socket's behavior independently of the
    /// socket type passed in `sock_type`.
    pub struct SocketFlags(u32);
    /// Set the socket to non-blocking mode (`SOCK_NONBLOCK`).
    const NONBLOCK = 0o4000;
    /// Set close-on-exec on the new file descriptor (`SOCK_CLOEXEC`).
    const CLOEXEC = 0o2_000_000;
}

/// IPv4 socket address.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct SockAddrIn {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: u32,
    pub sin_zero: [u8; 8],
}

/// Message header for sendmsg/recvmsg.
///
/// The padding fields match the `x86_64` C ABI layout of `struct msghdr`:
/// the compiler inserts padding after `msg_namelen` (u32) to align
/// `msg_iov` (pointer) to 8 bytes, and after `msg_flags` (i32) to bring
/// the struct size to a multiple of 8 (the alignment of pointer fields).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct MsgHdr {
    pub msg_name: *mut u8,
    pub msg_namelen: u32,
    /// Alignment padding after u32 `msg_namelen` to align `msg_iov` to 8 bytes.
    pub(crate) _pad1: u32,
    pub msg_iov: *mut IoVec,
    pub msg_iovlen: usize,
    pub msg_control: *mut u8,
    pub msg_controllen: usize,
    pub msg_flags: i32,
    /// Trailing padding after i32 `msg_flags` for 8-byte struct alignment.
    pub(crate) _pad2: u32,
}

impl Default for MsgHdr {
    fn default() -> Self {
        // Safety: all fields are integer or pointer types; zero is valid.
        unsafe { core::mem::zeroed() }
    }
}
