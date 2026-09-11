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

    /// Combine this type with socket flags the way `socket(2)` expects.
    ///
    /// `SOCK_NONBLOCK` and `SOCK_CLOEXEC` are not a separate argument to
    /// `socket(2)`; they are OR'd into the type, and `IORING_OP_SOCKET`
    /// keeps that convention:
    ///
    /// ```text
    /// if (sqe->addr || sqe->rw_flags || sqe->buf_index)
    ///         return -EINVAL;
    /// sock->type = READ_ONCE(sqe->off);
    /// sock->flags = sock->type & ~SOCK_TYPE_MASK;
    /// ```
    ///
    /// So the flags ride in the type field and `rw_flags` must be zero —
    /// putting the flags there instead fails the request outright with
    /// `EINVAL`, whatever the flags are.
    #[must_use]
    #[allow(clippy::cast_sign_loss)]
    pub const fn with_flags(self, flags: SocketFlags) -> u32 {
        self.as_raw() as u32 | flags.bits()
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
    /// Set close-on-exec on descriptors received through `SCM_RIGHTS`
    /// (`MSG_CMSG_CLOEXEC`, recvmsg only).
    ///
    /// The kernel applies the flag as it installs each descriptor. A later
    /// `fcntl(F_SETFD)` cannot do the same: between the recvmsg and the
    /// fcntl, a concurrent fork+exec leaks the descriptor to the child.
    const CMSG_CLOEXEC = 0x4000_0000;
}

bitflags! {
    /// Flags the kernel writes *back* into `msg_flags` after a `recvmsg`.
    ///
    /// These are an output, not an input: a value set in `msg_flags`
    /// before submission is overwritten and ignored, which is why they are
    /// a separate type from [`MsgFlags`] rather than more constants on it.
    ///
    /// [`TRUNC`](Self::TRUNC) is the one that matters. A datagram longer
    /// than the supplied buffers is delivered truncated and the CQE result
    /// is the number of bytes *kept*, which is indistinguishable from a
    /// short datagram that arrived whole. Only this flag says the rest was
    /// discarded.
    pub struct MsgOutFlags(u32);
    /// Out-of-band data (`MSG_OOB`).
    const OOB = 0x1;
    /// Control data was discarded for lack of room (`MSG_CTRUNC`).
    const CTRUNC = 0x8;
    /// Payload was discarded for lack of room (`MSG_TRUNC`).
    const TRUNC = 0x20;
    /// This read ends a record (`MSG_EOR`).
    const EOR = 0x80;
    /// The message came from the socket error queue (`MSG_ERRQUEUE`).
    const ERRQUEUE = 0x2000;
}

impl MsgOutFlags {
    /// Adopt the `msg_flags` value the kernel wrote back.
    ///
    /// Unknown bits are kept rather than masked away: this describes what
    /// a kernel reported, and a newer kernel may report a bit this crate
    /// does not name yet.
    #[must_use]
    pub(crate) const fn from_raw(bits: u32) -> Self {
        Self(bits)
    }
}

bitflags! {
    /// Accept flags (same as socket flags that make sense for accept4).
    ///
    /// Use `AcceptFlags::default()` for no flags.
    pub struct AcceptFlags(u32);
    const NONBLOCK = 0o4000;
}

bitflags! {
    /// Flags for `IORING_OP_SOCKET`, carried in the socket *type*.
    ///
    /// These modify the created socket's behaviour independently of the
    /// socket type, but they do not travel in a field of their own: see
    /// [`SocketType::with_flags`].
    ///
    /// Use `SocketFlags::default()` for no flags.
    pub struct SocketFlags(u32);
    /// Set the socket to non-blocking mode (`SOCK_NONBLOCK`).
    const NONBLOCK = 0o4000;
    /// Set close-on-exec on the new file descriptor (`SOCK_CLOEXEC`).
    const CLOEXEC = 0o2_000_000;
}

/// IPv4 socket address.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(C)]
pub struct SockAddrIn {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: u32,
    pub sin_zero: [u8; 8],
}

impl SockAddrIn {
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut buf = [0u8; 16];
        buf[0..2].copy_from_slice(&self.sin_family.to_ne_bytes());
        buf[2..4].copy_from_slice(&self.sin_port.to_ne_bytes());
        buf[4..8].copy_from_slice(&self.sin_addr.to_ne_bytes());
        buf
    }
}

/// Message header for sendmsg/recvmsg.
///
/// Field order matches the kernel's `struct msghdr`. The padding around
/// `msg_namelen` and `msg_flags` is left to `repr(C)` rather than written
/// out: on 64-bit targets it inserts four bytes after each to align the
/// following pointer, and on 32-bit ARM it inserts none, because pointers
/// there align to 4. Declaring those gaps as `u32` fields would make them
/// real members on ARM and displace every pointer after them.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct MsgHdr {
    pub msg_name: *mut u8,
    pub msg_namelen: u32,
    pub msg_iov: *mut IoVec,
    pub msg_iovlen: usize,
    pub msg_control: *mut u8,
    pub msg_controllen: usize,
    pub msg_flags: i32,
}

const _: () = assert!(
    core::mem::size_of::<MsgHdr>() == 7 * core::mem::size_of::<*mut u8>(),
    "MsgHdr must occupy exactly seven pointer-widths: four pointer-sized members, and three 32-bit members each padded out to a pointer. A padding field declared by hand breaks this on 32-bit targets, where the gap it claims to fill does not exist."
);

const _: () = assert!(
    core::mem::offset_of!(MsgHdr, msg_iov) == 2 * core::mem::size_of::<*mut u8>(),
    "msg_iov must sit exactly two pointer-widths in. A hand-declared padding field before it is invisible in the total size on 64-bit targets but displaces this offset on 32-bit ones."
);

impl Default for MsgHdr {
    fn default() -> Self {
        // Safety: all fields are integer or pointer types; zero is valid.
        unsafe { core::mem::zeroed() }
    }
}

/// Header the kernel prepends to each multishot-`recvmsg` buffer.
///
/// Plain `recvmsg` writes the payload straight into the buffer. **Multishot**
/// `recvmsg` does not: into the provided buffer the kernel writes this 16-byte
/// header, then the peer name, then the control (cmsg) data, then the payload —
/// because a single multishot request must self-describe how each delivered
/// buffer is carved up. Treating the buffer as raw payload (as you would for
/// [`recv_multishot`](crate::op::Sqe::recv_multishot)) yields a header-prefixed,
/// truncated mess.
///
/// Mirrors the kernel's `struct io_uring_recvmsg_out`. The four `u32` fields
/// report what *would have been* written by a blocking `recvmsg(2)`:
///
/// - `namelen` — peer-address bytes. May exceed the `msg_namelen` you supplied
///   if the address was truncated; the buffer still only reserves
///   `msg_namelen` bytes for it, so read no more than that.
/// - `controllen` — control/cmsg bytes (likewise capped by your
///   `msg_controllen`).
/// - `payloadlen` — payload bytes.
/// - `flags` — the resulting `msg_flags` (`MSG_TRUNC`, `MSG_CTRUNC`, …).
///
/// Use [`RecvmsgOut::parse`] to validate a delivered buffer and slice out the
/// name / control / payload sub-regions safely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct RecvmsgOut {
    pub namelen: u32,
    pub controllen: u32,
    pub payloadlen: u32,
    pub flags: u32,
}

/// The name, control, and payload sub-slices carved out of a multishot
/// `recvmsg` buffer by [`RecvmsgOut::parse`].
///
/// Each slice borrows the original buffer. The lengths reflect what is actually
/// readable in the buffer — i.e. capped at the `msg_namelen` / `msg_controllen`
/// reserved when the request was prepared, not the (possibly larger) values the
/// header reports for a truncated name or control.
#[derive(Debug)]
pub struct RecvmsgParts<'a> {
    /// The `io_uring_recvmsg_out` header itself.
    pub header: RecvmsgOut,
    /// Peer address bytes (length `min(header.namelen, msg_namelen)`).
    pub name: &'a [u8],
    /// Control/cmsg bytes (length `min(header.controllen, msg_controllen)`).
    pub control: &'a [u8],
    /// Payload bytes (the remainder of the kernel-written region).
    pub payload: &'a [u8],
}

impl RecvmsgOut {
    /// Size of the prepended header, in bytes (always 16).
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// Validate and split a buffer delivered by
    /// [`recvmsg_multishot`](crate::op::Sqe::recvmsg_multishot).
    ///
    /// `buf` is the buffer the kernel chose (e.g. via
    /// `BufferConsumer::buffer(buf_id, cqe.result)`); `msg_namelen` and
    /// `msg_controllen` are the values from the `MsgHdr` you submitted with the
    /// request — they determine the fixed widths of the name and control
    /// regions inside the buffer (the kernel reserves exactly that much,
    /// regardless of how much was actually received).
    ///
    /// Returns the parsed [`RecvmsgOut`] header plus borrowed name / control /
    /// payload sub-slices, or `None` if the buffer is too small to contain the
    /// header and both fixed-width regions (which is how the kernel signals an
    /// internal truncation — equivalent to liburing's
    /// `io_uring_recvmsg_validate` returning `NULL`).
    ///
    /// This mirrors `io_uring_recvmsg_validate` + the
    /// `io_uring_recvmsg_{name,cmsg_firsthdr,payload}` accessors: the name
    /// region is always `msg_namelen` wide and the control region always
    /// `msg_controllen` wide, with the payload occupying the rest.
    #[must_use]
    pub fn parse(buf: &[u8], msg_namelen: u32, msg_controllen: u32) -> Option<RecvmsgParts<'_>> {
        let name_reserved = msg_namelen as usize;
        let ctrl_reserved = msg_controllen as usize;

        // The buffer must hold at least the header + both reserved regions; if
        // it doesn't, the kernel truncated internally and the buffer is invalid.
        let fixed = Self::SIZE
            .checked_add(name_reserved)?
            .checked_add(ctrl_reserved)?;
        if buf.len() < fixed {
            return None;
        }

        let header = Self {
            namelen: Self::read_u32(buf, 0),
            controllen: Self::read_u32(buf, 4),
            payloadlen: Self::read_u32(buf, 8),
            flags: Self::read_u32(buf, 12),
        };

        // The readable name/control are capped at what we reserved: a truncated
        // address reports a larger `namelen` but only `msg_namelen` bytes exist.
        let name_len = (header.namelen as usize).min(name_reserved);
        let ctrl_len = (header.controllen as usize).min(ctrl_reserved);

        let name_start = Self::SIZE;
        let ctrl_start = name_start + name_reserved;
        let payload_start = ctrl_start + ctrl_reserved;

        Some(RecvmsgParts {
            header,
            name: &buf[name_start..name_start + name_len],
            control: &buf[ctrl_start..ctrl_start + ctrl_len],
            payload: &buf[payload_start..],
        })
    }
    /// Read a `u32` at `off` from `buf` without assuming alignment.
    ///
    /// The kernel writes `struct io_uring_recvmsg_out` in native byte order,
    /// so this decodes native-endian. Callers guarantee `off + 4 <=
    /// buf.len()`.
    const fn read_u32(buf: &[u8], off: usize) -> u32 {
        u32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
    }
}
