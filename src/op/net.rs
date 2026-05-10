//! Networking SQEs: socket, connect/accept, send/recv (and variants).

use super::{Sqe, ZEROED};
use crate::types::{
    AcceptFlags, AddressFamily, IORING_ACCEPT_MULTISHOT, IORING_RECV_MULTISHOT, MsgFlags, MsgHdr,
    Opcode, ShutdownHow, SockAddrIn, SocketFlags, SocketType,
};

impl Sqe {
    /// Prepare a socket creation operation.
    ///
    /// `protocol` is the kernel protocol number (e.g. `IPPROTO_TCP = 6`,
    /// `IPPROTO_UDP = 17`). Pass `0` for the default protocol of the
    /// chosen `sock_type`. `flags` controls fd-level options like
    /// `NONBLOCK` and `CLOEXEC`. The CQE result is the new fd.
    #[must_use]
    pub fn socket(
        domain: AddressFamily,
        sock_type: SocketType,
        protocol: i32,
        flags: SocketFlags,
    ) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Socket.into();
        sqe.fd = domain.as_raw();
        sqe.off = sock_type.as_raw() as u64;
        sqe.len = protocol as u32;
        sqe.op_flags = flags.bits();
        Self(sqe)
    }

    /// Prepare a socket creation that allocates a fixed-file slot directly.
    ///
    /// Same as [`socket`](Self::socket) but sets `IORING_FILE_INDEX_ALLOC`
    /// in `splice_fd_in`, telling the kernel to auto-allocate a slot in
    /// the registered-files table and return its index in `cqe.res`.
    /// The returned index can be used directly with [`fixed_file`](Self::fixed_file)
    /// on a linked `connect` (or any subsequent op) — no userspace fd is
    /// ever materialized, saving a file-table lookup and avoiding the
    /// race window between syscall return and registration.
    ///
    /// Requires a registered-files table to be set up via
    /// [`IoUring::register_files`](crate::IoUring::register_files) (an
    /// empty sparse table works:
    /// `register_files(&[-1; N])`). Available on Linux 5.19+.
    #[must_use]
    pub fn socket_direct(
        domain: AddressFamily,
        sock_type: SocketType,
        protocol: i32,
        flags: SocketFlags,
    ) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Socket.into();
        sqe.fd = domain.as_raw();
        sqe.off = sock_type.as_raw() as u64;
        sqe.len = protocol as u32;
        sqe.op_flags = flags.bits();
        // `IORING_FILE_INDEX_ALLOC` — kernel reads splice_fd_in as the
        // fixed-file index; ~0u32 means "allocate one for me".
        sqe.splice_fd_in = -1;
        Self(sqe)
    }

    /// Prepare a shutdown operation.
    #[must_use]
    pub fn shutdown(fd: i32, how: ShutdownHow) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Shutdown.into();
        sqe.fd = fd;
        sqe.len = how.into();
        Self(sqe)
    }

    /// Prepare a connect operation.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn connect(fd: i32, addr: &[u8]) -> Self {
        unsafe { Self::connect_ptr(fd, addr.as_ptr(), addr.len() as u32) }
    }

    /// Prepare a connect operation from raw pointers.
    ///
    /// # Safety
    ///
    /// `addr` must point to a valid socket address of `addrlen` bytes that
    /// remains valid until the operation completes.
    #[must_use]
    pub unsafe fn connect_ptr(fd: i32, addr: *const u8, addrlen: u32) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Connect.into();
        sqe.fd = fd;
        sqe.addr = addr as u64;
        sqe.off = u64::from(addrlen);
        Self(sqe)
    }

    /// Prepare an accept operation without capturing the peer address.
    ///
    /// For accept with peer address, use [`accept_ptr`](Self::accept_ptr).
    #[must_use]
    pub fn accept(fd: i32, flags: AcceptFlags) -> Self {
        unsafe { Self::accept_ptr(fd, core::ptr::null_mut(), core::ptr::null_mut(), flags) }
    }

    /// Prepare an accept operation from raw pointers.
    ///
    /// # Safety
    ///
    /// If non-null, `addr` must point to a buffer large enough for the peer
    /// address and `addrlen` must point to its size. Both must remain valid
    /// until the operation completes.
    #[must_use]
    pub unsafe fn accept_ptr(
        fd: i32,
        addr: *mut u8,
        addrlen: *mut u32,
        flags: AcceptFlags,
    ) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Accept.into();
        sqe.fd = fd;
        sqe.addr = addr as u64;
        sqe.off = addrlen as u64;
        sqe.op_flags = flags.bits();
        Self(sqe)
    }

    /// Prepare an accept that captures the peer address into `addr`.
    ///
    /// On completion `addr` is populated with the peer's `SockAddrIn` and
    /// `addrlen` is updated to the actual address length.
    #[must_use]
    pub fn accept_with_addr(
        fd: i32,
        addr: &mut SockAddrIn,
        addrlen: &mut u32,
        flags: AcceptFlags,
    ) -> Self {
        unsafe {
            Self::accept_ptr(
                fd,
                core::ptr::from_mut(addr).cast(),
                core::ptr::from_mut(addrlen),
                flags,
            )
        }
    }

    /// Prepare a multishot accept operation.
    ///
    /// A single SQE generates a CQE for every accepted connection. Each CQE
    /// has `CqeFlags::MORE` set until the multishot is cancelled or errors.
    #[must_use]
    pub fn accept_multishot(fd: i32, flags: AcceptFlags) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Accept.into();
        sqe.fd = fd;
        sqe.op_flags = flags.bits();
        sqe.ioprio = IORING_ACCEPT_MULTISHOT;
        Self(sqe)
    }

    /// Prepare a send operation.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn send(fd: i32, buf: &[u8], flags: MsgFlags) -> Self {
        debug_assert!(buf.len() <= u32::MAX as usize);
        unsafe { Self::send_ptr(fd, buf.as_ptr(), buf.len() as u32, flags) }
    }

    /// Prepare a send operation from raw pointers.
    ///
    /// # Safety
    ///
    /// `buf` must point to at least `len` bytes of valid, readable memory
    /// that remains valid until the operation completes.
    #[must_use]
    pub unsafe fn send_ptr(fd: i32, buf: *const u8, len: u32, flags: MsgFlags) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Send.into();
        sqe.fd = fd;
        sqe.addr = buf as u64;
        sqe.len = len;
        sqe.op_flags = flags.bits();
        Self(sqe)
    }

    /// Prepare a recv operation.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn recv(fd: i32, buf: &mut [u8], flags: MsgFlags) -> Self {
        debug_assert!(buf.len() <= u32::MAX as usize);
        unsafe { Self::recv_ptr(fd, buf.as_mut_ptr(), buf.len() as u32, flags) }
    }

    /// Prepare a recv operation from raw pointers.
    ///
    /// # Safety
    ///
    /// `buf` must point to at least `len` bytes of valid, writable memory
    /// that remains valid until the operation completes.
    #[must_use]
    pub unsafe fn recv_ptr(fd: i32, buf: *mut u8, len: u32, flags: MsgFlags) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Recv.into();
        sqe.fd = fd;
        sqe.addr = buf as u64;
        sqe.len = len;
        sqe.op_flags = flags.bits();
        Self(sqe)
    }

    /// Prepare a multishot recv operation.
    ///
    /// A single SQE generates a CQE for every received message. Requires
    /// buffer selection (`buffer_select`) to be set — the kernel picks a
    /// buffer from the group for each arrival.
    #[must_use]
    pub fn recv_multishot(fd: i32, flags: MsgFlags) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Recv.into();
        sqe.fd = fd;
        sqe.op_flags = flags.bits() | IORING_RECV_MULTISHOT;
        Self(sqe)
    }

    /// Prepare a sendmsg operation.
    #[must_use]
    pub fn sendmsg(fd: i32, msg: &MsgHdr, flags: MsgFlags) -> Self {
        unsafe { Self::sendmsg_ptr(fd, core::ptr::from_ref(msg), flags) }
    }

    /// Prepare a sendmsg operation from a raw pointer.
    ///
    /// # Safety
    ///
    /// `msg` and all buffers it references must remain valid until the
    /// operation completes.
    #[must_use]
    pub unsafe fn sendmsg_ptr(fd: i32, msg: *const MsgHdr, flags: MsgFlags) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::SendMsg.into();
        sqe.fd = fd;
        sqe.addr = msg as u64;
        sqe.len = 1;
        sqe.op_flags = flags.bits();
        Self(sqe)
    }

    /// Prepare a recvmsg operation.
    #[must_use]
    pub fn recvmsg(fd: i32, msg: &mut MsgHdr, flags: MsgFlags) -> Self {
        unsafe { Self::recvmsg_ptr(fd, core::ptr::from_mut(msg), flags) }
    }

    /// Prepare a recvmsg operation from a raw pointer.
    ///
    /// # Safety
    ///
    /// `msg` and all buffers it references must remain valid until the
    /// operation completes.
    #[must_use]
    pub unsafe fn recvmsg_ptr(fd: i32, msg: *mut MsgHdr, flags: MsgFlags) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::RecvMsg.into();
        sqe.fd = fd;
        sqe.addr = msg as u64;
        sqe.len = 1;
        sqe.op_flags = flags.bits();
        Self(sqe)
    }

    /// Prepare a multishot recvmsg operation.
    ///
    /// Like `recv_multishot` but for the msghdr variant — useful when you
    /// need ancillary data (control messages, peer address). Requires
    /// buffer selection (`buffer_select`) to be set.
    ///
    /// # Safety
    ///
    /// `msg` and all buffers it references must remain valid until the
    /// multishot is cancelled or errors out.
    #[must_use]
    pub unsafe fn recvmsg_multishot(fd: i32, msg: *mut MsgHdr, flags: MsgFlags) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::RecvMsg.into();
        sqe.fd = fd;
        sqe.addr = msg as u64;
        sqe.len = 1;
        sqe.op_flags = flags.bits() | IORING_RECV_MULTISHOT;
        Self(sqe)
    }

    /// Prepare a zero-copy send operation (kernel 6.0+).
    ///
    /// Like `send`, but the kernel maps the buffer directly into the NIC
    /// without copying. The CQE with `CqeFlags::NOTIF` set confirms when
    /// the kernel has released the buffer — do not free `buf` before then.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn send_zc(fd: i32, buf: &[u8], flags: MsgFlags) -> Self {
        debug_assert!(buf.len() <= u32::MAX as usize);
        unsafe { Self::send_zc_ptr(fd, buf.as_ptr(), buf.len() as u32, flags) }
    }

    /// Prepare a zero-copy send from a raw pointer.
    ///
    /// # Safety
    ///
    /// `buf` must point to at least `len` bytes of valid readable memory that
    /// remains valid until the kernel sends a `CqeFlags::NOTIF` completion.
    #[must_use]
    pub unsafe fn send_zc_ptr(fd: i32, buf: *const u8, len: u32, flags: MsgFlags) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::SendZc.into();
        sqe.fd = fd;
        sqe.addr = buf as u64;
        sqe.len = len;
        sqe.op_flags = flags.bits();
        Self(sqe)
    }
}
