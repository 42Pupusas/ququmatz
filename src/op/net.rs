//! Networking SQEs: socket, connect/accept, send/recv (and variants).

use super::{Sqe, ZEROED};
use crate::types::{
    AcceptFlags, AddressFamily, IORING_ACCEPT_MULTISHOT, IORING_RECV_MULTISHOT, MsgFlags, MsgHdr,
    Opcode, RawFd, ShutdownHow, SockAddrIn, SocketFlags, SocketType,
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
    pub fn shutdown(fd: RawFd, how: ShutdownHow) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Shutdown.into();
        sqe.fd = fd.as_i32();
        sqe.len = how.into();
        Self(sqe)
    }

    /// Prepare a connect operation.
    ///
    /// # Safety
    ///
    /// `addr` is borrowed only for this call — the returned `Sqe` stores a
    /// raw pointer derived from it, not the borrow itself. The caller must
    /// ensure the memory `addr` points to remains valid until the kernel
    /// posts the completion for this operation.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub unsafe fn connect(fd: RawFd, addr: &[u8]) -> Self {
        unsafe { Self::connect_ptr(fd, addr.as_ptr(), addr.len() as u32) }
    }

    /// Prepare a connect operation from raw pointers.
    ///
    /// # Safety
    ///
    /// `addr` must point to a valid socket address of `addrlen` bytes that
    /// remains valid until the operation completes.
    #[must_use]
    pub unsafe fn connect_ptr(fd: RawFd, addr: *const u8, addrlen: u32) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Connect.into();
        sqe.fd = fd.as_i32();
        sqe.addr = addr as u64;
        sqe.off = u64::from(addrlen);
        Self(sqe)
    }

    /// Prepare an accept operation without capturing the peer address.
    ///
    /// For accept with peer address, use [`accept_ptr`](Self::accept_ptr).
    #[must_use]
    pub fn accept(fd: RawFd, flags: AcceptFlags) -> Self {
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
        fd: RawFd,
        addr: *mut u8,
        addrlen: *mut u32,
        flags: AcceptFlags,
    ) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Accept.into();
        sqe.fd = fd.as_i32();
        sqe.addr = addr as u64;
        sqe.off = addrlen as u64;
        sqe.op_flags = flags.bits();
        Self(sqe)
    }

    /// Prepare an accept that captures the peer address into `addr`.
    ///
    /// On completion `addr` is populated with the peer's `SockAddrIn` and
    /// `addrlen` is updated to the actual address length.
    ///
    /// # Safety
    ///
    /// `addr` and `addrlen` are borrowed only for this call — the returned
    /// `Sqe` stores raw pointers derived from them, not the borrows
    /// themselves. The caller must ensure both remain valid, writable, and
    /// exclusively accessible until the kernel posts the completion for
    /// this operation.
    #[must_use]
    pub unsafe fn accept_with_addr(
        fd: RawFd,
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
    pub fn accept_multishot(fd: RawFd, flags: AcceptFlags) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Accept.into();
        sqe.fd = fd.as_i32();
        sqe.op_flags = flags.bits();
        sqe.ioprio = IORING_ACCEPT_MULTISHOT;
        Self(sqe)
    }

    /// Prepare a multishot accept that installs into the ring's file table.
    ///
    /// Each connection goes into a slot of the registered file table rather
    /// than this process's descriptor table, and the CQE result is the slot
    /// index rather than a descriptor.
    ///
    /// The slot is always kernel-chosen:
    /// `io_uring_prep_multishot_accept_direct(3)` takes no `file_index`
    /// argument, because one armed request accepts many connections and
    /// they cannot all share a slot. Callers who also assign slots
    /// explicitly can separate the ranges with
    /// `IORING_REGISTER_FILE_ALLOC_RANGE`, which this crate does not wrap.
    ///
    /// Requires a registered file table — see
    /// [`IoUring::register_files`](crate::IoUring::register_files). When the
    /// table is full the CQE result is `-ENFILE` and the request *ends*,
    /// since the kernel gates its re-arm on a non-negative result.
    ///
    /// `SOCK_CLOEXEC` is rejected by the kernel for direct accepts.
    #[must_use]
    pub fn accept_multishot_direct(fd: RawFd, flags: AcceptFlags) -> Self {
        let mut sqe = Self::accept_multishot(fd, flags);
        // `IORING_FILE_INDEX_ALLOC`: the kernel reads `file_index` (which
        // aliases `splice_fd_in`) as ~0u32 and allocates a slot per
        // connection.
        sqe.0.splice_fd_in = -1;
        sqe
    }

    /// Prepare a send operation.
    ///
    /// # Safety
    ///
    /// `buf` is borrowed only for this call — the returned `Sqe` stores a
    /// raw pointer derived from it, not the borrow itself. The caller must
    /// ensure the memory `buf` points to remains valid and readable until
    /// the kernel posts the completion for this operation.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub unsafe fn send(fd: RawFd, buf: &[u8], flags: MsgFlags) -> Self {
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
    pub unsafe fn send_ptr(fd: RawFd, buf: *const u8, len: u32, flags: MsgFlags) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Send.into();
        sqe.fd = fd.as_i32();
        sqe.addr = buf as u64;
        sqe.len = len;
        sqe.op_flags = flags.bits();
        Self(sqe)
    }

    /// Prepare a recv operation.
    ///
    /// # Safety
    ///
    /// `buf` is borrowed only for this call — the returned `Sqe` stores a
    /// raw pointer derived from it, not the borrow itself. The caller must
    /// ensure the memory `buf` points to remains valid, writable, and
    /// exclusively accessible until the kernel posts the completion for
    /// this operation.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub unsafe fn recv(fd: RawFd, buf: &mut [u8], flags: MsgFlags) -> Self {
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
    pub unsafe fn recv_ptr(fd: RawFd, buf: *mut u8, len: u32, flags: MsgFlags) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Recv.into();
        sqe.fd = fd.as_i32();
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
    pub fn recv_multishot(fd: RawFd, flags: MsgFlags) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Recv.into();
        sqe.fd = fd.as_i32();
        sqe.op_flags = flags.bits();
        // Multishot bit lives in `ioprio`, NOT `op_flags` — the latter
        // aliases `msg_flags` for recv, where bit 1 is `MSG_PEEK`.
        sqe.ioprio = IORING_RECV_MULTISHOT;
        Self(sqe)
    }

    /// Prepare a sendmsg operation.
    ///
    /// # Safety
    ///
    /// `msg` and every buffer it references are borrowed only for this call
    /// — the returned `Sqe` stores a raw pointer derived from `msg`, not
    /// the borrow itself. The caller must ensure `msg` and everything it
    /// points to remain valid and readable until the kernel posts the
    /// completion for this operation.
    #[must_use]
    pub unsafe fn sendmsg(fd: RawFd, msg: &MsgHdr, flags: MsgFlags) -> Self {
        unsafe { Self::sendmsg_ptr(fd, core::ptr::from_ref(msg), flags) }
    }

    /// Prepare a sendmsg operation from a raw pointer.
    ///
    /// # Safety
    ///
    /// `msg` and all buffers it references must remain valid until the
    /// operation completes.
    #[must_use]
    pub unsafe fn sendmsg_ptr(fd: RawFd, msg: *const MsgHdr, flags: MsgFlags) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::SendMsg.into();
        sqe.fd = fd.as_i32();
        sqe.addr = msg as u64;
        sqe.len = 1;
        sqe.op_flags = flags.bits();
        Self(sqe)
    }

    /// Prepare a recvmsg operation.
    ///
    /// # Safety
    ///
    /// `msg` and every buffer it references are borrowed only for this call
    /// — the returned `Sqe` stores a raw pointer derived from `msg`, not
    /// the borrow itself. The caller must ensure `msg` and everything it
    /// points to remain valid, writable, and exclusively accessible until
    /// the kernel posts the completion for this operation.
    #[must_use]
    pub unsafe fn recvmsg(fd: RawFd, msg: &mut MsgHdr, flags: MsgFlags) -> Self {
        unsafe { Self::recvmsg_ptr(fd, core::ptr::from_mut(msg), flags) }
    }

    /// Prepare a recvmsg operation from a raw pointer.
    ///
    /// # Safety
    ///
    /// `msg` and all buffers it references must remain valid until the
    /// operation completes.
    #[must_use]
    pub unsafe fn recvmsg_ptr(fd: RawFd, msg: *mut MsgHdr, flags: MsgFlags) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::RecvMsg.into();
        sqe.fd = fd.as_i32();
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
    pub unsafe fn recvmsg_multishot(fd: RawFd, msg: *mut MsgHdr, flags: MsgFlags) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::RecvMsg.into();
        sqe.fd = fd.as_i32();
        sqe.addr = msg as u64;
        sqe.len = 1;
        sqe.op_flags = flags.bits();
        // Multishot bit lives in `ioprio`, NOT `op_flags` — same reasoning
        // as `recv_multishot`.
        sqe.ioprio = IORING_RECV_MULTISHOT;
        Self(sqe)
    }

    /// Prepare a zero-copy send operation (kernel 6.0+).
    ///
    /// Like `send`, but the kernel maps the buffer directly into the NIC
    /// without copying. The CQE with `CqeFlags::NOTIF` set confirms when
    /// the kernel has released the buffer — do not free `buf` before then.
    ///
    /// # Safety
    ///
    /// `buf` is borrowed only for this call — the returned `Sqe` stores a
    /// raw pointer derived from it, not the borrow itself. The caller must
    /// ensure the memory `buf` points to remains valid and readable until
    /// the kernel posts the `CqeFlags::NOTIF` completion that releases it
    /// — not merely the first completion, which may only signal submission.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub unsafe fn send_zc(fd: RawFd, buf: &[u8], flags: MsgFlags) -> Self {
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
    pub unsafe fn send_zc_ptr(fd: RawFd, buf: *const u8, len: u32, flags: MsgFlags) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::SendZc.into();
        sqe.fd = fd.as_i32();
        sqe.addr = buf as u64;
        sqe.len = len;
        sqe.op_flags = flags.bits();
        Self(sqe)
    }
}
