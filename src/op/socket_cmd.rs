//! `IORING_OP_URING_CMD` socket sub-commands (`SOCKET_URING_OP_*`).
//!
//! See [`crate::types::SocketUringCmdOp`] for the field-union layout these
//! constructors rely on — every one of them fits in the ordinary 64-byte
//! SQE.

use super::{Sqe, ZEROED};
use crate::types::{Opcode, RawFd, SocketUringCmdOp};

impl Sqe {
    /// Prepare `SOCKET_URING_OP_SIOCINQ`: report bytes currently queued
    /// for reading on `fd`. The CQE result is the byte count, matching
    /// `ioctl(fd, SIOCINQ, ...)`'s own return.
    #[must_use]
    pub fn uring_cmd_sock_inq(fd: RawFd) -> Self {
        Self::uring_cmd_sock_op(fd, SocketUringCmdOp::SiocInq)
    }

    /// Prepare `SOCKET_URING_OP_SIOCOUTQ`: report bytes currently queued
    /// for writing (not yet acknowledged, for TCP) on `fd`.
    #[must_use]
    pub fn uring_cmd_sock_outq(fd: RawFd) -> Self {
        Self::uring_cmd_sock_op(fd, SocketUringCmdOp::SiocOutq)
    }

    fn uring_cmd_sock_op(fd: RawFd, op: SocketUringCmdOp) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::UringCmd.into();
        sqe.fd = fd.as_i32();
        sqe.set_cmd_op(op.into());
        Self(sqe)
    }

    /// Prepare `SOCKET_URING_OP_GETSOCKOPT`.
    ///
    /// Restricted by the kernel to `level == SOL_SOCKET`; any other level
    /// is rejected with `-EOPNOTSUPP`. On success the CQE result is the
    /// option's actual length, which may be smaller than `optval.len()`
    /// (the "report how much was really copied" contract `getsockopt(2)`
    /// itself has via its `optlen` out-parameter).
    ///
    /// # Safety
    ///
    /// `optval` is borrowed only for this call — the returned `Sqe` stores
    /// a raw pointer derived from it, not the borrow itself. The caller
    /// must ensure the memory `optval` points to remains valid and
    /// writable until the kernel posts the completion for this operation.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub unsafe fn uring_cmd_sock_getsockopt(
        fd: RawFd,
        level: u32,
        optname: u32,
        optval: &mut [u8],
    ) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::UringCmd.into();
        sqe.fd = fd.as_i32();
        sqe.set_cmd_op(SocketUringCmdOp::GetSockOpt.into());
        sqe.set_sock_level(level);
        sqe.set_sock_optname(optname);
        sqe.set_sock_optval(optval.as_mut_ptr() as u64);
        sqe.set_optlen(optval.len() as u32);
        Self(sqe)
    }

    /// Prepare `SOCKET_URING_OP_SETSOCKOPT`.
    ///
    /// Unlike [`uring_cmd_sock_getsockopt`](Self::uring_cmd_sock_getsockopt),
    /// the kernel forwards `level` unrestricted, exactly as the ordinary
    /// `setsockopt(2)` syscall would.
    ///
    /// # Safety
    ///
    /// `optval` is borrowed only for this call — the returned `Sqe` stores
    /// a raw pointer derived from it, not the borrow itself. The caller
    /// must ensure the memory `optval` points to remains valid and
    /// readable until the kernel posts the completion for this operation.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub unsafe fn uring_cmd_sock_setsockopt(
        fd: RawFd,
        level: u32,
        optname: u32,
        optval: &[u8],
    ) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::UringCmd.into();
        sqe.fd = fd.as_i32();
        sqe.set_cmd_op(SocketUringCmdOp::SetSockOpt.into());
        sqe.set_sock_level(level);
        sqe.set_sock_optname(optname);
        sqe.set_sock_optval(optval.as_ptr() as u64);
        sqe.set_optlen(optval.len() as u32);
        Self(sqe)
    }

    /// Prepare `SOCKET_URING_OP_GETSOCKNAME`: fetch the local address
    /// bound to `fd`.
    ///
    /// # Safety
    ///
    /// `addr` and `addr_len` are each borrowed only for this call — the
    /// returned `Sqe` stores raw pointers derived from them, not the
    /// borrows themselves. `addr` must remain valid and writable for at
    /// least the value `*addr_len` holds at submission time (the kernel
    /// caps its write at that length and updates it to the address's true
    /// size, exactly as `getsockname(2)` does), and `addr_len` itself must
    /// remain valid and writable, until the kernel posts the completion.
    #[must_use]
    pub unsafe fn uring_cmd_sock_getsockname(fd: RawFd, addr: *mut u8, addr_len: *mut i32) -> Self {
        Self::uring_cmd_sock_name(fd, addr, addr_len, false)
    }

    /// Prepare `SOCKET_URING_OP_GETSOCKNAME` with the peer flag set:
    /// fetch the address of the peer `fd` is connected to (`getpeername(2)`'s
    /// equivalent).
    ///
    /// # Safety
    ///
    /// Same contract as [`uring_cmd_sock_getsockname`](Self::uring_cmd_sock_getsockname).
    #[must_use]
    pub unsafe fn uring_cmd_sock_getpeername(fd: RawFd, addr: *mut u8, addr_len: *mut i32) -> Self {
        Self::uring_cmd_sock_name(fd, addr, addr_len, true)
    }

    fn uring_cmd_sock_name(fd: RawFd, addr: *mut u8, addr_len: *mut i32, peer: bool) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::UringCmd.into();
        sqe.fd = fd.as_i32();
        sqe.set_cmd_op(SocketUringCmdOp::GetSockName.into());
        sqe.addr = addr as u64;
        sqe.addr3 = addr_len as u64;
        sqe.set_optlen(u32::from(peer));
        Self(sqe)
    }
}
