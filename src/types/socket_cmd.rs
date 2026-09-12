//! Socket sub-commands for `IORING_OP_URING_CMD` (`SOCKET_URING_OP_*`,
//! kernel 6.3+).
//!
//! Confirmed against `io_uring/cmd_net.c`'s `io_uring_cmd_sock` and its
//! per-sub-command helpers: unlike a passthrough `uring_cmd` aimed at a
//! driver-defined `cmd[]` payload, every socket sub-command here reads its
//! arguments from the *ordinary* 64-byte SQE's existing field unions —
//! `cmd_op` aliases the low 32 bits of `off`, `level`/`optname` split
//! `addr` into two 32-bit halves, `optval` aliases the same eight bytes as
//! `addr3`/`attr_ptr` (the PI-attribute pointer), and `optlen` aliases
//! `splice_fd_in`. None of that needs `IORING_SETUP_SQE128`.
//!
//! `SOCKET_URING_OP_TX_TIMESTAMP` is deliberately not covered here: it
//! requires `IORING_SETUP_CQE32` (the handler rejects it outright without
//! that flag) and drives a multishot completion path posting a second,
//! wider CQE per timestamp — machinery this crate does not have yet
//! (Tier 3 item 37). The four sub-commands here all complete with one
//! ordinary CQE, matching every other opcode already wired into this
//! crate's `Completion` model.

/// A `SOCKET_URING_OP_*` sub-command value, carried in `sqe->cmd_op`
/// (`IoUringSqe::cmd_op`) for an `IORING_OP_URING_CMD` submitted against a
/// socket fd.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SocketUringCmdOp {
    /// `SIOCINQ`: bytes currently queued for reading. Result rides in the
    /// CQE's ordinary `res` field, matching `ioctl(SIOCINQ)`'s own return.
    SiocInq = 0,
    /// `SIOCOUTQ`: bytes currently queued for writing (not yet acked, for
    /// TCP).
    SiocOutq = 1,
    /// A `getsockopt(2)` call, restricted to `level == SOL_SOCKET` by the
    /// kernel handler (`-EOPNOTSUPP` for any other level). `sqe->optname`
    /// names the option, `sqe->optval`/`optlen` describe the destination
    /// buffer; the CQE result is the option's actual length on success —
    /// the same "report what was really copied" contract `getsockopt(2)`
    /// itself has via its own `optlen` out-parameter.
    GetSockOpt = 2,
    /// A `setsockopt(2)` call. Unlike `GetSockOpt`, the kernel does not
    /// restrict `level` here — it is forwarded to `do_sock_setsockopt`
    /// exactly as the ordinary `setsockopt` syscall would.
    SetSockOpt = 3,
    /// `getsockname(2)`/`getpeername(2)`, selected by a `peer` flag folded
    /// into `sqe->optlen` (`0` = local name, `1` = peer name; any other
    /// value is rejected with `-EINVAL`). `sqe->addr` is the destination
    /// `sockaddr`, `sqe->addr3` a pointer to the caller's buffer-length
    /// in/out value, matching `getsockname(2)`'s own `addrlen` parameter.
    GetSockName = 5,
}

impl From<SocketUringCmdOp> for u32 {
    fn from(op: SocketUringCmdOp) -> Self {
        op as Self
    }
}
