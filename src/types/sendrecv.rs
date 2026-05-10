//! Tunables that go into SQE `ioprio` / `op_flags` for send/recv-family ops.

// Multishot bits. Set internally by the dedicated constructors
// (`Sqe::accept_multishot`, `recv_multishot`, `recvmsg_multishot`); not
// part of the public API. The submodule is private; `mod.rs` controls
// crate-level visibility via `pub(crate) use`.
pub const IORING_ACCEPT_MULTISHOT: u16 = 1 << 0;
// IORING_RECV_MULTISHOT lives in `sqe.ioprio` (a u16) — NOT in `op_flags`.
// The kernel's `op_flags` field for recv aliases `msg_flags`, where bit 1
// is `MSG_PEEK` (0x2). Setting this in op_flags would silently turn the
// op into a peek recv. See linux/io_uring.h.
pub const IORING_RECV_MULTISHOT: u16 = 1 << 1;

// `ioprio` bits used by `SendRecvFlag`. Internal — callers reach these
// through `Sqe::with(SendRecvFlag::…)`.
pub const IORING_RECVSEND_POLL_FIRST: u16 = 1 << 0;
pub const IORING_RECVSEND_FIXED_BUF: u16 = 1 << 1;
pub const IORING_SEND_ZC_REPORT_USAGE: u16 = 1 << 3;

/// Tunable for send/recv-family SQEs.
///
/// Pass via [`Sqe::with`] to compose with regular `send`/`recv`/`send_zc`
/// constructors. Multishot variants have dedicated constructors
/// ([`Sqe::recv_multishot`], [`Sqe::recvmsg_multishot`],
/// [`Sqe::accept_multishot`]).
#[derive(Debug, Clone, Copy)]
pub enum SendRecvFlag {
    /// Register internal poll for fd readiness before dispatching.
    ///
    /// Without this, a SEND on a non-writable socket (or a RECV on an
    /// empty one) is handed to an io-wq worker that blocks until the
    /// operation can proceed. A backpressured peer can saturate the
    /// io-wq pool and stall sends to other sockets. With this set, the
    /// kernel polls first and completes inline once the fd is ready.
    ///
    /// Valid on `send`, `recv`, `sendmsg`, `recvmsg`, `send_zc`. Linux 5.19+.
    PollFirst,

    /// Use a registered (fixed) buffer at the given index instead of a
    /// user pointer. The SQE's `addr`/`len` then describe a sub-range
    /// within the registered buffer.
    ///
    /// Requires buffers registered via `IORING_REGISTER_BUFFERS`. Valid
    /// on `send`, `recv`, `send_zc`, and their msg variants.
    FixedBuf(u16),

    /// Have the kernel report zero-copy outcome in the upper 16 bits of
    /// the notification CQE's `res`. The only signal that zero-copy is
    /// actually winning over plain `send`.
    ///
    /// Valid only on `send_zc`. Linux 6.2+.
    ReportUsage,
}
