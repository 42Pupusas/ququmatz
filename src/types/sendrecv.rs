//! Tunables that go into SQE `ioprio` / `op_flags` for send/recv-family ops.

// Multishot bits. Set internally by the dedicated constructors
// (`Sqe::accept_multishot`, `recv_multishot`, `recvmsg_multishot`); not
// part of the public API. The submodule is private; `mod.rs` controls
// crate-level visibility via `pub(crate) use`.
pub const IORING_ACCEPT_MULTISHOT: u16 = 1 << 0;
// The remaining two accept `ioprio` bits. Reached through
// `Sqe::accept_with`/`AcceptModifier`, not set directly.
pub const IORING_ACCEPT_DONTWAIT: u16 = 1 << 1;
pub const IORING_ACCEPT_POLL_FIRST: u16 = 1 << 2;
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
pub const IORING_RECVSEND_BUNDLE: u16 = 1 << 4;
pub const IORING_SEND_VECTORIZED: u16 = 1 << 5;

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

    /// Grab as many buffers as available from the buffer group given by
    /// `IOSQE_BUFFER_SELECT` and send or receive across all of them,
    /// rather than a single buffer.
    ///
    /// The completion's `res` is the number of bytes across every buffer
    /// used; the starting buffer ID lands in the CQE's buffer-ID bits as
    /// usual, and consumed buffers are contiguous from that starting ID.
    ///
    /// Requires a ring-provided buffer group (`IOSQE_BUFFER_SELECT` with
    /// a ring, not the legacy `PROVIDE_BUFFERS` list). Valid on `send`,
    /// `recv`, and `send_zc`. Linux 6.10+.
    Bundle,

    /// Treat the SQE's `addr`/`len` as an `iovec` array instead of a
    /// single buffer, enabling vectored send.
    ///
    /// Valid on `send` and `send_zc`. Linux 6.11+.
    Vectorized,
}

/// Tunable for `accept`-family SQEs, applied via [`Sqe::with_accept`].
///
/// Composes with [`Sqe::accept`]/[`Sqe::accept_ptr`]/[`Sqe::accept_with_addr`]
/// — call [`Sqe::with_accept`] multiple times to set several. The
/// dedicated multishot constructors ([`Sqe::accept_multishot`],
/// [`Sqe::accept_multishot_direct`]) already set [`IORING_ACCEPT_MULTISHOT`]
/// and compose with this modifier the same way.
///
/// [`Sqe::accept`]: crate::op::Sqe::accept
/// [`Sqe::accept_ptr`]: crate::op::Sqe::accept_ptr
/// [`Sqe::accept_with_addr`]: crate::op::Sqe::accept_with_addr
/// [`Sqe::accept_multishot`]: crate::op::Sqe::accept_multishot
/// [`Sqe::accept_multishot_direct`]: crate::op::Sqe::accept_multishot_direct
/// [`Sqe::with_accept`]: crate::op::Sqe::with_accept
#[derive(Debug, Clone, Copy)]
pub enum AcceptModifier {
    /// Fail with `-EAGAIN` immediately instead of arming internal poll
    /// when no connection is waiting.
    ///
    /// Without this, an accept on a listener with nothing pending is
    /// handed to an io-wq worker (or polled, with `PollFirst`) and blocks
    /// until a connection arrives. With this set, the kernel never waits:
    /// an empty backlog completes at once with `-EAGAIN`, matching a
    /// non-blocking `accept4(2)`.
    ///
    /// Linux 6.7+.
    DontWait,

    /// Register internal poll for the listener's readiness before
    /// dispatching, the same tradeoff `SendRecvFlag::PollFirst` describes
    /// for send/recv: avoids handing an accept with nothing pending to an
    /// io-wq worker, at the cost of a poll registration up front.
    ///
    /// Linux 6.7+.
    PollFirst,
}
