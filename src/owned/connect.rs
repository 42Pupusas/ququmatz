//! `connect`, the last pointer-bearing operation to get an owned form.
//!
//! The kernel is handed a socket address at `addr` and its length in
//! `off` — note the difference from [`bind`](super::bind), which carries
//! the length in `addr2`. Everything else in the SQE stays zero.
//!
//! # `EINPROGRESS` is not reachable, so it is not in the outcome
//!
//! `connect(2)` on a non-blocking socket reports `EINPROGRESS` and leaves
//! the caller to poll for the result, which invites an `InProgress`
//! variant. Measured against a real kernel, that variant would be dead
//! code: `io_uring` arms a poll internally and retries, so the CQE is not
//! posted until the handshake has actually resolved. A socket created
//! with `SOCK_NONBLOCK` completes with `0`, not `-EINPROGRESS`.
//!
//! The same measurement shows the cost of that convenience: connecting to
//! an address nothing answers for does not complete promptly. The request
//! stays in flight until the kernel gives up, so a caller who needs a
//! deadline wants a linked timeout rather than a non-blocking socket.
//!
//! # A second connect reports `EISCONN`, not `EALREADY`
//!
//! Measured on a live ring:
//!
//! | request | result |
//! |---|---|
//! | connect to a listening socket | `0` |
//! | connect that socket a second time | `-EISCONN` |
//! | connect with `SOCK_NONBLOCK` set | `0` |
//! | connect to a port nothing listens on | `-ECONNREFUSED` |
//! | connect with a bad `sin_family` | `-EAFNOSUPPORT` |
//! | connect on a listening socket | `-EISCONN` |
//!
//! [`ConnectOutcome`] keeps `ConnectionRefused` apart from
//! `AlreadyConnected` because they call for opposite responses: retrying
//! reaches a listener that has since come up, and never un-connects a
//! socket that is already connected.
//!
//! The typed [`SockAddrIn`] rules out the `EAFNOSUPPORT` row at
//! construction, the same way it does for `bind`.
//!
//! # Storage is owned for the same reason bind's is
//!
//! Measured: an address overwritten *after* `submit` returned still
//! connects to the address originally staged, and one overwritten between
//! `push` and `submit` fails with `EAFNOSUPPORT`. The read happens inside
//! `io_uring_enter`.
//!
//! That is not enough for a borrow.
//! [`split_owned`](crate::IoUring::split_owned) accepts an SQPOLL ring,
//! where the submitting thread never enters the kernel and the SQ thread
//! reads the SQE on its own schedule. No call's return proves the copy has
//! happened, so the storage is owned until the completion.
//!
//! That machinery lives in [`staged_addr`](super::staged_addr), shared
//! verbatim with [`bind`](super::bind): this module supplies only the SQE
//! builder and the outcome table that make a `connect` different from a
//! `bind`.

use super::identity::{RequestId, RingId};
use super::request::Receipt;
use super::staged_addr::{AddrOp, StagedDone, StagedPending, StagedPrepared};
use crate::error::Errno;
use crate::op::Sqe;
use crate::types::{RawFd, SockAddrIn};

/// `-ECONNREFUSED`: nothing is listening on that address.
const ECONNREFUSED: i32 = -111;
/// `-EISCONN`: this socket is connected already.
const EISCONN: i32 = -106;
/// `-ETIMEDOUT`: the peer never answered.
const ETIMEDOUT: i32 = -110;
/// `-ENETUNREACH`: no route to that address.
const ENETUNREACH: i32 = -101;

/// How a `connect` ended.
///
/// There is deliberately no `InProgress`: `io_uring` resolves the handshake
/// before posting the CQE, so a non-blocking socket reports `0` rather
/// than `EINPROGRESS`. See the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectOutcome {
    /// The socket is connected to the requested address.
    Connected,
    /// Nothing is listening on that address.
    ///
    /// Worth retrying: a listener that starts later will answer.
    ConnectionRefused,
    /// This socket is connected already.
    ///
    /// Retrying never helps. A listening socket reports this too.
    AlreadyConnected,
    /// The peer never answered before the kernel gave up.
    TimedOut,
    /// There is no route to that address.
    NetworkUnreachable,
    /// The kernel rejected the request for another reason.
    Failed(Errno),
}

impl ConnectOutcome {
    /// Classify a raw CQE result.
    const fn from_raw(result: i32) -> Self {
        match result {
            ECONNREFUSED => Self::ConnectionRefused,
            EISCONN => Self::AlreadyConnected,
            ETIMEDOUT => Self::TimedOut,
            ENETUNREACH => Self::NetworkUnreachable,
            other if other < 0 => Self::Failed(Errno::new(-other)),
            _ => Self::Connected,
        }
    }

    /// Classify a raw result directly, for tests that need an outcome the
    /// kernel is hard to coax into producing on demand.
    #[cfg(test)]
    pub(crate) const fn from_raw_for_test(result: i32) -> Self {
        Self::from_raw(result)
    }

    /// Whether the socket is now connected to the requested address.
    #[must_use]
    pub const fn is_connected(self) -> bool {
        matches!(self, Self::Connected)
    }
}

impl core::fmt::Display for ConnectOutcome {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Connected => f.write_str("socket connected"),
            Self::ConnectionRefused => f.write_str("connection refused"),
            Self::AlreadyConnected => f.write_str("socket is already connected"),
            Self::TimedOut => f.write_str("connection timed out"),
            Self::NetworkUnreachable => f.write_str("network is unreachable"),
            Self::Failed(e) => write!(f, "connect failed: {e}"),
        }
    }
}

/// Why a `connect` request could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectError {
    /// The storage cannot hold a whole socket address.
    StoreTooSmall {
        /// Bytes a socket address needs.
        needed: usize,
        /// Bytes the supplied storage has.
        got: usize,
    },
}

impl core::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::StoreTooSmall { needed, got } => {
                write!(f, "connect address storage needs {needed} bytes, got {got}")
            }
        }
    }
}

/// Marker tying [`staged_addr`](super::staged_addr)'s generic machinery to
/// `connect`'s SQE shape and outcome table.
pub(super) enum ConnectOp {}

impl AddrOp for ConnectOp {
    type Outcome = ConnectOutcome;
    type Error = ConnectError;

    fn too_small(needed: usize, got: usize) -> Self::Error {
        ConnectError::StoreTooSmall { needed, got }
    }

    unsafe fn build_sqe(fd: RawFd, addr: *const u8, len: u32) -> Sqe {
        // SAFETY: forwarded from the caller, who requires the same of us.
        unsafe { Sqe::connect_ptr(fd, addr, len) }
    }

    fn classify(result: i32) -> Self::Outcome {
        ConnectOutcome::from_raw(result)
    }
}

/// A `connect` that owns its address storage, not yet queued.
pub struct PreparedConnect<S>(StagedPrepared<S, ConnectOp>);

impl<S: super::buffer::StableBufferMut> PreparedConnect<S> {
    /// Prepare a connect of `fd` to `addr`.
    ///
    /// Takes ownership of `store`, which the kernel reads the address from
    /// after submission, so no caller alias to it may survive. The
    /// descriptor is not taken: `connect` borrows it for the call.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectError`] with the storage handed back if `store` is
    /// too small for a socket address.
    pub fn new(fd: RawFd, addr: SockAddrIn, store: S) -> Result<Self, (S, ConnectError)> {
        StagedPrepared::new(fd, addr, store).map(Self)
    }
}

impl<S> PreparedConnect<S> {
    /// The socket this request connects.
    #[must_use]
    pub const fn fd(&self) -> RawFd {
        self.0.fd()
    }

    /// The address this request connects to.
    #[must_use]
    pub const fn addr(&self) -> SockAddrIn {
        self.0.addr()
    }

    /// The address bytes exactly as the kernel will read them.
    ///
    /// Reads back the published storage rather than rebuilding it, so it
    /// shows what was actually written.
    #[must_use]
    pub const fn published(&self) -> [u8; super::staged_addr::ADDR_LEN] {
        self.0.published()
    }

    /// Give the storage back, abandoning the request.
    #[must_use]
    pub fn into_store(self) -> S {
        self.0.into_store()
    }

    /// Build the SQE and move to the pending state.
    pub(crate) fn into_pending(self, ring: RingId, id: RequestId) -> (Sqe, PendingConnect<S>) {
        let (sqe, pending) = self.0.into_pending(ring, id);
        (sqe, PendingConnect(pending))
    }
}

/// A submitted `connect` whose address storage the kernel may be reading.
///
/// # Drop and `forget` both leak rather than free
///
/// Dropping this runs no destructor for the storage. Under SQPOLL the
/// submitting thread never enters the kernel, so nothing here can prove
/// the address has been read, and the storage leaks on purpose — the same
/// failure mode as every other in-flight ticket.
///
/// No descriptor goes with it: `connect` borrows the socket rather than
/// taking it, so only the storage is at stake.
#[must_use = "dropping the ticket leaks the address storage"]
pub struct PendingConnect<S>(StagedPending<S, ConnectOp>);

impl<S> PendingConnect<S> {
    /// Identity the kernel echoes back in this request's CQE.
    #[must_use]
    pub const fn id(&self) -> RequestId {
        self.0.id()
    }

    /// Identity of the queue that accepted this request.
    #[must_use]
    pub const fn ring(&self) -> RingId {
        self.0.ring()
    }

    /// The address this request connects to.
    #[must_use]
    pub const fn addr(&self) -> SockAddrIn {
        self.0.addr()
    }

    /// Whether `receipt` authenticates this exact request.
    #[must_use]
    pub const fn matches(&self, receipt: &Receipt) -> bool {
        self.0.matches(receipt)
    }

    /// Take the storage back without a receipt, undoing a failed push.
    ///
    /// # Safety
    ///
    /// The kernel must never have seen this request's SQE. Calling this
    /// after publication hands back storage the kernel may still read.
    pub(crate) unsafe fn reclaim_unsubmitted(self) -> PreparedConnect<S> {
        // SAFETY: forwarded from the caller, who requires the same of us.
        PreparedConnect(unsafe { self.0.reclaim_unsubmitted() })
    }

    /// Trade a matching receipt for the outcome and the storage.
    ///
    /// # Errors
    ///
    /// Returns the ticket and receipt unchanged if the receipt belongs to
    /// another request or another ring.
    pub fn redeem(self, receipt: Receipt) -> Result<ConnectDone<S>, (Self, Receipt)> {
        self.0
            .redeem(receipt)
            .map(ConnectDone)
            .map_err(|(pending, receipt)| (Self(pending), receipt))
    }
}

/// A finished `connect`: how it ended, and the storage back.
pub struct ConnectDone<S>(StagedDone<S, ConnectOp>);

impl<S> ConnectDone<S> {
    /// Identity of the request this completes.
    #[must_use]
    pub const fn id(&self) -> RequestId {
        self.0.id()
    }

    /// Raw CQE result: `0` on success, `-errno` otherwise.
    #[must_use]
    pub const fn raw_result(&self) -> i32 {
        self.0.raw_result()
    }

    /// How the request ended.
    #[must_use]
    pub fn outcome(&self) -> ConnectOutcome {
        self.0.outcome()
    }

    /// The address this request connected to.
    #[must_use]
    pub const fn addr(&self) -> SockAddrIn {
        self.0.addr()
    }

    /// Take the storage back for reuse.
    #[must_use]
    pub fn into_store(self) -> S {
        self.0.into_store()
    }

    /// Take the outcome and the storage together.
    #[must_use]
    pub fn into_parts(self) -> (ConnectOutcome, S) {
        self.0.into_parts()
    }
}
