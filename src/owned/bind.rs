//! `bind`, whose address the kernel copies while servicing the request.
//!
//! The kernel is handed a socket address at `addr` and its length in
//! `addr2`. It rejects a non-zero `len`, `buf_index`, `rw_flags`, or
//! `splice_fd_in` outright, so the SQE carries the address and nothing
//! else.
//!
//! # There is no owned `listen`
//!
//! `listen` reads no caller memory at all — the kernel takes the backlog
//! from `len` and rejects a request that carries an address. It owns
//! nothing, so it has nothing to model and stays a safe
//! [`Sqe::listen`](crate::Sqe::listen).
//!
//! # Storage is owned for the same reason a timeout's is
//!
//! Measured on a live ring, `io_bind_prep` copies the address into the
//! kernel during `io_uring_enter`: an address overwritten with `0xFF`
//! *after* `submit` returned still binds the port originally staged.
//! Overwriting it between `push` and `submit` instead fails with
//! `EAFNOSUPPORT`, which locates the read precisely — inside the submit
//! call, not at push.
//!
//! That is *almost* an argument for a plain borrow, and it fails for the
//! same reason the timeout's does:
//! [`split_owned`](crate::IoUring::split_owned) accepts an SQPOLL ring,
//! where the submitting thread never enters the kernel and the SQ thread
//! reads the SQE on its own schedule. No call's return proves the copy has
//! happened, so the storage is owned until the completion.
//!
//! That storage-ownership machinery is not written here at all: `bind` and
//! [`connect`](super::connect) need the identical state machine around one
//! staged [`SockAddrIn`], so [`staged_addr`](super::staged_addr) carries it
//! once and this module supplies only what tells the two apart — the SQE
//! builder and the outcome table below.
//!
//! # A typed address makes one failure unrepresentable
//!
//! The request takes a [`SockAddrIn`] rather than raw bytes. A malformed
//! address is then impossible to construct, which matters because the
//! kernel reports it with the same `EINVAL` it uses for a socket that is
//! already bound. Measured against a real kernel:
//!
//! | request | result |
//! |---|---|
//! | bind a fresh socket | `0` |
//! | bind the same socket again | `-EINVAL` |
//! | bind a port another socket holds | `-EADDRINUSE` |
//! | bind a privileged port unprivileged | `-EACCES` |
//! | a zero-length or null address | `-EINVAL` / `-EFAULT` |
//!
//! The last row is what the typed address rules out. The two middle rows
//! are different errnos for what a caller might lump together as "the
//! bind did not take", and [`BindOutcome`] keeps them apart: a retry on a
//! different port fixes one and loops forever on the other.

use super::identity::{RequestId, RingId};
use super::request::Receipt;
use super::staged_addr::{AddrOp, StagedDone, StagedPending, StagedPrepared};
use crate::error::Errno;
use crate::op::Sqe;
use crate::types::{RawFd, SockAddrIn};

/// `-EADDRINUSE`: another socket holds this address.
const EADDRINUSE: i32 = -98;
/// `-EINVAL`: this socket is already bound.
const EINVAL: i32 = -22;
/// `-EACCES`: binding this address needs privilege.
const EACCES: i32 = -13;

/// How a `bind` ended.
///
/// The three named failures are routine and call for different responses,
/// so they are distinguished rather than folded into one error a caller
/// has to decode. Retrying a different port resolves
/// [`AddressInUse`](Self::AddressInUse) and never resolves
/// [`AlreadyBound`](Self::AlreadyBound).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindOutcome {
    /// The socket is bound to the requested address.
    Bound,
    /// Another socket already holds this address.
    AddressInUse,
    /// This socket has been bound once already.
    ///
    /// The kernel spends `EINVAL` on both this and a malformed address;
    /// [`PreparedBind`] takes a typed [`SockAddrIn`], so the second cannot
    /// be constructed and this reading is the only one left.
    AlreadyBound,
    /// Binding this address requires privilege the process does not have.
    PermissionDenied,
    /// The kernel rejected the request for another reason.
    Failed(Errno),
}

impl BindOutcome {
    /// Classify a raw CQE result.
    const fn from_raw(result: i32) -> Self {
        match result {
            EADDRINUSE => Self::AddressInUse,
            EINVAL => Self::AlreadyBound,
            EACCES => Self::PermissionDenied,
            other if other < 0 => Self::Failed(Errno::new(-other)),
            _ => Self::Bound,
        }
    }

    /// Classify a raw result directly, for tests that need an outcome the
    /// kernel is hard to coax into producing on demand.
    #[cfg(test)]
    pub(crate) const fn from_raw_for_test(result: i32) -> Self {
        Self::from_raw(result)
    }

    /// Whether the socket is now bound to the requested address.
    #[must_use]
    pub const fn is_bound(self) -> bool {
        matches!(self, Self::Bound)
    }
}

impl core::fmt::Display for BindOutcome {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Bound => f.write_str("socket bound"),
            Self::AddressInUse => f.write_str("address is already in use"),
            Self::AlreadyBound => f.write_str("socket is already bound"),
            Self::PermissionDenied => f.write_str("binding this address requires privilege"),
            Self::Failed(e) => write!(f, "bind failed: {e}"),
        }
    }
}

/// Why a `bind` request could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindError {
    /// The storage cannot hold a whole socket address.
    StoreTooSmall {
        /// Bytes a socket address needs.
        needed: usize,
        /// Bytes the supplied storage has.
        got: usize,
    },
}

impl core::fmt::Display for BindError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::StoreTooSmall { needed, got } => {
                write!(f, "bind address storage needs {needed} bytes, got {got}")
            }
        }
    }
}

/// Marker tying [`staged_addr`](super::staged_addr)'s generic machinery to
/// `bind`'s SQE shape and outcome table.
pub(super) enum BindOp {}

impl AddrOp for BindOp {
    type Outcome = BindOutcome;
    type Error = BindError;

    fn too_small(needed: usize, got: usize) -> Self::Error {
        BindError::StoreTooSmall { needed, got }
    }

    unsafe fn build_sqe(fd: RawFd, addr: *const u8, len: u32) -> Sqe {
        // SAFETY: forwarded from the caller, who requires the same of us.
        unsafe { Sqe::bind_ptr(fd, addr, len) }
    }

    fn classify(result: i32) -> Self::Outcome {
        BindOutcome::from_raw(result)
    }
}

/// A `bind` that owns its address storage, not yet queued.
pub struct PreparedBind<S>(StagedPrepared<S, BindOp>);

impl<S: super::buffer::StableBufferMut> PreparedBind<S> {
    /// Prepare a bind of `fd` to `addr`.
    ///
    /// Takes ownership of `store`, which the kernel reads the address from
    /// after submission, so no caller alias to it may survive. The
    /// descriptor is not taken: `bind` borrows it for the call.
    ///
    /// # Errors
    ///
    /// Returns [`BindError`] with the storage handed back if `store` is
    /// too small for a socket address.
    pub fn new(fd: RawFd, addr: SockAddrIn, store: S) -> Result<Self, (S, BindError)> {
        StagedPrepared::new(fd, addr, store).map(Self)
    }
}

impl<S> PreparedBind<S> {
    /// The socket this request binds.
    #[must_use]
    pub const fn fd(&self) -> RawFd {
        self.0.fd()
    }

    /// The address this request binds to.
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
    pub(crate) fn into_pending(self, ring: RingId, id: RequestId) -> (Sqe, PendingBind<S>) {
        let (sqe, pending) = self.0.into_pending(ring, id);
        (sqe, PendingBind(pending))
    }
}

/// A submitted `bind` whose address storage the kernel may be reading.
///
/// # Drop and `forget` both leak rather than free
///
/// Dropping this runs no destructor for the storage. Under SQPOLL the
/// submitting thread never enters the kernel, so nothing here can prove
/// the address has been read, and the storage leaks on purpose — the same
/// failure mode as every other in-flight ticket.
///
/// No descriptor goes with it: `bind` borrows the socket rather than
/// taking it, so only the storage is at stake.
#[must_use = "dropping the ticket leaks the address storage"]
pub struct PendingBind<S>(StagedPending<S, BindOp>);

impl<S> PendingBind<S> {
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

    /// The address this request binds to.
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
    pub(crate) unsafe fn reclaim_unsubmitted(self) -> PreparedBind<S> {
        // SAFETY: forwarded from the caller, who requires the same of us.
        PreparedBind(unsafe { self.0.reclaim_unsubmitted() })
    }

    /// Trade a matching receipt for the outcome and the storage.
    ///
    /// # Errors
    ///
    /// Returns the ticket and receipt unchanged if the receipt belongs to
    /// another request or another ring.
    pub fn redeem(self, receipt: Receipt) -> Result<BindDone<S>, (Self, Receipt)> {
        self.0
            .redeem(receipt)
            .map(BindDone)
            .map_err(|(pending, receipt)| (Self(pending), receipt))
    }
}

/// A finished `bind`: how it ended, and the storage back.
pub struct BindDone<S>(StagedDone<S, BindOp>);

impl<S> BindDone<S> {
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
    pub fn outcome(&self) -> BindOutcome {
        self.0.outcome()
    }

    /// The address this request bound to.
    ///
    /// A port of `0` asks the kernel to choose one, and the choice is not
    /// reported here — read it back with `getsockname` once bound.
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
    pub fn into_parts(self) -> (BindOutcome, S) {
        self.0.into_parts()
    }
}
