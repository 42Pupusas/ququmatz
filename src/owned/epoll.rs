//! `epoll_ctl`, where one of the three operations reads nothing.
//!
//! The kernel is handed an `epoll_event` at `addr` and an operation in
//! `len`. For `Add` and `Mod` it reads the struct to learn the mask and
//! the user data; for `Del` it does not read it at all — a `Del` with a
//! **null** pointer returns `0` against a real kernel, which is how that
//! was established rather than assumed.
//!
//! [`EpollChange`] is shaped around that difference: the event is carried
//! by the two variants that use it and absent from the one that does not,
//! so a `Del` cannot be given a mask that would be silently discarded, and
//! an `Add` cannot omit one.
//!
//! # Storage is owned for the same reason a timeout's is
//!
//! The struct is small and fixed-size, and the kernel copies it while
//! servicing the request rather than keeping it. That is not enough to
//! make a borrow safe: [`split_owned`](crate::IoUring::split_owned)
//! accepts an SQPOLL ring, where the submitting thread never enters the
//! kernel and the SQ thread reads the SQE on its own schedule. No call's
//! return proves the read has happened, so the storage is owned until the
//! completion like every other request.
//!
//! A [`Del`](EpollChange::Del) still needs storage even though nothing
//! reads it, because the request is the same shape and the ticket must own
//! something for the array's address to be stable. Rather than special-case
//! it, the published bytes are simply zero.
//!
//! That storage-ownership machinery is not written here at all: `epoll_ctl`
//! and [`timeout`](super::timeout) need the identical state machine around
//! one staged, fixed-size, aligned value, so
//! [`staged_value`](super::staged_value) carries it once and this module
//! supplies only what tells the two apart — the value to publish, the SQE
//! builder, and the outcome table below.
//!
//! # The interesting failures are about the registration, not the memory
//!
//! Measured against a real kernel:
//!
//! | request | result |
//! |---|---|
//! | `Add` on a fresh fd | `0` |
//! | `Add` on one already registered | `-EEXIST` |
//! | `Mod` on an unregistered fd | `-ENOENT` |
//! | `Del` of a registered fd | `0` |
//!
//! None of those is a memory hazard, and all of them are ordinary outcomes
//! of racing another thread that touched the same epoll set, so
//! [`EpollOutcome`] names them rather than folding them into one error.

use super::identity::{RequestId, RingId};
use super::request::Receipt;
use super::staged_value::{ValueDone, ValueOp, ValuePending, ValuePrepared};
use crate::error::Errno;
use crate::op::Sqe;
use crate::types::{EpollEvent, EpollEvents, EpollOp, RawFd};

/// `-EEXIST`: the descriptor is already in this epoll set.
const EEXIST: i32 = -17;
/// `-ENOENT`: the descriptor is not in this epoll set.
const ENOENT: i32 = -2;

/// What a request changes about one descriptor's registration.
///
/// The event is attached to the two operations that read it and absent
/// from the one that does not, because the kernel ignores it for a `Del`
/// entirely — a mask supplied there would be silently discarded rather
/// than rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpollChange {
    /// Register the descriptor, failing with `EEXIST` if it already is.
    Add {
        /// Events to watch for.
        events: EpollEvents,
        /// Value the kernel reports back with each event.
        data: u64,
    },
    /// Replace an existing registration, failing with `ENOENT` if absent.
    Mod {
        /// Events to watch for.
        events: EpollEvents,
        /// Value the kernel reports back with each event.
        data: u64,
    },
    /// Remove the registration. The kernel reads no event for this.
    Del,
}

impl EpollChange {
    /// The kernel's operation code.
    const fn op(self) -> EpollOp {
        match self {
            Self::Add { .. } => EpollOp::Add,
            Self::Mod { .. } => EpollOp::Mod,
            Self::Del => EpollOp::Del,
        }
    }

    /// The event the kernel reads, or a zeroed one for a `Del`.
    const fn event(self) -> EpollEvent {
        match self {
            Self::Add { events, data } | Self::Mod { events, data } => EpollEvent {
                events: events.bits(),
                data,
            },
            Self::Del => EpollEvent { events: 0, data: 0 },
        }
    }
}

/// How an `epoll_ctl` ended.
///
/// The two registration errors are ordinary outcomes of another thread
/// having touched the same epoll set, so they are named rather than being
/// folded into a generic failure a caller has to decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpollOutcome {
    /// The change was applied.
    Applied,
    /// An `Add` for a descriptor that is already registered.
    AlreadyRegistered,
    /// A `Mod` or `Del` for a descriptor that is not registered.
    NotRegistered,
    /// The kernel rejected the request for another reason.
    Failed(Errno),
}

impl EpollOutcome {
    /// Classify a raw CQE result.
    const fn from_raw(result: i32) -> Self {
        match result {
            EEXIST => Self::AlreadyRegistered,
            ENOENT => Self::NotRegistered,
            other if other < 0 => Self::Failed(Errno::new(-other)),
            _ => Self::Applied,
        }
    }

    /// Classify a raw result directly, for tests that need an outcome the
    /// kernel is hard to coax into producing on demand.
    #[cfg(test)]
    pub(crate) const fn from_raw_for_test(result: i32) -> Self {
        Self::from_raw(result)
    }

    /// Whether the epoll set now reflects the requested change.
    #[must_use]
    pub const fn is_applied(self) -> bool {
        matches!(self, Self::Applied)
    }
}

impl core::fmt::Display for EpollOutcome {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Applied => f.write_str("epoll registration updated"),
            Self::AlreadyRegistered => f.write_str("descriptor is already registered"),
            Self::NotRegistered => f.write_str("descriptor is not registered"),
            Self::Failed(e) => write!(f, "epoll_ctl failed: {e}"),
        }
    }
}

/// Why an `epoll_ctl` request could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpollError {
    /// The storage cannot hold a whole [`EpollEvent`].
    StoreTooSmall {
        /// Bytes an `EpollEvent` needs.
        needed: usize,
        /// Bytes the supplied storage has.
        got: usize,
    },
    /// The storage is not aligned for an [`EpollEvent`].
    ///
    /// [`MmapBuffer`](super::MmapBuffer) is page-aligned and always
    /// satisfies this; a hand-written [`StableBufferMut`] might not.
    StoreMisaligned {
        /// Alignment an `EpollEvent` requires.
        needed: usize,
    },
}

impl core::fmt::Display for EpollError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::StoreTooSmall { needed, got } => {
                write!(f, "epoll_event storage needs {needed} bytes, got {got}")
            }
            Self::StoreMisaligned { needed } => {
                write!(f, "epoll_event storage must be {needed}-byte aligned")
            }
        }
    }
}

/// The request's own fields, kept in [`staged_value`](super::staged_value)'s
/// `ctx` for as long as the request is live.
#[derive(Debug, Clone, Copy)]
pub(super) struct EpollCtx {
    epoll: RawFd,
    target: RawFd,
    change: EpollChange,
}

/// Marker tying [`staged_value`](super::staged_value)'s generic machinery
/// to `epoll_ctl`'s SQE shape and outcome table.
pub(super) enum EpollCtlOp {}

impl ValueOp for EpollCtlOp {
    type Context = EpollCtx;
    type Info = EpollChange;
    type Value = EpollEvent;
    type Outcome = EpollOutcome;
    type Error = EpollError;

    fn too_small(needed: usize, got: usize) -> Self::Error {
        EpollError::StoreTooSmall { needed, got }
    }

    fn misaligned(needed: usize) -> Self::Error {
        EpollError::StoreMisaligned { needed }
    }

    fn value(ctx: &Self::Context) -> Self::Value {
        ctx.change.event()
    }

    unsafe fn build_sqe(ctx: &Self::Context, addr: *const Self::Value) -> Sqe {
        // SAFETY: forwarded from the caller, who requires the same of us.
        unsafe { Sqe::epoll_ctl_ptr(ctx.epoll, ctx.change.op(), ctx.target, addr) }
    }

    fn info(ctx: &Self::Context) -> Self::Info {
        ctx.change
    }

    fn classify(result: i32) -> Self::Outcome {
        EpollOutcome::from_raw(result)
    }
}

/// An `epoll_ctl` that owns the event storage, not yet queued.
pub struct PreparedEpollCtl<S>(ValuePrepared<S, EpollCtlOp>);

impl<S: super::buffer::StableBufferMut> PreparedEpollCtl<S> {
    /// Prepare a change to `target`'s registration in the `epoll` set.
    ///
    /// Takes ownership of `store`, which the kernel reads the event from
    /// after submission, so no caller alias to it may survive. Neither
    /// descriptor is taken: `epoll_ctl` borrows both for the call.
    ///
    /// # Errors
    ///
    /// Returns [`EpollError`] with the storage handed back if `store` is
    /// too small or misaligned for an [`EpollEvent`].
    pub fn new(
        epoll: RawFd,
        target: RawFd,
        change: EpollChange,
        store: S,
    ) -> Result<Self, (S, EpollError)> {
        let ctx = EpollCtx {
            epoll,
            target,
            change,
        };
        ValuePrepared::new(ctx, store).map(Self)
    }
}

impl<S> PreparedEpollCtl<S> {
    /// The epoll set this request changes.
    #[must_use]
    pub const fn epoll(&self) -> RawFd {
        self.0.ctx().epoll
    }

    /// The descriptor whose registration changes.
    #[must_use]
    pub const fn target(&self) -> RawFd {
        self.0.ctx().target
    }

    /// What this request changes.
    #[must_use]
    pub const fn change(&self) -> EpollChange {
        self.0.ctx().change
    }

    /// The event exactly as the kernel will read it.
    ///
    /// Reads back the published storage rather than rebuilding it, so it
    /// shows what was actually written.
    #[must_use]
    pub const fn published(&self) -> EpollEvent {
        self.0.published()
    }

    /// Give the storage back, abandoning the request.
    #[must_use]
    pub fn into_store(self) -> S {
        self.0.into_store()
    }

    /// Build the SQE and move to the pending state.
    pub(crate) fn into_pending(self, ring: RingId, id: RequestId) -> (Sqe, PendingEpollCtl<S>) {
        let (sqe, pending) = self.0.into_pending(ring, id);
        (sqe, PendingEpollCtl(pending))
    }
}

/// A submitted `epoll_ctl` whose event storage the kernel may be reading.
///
/// # Drop and `forget` both leak rather than free
///
/// Dropping this runs no destructor for the storage. Under SQPOLL the
/// submitting thread never enters the kernel, so nothing here can prove
/// the event has been read, and the storage leaks on purpose — the same
/// failure mode as every other in-flight ticket.
///
/// No descriptor goes with it: `epoll_ctl` borrows both descriptors rather
/// than taking them, so only the storage is at stake.
#[must_use = "dropping the ticket leaks the event storage"]
pub struct PendingEpollCtl<S>(ValuePending<S, EpollCtlOp>);

impl<S> PendingEpollCtl<S> {
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

    /// What this request changes.
    #[must_use]
    pub const fn change(&self) -> EpollChange {
        self.0.ctx().change
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
    pub(crate) unsafe fn reclaim_unsubmitted(self) -> PreparedEpollCtl<S> {
        // SAFETY: forwarded from the caller, who requires the same of us.
        PreparedEpollCtl(unsafe { self.0.reclaim_unsubmitted() })
    }

    /// Trade a matching receipt for the outcome and the storage.
    ///
    /// # Errors
    ///
    /// Returns the ticket and receipt unchanged if the receipt belongs to
    /// another request or another ring.
    pub fn redeem(self, receipt: Receipt) -> Result<EpollCtlDone<S>, (Self, Receipt)> {
        self.0
            .redeem(receipt)
            .map(EpollCtlDone)
            .map_err(|(pending, receipt)| (Self(pending), receipt))
    }
}

/// A finished `epoll_ctl`: how it ended, and the storage back.
pub struct EpollCtlDone<S>(ValueDone<S, EpollCtlOp>);

impl<S> EpollCtlDone<S> {
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
    pub fn outcome(&self) -> EpollOutcome {
        self.0.outcome()
    }

    /// What this request changed.
    #[must_use]
    pub const fn change(&self) -> EpollChange {
        *self.0.info()
    }

    /// Take the storage back for reuse.
    #[must_use]
    pub fn into_store(self) -> S {
        self.0.into_store()
    }

    /// Take the outcome and the storage together.
    #[must_use]
    pub fn into_parts(self) -> (EpollOutcome, S) {
        self.0.into_parts()
    }
}
