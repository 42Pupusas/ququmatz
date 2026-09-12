//! `IORING_OP_ASYNC_CANCEL`, which owns nothing and reports a racy outcome.
//!
//! A cancel request is the odd one out among owned requests: it touches no
//! caller memory the kernel dereferences, so there is no buffer to hold
//! across submission and no storage a dropped ticket could leak. What it
//! carries instead is a **target key** — a `user_data`, an `fd`, or "any
//! request" — chosen at construction, mirroring the three
//! [`Sqe`](crate::Sqe) constructors ([`Sqe::cancel`], [`Sqe::cancel_fd`],
//! [`Sqe::cancel_any`]) it wraps.
//!
//! # The outcome is inherently racy, not merely fallible
//!
//! Per `io_uring_cancelation(7)`, a cancel's own CQE and the CQE of the
//! request it targets can arrive in either order, and the target may
//! finish successfully, fail on its own, or already be too far along to
//! stop before the kernel processes the cancel. `-ENOENT` and `-EALREADY`
//! are therefore ordinary outcomes of that race rather than programming
//! errors, so [`CancelOutcome`] names them instead of folding them into a
//! generic failure — the same treatment
//! [`EpollOutcome`](super::EpollOutcome) gives `EEXIST`/`ENOENT`.
//!
//! This module does not attempt to correlate the cancel's outcome with the
//! target request's own completion; that pairing is the caller's, done by
//! matching `user_data` values, exactly as the raw [`Sqe`] surface already
//! requires.

use super::identity::{RequestId, RingId};
use super::request::Receipt;
use crate::op::Sqe;
use crate::types::{CancelFlags, CancelOutcome, RawFd};

/// Which requests a cancel targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelTarget {
    /// Match by the target request's `user_data`.
    UserData(u64),
    /// Match every in-flight request on a descriptor.
    Fd(RawFd),
    /// Match any single in-flight request, ignoring key entirely.
    Any,
}

/// An async-cancel request that has not been queued yet.
///
/// `Copy`, because it owns no resource — there is nothing a rejected push
/// needs to hand back beyond an identical copy of the request.
#[derive(Debug, Clone, Copy)]
pub struct PreparedCancel {
    target: CancelTarget,
    flags: CancelFlags,
}

impl PreparedCancel {
    /// Prepare a cancel matching a specific request's `user_data`.
    #[must_use]
    pub const fn user_data(target_user_data: u64, flags: CancelFlags) -> Self {
        Self {
            target: CancelTarget::UserData(target_user_data),
            flags,
        }
    }

    /// Prepare a cancel matching every in-flight request on `fd`.
    ///
    /// Closing `fd` does not by itself cancel requests still using it —
    /// the kernel holds its own reference per request — so this is the
    /// intended way to stop pending work before a close.
    #[must_use]
    pub const fn fd(target: RawFd, flags: CancelFlags) -> Self {
        Self {
            target: CancelTarget::Fd(target),
            flags,
        }
    }

    /// Prepare a cancel matching any single in-flight request.
    ///
    /// Combine `flags` with [`CancelFlags::ALL`] to drain every request on
    /// the ring — the usual way to cancel everything before shutdown.
    #[must_use]
    pub const fn any(flags: CancelFlags) -> Self {
        Self {
            target: CancelTarget::Any,
            flags,
        }
    }

    /// What this request targets.
    #[must_use]
    pub const fn target(&self) -> CancelTarget {
        self.target
    }

    /// The flags this request was prepared with.
    #[must_use]
    pub const fn flags(&self) -> CancelFlags {
        self.flags
    }

    /// Build the SQE and move to the pending state.
    pub(crate) fn into_pending(self, ring: RingId, id: RequestId) -> (Sqe, PendingCancel) {
        let sqe = match self.target {
            CancelTarget::UserData(target) => Sqe::cancel_with_flags(target, self.flags),
            CancelTarget::Fd(fd) => Sqe::cancel_fd(fd, self.flags),
            CancelTarget::Any => Sqe::cancel_any(self.flags),
        };
        let pending = PendingCancel {
            ring,
            id,
            target: self.target,
        };
        (sqe.user_data(id.raw()), pending)
    }
}

/// A submitted cancel request.
///
/// Owns nothing, so dropping it — unlike every buffer-owning ticket in
/// this module — leaks nothing. It is still worth redeeming: without the
/// receipt there is no way to distinguish "cancelled" from "no matching
/// request" from "already too late".
#[derive(Debug)]
pub struct PendingCancel {
    ring: RingId,
    id: RequestId,
    target: CancelTarget,
}

impl PendingCancel {
    /// Identity the kernel echoes back in this request's CQE.
    #[must_use]
    pub const fn id(&self) -> RequestId {
        self.id
    }

    /// Identity of the queue that accepted this request.
    #[must_use]
    pub const fn ring(&self) -> RingId {
        self.ring
    }

    /// What this request targets.
    #[must_use]
    pub const fn target(&self) -> CancelTarget {
        self.target
    }

    /// Whether `receipt` authenticates this exact request.
    #[must_use]
    pub const fn matches(&self, receipt: &Receipt) -> bool {
        receipt.belongs_to(self.ring, self.id)
    }

    /// Trade a matching receipt for the outcome.
    ///
    /// # Errors
    ///
    /// Returns the ticket and receipt unchanged if the receipt belongs to
    /// another request or another ring.
    pub const fn redeem(self, receipt: Receipt) -> Result<CancelDone, (Self, Receipt)> {
        if !self.matches(&receipt) {
            return Err((self, receipt));
        }
        Ok(CancelDone {
            target: self.target,
            id: self.id,
            result: receipt.raw_result(),
        })
    }
}

/// A finished cancel: how it ended, and what it targeted.
#[derive(Debug, Clone, Copy)]
pub struct CancelDone {
    target: CancelTarget,
    id: RequestId,
    result: i32,
}

impl CancelDone {
    /// Identity of the request this completes.
    #[must_use]
    pub const fn id(&self) -> RequestId {
        self.id
    }

    /// What this request targeted.
    #[must_use]
    pub const fn target(&self) -> CancelTarget {
        self.target
    }

    /// Raw CQE result: a non-negative count on success, `-errno` otherwise.
    #[must_use]
    pub const fn raw_result(&self) -> i32 {
        self.result
    }

    /// How the request ended.
    #[must_use]
    pub const fn outcome(&self) -> CancelOutcome {
        CancelOutcome::from_raw(self.result)
    }
}
