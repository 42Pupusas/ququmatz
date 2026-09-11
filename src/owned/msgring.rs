//! `IORING_OP_MSG_RING`, which — like [`cancel`](super::cancel) — owns no
//! caller memory the kernel dereferences.
//!
//! `len` and `data` travel as SQE fields, not through a pointer, so there
//! is no buffer for a ticket to hold across submission and nothing a
//! dropped ticket leaks. What is worth tracking is only identity and the
//! raw result, exactly as for [`PendingCancel`](super::PendingCancel).
//!
//! # The completion this ticket redeems is not the message
//!
//! A `msg_ring` produces **two** CQEs on success, on two different rings:
//! one on *this* ring, for the `msg_ring` request itself (`0` on success),
//! and one on the *target* ring, carrying the payload (`res = len`,
//! `user_data = data`). [`PendingMsgRing::redeem`] only ever seals the
//! first — the request this ticket represents. Reading the message on the
//! target ring is the receiving side's problem, using whatever identity
//! `data` was chosen to carry; this module has no way to observe a ring it
//! was not built to submit into.

use super::identity::{RequestId, RingId};
use super::request::Receipt;
use crate::op::Sqe;
use crate::types::{MsgRingFlags, RawFd};

/// An `IORING_OP_MSG_RING` request that has not been queued yet.
///
/// `Copy`, because it owns no resource — a rejected push simply hands back
/// an identical copy.
#[derive(Debug, Clone, Copy)]
pub struct PreparedMsgRing {
    target: RawFd,
    len: u32,
    data: u64,
    flags: MsgRingFlags,
}

impl PreparedMsgRing {
    /// Prepare a message to `target`'s completion queue.
    ///
    /// `target` must be an `io_uring` file descriptor — any ring the
    /// caller has access to, including the ring this request is itself
    /// submitted on.
    #[must_use]
    pub const fn new(target: RawFd, len: u32, data: u64, flags: MsgRingFlags) -> Self {
        Self {
            target,
            len,
            data,
            flags,
        }
    }

    /// The ring this message is addressed to.
    #[must_use]
    pub const fn target(&self) -> RawFd {
        self.target
    }

    /// The payload's length field, delivered as the target CQE's `res`.
    #[must_use]
    pub const fn payload_len(&self) -> u32 {
        self.len
    }

    /// The payload's data field, delivered as the target CQE's `user_data`.
    #[must_use]
    pub const fn data(&self) -> u64 {
        self.data
    }

    /// Build the SQE and move to the pending state.
    pub(crate) fn into_pending(self, ring: RingId, id: RequestId) -> (Sqe, PendingMsgRing) {
        let sqe = Sqe::msg_ring_with_flags(self.target, self.len, self.data, self.flags);
        let pending = PendingMsgRing {
            ring,
            id,
            target: self.target,
        };
        (sqe.user_data(id.raw()), pending)
    }
}

/// A submitted `msg_ring` request.
///
/// Owns nothing, so dropping it leaks nothing — but its completion is the
/// only proof the message was accepted for delivery, so redeeming it is
/// worth doing before assuming the target ring saw anything.
#[derive(Debug)]
pub struct PendingMsgRing {
    ring: RingId,
    id: RequestId,
    target: RawFd,
}

impl PendingMsgRing {
    /// Identity the kernel echoes back in this request's own CQE.
    #[must_use]
    pub const fn id(&self) -> RequestId {
        self.id
    }

    /// Identity of the queue that accepted this request.
    #[must_use]
    pub const fn ring(&self) -> RingId {
        self.ring
    }

    /// The ring this message was addressed to.
    #[must_use]
    pub const fn target(&self) -> RawFd {
        self.target
    }

    /// Whether `receipt` authenticates this exact request.
    #[must_use]
    pub const fn matches(&self, receipt: &Receipt) -> bool {
        receipt.id().raw() == self.id.raw() && receipt.ring().raw() == self.ring.raw()
    }

    /// Trade a matching receipt for the request's own outcome.
    ///
    /// This is **not** the target ring's CQE — see the module docs. A
    /// non-negative result here means the kernel accepted delivery, not
    /// that the target ring's completion queue has room; `-EOVERFLOW`
    /// reports the latter failing.
    ///
    /// # Errors
    ///
    /// Returns the ticket and receipt unchanged if the receipt belongs to
    /// another request or another ring.
    pub const fn redeem(self, receipt: Receipt) -> Result<MsgRingDone, (Self, Receipt)> {
        if !self.matches(&receipt) {
            return Err((self, receipt));
        }
        Ok(MsgRingDone {
            target: self.target,
            id: self.id,
            result: receipt.raw_result(),
        })
    }
}

/// A finished `msg_ring` request: whether the kernel accepted it for
/// delivery.
#[derive(Debug, Clone, Copy)]
pub struct MsgRingDone {
    target: RawFd,
    id: RequestId,
    result: i32,
}

impl MsgRingDone {
    /// Identity of the request this completes.
    #[must_use]
    pub const fn id(&self) -> RequestId {
        self.id
    }

    /// The ring this message was addressed to.
    #[must_use]
    pub const fn target(&self) -> RawFd {
        self.target
    }

    /// Raw CQE result: `0` on success, `-errno` otherwise.
    #[must_use]
    pub const fn raw_result(&self) -> i32 {
        self.result
    }

    /// Whether the kernel accepted the message for delivery.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.result >= 0
    }
}
