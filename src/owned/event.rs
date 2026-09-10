//! What a reaped CQE authorizes.
//!
//! The kernel's `IORING_CQE_F_MORE` flag answers one question — will more
//! completions follow for this request? — and that is exactly the question
//! "may this CQE release the buffer?". A CQE carrying `MORE` cannot be
//! terminal, so it must not mint a [`Receipt`].
//!
//! `MORE` says nothing about *what* the CQE carries, though, and the two
//! axes are independent. A zero-copy send's result CQE reports a byte count
//! with the pages still mapped to the NIC; a multishot arrival reports a
//! byte count *and* the id of a pool buffer that must be recycled. Both are
//! non-terminal, so both become [`Partial`](Event::Partial), and the flags
//! that ride along are preserved rather than discarded — a dropped buffer
//! id drains the pool and stalls the multishot on `ENOBUFS`.

use super::identity::{RequestId, RingId};
use super::request::Receipt;
use crate::types::CqeFlags;

/// A completion that does **not** release its request's resources.
///
/// Minted only from a CQE carrying `IORING_CQE_F_MORE`, meaning the kernel
/// promised at least one more completion for the same request. It is
/// deliberately a distinct type from [`Receipt`]: nothing in the API
/// accepts it where a release is required, so a non-terminal completion
/// cannot free storage the kernel is still using.
#[derive(Debug)]
pub struct PartialReceipt {
    pub(crate) ring: RingId,
    pub(crate) id: RequestId,
    pub(crate) result: i32,
    pub(crate) flags: CqeFlags,
}

impl PartialReceipt {
    /// Which request this reports.
    #[must_use]
    pub const fn id(&self) -> RequestId {
        self.id
    }

    /// Which ring produced it.
    #[must_use]
    pub const fn ring(&self) -> RingId {
        self.ring
    }

    /// Raw CQE result: a byte count when non-negative, `-errno` otherwise.
    #[must_use]
    pub const fn raw_result(&self) -> i32 {
        self.result
    }

    /// Kernel-set CQE flags.
    ///
    /// Retained because a non-terminal CQE can carry a resource of its own:
    /// a multishot arrival's chosen buffer id lives in the upper 16 bits.
    #[must_use]
    pub const fn flags(&self) -> CqeFlags {
        self.flags
    }

    /// The pool buffer id this completion consumed, if any.
    ///
    /// `Some` only when the kernel set `IORING_CQE_F_BUFFER`, which it does
    /// for operations submitted with
    /// [`buffer_select`](crate::op::Sqe::buffer_select). That buffer is out
    /// of the pool until it is recycled.
    #[must_use]
    pub const fn buffer_id(&self) -> Option<u16> {
        self.flags.buffer_id()
    }
}

/// What a reaped CQE authorizes.
///
/// Returned by [`reap_event`](super::OwnedCompleter::reap_event) for rings
/// whose requests do not all complete in one CQE, where "is this completion
/// terminal?" can no longer be answered by the completer alone.
#[derive(Debug)]
pub enum Event {
    /// A terminal completion. Releases the resources of the ticket it
    /// matches, and for a multishot means the request is finished and must
    /// be re-armed to keep receiving.
    Complete(Receipt),
    /// A non-terminal completion: a zero-copy send's result, or one
    /// multishot arrival. More completions will follow for this request.
    Partial(PartialReceipt),
}

impl Event {
    /// The terminal receipt, if this event carries one.
    #[must_use]
    pub const fn into_receipt(self) -> Option<Receipt> {
        match self {
            Self::Complete(receipt) => Some(receipt),
            Self::Partial(_) => None,
        }
    }

    /// Which request this event belongs to.
    #[must_use]
    pub const fn id(&self) -> RequestId {
        match self {
            Self::Complete(receipt) => receipt.id,
            Self::Partial(partial) => partial.id,
        }
    }

    /// Which ring produced it.
    #[must_use]
    pub const fn ring(&self) -> RingId {
        match self {
            Self::Complete(receipt) => receipt.ring,
            Self::Partial(partial) => partial.ring,
        }
    }

    /// Raw CQE result, whichever kind this is.
    #[must_use]
    pub const fn raw_result(&self) -> i32 {
        match self {
            Self::Complete(receipt) => receipt.result,
            Self::Partial(partial) => partial.result,
        }
    }

    /// Kernel-set CQE flags, whichever kind this is.
    #[must_use]
    pub const fn flags(&self) -> CqeFlags {
        match self {
            Self::Complete(receipt) => receipt.flags,
            Self::Partial(partial) => partial.flags,
        }
    }

    /// Whether this event releases its request's resources.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Complete(_))
    }
}
