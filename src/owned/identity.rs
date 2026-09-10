//! Ring and request identities used to authenticate completions.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Process-wide identity for one owned-submission ring.
///
/// A [`Completion`](crate::Completion) is a plain public struct that any
/// safe code can build, so a raw `user_data` match is not proof that a CQE
/// belongs to a given request. Every ticket and receipt carries the
/// `RingId` of the queue that produced it, and redemption rejects a
/// mismatch. That keeps a receipt from one ring from unlocking a ticket
/// from another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RingId(u32);

impl RingId {
    /// Allocate an identity that no live ring shares.
    pub(crate) fn next() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(1);
        Self(NEXT.fetch_add(1, Ordering::Relaxed))
    }

    pub(crate) const fn raw(self) -> u32 {
        self.0
    }
}

/// Identity of one submitted operation, unique within its ring.
///
/// Encoded into the SQE's `user_data` so the kernel hands it back in the
/// CQE. Monotonic and never reused, so a stale receipt for a long-finished
/// request cannot authenticate a later one that happens to occupy the same
/// storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RequestId(u64);

impl RequestId {
    pub(crate) const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// The value carried in the SQE/CQE `user_data` field.
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Monotonic source of [`RequestId`]s for a single ring.
///
/// Not exported: identities are minted only by an
/// [`OwnedSubmitter`](super::OwnedSubmitter), never by callers.
#[allow(clippy::redundant_pub_crate)]
pub(crate) struct RequestIdSource {
    next: AtomicU64,
}

impl RequestIdSource {
    pub(crate) const fn new() -> Self {
        Self {
            next: AtomicU64::new(1),
        }
    }

    /// Hand out the next identity.
    ///
    /// `u64` at even a billion submissions a second takes ~584 years to
    /// wrap, so exhaustion is not a practical failure mode.
    pub(crate) fn next(&self) -> RequestId {
        RequestId(self.next.fetch_add(1, Ordering::Relaxed))
    }
}

#[cfg(test)]
mod identity_tests {
    use super::{RequestId, RequestIdSource, RingId};

    #[test]
    fn ring_ids_are_distinct() {
        let a = RingId::next();
        let b = RingId::next();
        assert_ne!(a, b);
    }

    #[test]
    fn request_ids_are_monotonic_and_unique() {
        let source = RequestIdSource::new();
        let ids = [source.next(), source.next(), source.next()];
        assert!(ids[0] < ids[1] && ids[1] < ids[2]);
    }

    #[test]
    fn request_id_round_trips_through_raw_user_data() {
        let source = RequestIdSource::new();
        let id = source.next();
        assert_eq!(RequestId::from_raw(id.raw()), id);
    }

    #[test]
    fn separate_sources_start_from_the_same_base() {
        assert_eq!(RequestIdSource::new().next(), RequestIdSource::new().next());
    }
}
