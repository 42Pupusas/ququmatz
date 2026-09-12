//! Multishot read, the file-side twin of [`multishot`](super::multishot).
//!
//! `IORING_OP_READ_MULTISHOT` (kernel 6.7+) shares its whole state machine
//! with multishot recv: one SQE stays armed, the kernel draws a buffer from
//! a registered pool for each arrival, `IORING_CQE_F_MORE` means still
//! armed, and its absence means the request is over and must be
//! re-submitted. [`Armed`](super::Armed), [`Delivery`](super::Delivery),
//! [`Arrival`](super::Arrival), and [`Finished`](super::Finished) already
//! model exactly that and mention nothing socket-specific, so this module
//! reuses them rather than re-deriving the same borrow-and-recycle guard
//! under a new name. The only new thing is what gets armed and how: a
//! pollable file and a byte offset instead of a socket and message flags.

use super::event::Event;
use super::identity::{RequestId, RingId};
use crate::op::Sqe;
use crate::types::RawFd;

/// A multishot read that has not been queued yet.
///
/// Carries no buffer: the pool named by `bgid` supplies one per arrival.
/// `Copy`, because there is no owned resource here to make duplication
/// unsound — which is what lets a rejected push hand the request back
/// exactly as it was given.
#[derive(Debug, Clone, Copy)]
pub struct PreparedReadMultishot {
    fd: RawFd,
    offset: u64,
    bgid: u16,
}

impl PreparedReadMultishot {
    /// Prepare a multishot read on `fd`, drawing buffers from the pool
    /// registered under `bgid`.
    ///
    /// `fd` must name a pollable file — a pipe, a `tun` device, and
    /// similar. The kernel rejects a regular file with `-EBADFD`, since
    /// "more data becomes available later" has no meaning there. On files
    /// that cannot seek, `offset` must be `0` or `u64::MAX`.
    #[must_use]
    pub const fn on(fd: RawFd, offset: u64, bgid: u16) -> Self {
        Self { fd, offset, bgid }
    }

    /// The file this read is armed on.
    #[must_use]
    pub const fn fd(&self) -> RawFd {
        self.fd
    }

    /// The file offset this request reads from.
    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    /// The buffer group arrivals will be drawn from.
    #[must_use]
    pub const fn bgid(&self) -> u16 {
        self.bgid
    }

    /// Build the SQE and move to the armed state.
    pub(crate) fn into_pending(self, ring: RingId, id: RequestId) -> (Sqe, MultishotRead) {
        let sqe = Sqe::read_multishot(self.fd, self.offset, self.bgid).user_data(id.raw());
        (
            sqe,
            MultishotRead {
                ring,
                id,
                bgid: self.bgid,
                fd: self.fd,
            },
        )
    }
}

/// A submitted multishot read.
///
/// Unlike [`Pending`](super::Pending) this owns no buffer, so dropping it
/// frees nothing and leaks nothing — but the *kernel request* outlives the
/// ticket. Dropping this while the multishot is still armed leaves it
/// delivering into the pool with nobody reading, which drains the pool.
/// Cancel the request through the raw submitter, or drain until
/// [`Armed::Finished`](super::Armed::Finished), before letting the ticket
/// go.
#[derive(Debug)]
pub struct MultishotRead {
    ring: RingId,
    id: RequestId,
    bgid: u16,
    fd: RawFd,
}

impl MultishotRead {
    /// Identity the kernel echoes back in every CQE for this request.
    #[must_use]
    pub const fn id(&self) -> RequestId {
        self.id
    }

    /// Identity of the queue that accepted this request.
    #[must_use]
    pub const fn ring(&self) -> RingId {
        self.ring
    }

    /// The buffer group arrivals are drawn from.
    #[must_use]
    pub const fn bgid(&self) -> u16 {
        self.bgid
    }

    /// The file this read is armed on.
    #[must_use]
    pub const fn fd(&self) -> RawFd {
        self.fd
    }

    /// Whether a completion belongs to this request.
    #[must_use]
    pub const fn matches(&self, event: &Event) -> bool {
        event.belongs_to(self.ring, self.id)
    }

    /// Interpret a completion for this request.
    ///
    /// Returns whether the multishot is still armed. A [`Delivery::Data`]
    /// carries the pool slot the kernel filled; hold it only as long as the
    /// bytes are needed, since the slot is out of the pool until it drops.
    ///
    /// # Errors
    ///
    /// Returns the event unchanged if it belongs to another request or
    /// another ring.
    pub fn record<'pool>(
        &self,
        event: Event,
        pool: &'pool mut crate::ring::BufferConsumer,
    ) -> Result<super::Delivery<'pool>, Event> {
        if !self.matches(&event) {
            return Err(event);
        }
        Ok(super::Delivery::from_event(event, pool))
    }
}
