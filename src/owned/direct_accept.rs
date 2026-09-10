//! Multishot accept that installs into the ring's file table.
//!
//! The direct sibling of [`accept`](super::accept). One SQE stays armed and
//! the kernel posts a CQE per connection, but each connection is installed
//! into a slot of the ring's registered-file table rather than into this
//! process's descriptor table. Nothing here is a descriptor, so nothing
//! here is closed.
//!
//! # The slot is always kernel-chosen
//!
//! `io_uring_prep_multishot_accept_direct(3)` takes no `file_index`
//! argument, unlike its single-shot counterpart. One armed request accepts
//! many connections and they cannot all land in the same slot, so the
//! kernel picks a free one per connection and reports its index in the CQE
//! result. There is therefore no [`SlotTarget`](super::SlotTarget) here:
//! the target is always `Auto`, and every successful result is an index.
//!
//! Callers who also install into explicit slots can keep the two ranges
//! apart with `IORING_REGISTER_FILE_ALLOC_RANGE`, which this crate does not
//! yet wrap.
//!
//! # Exhaustion ends the request
//!
//! A registered table is far smaller than `RLIMIT_NOFILE`, so running out
//! of slots is ordinary rather than exotic. When it happens the kernel
//! reports `-ENFILE` — and **the request is over**, because the re-arm is
//! gated on the result being non-negative:
//!
//! ```text
//! if (ret >= 0 && (req->flags & REQ_F_APOLL_MULTISHOT) &&
//!     io_req_post_cqe(req, ret, cflags | IORING_CQE_F_MORE)) {
//!         ...                          /* stayed armed */
//! }
//! io_req_set_res(req, ret, cflags);    /* terminal */
//! ```
//!
//! So a full table does not merely refuse one connection, it stops the
//! listener. This was measured rather than assumed: with a two-slot table,
//! the third connection yields `res=-23` with `IORING_CQE_F_MORE` clear,
//! and a fourth connection produces no completion at all. Any design that
//! treated `-ENFILE` as a survivable hiccup would wait forever on a
//! listener the kernel had already retired, so [`DirectIncoming`] reports
//! it as [`Done`](DirectIncoming::Done) like any other ending.
//!
//! # The terminal CQE can still carry a slot
//!
//! The same fold as the descriptor-returning accept: the kernel installs
//! into the table before deciding whether the request continues, so when
//! the extra CQE cannot be posted the installed slot rides out on the
//! terminal CQE. [`DirectAcceptFinished`] carries it rather than dropping
//! it, since a discarded slot stays occupied until the ring dies.

use super::event::Event;
use super::identity::{RequestId, RingId};
use super::request::Receipt;
use super::slot::{DirectSlot, SlotTarget};
use crate::op::Sqe;
use crate::types::{AcceptFlags, RawFd};

/// A direct multishot accept that has not been queued yet.
///
/// `Copy`: it owns nothing, which is what lets a rejected push hand the
/// request back exactly as it was given.
#[derive(Debug, Clone, Copy)]
pub struct PreparedDirectAccept {
    fd: RawFd,
    flags: AcceptFlags,
}

impl PreparedDirectAccept {
    /// Prepare a direct multishot accept on a listening socket.
    ///
    /// Requires a registered file table — see
    /// [`IoUring::register_files`](crate::IoUring::register_files). Without
    /// one every completion fails instead of installing anything.
    ///
    /// The peer address is deliberately not captured, for the same reason
    /// as [`PreparedAccept`](super::PreparedAccept): one armed request
    /// would write every connection's address into the same buffer.
    #[must_use]
    pub const fn on(fd: RawFd, flags: AcceptFlags) -> Self {
        Self { fd, flags }
    }

    /// The listening socket this accept is armed on.
    #[must_use]
    pub const fn fd(&self) -> RawFd {
        self.fd
    }

    /// The accept flags this request was prepared with.
    #[must_use]
    pub const fn flags(&self) -> AcceptFlags {
        self.flags
    }

    /// Build the SQE and move to the armed state.
    pub(crate) fn into_pending(self, ring: RingId, id: RequestId) -> (Sqe, DirectAccept) {
        let sqe = Sqe::accept_multishot_direct(self.fd, self.flags).user_data(id.raw());
        (
            sqe,
            DirectAccept {
                ring,
                id,
                fd: self.fd,
            },
        )
    }
}

/// A submitted direct multishot accept.
///
/// Owns nothing, so dropping it frees nothing — but the kernel request
/// outlives the ticket and keeps installing connections into the ring's
/// table. Dropping this while armed fills that table with connections
/// nothing names. Drain until [`Done`](DirectIncoming::Done), or cancel
/// through the raw submitter, before letting it go.
#[derive(Debug)]
pub struct DirectAccept {
    ring: RingId,
    id: RequestId,
    fd: RawFd,
}

impl DirectAccept {
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

    /// The listening socket this accept is armed on.
    #[must_use]
    pub const fn fd(&self) -> RawFd {
        self.fd
    }

    /// Whether a completion belongs to this request.
    #[must_use]
    pub const fn matches(&self, event: &Event) -> bool {
        let (ring, id) = match event {
            Event::Complete(receipt) => (receipt.ring(), receipt.id()),
            Event::Partial(partial) => (partial.ring(), partial.id()),
        };
        ring.raw() == self.ring.raw() && id.raw() == self.id.raw()
    }

    /// Interpret a completion for this request.
    ///
    /// Takes `&mut self` to keep the installed slots sequential at the call
    /// site, matching [`MultishotAccept`](super::MultishotAccept).
    ///
    /// # Errors
    ///
    /// Returns the event unchanged if it belongs to another request or
    /// another ring.
    pub fn record(&mut self, event: Event) -> Result<DirectIncoming, Event> {
        if !self.matches(&event) {
            return Err(event);
        }
        match event {
            Event::Partial(partial) => {
                let result = partial.raw_result();
                Ok(self
                    .claim(result)
                    .map_or(DirectIncoming::Empty(result), DirectIncoming::Installed))
            }
            Event::Complete(receipt) => {
                let last = self.claim(receipt.raw_result());
                Ok(DirectIncoming::Done(DirectAcceptFinished { receipt, last }))
            }
        }
    }

    /// Adopt the slot a completion installed into, if it installed one.
    ///
    /// The target is always `Auto` for a multishot direct accept, so the
    /// result *is* the index — including zero, which is a real slot here
    /// rather than the "not a direct request" sentinel the submission side
    /// has to encode around.
    fn claim(&self, result: i32) -> Option<DirectSlot> {
        SlotTarget::Auto
            .resolve(result)
            .map(|index| DirectSlot::new(index, self.ring))
    }
}

/// What one completion of a direct multishot accept delivered.
///
/// Deliberately exhaustive: naming the [`Done`] case is the point, since
/// ignoring it leaves a listener that has silently stopped accepting — and
/// for this operation an exhausted table is a routine way to get there.
///
/// [`Done`]: DirectIncoming::Done
#[derive(Debug)]
pub enum DirectIncoming {
    /// A connection was installed into this slot of the ring's table.
    Installed(DirectSlot),
    /// The request stayed armed but installed nothing, carrying the raw
    /// CQE result.
    Empty(i32),
    /// The request is over and must be re-submitted to accept again.
    ///
    /// Reached by cancellation, by an error, and — unlike the
    /// descriptor-returning accept — routinely by the table filling up,
    /// which reports `-ENFILE` here rather than staying armed.
    /// May still carry a final slot; see [`DirectAcceptFinished::last`].
    Done(DirectAcceptFinished),
}

impl DirectIncoming {
    /// Whether the accept is still armed after this completion.
    #[must_use]
    pub const fn armed(&self) -> super::Armed {
        match self {
            Self::Installed(_) | Self::Empty(_) => super::Armed::Yes,
            Self::Done(_) => super::Armed::Finished,
        }
    }

    /// Take the slot this completion carried, if any.
    ///
    /// A [`Done`](Self::Done) can carry one too, when the kernel had to
    /// fold the last install into the terminal CQE.
    #[must_use]
    pub const fn into_slot(self) -> Option<DirectSlot> {
        match self {
            Self::Installed(slot) => Some(slot),
            Self::Done(finished) => finished.into_parts().1,
            Self::Empty(_) => None,
        }
    }
}

/// A direct multishot accept the kernel has stopped delivering for.
///
/// Accepting again means submitting a new [`PreparedDirectAccept`]; the
/// kernel requires a fresh request rather than a re-arm of the old one.
#[derive(Debug)]
pub struct DirectAcceptFinished {
    receipt: Receipt,
    last: Option<DirectSlot>,
}

impl DirectAcceptFinished {
    /// The slot folded into this terminal CQE, if the kernel had to put one
    /// there.
    ///
    /// Normally `None`: an install and the end of the request are usually
    /// separate CQEs. It is `Some` when the kernel could not post the extra
    /// completion — a full CQ — and finished the request carrying the slot
    /// it had already installed into.
    #[must_use]
    pub const fn last(&self) -> Option<&DirectSlot> {
        self.last.as_ref()
    }

    /// Raw result of the terminal CQE.
    #[must_use]
    pub const fn raw_result(&self) -> i32 {
        self.receipt.raw_result()
    }

    /// Why the accept ended.
    ///
    /// `-ENFILE` here means the ring's file table is full, not that the
    /// process is out of descriptors.
    ///
    /// # Errors
    ///
    /// Returns [`CompletionError::Failed`](crate::CompletionError::Failed)
    /// when the terminal CQE carried a negative errno.
    #[allow(clippy::cast_sign_loss)]
    pub const fn result(&self) -> Result<u32, crate::Error> {
        let raw = self.receipt.raw_result();
        if raw < 0 {
            Err(crate::Error::Completion(crate::CompletionError::Failed(
                crate::Errno::new(-raw),
            )))
        } else {
            Ok(raw as u32)
        }
    }

    /// Split into the terminal receipt and any final slot.
    ///
    /// Returns both rather than just the receipt: discarding the slot here
    /// would strand an installed connection in the ring's table.
    #[must_use]
    pub const fn into_parts(self) -> (Receipt, Option<DirectSlot>) {
        (self.receipt, self.last)
    }
}
