//! Multishot receive, which borrows pool buffers instead of owning one.
//!
//! Every other owned request holds a buffer for its whole life:
//! [`Prepared`](super::Prepared) takes one in and
//! [`Completed`](super::Completed) gives it back. A multishot receive owns
//! nothing. One SQE stays armed across many arrivals, and the kernel picks
//! a different buffer from a registered pool for each one, so the resource
//! to manage is not an allocation but a **borrow of a pool slot that must be
//! recycled exactly once**. Recycling twice hands the kernel a buffer that
//! is already queued; never recycling drains the pool until the receive
//! stalls on `ENOBUFS`.
//!
//! [`Arrival`] is that borrow. It reads the bytes and recycles the slot on
//! drop, so the only way to leak one is to [`forget`](core::mem::forget) it.
//!
//! # Finishing is not failure
//!
//! A multishot is armed until the kernel decides otherwise. Per
//! `io_uring_prep_recv_multishot(3)`:
//!
//! > If a posted CQE does not have the `IORING_CQE_F_MORE` flag set, then
//! > the multishot receive is done and the application must issue a new
//! > request if it still wishes to receive data from the socket.
//!
//! So the terminal CQE means *re-arm*, not merely "finished", and it can
//! arrive at any time — `ENOBUFS` from a drained pool is the common cause.
//! Treating it as an ordinary end-of-stream leaves a socket permanently
//! deaf while the program waits for arrivals that will never come.
//! [`MultishotRecv::record`] therefore reports [`Armed::Finished`] rather
//! than returning quietly, and the ticket cannot be reused: re-arming means
//! submitting a new request, which is what the kernel actually requires.

use super::event::{Event, PartialReceipt};
use super::identity::{RequestId, RingId};
use super::request::Receipt;
use crate::op::Sqe;
use crate::ring::BufferConsumer;
use crate::types::{MsgFlags, RawFd};

/// A multishot receive that has not been queued yet.
///
/// Carries no buffer: the pool named by `bgid` supplies one per arrival.
/// `Copy`, because there is no owned resource here to make duplication
/// unsound — which is what lets a rejected push hand the request back
/// exactly as it was given.
#[derive(Debug, Clone, Copy)]
pub struct PreparedMultishot {
    fd: RawFd,
    bgid: u16,
    flags: MsgFlags,
}

impl PreparedMultishot {
    /// Prepare a multishot receive on `fd`, drawing buffers from the pool
    /// registered under `bgid`.
    ///
    /// The pool is the one behind
    /// [`BufferConsumer::bgid`](crate::ring::BufferConsumer::bgid); the
    /// completion thread owns it and recycles into it.
    #[must_use]
    pub const fn recv(fd: RawFd, bgid: u16, flags: MsgFlags) -> Self {
        Self { fd, bgid, flags }
    }

    /// The socket this receive is armed on.
    #[must_use]
    pub const fn fd(&self) -> RawFd {
        self.fd
    }

    /// The buffer group arrivals will be drawn from.
    #[must_use]
    pub const fn bgid(&self) -> u16 {
        self.bgid
    }

    /// The receive flags this request was prepared with.
    #[must_use]
    pub const fn flags(&self) -> MsgFlags {
        self.flags
    }

    /// Build the SQE and move to the armed state.
    pub(crate) fn into_pending(self, ring: RingId, id: RequestId) -> (Sqe, MultishotRecv) {
        let sqe = Sqe::recv_multishot(self.fd, self.flags)
            .buffer_select(self.bgid)
            .user_data(id.raw());
        (
            sqe,
            MultishotRecv {
                ring,
                id,
                bgid: self.bgid,
                fd: self.fd,
            },
        )
    }
}

/// Whether a multishot is still armed after a completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Armed {
    /// The kernel will keep delivering arrivals for this request.
    Yes,
    /// The request is over. Nothing further will arrive until a new
    /// multishot is submitted for the socket.
    Finished,
}

impl Armed {
    /// Whether the request is still delivering.
    #[must_use]
    pub const fn is_armed(self) -> bool {
        matches!(self, Self::Yes)
    }
}

/// A submitted multishot receive.
///
/// Unlike [`Pending`](super::Pending) this owns no buffer, so dropping it
/// frees nothing and leaks nothing — but the *kernel request* outlives the
/// ticket. Dropping this while the multishot is still armed leaves it
/// delivering into the pool with nobody reading, which drains the pool.
/// Cancel the request through the raw submitter, or drain until
/// [`Armed::Finished`], before letting the ticket go.
pub struct MultishotRecv {
    ring: RingId,
    id: RequestId,
    bgid: u16,
    fd: RawFd,
}

impl MultishotRecv {
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

    /// The socket this receive is armed on.
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
        pool: &'pool mut BufferConsumer,
    ) -> Result<Delivery<'pool>, Event> {
        if !self.matches(&event) {
            return Err(event);
        }
        match event {
            Event::Partial(partial) => Ok(Self::deliver(&partial, pool)),
            Event::Complete(receipt) => Ok(Delivery::Done(Finished { receipt })),
        }
    }

    fn deliver<'pool>(
        partial: &PartialReceipt,
        pool: &'pool mut BufferConsumer,
    ) -> Delivery<'pool> {
        match (partial.buffer_id(), u32::try_from(partial.raw_result())) {
            (Some(buf_id), Ok(len)) => Delivery::Data(Arrival { pool, buf_id, len }),
            // An armed CQE with no buffer or a negative result carries no
            // slot to recycle; reporting it as an empty arrival would invent
            // a borrow that does not exist.
            _ => Delivery::Empty(partial.raw_result()),
        }
    }
}

/// What one completion of a multishot receive delivered.
///
/// Deliberately exhaustive: forcing every caller to name the [`Done`]
/// case is the point, since ignoring it leaves a socket permanently deaf.
///
/// [`Done`]: Delivery::Done
#[derive(Debug)]
pub enum Delivery<'pool> {
    /// Bytes arrived in a pool buffer, borrowed until this drops.
    Data(Arrival<'pool>),
    /// The request stayed armed but delivered no buffer, carrying the raw
    /// CQE result — a kernel-reported error on an otherwise live request.
    Empty(i32),
    /// The request is over and must be re-submitted to receive again.
    Done(Finished),
}

impl Delivery<'_> {
    /// Whether the multishot is still armed after this completion.
    #[must_use]
    pub const fn armed(&self) -> Armed {
        match self {
            Self::Data(_) | Self::Empty(_) => Armed::Yes,
            Self::Done(_) => Armed::Finished,
        }
    }

    /// The arrival's bytes, if this delivery carried any.
    #[must_use]
    pub fn bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Data(arrival) => Some(arrival.bytes()),
            Self::Empty(_) | Self::Done(_) => None,
        }
    }
}

/// One multishot arrival: a pool buffer borrowed until this drops.
///
/// The slot is out of the pool for as long as this lives, so hold it only
/// while reading. Dropping recycles it — including on unwind — which is why
/// this is a guard rather than a plain id the caller must remember to hand
/// back. The borrow of the pool is exclusive, so a second arrival cannot be
/// taken while one is outstanding and the ids cannot be confused.
pub struct Arrival<'pool> {
    pool: &'pool mut BufferConsumer,
    buf_id: u16,
    len: u32,
}

impl core::fmt::Debug for Arrival<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Arrival")
            .field("buffer_id", &self.buf_id)
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl Arrival<'_> {
    /// The bytes the kernel wrote into this slot.
    ///
    /// Empty if the kernel reported a length the pool cannot honour, which
    /// would mean a buffer id outside the registered range.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.pool.buffer(self.buf_id, self.len).unwrap_or(&[])
    }

    /// The pool slot this arrival occupies.
    #[must_use]
    pub const fn buffer_id(&self) -> u16 {
        self.buf_id
    }

    /// How many bytes the kernel wrote.
    #[must_use]
    pub const fn len(&self) -> u32 {
        self.len
    }

    /// Whether the kernel wrote no bytes, which on a stream socket means
    /// the peer closed.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Drop for Arrival<'_> {
    fn drop(&mut self) {
        // Unlike an owned buffer, a pool slot must go back: the kernel owns
        // the storage and is waiting to reuse it. Publishing immediately
        // keeps the pool from draining while the caller processes a burst.
        self.pool.recycle_and_commit(self.buf_id);
    }
}

/// A multishot receive that the kernel has stopped delivering for.
///
/// Holds the terminal CQE's result. Receiving again means submitting a new
/// [`PreparedMultishot`]; this is deliberately not reusable, because the
/// kernel requires a fresh request rather than a re-arm of the old one.
#[derive(Debug)]
pub struct Finished {
    receipt: Receipt,
}

impl Finished {
    /// Raw result of the terminal CQE.
    #[must_use]
    pub const fn raw_result(&self) -> i32 {
        self.receipt.raw_result()
    }

    /// Why the multishot ended.
    ///
    /// A non-negative result is an ordinary end; `ENOBUFS` means the pool
    /// ran dry, which is a signal to recycle faster or register more
    /// buffers rather than to abandon the socket.
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

    /// The terminal receipt, for callers tracking identity themselves.
    #[must_use]
    pub const fn into_receipt(self) -> Receipt {
        self.receipt
    }
}
