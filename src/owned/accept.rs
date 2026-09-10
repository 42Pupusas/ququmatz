//! Multishot accept, which yields owned connections.
//!
//! The sibling of [`multishot`](super::multishot): one SQE stays armed and
//! the kernel posts a CQE per connection. The state machine is the same —
//! `IORING_CQE_F_MORE` means still armed, its absence means the request is
//! over and must be re-submitted — but the resource each completion carries
//! is different, and that difference is the whole reason this is a separate
//! type rather than a parameter on the other one.
//!
//! A recv arrival *borrows* a pool slot: the kernel owns the storage and is
//! waiting for it back, so [`Arrival`](super::Arrival) holds a lifetime and
//! recycles on drop. An accepted connection is *owned* outright. The kernel
//! has already called `fd_install`, so the descriptor belongs to this
//! process whether or not anyone reads the CQE, and the only way to release
//! it is `close`. There is no pool to borrow from, so there is no lifetime;
//! dropping it closes the socket rather than returning it to anyone.
//!
//! That is why [`Incoming::Connection`] carries a plain [`Socket`], the
//! crate's existing owning descriptor. Leaking one leaks a file
//! descriptor — bounded by `RLIMIT_NOFILE`, so a server that ignores them
//! stops accepting.
//!
//! # The terminal CQE can still carry a connection
//!
//! `io_accept()` installs the descriptor before it decides whether the
//! request continues:
//!
//! ```text
//! } else if (!fixed) {
//!         fd_install(fd, file);        /* the fd is live in this process */
//!         ret = fd;
//! }
//! if (ret >= 0 && (req->flags & REQ_F_APOLL_MULTISHOT) &&
//!     io_req_post_cqe(req, ret, cflags | IORING_CQE_F_MORE)) {
//!         ...                          /* stayed armed */
//! }
//! io_req_set_res(req, ret, cflags);    /* terminal, ret is still the fd */
//! ```
//!
//! When the extra CQE cannot be posted — a full completion queue — that
//! installed descriptor rides out on the *terminal* CQE. Discarding it
//! would leak a live connection, so [`AcceptFinished`] carries it.

use super::event::Event;
use super::identity::{RequestId, RingId};
use super::request::Receipt;
use crate::net::Socket;
use crate::op::Sqe;
use crate::types::{AcceptFlags, RawFd};

/// A multishot accept that has not been queued yet.
///
/// `Copy`: it owns nothing, which is what lets a rejected push hand the
/// request back exactly as it was given.
#[derive(Debug, Clone, Copy)]
pub struct PreparedAccept {
    fd: RawFd,
    flags: AcceptFlags,
}

impl PreparedAccept {
    /// Prepare a multishot accept on a listening socket.
    ///
    /// The peer address is deliberately not captured. A multishot accept
    /// would write every connection's address into the same buffer, so a
    /// fast second connection can overwrite the first before it is read;
    /// callers who need it should ask the accepted socket rather than trust
    /// a racing shared slot.
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
    pub(crate) fn into_pending(self, ring: RingId, id: RequestId) -> (Sqe, MultishotAccept) {
        let sqe = Sqe::accept_multishot(self.fd, self.flags).user_data(id.raw());
        (
            sqe,
            MultishotAccept {
                ring,
                id,
                fd: self.fd,
            },
        )
    }
}

/// A submitted multishot accept.
///
/// Owns nothing, so dropping it frees nothing — but the kernel request
/// outlives the ticket, and it keeps accepting. Dropping this while armed
/// leaves connections being installed into the process with nobody to
/// close them, which exhausts the descriptor table. Cancel the request
/// through the raw submitter, or drain until
/// [`Armed::Finished`](super::Armed::Finished), before letting it go.
#[derive(Debug)]
pub struct MultishotAccept {
    ring: RingId,
    id: RequestId,
    fd: RawFd,
}

impl MultishotAccept {
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
    /// Takes `&mut self` purely to make the accepted connections sequential
    /// at the call site: the kernel hands out descriptors one CQE at a
    /// time, and reading them through an exclusive borrow keeps that order
    /// visible rather than letting two completions be interpreted
    /// concurrently against one ticket.
    ///
    /// # Errors
    ///
    /// Returns the event unchanged if it belongs to another request or
    /// another ring.
    pub fn record(&mut self, event: Event) -> Result<Incoming, Event> {
        if !self.matches(&event) {
            return Err(event);
        }
        match event {
            Event::Partial(partial) => {
                let result = partial.raw_result();
                Ok(Self::claim(result).map_or(Incoming::Empty(result), Incoming::Connection))
            }
            Event::Complete(receipt) => {
                let last = Self::claim(receipt.raw_result());
                Ok(Incoming::Done(AcceptFinished { receipt, last }))
            }
        }
    }

    /// Adopt the descriptor a completion installed, if it installed one.
    fn claim(result: i32) -> Option<Socket> {
        let fd = u32::try_from(result).ok()?;
        // SAFETY: a non-negative accept result is a descriptor the kernel
        // installed into this process with `fd_install`. Nothing else holds
        // it — the CQE is reaped once — so taking ownership here is the
        // only claim on it.
        Some(unsafe { Socket::from_fd(RawFd::from_raw(fd as usize)) })
    }
}

/// What one completion of a multishot accept delivered.
///
/// Deliberately exhaustive: naming the [`Done`] case is the point, since
/// ignoring it leaves a listener that has silently stopped accepting.
///
/// [`Done`]: Incoming::Done
#[derive(Debug)]
pub enum Incoming {
    /// A connection was accepted. Closes when dropped.
    Connection(Socket),
    /// The request stayed armed but installed no descriptor, carrying the
    /// raw CQE result — a kernel-reported error on an otherwise live
    /// listener.
    Empty(i32),
    /// The request is over and must be re-submitted to accept again.
    /// May still carry a final connection — see [`AcceptFinished::last`].
    Done(AcceptFinished),
}

impl Incoming {
    /// Whether the accept is still armed after this completion.
    #[must_use]
    pub const fn armed(&self) -> super::Armed {
        match self {
            Self::Connection(_) | Self::Empty(_) => super::Armed::Yes,
            Self::Done(_) => super::Armed::Finished,
        }
    }

    /// Take the connection this completion carried, if any.
    ///
    /// A [`Done`](Self::Done) can carry one too, when the kernel had to
    /// fold the last accept into the terminal CQE.
    #[must_use]
    pub fn into_connection(self) -> Option<Socket> {
        match self {
            Self::Connection(socket) => Some(socket),
            Self::Done(finished) => finished.into_parts().1,
            Self::Empty(_) => None,
        }
    }
}

/// A multishot accept the kernel has stopped delivering for.
///
/// Accepting again means submitting a new [`PreparedAccept`]; this is
/// deliberately not reusable, because the kernel requires a fresh request
/// rather than a re-arm of the old one.
#[derive(Debug)]
pub struct AcceptFinished {
    receipt: Receipt,
    last: Option<Socket>,
}

impl AcceptFinished {
    /// The connection folded into this terminal CQE, if the kernel had to
    /// put one there.
    ///
    /// Normally `None`: a connection and the end of the request are usually
    /// separate CQEs. It is `Some` when the kernel could not post the extra
    /// completion — a full CQ — and finished the request carrying the
    /// descriptor it had already installed. That connection is live, and
    /// closes when it drops.
    #[must_use]
    pub const fn last(&self) -> Option<&Socket> {
        self.last.as_ref()
    }

    /// Raw result of the terminal CQE.
    #[must_use]
    pub const fn raw_result(&self) -> i32 {
        self.receipt.raw_result()
    }

    /// Why the accept ended.
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

    /// Split into the terminal receipt and any final connection.
    ///
    /// Returns both rather than just the receipt: discarding the connection
    /// here would leak a live descriptor, and the type should not make that
    /// the quiet default.
    #[must_use]
    pub fn into_parts(self) -> (Receipt, Option<Socket>) {
        (self.receipt, self.last)
    }
}
