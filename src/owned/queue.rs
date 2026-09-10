//! Split submission/completion halves for owned requests.

use super::buffer::StableBuffer;
use super::identity::{RequestIdSource, RingId};
use super::request::{Pending, Prepared, Receipt};
use crate::error::Error;
use crate::ring::{Completer, IoUring, Submitter};
use crate::types::CqeFlags;

/// The submission half of an owned-request ring.
///
/// Moves to whichever OS thread submits work. Each accepted request yields
/// a [`Pending`] ticket that owns its buffer; the application decides how
/// to get that ticket to the completion thread.
pub struct OwnedSubmitter {
    inner: Submitter,
    ring: RingId,
    ids: RequestIdSource,
}

impl OwnedSubmitter {
    /// Queue an operation, taking ownership of its buffer.
    ///
    /// On success the buffer belongs to the returned ticket and is
    /// unreachable until redeemed. Nothing is sent to the kernel yet —
    /// call [`submit`](Self::submit) to publish.
    ///
    /// # Errors
    ///
    /// If the submission queue is full the request is handed back intact,
    /// still owning its buffer, so the caller can retry after draining.
    pub fn push<B: StableBuffer>(
        &mut self,
        request: Prepared<B>,
    ) -> Result<Pending<B>, (Prepared<B>, Error)> {
        let id = self.ids.next();
        let (sqe, pending) = request.into_pending(self.ring, id);
        match self.inner.push(sqe) {
            Ok(()) => Ok(pending),
            // The SQE never became kernel-visible, so the kernel never saw
            // the pointer and reclaiming the buffer is sound.
            Err(e) => Err((Self::reclaim(pending), e)),
        }
    }

    /// Undo a push that the kernel never observed.
    fn reclaim<B: StableBuffer>(pending: Pending<B>) -> Prepared<B> {
        // SAFETY: only reached when `Submitter::push` reported the queue was
        // full, which happens before the SQE is written or the tail is
        // advanced. No kernel-visible pointer to the buffer exists, so
        // taking ownership back cannot leave the kernel holding a dangling
        // address.
        unsafe { pending.reclaim_unsubmitted() }
    }

    /// Publish queued entries to the kernel.
    ///
    /// # Errors
    ///
    /// Returns the `io_uring_enter` error. Tickets stay valid and owned:
    /// once published, a buffer must not be reclaimed even on error,
    /// because the kernel may already have started the operation.
    pub fn submit(&mut self) -> Result<u32, Error> {
        self.inner.submit()
    }

    /// Publish and wait for at least `min_complete` completions.
    ///
    /// # Errors
    ///
    /// Returns the `io_uring_enter` error.
    pub fn submit_and_wait(&mut self, min_complete: u32) -> Result<u32, Error> {
        self.inner.submit_and_wait(min_complete)
    }

    /// Free submission-queue slots.
    #[must_use]
    pub fn space_left(&self) -> u32 {
        self.inner.sq_space_left()
    }

    /// Identity stamped into every ticket this half produces.
    #[must_use]
    pub const fn ring(&self) -> RingId {
        self.ring
    }

    /// The underlying submitter, for operations outside the owned API.
    #[must_use]
    pub const fn raw(&mut self) -> &mut Submitter {
        &mut self.inner
    }
}

/// The completion half of an owned-request ring.
///
/// Moves to whichever OS thread reaps completions. Turns CQEs into
/// [`Receipt`]s, the only values that can unlock a [`Pending`] ticket.
pub struct OwnedCompleter {
    inner: Completer,
    ring: RingId,
}

impl OwnedCompleter {
    /// Reap one completion as a receipt, if one is ready.
    ///
    /// Non-blocking. Multishot CQEs (`IORING_CQE_F_MORE` set) are not
    /// terminal — the kernel will keep using the buffer — so they are
    /// skipped rather than turned into a receipt that would wrongly
    /// release storage.
    #[must_use]
    pub fn reap(&mut self) -> Option<Receipt> {
        loop {
            let cqe = self.inner.complete()?;
            if cqe.flags.contains(CqeFlags::MORE) {
                continue;
            }
            return Some(Receipt {
                ring: self.ring,
                id: super::identity::RequestId::from_raw(cqe.user_data),
                result: cqe.result,
                flags: cqe.flags,
            });
        }
    }

    /// Block until at least `min_complete` completions are ready.
    ///
    /// # Errors
    ///
    /// Returns the `io_uring_enter` error.
    pub fn wait(&mut self, min_complete: u32) -> Result<(), Error> {
        self.inner.wait(min_complete)
    }

    /// Block, then reap one receipt.
    ///
    /// # Errors
    ///
    /// Returns the `io_uring_enter` error, or
    /// [`CompletionError::NoCompletion`](crate::CompletionError::NoCompletion)
    /// if the wait returned without a terminal completion.
    pub fn wait_one(&mut self) -> Result<Receipt, Error> {
        self.wait(1)?;
        self.reap().ok_or(Error::Completion(
            crate::error::CompletionError::NoCompletion,
        ))
    }

    /// Publish consumed CQ slots back to the kernel.
    pub fn sync(&mut self) {
        self.inner.sync_cq();
    }

    /// Identity this half stamps into receipts.
    #[must_use]
    pub const fn ring(&self) -> RingId {
        self.ring
    }

    /// The underlying completer, for operations outside the owned API.
    #[must_use]
    pub const fn raw(&mut self) -> &mut Completer {
        &mut self.inner
    }
}

impl IoUring {
    /// Split into owned-request halves that are safe to use from two OS
    /// threads.
    ///
    /// Unlike [`split`](IoUring::split), which hands out raw `Sqe`-level
    /// halves, these move buffer ownership into the request tickets, so
    /// submitting I/O needs no `unsafe` and no borrow has to outlive the
    /// call that created it.
    ///
    /// # Errors
    ///
    /// Fails for the same thread-affinity reasons as
    /// [`split`](IoUring::split), returning the ring unchanged.
    pub fn split_owned(self) -> Result<(OwnedSubmitter, OwnedCompleter), (Self, Error)> {
        let ring = RingId::next();
        let (submitter, completer) = self.split()?;
        Ok((
            OwnedSubmitter {
                inner: submitter,
                ring,
                ids: RequestIdSource::new(),
            },
            OwnedCompleter {
                inner: completer,
                ring,
            },
        ))
    }
}
