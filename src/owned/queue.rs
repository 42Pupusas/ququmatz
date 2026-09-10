//! Split submission/completion halves for owned requests.

use super::accept::{MultishotAccept, PreparedAccept};
use super::buffer::{StableBuffer, StableBufferMut};
use super::direct::{PendingDirectOpen, PreparedDirectOpen};
use super::direct_accept::{DirectAccept, PreparedDirectAccept};
use super::direct_socket::{PendingDirectSocket, PreparedDirectSocket};
use super::event::{Event, PartialReceipt};
use super::identity::{RequestIdSource, RingId};
use super::multishot::{MultishotRecv, PreparedMultishot};
use super::open::{PendingOpen, PreparedOpen};
use super::pathop::{PendingPathOp, PreparedPathOp};
use super::rename::{PendingRename, PreparedRename};
use super::request::{Pending, Prepared, Receipt};
use super::statx::{PendingStatx, PreparedStatx};
use super::vectored::{PendingVectored, PreparedVectored};
use super::zerocopy::{PendingZc, PreparedZc};
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

    /// Queue a zero-copy send, taking ownership of its buffer.
    ///
    /// The returned ticket holds the buffer until the *terminal*
    /// completion, which for `send_zc` is normally the notification rather
    /// than the send result — see [`PendingZc`].
    ///
    /// # Errors
    ///
    /// If the submission queue is full the request is handed back intact,
    /// still owning its buffer.
    pub fn push_zc<B: StableBuffer>(
        &mut self,
        request: PreparedZc<B>,
    ) -> Result<PendingZc<B>, (PreparedZc<B>, Error)> {
        let id = self.ids.next();
        let (sqe, pending) = request.into_pending(self.ring, id);
        match self.inner.push(sqe) {
            Ok(()) => Ok(pending),
            Err(e) => Err((Self::reclaim_zc(pending), e)),
        }
    }

    /// Arm a multishot receive against a registered buffer pool.
    ///
    /// Unlike [`push`](Self::push) this transfers no buffer: the kernel
    /// draws one from the pool per arrival, and the completion thread
    /// recycles them. The returned ticket stays valid across many
    /// completions until one reports
    /// [`Armed::Finished`](super::Armed::Finished).
    ///
    /// # Errors
    ///
    /// If the submission queue is full the request is handed back intact.
    pub fn push_multishot(
        &mut self,
        request: PreparedMultishot,
    ) -> Result<MultishotRecv, (PreparedMultishot, Error)> {
        let id = self.ids.next();
        let (sqe, pending) = request.into_pending(self.ring, id);
        match self.inner.push(sqe) {
            Ok(()) => Ok(pending),
            // The request owns no buffer, so handing back the copy taken
            // before submission returns it exactly as it arrived.
            Err(e) => Err((request, e)),
        }
    }

    /// Queue a multishot accept on a listening socket.
    ///
    /// One armed request yields a CQE per connection. Each accepted
    /// descriptor is owned by the caller from the moment it is read, so
    /// drain the completions or the process runs out of descriptors.
    ///
    /// # Errors
    ///
    /// If the submission queue is full the request is handed back intact.
    pub fn push_accept(
        &mut self,
        request: PreparedAccept,
    ) -> Result<MultishotAccept, (PreparedAccept, Error)> {
        let id = self.ids.next();
        let (sqe, pending) = request.into_pending(self.ring, id);
        match self.inner.push(sqe) {
            Ok(()) => Ok(pending),
            // The request owns nothing, so handing back the copy taken
            // before submission returns it exactly as it arrived.
            Err(e) => Err((request, e)),
        }
    }

    /// Queue a direct multishot accept on a listening socket.
    ///
    /// Each connection is installed into a kernel-chosen slot of the ring's
    /// registered file table, so a table must be registered first. Nothing
    /// enters this process's descriptor table.
    ///
    /// # Errors
    ///
    /// If the submission queue is full the request is handed back intact.
    pub fn push_direct_accept(
        &mut self,
        request: PreparedDirectAccept,
    ) -> Result<DirectAccept, (PreparedDirectAccept, Error)> {
        let id = self.ids.next();
        let (sqe, pending) = request.into_pending(self.ring, id);
        match self.inner.push(sqe) {
            Ok(()) => Ok(pending),
            // The request owns nothing, so handing back the copy taken
            // before submission returns it exactly as it arrived.
            Err(e) => Err((request, e)),
        }
    }

    /// Queue a socket creation that installs into the ring's file table.
    ///
    /// The completion yields a [`DirectSlot`](super::DirectSlot) rather
    /// than a descriptor, so a file table must be registered first.
    ///
    /// An explicit [`SlotTarget::Exact`](super::SlotTarget::Exact) closes
    /// whatever file already occupies the slot, reporting the same success
    /// as an install into a free one.
    ///
    /// # Errors
    ///
    /// If the submission queue is full the request is handed back intact.
    pub fn push_direct_socket(
        &mut self,
        request: PreparedDirectSocket,
    ) -> Result<PendingDirectSocket, (PreparedDirectSocket, Error)> {
        let id = self.ids.next();
        let (sqe, pending) = request.into_pending(self.ring, id);
        match self.inner.push(sqe) {
            Ok(()) => Ok(pending),
            // The request owns nothing, so handing back the copy taken
            // before submission returns it exactly as it arrived.
            Err(e) => Err((request, e)),
        }
    }

    /// Queue a vectored operation, taking ownership of every buffer and of
    /// the descriptor array naming them.
    ///
    /// # Errors
    ///
    /// If the submission queue is full the request is handed back intact,
    /// still owning all of its storage.
    pub fn push_vectored<B: StableBuffer, V: StableBufferMut, const N: usize>(
        &mut self,
        request: PreparedVectored<B, V, N>,
    ) -> Result<PendingVectored<B, V, N>, (PreparedVectored<B, V, N>, Error)> {
        let id = self.ids.next();
        let (sqe, pending) = request.into_pending(self.ring, id);
        match self.inner.push(sqe) {
            Ok(()) => Ok(pending),
            // The SQE never became kernel-visible, so no pointer to the
            // buffers or to the descriptor array ever reached the kernel.
            Err(e) => Err((Self::reclaim_vectored(pending), e)),
        }
    }

    /// Queue an open, taking ownership of its path storage.
    ///
    /// The completion carries a descriptor as well as the storage, so
    /// redeem the ticket even if the path is not wanted back: dropping it
    /// unredeemed leaks an open file descriptor.
    ///
    /// # Errors
    ///
    /// If the submission queue is full the request is handed back intact,
    /// still owning its path storage.
    pub fn push_open<S: StableBuffer>(
        &mut self,
        request: PreparedOpen<S>,
    ) -> Result<PendingOpen<S>, (PreparedOpen<S>, Error)> {
        let id = self.ids.next();
        let (sqe, pending) = request.into_pending(self.ring, id);
        match self.inner.push(sqe) {
            Ok(()) => Ok(pending),
            // The SQE never became kernel-visible, so the kernel never saw
            // the path pointer and reclaiming the storage is sound.
            Err(e) => Err((Self::reclaim_open(pending), e)),
        }
    }

    /// Queue a direct open, taking ownership of its path storage.
    ///
    /// Unlike [`push_open`](Self::push_open) the completion yields a
    /// [`DirectSlot`](super::DirectSlot) rather than a descriptor: the file
    /// is installed into this ring's registered file table and never enters
    /// the process's descriptor table at all.
    ///
    /// # Errors
    ///
    /// If the submission queue is full the request is handed back intact,
    /// still owning its path storage.
    pub fn push_direct_open<S: StableBuffer>(
        &mut self,
        request: PreparedDirectOpen<S>,
    ) -> Result<PendingDirectOpen<S>, (PreparedDirectOpen<S>, Error)> {
        let id = self.ids.next();
        let (sqe, pending) = request.into_pending(self.ring, id);
        match self.inner.push(sqe) {
            Ok(()) => Ok(pending),
            // The SQE never became kernel-visible, so the kernel never saw
            // the path pointer and reclaiming the storage is sound.
            Err(e) => Err((Self::reclaim_direct_open(pending), e)),
        }
    }

    /// Queue an `unlinkat` or `mkdirat`, taking ownership of its path.
    ///
    /// The completion carries no resource — only whether it worked — so
    /// an abandoned ticket leaks the path storage and nothing else.
    ///
    /// # Errors
    ///
    /// If the submission queue is full the request is handed back intact,
    /// still owning its path storage.
    pub fn push_path_op<S: StableBuffer>(
        &mut self,
        request: PreparedPathOp<S>,
    ) -> Result<PendingPathOp<S>, (PreparedPathOp<S>, Error)> {
        let id = self.ids.next();
        let (sqe, pending) = request.into_pending(self.ring, id);
        match self.inner.push(sqe) {
            Ok(()) => Ok(pending),
            // The SQE never became kernel-visible, so the kernel never saw
            // the path pointer and reclaiming the storage is sound.
            Err(e) => Err((Self::reclaim_path_op(pending), e)),
        }
    }

    /// Queue a rename, taking ownership of both path storages.
    ///
    /// A [`RenameMode::Replace`](super::RenameMode::Replace) overwrites an
    /// existing destination and reports the same success as a rename onto
    /// a free name, so the mode is chosen explicitly.
    ///
    /// # Errors
    ///
    /// If the submission queue is full the request is handed back intact,
    /// still owning both path storages.
    pub fn push_rename<F: StableBuffer, T: StableBuffer>(
        &mut self,
        request: PreparedRename<F, T>,
    ) -> Result<PendingRename<F, T>, (PreparedRename<F, T>, Error)> {
        let id = self.ids.next();
        let (sqe, pending) = request.into_pending(self.ring, id);
        match self.inner.push(sqe) {
            Ok(()) => Ok(pending),
            // The SQE never became kernel-visible, so the kernel never saw
            // either path pointer and reclaiming both storages is sound.
            Err(e) => Err((Self::reclaim_rename(pending), e)),
        }
    }

    /// Queue a `statx`, taking ownership of its path and destination.
    ///
    /// The kernel writes a fixed-size struct into the destination after
    /// submission, so the storage is owned by the ticket until redeemed.
    ///
    /// # Errors
    ///
    /// If the submission queue is full the request is handed back intact,
    /// still owning both storages.
    pub fn push_statx<S: StableBuffer, D: StableBufferMut>(
        &mut self,
        request: PreparedStatx<S, D>,
    ) -> Result<PendingStatx<S, D>, (PreparedStatx<S, D>, Error)> {
        let id = self.ids.next();
        let (sqe, pending) = request.into_pending(self.ring, id);
        match self.inner.push(sqe) {
            Ok(()) => Ok(pending),
            // The SQE never became kernel-visible, so the kernel never saw
            // either pointer and reclaiming both storages is sound.
            Err(e) => Err((Self::reclaim_statx(pending), e)),
        }
    }

    /// Undo a `statx` push that the kernel never observed.
    fn reclaim_statx<S: StableBuffer, D: StableBufferMut>(
        pending: PendingStatx<S, D>,
    ) -> PreparedStatx<S, D> {
        // SAFETY: only reached when `Submitter::push` reported the queue was
        // full, which happens before the SQE is written or the tail is
        // advanced. No kernel-visible pointer to either storage exists.
        unsafe { pending.reclaim_unsubmitted() }
    }

    /// Undo a single-path push that the kernel never observed.
    fn reclaim_path_op<S: StableBuffer>(pending: PendingPathOp<S>) -> PreparedPathOp<S> {
        // SAFETY: only reached when `Submitter::push` reported the queue was
        // full, which happens before the SQE is written or the tail is
        // advanced. No kernel-visible pointer to the path exists.
        unsafe { pending.reclaim_unsubmitted() }
    }

    /// Undo a rename push that the kernel never observed.
    fn reclaim_rename<F: StableBuffer, T: StableBuffer>(
        pending: PendingRename<F, T>,
    ) -> PreparedRename<F, T> {
        // SAFETY: only reached when `Submitter::push` reported the queue was
        // full, which happens before the SQE is written or the tail is
        // advanced. No kernel-visible pointer to either path exists.
        unsafe { pending.reclaim_unsubmitted() }
    }

    /// Undo a direct-open push that the kernel never observed.
    fn reclaim_direct_open<S: StableBuffer>(
        pending: PendingDirectOpen<S>,
    ) -> PreparedDirectOpen<S> {
        // SAFETY: only reached when `Submitter::push` reported the queue was
        // full, which happens before the SQE is written or the tail is
        // advanced. No kernel-visible pointer to the path exists.
        unsafe { pending.reclaim_unsubmitted() }
    }

    /// Undo an open push that the kernel never observed.
    fn reclaim_open<S: StableBuffer>(pending: PendingOpen<S>) -> PreparedOpen<S> {
        // SAFETY: only reached when `Submitter::push` reported the queue was
        // full, which happens before the SQE is written or the tail is
        // advanced. No kernel-visible pointer to the path exists.
        unsafe { pending.reclaim_unsubmitted() }
    }

    /// Undo a vectored push that the kernel never observed.
    fn reclaim_vectored<B, V, const N: usize>(
        pending: PendingVectored<B, V, N>,
    ) -> PreparedVectored<B, V, N> {
        // SAFETY: only reached when `Submitter::push` reported the queue was
        // full, which happens before the SQE is written or the tail is
        // advanced. No kernel-visible pointer to the storage exists.
        unsafe { pending.reclaim_unsubmitted() }
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

    /// Undo a zero-copy push that the kernel never observed.
    fn reclaim_zc<B: StableBuffer>(pending: PendingZc<B>) -> PreparedZc<B> {
        // SAFETY: only reached when `Submitter::push` reported the queue was
        // full, which happens before the SQE is written or the tail is
        // advanced. No kernel-visible pointer to the buffer exists.
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
    /// Reap one terminal completion as a receipt, if one is ready.
    ///
    /// Non-blocking. Non-terminal CQEs (`IORING_CQE_F_MORE` set) cannot
    /// release storage, so they are skipped rather than turned into a
    /// receipt that would wrongly free it.
    ///
    /// # Discards non-terminal completions
    ///
    /// Skipping is lossy, and for two kinds of request it loses something
    /// that matters:
    ///
    /// - a zero-copy send's result CQE carries the byte count, so only the
    ///   notification survives;
    /// - a multishot arrival carries a **pool buffer id**, and dropping it
    ///   means that buffer is never recycled — the pool drains and the
    ///   multishot stalls on `ENOBUFS`.
    ///
    /// Rings that submit [`push_zc`](OwnedSubmitter::push_zc) or multishot
    /// work must use [`reap_event`](Self::reap_event), which reports both
    /// kinds. This method suits rings whose requests all finish in one CQE.
    #[must_use]
    pub fn reap(&mut self) -> Option<Receipt> {
        loop {
            match self.reap_event()? {
                Event::Complete(receipt) => return Some(receipt),
                Event::Partial(_) => {}
            }
        }
    }

    /// Reap one completion, reporting whether it releases anything.
    ///
    /// Non-blocking. A CQE with `IORING_CQE_F_MORE` promises more
    /// completions for the same request, so it cannot release storage; it
    /// becomes [`Event::Partial`], which no API accepts where a release is
    /// required. Everything else is terminal and becomes
    /// [`Event::Complete`].
    ///
    /// Reading the kernel's flag rather than counting completions is what
    /// makes both `send_zc` and multishot safe to expose: a zero-copy send
    /// that promises no notification is terminal on the spot, and a
    /// multishot that has stopped re-arming is recognised as finished
    /// rather than waited on forever.
    ///
    /// The CQE's flags are preserved on both variants, so a non-terminal
    /// arrival's chosen buffer id survives to be recycled.
    #[must_use]
    pub fn reap_event(&mut self) -> Option<Event> {
        let cqe = self.inner.complete()?;
        let id = super::identity::RequestId::from_raw(cqe.user_data);
        if cqe.flags.contains(CqeFlags::MORE) {
            return Some(Event::Partial(PartialReceipt {
                ring: self.ring,
                id,
                result: cqe.result,
                flags: cqe.flags,
            }));
        }
        Some(Event::Complete(Receipt {
            ring: self.ring,
            id,
            result: cqe.result,
            flags: cqe.flags,
        }))
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
