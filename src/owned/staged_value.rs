//! Shared plumbing for owned requests that stage one fixed-size, aligned
//! value — as opposed to [`staged_addr`](super::staged_addr), which stages
//! a socket address read bytewise and needs no alignment check.
//!
//! `timeout` and `epoll_ctl` each hand the kernel one small `Copy` struct
//! at a pointer the SQE carries — a [`Timespec`](crate::types::Timespec)
//! or an [`EpollEvent`](crate::types::EpollEvent) — and both need the
//! identical storage-ownership story: measured on a live ring, the kernel
//! copies the struct during `io_uring_enter`, but
//! [`split_owned`](super::queue) accepts an SQPOLL ring where the
//! submitting thread never enters the kernel at all, so no call's return
//! proves the copy has happened. The storage is therefore owned until the
//! completion rather than borrowed, and every other piece of the state
//! machine — size and alignment checked once, publish-before-submit,
//! authenticated redemption, leak-on-drop — is the same for both requests
//! too.
//!
//! This module holds that machinery exactly once. `timeout.rs` and
//! `epoll.rs` supply only their [`ValueOp`] impl — the value to publish,
//! the SQE builder, and what of the request's own fields survives to the
//! completed state — plus their own outcome and error enums, which carry
//! the domain-specific meaning callers match on.

use core::marker::PhantomData;
use core::mem::{ManuallyDrop, align_of, size_of};

use super::buffer::StableBufferMut;
use super::identity::{RequestId, RingId};
use super::request::Receipt;
use crate::op::Sqe;

/// What one value-staging request supplies around the shared storage,
/// matching, and redemption machinery below.
pub(super) trait ValueOp {
    /// The request's own fields, needed for as long as the request is
    /// live: enough to build the SQE and to answer accessors before
    /// completion.
    type Context: Copy;
    /// The subset of [`Context`](Self::Context) worth keeping once the
    /// storage and descriptors are no longer at stake.
    type Info: Copy;
    /// The fixed-size, `Copy` struct published into the caller's storage.
    type Value: Copy;
    /// How the request ended, once redeemed.
    type Outcome;
    /// Why the request could not be built.
    type Error;

    /// Build the error for storage too small to hold [`Value`](Self::Value).
    fn too_small(needed: usize, got: usize) -> Self::Error;

    /// Build the error for storage misaligned for [`Value`](Self::Value).
    fn misaligned(needed: usize) -> Self::Error;

    /// The value to publish for this context.
    fn value(ctx: &Self::Context) -> Self::Value;

    /// Build the SQE naming `ctx` and the published value at `addr`.
    ///
    /// # Safety
    ///
    /// `addr` must point to one live, exclusively owned, properly aligned
    /// [`Value`](Self::Value) that outlives the kernel's access to the SQE
    /// this produces.
    unsafe fn build_sqe(ctx: &Self::Context, addr: *const Self::Value) -> Sqe;

    /// The part of `ctx` worth keeping once the request completes.
    fn info(ctx: &Self::Context) -> Self::Info;

    /// Classify a raw CQE result into this operation's outcome.
    fn classify(result: i32) -> Self::Outcome;
}

/// A value-staging request that owns its storage, not yet queued.
pub(super) struct ValuePrepared<S, Op: ValueOp> {
    store: S,
    ctx: Op::Context,
    /// Address of the published value, cached where the stability bound is
    /// in scope and checked for size and alignment before it was formed.
    addr: *mut Op::Value,
}

// SAFETY: the pointer refers into storage this struct exclusively owns, so
// it stays valid wherever the value goes. The struct adds no thread
// affinity of its own, leaving `S` to decide. `Op::Context` is required
// `Copy`, which this crate uses only for plain data with no thread
// affinity of its own.
unsafe impl<S: Send, Op: ValueOp> Send for ValuePrepared<S, Op> {}

impl<S: StableBufferMut, Op: ValueOp> ValuePrepared<S, Op> {
    /// Prepare a request holding `ctx`, publishing its value into `store`.
    ///
    /// Takes ownership of `store`, which the kernel reads the value from
    /// after submission, so no caller alias to it may survive.
    pub(super) fn new(ctx: Op::Context, mut store: S) -> Result<Self, (S, Op::Error)> {
        let needed = size_of::<Op::Value>();
        let got = store.stable_len();
        if got < needed {
            return Err((store, Op::too_small(needed, got)));
        }
        let base = store.stable_mut_ptr();
        let align = align_of::<Op::Value>();
        // Checked on the address rather than by casting first: the cast is
        // only sound once this has passed.
        if !base.addr().is_multiple_of(align) {
            return Err((store, Op::misaligned(align)));
        }
        // The alignment check above is what makes this cast well-defined.
        #[allow(clippy::cast_ptr_alignment)]
        let addr = base.cast::<Op::Value>();
        let mut prepared = Self { store, ctx, addr };
        prepared.publish();
        Ok(prepared)
    }
}

impl<S, Op: ValueOp> ValuePrepared<S, Op> {
    /// Write the value into the storage the kernel will read.
    ///
    /// Done at construction so the bytes are in place before any SQE can
    /// name them.
    fn publish(&mut self) {
        // SAFETY: `addr` was checked for size and alignment against
        // `Op::Value` and points into storage this request owns
        // exclusively, so nothing else can observe the write. No SQE
        // naming it exists yet, so the kernel is not reading concurrently.
        unsafe { self.addr.write(Op::value(&self.ctx)) }
    }

    /// The request's own fields.
    #[must_use]
    pub(super) const fn ctx(&self) -> &Op::Context {
        &self.ctx
    }

    /// The value exactly as the kernel will read it.
    ///
    /// Reads back the published storage rather than rebuilding it, so it
    /// shows what was actually written.
    #[must_use]
    pub(super) const fn published(&self) -> Op::Value {
        // SAFETY: `addr` points into storage this request owns and was
        // written by `publish` at construction, so it holds an initialised
        // `Op::Value` at a properly aligned address.
        unsafe { self.addr.read() }
    }

    /// Give the storage back, abandoning the request.
    #[must_use]
    pub(super) fn into_store(self) -> S {
        self.store
    }

    /// Build the SQE and move to the pending state.
    pub(super) fn into_pending(self, ring: RingId, id: RequestId) -> (Sqe, ValuePending<S, Op>) {
        // SAFETY: `addr` was checked for size and alignment against
        // `Op::Value`, written by `publish`, and points into storage this
        // request owns exclusively. The storage moves into
        // `ValuePending`, whose destructor is suppressed unless a
        // receipt proves the kernel finished.
        let sqe = unsafe { Op::build_sqe(&self.ctx, self.addr.cast_const()) };
        let pending = ValuePending {
            store: ManuallyDrop::new(self.store),
            ring,
            id,
            ctx: self.ctx,
            addr: self.addr,
        };
        (sqe.user_data(id.raw()), pending)
    }
}

/// A submitted value-staging request whose storage the kernel may be
/// reading.
///
/// # Drop and `forget` both leak rather than free
///
/// Dropping this runs no destructor for the storage. Under SQPOLL the
/// submitting thread never enters the kernel, so nothing here can prove
/// the value has been read, and the storage leaks on purpose — the same
/// failure mode as every other in-flight ticket.
#[must_use = "dropping the ticket leaks the value storage"]
pub(super) struct ValuePending<S, Op: ValueOp> {
    store: ManuallyDrop<S>,
    ring: RingId,
    id: RequestId,
    ctx: Op::Context,
    addr: *mut Op::Value,
}

// SAFETY: the pointer refers into storage this ticket exclusively owns and
// keeps alive at a fixed address, so moving the ticket to another thread
// keeps it valid; `S` decides whether that move is allowed.
unsafe impl<S: Send, Op: ValueOp> Send for ValuePending<S, Op> {}

impl<S, Op: ValueOp> ValuePending<S, Op> {
    /// Identity the kernel echoes back in this request's CQE.
    #[must_use]
    pub(super) const fn id(&self) -> RequestId {
        self.id
    }

    /// Identity of the queue that accepted this request.
    #[must_use]
    pub(super) const fn ring(&self) -> RingId {
        self.ring
    }

    /// The request's own fields.
    #[must_use]
    pub(super) const fn ctx(&self) -> &Op::Context {
        &self.ctx
    }

    /// Whether `receipt` authenticates this exact request.
    #[must_use]
    pub(super) const fn matches(&self, receipt: &Receipt) -> bool {
        receipt.id().raw() == self.id.raw() && receipt.ring().raw() == self.ring.raw()
    }

    /// Take the storage back without a receipt, undoing a failed push.
    ///
    /// # Safety
    ///
    /// The kernel must never have seen this request's SQE. Calling this
    /// after publication hands back storage the kernel may still read.
    pub(super) unsafe fn reclaim_unsubmitted(self) -> ValuePrepared<S, Op> {
        let mut this = ManuallyDrop::new(self);
        // SAFETY: `this` is wrapped in `ManuallyDrop` so the no-op `Drop`
        // cannot observe the moved-out field. The caller guarantees no
        // kernel-visible pointer to the storage exists.
        let store = unsafe { ManuallyDrop::take(&mut this.store) };
        ValuePrepared {
            store,
            ctx: this.ctx,
            addr: this.addr,
        }
    }

    /// Trade a matching receipt for the outcome and the storage.
    ///
    /// # Errors
    ///
    /// Returns the ticket and receipt unchanged if the receipt belongs to
    /// another request or another ring.
    pub(super) fn redeem(self, receipt: Receipt) -> Result<ValueDone<S, Op>, (Self, Receipt)> {
        if !self.matches(&receipt) {
            return Err((self, receipt));
        }
        let mut this = ManuallyDrop::new(self);
        // SAFETY: `this` is wrapped in `ManuallyDrop`, so `Drop` will not
        // run and cannot observe the moved-out field. The receipt proves
        // the kernel finished with these bytes.
        let store = unsafe { ManuallyDrop::take(&mut this.store) };
        Ok(ValueDone {
            store,
            info: Op::info(&this.ctx),
            id: this.id,
            result: receipt.raw_result(),
            _op: PhantomData,
        })
    }
}

impl<S, Op: ValueOp> Drop for ValuePending<S, Op> {
    fn drop(&mut self) {
        // Intentionally no `ManuallyDrop::drop`. See the type docs: the
        // kernel may still be reading the value, so the storage leaks
        // rather than being freed underneath an in-flight request.
    }
}

/// A finished value-staging request: how it ended, and the storage back.
pub(super) struct ValueDone<S, Op: ValueOp> {
    store: S,
    info: Op::Info,
    id: RequestId,
    result: i32,
    _op: PhantomData<Op>,
}

impl<S, Op: ValueOp> ValueDone<S, Op> {
    /// Identity of the request this completes.
    #[must_use]
    pub(super) const fn id(&self) -> RequestId {
        self.id
    }

    /// Raw CQE result: `0` on success, `-errno` otherwise.
    #[must_use]
    pub(super) const fn raw_result(&self) -> i32 {
        self.result
    }

    /// How the request ended.
    #[must_use]
    pub(super) fn outcome(&self) -> Op::Outcome {
        Op::classify(self.result)
    }

    /// The part of the request's own fields kept past completion.
    #[must_use]
    pub(super) const fn info(&self) -> &Op::Info {
        &self.info
    }

    /// Take the storage back for reuse.
    #[must_use]
    pub(super) fn into_store(self) -> S {
        self.store
    }

    /// Take the outcome and the storage together.
    #[must_use]
    pub(super) fn into_parts(self) -> (Op::Outcome, S) {
        (self.outcome(), self.store)
    }
}
