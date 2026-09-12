//! Shared plumbing for owned requests that stage one socket address.
//!
//! `bind` and `connect` hand the kernel a [`SockAddrIn`] at one SQE field
//! and its length at another, and both need the identical
//! storage-ownership story: measured on a live ring, the kernel copies the
//! address during `io_uring_enter`, but [`split_owned`](super::queue)
//! accepts an SQPOLL ring where the submitting thread never enters the
//! kernel at all, so no call's return proves the copy has happened. The
//! storage is therefore owned until the completion rather than borrowed,
//! and every other piece of the state machine — publish-before-submit,
//! authenticated redemption, leak-on-drop — is the same for both requests
//! too.
//!
//! This module holds that machinery exactly once. `bind.rs` and
//! `connect.rs` supply only their [`AddrOp`] impl — the SQE builder and
//! the outcome a raw result decodes to — plus their own outcome and error
//! enums, which carry the domain-specific meaning callers match on.

use core::marker::PhantomData;
use core::mem::{ManuallyDrop, size_of};

use super::buffer::StableBufferMut;
use super::identity::{RequestId, RingId};
use super::request::Receipt;
use crate::op::Sqe;
use crate::types::{RawFd, SockAddrIn};

/// Bytes of socket address the kernel is given.
pub(super) const ADDR_LEN: usize = size_of::<SockAddrIn>();

/// The same length in the width the SQE carries it in.
///
/// Built from the `u32` side so there is no narrowing cast to justify;
/// the assertion pins it to the real struct rather than to a literal that
/// could drift away from it.
pub(super) const ADDR_LEN_U32: u32 = 16;
const _: () = assert!(ADDR_LEN_U32 as usize == ADDR_LEN);

/// What one address-staging request supplies around the shared storage,
/// matching, and redemption machinery below.
pub(super) trait AddrOp {
    /// How the request ended, once redeemed.
    type Outcome;
    /// Why the request could not be built.
    type Error;

    /// Build the error for storage too small to hold a socket address.
    fn too_small(needed: usize, got: usize) -> Self::Error;

    /// Build the SQE naming `fd` and the published address at `addr`.
    ///
    /// # Safety
    ///
    /// `addr` must point to `len` live, exclusively owned bytes that
    /// outlive the kernel's access to the SQE this produces.
    unsafe fn build_sqe(fd: RawFd, addr: *const u8, len: u32) -> Sqe;

    /// Classify a raw CQE result into this operation's outcome.
    fn classify(result: i32) -> Self::Outcome;
}

/// An address-staging request that owns its storage, not yet queued.
pub(super) struct StagedPrepared<S, Op> {
    store: S,
    fd: RawFd,
    addr: SockAddrIn,
    /// Address of the published bytes, cached where the stability bound is
    /// in scope and checked for size before it was formed.
    staged: *mut u8,
    _op: PhantomData<Op>,
}

// SAFETY: the pointer refers into storage this struct exclusively owns, so
// it stays valid wherever the value goes. The struct adds no thread
// affinity of its own, leaving `S` to decide. `Op` is a zero-sized marker
// carried only in `PhantomData`.
unsafe impl<S: Send, Op> Send for StagedPrepared<S, Op> {}

impl<S: StableBufferMut, Op: AddrOp> StagedPrepared<S, Op> {
    /// Prepare a request naming `fd` and `addr`.
    ///
    /// Takes ownership of `store`, which the kernel reads the address from
    /// after submission, so no caller alias to it may survive.
    pub(super) fn new(fd: RawFd, addr: SockAddrIn, mut store: S) -> Result<Self, (S, Op::Error)> {
        let got = store.stable_len();
        if got < ADDR_LEN {
            return Err((store, Op::too_small(ADDR_LEN, got)));
        }
        let staged = store.stable_mut_ptr();
        let mut prepared = Self {
            store,
            fd,
            addr,
            staged,
            _op: PhantomData,
        };
        prepared.publish();
        Ok(prepared)
    }
}

impl<S, Op> StagedPrepared<S, Op> {
    /// Write the address into the storage the kernel will read.
    ///
    /// Done at construction so the bytes are in place before any SQE can
    /// name them. The address is staged as bytes rather than as a struct,
    /// which is why this needs no alignment check: the kernel copies it
    /// bytewise, and so does this.
    fn publish(&mut self) {
        let bytes = self.addr.to_bytes();
        // SAFETY: `staged` points into storage this request owns
        // exclusively and was checked to hold at least `ADDR_LEN` bytes,
        // so the copy stays in bounds and nothing else can observe it. No
        // SQE naming it exists yet, so the kernel is not reading
        // concurrently.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), self.staged, ADDR_LEN) }
    }

    /// The descriptor this request acts on.
    #[must_use]
    pub(super) const fn fd(&self) -> RawFd {
        self.fd
    }

    /// The address named at construction.
    #[must_use]
    pub(super) const fn addr(&self) -> SockAddrIn {
        self.addr
    }

    /// The address bytes exactly as the kernel will read them.
    ///
    /// Reads back the published storage rather than rebuilding it, so it
    /// shows what was actually written.
    #[must_use]
    pub(super) const fn published(&self) -> [u8; ADDR_LEN] {
        let mut out = [0u8; ADDR_LEN];
        // SAFETY: `staged` points into storage this request owns and was
        // written by `publish` at construction, so `ADDR_LEN` initialised
        // bytes are readable there.
        unsafe { core::ptr::copy_nonoverlapping(self.staged, out.as_mut_ptr(), ADDR_LEN) }
        out
    }

    /// Give the storage back, abandoning the request.
    #[must_use]
    pub(super) fn into_store(self) -> S {
        self.store
    }
}

impl<S, Op: AddrOp> StagedPrepared<S, Op> {
    /// Build the SQE and move to the pending state.
    pub(super) fn into_pending(self, ring: RingId, id: RequestId) -> (Sqe, StagedPending<S, Op>) {
        // SAFETY: `staged` was checked to hold a whole socket address,
        // written by `publish`, and points into storage this request owns
        // exclusively. The storage moves into `StagedPending`, whose
        // destructor is suppressed unless a receipt proves the kernel
        // finished.
        let sqe = unsafe { Op::build_sqe(self.fd, self.staged.cast_const(), ADDR_LEN_U32) };
        let pending = StagedPending {
            store: ManuallyDrop::new(self.store),
            ring,
            id,
            fd: self.fd,
            addr: self.addr,
            staged: self.staged,
            _op: PhantomData,
        };
        (sqe.user_data(id.raw()), pending)
    }
}

/// A submitted address-staging request whose storage the kernel may be
/// reading.
///
/// # Drop and `forget` both leak rather than free
///
/// Dropping this runs no destructor for the storage. Under SQPOLL the
/// submitting thread never enters the kernel, so nothing here can prove
/// the address has been read, and the storage leaks on purpose — the same
/// failure mode as every other in-flight ticket.
///
/// No descriptor goes with it: both requests this backs borrow their
/// descriptor rather than taking it, so only the storage is at stake.
#[must_use = "dropping the ticket leaks the address storage"]
pub(super) struct StagedPending<S, Op> {
    store: ManuallyDrop<S>,
    ring: RingId,
    id: RequestId,
    fd: RawFd,
    addr: SockAddrIn,
    staged: *mut u8,
    _op: PhantomData<Op>,
}

// SAFETY: the pointer refers into storage this ticket exclusively owns and
// keeps alive at a fixed address, so moving the ticket to another thread
// keeps it valid; `S` decides whether that move is allowed.
unsafe impl<S: Send, Op> Send for StagedPending<S, Op> {}

impl<S, Op: AddrOp> StagedPending<S, Op> {
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

    /// The address named at construction.
    #[must_use]
    pub(super) const fn addr(&self) -> SockAddrIn {
        self.addr
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
    pub(super) unsafe fn reclaim_unsubmitted(self) -> StagedPrepared<S, Op> {
        let mut this = ManuallyDrop::new(self);
        // SAFETY: `this` is wrapped in `ManuallyDrop` so the no-op `Drop`
        // cannot observe the moved-out field. The caller guarantees no
        // kernel-visible pointer to the storage exists.
        let store = unsafe { ManuallyDrop::take(&mut this.store) };
        StagedPrepared {
            store,
            fd: this.fd,
            addr: this.addr,
            staged: this.staged,
            _op: PhantomData,
        }
    }

    /// Trade a matching receipt for the outcome and the storage.
    ///
    /// # Errors
    ///
    /// Returns the ticket and receipt unchanged if the receipt belongs to
    /// another request or another ring.
    pub(super) fn redeem(self, receipt: Receipt) -> Result<StagedDone<S, Op>, (Self, Receipt)> {
        if !self.matches(&receipt) {
            return Err((self, receipt));
        }
        let mut this = ManuallyDrop::new(self);
        // SAFETY: `this` is wrapped in `ManuallyDrop`, so `Drop` will not
        // run and cannot observe the moved-out field. The receipt proves
        // the kernel finished with these bytes.
        let store = unsafe { ManuallyDrop::take(&mut this.store) };
        Ok(StagedDone {
            store,
            addr: this.addr,
            id: this.id,
            result: receipt.raw_result(),
            _op: PhantomData,
        })
    }
}

impl<S, Op> Drop for StagedPending<S, Op> {
    fn drop(&mut self) {
        // Intentionally no `ManuallyDrop::drop`. See the type docs: the
        // kernel may still be reading the address, so the storage leaks
        // rather than being freed underneath an in-flight request.
    }
}

/// A finished address-staging request: how it ended, and the storage back.
pub(super) struct StagedDone<S, Op> {
    store: S,
    addr: SockAddrIn,
    id: RequestId,
    result: i32,
    _op: PhantomData<Op>,
}

impl<S, Op: AddrOp> StagedDone<S, Op> {
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

    /// The address named at construction.
    #[must_use]
    pub(super) const fn addr(&self) -> SockAddrIn {
        self.addr
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
