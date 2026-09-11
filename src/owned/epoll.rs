//! `epoll_ctl`, where one of the three operations reads nothing.
//!
//! The kernel is handed an `epoll_event` at `addr` and an operation in
//! `len`. For `Add` and `Mod` it reads the struct to learn the mask and
//! the user data; for `Del` it does not read it at all — a `Del` with a
//! **null** pointer returns `0` against a real kernel, which is how that
//! was established rather than assumed.
//!
//! [`EpollChange`] is shaped around that difference: the event is carried
//! by the two variants that use it and absent from the one that does not,
//! so a `Del` cannot be given a mask that would be silently discarded, and
//! an `Add` cannot omit one.
//!
//! # Storage is owned for the same reason a timeout's is
//!
//! The struct is small and fixed-size, and the kernel copies it while
//! servicing the request rather than keeping it. That is not enough to
//! make a borrow safe: [`split_owned`](crate::IoUring::split_owned)
//! accepts an SQPOLL ring, where the submitting thread never enters the
//! kernel and the SQ thread reads the SQE on its own schedule. No call's
//! return proves the read has happened, so the storage is owned until the
//! completion like every other request.
//!
//! A [`Del`](EpollChange::Del) still needs storage even though nothing
//! reads it, because the request is the same shape and the ticket must own
//! something for the array's address to be stable. Rather than special-case
//! it, the published bytes are simply zero.
//!
//! # The interesting failures are about the registration, not the memory
//!
//! Measured against a real kernel:
//!
//! | request | result |
//! |---|---|
//! | `Add` on a fresh fd | `0` |
//! | `Add` on one already registered | `-EEXIST` |
//! | `Mod` on an unregistered fd | `-ENOENT` |
//! | `Del` of a registered fd | `0` |
//!
//! None of those is a memory hazard, and all of them are ordinary outcomes
//! of racing another thread that touched the same epoll set, so
//! [`EpollOutcome`] names them rather than folding them into one error.

use core::mem::{ManuallyDrop, align_of, size_of};

use super::buffer::StableBufferMut;
use super::identity::{RequestId, RingId};
use super::request::Receipt;
use crate::error::Errno;
use crate::op::Sqe;
use crate::types::{EpollEvent, EpollEvents, EpollOp, RawFd};

/// `-EEXIST`: the descriptor is already in this epoll set.
const EEXIST: i32 = -17;
/// `-ENOENT`: the descriptor is not in this epoll set.
const ENOENT: i32 = -2;

/// What a request changes about one descriptor's registration.
///
/// The event is attached to the two operations that read it and absent
/// from the one that does not, because the kernel ignores it for a `Del`
/// entirely — a mask supplied there would be silently discarded rather
/// than rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpollChange {
    /// Register the descriptor, failing with `EEXIST` if it already is.
    Add {
        /// Events to watch for.
        events: EpollEvents,
        /// Value the kernel reports back with each event.
        data: u64,
    },
    /// Replace an existing registration, failing with `ENOENT` if absent.
    Mod {
        /// Events to watch for.
        events: EpollEvents,
        /// Value the kernel reports back with each event.
        data: u64,
    },
    /// Remove the registration. The kernel reads no event for this.
    Del,
}

impl EpollChange {
    /// The kernel's operation code.
    const fn op(self) -> EpollOp {
        match self {
            Self::Add { .. } => EpollOp::Add,
            Self::Mod { .. } => EpollOp::Mod,
            Self::Del => EpollOp::Del,
        }
    }

    /// The event the kernel reads, or a zeroed one for a `Del`.
    const fn event(self) -> EpollEvent {
        match self {
            Self::Add { events, data } | Self::Mod { events, data } => EpollEvent {
                events: events.bits(),
                data,
            },
            Self::Del => EpollEvent { events: 0, data: 0 },
        }
    }
}

/// How an `epoll_ctl` ended.
///
/// The two registration errors are ordinary outcomes of another thread
/// having touched the same epoll set, so they are named rather than being
/// folded into a generic failure a caller has to decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpollOutcome {
    /// The change was applied.
    Applied,
    /// An `Add` for a descriptor that is already registered.
    AlreadyRegistered,
    /// A `Mod` or `Del` for a descriptor that is not registered.
    NotRegistered,
    /// The kernel rejected the request for another reason.
    Failed(Errno),
}

impl EpollOutcome {
    /// Classify a raw CQE result.
    const fn from_raw(result: i32) -> Self {
        match result {
            EEXIST => Self::AlreadyRegistered,
            ENOENT => Self::NotRegistered,
            other if other < 0 => Self::Failed(Errno::new(-other)),
            _ => Self::Applied,
        }
    }

    /// Classify a raw result directly, for tests that need an outcome the
    /// kernel is hard to coax into producing on demand.
    #[cfg(test)]
    pub(crate) const fn from_raw_for_test(result: i32) -> Self {
        Self::from_raw(result)
    }

    /// Whether the epoll set now reflects the requested change.
    #[must_use]
    pub const fn is_applied(self) -> bool {
        matches!(self, Self::Applied)
    }
}

impl core::fmt::Display for EpollOutcome {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Applied => f.write_str("epoll registration updated"),
            Self::AlreadyRegistered => f.write_str("descriptor is already registered"),
            Self::NotRegistered => f.write_str("descriptor is not registered"),
            Self::Failed(e) => write!(f, "epoll_ctl failed: {e}"),
        }
    }
}

/// Why an `epoll_ctl` request could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpollError {
    /// The storage cannot hold a whole [`EpollEvent`].
    StoreTooSmall {
        /// Bytes an `EpollEvent` needs.
        needed: usize,
        /// Bytes the supplied storage has.
        got: usize,
    },
    /// The storage is not aligned for an [`EpollEvent`].
    ///
    /// [`MmapBuffer`](super::MmapBuffer) is page-aligned and always
    /// satisfies this; a hand-written [`StableBufferMut`] might not.
    StoreMisaligned {
        /// Alignment an `EpollEvent` requires.
        needed: usize,
    },
}

impl core::fmt::Display for EpollError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::StoreTooSmall { needed, got } => {
                write!(f, "epoll_event storage needs {needed} bytes, got {got}")
            }
            Self::StoreMisaligned { needed } => {
                write!(f, "epoll_event storage must be {needed}-byte aligned")
            }
        }
    }
}

/// An `epoll_ctl` that owns the event storage, not yet queued.
pub struct PreparedEpollCtl<S> {
    store: S,
    epoll: RawFd,
    target: RawFd,
    change: EpollChange,
    /// Address of the published event, cached where the stability bound is
    /// in scope and checked for size and alignment before it was formed.
    addr: *mut EpollEvent,
}

// SAFETY: the pointer refers into storage this struct exclusively owns, so
// it stays valid wherever the value goes. The struct adds no thread
// affinity of its own, leaving `S` to decide.
unsafe impl<S: Send> Send for PreparedEpollCtl<S> {}

impl<S: StableBufferMut> PreparedEpollCtl<S> {
    /// Prepare a change to `target`'s registration in the `epoll` set.
    ///
    /// Takes ownership of `store`, which the kernel reads the event from
    /// after submission, so no caller alias to it may survive. Neither
    /// descriptor is taken: `epoll_ctl` borrows both for the call.
    ///
    /// # Errors
    ///
    /// Returns [`EpollError`] with the storage handed back if `store` is
    /// too small or misaligned for an [`EpollEvent`].
    pub fn new(
        epoll: RawFd,
        target: RawFd,
        change: EpollChange,
        mut store: S,
    ) -> Result<Self, (S, EpollError)> {
        let needed = size_of::<EpollEvent>();
        let got = store.stable_len();
        if got < needed {
            return Err((store, EpollError::StoreTooSmall { needed, got }));
        }
        let base = store.stable_mut_ptr();
        let align = align_of::<EpollEvent>();
        // Checked on the address rather than by casting first: the cast is
        // only sound once this has passed.
        if !base.addr().is_multiple_of(align) {
            return Err((store, EpollError::StoreMisaligned { needed: align }));
        }
        // The alignment check above is what makes this cast well-defined.
        #[allow(clippy::cast_ptr_alignment)]
        let addr = base.cast::<EpollEvent>();
        let mut prepared = Self {
            store,
            epoll,
            target,
            change,
            addr,
        };
        prepared.publish();
        Ok(prepared)
    }
}

impl<S> PreparedEpollCtl<S> {
    /// Write the event into the storage the kernel will read.
    ///
    /// Done at construction so the bytes are in place before any SQE can
    /// name them. A `Del` publishes a zeroed event, which the kernel does
    /// not read.
    const fn publish(&mut self) {
        // SAFETY: `addr` was checked for size and alignment against
        // `EpollEvent` and points into storage this request owns
        // exclusively, so nothing else can observe the write. No SQE
        // naming it exists yet, so the kernel is not reading concurrently.
        unsafe { self.addr.write(self.change.event()) }
    }

    /// The epoll set this request changes.
    #[must_use]
    pub const fn epoll(&self) -> RawFd {
        self.epoll
    }

    /// The descriptor whose registration changes.
    #[must_use]
    pub const fn target(&self) -> RawFd {
        self.target
    }

    /// What this request changes.
    #[must_use]
    pub const fn change(&self) -> EpollChange {
        self.change
    }

    /// The event exactly as the kernel will read it.
    ///
    /// Reads back the published storage rather than rebuilding it, so it
    /// shows what was actually written.
    #[must_use]
    pub const fn published(&self) -> EpollEvent {
        // SAFETY: `addr` points into storage this request owns and was
        // written by `publish` at construction, so it holds an initialised
        // `EpollEvent` at a properly aligned address.
        unsafe { self.addr.read() }
    }

    /// Give the storage back, abandoning the request.
    #[must_use]
    pub fn into_store(self) -> S {
        self.store
    }

    /// Build the SQE and move to the pending state.
    pub(crate) fn into_pending(self, ring: RingId, id: RequestId) -> (Sqe, PendingEpollCtl<S>) {
        // SAFETY: `addr` was checked for size and alignment against
        // `EpollEvent`, written by `publish`, and points into storage this
        // request owns exclusively. The storage moves into
        // `PendingEpollCtl`, whose destructor is suppressed unless a
        // receipt proves the kernel finished.
        let sqe = unsafe {
            Sqe::epoll_ctl_ptr(
                self.epoll,
                self.change.op(),
                self.target,
                self.addr.cast_const(),
            )
        };
        let pending = PendingEpollCtl {
            store: ManuallyDrop::new(self.store),
            ring,
            id,
            epoll: self.epoll,
            target: self.target,
            change: self.change,
            addr: self.addr,
        };
        (sqe.user_data(id.raw()), pending)
    }
}

/// A submitted `epoll_ctl` whose event storage the kernel may be reading.
///
/// # Drop and `forget` both leak rather than free
///
/// Dropping this runs no destructor for the storage. Under SQPOLL the
/// submitting thread never enters the kernel, so nothing here can prove
/// the event has been read, and the storage leaks on purpose — the same
/// failure mode as every other in-flight ticket.
///
/// No descriptor goes with it: `epoll_ctl` borrows both descriptors rather
/// than taking them, so only the storage is at stake.
#[must_use = "dropping the ticket leaks the event storage"]
pub struct PendingEpollCtl<S> {
    store: ManuallyDrop<S>,
    ring: RingId,
    id: RequestId,
    epoll: RawFd,
    target: RawFd,
    change: EpollChange,
    addr: *mut EpollEvent,
}

// SAFETY: the pointer refers into storage this ticket exclusively owns and
// keeps alive at a fixed address, so moving the ticket to another thread
// keeps it valid; `S` decides whether that move is allowed.
unsafe impl<S: Send> Send for PendingEpollCtl<S> {}

impl<S> PendingEpollCtl<S> {
    /// Identity the kernel echoes back in this request's CQE.
    #[must_use]
    pub const fn id(&self) -> RequestId {
        self.id
    }

    /// Identity of the queue that accepted this request.
    #[must_use]
    pub const fn ring(&self) -> RingId {
        self.ring
    }

    /// What this request changes.
    #[must_use]
    pub const fn change(&self) -> EpollChange {
        self.change
    }

    /// Whether `receipt` authenticates this exact request.
    #[must_use]
    pub const fn matches(&self, receipt: &Receipt) -> bool {
        receipt.id().raw() == self.id.raw() && receipt.ring().raw() == self.ring.raw()
    }

    /// Take the storage back without a receipt, undoing a failed push.
    ///
    /// # Safety
    ///
    /// The kernel must never have seen this request's SQE. Calling this
    /// after publication hands back storage the kernel may still read.
    pub(crate) unsafe fn reclaim_unsubmitted(self) -> PreparedEpollCtl<S> {
        let mut this = ManuallyDrop::new(self);
        // SAFETY: `this` is wrapped in `ManuallyDrop` so the no-op `Drop`
        // cannot observe the moved-out field. The caller guarantees no
        // kernel-visible pointer to the storage exists.
        let store = unsafe { ManuallyDrop::take(&mut this.store) };
        PreparedEpollCtl {
            store,
            epoll: this.epoll,
            target: this.target,
            change: this.change,
            addr: this.addr,
        }
    }

    /// Trade a matching receipt for the outcome and the storage.
    ///
    /// # Errors
    ///
    /// Returns the ticket and receipt unchanged if the receipt belongs to
    /// another request or another ring.
    pub fn redeem(self, receipt: Receipt) -> Result<EpollCtlDone<S>, (Self, Receipt)> {
        if !self.matches(&receipt) {
            return Err((self, receipt));
        }
        let mut this = ManuallyDrop::new(self);
        // SAFETY: `this` is wrapped in `ManuallyDrop`, so `Drop` will not
        // run and cannot observe the moved-out field. The receipt proves
        // the kernel finished with these bytes.
        let store = unsafe { ManuallyDrop::take(&mut this.store) };
        Ok(EpollCtlDone {
            store,
            change: this.change,
            id: this.id,
            result: receipt.raw_result(),
        })
    }
}

impl<S> Drop for PendingEpollCtl<S> {
    fn drop(&mut self) {
        // Intentionally no `ManuallyDrop::drop`. See the type docs: the
        // kernel may still be reading the event, so the storage leaks
        // rather than being freed underneath an in-flight request.
    }
}

/// A finished `epoll_ctl`: how it ended, and the storage back.
pub struct EpollCtlDone<S> {
    store: S,
    change: EpollChange,
    id: RequestId,
    result: i32,
}

impl<S> EpollCtlDone<S> {
    /// Identity of the request this completes.
    #[must_use]
    pub const fn id(&self) -> RequestId {
        self.id
    }

    /// Raw CQE result: `0` on success, `-errno` otherwise.
    #[must_use]
    pub const fn raw_result(&self) -> i32 {
        self.result
    }

    /// How the request ended.
    #[must_use]
    pub const fn outcome(&self) -> EpollOutcome {
        EpollOutcome::from_raw(self.result)
    }

    /// What this request changed.
    #[must_use]
    pub const fn change(&self) -> EpollChange {
        self.change
    }

    /// Take the storage back for reuse.
    #[must_use]
    pub fn into_store(self) -> S {
        self.store
    }

    /// Take the outcome and the storage together.
    #[must_use]
    pub fn into_parts(self) -> (EpollOutcome, S) {
        (self.outcome(), self.store)
    }
}
