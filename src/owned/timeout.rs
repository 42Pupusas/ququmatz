//! Timeouts, where the ordinary reading of a CQE result is wrong.
//!
//! Every other owned request treats a negative result as a failure and a
//! non-negative one as success. A timeout inverts that. The kernel reports
//! `-ETIME` when the timer ran to completion — the thing the caller
//! *asked for* — and `0` when it did not, because enough other
//! completions arrived first. Handing that to a `result() -> Result<>`
//! would report the working case as an error and the pre-empted case as
//! success.
//!
//! [`Expiry`] is therefore what a completion yields, and it names the four
//! outcomes measured against a real kernel:
//!
//! | outcome | result | meaning |
//! |---|---|---|
//! | [`Expired`](Expiry::Expired) | `-ETIME` | the duration elapsed |
//! | [`CountReached`](Expiry::CountReached) | `0` | `count` completions arrived first |
//! | [`Cancelled`](Expiry::Cancelled) | `-ECANCELED` | removed before it fired |
//! | [`Failed`](Expiry::Failed) | other `-errno` | the request was rejected |
//!
//! A zero duration and an absolute time already in the past both report
//! `Expired` immediately rather than being rejected, so neither is a
//! special case a caller has to pre-empt.
//!
//! # The storage must be owned, and the reason is SQPOLL
//!
//! Measured on a live ring, the kernel copies the `Timespec` out of caller
//! memory during `io_uring_enter` and never looks at it again: a timeout
//! staged at 300ms, submitted, then overwritten with 9000ms still fires at
//! 300ms, and one whose storage is dropped entirely before expiry still
//! fires correctly. Two timeouts sharing one slot in a single enter both
//! use whatever value was there at enter, not at push.
//!
//! That is *almost* an argument for taking a plain borrow. It fails on
//! SQPOLL. [`split_owned`](crate::IoUring::split_owned) accepts a polling
//! ring, and there the submitting thread never enters the kernel at all —
//! the SQ thread consumes entries on its own schedule, measured here at
//! tens of microseconds *after* `submit` returned. So there is no call
//! whose return proves the copy has happened, and the borrow that would
//! have to end somewhere has nowhere safe to end. The storage is owned
//! until the completion, like every other request.
//!
//! # `count` makes a timeout a barrier
//!
//! With `count == 0` this is a pure timer. With `count == n` it completes
//! when `n` *other* completions have been posted or the duration elapses,
//! whichever happens first — which is why the two outcomes need telling
//! apart. [`Count`] names the distinction so `0` is not a magic number
//! meaning "no barrier".
//!
//! # Not covered: linked timeouts
//!
//! `IORING_OP_LINK_TIMEOUT` cancels the operation it follows, but only if
//! it is submitted **immediately after** that operation in the same
//! submission. Nothing in this API expresses "these two SQEs are adjacent
//! and in this order" — each `push` is independent and may fail on its
//! own, leaving a link half-formed. Expressing that safely needs a request
//! pair rather than a request, so it stays on the
//! [`Sqe`](crate::Sqe) surface.

use core::mem::{ManuallyDrop, align_of, size_of};

use super::buffer::StableBufferMut;
use super::identity::{RequestId, RingId};
use super::request::Receipt;
use crate::error::Errno;
use crate::op::Sqe;
use crate::types::{TimeoutFlags, Timespec};

/// The result a timer that ran to completion reports: `-ETIME`.
const EXPIRED: i32 = -62;
/// The result a removed timeout reports: `-ECANCELED`.
const CANCELLED: i32 = -125;

/// How many other completions a timeout waits for before giving up.
///
/// A bare `u32` would make `0` a magic value meaning "not a barrier at
/// all", which is a different kind of request rather than a smaller
/// number of one, so the two are named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Count {
    /// A pure timer: nothing but the clock completes it.
    Timer,
    /// Complete once this many other completions have been posted, or the
    /// duration elapses — whichever comes first.
    Completions(u32),
}

impl Count {
    /// The value the kernel reads from the SQE's `off` field.
    const fn raw(self) -> u64 {
        match self {
            Self::Timer => 0,
            Self::Completions(n) => n as u64,
        }
    }
}

/// How a timeout ended.
///
/// The kernel's result field is not a success/failure code here: the
/// timer running to completion is reported as `-ETIME`, so a plain
/// `Result` would invert the two cases that matter. Every variant except
/// [`Failed`](Self::Failed) is a request that did what it was told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expiry {
    /// The duration elapsed without the completion count being reached.
    ///
    /// The kernel reports this as `-ETIME`. For a [`Count::Timer`] it is
    /// the only non-cancelled outcome.
    Expired,
    /// Enough other completions arrived before the duration elapsed.
    ///
    /// Only reachable for [`Count::Completions`]; the kernel reports `0`.
    CountReached,
    /// The timeout was removed before it fired.
    Cancelled,
    /// The kernel rejected the request.
    Failed(Errno),
}

impl Expiry {
    /// Classify a raw CQE result.
    const fn from_raw(result: i32) -> Self {
        match result {
            EXPIRED => Self::Expired,
            CANCELLED => Self::Cancelled,
            other if other < 0 => Self::Failed(Errno::new(-other)),
            _ => Self::CountReached,
        }
    }

    /// Classify a raw result directly, for tests that need an outcome the
    /// kernel is hard to coax into producing on demand.
    #[cfg(test)]
    pub(crate) const fn from_raw_for_test(result: i32) -> Self {
        Self::from_raw(result)
    }

    /// Whether the timer ran to completion.
    #[must_use]
    pub const fn is_expired(self) -> bool {
        matches!(self, Self::Expired)
    }

    /// Whether the request did what it was asked, however it ended.
    ///
    /// True for every outcome except [`Failed`](Self::Failed) — including
    /// [`Cancelled`](Self::Cancelled), since a removed timeout was
    /// removed on purpose.
    #[must_use]
    pub const fn is_ok(self) -> bool {
        !matches!(self, Self::Failed(_))
    }
}

impl core::fmt::Display for Expiry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Expired => f.write_str("timer expired"),
            Self::CountReached => f.write_str("completion count reached first"),
            Self::Cancelled => f.write_str("timeout cancelled"),
            Self::Failed(e) => write!(f, "timeout failed: {e}"),
        }
    }
}

/// Why a timeout request could not be built.
///
/// Hands the caller's storage back rather than consuming it, so a
/// rejected request never costs an allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeoutError {
    /// The storage cannot hold a whole [`Timespec`].
    ///
    /// The kernel reads `size_of::<Timespec>()` bytes from this address,
    /// so a short region is a read past the end of the allocation rather
    /// than a truncated request.
    StoreTooSmall {
        /// Bytes a `Timespec` needs.
        needed: usize,
        /// Bytes the supplied storage has.
        got: usize,
    },
    /// The storage is not aligned for a [`Timespec`].
    ///
    /// [`MmapBuffer`](super::MmapBuffer) is page-aligned and always
    /// satisfies this; a hand-written [`StableBufferMut`] might not.
    StoreMisaligned {
        /// Alignment `Timespec` requires.
        needed: usize,
    },
}

impl core::fmt::Display for TimeoutError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::StoreTooSmall { needed, got } => {
                write!(f, "timespec storage needs {needed} bytes, got {got}")
            }
            Self::StoreMisaligned { needed } => {
                write!(f, "timespec storage must be {needed}-byte aligned")
            }
        }
    }
}

/// A timeout that owns the storage its `Timespec` lives in, not yet queued.
pub struct PreparedTimeout<S> {
    store: S,
    duration: Timespec,
    count: Count,
    flags: TimeoutFlags,
    /// Address of the published `Timespec`, cached where the stability
    /// bound is in scope and checked for size and alignment before it was
    /// formed.
    addr: *mut Timespec,
}

// SAFETY: the pointer refers into storage this struct exclusively owns, so
// it stays valid wherever the value goes. The struct adds no thread
// affinity of its own, leaving `S` to decide.
unsafe impl<S: Send> Send for PreparedTimeout<S> {}

impl<S: StableBufferMut> PreparedTimeout<S> {
    /// Prepare a timeout of `duration`, relative to now.
    ///
    /// Takes ownership of `store`, which the kernel reads the duration
    /// from after submission, so no caller alias to it may survive.
    ///
    /// # Errors
    ///
    /// Returns [`TimeoutError`] with the storage handed back if `store`
    /// is too small or misaligned for a [`Timespec`].
    pub fn after(duration: Timespec, count: Count, store: S) -> Result<Self, (S, TimeoutError)> {
        Self::build(duration, count, TimeoutFlags::default(), store)
    }

    /// Prepare a timeout that fires at an absolute point on the clock.
    ///
    /// A time already in the past is not rejected: it reports
    /// [`Expiry::Expired`] immediately.
    ///
    /// # Errors
    ///
    /// As [`after`](Self::after).
    pub fn at(deadline: Timespec, count: Count, store: S) -> Result<Self, (S, TimeoutError)> {
        Self::build(deadline, count, TimeoutFlags::ABS, store)
    }

    /// Check the storage, then publish the duration into it.
    fn build(
        duration: Timespec,
        count: Count,
        flags: TimeoutFlags,
        mut store: S,
    ) -> Result<Self, (S, TimeoutError)> {
        let needed = size_of::<Timespec>();
        let got = store.stable_len();
        if got < needed {
            return Err((store, TimeoutError::StoreTooSmall { needed, got }));
        }
        let base = store.stable_mut_ptr();
        let align = align_of::<Timespec>();
        // Checked on the address rather than by casting first: the cast is
        // only sound once this has passed.
        if !base.addr().is_multiple_of(align) {
            return Err((store, TimeoutError::StoreMisaligned { needed: align }));
        }
        // The alignment check above is what makes this cast well-defined.
        #[allow(clippy::cast_ptr_alignment)]
        let addr = base.cast::<Timespec>();
        let mut prepared = Self {
            store,
            duration,
            count,
            flags,
            addr,
        };
        prepared.publish();
        Ok(prepared)
    }
}

impl<S> PreparedTimeout<S> {
    /// Write the duration into the storage the kernel will read.
    ///
    /// Done at construction so the bytes are in place before any SQE can
    /// name them.
    const fn publish(&mut self) {
        // SAFETY: `addr` was checked for size and alignment against
        // `Timespec` and points into storage this request owns
        // exclusively, so nothing else can observe the write. No SQE
        // naming it exists yet, so the kernel is not reading concurrently.
        unsafe { self.addr.write(self.duration) }
    }

    /// The duration this timeout was prepared with.
    #[must_use]
    pub const fn duration(&self) -> Timespec {
        self.duration
    }

    /// How many other completions this timeout waits for.
    #[must_use]
    pub const fn count(&self) -> Count {
        self.count
    }

    /// Whether the duration is an absolute clock time rather than a delay.
    #[must_use]
    pub const fn is_absolute(&self) -> bool {
        self.flags.contains(TimeoutFlags::ABS)
    }

    /// The `Timespec` exactly as the kernel will read it.
    ///
    /// Reads back the published storage rather than returning the field,
    /// so it shows what was actually written.
    #[must_use]
    pub const fn published(&self) -> Timespec {
        // SAFETY: `addr` points into storage this request owns and was
        // written by `publish` at construction, so it holds an initialised
        // `Timespec` at a properly aligned address.
        unsafe { self.addr.read() }
    }

    /// Give the storage back, abandoning the request.
    #[must_use]
    pub fn into_store(self) -> S {
        self.store
    }

    /// Build the SQE and move to the pending state.
    pub(crate) fn into_pending(self, ring: RingId, id: RequestId) -> (Sqe, PendingTimeout<S>) {
        // SAFETY: `addr` was checked for size and alignment against
        // `Timespec`, written by `publish`, and points into storage this
        // request owns exclusively. The storage moves into
        // `PendingTimeout`, whose destructor is suppressed unless a
        // receipt proves the kernel finished.
        let sqe = unsafe { Sqe::timeout_ptr(self.addr.cast_const(), self.count_raw(), self.flags) };
        let pending = PendingTimeout {
            store: ManuallyDrop::new(self.store),
            ring,
            id,
            duration: self.duration,
            count: self.count,
            flags: self.flags,
            addr: self.addr,
        };
        (sqe.user_data(id.raw()), pending)
    }

    /// The completion count as the kernel's SQE field wants it.
    #[allow(clippy::cast_possible_truncation)]
    const fn count_raw(&self) -> u32 {
        self.count.raw() as u32
    }
}

/// A submitted timeout whose storage the kernel may be reading.
///
/// # Drop and `forget` both leak rather than free
///
/// Dropping this runs no destructor for the storage. The kernel may not
/// have copied the `Timespec` yet — under SQPOLL the submitting thread
/// never enters the kernel, so nothing here can prove otherwise — and so
/// the storage leaks on purpose, the same failure mode as every other
/// in-flight ticket.
///
/// Unlike an open or an accept, an abandoned timeout loses no descriptor
/// and no table slot: the completion carries no resource, so only the
/// storage is at stake.
#[must_use = "dropping the ticket leaks the timespec storage"]
pub struct PendingTimeout<S> {
    store: ManuallyDrop<S>,
    ring: RingId,
    id: RequestId,
    duration: Timespec,
    count: Count,
    flags: TimeoutFlags,
    addr: *mut Timespec,
}

// SAFETY: the pointer refers into storage this ticket exclusively owns and
// keeps alive at a fixed address, so moving the ticket to another thread
// keeps it valid; `S` decides whether that move is allowed.
unsafe impl<S: Send> Send for PendingTimeout<S> {}

impl<S> PendingTimeout<S> {
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

    /// How many other completions this timeout waits for.
    #[must_use]
    pub const fn count(&self) -> Count {
        self.count
    }

    /// The `user_data` a [`Sqe::timeout_remove`] must name to cancel this.
    ///
    /// Cancellation is not part of the owned API — removing a timeout is
    /// a second request, and the ticket for the first is still held by
    /// whoever is waiting on it — so this exposes the value that lets a
    /// caller build one on the raw surface.
    #[must_use]
    pub const fn cancel_key(&self) -> u64 {
        self.id.raw()
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
    pub(crate) unsafe fn reclaim_unsubmitted(self) -> PreparedTimeout<S> {
        let mut this = ManuallyDrop::new(self);
        // SAFETY: `this` is wrapped in `ManuallyDrop` so the no-op `Drop`
        // cannot observe the moved-out field. The caller guarantees no
        // kernel-visible pointer to the storage exists.
        let store = unsafe { ManuallyDrop::take(&mut this.store) };
        PreparedTimeout {
            store,
            duration: this.duration,
            count: this.count,
            flags: this.flags,
            addr: this.addr,
        }
    }

    /// Trade a matching receipt for the outcome and the storage.
    ///
    /// The receipt proves the kernel posted this request's completion and
    /// has stopped reading the storage, which is what makes returning it
    /// sound.
    ///
    /// # Errors
    ///
    /// Returns the ticket and receipt unchanged if the receipt belongs to
    /// another request or another ring.
    pub fn redeem(self, receipt: Receipt) -> Result<TimeoutCompleted<S>, (Self, Receipt)> {
        if !self.matches(&receipt) {
            return Err((self, receipt));
        }
        let mut this = ManuallyDrop::new(self);
        // SAFETY: `this` is wrapped in `ManuallyDrop`, so `Drop` will not
        // run and cannot observe the moved-out field. The receipt proves
        // the kernel finished with these bytes.
        let store = unsafe { ManuallyDrop::take(&mut this.store) };
        Ok(TimeoutCompleted {
            store,
            count: this.count,
            id: this.id,
            result: receipt.raw_result(),
        })
    }
}

impl<S> Drop for PendingTimeout<S> {
    fn drop(&mut self) {
        // Intentionally no `ManuallyDrop::drop`. See the type docs: the
        // kernel may not have copied the `Timespec` yet, so the storage
        // leaks rather than being freed underneath an in-flight request.
    }
}

/// A finished timeout: how it ended, and the storage back.
pub struct TimeoutCompleted<S> {
    store: S,
    count: Count,
    id: RequestId,
    result: i32,
}

impl<S> TimeoutCompleted<S> {
    /// Identity of the request this completes.
    #[must_use]
    pub const fn id(&self) -> RequestId {
        self.id
    }

    /// Raw CQE result, for callers that want the kernel's own encoding.
    ///
    /// Prefer [`expiry`](Self::expiry): `-ETIME` here means the timer did
    /// exactly what was asked, which the usual reading of a negative
    /// result would call a failure.
    #[must_use]
    pub const fn raw_result(&self) -> i32 {
        self.result
    }

    /// How the timeout ended.
    #[must_use]
    pub const fn expiry(&self) -> Expiry {
        Expiry::from_raw(self.result)
    }

    /// How many other completions this timeout was waiting for.
    #[must_use]
    pub const fn count(&self) -> Count {
        self.count
    }

    /// Take the storage back for reuse.
    #[must_use]
    pub fn into_store(self) -> S {
        self.store
    }

    /// Take the outcome and the storage together.
    #[must_use]
    pub fn into_parts(self) -> (Expiry, S) {
        (self.expiry(), self.store)
    }
}
