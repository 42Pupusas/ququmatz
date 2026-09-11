//! `IORING_OP_FUTEX_WAIT` / `FUTEX_WAKE`, which reference a word this
//! ticket cannot own.
//!
//! Every other request in this module transfers *exclusive* ownership of
//! the memory the kernel touches — that is what makes leaking on an
//! abandoned ticket the safe failure mode, and what makes handing the
//! storage back on completion sound. A futex word cannot work that way:
//! its entire purpose is to be mutated by *other* threads while a wait is
//! outstanding, so an "owning" wrapper here would contradict the
//! synchronization primitive it wraps rather than make it safer.
//!
//! So, like [`PreparedCancel`](super::PreparedCancel) and
//! [`PreparedMsgRing`](super::PreparedMsgRing), these tickets own no
//! caller memory — there is a target address rather than a buffer — and
//! [`FutexWait::new`]/[`FutexWake::new`] are `unsafe` for the same reason
//! every raw-pointer [`Sqe`] constructor is: the caller, not this type,
//! is responsible for keeping the word valid and readable (writable too,
//! for the ordinary case of a shared atomic other threads update) until
//! the kernel posts the completion.
//!
//! # Outcomes are named because a mismatch is not a failure
//!
//! `futex_wait` reports `-EAGAIN` at once when the word already differs
//! from the expected value at issue time — the same "nothing to wait for"
//! case `FUTEX_WAIT` has always had — and `-ECANCELED` when a cancel
//! reached it first. Neither is a programming error, so [`FutexWaitOutcome`]
//! names both rather than folding them into [`FutexWaitOutcome::Failed`].

use super::identity::{RequestId, RingId};
use super::request::Receipt;
use crate::error::Errno;
use crate::op::Sqe;
use crate::types::Futex2Flags;

/// `-EAGAIN`: the word already differed from the expected value.
const EAGAIN: i32 = -11;
/// `-ECANCELED`: a cancel reached the wait before it could be woken.
const ECANCELED: i32 = -125;

/// How a `futex_wait` ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FutexWaitOutcome {
    /// A matching wake arrived.
    Woken,
    /// The word already differed from the expected value at issue time,
    /// so there was nothing to wait for.
    ValueMismatch,
    /// The wait was cancelled before it could be woken.
    Cancelled,
    /// The kernel rejected the request for another reason.
    Failed(Errno),
}

impl FutexWaitOutcome {
    const fn from_raw(result: i32) -> Self {
        match result {
            0 => Self::Woken,
            EAGAIN => Self::ValueMismatch,
            ECANCELED => Self::Cancelled,
            other => Self::Failed(Errno::new(-other)),
        }
    }
}

/// A `futex_wait` referencing a caller-managed word, not queued yet.
///
/// `Copy`, because it owns no resource — a rejected push simply hands back
/// an identical copy.
#[derive(Debug, Clone, Copy)]
pub struct PreparedFutexWait {
    uaddr: *const u32,
    val: u64,
    mask: u64,
    flags: Futex2Flags,
}

// SAFETY: this struct stores a raw pointer to memory it does not own —
// see the module docs for why ownership is the wrong model for a futex
// word. It confers no thread affinity of its own; the caller's promise
// under `new`'s safety contract is what makes sending it sound.
unsafe impl Send for PreparedFutexWait {}

impl PreparedFutexWait {
    /// Prepare a wait for the word at `uaddr` to stop holding `val`, or
    /// for a wake whose bitset matches `mask`.
    ///
    /// `mask` must be non-zero — the kernel rejects a zero bitset with
    /// `EINVAL` — and `u32::MAX` matches any wake.
    ///
    /// # Safety
    ///
    /// `uaddr` must remain valid and readable, at a stable address, until
    /// this request's completion is redeemed or proven cancelled. Unlike
    /// every buffer-owning ticket in this module, this contract does
    /// *not* require exclusive access — the word is expected to be
    /// written by other threads while the wait is outstanding, which is
    /// the entire point of a futex.
    #[must_use]
    pub const unsafe fn new(uaddr: *const u32, val: u64, mask: u64, flags: Futex2Flags) -> Self {
        Self {
            uaddr,
            val,
            mask,
            flags,
        }
    }

    /// The address this request waits on.
    #[must_use]
    pub const fn uaddr(&self) -> *const u32 {
        self.uaddr
    }

    /// Build the SQE and move to the pending state.
    pub(crate) fn into_pending(self, ring: RingId, id: RequestId) -> (Sqe, PendingFutexWait) {
        // SAFETY: the caller upheld `new`'s contract, which this ticket
        // carries forward unchanged — nothing here narrows or widens it.
        let sqe = unsafe { Sqe::futex_wait(self.uaddr, self.val, self.mask, self.flags) };
        let pending = PendingFutexWait {
            ring,
            id,
            uaddr: self.uaddr,
        };
        (sqe.user_data(id.raw()), pending)
    }
}

/// A submitted `futex_wait`.
///
/// Owns nothing, so dropping it leaks nothing — but the word it named may
/// still be read by the kernel until this is redeemed or the request is
/// proven cancelled, per [`PreparedFutexWait::new`]'s safety contract.
#[derive(Debug)]
pub struct PendingFutexWait {
    ring: RingId,
    id: RequestId,
    uaddr: *const u32,
}

// SAFETY: the pointer refers to memory this ticket does not own; the
// caller's promise under `PreparedFutexWait::new` is what makes moving it
// between threads sound, exactly as for the prepared state.
unsafe impl Send for PendingFutexWait {}

impl PendingFutexWait {
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

    /// The address this request waits on.
    #[must_use]
    pub const fn uaddr(&self) -> *const u32 {
        self.uaddr
    }

    /// Whether `receipt` authenticates this exact request.
    #[must_use]
    pub const fn matches(&self, receipt: &Receipt) -> bool {
        receipt.id().raw() == self.id.raw() && receipt.ring().raw() == self.ring.raw()
    }

    /// Trade a matching receipt for the outcome.
    ///
    /// # Errors
    ///
    /// Returns the ticket and receipt unchanged if the receipt belongs to
    /// another request or another ring.
    pub const fn redeem(self, receipt: Receipt) -> Result<FutexWaitDone, (Self, Receipt)> {
        if !self.matches(&receipt) {
            return Err((self, receipt));
        }
        Ok(FutexWaitDone {
            id: self.id,
            result: receipt.raw_result(),
        })
    }
}

/// A finished `futex_wait`.
#[derive(Debug, Clone, Copy)]
pub struct FutexWaitDone {
    id: RequestId,
    result: i32,
}

impl FutexWaitDone {
    /// Identity of the request this completes.
    #[must_use]
    pub const fn id(&self) -> RequestId {
        self.id
    }

    /// Raw CQE result.
    #[must_use]
    pub const fn raw_result(&self) -> i32 {
        self.result
    }

    /// How the wait ended.
    #[must_use]
    pub const fn outcome(&self) -> FutexWaitOutcome {
        FutexWaitOutcome::from_raw(self.result)
    }
}

/// A `futex_wake` referencing a caller-managed word, not queued yet.
///
/// `Copy`, for the same reason as [`PreparedFutexWait`]: it owns no
/// resource.
#[derive(Debug, Clone, Copy)]
pub struct PreparedFutexWake {
    uaddr: *const u32,
    count: u64,
    mask: u64,
    flags: Futex2Flags,
}

// SAFETY: see `PreparedFutexWait`'s impl — the same reasoning applies.
unsafe impl Send for PreparedFutexWake {}

impl PreparedFutexWake {
    /// Prepare a wake of up to `count` waiters on the word at `uaddr`
    /// whose bitset matches `mask`.
    ///
    /// `mask` must be non-zero, and `u32::MAX` wakes any waiter
    /// regardless of the bitset it waited with.
    ///
    /// # Safety
    ///
    /// `uaddr` must remain valid and readable until this request's
    /// completion is redeemed. As with [`PreparedFutexWait::new`], this
    /// does not require exclusive access.
    #[must_use]
    pub const unsafe fn new(uaddr: *const u32, count: u64, mask: u64, flags: Futex2Flags) -> Self {
        Self {
            uaddr,
            count,
            mask,
            flags,
        }
    }

    /// The address this request wakes.
    #[must_use]
    pub const fn uaddr(&self) -> *const u32 {
        self.uaddr
    }

    /// Build the SQE and move to the pending state.
    pub(crate) fn into_pending(self, ring: RingId, id: RequestId) -> (Sqe, PendingFutexWake) {
        // SAFETY: the caller upheld `new`'s contract, carried forward
        // unchanged.
        let sqe = unsafe { Sqe::futex_wake(self.uaddr, self.count, self.mask, self.flags) };
        let pending = PendingFutexWake {
            ring,
            id,
            uaddr: self.uaddr,
        };
        (sqe.user_data(id.raw()), pending)
    }
}

/// A submitted `futex_wake`.
///
/// Owns nothing, so dropping it leaks nothing.
#[derive(Debug)]
pub struct PendingFutexWake {
    ring: RingId,
    id: RequestId,
    uaddr: *const u32,
}

// SAFETY: see `PendingFutexWait`'s impl — the same reasoning applies.
unsafe impl Send for PendingFutexWake {}

impl PendingFutexWake {
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

    /// The address this request wakes.
    #[must_use]
    pub const fn uaddr(&self) -> *const u32 {
        self.uaddr
    }

    /// Whether `receipt` authenticates this exact request.
    #[must_use]
    pub const fn matches(&self, receipt: &Receipt) -> bool {
        receipt.id().raw() == self.id.raw() && receipt.ring().raw() == self.ring.raw()
    }

    /// Trade a matching receipt for the outcome.
    ///
    /// # Errors
    ///
    /// Returns the ticket and receipt unchanged if the receipt belongs to
    /// another request or another ring.
    pub const fn redeem(self, receipt: Receipt) -> Result<FutexWakeDone, (Self, Receipt)> {
        if !self.matches(&receipt) {
            return Err((self, receipt));
        }
        Ok(FutexWakeDone {
            id: self.id,
            result: receipt.raw_result(),
        })
    }
}

/// A finished `futex_wake`: how many waiters the kernel woke.
#[derive(Debug, Clone, Copy)]
pub struct FutexWakeDone {
    id: RequestId,
    result: i32,
}

impl FutexWakeDone {
    /// Identity of the request this completes.
    #[must_use]
    pub const fn id(&self) -> RequestId {
        self.id
    }

    /// Raw CQE result: a non-negative count on success, `-errno` otherwise.
    #[must_use]
    pub const fn raw_result(&self) -> i32 {
        self.result
    }

    /// Waiters woken, or the kernel's failure.
    ///
    /// # Errors
    ///
    /// Returns [`CompletionError::Failed`](crate::CompletionError::Failed)
    /// when the CQE carried a negative errno.
    #[allow(clippy::cast_sign_loss)]
    pub const fn woken(&self) -> Result<u32, crate::Error> {
        if self.result < 0 {
            Err(crate::Error::Completion(crate::CompletionError::Failed(
                Errno::new(-self.result),
            )))
        } else {
            Ok(self.result as u32)
        }
    }
}
