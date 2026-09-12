//! `IORING_OP_FUTEX_WAITV`, which reads an *array* of words it does not own.
//!
//! [`PreparedFutexWait`](super::PreparedFutexWait) references one word this
//! ticket cannot own — see that module for why. `FUTEX_WAITV` compounds
//! that with the vectored-array hazard [`PreparedVectored`] already
//! solves: the kernel is handed a pointer to an **array of
//! [`FutexWaitv`]** entries, and dereferences that array to find each
//! word's own address. So there are two things that must stay put — the
//! array, and every word each entry names — and neither is owned here,
//! because a futex word's whole purpose is to be mutated by other threads
//! while this wait is outstanding.
//!
//! The array is therefore staged in caller-supplied [`StableBufferMut`]
//! storage, checked for size and alignment before the request can exist,
//! exactly as [`PreparedVectored`]'s descriptor array is — but unlike that
//! array, which the request populates from owned buffers, this one is
//! filled by the caller via [`FutexWaitv::new`] before handing it to
//! [`PreparedFutexWaitv::new`], since the words themselves are never
//! owned here to read a length or address from.
//!
//! [`PreparedVectored`]: super::PreparedVectored

use core::mem::{ManuallyDrop, align_of};

use super::buffer::StableBufferMut;
use super::identity::{RequestId, RingId};
use super::request::Receipt;
use crate::error::Errno;
use crate::op::Sqe;
use crate::types::{FUTEX_WAITV_MAX, FutexWaitv};

/// Why a `futex_waitv` request could not be built.
///
/// Hands the caller's storage back rather than consuming it, so a
/// rejected request never costs an allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FutexWaitvError {
    /// The storage cannot hold `count` [`FutexWaitv`] entries.
    ArrayTooSmall {
        /// Bytes the array needs.
        needed: usize,
        /// Bytes the supplied storage has.
        got: usize,
    },
    /// The storage is not aligned for [`FutexWaitv`].
    ArrayMisaligned {
        /// Alignment `FutexWaitv` requires.
        needed: usize,
    },
    /// More waiters than `FUTEX_WAITV_MAX`.
    ///
    /// The kernel rejects the whole request with `EINVAL` rather than
    /// waiting on a prefix.
    TooManyWaiters {
        /// Waiters asked for.
        got: usize,
        /// The most the kernel accepts.
        max: usize,
    },
    /// Zero waiters. The kernel rejects this with `EINVAL`.
    NoWaiters,
}

impl core::fmt::Display for FutexWaitvError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ArrayTooSmall { needed, got } => {
                write!(f, "futex_waitv array needs {needed} bytes, got {got}")
            }
            Self::ArrayMisaligned { needed } => {
                write!(f, "futex_waitv array must be {needed}-byte aligned")
            }
            Self::TooManyWaiters { got, max } => {
                write!(f, "{got} waiters exceeds the kernel's limit of {max}")
            }
            Self::NoWaiters => write!(f, "futex_waitv needs at least one waiter"),
        }
    }
}

/// A `futex_waitv` that owns its descriptor array's storage but not the
/// words the array names, not queued yet.
///
/// `V` holds the [`FutexWaitv`] array the kernel reads. The words each
/// entry names are never owned here — see the module docs.
pub struct PreparedFutexWaitv<V> {
    array: V,
    count: usize,
    /// Address of the first entry, cached where the stability bound is in
    /// scope.
    addr: *const FutexWaitv,
}

// SAFETY: `addr` points into `array`, which this struct exclusively owns,
// so the pointer is valid wherever the value is. It adds no thread
// affinity of its own, leaving `V` to decide — the words the entries
// point to are governed by the safety contract on the `FutexWaitv`s
// themselves rather than by this struct.
unsafe impl<V: Send> Send for PreparedFutexWaitv<V> {}

impl<V: StableBufferMut> PreparedFutexWaitv<V> {
    /// Check `array` against `waiters` and copy them in.
    ///
    /// # Safety
    ///
    /// Every [`FutexWaitv`] in `waiters` was built under
    /// [`FutexWaitv::new`]'s safety contract, which the caller must
    /// continue to uphold: the word each one names must remain valid and
    /// readable, at a stable address, until this request's completion is
    /// redeemed.
    ///
    /// # Errors
    ///
    /// Returns [`FutexWaitvError`] with the storage handed back if
    /// `waiters` is empty, exceeds `FUTEX_WAITV_MAX`, or `array` is too
    /// small or misaligned to hold it.
    pub unsafe fn new(waiters: &[FutexWaitv], mut array: V) -> Result<Self, (V, FutexWaitvError)> {
        let count = waiters.len();
        if count == 0 {
            return Err((array, FutexWaitvError::NoWaiters));
        }
        if count > FUTEX_WAITV_MAX {
            return Err((
                array,
                FutexWaitvError::TooManyWaiters {
                    got: count,
                    max: FUTEX_WAITV_MAX,
                },
            ));
        }
        let needed = core::mem::size_of_val(waiters);
        let got = array.stable_len();
        if got < needed {
            return Err((array, FutexWaitvError::ArrayTooSmall { needed, got }));
        }
        let base = array.stable_mut_ptr();
        let align = align_of::<FutexWaitv>();
        if !base.addr().is_multiple_of(align) {
            return Err((array, FutexWaitvError::ArrayMisaligned { needed: align }));
        }
        // The alignment check above is what makes this cast well-defined.
        #[allow(clippy::cast_ptr_alignment)]
        let dest = base.cast::<FutexWaitv>();
        // SAFETY: `dest` was just checked to be aligned and to have room
        // for `count` entries inside storage this value is about to own
        // exclusively, and `waiters` is a valid slice of `count` readable
        // entries.
        unsafe {
            core::ptr::copy_nonoverlapping(waiters.as_ptr(), dest, count);
        }
        Ok(Self {
            array,
            count,
            addr: dest.cast_const(),
        })
    }
}

impl<V> PreparedFutexWaitv<V> {
    /// How many waiters this request covers.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Give the array storage back, abandoning the request.
    #[must_use]
    pub fn into_array(self) -> V {
        self.array
    }

    /// Build the SQE and move to the pending state.
    pub(crate) fn into_pending(self, ring: RingId, id: RequestId) -> (Sqe, PendingFutexWaitv<V>) {
        #[allow(clippy::cast_possible_truncation)]
        let nr = self.count as u32;
        // SAFETY: `addr` points at `count` initialised entries inside
        // `self.array`, which moves into the returned `PendingFutexWaitv`.
        // The words each entry names are governed by the safety contract
        // the caller upheld in `new`, carried forward unchanged.
        let sqe = unsafe { Sqe::futex_waitv_ptr(self.addr, nr) };
        let pending = PendingFutexWaitv {
            array: ManuallyDrop::new(self.array),
            ring,
            id,
            count: self.count,
            addr: self.addr,
        };
        (sqe.user_data(id.raw()), pending)
    }
}

impl<V> Drop for PendingFutexWaitv<V> {
    fn drop(&mut self) {
        // Intentionally no `ManuallyDrop::drop`. See the type docs: the
        // kernel may not have copied the array yet, so it leaks rather
        // than being freed underneath an in-flight request.
    }
}

/// A submitted `futex_waitv`.
///
/// # Drop and `forget` both leak rather than free
///
/// Dropping this runs no destructor for the array. The kernel may not
/// have copied it yet — under SQPOLL the submitting thread never enters
/// the kernel, so nothing here can prove otherwise — so it leaks on
/// purpose, the same failure mode as every other in-flight ticket. See
/// the module docs for why this is owned at all rather than freed as soon
/// as `push` returns.
#[must_use = "dropping the ticket leaks the array storage"]
pub struct PendingFutexWaitv<V> {
    array: ManuallyDrop<V>,
    ring: RingId,
    id: RequestId,
    count: usize,
    addr: *const FutexWaitv,
}

// SAFETY: `addr` points into `array`, which this ticket exclusively owns
// and keeps alive at a fixed address, so moving the ticket to another
// thread keeps it valid; `V` decides whether that move is allowed.
unsafe impl<V: Send> Send for PendingFutexWaitv<V> {}

impl<V> PendingFutexWaitv<V> {
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

    /// How many waiters this request covers.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Whether `receipt` authenticates this exact request.
    #[must_use]
    pub const fn matches(&self, receipt: &Receipt) -> bool {
        receipt.belongs_to(self.ring, self.id)
    }

    /// Take the array back without a receipt, undoing a failed push.
    ///
    /// # Safety
    ///
    /// The kernel must never have seen this request's SQE. Calling this
    /// after publication hands back storage the kernel may still read.
    pub(crate) unsafe fn reclaim_unsubmitted(self) -> PreparedFutexWaitv<V> {
        let mut this = ManuallyDrop::new(self);
        // SAFETY: `this` is wrapped in `ManuallyDrop` so the no-op `Drop`
        // cannot observe the moved-out field. The caller guarantees no
        // kernel-visible pointer to the array exists.
        let array = unsafe { ManuallyDrop::take(&mut this.array) };
        PreparedFutexWaitv {
            array,
            count: this.count,
            addr: this.addr,
        }
    }

    /// Trade a matching receipt for the outcome and the array storage.
    ///
    /// # Errors
    ///
    /// Returns the ticket and receipt unchanged if the receipt belongs to
    /// another request or another ring.
    pub fn redeem(self, receipt: Receipt) -> Result<FutexWaitvDone<V>, (Self, Receipt)> {
        if !self.matches(&receipt) {
            return Err((self, receipt));
        }
        let mut this = ManuallyDrop::new(self);
        // SAFETY: `this` is wrapped in `ManuallyDrop`, so `Drop` will not
        // run and cannot observe the moved-out field. The receipt proves
        // the kernel finished with the array.
        let array = unsafe { ManuallyDrop::take(&mut this.array) };
        Ok(FutexWaitvDone {
            array,
            id: this.id,
            result: receipt.raw_result(),
        })
    }
}

/// A finished `futex_waitv`: the index of a woken waiter, and the array
/// storage back.
pub struct FutexWaitvDone<V> {
    array: V,
    id: RequestId,
    result: i32,
}

impl<V> FutexWaitvDone<V> {
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

    /// The index into the original waiter list that woke this request.
    ///
    /// No further information is available: any number of the other
    /// waiters may also have been woken by the same event, and this is
    /// not necessarily the smallest index or the most recently woken one
    /// — it is only *an* index that woke, per the kernel's own
    /// documented contract for `futex_waitv`.
    ///
    /// # Errors
    ///
    /// Returns [`CompletionError::Failed`](crate::CompletionError::Failed)
    /// when the CQE carried a negative errno.
    #[allow(clippy::cast_sign_loss)]
    pub const fn woken_index(&self) -> Result<u32, crate::Error> {
        if self.result < 0 {
            Err(crate::Error::Completion(crate::CompletionError::Failed(
                Errno::new(-self.result),
            )))
        } else {
            Ok(self.result as u32)
        }
    }

    /// Take the array storage back for reuse.
    #[must_use]
    pub fn into_array(self) -> V {
        self.array
    }
}
