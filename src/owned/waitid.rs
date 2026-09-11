//! `IORING_OP_WAITID`, an async `waitid(2)` that writes a fixed-size struct.
//!
//! Shaped like [`PreparedStatx`](super::PreparedStatx): the kernel writes
//! `size_of::<WaitidSiginfo>()` bytes at a destination address with no
//! length field of its own, so a short destination is a write past the
//! end of the allocation rather than a short write, and nothing in the
//! result reveals it happened. The destination is therefore checked once,
//! before the request can exist, and taken as owned
//! [`StableBufferMut`] storage rather than a borrow — the kernel writes
//! through that pointer after submission, so no caller alias may survive.
//!
//! Unlike `statx`, the destination may be omitted entirely: `infop == NULL`
//! is a documented way to wait for a state change without wanting the
//! details. [`PreparedWaitId::discard`] models that case with no storage
//! at all, alongside [`PreparedWaitId::new`], which takes a destination.

use core::mem::{ManuallyDrop, align_of, size_of};

use super::buffer::StableBufferMut;
use super::identity::{RequestId, RingId};
use super::request::Receipt;
use crate::op::Sqe;
use crate::types::{IdType, WaitOptions, WaitidSiginfo};

/// Why a `waitid` request could not be built.
///
/// Hands the caller's storage back rather than consuming it, so a
/// rejected request never costs an allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitIdError {
    /// The destination cannot hold a whole `WaitidSiginfo`.
    DestTooSmall {
        /// Bytes a `WaitidSiginfo` needs.
        needed: usize,
        /// Bytes the supplied storage has.
        got: usize,
    },
    /// The destination is not aligned for `WaitidSiginfo`.
    DestMisaligned {
        /// Alignment `WaitidSiginfo` requires.
        needed: usize,
    },
}

impl core::fmt::Display for WaitIdError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DestTooSmall { needed, got } => {
                write!(f, "waitid destination needs {needed} bytes, got {got}")
            }
            Self::DestMisaligned { needed } => {
                write!(f, "waitid destination must be {needed}-byte aligned")
            }
        }
    }
}

/// A `waitid` that owns its destination (if any) but is not queued yet.
///
/// `D` holds the [`WaitidSiginfo`] the kernel writes, when there is one at
/// all — [`discard`](Self::discard) builds a request with none.
pub struct PreparedWaitId<D> {
    dest: Option<D>,
    id_type: IdType,
    id: i32,
    options: WaitOptions,
    /// Address of the destination struct, cached where the stability bound
    /// is in scope. Null when no destination was given.
    dest_addr: *mut WaitidSiginfo,
}

// SAFETY: the pointer refers into storage this struct exclusively owns (or
// is null), so it stays valid wherever the value goes. The struct adds no
// thread affinity of its own, leaving `D` to decide.
unsafe impl<D: Send> Send for PreparedWaitId<D> {}

impl<D: StableBufferMut> PreparedWaitId<D> {
    /// Prepare a `waitid` that writes its result into `dest`.
    ///
    /// Takes ownership of `dest`: the kernel writes into it after
    /// submission, so no caller alias may survive.
    ///
    /// # Errors
    ///
    /// Returns [`WaitIdError`] with the storage handed back if `dest` is
    /// too small or misaligned for a [`WaitidSiginfo`].
    pub fn new(
        id_type: IdType,
        id: i32,
        options: WaitOptions,
        mut dest: D,
    ) -> Result<Self, (D, WaitIdError)> {
        let needed = size_of::<WaitidSiginfo>();
        let got = dest.stable_len();
        if got < needed {
            return Err((dest, WaitIdError::DestTooSmall { needed, got }));
        }
        let base = dest.stable_mut_ptr();
        let align = align_of::<WaitidSiginfo>();
        // Checked on the address rather than by casting first: the cast is
        // only sound once this has passed.
        if !base.addr().is_multiple_of(align) {
            return Err((dest, WaitIdError::DestMisaligned { needed: align }));
        }
        // The alignment check above is what makes this cast well-defined.
        #[allow(clippy::cast_ptr_alignment)]
        let dest_addr = base.cast::<WaitidSiginfo>();
        Ok(Self {
            dest: Some(dest),
            id_type,
            id,
            options,
            dest_addr,
        })
    }
}

impl<D> PreparedWaitId<D> {
    /// Prepare a `waitid` that discards the child's info, reporting only
    /// that a matching state change occurred.
    #[must_use]
    pub const fn discard(id_type: IdType, id: i32, options: WaitOptions) -> Self {
        Self {
            dest: None,
            id_type,
            id,
            options,
            dest_addr: core::ptr::null_mut(),
        }
    }

    /// Which children this request selects.
    #[must_use]
    pub const fn id_type(&self) -> IdType {
        self.id_type
    }

    /// The pid/pgid/pidfd this request selects, per [`id_type`](Self::id_type).
    #[must_use]
    pub const fn id(&self) -> i32 {
        self.id
    }

    /// The options this request was prepared with.
    #[must_use]
    pub const fn options(&self) -> WaitOptions {
        self.options
    }

    /// Give the destination back, abandoning the request.
    #[must_use]
    pub fn into_dest(self) -> Option<D> {
        self.dest
    }

    /// Build the SQE and move to the pending state.
    pub(crate) fn into_pending(self, ring: RingId, id: RequestId) -> (Sqe, PendingWaitId<D>) {
        // SAFETY: `dest_addr` is either null (the kernel writes nothing)
        // or was checked for size and alignment against `WaitidSiginfo`
        // and points into storage this request owns exclusively. The
        // destination moves into `PendingWaitId`, whose destructor is
        // suppressed unless a receipt proves the kernel finished.
        let sqe =
            unsafe { Sqe::waitid(self.id_type, self.id, self.dest_addr, self.options) };
        let pending = PendingWaitId {
            dest: ManuallyDrop::new(self.dest),
            ring,
            id,
            id_type: self.id_type,
            waitid_id: self.id,
            options: self.options,
            dest_addr: self.dest_addr,
        };
        (sqe.user_data(id.raw()), pending)
    }
}

/// A submitted `waitid` whose destination the kernel may be writing.
///
/// # Drop and `forget` both leak rather than free
///
/// Dropping this runs no destructor for the destination. The kernel may
/// still be writing it, and nothing here can prove otherwise, so it leaks
/// on purpose — the same failure mode as every other in-flight ticket.
#[must_use = "dropping the ticket leaks the destination storage, if any"]
pub struct PendingWaitId<D> {
    dest: ManuallyDrop<Option<D>>,
    ring: RingId,
    id: RequestId,
    id_type: IdType,
    waitid_id: i32,
    options: WaitOptions,
    dest_addr: *mut WaitidSiginfo,
}

// SAFETY: the pointer refers into storage this ticket exclusively owns (or
// is null) and keeps alive at a fixed address, so moving the ticket to
// another thread keeps it valid; `D` decides whether that move is allowed.
unsafe impl<D: Send> Send for PendingWaitId<D> {}

impl<D> PendingWaitId<D> {
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

    /// Which children this request selects.
    #[must_use]
    pub const fn id_type(&self) -> IdType {
        self.id_type
    }

    /// Whether `receipt` authenticates this exact request.
    #[must_use]
    pub const fn matches(&self, receipt: &Receipt) -> bool {
        receipt.id().raw() == self.id.raw() && receipt.ring().raw() == self.ring.raw()
    }

    /// Take the destination back without a receipt, undoing a failed push.
    ///
    /// # Safety
    ///
    /// The kernel must never have seen this request's SQE. Calling this
    /// after publication hands back storage the kernel may still write to.
    pub(crate) unsafe fn reclaim_unsubmitted(self) -> PreparedWaitId<D> {
        let mut this = ManuallyDrop::new(self);
        // SAFETY: `this` is wrapped in `ManuallyDrop` so the no-op `Drop`
        // cannot observe the moved-out field. The caller guarantees no
        // kernel-visible pointer to the destination exists.
        let dest = unsafe { ManuallyDrop::take(&mut this.dest) };
        PreparedWaitId {
            dest,
            id_type: this.id_type,
            id: this.waitid_id,
            options: this.options,
            dest_addr: this.dest_addr,
        }
    }

    /// Trade a matching receipt for the outcome and the destination.
    ///
    /// The receipt proves the kernel posted this request's completion and
    /// has stopped writing the destination, which is what makes returning
    /// it sound.
    ///
    /// # Errors
    ///
    /// Returns the ticket and receipt unchanged if the receipt belongs to
    /// another request or another ring.
    pub fn redeem(self, receipt: Receipt) -> Result<WaitIdCompleted<D>, (Self, Receipt)> {
        if !self.matches(&receipt) {
            return Err((self, receipt));
        }
        let mut this = ManuallyDrop::new(self);
        // SAFETY: `this` is wrapped in `ManuallyDrop`, so `Drop` will not
        // run and cannot observe the moved-out field. The receipt proves
        // the kernel finished with the destination.
        let dest = unsafe { ManuallyDrop::take(&mut this.dest) };
        let result = receipt.raw_result();
        Ok(WaitIdCompleted {
            dest,
            id: this.id,
            result,
            dest_addr: this.dest_addr,
        })
    }
}

impl<D> Drop for PendingWaitId<D> {
    fn drop(&mut self) {
        // Intentionally no `ManuallyDrop::drop`. See the type docs: the
        // kernel may still be writing the destination, so it leaks rather
        // than being freed under an in-flight request.
    }
}

/// A finished `waitid`: the filled struct, if any, and the destination back.
pub struct WaitIdCompleted<D> {
    dest: Option<D>,
    id: RequestId,
    result: i32,
    dest_addr: *mut WaitidSiginfo,
}

impl<D> WaitIdCompleted<D> {
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

    /// Whether the `waitid` succeeded.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.result >= 0
    }

    /// Why the `waitid` failed, if it did.
    ///
    /// # Errors
    ///
    /// Returns [`CompletionError::Failed`](crate::CompletionError::Failed)
    /// when the CQE carried a negative errno.
    pub const fn result(&self) -> Result<(), crate::Error> {
        if self.result < 0 {
            Err(crate::Error::Completion(crate::CompletionError::Failed(
                crate::Errno::new(-self.result),
            )))
        } else {
            Ok(())
        }
    }

    /// Borrow the filled struct, when a destination was given and the
    /// request succeeded.
    ///
    /// Returns `None` on failure, since the kernel does not write the
    /// destination at all when it errors, so the storage still holds
    /// whatever it held before.
    #[must_use]
    pub fn info(&self) -> Option<&WaitidSiginfo> {
        if self.result < 0 || self.dest_addr.is_null() {
            return None;
        }
        // SAFETY: the destination was checked for size and alignment
        // against `WaitidSiginfo` before submission, this value owns that
        // storage, and a non-negative result means the kernel filled it.
        Some(unsafe { &*self.dest_addr })
    }

    /// Take the destination back, if this request was given one.
    #[must_use]
    pub fn into_dest(self) -> Option<D> {
        self.dest
    }
}
