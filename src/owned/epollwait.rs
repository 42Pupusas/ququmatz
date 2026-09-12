//! `epoll_wait`, where the kernel writes a variable-length array of typed
//! structs into caller storage and reports how many it filled.
//!
//! This sits between the two shapes the crate already has for a
//! kernel-written destination. Like [`PreparedStatx`](super::PreparedStatx),
//! the destination holds a typed struct the kernel writes rather than plain
//! bytes, so it is checked for size and alignment before the request can
//! exist. Unlike `statx`, more than one struct fits: the destination holds
//! `N` `EpollEvent`s, `N` chosen by how many the storage can hold, and the
//! CQE result is that count — anywhere from `0` up to `N` — rather than a
//! byte count or a plain success/failure.
//!
//! `0` is a real, successful outcome here: it means nothing was ready
//! before whatever caused the wait to return (this crate never arms the
//! kernel timeout argument, so in practice that is a signal or a
//! `link_timeout`), not an error and not "the array was too small."

use core::mem::{ManuallyDrop, align_of, size_of};

use super::buffer::StableBufferMut;
use super::identity::{RequestId, RingId};
use super::request::Receipt;
use crate::op::Sqe;
use crate::types::{EpollEvent, RawFd};

/// Why an `epoll_wait` request could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpollWaitError {
    /// The storage cannot hold even one `EpollEvent`.
    StoreTooSmall {
        /// Bytes one `EpollEvent` needs.
        needed: usize,
        /// Bytes the supplied storage has.
        got: usize,
    },
    /// The storage is not aligned for an `EpollEvent`.
    ///
    /// [`MmapBuffer`](super::MmapBuffer) is page-aligned and always
    /// satisfies this; a hand-written [`StableBufferMut`] might not.
    StoreMisaligned {
        /// Alignment an `EpollEvent` requires.
        needed: usize,
    },
}

impl core::fmt::Display for EpollWaitError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::StoreTooSmall { needed, got } => {
                write!(f, "epoll_wait storage needs at least {needed} bytes, got {got}")
            }
            Self::StoreMisaligned { needed } => {
                write!(f, "epoll_wait storage must be {needed}-byte aligned")
            }
        }
    }
}

#[allow(clippy::cast_possible_truncation)]
const fn clamp_max_events(slots: usize) -> u32 {
    if slots > u32::MAX as usize {
        u32::MAX
    } else {
        slots as u32
    }
}

/// An `epoll_wait` that owns its event storage, not yet queued.
pub struct PreparedEpollWait<D> {
    store: D,
    epfd: RawFd,
    max_events: u32,
    /// Address of the destination array, cached where the stability bound
    /// is in scope and checked for size and alignment before it was
    /// formed.
    addr: *mut EpollEvent,
}

// SAFETY: the pointer refers into storage this struct exclusively owns, so
// it stays valid wherever the value goes. The struct adds no thread
// affinity of its own, leaving `D` to decide.
unsafe impl<D: Send> Send for PreparedEpollWait<D> {}

impl<D: StableBufferMut> PreparedEpollWait<D> {
    /// Prepare an `epoll_wait` on `epfd`, filling as many events as `store`
    /// can hold.
    ///
    /// Takes ownership of `store`: the kernel writes into it after
    /// submission, so no caller alias may survive.
    ///
    /// # Errors
    ///
    /// Returns [`EpollWaitError`] with the storage handed back if `store`
    /// cannot hold even one `EpollEvent`, or is misaligned for one.
    pub fn new(epfd: RawFd, mut store: D) -> Result<Self, (D, EpollWaitError)> {
        let needed = size_of::<EpollEvent>();
        let got = store.stable_len();
        if got < needed {
            return Err((store, EpollWaitError::StoreTooSmall { needed, got }));
        }
        let base = store.stable_mut_ptr();
        let align = align_of::<EpollEvent>();
        // Checked on the address rather than by casting first: the cast is
        // only sound once this has passed.
        if !base.addr().is_multiple_of(align) {
            return Err((store, EpollWaitError::StoreMisaligned { needed: align }));
        }
        let max_events = clamp_max_events(got / needed);
        // The alignment check above is what makes this cast well-defined.
        #[allow(clippy::cast_ptr_alignment)]
        let addr = base.cast::<EpollEvent>();
        Ok(Self {
            store,
            epfd,
            max_events,
            addr,
        })
    }
}

impl<D> PreparedEpollWait<D> {
    /// The epoll set this request waits on.
    #[must_use]
    pub const fn epfd(&self) -> RawFd {
        self.epfd
    }

    /// How many events the destination can hold.
    #[must_use]
    pub const fn max_events(&self) -> u32 {
        self.max_events
    }

    /// Give the storage back, abandoning the request.
    #[must_use]
    pub fn into_store(self) -> D {
        self.store
    }

    /// Build the SQE and move to the pending state.
    pub(crate) fn into_pending(self, ring: RingId, id: RequestId) -> (Sqe, PendingEpollWait<D>) {
        // SAFETY: `addr` was checked for size and alignment against
        // `EpollEvent` and points into storage this request owns
        // exclusively, sized for `max_events` entries. The storage moves
        // into `PendingEpollWait`, whose destructor is suppressed unless a
        // receipt proves the kernel finished.
        let sqe = unsafe { Sqe::epoll_wait_ptr(self.epfd, self.addr, self.max_events) };
        let pending = PendingEpollWait {
            store: ManuallyDrop::new(self.store),
            ring,
            id,
            epfd: self.epfd,
            max_events: self.max_events,
            addr: self.addr,
        };
        (sqe.user_data(id.raw()), pending)
    }
}

/// A submitted `epoll_wait` whose destination the kernel may be writing.
///
/// # Drop and `forget` both leak rather than free
///
/// Dropping this runs no destructor for the storage: the kernel may still
/// be writing into it, and nothing here can prove otherwise, so it leaks on
/// purpose — the same failure mode as every other in-flight ticket.
#[must_use = "dropping the ticket leaks the event storage"]
pub struct PendingEpollWait<D> {
    store: ManuallyDrop<D>,
    ring: RingId,
    id: RequestId,
    epfd: RawFd,
    max_events: u32,
    addr: *mut EpollEvent,
}

// SAFETY: the pointer refers into storage this ticket exclusively owns and
// keeps alive at a fixed address, so moving the ticket to another thread
// keeps it valid; `D` decides whether that move is allowed.
unsafe impl<D: Send> Send for PendingEpollWait<D> {}

impl<D> PendingEpollWait<D> {
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

    /// Whether `receipt` authenticates this exact request.
    #[must_use]
    pub const fn matches(&self, receipt: &Receipt) -> bool {
        receipt.belongs_to(self.ring, self.id)
    }

    /// Take the storage back without a receipt, undoing a failed push.
    ///
    /// # Safety
    ///
    /// The kernel must never have seen this request's SQE. Calling this
    /// after publication hands back storage the kernel may still write to.
    pub(crate) unsafe fn reclaim_unsubmitted(self) -> PreparedEpollWait<D> {
        let mut this = ManuallyDrop::new(self);
        // SAFETY: `this` is wrapped in `ManuallyDrop` so the no-op `Drop`
        // cannot observe the moved-out field. The caller guarantees no
        // kernel-visible pointer to the storage exists.
        let store = unsafe { ManuallyDrop::take(&mut this.store) };
        PreparedEpollWait {
            store,
            epfd: this.epfd,
            max_events: this.max_events,
            addr: this.addr,
        }
    }

    /// Trade a matching receipt for the finished wait and its storage.
    ///
    /// # Errors
    ///
    /// Returns the ticket and receipt unchanged if the receipt belongs to
    /// another request or another ring.
    pub fn redeem(self, receipt: Receipt) -> Result<EpollWaitCompleted<D>, (Self, Receipt)> {
        if !self.matches(&receipt) {
            return Err((self, receipt));
        }
        let mut this = ManuallyDrop::new(self);
        // SAFETY: `this` is wrapped in `ManuallyDrop`, so `Drop` will not
        // run and cannot observe the moved-out field. The receipt proves
        // the kernel finished writing these bytes.
        let store = unsafe { ManuallyDrop::take(&mut this.store) };
        Ok(EpollWaitCompleted {
            store,
            id: this.id,
            result: receipt.raw_result(),
            addr: this.addr,
        })
    }
}

impl<D> Drop for PendingEpollWait<D> {
    fn drop(&mut self) {
        // Intentionally no `ManuallyDrop::drop`. See the type docs: the
        // kernel may still be writing the destination, so it leaks rather
        // than being freed underneath an in-flight request.
    }
}

/// A finished `epoll_wait`: however many events it reported, and the
/// storage back.
pub struct EpollWaitCompleted<D> {
    store: D,
    id: RequestId,
    result: i32,
    addr: *mut EpollEvent,
}

impl<D> EpollWaitCompleted<D> {
    /// Identity of the request this completes.
    #[must_use]
    pub const fn id(&self) -> RequestId {
        self.id
    }

    /// Raw CQE result: a non-negative event count on success, `-errno`
    /// otherwise.
    #[must_use]
    pub const fn raw_result(&self) -> i32 {
        self.result
    }

    /// How many events the kernel reported, or its error.
    ///
    /// # Errors
    ///
    /// Returns [`CompletionError::Failed`](crate::CompletionError::Failed)
    /// when the CQE carried a negative errno.
    #[allow(clippy::cast_sign_loss)]
    pub const fn count(&self) -> Result<u32, crate::Error> {
        if self.result < 0 {
            Err(crate::Error::Completion(crate::CompletionError::Failed(
                crate::Errno::new(-self.result),
            )))
        } else {
            Ok(self.result as u32)
        }
    }

    /// The events the kernel filled, or an empty slice on failure.
    ///
    /// The slice's length is exactly [`count`](Self::count), never the
    /// destination's full capacity: entries past that point were never
    /// written and would be uninitialised or stale.
    #[must_use]
    pub const fn events(&self) -> &[EpollEvent] {
        let Ok(n) = self.count() else {
            return &[];
        };
        // SAFETY: `addr` was checked for size and alignment against
        // `EpollEvent` before submission, this value owns that storage,
        // and a receipt proved the kernel wrote exactly `n` entries
        // starting at `addr` (`n` is the CQE result, which the kernel
        // never reports larger than the `max_events` it was given).
        unsafe { core::slice::from_raw_parts(self.addr.cast_const(), n as usize) }
    }

    /// Borrow the raw destination storage.
    #[must_use]
    pub const fn store(&self) -> &D {
        &self.store
    }

    /// Take the storage back for reuse.
    #[must_use]
    pub fn into_store(self) -> D {
        self.store
    }
}
