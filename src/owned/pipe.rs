//! `IORING_OP_PIPE`, where the kernel writes a fixed two-element array of
//! descriptors into caller storage.
//!
//! Shaped like [`PreparedStatx`](super::PreparedStatx): the kernel writes a
//! fixed-size destination with no length field of its own, so the
//! destination is checked for size and alignment before the request can
//! exist rather than after a short write is discovered. Unlike `statx`,
//! what lands there is not a single typed struct but two `i32`s — the read
//! end at index `0`, the write end at index `1`, the same order and
//! meaning as `pipe2(2)`.
//!
//! # No path, no read buffer
//!
//! This request owns nothing the kernel *reads* — a pipe is described
//! entirely by its flags. What must be owned is only the destination the
//! kernel writes the two descriptors into, exactly the concern
//! [`PreparedEpollWait`](super::PreparedEpollWait) already has for its
//! event array. The result here is smaller and fixed at two entries rather
//! than sized from the storage, since `pipe(2)` always produces exactly a
//! pair.
//!
//! # The result is not a byte count
//!
//! Like `statx`, the CQE result on success is plain `0`, not a length or a
//! descriptor — both descriptors live in the destination storage, not in
//! `cqe.res`. A negative result is `-errno` and means the destination was
//! never written at all.

use core::mem::{ManuallyDrop, align_of, size_of};

use super::buffer::StableBufferMut;
use super::identity::{RequestId, RingId};
use super::request::Receipt;
use crate::op::Sqe;
use crate::types::PipeFlags;

/// Byte size of the two-descriptor destination `IORING_OP_PIPE` writes.
const DEST_LEN: usize = size_of::<[i32; 2]>();
/// Alignment the destination must have for its `i32` pair.
const DEST_ALIGN: usize = align_of::<i32>();

/// Why a `pipe` request could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeError {
    /// The destination cannot hold both descriptors.
    DestTooSmall {
        /// Bytes the two descriptors need.
        needed: usize,
        /// Bytes the supplied storage has.
        got: usize,
    },
    /// The destination is not aligned for an `i32` pair.
    DestMisaligned {
        /// Alignment the destination requires.
        needed: usize,
    },
}

impl core::fmt::Display for PipeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DestTooSmall { needed, got } => {
                write!(f, "pipe destination needs {needed} bytes, got {got}")
            }
            Self::DestMisaligned { needed } => {
                write!(f, "pipe destination must be {needed}-byte aligned")
            }
        }
    }
}

/// A `pipe` request that owns its destination storage but is not queued yet.
pub struct PreparedPipe<D> {
    dest: D,
    flags: PipeFlags,
    /// Address of the two-descriptor destination, cached where the
    /// stability bound is in scope and checked for size and alignment
    /// before it was formed.
    addr: *mut i32,
}

// SAFETY: `addr` points into storage this struct exclusively owns, so it
// stays valid wherever the value goes. The struct adds no thread affinity
// of its own, leaving `D` to decide.
unsafe impl<D: Send> Send for PreparedPipe<D> {}

impl<D: StableBufferMut> PreparedPipe<D> {
    /// Prepare a pipe creation, writing both descriptors into `dest`.
    ///
    /// Takes ownership of `dest`: the kernel writes into it after
    /// submission, so no caller alias may survive.
    ///
    /// # Errors
    ///
    /// Returns [`PipeError`] with the storage handed back if `dest` cannot
    /// hold two `i32`s, or is misaligned for one.
    pub fn new(flags: PipeFlags, mut dest: D) -> Result<Self, (D, PipeError)> {
        let got = dest.stable_len();
        if got < DEST_LEN {
            return Err((
                dest,
                PipeError::DestTooSmall {
                    needed: DEST_LEN,
                    got,
                },
            ));
        }
        let base = dest.stable_mut_ptr();
        if !base.addr().is_multiple_of(DEST_ALIGN) {
            return Err((
                dest,
                PipeError::DestMisaligned {
                    needed: DEST_ALIGN,
                },
            ));
        }
        // The alignment check above is what makes this cast well-defined.
        #[allow(clippy::cast_ptr_alignment)]
        let addr = base.cast::<i32>();
        Ok(Self { dest, flags, addr })
    }
}

impl<D> PreparedPipe<D> {
    /// The flags this request was prepared with.
    #[must_use]
    pub const fn flags(&self) -> PipeFlags {
        self.flags
    }

    /// Give the storage back, abandoning the request.
    #[must_use]
    pub fn into_dest(self) -> D {
        self.dest
    }

    /// Build the SQE and move to the pending state.
    pub(crate) fn into_pending(self, ring: RingId, id: RequestId) -> (Sqe, PendingPipe<D>) {
        // SAFETY: `addr` was checked for size and alignment against two
        // `i32`s and points into storage this request owns exclusively.
        // The storage moves into `PendingPipe`, whose destructor is
        // suppressed unless a receipt proves the kernel finished.
        let sqe = unsafe { Sqe::pipe_ptr(self.addr, self.flags) };
        let pending = PendingPipe {
            dest: ManuallyDrop::new(self.dest),
            ring,
            id,
            flags: self.flags,
            addr: self.addr,
        };
        (sqe.user_data(id.raw()), pending)
    }
}

/// A submitted `pipe` whose destination the kernel may be writing.
///
/// # Drop and `forget` both leak rather than free
///
/// Dropping this runs no destructor for the storage: the kernel may still
/// be writing into it, and nothing here can prove otherwise, so it leaks on
/// purpose — the same failure mode as every other in-flight ticket.
#[must_use = "dropping the ticket leaks the destination storage"]
pub struct PendingPipe<D> {
    dest: ManuallyDrop<D>,
    ring: RingId,
    id: RequestId,
    flags: PipeFlags,
    addr: *mut i32,
}

// SAFETY: `addr` points into storage this ticket exclusively owns and
// keeps alive at a fixed address, so moving the ticket to another thread
// keeps it valid; `D` decides whether that move is allowed.
unsafe impl<D: Send> Send for PendingPipe<D> {}

impl<D> PendingPipe<D> {
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

    /// The flags this request was prepared with.
    #[must_use]
    pub const fn flags(&self) -> PipeFlags {
        self.flags
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
    pub(crate) unsafe fn reclaim_unsubmitted(self) -> PreparedPipe<D> {
        let mut this = ManuallyDrop::new(self);
        // SAFETY: `this` is wrapped in `ManuallyDrop` so the no-op `Drop`
        // cannot observe the moved-out field. The caller guarantees no
        // kernel-visible pointer to the storage exists.
        let dest = unsafe { ManuallyDrop::take(&mut this.dest) };
        PreparedPipe {
            dest,
            flags: this.flags,
            addr: this.addr,
        }
    }

    /// Trade a matching receipt for the created pipe and its storage.
    ///
    /// # Errors
    ///
    /// Returns the ticket and receipt unchanged if the receipt belongs to
    /// another request or another ring.
    pub fn redeem(self, receipt: Receipt) -> Result<PipeCreated<D>, (Self, Receipt)> {
        if !self.matches(&receipt) {
            return Err((self, receipt));
        }
        let mut this = ManuallyDrop::new(self);
        // SAFETY: `this` is wrapped in `ManuallyDrop`, so `Drop` will not
        // run and cannot observe the moved-out field. The receipt proves
        // the kernel finished writing these bytes.
        let dest = unsafe { ManuallyDrop::take(&mut this.dest) };
        Ok(PipeCreated {
            dest,
            id: this.id,
            result: receipt.raw_result(),
            addr: this.addr,
        })
    }
}

impl<D> Drop for PendingPipe<D> {
    fn drop(&mut self) {
        // Intentionally no `ManuallyDrop::drop`. See the type docs: the
        // kernel may still be writing the destination, so it leaks rather
        // than being freed underneath an in-flight request.
    }
}

/// A finished `pipe` request: both descriptors, if it succeeded, and the
/// storage back.
pub struct PipeCreated<D> {
    dest: D,
    id: RequestId,
    result: i32,
    addr: *mut i32,
}

impl<D> PipeCreated<D> {
    /// Identity of the request this completes.
    #[must_use]
    pub const fn id(&self) -> RequestId {
        self.id
    }

    /// Raw CQE result: `0` on success, `-errno` otherwise. The
    /// descriptors themselves live in the destination, not here.
    #[must_use]
    pub const fn raw_result(&self) -> i32 {
        self.result
    }

    /// Whether the pipe was created.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.result >= 0
    }

    /// Why the creation failed, if it did.
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

    /// The read end's descriptor, if the pipe was created.
    #[must_use]
    pub const fn read_fd(&self) -> Option<i32> {
        if self.result < 0 {
            return None;
        }
        // SAFETY: the destination was checked for size and alignment
        // before submission, this value owns that storage, and a
        // non-negative result means the kernel filled both entries.
        Some(unsafe { *self.addr })
    }

    /// The write end's descriptor, if the pipe was created.
    #[must_use]
    pub const fn write_fd(&self) -> Option<i32> {
        if self.result < 0 {
            return None;
        }
        // SAFETY: as `read_fd`, offset one `i32` into the same
        // two-element destination.
        Some(unsafe { *self.addr.add(1) })
    }

    /// Borrow the raw destination storage.
    #[must_use]
    pub const fn dest(&self) -> &D {
        &self.dest
    }

    /// Take the storage back for reuse.
    #[must_use]
    pub fn into_dest(self) -> D {
        self.dest
    }
}
