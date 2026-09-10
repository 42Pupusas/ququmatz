//! `statx`, where the kernel writes a typed struct into caller storage.
//!
//! Every other owned request moves *bytes*: the length in the SQE says how
//! many, and the CQE result says how many actually moved. `statx` moves a
//! **fixed-size structure** instead. There is no length field for the
//! destination anywhere in the SQE — the kernel writes `size_of::<Statx>()`
//! bytes at `addr2` and reports only success or `-errno`.
//!
//! That makes the destination a different kind of hazard from a read
//! buffer. A short read buffer yields a short read; a short *statx*
//! destination is a fixed-size write past the end of the allocation, and
//! nothing in the result reveals it happened. Alignment matters for the
//! same reason: `Statx` is `repr(C)` with 8-byte alignment, so storage that
//! merely holds enough bytes is not sufficient.
//!
//! Both are therefore checked once, before the request can exist, and the
//! destination is taken as owned [`StableBufferMut`] storage rather than a
//! borrow — the kernel writes through that pointer after submission, so no
//! caller alias may survive.
//!
//! # The result is partially valid
//!
//! The other difference is what comes back. A read returns a byte count and
//! every byte within it is meaningful. `statx` returns a struct in which
//! *some fields are filled and some are not*, and which is which is
//! reported in-band by `stx_mask`. The kernel is explicit that this need
//! not equal the requested mask: a filesystem may decline a field that was
//! asked for, and may volunteer one that was not.
//!
//! So reading `stx_size` without consulting `stx_mask` reads whatever the
//! kernel left there — often a plausible-looking dummy value rather than an
//! obviously wrong one. The mask-gated accessors on [`Statx`] return
//! `Option` for exactly this reason, and are the intended way to read a
//! result.
//!
//! # Not covered: `AT_EMPTY_PATH`
//!
//! `statx` can stat an open descriptor directly by passing an empty path
//! with `AT_EMPTY_PATH`. [`OwnedPath`] rejects empty paths by construction,
//! so that mode is not reachable here. Use the unsafe
//! [`Sqe::statx_ptr`](crate::Sqe::statx_ptr) for it.

use core::mem::{ManuallyDrop, align_of, size_of};

use super::buffer::{StableBuffer, StableBufferMut};
use super::identity::{RequestId, RingId};
use super::path::OwnedPath;
use super::request::Receipt;
use crate::op::Sqe;
use crate::types::{DirFd, Statx, StatxFlags, StatxMask};

/// Bit the kernel reserves in `mask` and rejects with `EINVAL`.
const STATX_RESERVED: u32 = 0x8000_0000;

/// Why a `statx` request could not be built.
///
/// Each hands the caller's storage back rather than consuming it, so a
/// rejected request never costs an allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatxError {
    /// The destination cannot hold a whole `Statx`.
    ///
    /// The kernel writes a fixed-size struct with no regard for how much
    /// room the caller provided, so this is refused up front.
    DestTooSmall {
        /// Bytes a `Statx` needs.
        needed: usize,
        /// Bytes the supplied storage has.
        got: usize,
    },
    /// The destination is not aligned for `Statx`.
    ///
    /// [`MmapBuffer`](super::MmapBuffer) is page-aligned and always
    /// satisfies this; a hand-written [`StableBufferMut`] might not.
    DestMisaligned {
        /// Alignment `Statx` requires.
        needed: usize,
    },
    /// The mask sets the bit the kernel reserves.
    ///
    /// `statx` fails this with `EINVAL`, so it is caught here where the
    /// caller still has the storage back.
    ReservedMaskBit,
}

impl core::fmt::Display for StatxError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DestTooSmall { needed, got } => {
                write!(f, "statx destination needs {needed} bytes, got {got}")
            }
            Self::DestMisaligned { needed } => {
                write!(f, "statx destination must be {needed}-byte aligned")
            }
            Self::ReservedMaskBit => write!(f, "statx mask sets a reserved bit"),
        }
    }
}

/// A `statx` that owns its path and destination but is not queued yet.
///
/// `S` holds the path bytes the kernel reads; `D` holds the `Statx` the
/// kernel writes. Both are owned here and both come back together from
/// [`StatxCompleted::into_parts`].
pub struct PreparedStatx<S, D> {
    path: OwnedPath<S>,
    dest: D,
    dir: DirFd,
    flags: StatxFlags,
    mask: StatxMask,
    /// Address of the path bytes, cached where the stability bound is in
    /// scope. Held as a pointer so the provenance reaches the SQE intact.
    path_addr: *const u8,
    /// Address of the destination struct, cached for the same reason.
    dest_addr: *mut Statx,
}

// SAFETY: both pointers refer into storage this struct exclusively owns, so
// they stay valid wherever the value goes. The struct adds no thread
// affinity of its own, leaving `S` and `D` to decide.
unsafe impl<S: Send, D: Send> Send for PreparedStatx<S, D> {}

impl<S: StableBuffer, D: StableBufferMut> PreparedStatx<S, D> {
    /// Prepare a `statx` of `path` relative to `dir`, writing into `dest`.
    ///
    /// Takes ownership of both: the kernel reads the path and writes the
    /// destination after submission, so no caller alias may survive.
    ///
    /// # Errors
    ///
    /// Returns [`StatxError`] with all the storage handed back if `dest` is
    /// too small or misaligned for a `Statx`, or if `mask` sets the bit the
    /// kernel reserves.
    pub fn at(
        dir: DirFd,
        path: OwnedPath<S>,
        flags: StatxFlags,
        mask: StatxMask,
        mut dest: D,
    ) -> Result<Self, (OwnedPath<S>, D, StatxError)> {
        if mask.bits() & STATX_RESERVED != 0 {
            return Err((path, dest, StatxError::ReservedMaskBit));
        }
        let needed = size_of::<Statx>();
        let got = dest.stable_len();
        if got < needed {
            return Err((path, dest, StatxError::DestTooSmall { needed, got }));
        }
        let base = dest.stable_mut_ptr();
        let align = align_of::<Statx>();
        // Checked on the address rather than by casting first: the cast is
        // only sound once this has passed.
        if !base.addr().is_multiple_of(align) {
            return Err((path, dest, StatxError::DestMisaligned { needed: align }));
        }
        let path_addr = path.stable_ptr();
        // The alignment check above is what makes this cast well-defined.
        #[allow(clippy::cast_ptr_alignment)]
        let dest_addr = base.cast::<Statx>();
        Ok(Self {
            path,
            dest,
            dir,
            flags,
            mask,
            path_addr,
            dest_addr,
        })
    }

    /// Prepare a `statx` relative to the current working directory.
    ///
    /// # Errors
    ///
    /// As [`at`](Self::at).
    pub fn cwd(
        path: OwnedPath<S>,
        flags: StatxFlags,
        mask: StatxMask,
        dest: D,
    ) -> Result<Self, (OwnedPath<S>, D, StatxError)> {
        Self::at(DirFd::Cwd, path, flags, mask, dest)
    }
}

impl<S, D> PreparedStatx<S, D> {
    /// The directory this request resolves against.
    #[must_use]
    pub const fn dir(&self) -> DirFd {
        self.dir
    }

    /// The flags this request was prepared with.
    #[must_use]
    pub const fn flags(&self) -> StatxFlags {
        self.flags
    }

    /// The field mask this request was prepared with.
    ///
    /// The kernel need not honour it exactly; read the completed
    /// `stx_mask` to learn what was actually filled.
    #[must_use]
    pub const fn mask(&self) -> StatxMask {
        self.mask
    }

    /// Borrow the path before submission.
    #[must_use]
    pub const fn path(&self) -> &OwnedPath<S> {
        &self.path
    }

    /// Give both pieces of storage back, abandoning the request.
    #[must_use]
    pub fn into_parts(self) -> (OwnedPath<S>, D) {
        (self.path, self.dest)
    }

    /// Build the SQE and move to the pending state.
    pub(crate) fn into_pending(self, ring: RingId, id: RequestId) -> (Sqe, PendingStatx<S, D>) {
        // SAFETY: `path_addr` came from the path storage through
        // `StableBuffer`, and `OwnedPath` proved a NUL lies within it, so
        // the kernel's scan terminates inside memory this request owns.
        // `dest_addr` was checked for size and alignment against `Statx`
        // and points into storage this request owns exclusively. Both move
        // into `PendingStatx`, whose destructor is suppressed unless a
        // receipt proves the kernel finished.
        let sqe = unsafe {
            Sqe::statx_ptr(
                self.dir.as_raw(),
                self.path_addr,
                self.flags,
                self.mask,
                self.dest_addr,
            )
        };
        let pending = PendingStatx {
            path: ManuallyDrop::new(self.path),
            dest: ManuallyDrop::new(self.dest),
            ring,
            id,
            dir: self.dir,
            flags: self.flags,
            mask: self.mask,
            path_addr: self.path_addr,
            dest_addr: self.dest_addr,
        };
        (sqe.user_data(id.raw()), pending)
    }
}

/// A submitted `statx` whose storage the kernel may be touching.
///
/// `Send` when both storages are, so the ticket can cross to a completion
/// thread like any other.
///
/// # Drop and `forget` both leak rather than free
///
/// Dropping this runs no destructor for either storage. The kernel may
/// still be reading the path or writing the destination, and nothing here
/// can prove otherwise, so both leak on purpose — the same failure mode as
/// every other in-flight ticket.
pub struct PendingStatx<S, D> {
    path: ManuallyDrop<OwnedPath<S>>,
    dest: ManuallyDrop<D>,
    ring: RingId,
    id: RequestId,
    dir: DirFd,
    flags: StatxFlags,
    mask: StatxMask,
    path_addr: *const u8,
    dest_addr: *mut Statx,
}

// SAFETY: both pointers refer into storage this ticket exclusively owns and
// keeps alive at fixed addresses, so moving the ticket to another thread
// keeps them valid; `S` and `D` decide whether that move is allowed.
unsafe impl<S: Send, D: Send> Send for PendingStatx<S, D> {}

impl<S, D> PendingStatx<S, D> {
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
        receipt.id().raw() == self.id.raw() && receipt.ring().raw() == self.ring.raw()
    }

    /// Take both storages back without a receipt, undoing a failed push.
    ///
    /// # Safety
    ///
    /// The kernel must never have seen this request's SQE. Calling this
    /// after publication hands back storage the kernel may still touch.
    pub(crate) unsafe fn reclaim_unsubmitted(self) -> PreparedStatx<S, D> {
        let mut this = ManuallyDrop::new(self);
        // SAFETY: `this` is wrapped in `ManuallyDrop` so the no-op `Drop`
        // cannot observe the moved-out fields. The caller guarantees no
        // kernel-visible pointer to either storage exists.
        let (path, dest) = unsafe {
            (
                ManuallyDrop::take(&mut this.path),
                ManuallyDrop::take(&mut this.dest),
            )
        };
        PreparedStatx {
            path,
            dest,
            dir: this.dir,
            flags: this.flags,
            mask: this.mask,
            path_addr: this.path_addr,
            dest_addr: this.dest_addr,
        }
    }

    /// Trade a matching receipt for the filled struct and both storages.
    ///
    /// The receipt proves the kernel posted this request's completion and
    /// has stopped touching the storage, which is what makes returning it
    /// sound.
    ///
    /// # Errors
    ///
    /// Returns the ticket and receipt unchanged if the receipt belongs to
    /// another request or another ring.
    pub fn redeem(self, receipt: Receipt) -> Result<StatxCompleted<S, D>, (Self, Receipt)> {
        if !self.matches(&receipt) {
            return Err((self, receipt));
        }
        let mut this = ManuallyDrop::new(self);
        // SAFETY: `this` is wrapped in `ManuallyDrop`, so `Drop` will not
        // run and cannot observe the moved-out fields. The receipt proves
        // the kernel finished with both regions.
        let (path, dest) = unsafe {
            (
                ManuallyDrop::take(&mut this.path),
                ManuallyDrop::take(&mut this.dest),
            )
        };
        let result = receipt.raw_result();
        Ok(StatxCompleted {
            path,
            dest,
            id: this.id,
            result,
            dest_addr: this.dest_addr,
        })
    }
}

impl<S, D> Drop for PendingStatx<S, D> {
    fn drop(&mut self) {
        // Intentionally no `ManuallyDrop::drop`. See the type docs: the
        // kernel may still be reading the path or writing the destination,
        // so both leak rather than being freed under an in-flight request.
    }
}

/// A finished `statx`: the filled struct, and both storages back.
pub struct StatxCompleted<S, D> {
    path: OwnedPath<S>,
    dest: D,
    id: RequestId,
    result: i32,
    dest_addr: *mut Statx,
}

impl<S, D> StatxCompleted<S, D> {
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

    /// Whether the `statx` succeeded.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.result >= 0
    }

    /// Why the `statx` failed, if it did.
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

    /// Borrow the filled struct, or `None` if the `statx` failed.
    ///
    /// Returns `None` rather than a zeroed struct on failure because the
    /// kernel does not write the destination at all when it errors, so the
    /// storage still holds whatever it held before.
    ///
    /// Read fields through the mask-gated accessors on [`Statx`]: which
    /// ones the kernel actually filled is reported by `stx_mask` and need
    /// not match what was requested.
    #[must_use]
    pub fn stat(&self) -> Option<&Statx> {
        if self.result < 0 {
            return None;
        }
        // SAFETY: the destination was checked for size and alignment
        // against `Statx` before submission, this value owns that storage,
        // and a non-negative result means the kernel filled it.
        Some(unsafe { &*self.dest_addr })
    }

    /// Borrow the path that was stat'd.
    #[must_use]
    pub const fn path(&self) -> &OwnedPath<S> {
        &self.path
    }

    /// Take both storages back.
    ///
    /// Call [`stat`](Self::stat) first if the result is wanted: the
    /// destination storage is returned raw, without the typed view.
    #[must_use]
    pub fn into_parts(self) -> (OwnedPath<S>, D) {
        (self.path, self.dest)
    }
}
