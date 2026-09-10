//! A direct open, whose result is a table slot rather than a descriptor.
//!
//! [`PreparedOpen`](super::PreparedOpen) transfers path storage and gets
//! back both the storage and a [`File`](crate::fs::File). This does the
//! same with the storage, but the file it opens is never installed into the
//! process: the kernel puts it in the ring's registered-file table and the
//! completion names a [`SlotIndex`].
//!
//! # Why this is not a flag on the other type
//!
//! The two differ in what the caller must do afterwards, which is the part
//! a type should encode. An open descriptor is released by `close(2)`, is
//! owned by the process, and outlives the ring. A table slot is released by
//! asking the ring, is owned by the ring, and dies with it. Making the
//! result an `Option<File>` in one case and a [`DirectSlot`] in the other
//! is precisely the distinction a boolean parameter would erase.
//!
//! # The result means different things depending on the request
//!
//! For [`SlotTarget::Auto`] the kernel picks a slot and returns its index:
//!
//! ```text
//! ret = io_file_bitmap_get(ctx);      /* a free slot */
//! ...
//! if (!ret && alloc_slot) ret = file_slot;
//! ```
//!
//! For an explicit slot `io_install_fixed_file` returns `0`, and the index
//! is simply what the caller asked for. So a success is `>= 0` in both
//! cases but only carries an index in one, which is why [`SlotTarget`]
//! resolves the result rather than the completion reading it directly.

use core::mem::ManuallyDrop;

use super::buffer::StableBuffer;
use super::identity::{RequestId, RingId};
use super::path::OwnedPath;
use super::request::Receipt;
use super::slot::{DirectSlot, SlotIndex, SlotTarget};
use crate::op::Sqe;
use crate::types::{DirFd, FileMode, OpenFlags};

/// A direct open that owns its path storage but has not been queued yet.
pub struct PreparedDirectOpen<S> {
    path: OwnedPath<S>,
    dir: DirFd,
    flags: OpenFlags,
    mode: FileMode,
    target: SlotTarget,
    addr: *const u8,
}

// SAFETY: `addr` points into the path storage this struct exclusively
// owns, so the pointer is valid wherever the value is. It adds no thread
// affinity of its own, leaving `S` to decide.
unsafe impl<S: Send> Send for PreparedDirectOpen<S> {}

/// Why a direct open could not be prepared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectOpenError {
    /// `O_CLOEXEC` was requested for a slot that is not a descriptor.
    ///
    /// The kernel rejects this with `EINVAL`:
    ///
    /// ```text
    /// if (open->file_slot && (open->how.flags & O_CLOEXEC))
    ///         return -EINVAL;
    /// ```
    ///
    /// The flag describes what `execve` does to a *descriptor*, and a table
    /// slot is not one, so it is caught here rather than after a round trip
    /// through the kernel.
    CloseOnExec,
}

impl core::fmt::Display for DirectOpenError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CloseOnExec => {
                write!(f, "O_CLOEXEC is meaningless for a file-table slot")
            }
        }
    }
}

impl<S: StableBuffer> PreparedDirectOpen<S> {
    /// Prepare an open that installs into the ring's file table.
    ///
    /// # Errors
    ///
    /// Returns the path storage back with [`DirectOpenError::CloseOnExec`]
    /// if `flags` contains `O_CLOEXEC`, which the kernel refuses for a
    /// direct open.
    pub fn at(
        dir: DirFd,
        path: OwnedPath<S>,
        flags: OpenFlags,
        mode: FileMode,
        target: SlotTarget,
    ) -> Result<Self, (OwnedPath<S>, DirectOpenError)> {
        if flags.contains(OpenFlags::CLOEXEC) {
            return Err((path, DirectOpenError::CloseOnExec));
        }
        let addr = path.stable_ptr();
        Ok(Self {
            path,
            dir,
            flags,
            mode,
            target,
            addr,
        })
    }

    /// Prepare a direct open relative to the current working directory.
    ///
    /// # Errors
    ///
    /// As [`at`](Self::at).
    pub fn cwd(
        path: OwnedPath<S>,
        flags: OpenFlags,
        mode: FileMode,
        target: SlotTarget,
    ) -> Result<Self, (OwnedPath<S>, DirectOpenError)> {
        Self::at(DirFd::Cwd, path, flags, mode, target)
    }

    /// The directory this open resolves against.
    #[must_use]
    pub const fn dir(&self) -> DirFd {
        self.dir
    }

    /// The flags this open was prepared with.
    #[must_use]
    pub const fn flags(&self) -> OpenFlags {
        self.flags
    }

    /// The creation mode this open was prepared with.
    #[must_use]
    pub const fn mode(&self) -> FileMode {
        self.mode
    }

    /// Which slot this open installs into.
    #[must_use]
    pub const fn target(&self) -> SlotTarget {
        self.target
    }

    /// Borrow the path before submission.
    #[must_use]
    pub const fn path(&self) -> &OwnedPath<S> {
        &self.path
    }

    /// Give the path storage back, abandoning the operation.
    #[must_use]
    pub fn into_path(self) -> OwnedPath<S> {
        self.path
    }

    /// Build the SQE and move to the pending state.
    pub(crate) fn into_pending(self, ring: RingId, id: RequestId) -> (Sqe, PendingDirectOpen<S>) {
        // SAFETY: `addr` was taken from the path storage through
        // `StableBuffer`, so it is fixed for the owner's life, and
        // `OwnedPath` proved a NUL lies within that storage, so the
        // kernel's scan terminates inside memory this request owns. The
        // storage moves into `PendingDirectOpen`, whose destructor is
        // suppressed unless a receipt proves the kernel finished.
        let sqe = unsafe {
            Sqe::openat_direct(
                self.dir.as_raw(),
                self.addr,
                self.flags,
                self.mode,
                self.target.raw(),
            )
        };
        let pending = PendingDirectOpen {
            path: ManuallyDrop::new(self.path),
            ring,
            id,
            dir: self.dir,
            flags: self.flags,
            mode: self.mode,
            target: self.target,
            addr: self.addr,
        };
        (sqe.user_data(id.raw()), pending)
    }
}

/// A submitted direct open whose path bytes the kernel may be reading.
///
/// # Drop and `forget` both leak rather than free
///
/// Dropping this runs no destructor for the path storage, for the same
/// reason as every other in-flight ticket: the kernel may still be
/// resolving those bytes.
///
/// Abandoning one also loses track of a slot that may now be occupied. That
/// is a smaller loss than abandoning a [`PendingOpen`](super::PendingOpen),
/// which strands a descriptor for the life of the *process* — a stranded
/// slot is released when the ring's table is torn down.
pub struct PendingDirectOpen<S> {
    path: ManuallyDrop<OwnedPath<S>>,
    ring: RingId,
    id: RequestId,
    dir: DirFd,
    flags: OpenFlags,
    mode: FileMode,
    target: SlotTarget,
    addr: *const u8,
}

// SAFETY: `addr` points into the path storage this ticket exclusively owns
// and keeps alive at a fixed address, so moving the ticket to another
// thread keeps the pointer valid; `S` decides whether that move is allowed.
unsafe impl<S: Send> Send for PendingDirectOpen<S> {}

impl<S> PendingDirectOpen<S> {
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

    /// Which slot this open installs into.
    #[must_use]
    pub const fn target(&self) -> SlotTarget {
        self.target
    }

    /// Whether `receipt` authenticates this exact request.
    #[must_use]
    pub const fn matches(&self, receipt: &Receipt) -> bool {
        receipt.id().raw() == self.id.raw() && receipt.ring().raw() == self.ring.raw()
    }

    /// Take the path storage back without a receipt, undoing a failed push.
    ///
    /// # Safety
    ///
    /// The kernel must never have seen this request's SQE.
    pub(crate) unsafe fn reclaim_unsubmitted(self) -> PreparedDirectOpen<S> {
        let mut this = ManuallyDrop::new(self);
        // SAFETY: `this` is wrapped in `ManuallyDrop` so the no-op `Drop`
        // cannot observe the moved-out field. The caller guarantees no
        // kernel-visible pointer to the storage exists.
        let path = unsafe { ManuallyDrop::take(&mut this.path) };
        PreparedDirectOpen {
            path,
            dir: this.dir,
            flags: this.flags,
            mode: this.mode,
            target: this.target,
            addr: this.addr,
        }
    }

    /// Trade a matching receipt for the installed slot and the path storage.
    ///
    /// # Errors
    ///
    /// Returns the ticket and receipt unchanged if the receipt belongs to
    /// another request or another ring.
    pub fn redeem(self, receipt: Receipt) -> Result<DirectOpened<S>, (Self, Receipt)> {
        if !self.matches(&receipt) {
            return Err((self, receipt));
        }
        let mut this = ManuallyDrop::new(self);
        // SAFETY: `this` is wrapped in `ManuallyDrop`, so `Drop` will not
        // run and cannot observe the moved-out field. The receipt proves
        // the kernel finished with these bytes.
        let path = unsafe { ManuallyDrop::take(&mut this.path) };
        let result = receipt.raw_result();
        let slot = if result < 0 {
            None
        } else {
            this.target
                .resolve(result)
                .map(|index| DirectSlot::new(index, this.ring))
        };
        Ok(DirectOpened {
            path,
            slot,
            id: this.id,
            result,
        })
    }
}

impl<S> Drop for PendingDirectOpen<S> {
    fn drop(&mut self) {
        // Intentionally no `ManuallyDrop::drop`. See the type docs: the
        // kernel may still be reading the path, so the storage leaks rather
        // than being freed underneath an in-flight request.
    }
}

/// A finished direct open: the slot it filled, and the path storage back.
pub struct DirectOpened<S> {
    path: OwnedPath<S>,
    slot: Option<DirectSlot>,
    id: RequestId,
    result: i32,
}

impl<S> DirectOpened<S> {
    /// Identity of the request this completes.
    #[must_use]
    pub const fn id(&self) -> RequestId {
        self.id
    }

    /// Raw CQE result.
    ///
    /// A slot index for [`SlotTarget::Auto`], `0` for an explicit slot, and
    /// `-errno` on failure — which is why [`slot`](Self::slot) is the right
    /// way to learn where the file landed.
    #[must_use]
    pub const fn raw_result(&self) -> i32 {
        self.result
    }

    /// Whether the open succeeded.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.result >= 0
    }

    /// Why the open failed, if it did.
    ///
    /// # Errors
    ///
    /// Returns [`CompletionError::Failed`](crate::CompletionError::Failed)
    /// when the CQE carried a negative errno. `ENXIO` means no file table
    /// is registered; `EINVAL` means the slot is outside it.
    pub const fn result(&self) -> Result<(), crate::Error> {
        if self.result < 0 {
            Err(crate::Error::Completion(crate::CompletionError::Failed(
                crate::Errno::new(-self.result),
            )))
        } else {
            Ok(())
        }
    }

    /// Where the file was installed, if the open succeeded.
    #[must_use]
    pub const fn slot(&self) -> Option<&DirectSlot> {
        self.slot.as_ref()
    }

    /// The index the file was installed at, if the open succeeded.
    #[must_use]
    pub fn index(&self) -> Option<SlotIndex> {
        self.slot.as_ref().map(DirectSlot::index)
    }

    /// Borrow the path that was opened.
    #[must_use]
    pub const fn path(&self) -> &OwnedPath<S> {
        &self.path
    }

    /// Take both the slot and the path storage.
    #[must_use]
    pub fn into_parts(self) -> (Option<DirectSlot>, OwnedPath<S>) {
        (self.slot, self.path)
    }
}
