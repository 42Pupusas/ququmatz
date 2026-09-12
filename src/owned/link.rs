//! `symlinkat` and `linkat`, the two-path siblings of [`PreparedPathOp`].
//!
//! [`PreparedRename`](super::PreparedRename) already established the shape
//! a two-path request needs: two independent [`OwnedPath`] storages, both
//! read by the kernel after submission, both handed back together. These
//! two ops need exactly that shape again, so they share a type the same
//! way [`PreparedPathOp`] lets `unlinkat` and `mkdirat` share one — one
//! parameter apiece distinguishes them, carried by [`LinkKind`].
//!
//! # `symlinkat`'s first path is not a path lookup
//!
//! Every other path-bearing op in this crate resolves its path against a
//! directory and an inode has to exist at the end of it. `symlinkat`'s
//! `old_path` is different: it is copied *verbatim* into the new symlink
//! as the link's target text, never opened, stat'd, or checked for
//! existence. That is why [`LinkKind::Symlink`] carries no directory for
//! it — there is nothing to resolve against — while
//! [`LinkKind::Link`] carries one for both sides, since a hard link
//! genuinely looks `old_path` up.
//!
//! # `linkat`'s default direction surprises
//!
//! Every other `*at` call defaults to *not* dereferencing a symlink named
//! by its path and takes a flag to force following it. `linkat` is the
//! exception in the other direction for its own default (it does not
//! follow `old_path` unless [`LinkFlags::SYMLINK_FOLLOW`] is set), which
//! matches the rest of the family, but the flag itself is easy to expect
//! backwards if `AT_SYMLINK_NOFOLLOW`'s convention is what comes to mind
//! first. There is no named enum for it the way [`RenameMode`] replaces
//! raw rename flags, because both of `linkat`'s flags are independent
//! options rather than mutually exclusive alternatives — nothing here
//! stops an invalid combination the kernel would itself accept.
//!
//! [`PreparedPathOp`]: super::PreparedPathOp
//! [`PreparedRename`]: super::PreparedRename
//! [`RenameMode`]: super::RenameMode

use core::mem::ManuallyDrop;

use super::buffer::StableBuffer;
use super::identity::{RequestId, RingId};
use super::path::OwnedPath;
use super::request::Receipt;
use crate::op::Sqe;
use crate::types::{DirFd, LinkFlags};

/// Which two-path operation a request performs.
///
/// Carries the parameters that distinguish `symlinkat` from `linkat` — see
/// the module docs for why they cannot share a single directory field.
#[derive(Debug, Clone, Copy)]
pub enum LinkKind {
    /// Create a symlink at the destination containing the source path's
    /// literal text.
    Symlink {
        /// Directory the destination path resolves against.
        new_dir: DirFd,
    },
    /// Create a hard link at the destination pointing to the source
    /// path's inode.
    Link {
        /// Directory the source path resolves against.
        old_dir: DirFd,
        /// Directory the destination path resolves against.
        new_dir: DirFd,
        flags: LinkFlags,
    },
}

impl LinkKind {
    /// Build this kind's SQE against already-validated path addresses.
    ///
    /// # Safety
    ///
    /// `old_addr` and `new_addr` must point to NUL-terminated paths that
    /// stay valid and fixed until the kernel posts this request's
    /// completion.
    unsafe fn sqe(self, old_addr: *const u8, new_addr: *const u8) -> Sqe {
        // SAFETY: forwarded from this function's own contract.
        unsafe {
            match self {
                Self::Symlink { new_dir } => {
                    Sqe::symlinkat_ptr(old_addr, new_dir.as_raw(), new_addr)
                }
                Self::Link {
                    old_dir,
                    new_dir,
                    flags,
                } => Sqe::linkat_ptr(old_dir.as_raw(), old_addr, new_dir.as_raw(), new_addr, flags),
            }
        }
    }
}

/// A two-path link operation that owns both path storages, not yet queued.
pub struct PreparedLink<F, T> {
    old: OwnedPath<F>,
    new: OwnedPath<T>,
    kind: LinkKind,
    /// Addresses of both paths, cached where the stability bound is in
    /// scope. Held as pointers so the provenance reaches the SQE intact.
    old_addr: *const u8,
    new_addr: *const u8,
}

// SAFETY: both pointers address path storage this struct exclusively owns,
// so they are valid wherever the value is. It adds no thread affinity of
// its own, leaving `F` and `T` to decide.
unsafe impl<F: Send, T: Send> Send for PreparedLink<F, T> {}

impl<F: StableBuffer, T: StableBuffer> PreparedLink<F, T> {
    /// Prepare `kind` from `old` to `new`.
    #[must_use]
    pub fn new(old: OwnedPath<F>, new: OwnedPath<T>, kind: LinkKind) -> Self {
        let old_addr = old.stable_ptr();
        let new_addr = new.stable_ptr();
        Self {
            old,
            new,
            kind,
            old_addr,
            new_addr,
        }
    }

    /// Create a symlink at `new`, relative to `new_dir`, containing `old`'s
    /// literal text.
    #[must_use]
    pub fn symlink_at(old: OwnedPath<F>, new_dir: DirFd, new: OwnedPath<T>) -> Self {
        Self::new(old, new, LinkKind::Symlink { new_dir })
    }

    /// Create a symlink at `new`, relative to the working directory,
    /// containing `old`'s literal text.
    #[must_use]
    pub fn symlink_cwd(old: OwnedPath<F>, new: OwnedPath<T>) -> Self {
        Self::symlink_at(old, DirFd::Cwd, new)
    }

    /// Create a hard link at `new` pointing to `old`'s inode, each
    /// resolved against its own directory.
    #[must_use]
    pub fn link_at(
        old_dir: DirFd,
        old: OwnedPath<F>,
        new_dir: DirFd,
        new: OwnedPath<T>,
        flags: LinkFlags,
    ) -> Self {
        Self::new(
            old,
            new,
            LinkKind::Link {
                old_dir,
                new_dir,
                flags,
            },
        )
    }

    /// Create a hard link, both paths relative to the working directory.
    #[must_use]
    pub fn link_cwd(old: OwnedPath<F>, new: OwnedPath<T>, flags: LinkFlags) -> Self {
        Self::link_at(DirFd::Cwd, old, DirFd::Cwd, new, flags)
    }

    /// Which operation this request performs.
    #[must_use]
    pub const fn kind(&self) -> LinkKind {
        self.kind
    }

    /// Borrow the source path before submission.
    #[must_use]
    pub const fn old(&self) -> &OwnedPath<F> {
        &self.old
    }

    /// Borrow the destination path before submission.
    #[must_use]
    pub const fn dest(&self) -> &OwnedPath<T> {
        &self.new
    }

    /// Give both path storages back, abandoning the operation.
    #[must_use]
    pub fn into_paths(self) -> (OwnedPath<F>, OwnedPath<T>) {
        (self.old, self.new)
    }

    /// Build the SQE and move to the pending state.
    pub(crate) fn into_pending(self, ring: RingId, id: RequestId) -> (Sqe, PendingLink<F, T>) {
        // SAFETY: both addresses were taken from path storage through
        // `StableBuffer`, and each `OwnedPath` proved a NUL lies within
        // its storage, so both kernel scans terminate inside memory this
        // request owns. Both storages move into `PendingLink`, whose
        // destructor is suppressed unless a receipt proves the kernel
        // finished.
        let sqe = unsafe { self.kind.sqe(self.old_addr, self.new_addr) };
        let pending = PendingLink {
            old: ManuallyDrop::new(self.old),
            new: ManuallyDrop::new(self.new),
            ring,
            id,
            kind: self.kind,
            old_addr: self.old_addr,
            new_addr: self.new_addr,
        };
        (sqe.user_data(id.raw()), pending)
    }
}

/// A submitted link operation whose two paths the kernel may be reading.
///
/// `Send` when both storages are, so the ticket can cross to a completion
/// thread like any other.
///
/// # Drop and `forget` both leak rather than free
///
/// Dropping this runs no destructor for either path storage, for the same
/// reason [`PendingRename`](super::PendingRename) does not: the kernel may
/// still be resolving those bytes.
#[must_use = "dropping the ticket leaks both path storages it owns"]
pub struct PendingLink<F, T> {
    old: ManuallyDrop<OwnedPath<F>>,
    new: ManuallyDrop<OwnedPath<T>>,
    ring: RingId,
    id: RequestId,
    kind: LinkKind,
    old_addr: *const u8,
    new_addr: *const u8,
}

// SAFETY: both pointers address path storage this ticket exclusively owns
// and keeps alive at fixed addresses, so moving the ticket to another
// thread keeps them valid; `F` and `T` decide whether that move is allowed.
unsafe impl<F: Send, T: Send> Send for PendingLink<F, T> {}

impl<F, T> PendingLink<F, T> {
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

    /// Which operation this request performs.
    #[must_use]
    pub const fn kind(&self) -> LinkKind {
        self.kind
    }

    /// Whether `receipt` authenticates this exact request.
    #[must_use]
    pub const fn matches(&self, receipt: &Receipt) -> bool {
        receipt.belongs_to(self.ring, self.id)
    }

    /// Take both path storages back without a receipt, undoing a failed
    /// push.
    ///
    /// # Safety
    ///
    /// The kernel must never have seen this request's SQE. Calling this
    /// after publication hands back storage the kernel may still read.
    pub(crate) unsafe fn reclaim_unsubmitted(self) -> PreparedLink<F, T> {
        let mut this = ManuallyDrop::new(self);
        // SAFETY: `this` is wrapped in `ManuallyDrop` so the no-op `Drop`
        // cannot observe the moved-out fields. The caller guarantees no
        // kernel-visible pointer to either storage exists.
        let (old, new) = unsafe {
            (
                ManuallyDrop::take(&mut this.old),
                ManuallyDrop::take(&mut this.new),
            )
        };
        PreparedLink {
            old,
            new,
            kind: this.kind,
            old_addr: this.old_addr,
            new_addr: this.new_addr,
        }
    }

    /// Trade a matching receipt for the result and both path storages.
    ///
    /// The receipt proves the kernel posted this request's completion and
    /// has stopped reading both paths, which is what makes returning the
    /// storage sound.
    ///
    /// # Errors
    ///
    /// Returns the ticket and receipt unchanged if the receipt belongs to
    /// another request or another ring.
    pub fn redeem(self, receipt: Receipt) -> Result<LinkCompleted<F, T>, (Self, Receipt)> {
        if !self.matches(&receipt) {
            return Err((self, receipt));
        }
        let mut this = ManuallyDrop::new(self);
        // SAFETY: `this` is wrapped in `ManuallyDrop`, so `Drop` will not
        // run and cannot observe the moved-out fields. The receipt proves
        // the kernel finished with both paths.
        let (old, new) = unsafe {
            (
                ManuallyDrop::take(&mut this.old),
                ManuallyDrop::take(&mut this.new),
            )
        };
        Ok(LinkCompleted {
            old,
            new,
            kind: this.kind,
            id: this.id,
            result: receipt.raw_result(),
        })
    }
}

impl<F, T> Drop for PendingLink<F, T> {
    fn drop(&mut self) {
        // Intentionally no `ManuallyDrop::drop`. See the type docs: the
        // kernel may still be reading both paths, so the storage leaks
        // rather than being freed underneath an in-flight request.
    }
}

/// A finished link operation: its result, and both path storages back.
pub struct LinkCompleted<F, T> {
    old: OwnedPath<F>,
    new: OwnedPath<T>,
    kind: LinkKind,
    id: RequestId,
    result: i32,
}

impl<F, T> LinkCompleted<F, T> {
    /// Identity of the request this completes.
    #[must_use]
    pub const fn id(&self) -> RequestId {
        self.id
    }

    /// Which operation was performed.
    #[must_use]
    pub const fn kind(&self) -> LinkKind {
        self.kind
    }

    /// Raw CQE result: `0` on success, `-errno` otherwise.
    #[must_use]
    pub const fn raw_result(&self) -> i32 {
        self.result
    }

    /// Whether the operation succeeded.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.result >= 0
    }

    /// Why the operation failed, if it did.
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

    /// Borrow the source path.
    #[must_use]
    pub const fn old(&self) -> &OwnedPath<F> {
        &self.old
    }

    /// Borrow the destination path.
    #[must_use]
    pub const fn dest(&self) -> &OwnedPath<T> {
        &self.new
    }

    /// Take both path storages back.
    #[must_use]
    pub fn into_paths(self) -> (OwnedPath<F>, OwnedPath<T>) {
        (self.old, self.new)
    }
}
