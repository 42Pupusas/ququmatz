//! Single-path directory-entry operations: `unlinkat` and `mkdirat`.
//!
//! Both resolve one path relative to a directory, change the directory
//! entry it names, and report only success or `-errno`. They own their
//! path storage exactly as [`PreparedOpen`](super::PreparedOpen) does, and
//! for the same reason: the kernel scans for the NUL after submission, so
//! no caller alias may survive.
//!
//! They share a type because they share a shape, not to save code. What
//! distinguishes them is one parameter each — a flag set for a removal, a
//! mode for a creation — which is what [`PathOpKind`] carries. The state
//! machine around it is identical, so duplicating it would mean two places
//! to get `ManuallyDrop` right instead of one.
//!
//! # Removing a directory is a different operation, not a flag
//!
//! `unlinkat` takes `AT_REMOVEDIR`, which looks like an option the caller
//! may set. It is not: the kernel refuses both mismatches.
//!
//! | target | flag | result |
//! |---|---|---|
//! | file | absent | removed |
//! | file | `REMOVEDIR` | `-ENOTDIR` |
//! | directory | absent | `-EISDIR` |
//! | directory | `REMOVEDIR` | removed |
//!
//! The flag is therefore determined by what is being removed rather than
//! chosen, so it is not exposed as a parameter. [`unlink_at`] removes a
//! non-directory and [`rmdir_at`] removes a directory, which makes the
//! only two working combinations the only two reachable ones.
//!
//! An `rmdir` also fails with `-ENOTEMPTY` on a directory that still has
//! entries — it removes one directory, never a tree.
//!
//! # `mkdirat`'s mode is a request, not a setting
//!
//! The mode is masked by the process umask, so it bounds the permissions
//! from above rather than setting them: asking for `0777` under the usual
//! `022` umask produces `0755`. Code that needs exact permissions must
//! `fchmod` afterwards, which no flag here can substitute for.
//!
//! [`unlink_at`]: PreparedPathOp::unlink_at
//! [`rmdir_at`]: PreparedPathOp::rmdir_at

use core::mem::ManuallyDrop;

use super::buffer::StableBuffer;
use super::identity::{RequestId, RingId};
use super::path::OwnedPath;
use super::request::Receipt;
use crate::op::Sqe;
use crate::types::{DirFd, FileMode, UnlinkFlags};

/// Which single-path operation a request performs.
///
/// Carries the one parameter that distinguishes them. Removals are split
/// by target because the kernel refuses the mismatched combinations — see
/// the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathOpKind {
    /// Remove a directory entry that is not a directory.
    Unlink,
    /// Remove an empty directory.
    Rmdir,
    /// Create a directory, with the mode the caller asked for.
    ///
    /// The mode is masked by the process umask, so the directory may end
    /// up with fewer permission bits than this names.
    Mkdir(FileMode),
}

impl PathOpKind {
    /// Build this kind's SQE against an already-validated path address.
    ///
    /// # Safety
    ///
    /// `addr` must point to a NUL-terminated path that stays valid and
    /// fixed until the kernel posts this request's completion.
    unsafe fn sqe(self, dir: DirFd, addr: *const u8) -> Sqe {
        // SAFETY: forwarded from this function's own contract.
        unsafe {
            match self {
                Self::Unlink => Sqe::unlinkat_ptr(dir.as_raw(), addr, UnlinkFlags::default()),
                Self::Rmdir => Sqe::unlinkat_ptr(dir.as_raw(), addr, UnlinkFlags::REMOVEDIR),
                Self::Mkdir(mode) => Sqe::mkdirat_ptr(dir.as_raw(), addr, mode),
            }
        }
    }
}

/// A single-path operation that owns its path storage, not yet queued.
pub struct PreparedPathOp<S> {
    path: OwnedPath<S>,
    dir: DirFd,
    kind: PathOpKind,
    /// Address of the path bytes, cached where the stability bound is in
    /// scope. Held as a pointer so the provenance reaches the SQE intact.
    addr: *const u8,
}

// SAFETY: `addr` points into the path storage this struct exclusively
// owns, so the pointer is valid wherever the value is. It adds no thread
// affinity of its own, leaving `S` to decide.
unsafe impl<S: Send> Send for PreparedPathOp<S> {}

impl<S: StableBuffer> PreparedPathOp<S> {
    /// Prepare `kind` against `path`, resolved relative to `dir`.
    #[must_use]
    pub fn new(dir: DirFd, path: OwnedPath<S>, kind: PathOpKind) -> Self {
        let addr = path.stable_ptr();
        Self {
            path,
            dir,
            kind,
            addr,
        }
    }

    /// Remove a non-directory entry, relative to `dir`.
    ///
    /// Fails with `EISDIR` if the path names a directory — use
    /// [`rmdir_at`](Self::rmdir_at) for those.
    #[must_use]
    pub fn unlink_at(dir: DirFd, path: OwnedPath<S>) -> Self {
        Self::new(dir, path, PathOpKind::Unlink)
    }

    /// Remove a non-directory entry, relative to the working directory.
    #[must_use]
    pub fn unlink_cwd(path: OwnedPath<S>) -> Self {
        Self::unlink_at(DirFd::Cwd, path)
    }

    /// Remove an empty directory, relative to `dir`.
    ///
    /// Fails with `ENOTDIR` if the path names a file, and with
    /// `ENOTEMPTY` if the directory still has entries.
    #[must_use]
    pub fn rmdir_at(dir: DirFd, path: OwnedPath<S>) -> Self {
        Self::new(dir, path, PathOpKind::Rmdir)
    }

    /// Remove an empty directory, relative to the working directory.
    #[must_use]
    pub fn rmdir_cwd(path: OwnedPath<S>) -> Self {
        Self::rmdir_at(DirFd::Cwd, path)
    }

    /// Create a directory, relative to `dir`.
    ///
    /// `mode` is masked by the process umask, so it is an upper bound on
    /// the permissions rather than the permissions themselves.
    #[must_use]
    pub fn mkdir_at(dir: DirFd, path: OwnedPath<S>, mode: FileMode) -> Self {
        Self::new(dir, path, PathOpKind::Mkdir(mode))
    }

    /// Create a directory, relative to the working directory.
    #[must_use]
    pub fn mkdir_cwd(path: OwnedPath<S>, mode: FileMode) -> Self {
        Self::mkdir_at(DirFd::Cwd, path, mode)
    }

    /// The directory this path resolves against.
    #[must_use]
    pub const fn dir(&self) -> DirFd {
        self.dir
    }

    /// Which operation this request performs.
    #[must_use]
    pub const fn kind(&self) -> PathOpKind {
        self.kind
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
    pub(crate) fn into_pending(self, ring: RingId, id: RequestId) -> (Sqe, PendingPathOp<S>) {
        // SAFETY: `addr` was taken from the path storage through
        // `StableBuffer`, so it is fixed for the owner's life, and
        // `OwnedPath` proved a NUL lies within that storage, so the
        // kernel's scan terminates inside memory this request owns. The
        // storage moves into `PendingPathOp`, whose destructor is
        // suppressed unless a receipt proves the kernel finished.
        let sqe = unsafe { self.kind.sqe(self.dir, self.addr) };
        let pending = PendingPathOp {
            path: ManuallyDrop::new(self.path),
            ring,
            id,
            dir: self.dir,
            kind: self.kind,
            addr: self.addr,
        };
        (sqe.user_data(id.raw()), pending)
    }
}

/// A submitted single-path operation whose path the kernel may be reading.
///
/// `Send` when its storage is, so the ticket can cross to a completion
/// thread like any other.
///
/// # Drop and `forget` both leak rather than free
///
/// Dropping this runs no destructor for the path storage. The kernel may
/// still be resolving those bytes, and nothing here can prove otherwise,
/// so the storage leaks on purpose — the same failure mode as every other
/// in-flight ticket. Unlike an open, no descriptor is lost with it: these
/// operations produce no resource, so the leak is bounded by the storage
/// the caller supplied.
#[must_use = "dropping the ticket leaks the path storage it owns"]
pub struct PendingPathOp<S> {
    path: ManuallyDrop<OwnedPath<S>>,
    ring: RingId,
    id: RequestId,
    dir: DirFd,
    kind: PathOpKind,
    addr: *const u8,
}

// SAFETY: `addr` points into the path storage this ticket exclusively owns
// and keeps alive at a fixed address, so moving the ticket to another
// thread keeps the pointer valid; `S` decides whether that move is allowed.
unsafe impl<S: Send> Send for PendingPathOp<S> {}

impl<S> PendingPathOp<S> {
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
    pub const fn kind(&self) -> PathOpKind {
        self.kind
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
    /// The kernel must never have seen this request's SQE. Calling this
    /// after publication hands back storage the kernel may still read.
    pub(crate) unsafe fn reclaim_unsubmitted(self) -> PreparedPathOp<S> {
        let mut this = ManuallyDrop::new(self);
        // SAFETY: `this` is wrapped in `ManuallyDrop` so the no-op `Drop`
        // cannot observe the moved-out field. The caller guarantees no
        // kernel-visible pointer to the storage exists.
        let path = unsafe { ManuallyDrop::take(&mut this.path) };
        PreparedPathOp {
            path,
            dir: this.dir,
            kind: this.kind,
            addr: this.addr,
        }
    }

    /// Trade a matching receipt for the result and the path storage.
    ///
    /// The receipt proves the kernel posted this request's completion and
    /// has stopped reading the path, which is what makes returning the
    /// storage sound.
    ///
    /// # Errors
    ///
    /// Returns the ticket and receipt unchanged if the receipt belongs to
    /// another request or another ring.
    pub fn redeem(self, receipt: Receipt) -> Result<PathOpCompleted<S>, (Self, Receipt)> {
        if !self.matches(&receipt) {
            return Err((self, receipt));
        }
        let mut this = ManuallyDrop::new(self);
        // SAFETY: `this` is wrapped in `ManuallyDrop`, so `Drop` will not
        // run and cannot observe the moved-out field. The receipt proves
        // the kernel finished with these bytes.
        let path = unsafe { ManuallyDrop::take(&mut this.path) };
        Ok(PathOpCompleted {
            path,
            kind: this.kind,
            id: this.id,
            result: receipt.raw_result(),
        })
    }
}

impl<S> Drop for PendingPathOp<S> {
    fn drop(&mut self) {
        // Intentionally no `ManuallyDrop::drop`. See the type docs: the
        // kernel may still be reading the path, so the storage leaks rather
        // than being freed underneath an in-flight request.
    }
}

/// A finished single-path operation: its result, and the path storage back.
pub struct PathOpCompleted<S> {
    path: OwnedPath<S>,
    kind: PathOpKind,
    id: RequestId,
    result: i32,
}

impl<S> PathOpCompleted<S> {
    /// Identity of the request this completes.
    #[must_use]
    pub const fn id(&self) -> RequestId {
        self.id
    }

    /// Which operation was performed.
    #[must_use]
    pub const fn kind(&self) -> PathOpKind {
        self.kind
    }

    /// Raw CQE result: `0` on success, `-errno` otherwise.
    ///
    /// These operations produce no value, so the result carries no
    /// information beyond whether it worked.
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

    /// Borrow the path that was operated on.
    #[must_use]
    pub const fn path(&self) -> &OwnedPath<S> {
        &self.path
    }

    /// Take the path storage back.
    #[must_use]
    pub fn into_path(self) -> OwnedPath<S> {
        self.path
    }
}
