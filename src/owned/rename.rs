//! `renameat2`, the first owned request that reads two paths.
//!
//! Every other path-bearing request hands the kernel one address to scan.
//! This one hands it two, in different SQE fields, and both must stay valid
//! and fixed until the completion — so the ticket owns two independent
//! storages and gives both back. That is the same shape
//! [`PreparedStatx`](super::PreparedStatx) has, except that there the
//! second region is written by the kernel and here it is read.
//!
//! # The destination directory travels in the length field
//!
//! `renameat2` needs four values but the SQE has one `fd`, so the kernel
//! reads the *new* directory descriptor out of `len`:
//!
//! ```text
//! ren->new_dfd = READ_ONCE(sqe->len);
//! ```
//!
//! That is why a cross-directory rename works at all, and it is worth
//! stating because `len` means "bytes to transfer" in every other request
//! in this module. Renaming between two open directories was measured to
//! confirm it, not assumed.
//!
//! # A plain rename destroys the destination without saying so
//!
//! With no flags, renaming onto an existing file replaces it: the old
//! contents are gone and the result is `0`, indistinguishable from a
//! rename onto a free name. Nothing in the completion reveals that
//! anything was overwritten.
//!
//! This is the same hazard an explicit
//! [`SlotTarget::Exact`](super::SlotTarget) has, and it gets the same
//! treatment — the destructive form is reachable but named. [`replace`]
//! overwrites, [`no_replace`] refuses with `-EEXIST`, and [`exchange`]
//! swaps the two entries atomically. There is no default, because the
//! difference between them is data loss.
//!
//! # The flags are alternatives, not a set
//!
//! `NOREPLACE` and `EXCHANGE` together are rejected with `-EINVAL`, so
//! [`RenameMode`] is an enum rather than a flag set: the combination that
//! cannot work is not representable.
//!
//! An exchange also requires *both* paths to exist, failing `-ENOENT`
//! otherwise, which makes it the one mode that is not a way of creating
//! the destination.
//!
//! [`replace`]: RenameMode::Replace
//! [`no_replace`]: RenameMode::NoReplace
//! [`exchange`]: RenameMode::Exchange

use core::mem::ManuallyDrop;

use super::buffer::StableBuffer;
use super::identity::{RequestId, RingId};
use super::path::OwnedPath;
use super::request::Receipt;
use crate::op::Sqe;
use crate::types::{DirFd, RenameFlags};

/// How a rename treats an existing destination.
///
/// An enum rather than flags because the kernel rejects `NOREPLACE` and
/// `EXCHANGE` together with `EINVAL`, and because there is no safe default
/// — see the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenameMode {
    /// Overwrite the destination if it exists, discarding it.
    ///
    /// Reports `0` whether or not anything was replaced, so a caller that
    /// needs to know must check beforehand — and that check races with
    /// anyone else touching the filesystem. Prefer
    /// [`NoReplace`](Self::NoReplace) when the destination is meant to be
    /// new.
    Replace,
    /// Fail with `EEXIST` if the destination already exists.
    ///
    /// The only mode that cannot destroy data, and the atomic form of
    /// "create this name if it is free".
    NoReplace,
    /// Atomically swap the two entries.
    ///
    /// Both paths must exist; otherwise the kernel reports `ENOENT`.
    Exchange,
}

impl RenameMode {
    /// The `renameat2` flags this mode submits with.
    fn flags(self) -> RenameFlags {
        match self {
            Self::Replace => RenameFlags::default(),
            Self::NoReplace => RenameFlags::NOREPLACE,
            Self::Exchange => RenameFlags::EXCHANGE,
        }
    }
}

/// A rename that owns both path storages but has not been queued yet.
pub struct PreparedRename<F, T> {
    from: OwnedPath<F>,
    to: OwnedPath<T>,
    from_dir: DirFd,
    to_dir: DirFd,
    mode: RenameMode,
    /// Addresses of both paths, cached where the stability bound is in
    /// scope. Held as pointers so the provenance reaches the SQE intact.
    from_addr: *const u8,
    to_addr: *const u8,
}

// SAFETY: both pointers address path storage this struct exclusively owns,
// so they are valid wherever the value is. It adds no thread affinity of
// its own, leaving `F` and `T` to decide.
unsafe impl<F: Send, T: Send> Send for PreparedRename<F, T> {}

impl<F: StableBuffer, T: StableBuffer> PreparedRename<F, T> {
    /// Prepare a rename from `from` to `to`, each relative to its own
    /// directory.
    ///
    /// Takes ownership of both path storages: the kernel reads both after
    /// submission, so no caller alias may survive.
    #[must_use]
    pub fn new(
        from_dir: DirFd,
        from: OwnedPath<F>,
        to_dir: DirFd,
        to: OwnedPath<T>,
        mode: RenameMode,
    ) -> Self {
        let from_addr = from.stable_ptr();
        let to_addr = to.stable_ptr();
        Self {
            from,
            to,
            from_dir,
            to_dir,
            mode,
            from_addr,
            to_addr,
        }
    }

    /// Prepare a rename with both paths relative to the working directory.
    #[must_use]
    pub fn cwd(from: OwnedPath<F>, to: OwnedPath<T>, mode: RenameMode) -> Self {
        Self::new(DirFd::Cwd, from, DirFd::Cwd, to, mode)
    }

    /// The directory the source path resolves against.
    #[must_use]
    pub const fn from_dir(&self) -> DirFd {
        self.from_dir
    }

    /// The directory the destination path resolves against.
    #[must_use]
    pub const fn to_dir(&self) -> DirFd {
        self.to_dir
    }

    /// How this rename treats an existing destination.
    #[must_use]
    pub const fn mode(&self) -> RenameMode {
        self.mode
    }

    /// Borrow the source path before submission.
    #[must_use]
    pub const fn from(&self) -> &OwnedPath<F> {
        &self.from
    }

    /// Borrow the destination path before submission.
    #[must_use]
    pub const fn to(&self) -> &OwnedPath<T> {
        &self.to
    }

    /// Give both path storages back, abandoning the operation.
    #[must_use]
    pub fn into_paths(self) -> (OwnedPath<F>, OwnedPath<T>) {
        (self.from, self.to)
    }

    /// Build the SQE and move to the pending state.
    pub(crate) fn into_pending(self, ring: RingId, id: RequestId) -> (Sqe, PendingRename<F, T>) {
        // SAFETY: both addresses were taken from path storage through
        // `StableBuffer`, so they are fixed for their owners' lives, and
        // each `OwnedPath` proved a NUL lies within its storage, so both
        // kernel scans terminate inside memory this request owns. Both
        // storages move into `PendingRename`, whose destructor is
        // suppressed unless a receipt proves the kernel finished.
        let sqe = unsafe {
            Sqe::renameat_ptr(
                self.from_dir.as_raw(),
                self.from_addr,
                self.to_dir.as_raw(),
                self.to_addr,
                self.mode.flags(),
            )
        };
        let pending = PendingRename {
            from: ManuallyDrop::new(self.from),
            to: ManuallyDrop::new(self.to),
            ring,
            id,
            from_dir: self.from_dir,
            to_dir: self.to_dir,
            mode: self.mode,
            from_addr: self.from_addr,
            to_addr: self.to_addr,
        };
        (sqe.user_data(id.raw()), pending)
    }
}

/// A submitted rename whose two paths the kernel may be reading.
///
/// `Send` when both storages are, so the ticket can cross to a completion
/// thread like any other.
///
/// # Drop and `forget` both leak rather than free
///
/// Dropping this runs no destructor for either path storage. The kernel
/// may still be resolving those bytes, and nothing here can prove
/// otherwise, so both leak on purpose — twice the storage of a single-path
/// request, and the same failure mode.
#[must_use = "dropping the ticket leaks both path storages it owns"]
pub struct PendingRename<F, T> {
    from: ManuallyDrop<OwnedPath<F>>,
    to: ManuallyDrop<OwnedPath<T>>,
    ring: RingId,
    id: RequestId,
    from_dir: DirFd,
    to_dir: DirFd,
    mode: RenameMode,
    from_addr: *const u8,
    to_addr: *const u8,
}

// SAFETY: both pointers address path storage this ticket exclusively owns
// and keeps alive at fixed addresses, so moving the ticket to another
// thread keeps them valid; `F` and `T` decide whether that move is allowed.
unsafe impl<F: Send, T: Send> Send for PendingRename<F, T> {}

impl<F, T> PendingRename<F, T> {
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

    /// How this rename treats an existing destination.
    #[must_use]
    pub const fn mode(&self) -> RenameMode {
        self.mode
    }

    /// Whether `receipt` authenticates this exact request.
    #[must_use]
    pub const fn matches(&self, receipt: &Receipt) -> bool {
        receipt.id().raw() == self.id.raw() && receipt.ring().raw() == self.ring.raw()
    }

    /// Take both path storages back without a receipt, undoing a failed
    /// push.
    ///
    /// # Safety
    ///
    /// The kernel must never have seen this request's SQE. Calling this
    /// after publication hands back storage the kernel may still read.
    pub(crate) unsafe fn reclaim_unsubmitted(self) -> PreparedRename<F, T> {
        let mut this = ManuallyDrop::new(self);
        // SAFETY: `this` is wrapped in `ManuallyDrop` so the no-op `Drop`
        // cannot observe the moved-out fields. The caller guarantees no
        // kernel-visible pointer to either storage exists.
        let (from, to) = unsafe {
            (
                ManuallyDrop::take(&mut this.from),
                ManuallyDrop::take(&mut this.to),
            )
        };
        PreparedRename {
            from,
            to,
            from_dir: this.from_dir,
            to_dir: this.to_dir,
            mode: this.mode,
            from_addr: this.from_addr,
            to_addr: this.to_addr,
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
    pub fn redeem(self, receipt: Receipt) -> Result<RenameCompleted<F, T>, (Self, Receipt)> {
        if !self.matches(&receipt) {
            return Err((self, receipt));
        }
        let mut this = ManuallyDrop::new(self);
        // SAFETY: `this` is wrapped in `ManuallyDrop`, so `Drop` will not
        // run and cannot observe the moved-out fields. The receipt proves
        // the kernel finished with both regions.
        let (from, to) = unsafe {
            (
                ManuallyDrop::take(&mut this.from),
                ManuallyDrop::take(&mut this.to),
            )
        };
        Ok(RenameCompleted {
            from,
            to,
            mode: this.mode,
            id: this.id,
            result: receipt.raw_result(),
        })
    }
}

impl<F, T> Drop for PendingRename<F, T> {
    fn drop(&mut self) {
        // Intentionally no `ManuallyDrop::drop`. See the type docs: the
        // kernel may still be reading both paths, so the storage leaks
        // rather than being freed underneath an in-flight request.
    }
}

/// A finished rename: its result, and both path storages back.
pub struct RenameCompleted<F, T> {
    from: OwnedPath<F>,
    to: OwnedPath<T>,
    mode: RenameMode,
    id: RequestId,
    result: i32,
}

impl<F, T> RenameCompleted<F, T> {
    /// Identity of the request this completes.
    #[must_use]
    pub const fn id(&self) -> RequestId {
        self.id
    }

    /// How the rename treated an existing destination.
    #[must_use]
    pub const fn mode(&self) -> RenameMode {
        self.mode
    }

    /// Raw CQE result: `0` on success, `-errno` otherwise.
    ///
    /// A success does not say whether anything was overwritten — see the
    /// module docs.
    #[must_use]
    pub const fn raw_result(&self) -> i32 {
        self.result
    }

    /// Whether the rename succeeded.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.result >= 0
    }

    /// Why the rename failed, if it did.
    ///
    /// `EEXIST` means [`RenameMode::NoReplace`] found the destination
    /// taken, which is the mode working as intended rather than an error
    /// in the usual sense.
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
    pub const fn from(&self) -> &OwnedPath<F> {
        &self.from
    }

    /// Borrow the destination path.
    #[must_use]
    pub const fn to(&self) -> &OwnedPath<T> {
        &self.to
    }

    /// Take both path storages back.
    #[must_use]
    pub fn into_paths(self) -> (OwnedPath<F>, OwnedPath<T>) {
        (self.from, self.to)
    }
}
