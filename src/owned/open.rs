//! `openat`, where the request reads a buffer and produces a descriptor.
//!
//! Every owned request so far transferred storage in one direction and got
//! the same storage back. An open is the first one whose *result* is itself
//! a resource: the path buffer goes in and comes back, but the completion
//! also carries a file descriptor that the kernel created and this process
//! now owns.
//!
//! That makes two independent things reclaimable from one completion, and
//! they fail differently. Losing the path buffer leaks memory. Losing the
//! descriptor leaks a slot in a table bounded by `RLIMIT_NOFILE`, which is
//! usually far smaller than memory — a loop that drops them stops being
//! able to open anything long before it runs out of RAM.
//!
//! So [`Opened::into_parts`] hands back both, and the descriptor arrives as
//! an owning [`File`] rather than a bare number, closing on drop if the
//! caller never looks at it.
//!
//! # The kernel reads until NUL
//!
//! `openat` takes an address with no length. The bound on the read is the
//! terminator, which is why the path must be an [`OwnedPath`] — a type that
//! cannot exist without one — rather than any [`StableBuffer`].

use core::mem::ManuallyDrop;

use super::buffer::StableBuffer;
use super::identity::{RequestId, RingId};
use super::path::OwnedPath;
use super::request::Receipt;
use crate::fs::File;
use crate::op::Sqe;
use crate::types::{DirFd, FileMode, OpenFlags, RawFd};

/// An open that owns its path storage but has not been queued yet.
pub struct PreparedOpen<S> {
    path: OwnedPath<S>,
    dir: DirFd,
    flags: OpenFlags,
    mode: FileMode,
    /// Address of the path bytes, cached where the stability bound is in
    /// scope. Held as a pointer so the provenance reaches the SQE intact.
    addr: *const u8,
}

// SAFETY: `addr` points into the path storage, which this struct
// exclusively owns, so the pointer is valid wherever the value is. It adds
// no thread affinity of its own, leaving `S` to decide.
unsafe impl<S: Send> Send for PreparedOpen<S> {}

impl<S: StableBuffer> PreparedOpen<S> {
    /// Prepare an open of `path` relative to `dir`.
    ///
    /// Takes ownership of the path storage: the kernel reads those bytes
    /// after submission, so no caller alias may survive.
    #[must_use]
    pub fn at(dir: DirFd, path: OwnedPath<S>, flags: OpenFlags, mode: FileMode) -> Self {
        let addr = path.stable_ptr();
        Self {
            path,
            dir,
            flags,
            mode,
            addr,
        }
    }

    /// Prepare an open relative to the current working directory.
    #[must_use]
    pub fn cwd(path: OwnedPath<S>, flags: OpenFlags, mode: FileMode) -> Self {
        Self::at(DirFd::Cwd, path, flags, mode)
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
    pub(crate) fn into_pending(self, ring: RingId, id: RequestId) -> (Sqe, PendingOpen<S>) {
        // SAFETY: `addr` was taken from the path storage through
        // `StableBuffer`, so it is fixed for the owner's life, and
        // `OwnedPath` proved a NUL lies within that storage, so the
        // kernel's scan terminates inside memory this request owns. The
        // storage moves into `PendingOpen`, whose destructor is suppressed
        // unless a receipt proves the kernel finished.
        let sqe = unsafe { Sqe::openat_ptr(self.dir.as_raw(), self.addr, self.flags, self.mode) };
        let pending = PendingOpen {
            path: ManuallyDrop::new(self.path),
            ring,
            id,
            dir: self.dir,
            flags: self.flags,
            mode: self.mode,
            addr: self.addr,
        };
        (sqe.user_data(id.raw()), pending)
    }
}

/// A submitted open whose path bytes the kernel may be reading.
///
/// `Send` when its storage is, so the ticket can cross to a completion
/// thread like any other.
///
/// # Drop and `forget` both leak rather than free
///
/// Dropping this runs no destructor for the path storage. The kernel may
/// still be resolving those bytes, and nothing here can prove otherwise, so
/// the storage leaks on purpose — the same failure mode as every other
/// in-flight ticket.
///
/// Abandoning one also loses the descriptor the open may have produced,
/// which is the more expensive half: it stays open with no owner until the
/// process exits.
pub struct PendingOpen<S> {
    path: ManuallyDrop<OwnedPath<S>>,
    ring: RingId,
    id: RequestId,
    dir: DirFd,
    flags: OpenFlags,
    mode: FileMode,
    addr: *const u8,
}

// SAFETY: `addr` points into the path storage this ticket exclusively owns
// and keeps alive at a fixed address, so moving the ticket to another
// thread keeps the pointer valid; `S` decides whether that move is allowed.
unsafe impl<S: Send> Send for PendingOpen<S> {}

impl<S> PendingOpen<S> {
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

    /// The directory this open resolves against.
    #[must_use]
    pub const fn dir(&self) -> DirFd {
        self.dir
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
    pub(crate) unsafe fn reclaim_unsubmitted(self) -> PreparedOpen<S> {
        let mut this = ManuallyDrop::new(self);
        // SAFETY: `this` is wrapped in `ManuallyDrop` so the no-op `Drop`
        // cannot observe the moved-out field. The caller guarantees no
        // kernel-visible pointer to the storage exists.
        let path = unsafe { ManuallyDrop::take(&mut this.path) };
        PreparedOpen {
            path,
            dir: this.dir,
            flags: this.flags,
            mode: this.mode,
            addr: this.addr,
        }
    }

    /// Trade a matching receipt for the opened file and the path storage.
    ///
    /// The receipt proves the kernel posted this request's completion and
    /// has stopped reading the path, which is what makes returning the
    /// storage sound.
    ///
    /// # Errors
    ///
    /// Returns the ticket and receipt unchanged if the receipt belongs to
    /// another request or another ring.
    pub fn redeem(self, receipt: Receipt) -> Result<Opened<S>, (Self, Receipt)> {
        if !self.matches(&receipt) {
            return Err((self, receipt));
        }
        let mut this = ManuallyDrop::new(self);
        // SAFETY: `this` is wrapped in `ManuallyDrop`, so `Drop` will not
        // run and cannot observe the moved-out field. The receipt proves
        // the kernel finished with these bytes.
        let path = unsafe { ManuallyDrop::take(&mut this.path) };
        let result = receipt.raw_result();
        Ok(Opened {
            path,
            file: Self::claim(result),
            id: this.id,
            result,
        })
    }

    /// Adopt the descriptor this completion opened, if it opened one.
    fn claim(result: i32) -> Option<File> {
        let fd = u32::try_from(result).ok()?;
        // SAFETY: a non-negative openat result is a descriptor the kernel
        // installed into this process. The CQE is reaped once, so nothing
        // else holds it and taking ownership here is the only claim.
        Some(unsafe { File::from_fd(RawFd::from_raw(fd as usize)) })
    }
}

impl<S> Drop for PendingOpen<S> {
    fn drop(&mut self) {
        // Intentionally no `ManuallyDrop::drop`. See the type docs: the
        // kernel may still be reading the path, so the storage leaks rather
        // than being freed underneath an in-flight request.
    }
}

/// A finished open: the file it produced, and the path storage back.
///
/// Both halves are reclaimable, and the file is the one that matters more —
/// descriptors are a scarcer resource than memory.
pub struct Opened<S> {
    path: OwnedPath<S>,
    file: Option<File>,
    id: RequestId,
    result: i32,
}

impl<S> Opened<S> {
    /// Identity of the request this completes.
    #[must_use]
    pub const fn id(&self) -> RequestId {
        self.id
    }

    /// Raw CQE result: a descriptor when non-negative, `-errno` otherwise.
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

    /// Borrow the opened file, if the open succeeded.
    #[must_use]
    pub const fn file(&self) -> Option<&File> {
        self.file.as_ref()
    }

    /// Borrow the path that was opened.
    #[must_use]
    pub const fn path(&self) -> &OwnedPath<S> {
        &self.path
    }

    /// Take the opened file, leaving the path storage behind.
    ///
    /// Prefer [`into_parts`](Self::into_parts) unless the storage is
    /// genuinely not wanted: this drops it.
    #[must_use]
    pub fn into_file(self) -> Option<File> {
        self.file
    }

    /// Take both the file and the path storage.
    ///
    /// Returns both rather than just the file, because dropping the storage
    /// silently would waste an allocation the caller supplied, and returns
    /// the file as an owning [`File`] so ignoring it closes the descriptor
    /// rather than leaking it.
    #[must_use]
    pub fn into_parts(self) -> (Option<File>, OwnedPath<S>) {
        (self.file, self.path)
    }
}
