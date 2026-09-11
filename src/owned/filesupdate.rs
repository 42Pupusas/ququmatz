//! `files_update`, whose result is a count and may stop half-way.
//!
//! Every other table operation reports `0` or `-errno`. This one reports
//! **how many slots it installed**, and that number can come back smaller
//! than what was asked for: an array of `[good, bad, good]` returns `1`,
//! having installed the first entry and abandoned the rest. The result is
//! positive, so the usual "non-negative means success" reading calls that
//! a success and a caller believes three slots are live when one is.
//!
//! [`Update`] therefore separates the three outcomes rather than handing
//! back a number:
//!
//! | outcome | result | meaning |
//! |---|---|---|
//! | [`All`](Update::All) | `n` == requested | every entry installed |
//! | [`Partial`](Update::Partial) | `0 < n` < requested | stopped at a bad entry |
//! | [`Failed`](Update::Failed) | `-errno` | nothing installed |
//!
//! A bad descriptor in *first* position reports `-EBADF` rather than `0`,
//! so `Partial` always means at least one slot changed. Which entry failed
//! is not reported by the kernel beyond the count, and the count is the
//! index of the first one that did not take.
//!
//! # The kernel duplicates, so the caller keeps its descriptors
//!
//! Measured against a real kernel: after an update the caller's original
//! descriptor is still open and usable, the registered slot reaches the
//! same file, and closing the original afterwards leaves the slot working.
//! The table holds its own reference.
//!
//! That is what lets this API take descriptors it does not own. An
//! operation that *consumed* them would have to accept [`File`] or
//! [`Socket`] by value to prevent a double close; because the kernel
//! duplicates, a [`RawFd`] is the honest argument type and the caller's
//! handles stay exactly as valid as they were.
//!
//! [`File`]: crate::fs::File
//! [`Socket`]: crate::net::Socket
//!
//! # Replacing an occupied slot is silent
//!
//! Updating a slot that already holds a file installs over it and reports
//! the same count as an install into an empty one. The file that was
//! there is released by the table; the *caller's* copy, if it kept one, is
//! untouched. Nothing in the completion says a slot was overwritten, which
//! is the same sharp edge [`SlotTarget::Exact`](super::SlotTarget::Exact)
//! has on a direct socket.
//!
//! # Clearing is an entry, not a sentinel
//!
//! The kernel reads `-1` as "empty this slot". [`TableEntry`] names that
//! rather than leaving a caller to write the magic number, so a stray `-1`
//! from arithmetic cannot be mistaken for a deliberate clear.

use core::mem::{ManuallyDrop, align_of, size_of};

use super::buffer::StableBufferMut;
use super::identity::{RequestId, RingId};
use super::request::Receipt;
use super::slot::SlotIndex;
use crate::error::Errno;
use crate::op::Sqe;
use crate::types::RawFd;

/// The value the kernel reads as "clear this slot".
const CLEAR: i32 = -1;

/// What one slot of a `files_update` should become.
///
/// A bare `i32` would make `-1` a magic value meaning "empty" rather than
/// a descriptor, which is a different intent and not a smaller number, so
/// the two are named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableEntry {
    /// Install this descriptor into the slot.
    ///
    /// The kernel duplicates it, so the caller keeps its own handle and
    /// may close it afterwards without disturbing the table.
    Install(RawFd),
    /// Empty the slot, releasing whatever the table held there.
    Clear,
}

impl TableEntry {
    /// The value the kernel reads from the array.
    #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
    const fn raw(self) -> i32 {
        match self {
            Self::Install(fd) => fd.as_i32(),
            Self::Clear => CLEAR,
        }
    }
}

/// How much of a `files_update` took effect.
///
/// The kernel's result is a count, not a status, and a count that is
/// positive but short is the case a `Result` would hide: some slots hold
/// what was asked for and the rest still hold whatever they held before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Update {
    /// Every entry was installed.
    All {
        /// Slots changed, equal to the number requested.
        count: u32,
    },
    /// The kernel stopped part-way through.
    ///
    /// The first `installed` entries took effect and the rest did not.
    /// The slots beyond that point still hold their previous contents,
    /// which may be files the caller believes it replaced.
    Partial {
        /// Slots that were changed, counting from `offset`.
        installed: u32,
        /// Slots the request named.
        requested: u32,
    },
    /// Nothing was installed.
    ///
    /// `EBADF` for a bad descriptor in first position, `EINVAL` for a
    /// range that leaves the table or an empty request, `ENXIO` when no
    /// file table is registered at all.
    Failed(Errno),
}

impl Update {
    /// Classify a raw result against what the request asked for.
    const fn from_raw(result: i32, requested: u32) -> Self {
        if result < 0 {
            return Self::Failed(Errno::new(-result));
        }
        #[allow(clippy::cast_sign_loss)]
        let installed = result as u32;
        if installed >= requested {
            Self::All { count: requested }
        } else {
            Self::Partial {
                installed,
                requested,
            }
        }
    }

    /// Classify a raw result directly, for tests that need an outcome the
    /// kernel is hard to coax into producing on demand.
    #[cfg(test)]
    pub(crate) const fn from_raw_for_test(result: i32, requested: u32) -> Self {
        Self::from_raw(result, requested)
    }

    /// Slots that actually changed.
    #[must_use]
    pub const fn installed(self) -> u32 {
        match self {
            Self::All { count } => count,
            Self::Partial { installed, .. } => installed,
            Self::Failed(_) => 0,
        }
    }

    /// Whether every entry the request named took effect.
    ///
    /// False for [`Partial`](Self::Partial), which a non-negative result
    /// would otherwise read as success.
    #[must_use]
    pub const fn is_complete(self) -> bool {
        matches!(self, Self::All { .. })
    }
}

impl core::fmt::Display for Update {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::All { count } => write!(f, "{count} slots updated"),
            Self::Partial {
                installed,
                requested,
            } => write!(f, "only {installed} of {requested} slots updated"),
            Self::Failed(e) => write!(f, "files_update failed: {e}"),
        }
    }
}

/// Why a `files_update` request could not be built.
///
/// Each hands the caller's storage back rather than consuming it, so a
/// rejected request never costs an allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesUpdateError {
    /// The storage cannot hold the descriptor array.
    StoreTooSmall {
        /// Bytes the array needs.
        needed: usize,
        /// Bytes the supplied storage has.
        got: usize,
    },
    /// The storage is not aligned for an `i32`.
    ///
    /// [`MmapBuffer`](super::MmapBuffer) is page-aligned and always
    /// satisfies this; a hand-written [`StableBufferMut`] might not.
    StoreMisaligned {
        /// Alignment the array requires.
        needed: usize,
    },
    /// The request names no slots.
    ///
    /// The kernel answers `EINVAL` for a zero-length update, so it is
    /// refused here with the storage intact rather than submitted.
    Empty,
}

impl core::fmt::Display for FilesUpdateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::StoreTooSmall { needed, got } => {
                write!(f, "descriptor array needs {needed} bytes, got {got}")
            }
            Self::StoreMisaligned { needed } => {
                write!(f, "descriptor array must be {needed}-byte aligned")
            }
            Self::Empty => f.write_str("a files_update must name at least one slot"),
        }
    }
}

/// A `files_update` that owns the array the kernel reads, not yet queued.
///
/// `N` slots starting at the offset this was built with. The descriptors
/// themselves are not owned — the kernel duplicates them — but the array
/// naming them is, because the kernel reads it after submission.
pub struct PreparedFilesUpdate<S, const N: usize> {
    store: S,
    entries: [TableEntry; N],
    offset: SlotIndex,
    /// Address of the published array, cached where the stability bound is
    /// in scope and checked for size and alignment before it was formed.
    addr: *mut i32,
}

// SAFETY: the pointer refers into storage this struct exclusively owns, so
// it stays valid wherever the value goes. The struct adds no thread
// affinity of its own, leaving `S` to decide.
unsafe impl<S: Send, const N: usize> Send for PreparedFilesUpdate<S, N> {}

impl<S: StableBufferMut, const N: usize> PreparedFilesUpdate<S, N> {
    /// Prepare an update of `N` slots starting at `offset`.
    ///
    /// Takes ownership of `store`, which the kernel reads the descriptor
    /// array from after submission, so no caller alias to it may survive.
    /// The descriptors inside `entries` are *not* taken: the kernel
    /// duplicates them and the caller's handles stay valid.
    ///
    /// # Errors
    ///
    /// Returns [`FilesUpdateError`] with the storage handed back if
    /// `store` is too small or misaligned for the array, or if `N` is 0.
    pub fn at(
        offset: SlotIndex,
        entries: [TableEntry; N],
        mut store: S,
    ) -> Result<Self, (S, FilesUpdateError)> {
        if N == 0 {
            return Err((store, FilesUpdateError::Empty));
        }
        let needed = size_of::<i32>() * N;
        let got = store.stable_len();
        if got < needed {
            return Err((store, FilesUpdateError::StoreTooSmall { needed, got }));
        }
        let base = store.stable_mut_ptr();
        let align = align_of::<i32>();
        // Checked on the address rather than by casting first: the cast is
        // only sound once this has passed.
        if !base.addr().is_multiple_of(align) {
            return Err((store, FilesUpdateError::StoreMisaligned { needed: align }));
        }
        // The alignment check above is what makes this cast well-defined.
        #[allow(clippy::cast_ptr_alignment)]
        let addr = base.cast::<i32>();
        let mut prepared = Self {
            store,
            entries,
            offset,
            addr,
        };
        prepared.publish();
        Ok(prepared)
    }
}

impl<S, const N: usize> PreparedFilesUpdate<S, N> {
    /// Write the descriptor array into the storage the kernel will read.
    ///
    /// Done at construction so the values are in place before any SQE can
    /// name them.
    fn publish(&mut self) {
        for (i, entry) in self.entries.iter().enumerate() {
            // SAFETY: `addr` was checked to have room for `N` `i32`s at a
            // properly aligned address, and points into storage this
            // request owns exclusively, so nothing else can observe the
            // write. No SQE naming it exists yet, so the kernel is not
            // reading concurrently.
            unsafe { self.addr.add(i).write(entry.raw()) };
        }
    }

    /// The first table slot this request writes.
    #[must_use]
    pub const fn offset(&self) -> SlotIndex {
        self.offset
    }

    /// The entries this request will install.
    #[must_use]
    pub const fn entries(&self) -> &[TableEntry; N] {
        &self.entries
    }

    /// How many slots this request names.
    ///
    /// Never zero: an empty update is rejected at construction because the
    /// kernel answers `EINVAL` for one.
    #[allow(clippy::cast_possible_truncation)]
    #[must_use]
    pub const fn slots(&self) -> u32 {
        N as u32
    }

    /// The array exactly as the kernel will read it.
    ///
    /// Reads back the published storage rather than rebuilding it, so it
    /// shows what was actually written.
    #[must_use]
    pub fn published(&self) -> [i32; N] {
        let mut seen = [0i32; N];
        for (i, slot) in seen.iter_mut().enumerate() {
            // SAFETY: `addr` points into storage this request owns and was
            // filled by `publish` at construction, so all `N` values are
            // initialised at properly aligned addresses.
            *slot = unsafe { self.addr.add(i).read() };
        }
        seen
    }

    /// Give the storage back, abandoning the request.
    #[must_use]
    pub fn into_store(self) -> S {
        self.store
    }

    /// Build the SQE and move to the pending state.
    pub(crate) fn into_pending(
        self,
        ring: RingId,
        id: RequestId,
    ) -> (Sqe, PendingFilesUpdate<S, N>) {
        // SAFETY: `addr` was checked to have room for `N` `i32`s at an
        // aligned address, filled by `publish`, and points into storage
        // this request owns exclusively. The length is this request's own
        // `N` rather than a caller value, so it cannot describe more than
        // was written. The storage moves into `PendingFilesUpdate`, whose
        // destructor is suppressed unless a receipt proves the kernel
        // finished.
        let sqe = unsafe {
            Sqe::files_update_ptr(self.addr.cast_const(), self.slots(), self.offset.get())
        };
        let pending = PendingFilesUpdate {
            store: ManuallyDrop::new(self.store),
            ring,
            id,
            entries: self.entries,
            offset: self.offset,
            addr: self.addr,
        };
        (sqe.user_data(id.raw()), pending)
    }
}

/// A submitted `files_update` whose array the kernel may be reading.
///
/// # Drop and `forget` both leak rather than free
///
/// Dropping this runs no destructor for the storage. The kernel may still
/// be reading the descriptor array, so it leaks on purpose — the same
/// failure mode as every other in-flight ticket.
///
/// No descriptor is lost with it: the kernel duplicates what it installs
/// and the caller's handles were never taken, so only the array storage
/// is at stake.
#[must_use = "dropping the ticket leaks the descriptor array"]
pub struct PendingFilesUpdate<S, const N: usize> {
    store: ManuallyDrop<S>,
    ring: RingId,
    id: RequestId,
    entries: [TableEntry; N],
    offset: SlotIndex,
    addr: *mut i32,
}

// SAFETY: the pointer refers into storage this ticket exclusively owns and
// keeps alive at a fixed address, so moving the ticket to another thread
// keeps it valid; `S` decides whether that move is allowed.
unsafe impl<S: Send, const N: usize> Send for PendingFilesUpdate<S, N> {}

impl<S, const N: usize> PendingFilesUpdate<S, N> {
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

    /// The first table slot this request writes.
    #[must_use]
    pub const fn offset(&self) -> SlotIndex {
        self.offset
    }

    /// Whether `receipt` authenticates this exact request.
    #[must_use]
    pub const fn matches(&self, receipt: &Receipt) -> bool {
        receipt.id().raw() == self.id.raw() && receipt.ring().raw() == self.ring.raw()
    }

    /// Take the storage back without a receipt, undoing a failed push.
    ///
    /// # Safety
    ///
    /// The kernel must never have seen this request's SQE. Calling this
    /// after publication hands back storage the kernel may still read.
    pub(crate) unsafe fn reclaim_unsubmitted(self) -> PreparedFilesUpdate<S, N> {
        let mut this = ManuallyDrop::new(self);
        // SAFETY: `this` is wrapped in `ManuallyDrop` so the no-op `Drop`
        // cannot observe the moved-out field. The caller guarantees no
        // kernel-visible pointer to the storage exists.
        let store = unsafe { ManuallyDrop::take(&mut this.store) };
        PreparedFilesUpdate {
            store,
            entries: this.entries,
            offset: this.offset,
            addr: this.addr,
        }
    }

    /// Trade a matching receipt for the outcome and the storage.
    ///
    /// The receipt proves the kernel posted this request's completion and
    /// has stopped reading the array, which is what makes returning it
    /// sound.
    ///
    /// # Errors
    ///
    /// Returns the ticket and receipt unchanged if the receipt belongs to
    /// another request or another ring.
    pub fn redeem(self, receipt: Receipt) -> Result<FilesUpdated<S, N>, (Self, Receipt)> {
        if !self.matches(&receipt) {
            return Err((self, receipt));
        }
        let mut this = ManuallyDrop::new(self);
        // SAFETY: `this` is wrapped in `ManuallyDrop`, so `Drop` will not
        // run and cannot observe the moved-out field. The receipt proves
        // the kernel finished with these bytes.
        let store = unsafe { ManuallyDrop::take(&mut this.store) };
        Ok(FilesUpdated {
            store,
            entries: this.entries,
            offset: this.offset,
            id: this.id,
            result: receipt.raw_result(),
        })
    }
}

impl<S, const N: usize> Drop for PendingFilesUpdate<S, N> {
    fn drop(&mut self) {
        // Intentionally no `ManuallyDrop::drop`. See the type docs: the
        // kernel may still be reading the descriptor array, so the storage
        // leaks rather than being freed underneath an in-flight request.
    }
}

/// A finished `files_update`: how much of it took, and the storage back.
pub struct FilesUpdated<S, const N: usize> {
    store: S,
    entries: [TableEntry; N],
    offset: SlotIndex,
    id: RequestId,
    result: i32,
}

impl<S, const N: usize> FilesUpdated<S, N> {
    /// Identity of the request this completes.
    #[must_use]
    pub const fn id(&self) -> RequestId {
        self.id
    }

    /// Raw CQE result: a count of installed slots, or `-errno`.
    ///
    /// Prefer [`update`](Self::update): a positive result here can still
    /// mean most of the request did not happen.
    #[must_use]
    pub const fn raw_result(&self) -> i32 {
        self.result
    }

    /// How much of the request took effect.
    #[allow(clippy::cast_possible_truncation)]
    #[must_use]
    pub const fn update(&self) -> Update {
        Update::from_raw(self.result, N as u32)
    }

    /// The first table slot this request wrote.
    #[must_use]
    pub const fn offset(&self) -> SlotIndex {
        self.offset
    }

    /// The entries the request named, whether or not each took effect.
    #[must_use]
    pub const fn entries(&self) -> &[TableEntry; N] {
        &self.entries
    }

    /// Take the storage back for reuse.
    #[must_use]
    pub fn into_store(self) -> S {
        self.store
    }

    /// Take the outcome and the storage together.
    #[must_use]
    pub fn into_parts(self) -> (Update, S) {
        (self.update(), self.store)
    }
}
