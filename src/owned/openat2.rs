//! `openat2`, where the kernel reads a second struct to learn what to open.
//!
//! [`PreparedOpen`](super::PreparedOpen) puts everything the kernel needs
//! into the SQE itself: flags in one field, mode in another. `openat2`
//! puts them in a `struct open_how` in *caller memory* and stores only its
//! address, so the kernel dereferences a second region to find out what
//! the request even is.
//!
//! That makes this the same hazard as the vectored descriptor array rather
//! than a variation on an open. A ticket is `Send` and is meant to be
//! moved to a completion thread, so an inline `OpenHow` would relocate the
//! exact bytes the kernel is about to read, and the request would open
//! something described by whatever now occupies that address. The struct
//! therefore needs the guarantee [`StableBuffer`] already encodes, so its
//! storage is supplied by the caller and checked for size and alignment
//! before the request can exist — the same shape [`PreparedVectored`] uses
//! for its array.
//!
//! [`PreparedVectored`]: super::PreparedVectored
//!
//! # Two regions in, one descriptor out
//!
//! So three things are reclaimable from one completion: the path storage,
//! the `open_how` storage, and the descriptor the kernel created. They
//! fail differently — losing either storage leaks memory, losing the
//! descriptor consumes a slot in a table bounded by `RLIMIT_NOFILE`, which
//! runs out first — so [`Opened2::into_parts`] hands back all three and
//! the descriptor arrives as an owning [`File`].
//!
//! # `openat2` validates what `openat` ignores
//!
//! The two are not the same call with a wider argument. `openat` discards
//! bits it does not recognise; `openat2` rejects them, and the differences
//! are measurable:
//!
//! | request | `openat` | `openat2` |
//! |---|---|---|
//! | `mode` set without `CREAT`/`TMPFILE` | ignored | `-EINVAL` |
//! | `mode` above `0o7777` | ignored | `-EINVAL` |
//! | unknown flag bit | ignored | `-EINVAL` |
//! | unknown `resolve` bit | n/a | `-EINVAL` |
//! | `how_size` not `size_of::<OpenHow>()` | n/a | `-EINVAL` / `-E2BIG` |
//!
//! Every one of those is a request that cannot succeed, so none of them is
//! reachable here. [`Openat2Mode`] pairs the mode with the flag that gives
//! it meaning, so a stray mode cannot be expressed; [`ResolveFlags`] is a
//! named-bit type, so an unknown resolve bit cannot be; and `how_size` is
//! written by this module rather than chosen.
//!
//! The umask still applies to whatever mode survives that, exactly as it
//! does for `mkdirat`: asking for `0o777` under the usual `022` umask
//! produces `0o755`. The mode bounds the permissions from above rather
//! than setting them.

use core::mem::{ManuallyDrop, align_of, size_of};

use super::buffer::{StableBuffer, StableBufferMut};
use super::identity::{RequestId, RingId};
use super::path::OwnedPath;
use super::request::Receipt;
use crate::fs::File;
use crate::op::Sqe;
use crate::types::{DirFd, FileMode, OpenFlags, OpenHow, RawFd, ResolveFlags};

/// Permission bits the kernel accepts in `open_how.mode`.
const MODE_BITS: u32 = 0o7777;

/// How a request supplies the creation mode.
///
/// `openat2` fails with `EINVAL` when `mode` is non-zero and the flags
/// include neither `CREAT` nor `TMPFILE`, so the mode is not an
/// independent parameter: it is meaningful only alongside the flag that
/// asks for a file to be created. This pairs the two so the rejected
/// combination cannot be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Openat2Mode {
    /// Open an existing file. The kernel is sent `mode == 0`.
    Existing,
    /// Create the file if it is absent, with `mode` as an upper bound.
    Create(FileMode),
    /// Create the file only if it is absent, failing with `EEXIST` if not.
    CreateNew(FileMode),
    /// Create an unnamed temporary file in the directory the path names.
    Tmpfile(FileMode),
}

impl Openat2Mode {
    /// The open flags this mode implies, beyond the caller's own.
    const fn flags(self) -> OpenFlags {
        match self {
            Self::Existing => OpenFlags::empty(),
            Self::Create(_) => OpenFlags::CREAT,
            Self::CreateNew(_) => OpenFlags::CREAT.union_const(OpenFlags::EXCL),
            Self::Tmpfile(_) => OpenFlags::TMPFILE,
        }
    }

    /// The mode bits sent to the kernel.
    const fn mode(self) -> FileMode {
        match self {
            Self::Existing => FileMode::empty(),
            Self::Create(mode) | Self::CreateNew(mode) | Self::Tmpfile(mode) => mode,
        }
    }
}

/// Why an `openat2` request could not be built.
///
/// Each hands the caller's storage back rather than consuming it, so a
/// rejected request never costs an allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Openat2Error {
    /// The `open_how` storage cannot hold a whole [`OpenHow`].
    ///
    /// The kernel reads `size_of::<OpenHow>()` bytes from this address, so
    /// a short region is a read past the end of the allocation rather than
    /// a truncated request.
    HowTooSmall {
        /// Bytes an `OpenHow` needs.
        needed: usize,
        /// Bytes the supplied storage has.
        got: usize,
    },
    /// The `open_how` storage is not aligned for [`OpenHow`].
    ///
    /// [`MmapBuffer`](super::MmapBuffer) is page-aligned and always
    /// satisfies this; a hand-written [`StableBufferMut`] might not.
    HowMisaligned {
        /// Alignment `OpenHow` requires.
        needed: usize,
    },
    /// The mode sets bits outside `0o7777`.
    ///
    /// `openat2` rejects these with `EINVAL`, unlike `openat` which
    /// silently masks them, so it is caught here with the storage intact.
    ModeOutsidePermissionBits {
        /// The bits that do not belong in a permission mode.
        stray: u32,
    },
}

impl core::fmt::Display for Openat2Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::HowTooSmall { needed, got } => {
                write!(f, "open_how storage needs {needed} bytes, got {got}")
            }
            Self::HowMisaligned { needed } => {
                write!(f, "open_how storage must be {needed}-byte aligned")
            }
            Self::ModeOutsidePermissionBits { stray } => {
                write!(f, "mode sets bits outside 0o7777: {stray:o}")
            }
        }
    }
}

/// An `openat2` that owns its path and `open_how` storage, not yet queued.
///
/// `S` holds the path bytes and `H` holds the `OpenHow`; the kernel reads
/// both after submission, so both are owned here and both come back from
/// [`Opened2::into_parts`].
pub struct PreparedOpenat2<S, H> {
    path: OwnedPath<S>,
    how_store: H,
    dir: DirFd,
    flags: OpenFlags,
    mode: Openat2Mode,
    resolve: ResolveFlags,
    /// Address of the path bytes, cached where the stability bound is in
    /// scope. Held as a pointer so the provenance reaches the SQE intact.
    path_addr: *const u8,
    /// Address of the `OpenHow` the kernel reads, cached for the same
    /// reason and checked for size and alignment before it was formed.
    how_addr: *mut OpenHow,
}

// SAFETY: both pointers refer into storage this struct exclusively owns, so
// they stay valid wherever the value goes. The struct adds no thread
// affinity of its own, leaving `S` and `H` to decide.
unsafe impl<S: Send, H: Send> Send for PreparedOpenat2<S, H> {}

impl<S: StableBuffer, H: StableBufferMut> PreparedOpenat2<S, H> {
    /// Prepare an `openat2` of `path` relative to `dir`.
    ///
    /// Takes ownership of the path and of `how_store`, which the kernel
    /// reads the request parameters from after submission, so no caller
    /// alias to either may survive.
    ///
    /// # Errors
    ///
    /// Returns [`Openat2Error`] with all the storage handed back if
    /// `how_store` is too small or misaligned for an [`OpenHow`], or if
    /// the mode sets bits outside `0o7777`.
    pub fn at(
        dir: DirFd,
        path: OwnedPath<S>,
        flags: OpenFlags,
        mode: Openat2Mode,
        resolve: ResolveFlags,
        mut how_store: H,
    ) -> Result<Self, (OwnedPath<S>, H, Openat2Error)> {
        let stray = mode.mode().bits() & !MODE_BITS;
        if stray != 0 {
            return Err((
                path,
                how_store,
                Openat2Error::ModeOutsidePermissionBits { stray },
            ));
        }
        let needed = size_of::<OpenHow>();
        let got = how_store.stable_len();
        if got < needed {
            return Err((path, how_store, Openat2Error::HowTooSmall { needed, got }));
        }
        let base = how_store.stable_mut_ptr();
        let align = align_of::<OpenHow>();
        // Checked on the address rather than by casting first: the cast is
        // only sound once this has passed.
        if !base.addr().is_multiple_of(align) {
            return Err((
                path,
                how_store,
                Openat2Error::HowMisaligned { needed: align },
            ));
        }
        let path_addr = path.stable_ptr();
        // The alignment check above is what makes this cast well-defined.
        #[allow(clippy::cast_ptr_alignment)]
        let how_addr = base.cast::<OpenHow>();
        let mut prepared = Self {
            path,
            how_store,
            dir,
            flags,
            mode,
            resolve,
            path_addr,
            how_addr,
        };
        prepared.publish_how();
        Ok(prepared)
    }

    /// Prepare an `openat2` relative to the current working directory.
    ///
    /// # Errors
    ///
    /// As [`at`](Self::at).
    pub fn cwd(
        path: OwnedPath<S>,
        flags: OpenFlags,
        mode: Openat2Mode,
        resolve: ResolveFlags,
        how_store: H,
    ) -> Result<Self, (OwnedPath<S>, H, Openat2Error)> {
        Self::at(DirFd::Cwd, path, flags, mode, resolve, how_store)
    }
}

impl<S, H> PreparedOpenat2<S, H> {
    /// Write the request parameters into the storage the kernel will read.
    ///
    /// Done at construction so the bytes are in place before any SQE can
    /// name them, and repeated by the setters so the storage never
    /// disagrees with the request that owns it.
    fn publish_how(&mut self) {
        let how = OpenHow {
            flags: u64::from(self.flags.bits() | self.mode.flags().bits()),
            mode: u64::from(self.mode.mode().bits()),
            resolve: self.resolve.bits(),
        };
        // SAFETY: `how_addr` was checked for size and alignment against
        // `OpenHow` and points into storage this request owns exclusively,
        // so nothing else can observe the write. No SQE naming it exists
        // yet, so the kernel is not reading concurrently.
        unsafe { self.how_addr.write(how) }
    }

    /// The directory this open resolves against.
    #[must_use]
    pub const fn dir(&self) -> DirFd {
        self.dir
    }

    /// The caller-supplied flags, without the bits the mode implies.
    #[must_use]
    pub const fn flags(&self) -> OpenFlags {
        self.flags
    }

    /// How this request supplies its creation mode.
    #[must_use]
    pub const fn mode(&self) -> Openat2Mode {
        self.mode
    }

    /// The path-resolution restrictions this request was prepared with.
    #[must_use]
    pub const fn resolve(&self) -> ResolveFlags {
        self.resolve
    }

    /// The `open_how` exactly as the kernel will read it.
    ///
    /// Reads back the published storage rather than rebuilding it, so it
    /// shows what was actually written.
    #[must_use]
    pub const fn published_how(&self) -> OpenHow {
        // SAFETY: `how_addr` points into storage this request owns and was
        // written by `publish_how` at construction, so it holds an
        // initialised `OpenHow` at a properly aligned address.
        unsafe { self.how_addr.read() }
    }

    /// Borrow the path before submission.
    #[must_use]
    pub const fn path(&self) -> &OwnedPath<S> {
        &self.path
    }

    /// Give both pieces of storage back, abandoning the request.
    #[must_use]
    pub fn into_parts(self) -> (OwnedPath<S>, H) {
        (self.path, self.how_store)
    }

    /// Build the SQE and move to the pending state.
    pub(crate) fn into_pending(self, ring: RingId, id: RequestId) -> (Sqe, PendingOpenat2<S, H>) {
        // SAFETY: `path_addr` came from the path storage through
        // `StableBuffer`, and `OwnedPath` proved a NUL lies within it, so
        // the kernel's scan terminates inside memory this request owns.
        // `how_addr` was checked for size and alignment against `OpenHow`,
        // written by `publish_how`, and points into storage this request
        // owns exclusively. The length is this crate's own `size_of`
        // rather than a caller value, which is what the kernel validates
        // the struct against. Both storages move into `PendingOpenat2`,
        // whose destructor is suppressed unless a receipt proves the
        // kernel finished.
        let sqe = unsafe {
            Sqe::openat2_ptr(
                self.dir.as_raw(),
                self.path_addr,
                self.how_addr.cast_const(),
                Self::HOW_SIZE,
            )
        };
        let pending = PendingOpenat2 {
            path: ManuallyDrop::new(self.path),
            how_store: ManuallyDrop::new(self.how_store),
            ring,
            id,
            dir: self.dir,
            flags: self.flags,
            mode: self.mode,
            resolve: self.resolve,
            path_addr: self.path_addr,
            how_addr: self.how_addr,
        };
        (sqe.user_data(id.raw()), pending)
    }

    /// Size the kernel is told the `open_how` is.
    ///
    /// Not a caller parameter: the kernel returns `EINVAL` below its own
    /// known size and `E2BIG` above it, so the only correct value is this
    /// crate's `size_of`.
    #[allow(clippy::cast_possible_truncation)]
    const HOW_SIZE: u32 = size_of::<OpenHow>() as u32;
}

/// A submitted `openat2` whose storage the kernel may be reading.
///
/// `Send` when both storages are, so the ticket can cross to a completion
/// thread like any other.
///
/// # Drop and `forget` both leak rather than free
///
/// Dropping this runs no destructor for either storage. The kernel may
/// still be resolving the path or reading the `open_how`, and nothing here
/// can prove otherwise, so both leak on purpose — the same failure mode as
/// every other in-flight ticket.
///
/// Abandoning one also loses the descriptor the open may have produced,
/// which is the more expensive half: it stays open with no owner until the
/// process exits.
#[must_use = "dropping the ticket leaks both storages and any descriptor it opened"]
pub struct PendingOpenat2<S, H> {
    path: ManuallyDrop<OwnedPath<S>>,
    how_store: ManuallyDrop<H>,
    ring: RingId,
    id: RequestId,
    dir: DirFd,
    flags: OpenFlags,
    mode: Openat2Mode,
    resolve: ResolveFlags,
    path_addr: *const u8,
    how_addr: *mut OpenHow,
}

// SAFETY: both pointers refer into storage this ticket exclusively owns and
// keeps alive at fixed addresses, so moving the ticket to another thread
// keeps them valid; `S` and `H` decide whether that move is allowed.
unsafe impl<S: Send, H: Send> Send for PendingOpenat2<S, H> {}

impl<S, H> PendingOpenat2<S, H> {
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

    /// How this request supplies its creation mode.
    #[must_use]
    pub const fn mode(&self) -> Openat2Mode {
        self.mode
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
    /// after publication hands back storage the kernel may still read.
    pub(crate) unsafe fn reclaim_unsubmitted(self) -> PreparedOpenat2<S, H> {
        let mut this = ManuallyDrop::new(self);
        // SAFETY: `this` is wrapped in `ManuallyDrop` so the no-op `Drop`
        // cannot observe the moved-out fields. The caller guarantees no
        // kernel-visible pointer to either storage exists.
        let (path, how_store) = unsafe {
            (
                ManuallyDrop::take(&mut this.path),
                ManuallyDrop::take(&mut this.how_store),
            )
        };
        PreparedOpenat2 {
            path,
            how_store,
            dir: this.dir,
            flags: this.flags,
            mode: this.mode,
            resolve: this.resolve,
            path_addr: this.path_addr,
            how_addr: this.how_addr,
        }
    }

    /// Trade a matching receipt for the opened file and both storages.
    ///
    /// The receipt proves the kernel posted this request's completion and
    /// has stopped reading both regions, which is what makes returning
    /// them sound.
    ///
    /// # Errors
    ///
    /// Returns the ticket and receipt unchanged if the receipt belongs to
    /// another request or another ring.
    pub fn redeem(self, receipt: Receipt) -> Result<Opened2<S, H>, (Self, Receipt)> {
        if !self.matches(&receipt) {
            return Err((self, receipt));
        }
        let mut this = ManuallyDrop::new(self);
        // SAFETY: `this` is wrapped in `ManuallyDrop`, so `Drop` will not
        // run and cannot observe the moved-out fields. The receipt proves
        // the kernel finished with both regions.
        let (path, how_store) = unsafe {
            (
                ManuallyDrop::take(&mut this.path),
                ManuallyDrop::take(&mut this.how_store),
            )
        };
        let result = receipt.raw_result();
        Ok(Opened2 {
            path,
            how_store,
            file: Self::claim(result),
            id: this.id,
            result,
        })
    }

    /// Adopt the descriptor this completion opened, if it opened one.
    fn claim(result: i32) -> Option<File> {
        let fd = u32::try_from(result).ok()?;
        // SAFETY: a non-negative openat2 result is a descriptor the kernel
        // installed into this process. The CQE is reaped once, so nothing
        // else holds it and taking ownership here is the only claim.
        Some(unsafe { File::from_fd(RawFd::from_raw(fd as usize)) })
    }
}

impl<S, H> Drop for PendingOpenat2<S, H> {
    fn drop(&mut self) {
        // Intentionally no `ManuallyDrop::drop`. See the type docs: the
        // kernel may still be reading the path or the `open_how`, so both
        // leak rather than being freed underneath an in-flight request.
    }
}

/// A finished `openat2`: the file it produced, and both storages back.
///
/// All three are reclaimable, and the file is the one that matters most —
/// descriptors are a scarcer resource than memory.
pub struct Opened2<S, H> {
    path: OwnedPath<S>,
    how_store: H,
    file: Option<File>,
    id: RequestId,
    result: i32,
}

impl<S, H> Opened2<S, H> {
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

    /// Take the opened file, leaving both storages behind.
    ///
    /// Prefer [`into_parts`](Self::into_parts) unless the storage is
    /// genuinely not wanted: this drops it.
    #[must_use]
    pub fn into_file(self) -> Option<File> {
        self.file
    }

    /// Take the file and both storages.
    ///
    /// Returns all three rather than just the file, because dropping the
    /// storage silently would waste allocations the caller supplied, and
    /// returns the file as an owning [`File`] so ignoring it closes the
    /// descriptor rather than leaking it.
    #[must_use]
    pub fn into_parts(self) -> (Option<File>, OwnedPath<S>, H) {
        (self.file, self.path, self.how_store)
    }
}
