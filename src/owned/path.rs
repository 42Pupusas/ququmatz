//! Address-stable, NUL-terminated path storage.
//!
//! Every other owned request hands the kernel a pointer *and* a length, so
//! the length is what stops it. A path has no length field anywhere in the
//! SQE: `openat` takes only an address, and the kernel reads forward until
//! it finds a NUL byte. The terminator is the entire bound.
//!
//! That makes an unterminated path a fundamentally different failure from a
//! short buffer. A wrong length reads the wrong number of bytes; a missing
//! NUL means the kernel keeps reading past the end of the allocation into
//! whatever follows, and either faults or opens a filename assembled from
//! unrelated memory. Neither is something the caller can detect afterwards
//! from the result.
//!
//! So termination is checked once, here, before the request can be built,
//! and [`OwnedPath`] exists to carry the proof. A [`PreparedOpen`] cannot be
//! constructed from raw bytes at all — only from an `OwnedPath` — which
//! makes "the kernel reads until NUL" a fact about the type rather than a
//! rule the caller has to remember.
//!
//! [`PreparedOpen`]: super::PreparedOpen

use super::buffer::{StableBuffer, StableBufferMut};

/// Why some bytes could not be used as a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathError {
    /// No NUL byte within the storage.
    ///
    /// The kernel would read past the end of the allocation looking for
    /// one, so the request is refused rather than submitted.
    NotTerminated,
    /// The path is empty — a NUL at index zero.
    ///
    /// `openat` reports `ENOENT` for this, so it is caught up front where
    /// the caller still has the storage back.
    Empty,
    /// The storage does not contain the requested number of bytes.
    TooLong {
        /// Bytes the path needs, including the NUL.
        needed: usize,
        /// Bytes the supplied storage has.
        got: usize,
    },
}

impl core::fmt::Display for PathError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotTerminated => write!(f, "path is not NUL-terminated"),
            Self::Empty => write!(f, "path is empty"),
            Self::TooLong { needed, got } => {
                write!(f, "path needs {needed} bytes, storage has {got}")
            }
        }
    }
}

/// Storage holding a verified NUL-terminated path.
///
/// Wraps any [`StableBuffer`], so the bytes keep one address while the
/// kernel resolves them — the same requirement every in-flight buffer has.
/// What this type adds is the guarantee the length field would normally
/// provide: a NUL exists within the storage, so the kernel's scan for the
/// terminator cannot run off the end.
///
/// The check happens at construction. Once an `OwnedPath` exists, the
/// property holds for its whole life, because the bytes are unreachable
/// afterwards — there is no `as_mut_slice` here, deliberately, since
/// writing through one could remove the NUL that makes it sound.
pub struct OwnedPath<S> {
    storage: S,
    /// Byte count up to but not including the NUL, established at
    /// construction and unchanging because the bytes cannot be mutated.
    len: usize,
}

impl<S: StableBufferMut> OwnedPath<S> {
    /// Copy `path` into `storage` and append the terminator.
    ///
    /// `path` must not already contain a NUL: an interior one would end the
    /// kernel's read early, so `"etc\0passwd"` would silently open `etc`.
    ///
    /// # Errors
    ///
    /// Returns the storage back with [`PathError::TooLong`] if it cannot
    /// hold `path` plus a NUL, [`PathError::Empty`] for an empty path, or
    /// [`PathError::NotTerminated`] if `path` contains an interior NUL.
    pub fn copy_into(mut storage: S, path: &[u8]) -> Result<Self, (S, PathError)> {
        if path.is_empty() {
            return Err((storage, PathError::Empty));
        }
        if path.contains(&0) {
            return Err((storage, PathError::NotTerminated));
        }
        let needed = path.len() + 1;
        let got = storage.stable_len();
        if got < needed {
            return Err((storage, PathError::TooLong { needed, got }));
        }
        let base = storage.stable_mut_ptr();
        // SAFETY: `storage` has at least `needed` bytes, checked above, and
        // owns them exclusively. `path` is a distinct borrow, so the copy
        // cannot overlap.
        unsafe {
            core::ptr::copy_nonoverlapping(path.as_ptr(), base, path.len());
            base.add(path.len()).write(0);
        }
        Ok(Self {
            storage,
            len: path.len(),
        })
    }
}

impl<S: StableBuffer> OwnedPath<S> {
    /// Adopt storage that already holds a NUL-terminated path.
    ///
    /// Scans for the terminator rather than trusting the caller, because
    /// the whole point of this type is that the scan happened.
    ///
    /// # Errors
    ///
    /// Returns the storage back with [`PathError::NotTerminated`] if no NUL
    /// is present, or [`PathError::Empty`] if the first byte is one.
    pub fn adopt(storage: S) -> Result<Self, (S, PathError)> {
        let len = storage.stable_len();
        // SAFETY: `StableBuffer` guarantees `stable_len` bytes are
        // allocated and readable at `stable_ptr` for the owner's life.
        let bytes = unsafe { core::slice::from_raw_parts(storage.stable_ptr(), len) };
        match bytes.iter().position(|b| *b == 0) {
            None => Err((storage, PathError::NotTerminated)),
            Some(0) => Err((storage, PathError::Empty)),
            Some(n) => Ok(Self { storage, len: n }),
        }
    }

    /// Path length in bytes, not counting the NUL.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Always `false` — an empty path is rejected at construction.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The path bytes, without the terminator.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: `len` bytes were verified to precede a NUL inside the
        // storage, which owns them at a fixed address for its whole life.
        unsafe { core::slice::from_raw_parts(self.storage.stable_ptr(), self.len) }
    }

    /// Address the kernel starts reading from.
    pub(crate) fn stable_ptr(&self) -> *const u8 {
        self.storage.stable_ptr()
    }

    /// Give the storage back, discarding the verification.
    #[must_use]
    pub fn into_storage(self) -> S {
        self.storage
    }
}
