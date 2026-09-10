//! Vectored I/O, where the kernel reads a second array to find the first.
//!
//! A scalar [`Prepared`](super::Prepared) hands the kernel one pointer. A
//! vectored one hands it a pointer to an **array of `IoVec`**, and the
//! kernel dereferences that array to reach the data. So there are two
//! separate things the kernel touches, and both must stay put for the whole
//! operation — the buffers *and* the descriptor array naming them.
//!
//! The buffers are the easy half. [`StableBuffer`] already promises the
//! bytes never move even when the owner does, so `[B; N]` can sit inline in
//! the ticket: moving the ticket moves `N` owners, not `N * len` bytes.
//!
//! The array is the trap. It cannot live inline in the ticket, because a
//! [`Pending`](super::Pending) is deliberately `Send` and is *expected* to
//! be moved to a completion thread — and moving an inline array would
//! relocate the exact bytes the kernel is about to read, leaving it
//! following a pointer to a dead stack slot. Nothing in the type system
//! would notice: the request would still compile, still submit, and read or
//! write whatever now occupies that address.
//!
//! The array therefore needs precisely the guarantee `StableBuffer` already
//! encodes, so it is expressed with the same trait rather than a new one.
//! The caller supplies storage for it — usually an
//! [`MmapBuffer`](super::MmapBuffer) — which is checked for size and
//! alignment up front and handed back with the buffers at the end, so one
//! allocation can serve many requests.

use core::mem::{ManuallyDrop, align_of, size_of};

use super::buffer::{StableBuffer, StableBufferMut};
use super::identity::{RequestId, RingId};
use super::request::{Direction, Receipt};
use crate::error::{Error, InvalidArgKind, SetupError};
use crate::op::Sqe;
use crate::types::{IoVec, RawFd};

/// Why a vectored request could not be built.
///
/// Each returns the caller's storage rather than consuming it, so a
/// rejected request never costs a buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VectoredError {
    /// The descriptor storage is too small to hold `N` `IoVec`s.
    ArrayTooSmall {
        /// Bytes the array needs.
        needed: usize,
        /// Bytes the supplied storage has.
        got: usize,
    },
    /// The descriptor storage is not aligned for `IoVec`.
    ///
    /// [`MmapBuffer`](super::MmapBuffer) is page-aligned and always
    /// satisfies this; a hand-written [`StableBuffer`] might not.
    ArrayMisaligned {
        /// Alignment `IoVec` requires.
        needed: usize,
    },
}

impl From<VectoredError> for Error {
    fn from(_: VectoredError) -> Self {
        Self::Setup(SetupError::InvalidArg(InvalidArgKind::BufferSizeZero))
    }
}

impl core::fmt::Display for VectoredError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ArrayTooSmall { needed, got } => {
                write!(f, "iovec array needs {needed} bytes, got {got}")
            }
            Self::ArrayMisaligned { needed } => {
                write!(f, "iovec array must be {needed}-byte aligned")
            }
        }
    }
}

/// A vectored operation that owns its buffers but has not been queued yet.
///
/// `B` is the data storage, `N` of them; `V` is the storage for the `IoVec`
/// array that names them. Both are owned here, and both come back together
/// from [`VectoredCompleted::into_parts`].
pub struct PreparedVectored<B, V, const N: usize> {
    bufs: [B; N],
    vecs: V,
    fd: RawFd,
    offset: u64,
    direction: Direction,
    /// Address of the `IoVec` array inside `vecs`, cached where the
    /// stability bound is in scope. Kept as a pointer so the provenance
    /// reaches the SQE intact.
    array: *mut IoVec,
}

// SAFETY: `array` points into `vecs`, which this struct exclusively owns,
// so the pointer is valid wherever the value is. It adds no thread
// affinity of its own, leaving `B` and `V` to decide.
unsafe impl<B: Send, V: Send, const N: usize> Send for PreparedVectored<B, V, N> {}

impl<B: StableBufferMut, V: StableBufferMut, const N: usize> PreparedVectored<B, V, N> {
    /// Prepare a scatter read: one `fd`, `N` buffers filled in order.
    ///
    /// Takes ownership of every buffer and of the descriptor storage.
    ///
    /// # Errors
    ///
    /// Returns [`VectoredError`] with all the storage handed back if `vecs`
    /// is too small or misaligned for `N` descriptors.
    pub fn readv(
        fd: RawFd,
        mut bufs: [B; N],
        vecs: V,
        offset: u64,
    ) -> Result<Self, ([B; N], V, VectoredError)> {
        let mut lens = [0usize; N];
        for (slot, buf) in lens.iter_mut().zip(bufs.iter_mut()) {
            *slot = buf.stable_len();
        }
        Self::build(fd, bufs, vecs, offset, Direction::Read, &lens)
    }
}

impl<B: StableBuffer, V: StableBufferMut, const N: usize> PreparedVectored<B, V, N> {
    /// Prepare a gather write: `N` buffers written to `fd` in order.
    ///
    /// Each descriptor covers its buffer's whole length; use
    /// [`with_lens`](Self::with_lens) to send less than that.
    ///
    /// # Errors
    ///
    /// Returns [`VectoredError`] with all the storage handed back if `vecs`
    /// is too small or misaligned for `N` descriptors.
    pub fn writev(
        fd: RawFd,
        bufs: [B; N],
        vecs: V,
        offset: u64,
    ) -> Result<Self, ([B; N], V, VectoredError)> {
        let mut lens = [0usize; N];
        for (slot, buf) in lens.iter_mut().zip(bufs.iter()) {
            *slot = buf.stable_len();
        }
        Self::build(fd, bufs, vecs, offset, Direction::Write, &lens)
    }

    /// Shorten each descriptor to the matching entry in `lens`.
    ///
    /// A buffer's capacity and its useful contents are different things: a
    /// 64-byte buffer holding a 5-byte message should write 5 bytes. Each
    /// length is clamped to its buffer, so this can never describe more
    /// memory than the owner actually has.
    #[must_use]
    pub fn with_lens(mut self, lens: [usize; N]) -> Self {
        let mut clamped = [0usize; N];
        for ((slot, want), buf) in clamped.iter_mut().zip(lens.iter()).zip(self.bufs.iter()) {
            *slot = (*want).min(buf.stable_len());
        }
        self.write_array(&clamped);
        self
    }

    fn build(
        fd: RawFd,
        bufs: [B; N],
        mut vecs: V,
        offset: u64,
        direction: Direction,
        lens: &[usize; N],
    ) -> Result<Self, ([B; N], V, VectoredError)> {
        let needed = size_of::<IoVec>() * N;
        let got = vecs.stable_len();
        if got < needed {
            return Err((bufs, vecs, VectoredError::ArrayTooSmall { needed, got }));
        }
        let base = vecs.stable_mut_ptr();
        // Checked on the address rather than by casting first: producing a
        // misaligned `*mut IoVec` at all is what the cast would do, and the
        // point here is to never reach that state.
        if !base.addr().is_multiple_of(align_of::<IoVec>()) {
            return Err((
                bufs,
                vecs,
                VectoredError::ArrayMisaligned {
                    needed: align_of::<IoVec>(),
                },
            ));
        }
        let mut prepared = Self {
            bufs,
            vecs,
            fd,
            offset,
            direction,
            // The alignment was just verified, so this cast cannot produce
            // a pointer that is invalid to write through.
            #[allow(clippy::cast_ptr_alignment)]
            array: base.cast::<IoVec>(),
        };
        prepared.write_array(lens);
        Ok(prepared)
    }

    /// Stamp the descriptor array with each buffer's address and length.
    fn write_array(&mut self, lens: &[usize; N]) {
        for (i, (buf, len)) in self.bufs.iter().zip(lens.iter()).enumerate() {
            // SAFETY: `array` was checked to be aligned and to have room
            // for `N` descriptors, and `i < N`. The address comes from
            // `StableBuffer`, so it stays valid for as long as this value
            // owns the buffer — which outlasts the kernel's access.
            unsafe {
                self.array
                    .add(i)
                    .write(IoVec::new(buf.stable_ptr().cast_mut(), *len));
            }
        }
    }

    /// Total bytes across every descriptor.
    #[must_use]
    pub fn total_len(&self) -> usize {
        (0..N)
            // SAFETY: `array` holds `N` initialised descriptors, written by
            // `write_array` before this value was handed out.
            .map(|i| unsafe { (*self.array.add(i)).len() })
            .sum()
    }

    /// Direction the kernel will access the buffers.
    #[must_use]
    pub const fn direction(&self) -> Direction {
        self.direction
    }

    /// The file this operation targets.
    #[must_use]
    pub const fn fd(&self) -> RawFd {
        self.fd
    }

    /// How many buffers this operation covers.
    #[must_use]
    pub const fn count(&self) -> usize {
        N
    }

    /// Borrow the buffers before submission.
    #[must_use]
    pub const fn buffers(&self) -> &[B; N] {
        &self.bufs
    }

    /// Mutate the buffers before submission — the usual way to fill a
    /// gather write.
    #[must_use]
    pub const fn buffers_mut(&mut self) -> &mut [B; N] {
        &mut self.bufs
    }

    /// Give everything back, abandoning the operation.
    #[must_use]
    pub fn into_parts(self) -> ([B; N], V) {
        (self.bufs, self.vecs)
    }

    /// Build the SQE and move to the pending state.
    pub(crate) fn into_pending(
        self,
        ring: RingId,
        id: RequestId,
    ) -> (Sqe, PendingVectored<B, V, N>) {
        #[allow(clippy::cast_possible_truncation)]
        let nr = N as u32;
        let sqe = match self.direction {
            // SAFETY: `array` points at `N` descriptors inside `self.vecs`,
            // each naming a buffer owned by `self.bufs`. Both move into the
            // returned `PendingVectored`, which suppresses their destructors
            // unless a receipt proves the kernel finished, so every address
            // the kernel holds outlives its access.
            Direction::Read => unsafe { Sqe::readv_ptr(self.fd, self.array, nr, self.offset) },
            // SAFETY: as above; the kernel only reads here.
            Direction::Write => unsafe { Sqe::writev_ptr(self.fd, self.array, nr, self.offset) },
        };
        let pending = PendingVectored {
            bufs: ManuallyDrop::new(self.bufs),
            vecs: ManuallyDrop::new(self.vecs),
            ring,
            id,
            fd: self.fd,
            offset: self.offset,
            direction: self.direction,
            array: self.array,
        };
        (sqe.user_data(id.raw()), pending)
    }
}

/// A submitted vectored operation whose storage the kernel may be using.
///
/// Like [`Pending`](super::Pending), the buffers are unreachable while the
/// kernel may touch them, and dropping or [`forget`](core::mem::forget)ting
/// this leaks rather than frees — here it leaks the descriptor array too,
/// since the kernel is reading that as well.
pub struct PendingVectored<B, V, const N: usize> {
    bufs: ManuallyDrop<[B; N]>,
    vecs: ManuallyDrop<V>,
    ring: RingId,
    id: RequestId,
    /// Carried so a rejected push can be handed back aimed where the caller
    /// aimed it. Reconstructing a request with a default target would
    /// silently retarget a retry at fd 0.
    fd: RawFd,
    offset: u64,
    direction: Direction,
    array: *mut IoVec,
}

// SAFETY: `array` points into `vecs`, which this ticket exclusively owns
// and keeps at a fixed address for its whole life, so moving the ticket
// between threads leaves the kernel's pointer valid.
unsafe impl<B: Send, V: Send, const N: usize> Send for PendingVectored<B, V, N> {}

impl<B, V, const N: usize> PendingVectored<B, V, N> {
    /// Identity the kernel echoes back in this operation's CQE.
    #[must_use]
    pub const fn id(&self) -> RequestId {
        self.id
    }

    /// Identity of the queue that accepted this request.
    #[must_use]
    pub const fn ring(&self) -> RingId {
        self.ring
    }

    /// Direction the kernel accesses the buffers.
    #[must_use]
    pub const fn direction(&self) -> Direction {
        self.direction
    }

    /// The file this operation targets.
    #[must_use]
    pub const fn fd(&self) -> RawFd {
        self.fd
    }

    /// How many buffers this operation covers.
    #[must_use]
    pub const fn count(&self) -> usize {
        N
    }

    /// Whether `receipt` authenticates this exact request.
    #[must_use]
    pub const fn matches(&self, receipt: &Receipt) -> bool {
        receipt.id().raw() == self.id.raw() && receipt.ring().raw() == self.ring.raw()
    }

    /// Exchange a receipt for the storage and the kernel's result.
    ///
    /// # Errors
    ///
    /// Returns the ticket and the receipt unchanged if the receipt names a
    /// different request or a different ring.
    pub fn redeem(self, receipt: Receipt) -> Result<VectoredCompleted<B, V, N>, (Self, Receipt)> {
        if !self.matches(&receipt) {
            return Err((self, receipt));
        }
        let mut this = ManuallyDrop::new(self);
        // SAFETY: the receipt proves the kernel posted this request's
        // terminal completion, so it holds no pointer into either owner.
        // `this` is wrapped in `ManuallyDrop`, so taking both fields cannot
        // double-drop them.
        let (bufs, vecs) = unsafe {
            (
                ManuallyDrop::take(&mut this.bufs),
                ManuallyDrop::take(&mut this.vecs),
            )
        };
        Ok(VectoredCompleted {
            bufs,
            vecs,
            result: receipt.raw_result(),
            direction: this.direction,
        })
    }

    /// Take the storage back without a receipt, undoing a failed push.
    ///
    /// # Safety
    ///
    /// The kernel must never have seen this request's SQE. Calling this
    /// after publication hands back storage the kernel may still be using.
    pub(crate) unsafe fn reclaim_unsubmitted(self) -> PreparedVectored<B, V, N> {
        let mut this = ManuallyDrop::new(self);
        // SAFETY: the caller guarantees the kernel never saw the SQE, and
        // `this` is wrapped in `ManuallyDrop` so neither field is dropped
        // here as well as by the value being rebuilt.
        let (bufs, vecs) = unsafe {
            (
                ManuallyDrop::take(&mut this.bufs),
                ManuallyDrop::take(&mut this.vecs),
            )
        };
        PreparedVectored {
            bufs,
            vecs,
            fd: this.fd,
            offset: this.offset,
            direction: this.direction,
            array: this.array,
        }
    }
}

/// A finished vectored operation, with every owner returned.
pub struct VectoredCompleted<B, V, const N: usize> {
    bufs: [B; N],
    vecs: V,
    result: i32,
    direction: Direction,
}

impl<B, V, const N: usize> VectoredCompleted<B, V, N> {
    /// Direction the kernel accessed the buffers.
    #[must_use]
    pub const fn direction(&self) -> Direction {
        self.direction
    }

    /// Raw CQE result: bytes transferred when non-negative, `-errno`
    /// otherwise.
    #[must_use]
    pub const fn raw_result(&self) -> i32 {
        self.result
    }

    /// Total bytes transferred across all buffers.
    ///
    /// A short result is not an error: the kernel fills the descriptors in
    /// order and may stop partway, so this can be less than the total
    /// capacity without anything having gone wrong.
    ///
    /// # Errors
    ///
    /// Returns [`CompletionError::Failed`](crate::CompletionError::Failed)
    /// when the CQE carried a negative errno.
    #[allow(clippy::cast_sign_loss)]
    pub const fn result(&self) -> Result<u32, Error> {
        if self.result < 0 {
            Err(Error::Completion(crate::CompletionError::Failed(
                crate::Errno::new(-self.result),
            )))
        } else {
            Ok(self.result as u32)
        }
    }

    /// Borrow the buffers.
    #[must_use]
    pub const fn buffers(&self) -> &[B; N] {
        &self.bufs
    }

    /// The result alongside every owner.
    ///
    /// Returns the storage even on failure, so a failed operation never
    /// costs a buffer.
    pub fn into_parts(self) -> (Result<u32, Error>, [B; N], V) {
        (self.result(), self.bufs, self.vecs)
    }
}
