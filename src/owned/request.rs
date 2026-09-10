//! The prepared → pending → completed lifecycle for an owned operation.

use core::mem::ManuallyDrop;

use super::buffer::{StableBuffer, StableBufferMut};
use super::identity::{RequestId, RingId};
use crate::op::Sqe;
use crate::types::RawFd;

/// Which direction the kernel accesses the buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Kernel writes into the buffer (`read`).
    Read,
    /// Kernel reads out of the buffer (`write`).
    Write,
}

/// An operation that owns its buffer but has not been queued yet.
///
/// Holding one means the kernel has no pointer to the buffer, so dropping
/// it just releases the buffer normally.
pub struct Prepared<B> {
    buf: B,
    fd: RawFd,
    offset: u64,
    len: u32,
    direction: Direction,
    /// Captured at construction, where the direction-appropriate bound is
    /// in scope. Sound to cache because [`StableBuffer`] guarantees the
    /// address never changes, including across moves.
    addr: usize,
}

impl<B: StableBufferMut> Prepared<B> {
    /// Prepare a read of up to `buf`'s length from `fd` at `offset`.
    ///
    /// Takes ownership of `buf`: the kernel writes into it, so no caller
    /// alias may survive submission.
    #[must_use]
    pub fn read(fd: RawFd, mut buf: B, offset: u64) -> Self {
        let len = Self::clamp_len(buf.stable_len());
        let addr = buf.stable_mut_ptr() as usize;
        Self {
            buf,
            fd,
            offset,
            len,
            direction: Direction::Read,
            addr,
        }
    }
}

impl<B: StableBuffer> Prepared<B> {
    /// Prepare a write of `buf`'s contents to `fd` at `offset`.
    #[must_use]
    pub fn write(fd: RawFd, buf: B, offset: u64) -> Self {
        let len = Self::clamp_len(buf.stable_len());
        let addr = buf.stable_ptr() as usize;
        Self {
            buf,
            fd,
            offset,
            len,
            direction: Direction::Write,
            addr,
        }
    }

    #[allow(clippy::cast_possible_truncation)]
    const fn clamp_len(len: usize) -> u32 {
        if len > u32::MAX as usize {
            u32::MAX
        } else {
            len as u32
        }
    }

    /// Transfer only the first `len` bytes instead of the whole buffer.
    ///
    /// A buffer's capacity and a transfer's length are different things: a
    /// 64-byte buffer holding a 5-byte message should write 5 bytes. The
    /// default is the full capacity, which is what a read usually wants;
    /// writes usually want this.
    ///
    /// Clamped to the buffer's capacity, so it can never describe more
    /// memory than the owner actually has.
    #[must_use]
    pub const fn with_len(mut self, len: u32) -> Self {
        if len < self.len {
            self.len = len;
        }
        self
    }

    /// Bytes this operation will transfer.
    #[must_use]
    pub const fn len(&self) -> u32 {
        self.len
    }

    /// Whether the transfer length is zero.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Direction the kernel will access the buffer.
    #[must_use]
    pub const fn direction(&self) -> Direction {
        self.direction
    }

    /// Give the buffer back, abandoning the operation.
    #[must_use]
    pub fn into_buffer(self) -> B {
        self.buf
    }

    /// Borrow the buffer before submission.
    #[must_use]
    pub const fn buffer(&self) -> &B {
        &self.buf
    }

    /// Mutate the buffer before submission — the usual way to fill a write.
    #[must_use]
    pub const fn buffer_mut(&mut self) -> &mut B {
        &mut self.buf
    }

    /// Build the SQE and move to the pending state.
    ///
    /// Called by the queue, which supplies the identity. The buffer moves
    /// into [`Pending`], so no caller-visible owner survives this call.
    pub(crate) fn into_pending(self, ring: RingId, id: RequestId) -> (Sqe, Pending<B>) {
        let sqe = match self.direction {
            // SAFETY: `addr` was taken from `self.buf` through
            // `StableBufferMut`, which guarantees it is fixed, writable and
            // exclusively owned. `self.buf` moves into the returned
            // `Pending` rather than being dropped, and `Pending` suppresses
            // its destructor unless a receipt proves the kernel finished,
            // so the bytes outlive the kernel's access.
            Direction::Read => unsafe {
                Sqe::read_ptr(self.fd, self.addr as *mut u8, self.len, self.offset)
            },
            // SAFETY: as above, via `StableBuffer`; the kernel only reads.
            Direction::Write => unsafe {
                Sqe::write_ptr(self.fd, self.addr as *const u8, self.len, self.offset)
            },
        };
        let pending = Pending {
            buf: ManuallyDrop::new(self.buf),
            ring,
            id,
            fd: self.fd,
            offset: self.offset,
            len: self.len,
            direction: self.direction,
            addr: self.addr,
        };
        (sqe.user_data(id.raw()), pending)
    }
}

/// A submitted operation whose buffer the kernel may be accessing.
///
/// This is the ticket the application moves between threads. It is `Send`
/// when its buffer is, so a submission thread can hand it to a completion
/// thread through any channel the application already uses.
///
/// # Why the buffer is unreachable here
///
/// There is deliberately no way to read, write, or extract the buffer from
/// a `Pending`. The kernel may touch those bytes at any moment until the
/// terminal completion, so any access would race.
///
/// # Drop and `forget` both leak rather than free
///
/// Dropping a `Pending` runs no destructor for the buffer: the storage is
/// leaked on purpose. Freeing it would hand the kernel a dangling pointer,
/// and the queue keeps no registry that could find and reclaim it later.
/// `mem::forget` degrades the same way. Leaking is the safe failure; only
/// [`redeem`](Self::redeem), which requires proof the kernel has finished,
/// returns the storage.
pub struct Pending<B> {
    buf: ManuallyDrop<B>,
    ring: RingId,
    id: RequestId,
    fd: RawFd,
    offset: u64,
    len: u32,
    direction: Direction,
    addr: usize,
}

impl<B> Pending<B> {
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

    /// Bytes this operation was submitted to transfer.
    #[must_use]
    pub const fn len(&self) -> u32 {
        self.len
    }

    /// Whether the transfer length is zero.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Direction the kernel accesses the buffer.
    #[must_use]
    pub const fn direction(&self) -> Direction {
        self.direction
    }

    /// Whether `receipt` authenticates this exact request.
    #[must_use]
    pub const fn matches(&self, receipt: &Receipt) -> bool {
        receipt.id.raw() == self.id.raw() && receipt.ring.raw() == self.ring.raw()
    }

    /// Take the buffer back without a receipt, undoing a failed push.
    ///
    /// # Safety
    ///
    /// The kernel must never have seen this request's SQE: the entry was
    /// not written into the ring, or was written but never published by
    /// advancing the tail. Calling this after publication hands the caller
    /// storage the kernel may still write to.
    pub(crate) unsafe fn reclaim_unsubmitted(self) -> Prepared<B> {
        let mut this = ManuallyDrop::new(self);
        // SAFETY: `this` is wrapped in ManuallyDrop so the no-op `Drop` will
        // not observe the moved-out buffer. The caller guarantees no
        // kernel-visible pointer to it exists.
        let buf = unsafe { ManuallyDrop::take(&mut this.buf) };
        Prepared {
            buf,
            fd: this.fd,
            offset: this.offset,
            len: this.len,
            direction: this.direction,
            addr: this.addr,
        }
    }

    /// Trade a matching receipt for the finished operation and its buffer.
    ///
    /// The receipt is proof the kernel posted this request's terminal
    /// completion and has stopped touching the bytes, which is what makes
    /// returning the buffer sound.
    ///
    /// # Errors
    ///
    /// Returns the ticket and receipt unchanged if the receipt belongs to
    /// another request or another ring.
    pub fn redeem(self, receipt: Receipt) -> Result<Completed<B>, (Self, Receipt)> {
        if !self.matches(&receipt) {
            return Err((self, receipt));
        }
        let mut this = ManuallyDrop::new(self);
        // SAFETY: `this` is wrapped in ManuallyDrop, so `Pending::drop` will
        // not run and cannot observe the moved-out field. The receipt proves
        // the kernel finished with these bytes, so reviving the destructor
        // by handing ownership to `Completed` is now sound.
        let buf = unsafe { ManuallyDrop::take(&mut this.buf) };
        Ok(Completed {
            buf,
            id: this.id,
            direction: this.direction,
            result: receipt.result,
        })
    }
}

impl<B> Drop for Pending<B> {
    fn drop(&mut self) {
        // Intentionally no `ManuallyDrop::drop`. See the type docs: the
        // kernel may still hold this pointer, and nothing here can prove
        // otherwise, so the storage leaks instead of being freed underneath
        // an in-flight operation.
    }
}

/// A finished operation and the buffer the kernel has released.
pub struct Completed<B> {
    buf: B,
    id: RequestId,
    direction: Direction,
    result: i32,
}

impl<B> Completed<B> {
    /// Identity of the request this completes.
    #[must_use]
    pub const fn id(&self) -> RequestId {
        self.id
    }

    /// Direction the kernel accessed the buffer.
    #[must_use]
    pub const fn direction(&self) -> Direction {
        self.direction
    }

    /// Raw CQE result: byte count when non-negative, `-errno` otherwise.
    #[must_use]
    pub const fn raw_result(&self) -> i32 {
        self.result
    }

    /// Bytes transferred, or the kernel's error.
    ///
    /// # Errors
    ///
    /// Returns [`CompletionError::Failed`](crate::CompletionError::Failed)
    /// when the CQE carried a negative errno.
    #[allow(clippy::cast_sign_loss)]
    pub const fn result(&self) -> Result<u32, crate::Error> {
        if self.result < 0 {
            Err(crate::Error::Completion(crate::CompletionError::Failed(
                crate::Errno::new(-self.result),
            )))
        } else {
            Ok(self.result as u32)
        }
    }

    /// Borrow the buffer now that the kernel has finished with it.
    #[must_use]
    pub const fn buffer(&self) -> &B {
        &self.buf
    }

    /// Mutably borrow the buffer.
    #[must_use]
    pub const fn buffer_mut(&mut self) -> &mut B {
        &mut self.buf
    }

    /// Take the buffer back for reuse.
    #[must_use]
    pub fn into_buffer(self) -> B {
        self.buf
    }

    /// Take both the buffer and the transfer result.
    ///
    /// # Errors
    ///
    /// Returns the buffer alongside the error so it is never lost on a
    /// failed operation.
    pub fn into_parts(self) -> (Result<u32, crate::Error>, B) {
        (self.result(), self.buf)
    }
}

/// Proof that the kernel posted a specific request's terminal completion.
///
/// Only [`OwnedCompleter`](super::queue::OwnedCompleter) mints these, from
/// CQEs it actually reaped, so a receipt cannot be fabricated by safe code
/// the way a [`Completion`](crate::Completion) can. It is neither `Copy`
/// nor `Clone`, so it authorizes exactly one redemption.
#[derive(Debug)]
pub struct Receipt {
    pub(crate) ring: RingId,
    pub(crate) id: RequestId,
    pub(crate) result: i32,
    pub(crate) flags: crate::types::CqeFlags,
}

impl Receipt {
    /// Which request this receipt completes.
    #[must_use]
    pub const fn id(&self) -> RequestId {
        self.id
    }

    /// Which ring produced it.
    #[must_use]
    pub const fn ring(&self) -> RingId {
        self.ring
    }

    /// Raw CQE result.
    #[must_use]
    pub const fn raw_result(&self) -> i32 {
        self.result
    }

    /// Kernel-set CQE flags.
    #[must_use]
    pub const fn flags(&self) -> crate::types::CqeFlags {
        self.flags
    }
}
