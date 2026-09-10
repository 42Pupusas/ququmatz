//! Zero-copy send, whose buffer outlives its first completion.
//!
//! An ordinary `write` copies the buffer into the kernel, so the single CQE
//! that reports the byte count also means the bytes are free. `send_zc`
//! maps the pages to the NIC instead, so the send CQE says only *how much
//! was accepted* — the hardware may still be reading. Releasing the buffer
//! there is a use-after-free that a plain [`Pending`](super::Pending) would
//! happily perform, which is why this is a separate type rather than a flag
//! on the existing one.
//!
//! # The terminal completion is conditional
//!
//! A zero-copy send usually produces two CQEs, but not always. The kernel
//! sets `IORING_CQE_F_MORE` on the send CQE to promise a notification;
//! **without that flag no notification is ever posted** and the send CQE is
//! itself terminal. That happens when the kernel fell back to copying, so
//! the buffer really is free. A ticket that unconditionally waited for a
//! notification would leak every such request forever.
//!
//! [`PendingZc`] therefore reads the flag rather than assuming, and only
//! [`Receipt`] — minted from a terminal CQE — can release the storage.

use core::mem::ManuallyDrop;

use super::buffer::StableBuffer;
use super::identity::{RequestId, RingId};
use super::request::Receipt;
use crate::op::Sqe;
use crate::types::{MsgFlags, RawFd};

/// A zero-copy send that owns its buffer but has not been queued yet.
pub struct PreparedZc<B> {
    buf: B,
    fd: RawFd,
    len: u32,
    flags: MsgFlags,
    /// Derived from the buffer so provenance reaches the kernel intact; see
    /// the note on [`Prepared`](super::Prepared)'s equivalent field.
    addr: *const u8,
}

// SAFETY: `addr` points into `buf`, which this struct exclusively owns, so
// the pointer is valid wherever the buffer is. It confers no thread
// affinity of its own, leaving `B` to decide.
unsafe impl<B: Send> Send for PreparedZc<B> {}

impl<B: StableBuffer> PreparedZc<B> {
    /// Prepare a zero-copy send of `buf`'s contents to `fd`.
    ///
    /// Takes ownership: the kernel reads these bytes until the terminal
    /// completion, which is later than the send result.
    #[must_use]
    pub fn send(fd: RawFd, buf: B, flags: MsgFlags) -> Self {
        let len = Self::clamp_len(buf.stable_len());
        let addr = buf.stable_ptr();
        Self {
            buf,
            fd,
            len,
            flags,
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

    /// Send only the first `len` bytes instead of the whole buffer.
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

    /// Bytes this send will transfer.
    #[must_use]
    pub const fn len(&self) -> u32 {
        self.len
    }

    /// Whether the transfer length is zero.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Borrow the buffer before submission.
    #[must_use]
    pub const fn buffer(&self) -> &B {
        &self.buf
    }

    /// Mutate the buffer before submission — the usual way to fill a send.
    #[must_use]
    pub const fn buffer_mut(&mut self) -> &mut B {
        &mut self.buf
    }

    /// Give the buffer back, abandoning the send.
    #[must_use]
    pub fn into_buffer(self) -> B {
        self.buf
    }

    /// Build the SQE and move to the pending state.
    pub(crate) fn into_pending(self, ring: RingId, id: RequestId) -> (Sqe, PendingZc<B>) {
        // SAFETY: `addr` was taken from `self.buf` through `StableBuffer`,
        // which guarantees it is fixed, readable and exclusively owned.
        // `self.buf` moves into the returned `PendingZc`, whose destructor
        // is suppressed until a terminal receipt proves the kernel released
        // the pages, so the bytes outlive the kernel's access.
        let sqe = unsafe { Sqe::send_zc_ptr(self.fd, self.addr, self.len, self.flags) };
        let pending = PendingZc {
            buf: ManuallyDrop::new(self.buf),
            ring,
            id,
            fd: self.fd,
            len: self.len,
            flags: self.flags,
            addr: self.addr,
            sent: None,
        };
        (sqe.user_data(id.raw()), pending)
    }
}

/// A submitted zero-copy send whose buffer the NIC may still be reading.
///
/// Like [`Pending`](super::Pending) this is the ticket the application
/// moves between threads, it exposes no access to the buffer, and
/// abandoning it leaks the storage rather than freeing memory the kernel
/// may touch.
///
/// # Two completions, one release
///
/// The send result arrives first and is recorded with
/// [`record_sent`](Self::record_sent), which hands the ticket back still
/// holding the buffer. Only [`redeem`](Self::redeem), which takes a
/// [`Receipt`] minted from a terminal CQE, returns the storage.
pub struct PendingZc<B> {
    buf: ManuallyDrop<B>,
    ring: RingId,
    id: RequestId,
    fd: RawFd,
    len: u32,
    flags: MsgFlags,
    addr: *const u8,
    sent: Option<i32>,
}

// SAFETY: `addr` points into `buf`, which this ticket exclusively owns and
// keeps alive at a fixed address for its whole life. Moving the ticket
// moves the owner with it, so the pointer stays valid; `B` decides whether
// that move is allowed at all.
unsafe impl<B: Send> Send for PendingZc<B> {}

impl<B> PendingZc<B> {
    /// Identity the kernel echoes back in this send's CQEs.
    #[must_use]
    pub const fn id(&self) -> RequestId {
        self.id
    }

    /// Identity of the queue that accepted this request.
    #[must_use]
    pub const fn ring(&self) -> RingId {
        self.ring
    }

    /// Bytes this send was submitted to transfer.
    #[must_use]
    pub const fn len(&self) -> u32 {
        self.len
    }

    /// Whether the transfer length is zero.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The send CQE's result, once it has been recorded.
    ///
    /// `None` means the send result has not arrived yet — which is not the
    /// same as the buffer being free.
    #[must_use]
    pub const fn send_result(&self) -> Option<i32> {
        self.sent
    }

    /// Whether `receipt` authenticates this exact request.
    #[must_use]
    pub const fn matches(&self, receipt: &Receipt) -> bool {
        receipt.id.raw() == self.id.raw() && receipt.ring.raw() == self.ring.raw()
    }

    /// Whether `notice` authenticates this exact request.
    #[must_use]
    pub const fn matches_sent(&self, notice: &SendReceipt) -> bool {
        notice.id.raw() == self.id.raw() && notice.ring.raw() == self.ring.raw()
    }

    /// Record the send CQE's byte count, keeping the buffer in flight.
    ///
    /// This is deliberately not a release. The notification promised by the
    /// send CQE's `MORE` flag is the only thing that frees the pages.
    ///
    /// # Errors
    ///
    /// Returns the ticket and notice unchanged if the notice belongs to
    /// another request or another ring.
    pub const fn record_sent(mut self, notice: SendReceipt) -> Result<Self, (Self, SendReceipt)> {
        if !self.matches_sent(&notice) {
            return Err((self, notice));
        }
        self.sent = Some(notice.result);
        Ok(self)
    }

    /// Take the buffer back without a receipt, undoing a failed push.
    ///
    /// # Safety
    ///
    /// The kernel must never have seen this request's SQE.
    pub(crate) unsafe fn reclaim_unsubmitted(self) -> PreparedZc<B> {
        let mut this = ManuallyDrop::new(self);
        // SAFETY: `this` is wrapped in ManuallyDrop so the no-op `Drop` will
        // not observe the moved-out buffer. The caller guarantees no
        // kernel-visible pointer to it exists.
        let buf = unsafe { ManuallyDrop::take(&mut this.buf) };
        PreparedZc {
            buf,
            fd: this.fd,
            len: this.len,
            flags: this.flags,
            addr: this.addr,
        }
    }

    /// Trade a terminal receipt for the finished send and its buffer.
    ///
    /// The receipt proves the kernel posted this request's *terminal* CQE —
    /// the notification, or a send CQE that promised none — and has stopped
    /// reading the pages.
    ///
    /// # Errors
    ///
    /// Returns the ticket and receipt unchanged if the receipt belongs to
    /// another request or another ring.
    pub fn redeem(self, receipt: Receipt) -> Result<ZcCompleted<B>, (Self, Receipt)> {
        if !self.matches(&receipt) {
            return Err((self, receipt));
        }
        let mut this = ManuallyDrop::new(self);
        // SAFETY: `this` is wrapped in ManuallyDrop, so the no-op `Drop`
        // cannot observe the moved-out field. The receipt proves the kernel
        // released these pages, so reviving the destructor by handing
        // ownership to `ZcCompleted` is now sound.
        let buf = unsafe { ManuallyDrop::take(&mut this.buf) };
        Ok(ZcCompleted {
            buf,
            id: this.id,
            sent: this.sent,
            notified: receipt.result,
        })
    }
}

impl<B> Drop for PendingZc<B> {
    fn drop(&mut self) {
        // Intentionally no `ManuallyDrop::drop`. See the type docs: the NIC
        // may still be reading these pages, and nothing here can prove
        // otherwise, so the storage leaks instead of being freed underneath
        // an in-flight send.
    }
}

/// A finished zero-copy send and the buffer the kernel has released.
pub struct ZcCompleted<B> {
    buf: B,
    id: RequestId,
    sent: Option<i32>,
    notified: i32,
}

impl<B> ZcCompleted<B> {
    /// Identity of the request this completes.
    #[must_use]
    pub const fn id(&self) -> RequestId {
        self.id
    }

    /// Raw result of the send CQE, if one was recorded.
    #[must_use]
    pub const fn raw_send_result(&self) -> Option<i32> {
        self.sent
    }

    /// Raw result of the terminal CQE.
    #[must_use]
    pub const fn raw_result(&self) -> i32 {
        self.notified
    }

    /// Bytes sent, or the kernel's error.
    ///
    /// Reports the send CQE's count when one was recorded, since the
    /// notification carries no byte count of its own.
    ///
    /// # Errors
    ///
    /// Returns [`CompletionError::Failed`](crate::CompletionError::Failed)
    /// when either CQE carried a negative errno.
    #[allow(clippy::cast_sign_loss)]
    pub const fn result(&self) -> Result<u32, crate::Error> {
        let raw = match self.sent {
            Some(sent) => sent,
            None => self.notified,
        };
        if raw < 0 {
            Err(crate::Error::Completion(crate::CompletionError::Failed(
                crate::Errno::new(-raw),
            )))
        } else {
            Ok(raw as u32)
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

    /// Take both the buffer and the send result.
    ///
    /// # Errors
    ///
    /// Returns the buffer alongside the error so it is never lost on a
    /// failed send.
    pub fn into_parts(self) -> (Result<u32, crate::Error>, B) {
        (self.result(), self.buf)
    }
}

/// A zero-copy send's result CQE, which does **not** release the buffer.
///
/// Minted only from a CQE carrying `IORING_CQE_F_MORE`, meaning the kernel
/// has promised a later notification. It is deliberately a distinct type
/// from [`Receipt`]: nothing in the API accepts it where a release is
/// required, so a non-terminal completion cannot free storage the NIC is
/// still reading.
#[derive(Debug)]
pub struct SendReceipt {
    pub(crate) ring: RingId,
    pub(crate) id: RequestId,
    pub(crate) result: i32,
}

impl SendReceipt {
    /// Which request this reports.
    #[must_use]
    pub const fn id(&self) -> RequestId {
        self.id
    }

    /// Which ring produced it.
    #[must_use]
    pub const fn ring(&self) -> RingId {
        self.ring
    }

    /// Raw CQE result: bytes accepted when non-negative, `-errno` otherwise.
    #[must_use]
    pub const fn raw_result(&self) -> i32 {
        self.result
    }
}

/// What a reaped CQE authorizes.
///
/// Returned by [`OwnedCompleter::reap_event`](super::OwnedCompleter::reap_event)
/// for rings that mix ordinary owned requests with zero-copy sends, where
/// "is this completion terminal?" can no longer be answered by the
/// completer alone.
#[derive(Debug)]
pub enum Event {
    /// A terminal completion. Releases the buffer of the ticket it matches.
    Complete(Receipt),
    /// A zero-copy send's result, with a notification still to come.
    Sent(SendReceipt),
}

impl Event {
    /// The terminal receipt, if this event carries one.
    #[must_use]
    pub const fn into_receipt(self) -> Option<Receipt> {
        match self {
            Self::Complete(receipt) => Some(receipt),
            Self::Sent(_) => None,
        }
    }

    /// Which request this event belongs to.
    #[must_use]
    pub const fn id(&self) -> RequestId {
        match self {
            Self::Complete(receipt) => receipt.id,
            Self::Sent(notice) => notice.id,
        }
    }

    /// Whether this event releases a buffer.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Complete(_))
    }
}
