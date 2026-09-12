//! Zero-copy `sendmsg`, where two lifetimes from separate modules meet.
//!
//! [`PreparedSendmsg`](super::PreparedSendmsg) stages a header, a
//! descriptor array, and a destination address in caller memory so the
//! kernel can follow pointers *inside* the SQE's target rather than just
//! the SQE itself. [`PreparedZc`](super::PreparedZc) tracks a buffer whose
//! release is a second, conditional completion rather than the first CQE.
//! Zero-copy `sendmsg` needs both stories at once: the staged region and
//! payload buffers must stay put for the *whole* operation, which now ends
//! at the notification rather than at the send result.
//!
//! This module is therefore not a thin wrapper over either — it is
//! [`PreparedSendmsg`](super::PreparedSendmsg)'s staging with
//! [`PendingZc`](super::PendingZc)'s two-completion redemption bolted on,
//! because a request can only have one `Drop` and one `redeem`, and both
//! halves of the story have to agree on when it is safe to run.

use core::mem::ManuallyDrop;

use super::buffer::{StableBuffer, StableBufferMut};
use super::event::PartialReceipt;
use super::identity::{RequestId, RingId};
use super::msgregion::{MsgRegion, MsgRegionError};
use super::request::Receipt;
use super::sendmsg::SendTarget;
use crate::error::Error;
use crate::op::Sqe;
use crate::types::{IoVec, MsgFlags, MsgHdr, RawFd, SockAddrIn};

/// A zero-copy `sendmsg` that owns its buffers and staging storage, not
/// yet queued.
///
/// See [`PreparedSendmsg`](super::PreparedSendmsg) for the staging layout
/// and [`PreparedZc`](super::PreparedZc) for why the buffer outlives the
/// send result.
pub struct PreparedSendmsgZc<B, R, const N: usize> {
    bufs: [B; N],
    region: MsgRegion<R>,
    fd: RawFd,
    flags: MsgFlags,
    target: SendTarget,
}

impl<B: StableBuffer, R: StableBufferMut, const N: usize> PreparedSendmsgZc<B, R, N> {
    /// Prepare a zero-copy `sendmsg` gathering every buffer into one
    /// message.
    ///
    /// # Errors
    ///
    /// Returns [`MsgRegionError`] with all the storage handed back if
    /// `region` is too small or misaligned for the staged layout, or if
    /// `N` exceeds `UIO_MAXIOV`.
    pub fn new(
        fd: RawFd,
        bufs: [B; N],
        region: R,
        target: SendTarget,
        flags: MsgFlags,
    ) -> Result<Self, ([B; N], R, MsgRegionError)> {
        let mut lens = [0usize; N];
        for (slot, buf) in lens.iter_mut().zip(bufs.iter()) {
            *slot = buf.stable_len();
        }
        Self::build(fd, bufs, region, target, flags, &lens)
    }

    /// Shorten each descriptor to the matching entry in `lens`.
    ///
    /// See [`PreparedSendmsg::with_lens`](super::PreparedSendmsg::with_lens)
    /// — the same clamp-not-extend rule applies here.
    #[must_use]
    pub fn with_lens(mut self, lens: [usize; N]) -> Self {
        let mut clamped = [0usize; N];
        for ((slot, want), buf) in clamped.iter_mut().zip(lens.iter()).zip(self.bufs.iter()) {
            *slot = (*want).min(buf.stable_len());
        }
        self.write_descriptors(&clamped);
        self
    }

    fn build(
        fd: RawFd,
        bufs: [B; N],
        region: R,
        target: SendTarget,
        flags: MsgFlags,
        lens: &[usize; N],
    ) -> Result<Self, ([B; N], R, MsgRegionError)> {
        let region = match MsgRegion::stage(region, N) {
            Ok(region) => region,
            Err((store, e)) => return Err((bufs, store, e)),
        };
        let mut prepared = Self {
            bufs,
            region,
            fd,
            flags,
            target,
        };
        prepared.write_descriptors(lens);
        prepared.publish();
        Ok(prepared)
    }

    fn write_descriptors(&mut self, lens: &[usize; N]) {
        for (i, (buf, len)) in self.bufs.iter().zip(lens.iter()).enumerate() {
            // SAFETY: `i < N` and the region was staged for `N`
            // descriptors. The address comes from `StableBuffer`, so it
            // stays valid for as long as this value owns the buffer, which
            // outlasts the kernel's access.
            unsafe {
                self.region
                    .write_descriptor(i, buf.stable_ptr().cast_mut(), *len);
            }
        }
    }

    fn publish(&mut self) {
        if let SendTarget::To(addr) = self.target {
            self.region.write_name(addr);
        }
        self.region
            .publish_header(matches!(self.target, SendTarget::To(_)));
    }
}

impl<B, R, const N: usize> PreparedSendmsgZc<B, R, N> {
    /// The socket this message is sent on.
    #[must_use]
    pub const fn fd(&self) -> RawFd {
        self.fd
    }

    /// The send flags this message carries.
    #[must_use]
    pub const fn flags(&self) -> MsgFlags {
        self.flags
    }

    /// Where this message is addressed.
    #[must_use]
    pub const fn target(&self) -> SendTarget {
        self.target
    }

    /// How many buffers this message gathers.
    #[must_use]
    pub const fn count(&self) -> usize {
        N
    }

    /// The header exactly as the kernel will read it.
    #[must_use]
    pub const fn published_header(&self) -> MsgHdr {
        self.region.header()
    }

    /// A staged descriptor, as the kernel will read it.
    ///
    /// # Panics
    ///
    /// Panics if `index` is not below [`count`](Self::count).
    #[must_use]
    pub fn published_descriptor(&self, index: usize) -> IoVec {
        assert!(index < N, "descriptor {index} is out of range for {N}");
        self.region.descriptor(index)
    }

    /// Borrow the buffers before submission.
    #[must_use]
    pub const fn buffers(&self) -> &[B; N] {
        &self.bufs
    }

    /// Mutate the buffers before submission.
    #[must_use]
    pub const fn buffers_mut(&mut self) -> &mut [B; N] {
        &mut self.bufs
    }

    /// Give the buffers and staging storage back, abandoning the request.
    #[must_use]
    pub fn into_parts(self) -> ([B; N], R) {
        (self.bufs, self.region.into_store())
    }

    /// Build the SQE and move to the pending state.
    pub(crate) fn into_pending(
        self,
        ring: RingId,
        id: RequestId,
    ) -> (Sqe, PendingSendmsgZc<B, R, N>) {
        let hdr = self.region.header_ptr();
        // SAFETY: `hdr` points at a `MsgHdr` staged inside storage this
        // request owns, whose `msg_iov` names a descriptor array in the
        // same storage, whose entries name buffers owned by `self.bufs`.
        // Everything the kernel will dereference therefore lives in memory
        // this request owns, for as long as `PendingSendmsgZc` withholds
        // its destructor — which now waits for the notification, not just
        // the send result.
        let sqe = unsafe { Sqe::sendmsg_zc_ptr(self.fd, hdr.cast_const(), self.flags) };
        let (store, hdr, vecs, name, count) = self.region.into_raw_parts();
        let pending = PendingSendmsgZc {
            bufs: ManuallyDrop::new(self.bufs),
            store: ManuallyDrop::new(store),
            hdr,
            vecs,
            name,
            count,
            ring,
            id,
            fd: self.fd,
            flags: self.flags,
            target: self.target,
            sent: None,
        };
        (sqe.user_data(id.raw()), pending)
    }
}

/// A submitted zero-copy `sendmsg` whose storage the kernel may be
/// reading.
///
/// # Two completions, one release
///
/// Like [`PendingZc`](super::PendingZc), the send result arrives first and
/// is recorded with [`record_sent`](Self::record_sent); only a terminal
/// [`Receipt`] — the notification, or a send CQE that promised none —
/// releases the buffers and the staging storage together through
/// [`redeem`](Self::redeem).
#[must_use = "dropping the ticket leaks the buffers and the staging storage"]
pub struct PendingSendmsgZc<B, R, const N: usize> {
    bufs: ManuallyDrop<[B; N]>,
    store: ManuallyDrop<R>,
    hdr: *mut MsgHdr,
    vecs: *mut IoVec,
    name: *mut SockAddrIn,
    count: usize,
    ring: RingId,
    id: RequestId,
    fd: RawFd,
    flags: MsgFlags,
    target: SendTarget,
    sent: Option<i32>,
}

// SAFETY: every pointer refers into `store`, which this ticket exclusively
// owns and keeps at a fixed address for its whole life, so moving the
// ticket between threads leaves the kernel's pointers valid.
unsafe impl<B: Send, R: Send, const N: usize> Send for PendingSendmsgZc<B, R, N> {}

impl<B, R, const N: usize> PendingSendmsgZc<B, R, N> {
    /// Identity the kernel echoes back in this request's CQEs.
    #[must_use]
    pub const fn id(&self) -> RequestId {
        self.id
    }

    /// Identity of the queue that accepted this request.
    #[must_use]
    pub const fn ring(&self) -> RingId {
        self.ring
    }

    /// The socket this message is sent on.
    #[must_use]
    pub const fn fd(&self) -> RawFd {
        self.fd
    }

    /// How many buffers this message gathers.
    #[must_use]
    pub const fn count(&self) -> usize {
        N
    }

    /// The send CQE's result, once it has been recorded.
    ///
    /// `None` means the send result has not arrived yet — which is not the
    /// same as the storage being free.
    #[must_use]
    pub const fn send_result(&self) -> Option<i32> {
        self.sent
    }

    /// Whether `receipt` authenticates this exact request.
    #[must_use]
    pub const fn matches(&self, receipt: &Receipt) -> bool {
        receipt.belongs_to(self.ring, self.id)
    }

    /// Whether `notice` authenticates this exact request.
    #[must_use]
    pub const fn matches_sent(&self, notice: &PartialReceipt) -> bool {
        notice.belongs_to(self.ring, self.id)
    }

    /// Record the send CQE's byte count, keeping the storage in flight.
    ///
    /// This is deliberately not a release — the same reasoning as
    /// [`PendingZc::record_sent`](super::PendingZc::record_sent).
    ///
    /// # Errors
    ///
    /// Returns the ticket and notice unchanged if the notice belongs to
    /// another request or another ring.
    pub const fn record_sent(
        mut self,
        notice: PartialReceipt,
    ) -> Result<Self, (Self, PartialReceipt)> {
        if !self.matches_sent(&notice) {
            return Err((self, notice));
        }
        self.sent = Some(notice.raw_result());
        Ok(self)
    }

    /// Take the storage back without a receipt, undoing a failed push.
    ///
    /// # Safety
    ///
    /// The kernel must never have seen this request's SQE.
    pub(crate) unsafe fn reclaim_unsubmitted(self) -> PreparedSendmsgZc<B, R, N> {
        let mut this = ManuallyDrop::new(self);
        // SAFETY: the caller guarantees the kernel never saw the SQE, and
        // `this` is wrapped in `ManuallyDrop` so neither field is dropped
        // here as well as by the value being rebuilt.
        let (bufs, store) = unsafe {
            (
                ManuallyDrop::take(&mut this.bufs),
                ManuallyDrop::take(&mut this.store),
            )
        };
        PreparedSendmsgZc {
            bufs,
            region: MsgRegion::from_parts(store, this.hdr, this.vecs, this.name, this.count),
            fd: this.fd,
            flags: this.flags,
            target: this.target,
        }
    }

    /// Trade a terminal receipt for the finished send and its storage.
    ///
    /// # Errors
    ///
    /// Returns the ticket and receipt unchanged if the receipt belongs to
    /// another request or another ring.
    pub fn redeem(self, receipt: Receipt) -> Result<SendmsgZcCompleted<B, R, N>, (Self, Receipt)> {
        if !self.matches(&receipt) {
            return Err((self, receipt));
        }
        let mut this = ManuallyDrop::new(self);
        // SAFETY: the receipt proves the kernel posted this request's
        // terminal completion — the notification, or a send CQE that
        // promised none — and has stopped reading the header, the
        // descriptors, and the buffers they name. `this` is wrapped in
        // `ManuallyDrop`, so taking the fields cannot double-drop them.
        let (bufs, store) = unsafe {
            (
                ManuallyDrop::take(&mut this.bufs),
                ManuallyDrop::take(&mut this.store),
            )
        };
        Ok(SendmsgZcCompleted {
            bufs,
            region: MsgRegion::from_parts(store, this.hdr, this.vecs, this.name, this.count),
            sent: this.sent,
            notified: receipt.raw_result(),
        })
    }
}

impl<B, R, const N: usize> Drop for PendingSendmsgZc<B, R, N> {
    fn drop(&mut self) {
        // Intentionally no `ManuallyDrop::drop`. The kernel may still be
        // reading the header, the descriptors, or the buffers, so all of
        // it leaks rather than being freed under an in-flight request —
        // the same failure mode as every other in-flight ticket.
    }
}

/// A finished zero-copy `sendmsg`, with every owner returned.
pub struct SendmsgZcCompleted<B, R, const N: usize> {
    bufs: [B; N],
    region: MsgRegion<R>,
    sent: Option<i32>,
    notified: i32,
}

impl<B, R, const N: usize> SendmsgZcCompleted<B, R, N> {
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

    /// Bytes the kernel accepted from this message, or the kernel's error.
    ///
    /// Reports the send CQE's count when one was recorded, since the
    /// notification carries no byte count of its own — matching
    /// [`ZcCompleted::result`](super::ZcCompleted::result).
    ///
    /// # Errors
    ///
    /// Returns [`CompletionError::Failed`](crate::CompletionError::Failed)
    /// when either CQE carried a negative errno.
    #[allow(clippy::cast_sign_loss)]
    pub const fn result(&self) -> Result<u32, Error> {
        let raw = match self.sent {
            Some(sent) => sent,
            None => self.notified,
        };
        match Error::from_failed_cqe(raw) {
            Some(e) => Err(e),
            None => Ok(raw as u32),
        }
    }

    /// The header as the kernel left it.
    #[must_use]
    pub const fn header(&self) -> MsgHdr {
        self.region.header()
    }

    /// Borrow the buffers.
    #[must_use]
    pub const fn buffers(&self) -> &[B; N] {
        &self.bufs
    }

    /// The result alongside every owner.
    ///
    /// Returns the storage even on failure, so a failed send never costs a
    /// buffer.
    pub fn into_parts(self) -> (Result<u32, Error>, [B; N], R) {
        (self.result(), self.bufs, self.region.into_store())
    }
}
