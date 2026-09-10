//! `sendmsg`, where the kernel follows pointers stored inside a struct.
//!
//! [`PreparedVectored`](super::PreparedVectored) is one level of
//! indirection: the SQE names an `iovec` array, and the kernel reads the
//! buffers that array names. `sendmsg` adds another. The SQE names a
//! `struct msghdr`, and the kernel reads *that* to find the `iovec` array
//! and the destination address, then follows those to reach the data.
//!
//! So the addresses the kernel will dereference are not all in the SQE
//! where they can be checked at submission — some of them are bytes in
//! caller memory that happen to be pointers. If the header moved, the
//! kernel would read three addresses out of whatever now occupied that
//! space and follow them. Nothing about that is a type error.
//!
//! The header, the descriptor array, and the address are therefore staged
//! together in one caller-supplied region whose stability is checked once,
//! and which is handed back at the end — see [`MsgRegion`]. The payload
//! buffers stay inline in the ticket, since [`StableBuffer`] already
//! promises their bytes do not move when their owner does.
//!
//! [`MsgRegion`]: super::msgregion
//!
//! # What `sendmsg` gives that `writev` does not
//!
//! Gathering several buffers into one write is already possible with
//! [`PreparedVectored`](super::PreparedVectored). `sendmsg` adds the
//! things a socket needs and a file does not: a per-message destination
//! address, so one unconnected socket can be sent from without a
//! `connect` per peer, and send flags such as `MSG_DONTWAIT` that belong
//! to the message rather than the descriptor.
//!
//! # The header is read-only here
//!
//! The kernel does not write back into a `sendmsg` header — measured, not
//! assumed: `msg_namelen`, `msg_controllen`, `msg_iovlen`, and `msg_flags`
//! are all unchanged after a completed send. That is what separates this
//! from [`PreparedRecvmsg`](super::PreparedRecvmsg), whose header the
//! kernel overwrites, and it is why the payload buffers here need only
//! [`StableBuffer`] rather than [`StableBufferMut`].

use core::mem::ManuallyDrop;

use super::buffer::{StableBuffer, StableBufferMut};
use super::identity::{RequestId, RingId};
use super::msgregion::{MsgRegion, MsgRegionError};
use super::request::Receipt;
use crate::error::Error;
use crate::op::Sqe;
use crate::types::{IoVec, MsgFlags, MsgHdr, RawFd, SockAddrIn};

/// Where a `sendmsg` delivers its message.
///
/// A connected socket already knows its peer and the kernel ignores any
/// address supplied with the message; an unconnected one needs the address
/// per message. The two are distinguished here rather than by a nullable
/// pointer so that "no address" cannot be spelled as a null with a
/// non-zero length, which the kernel would read past.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendTarget {
    /// Use the socket's connected peer; stage no address at all.
    Connected,
    /// Deliver to this address, as `sendto` would.
    To(SockAddrIn),
}

/// A `sendmsg` that owns its buffers and staging storage, not yet queued.
///
/// `B` holds the payload, `N` of them; `R` holds the header, the
/// descriptor array, and the address. All of it comes back together from
/// [`SendmsgCompleted::into_parts`].
pub struct PreparedSendmsg<B, R, const N: usize> {
    bufs: [B; N],
    region: MsgRegion<R>,
    fd: RawFd,
    flags: MsgFlags,
    target: SendTarget,
}

impl<B: StableBuffer, R: StableBufferMut, const N: usize> PreparedSendmsg<B, R, N> {
    /// Prepare a `sendmsg` gathering every buffer into one message.
    ///
    /// Takes ownership of the buffers and of the staging storage, which
    /// the kernel reads the header and descriptors from after submission,
    /// so no caller alias to either may survive.
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
    /// A buffer's capacity and its useful contents are different things: a
    /// 64-byte buffer holding a 5-byte message should send 5 bytes. Each
    /// length is clamped to its buffer, so this can never describe more
    /// memory than the owner actually has.
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

    /// Stamp the staged array with each buffer's address and length.
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

    /// Write the address and header the kernel will read.
    fn publish(&mut self) {
        if let SendTarget::To(addr) = self.target {
            self.region.write_name(addr);
        }
        self.region
            .publish_header(matches!(self.target, SendTarget::To(_)));
    }
}

impl<B, R, const N: usize> PreparedSendmsg<B, R, N> {
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

    /// Total bytes across every descriptor.
    #[must_use]
    pub fn total_len(&self) -> usize {
        (0..N).map(|i| self.region.descriptor(i).len()).sum()
    }

    /// The header exactly as the kernel will read it.
    ///
    /// Reads back the staged storage rather than rebuilding it, so it
    /// shows what was actually written.
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

    /// Mutate the buffers before submission — the usual way to fill the
    /// message.
    ///
    /// The descriptors already point at these buffers and are unaffected
    /// by writing through them; use [`with_lens`](Self::with_lens) to
    /// change how much of each is sent.
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
    ) -> (Sqe, PendingSendmsg<B, R, N>) {
        let hdr = self.region.header_ptr();
        // SAFETY: `hdr` points at a `MsgHdr` staged inside storage this
        // request owns, whose `msg_iov` names a descriptor array in the
        // same storage, whose entries name buffers owned by `self.bufs`.
        // Everything the kernel will dereference therefore lives in memory
        // this request owns. All of it moves into `PendingSendmsg`, whose
        // destructor is suppressed unless a receipt proves the kernel
        // finished, so every address outlives the kernel's access.
        let sqe = unsafe { Sqe::sendmsg_ptr(self.fd, hdr.cast_const(), self.flags) };
        let (store, hdr, vecs, name, count) = self.region.into_raw_parts();
        let pending = PendingSendmsg {
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
        };
        (sqe.user_data(id.raw()), pending)
    }
}

/// A submitted `sendmsg` whose storage the kernel may be reading.
///
/// `Send` when its buffers and staging storage are, so the ticket can
/// cross to a completion thread like any other.
///
/// # Drop and `forget` both leak rather than free
///
/// Dropping this runs no destructor for the buffers or the staging
/// storage. The kernel may still be reading the header, following it to
/// the descriptor array, and reading the buffers that array names, and
/// nothing here can prove otherwise — so all of it leaks on purpose, the
/// same failure mode as every other in-flight ticket.
#[must_use = "dropping the ticket leaks the buffers and the staging storage"]
pub struct PendingSendmsg<B, R, const N: usize> {
    bufs: ManuallyDrop<[B; N]>,
    store: ManuallyDrop<R>,
    hdr: *mut MsgHdr,
    vecs: *mut IoVec,
    name: *mut SockAddrIn,
    count: usize,
    ring: RingId,
    id: RequestId,
    /// Carried so a rejected push can be handed back aimed where the
    /// caller aimed it, rather than at a default socket.
    fd: RawFd,
    flags: MsgFlags,
    target: SendTarget,
}

// SAFETY: every pointer refers into `store`, which this ticket exclusively
// owns and keeps at a fixed address for its whole life, so moving the
// ticket between threads leaves the kernel's pointers valid.
unsafe impl<B: Send, R: Send, const N: usize> Send for PendingSendmsg<B, R, N> {}

impl<B, R, const N: usize> PendingSendmsg<B, R, N> {
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
    pub fn redeem(self, receipt: Receipt) -> Result<SendmsgCompleted<B, R, N>, (Self, Receipt)> {
        if !self.matches(&receipt) {
            return Err((self, receipt));
        }
        let mut this = ManuallyDrop::new(self);
        // SAFETY: the receipt proves the kernel posted this request's
        // terminal completion, so it holds no pointer into either owner.
        // `this` is wrapped in `ManuallyDrop`, so taking the fields cannot
        // double-drop them.
        let (bufs, store) = unsafe {
            (
                ManuallyDrop::take(&mut this.bufs),
                ManuallyDrop::take(&mut this.store),
            )
        };
        Ok(SendmsgCompleted {
            bufs,
            region: MsgRegion::from_parts(store, this.hdr, this.vecs, this.name, this.count),
            result: receipt.raw_result(),
        })
    }

    /// Take the storage back without a receipt, undoing a failed push.
    ///
    /// # Safety
    ///
    /// The kernel must never have seen this request's SQE. Calling this
    /// after publication hands back storage the kernel may still be
    /// reading.
    pub(crate) unsafe fn reclaim_unsubmitted(self) -> PreparedSendmsg<B, R, N> {
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
        PreparedSendmsg {
            bufs,
            region: MsgRegion::from_parts(store, this.hdr, this.vecs, this.name, this.count),
            fd: this.fd,
            flags: this.flags,
            target: this.target,
        }
    }
}

impl<B, R, const N: usize> Drop for PendingSendmsg<B, R, N> {
    fn drop(&mut self) {
        // Intentionally no `ManuallyDrop::drop`. See the type docs: the
        // kernel may still be reading the header, the descriptors, or the
        // buffers, so all of it leaks rather than being freed under an
        // in-flight request.
    }
}

/// A finished `sendmsg`, with every owner returned.
pub struct SendmsgCompleted<B, R, const N: usize> {
    bufs: [B; N],
    region: MsgRegion<R>,
    result: i32,
}

impl<B, R, const N: usize> SendmsgCompleted<B, R, N> {
    /// Raw CQE result: bytes sent when non-negative, `-errno` otherwise.
    #[must_use]
    pub const fn raw_result(&self) -> i32 {
        self.result
    }

    /// Bytes the kernel accepted from this message.
    ///
    /// A short result is not an error on a stream socket: the kernel takes
    /// what fits and the caller sends the rest.
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

    /// The header as the kernel left it.
    ///
    /// `sendmsg` does not write back, so this still holds what was staged
    /// before submission. It is exposed for the same reason the send-side
    /// tests assert on it: it is the only way to see what the kernel was
    /// actually told.
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
