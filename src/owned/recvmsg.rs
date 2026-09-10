//! `recvmsg`, where the header is an output as well as an input.
//!
//! [`PreparedSendmsg`](super::PreparedSendmsg) established the shape: the
//! SQE names a `struct msghdr`, and the kernel reads *that* to find the
//! descriptor array and the address before following either to the data.
//! `recvmsg` uses the same three chained regions, staged the same way in
//! one [`MsgRegion`](super::msgregion).
//!
//! What differs is the direction. A send's header is read once and left
//! alone; measured, not assumed. A receive's header is **written back**:
//! the kernel overwrites `msg_namelen` with the peer address's real size
//! and `msg_flags` with what happened, so the staging region is memory the
//! kernel both reads and writes. The payload buffers therefore need
//! [`StableBufferMut`], and the region is no longer merely staging — it
//! carries the completion's most important field.
//!
//! # The result does not tell you whether you lost data
//!
//! An 11-byte datagram delivered into a 2-byte buffer completes with `2`,
//! which is byte-for-byte what a 2-byte datagram that arrived whole
//! reports. The nine discarded bytes appear nowhere in the CQE. Only
//! [`MsgOutFlags::TRUNC`], written back into the header, distinguishes
//! them — so [`RecvmsgCompleted::received`] returns the flags alongside
//! the count rather than letting a caller read the count alone.
//!
//! Truncation is a datagram property: the same 11 bytes into the same
//! 2-byte buffer on a stream socket also reports `2`, but sets no flag,
//! because the remaining nine are still queued.
//!
//! # The reported address size can exceed the room reserved
//!
//! [`MsgRegion`](super::msgregion) reserves one `SockAddrIn`, 16 bytes.
//! An IPv6 peer's address is 28, and the kernel reports 28 in
//! `msg_namelen` while writing only the 16 it was given — verified: the
//! bytes past the reservation were untouched. So the written-back length
//! cannot be used to bound the slot, and [`PeerAddress`] exists to make
//! that unrepresentable: it yields a `SockAddrIn` only when the kernel's
//! own reported length says one whole IPv4 address was written.
//!
//! [`MsgRegion`]: super::msgregion

use core::mem::ManuallyDrop;

use super::buffer::StableBufferMut;
use super::identity::{RequestId, RingId};
use super::msgregion::{MsgRegion, MsgRegionError};
use super::request::Receipt;
use crate::error::Error;
use crate::op::Sqe;
use crate::types::{AddressFamily, IoVec, MsgFlags, MsgHdr, MsgOutFlags, RawFd, SockAddrIn};

/// `AF_INET` as it appears in a `sockaddr_in`'s family field.
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
const AF_INET_FAMILY: u16 = AddressFamily::Inet.as_raw() as u16;

/// Bytes the staged address slot holds, as the kernel reports lengths.
#[allow(clippy::cast_possible_truncation)]
const RESERVED_NAME_LEN: u32 = size_of::<SockAddrIn>() as u32;

/// Whether a `recvmsg` reserves room for the sender's address.
///
/// A connected socket already knows its peer and the kernel writes no
/// address back at all — measured: `msg_namelen` comes back `0` on a
/// connected stream socket however much room was reserved. An unconnected
/// datagram socket needs the room to learn who sent each message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerWanted {
    /// Reserve nothing; the header names no address.
    No,
    /// Reserve one `SockAddrIn` for the kernel to fill in.
    Yes,
}

/// What the kernel wrote into the reserved address slot.
///
/// The reserved slot is one `SockAddrIn`, and the kernel does not promise
/// to fill it. Three measured behaviours make the reported length and a
/// readable IPv4 address different things:
///
/// - a connected socket writes nothing and reports `0`;
/// - an IPv6 peer reports `28` while writing only the 16 bytes reserved,
///   leaving the rest of the slot as it found it;
/// - an `AF_UNIX` peer with a short path reports a length *between* the
///   two — 11 for `/tmp/qq1` — writing only that many bytes.
///
/// So neither the length alone nor the presence of bytes proves an IPv4
/// address is there. [`V4`](Self::V4) is produced only when the kernel's
/// own reported length is exactly a whole `SockAddrIn` *and* the family it
/// wrote is `AF_INET`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerAddress {
    /// No room was reserved, or the kernel wrote nothing — which is what a
    /// connected socket does.
    None,
    /// A whole IPv4 address was written.
    V4(SockAddrIn),
    /// The peer's address is larger than the reserved slot, so only a
    /// prefix was written and it cannot be read as an address.
    ///
    /// An IPv6 peer does this: 28 bytes reported into 16 reserved.
    Truncated {
        /// Size the kernel reported, in bytes.
        reported: u32,
        /// Size the region reserved, in bytes.
        reserved: u32,
    },
    /// An address that fits the slot but is not an IPv4 one.
    ///
    /// A short `AF_UNIX` path is the reachable case: fewer bytes written
    /// than the slot holds, so reading the whole slot would mix the
    /// kernel's bytes with whatever preceded them.
    Other {
        /// Address family the kernel wrote, when it wrote enough bytes to
        /// hold one.
        family: u16,
        /// Size the kernel reported, in bytes.
        reported: u32,
    },
}

impl PeerAddress {
    /// The address, when a whole IPv4 one was written.
    #[must_use]
    pub const fn v4(self) -> Option<SockAddrIn> {
        match self {
            Self::V4(addr) => Some(addr),
            _ => None,
        }
    }

    /// Whether the peer's address was too large for the reserved slot.
    #[must_use]
    pub const fn is_truncated(self) -> bool {
        matches!(self, Self::Truncated { .. })
    }
}

/// A `recvmsg` that owns its buffers and staging storage, not yet queued.
///
/// `B` holds the payload, `N` of them; `R` holds the header, the
/// descriptor array, and the address slot. All of it comes back together
/// from [`RecvmsgCompleted::into_parts`].
pub struct PreparedRecvmsg<B, R, const N: usize> {
    bufs: [B; N],
    region: MsgRegion<R>,
    fd: RawFd,
    flags: MsgFlags,
    peer: PeerWanted,
}

impl<B: StableBufferMut, R: StableBufferMut, const N: usize> PreparedRecvmsg<B, R, N> {
    /// Prepare a `recvmsg` scattering one message across every buffer.
    ///
    /// Takes ownership of the buffers and of the staging storage. The
    /// kernel writes into both after submission — the buffers with the
    /// payload, the region with the header it updates — so no caller alias
    /// to either may survive.
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
        peer: PeerWanted,
        flags: MsgFlags,
    ) -> Result<Self, ([B; N], R, MsgRegionError)> {
        let mut lens = [0usize; N];
        for (slot, buf) in lens.iter_mut().zip(bufs.iter()) {
            *slot = buf.stable_len();
        }
        Self::build(fd, bufs, region, peer, flags, &lens)
    }

    /// Cap how much of each buffer the kernel may fill.
    ///
    /// Each length is clamped to its buffer, so this can never describe
    /// more memory than the owner actually has. Shortening a receive
    /// descriptor discards data on a datagram socket rather than leaving
    /// it queued, so the flags in the completion are the only warning.
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
        peer: PeerWanted,
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
            peer,
        };
        prepared.write_descriptors(lens);
        prepared.publish();
        Ok(prepared)
    }

    /// Stamp the staged array with each buffer's address and capacity.
    fn write_descriptors(&mut self, lens: &[usize; N]) {
        for (i, (buf, len)) in self.bufs.iter_mut().zip(lens.iter()).enumerate() {
            // SAFETY: `i < N` and the region was staged for `N`
            // descriptors. The address comes from `StableBufferMut`, so it
            // stays valid for as long as this value owns the buffer, which
            // outlasts the kernel's access.
            unsafe {
                self.region.write_descriptor(i, buf.stable_mut_ptr(), *len);
            }
        }
    }

    /// Zero the address slot and write the header the kernel will read.
    ///
    /// The slot is zeroed rather than left as whatever the storage last
    /// held, so a completion that reports an address the kernel never
    /// wrote yields zeroes rather than a stale peer from an earlier
    /// request through the same region.
    fn publish(&mut self) {
        let named = matches!(self.peer, PeerWanted::Yes);
        if named {
            self.region.write_name(SockAddrIn::default());
        }
        self.region.publish_header(named);
    }
}

impl<B, R, const N: usize> PreparedRecvmsg<B, R, N> {
    /// The socket this message is received on.
    #[must_use]
    pub const fn fd(&self) -> RawFd {
        self.fd
    }

    /// The receive flags this request carries.
    #[must_use]
    pub const fn flags(&self) -> MsgFlags {
        self.flags
    }

    /// Whether room is reserved for the sender's address.
    #[must_use]
    pub const fn peer_wanted(&self) -> PeerWanted {
        self.peer
    }

    /// How many buffers this receive scatters across.
    #[must_use]
    pub const fn count(&self) -> usize {
        N
    }

    /// Total bytes the kernel may write across every descriptor.
    #[must_use]
    pub fn capacity(&self) -> usize {
        (0..N).map(|i| self.region.descriptor(i).len()).sum()
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
    ) -> (Sqe, PendingRecvmsg<B, R, N>) {
        let hdr = self.region.header_ptr();
        // SAFETY: `hdr` points at a `MsgHdr` staged inside storage this
        // request owns, whose `msg_iov` names a descriptor array in the
        // same storage, whose entries name buffers owned by `self.bufs`.
        // The kernel writes through all of it, and all of it moves into
        // `PendingRecvmsg`, whose destructor is suppressed unless a receipt
        // proves the kernel finished — so every address stays valid and
        // unaliased for the whole window.
        let sqe = unsafe { Sqe::recvmsg_ptr(self.fd, hdr, self.flags) };
        let (store, hdr, vecs, name, count) = self.region.into_raw_parts();
        let pending = PendingRecvmsg {
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
            wanted: self.peer,
        };
        (sqe.user_data(id.raw()), pending)
    }
}

/// A submitted `recvmsg` whose storage the kernel may be writing.
///
/// `Send` when its buffers and staging storage are, so the ticket can
/// cross to a completion thread like any other.
///
/// # Drop and `forget` both leak rather than free
///
/// Dropping this runs no destructor for the buffers or the staging
/// storage. The kernel may still be writing the header, reading it to
/// reach the descriptor array, and filling the buffers that array names,
/// and nothing here can prove otherwise — so all of it leaks on purpose,
/// the same failure mode as every other in-flight ticket.
#[must_use = "dropping the ticket leaks the buffers and the staging storage"]
pub struct PendingRecvmsg<B, R, const N: usize> {
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
    wanted: PeerWanted,
}

// SAFETY: every pointer refers into `store`, which this ticket exclusively
// owns and keeps at a fixed address for its whole life, so moving the
// ticket between threads leaves the kernel's pointers valid.
unsafe impl<B: Send, R: Send, const N: usize> Send for PendingRecvmsg<B, R, N> {}

impl<B, R, const N: usize> PendingRecvmsg<B, R, N> {
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

    /// The socket this message is received on.
    #[must_use]
    pub const fn fd(&self) -> RawFd {
        self.fd
    }

    /// How many buffers this receive scatters across.
    #[must_use]
    pub const fn count(&self) -> usize {
        N
    }

    /// Whether `receipt` authenticates this exact request.
    #[must_use]
    pub const fn matches(&self, receipt: &Receipt) -> bool {
        receipt.id().raw() == self.id.raw() && receipt.ring().raw() == self.ring.raw()
    }

    /// Exchange a receipt for the storage, the kernel's result, and the
    /// header it wrote back.
    ///
    /// # Errors
    ///
    /// Returns the ticket and the receipt unchanged if the receipt names a
    /// different request or a different ring.
    pub fn redeem(self, receipt: Receipt) -> Result<RecvmsgCompleted<B, R, N>, (Self, Receipt)> {
        if !self.matches(&receipt) {
            return Err((self, receipt));
        }
        let wanted = self.wanted;
        let mut this = ManuallyDrop::new(self);
        // SAFETY: the receipt proves the kernel posted this request's
        // terminal completion, so it holds no pointer into either owner and
        // has finished writing both. `this` is wrapped in `ManuallyDrop`,
        // so taking the fields cannot double-drop them.
        let (bufs, store) = unsafe {
            (
                ManuallyDrop::take(&mut this.bufs),
                ManuallyDrop::take(&mut this.store),
            )
        };
        Ok(RecvmsgCompleted {
            bufs,
            region: MsgRegion::from_parts(store, this.hdr, this.vecs, this.name, this.count),
            result: receipt.raw_result(),
            wanted,
        })
    }

    /// Take the storage back without a receipt, undoing a failed push.
    ///
    /// # Safety
    ///
    /// The kernel must never have seen this request's SQE. Calling this
    /// after publication hands back storage the kernel may still be
    /// writing.
    pub(crate) unsafe fn reclaim_unsubmitted(self) -> PreparedRecvmsg<B, R, N> {
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
        PreparedRecvmsg {
            bufs,
            region: MsgRegion::from_parts(store, this.hdr, this.vecs, this.name, this.count),
            fd: this.fd,
            flags: this.flags,
            peer: this.wanted,
        }
    }
}

impl<B, R, const N: usize> Drop for PendingRecvmsg<B, R, N> {
    fn drop(&mut self) {
        // Intentionally no `ManuallyDrop::drop`. See the type docs: the
        // kernel may still be writing the header, reading the descriptors,
        // or filling the buffers, so all of it leaks rather than being
        // freed under an in-flight request.
    }
}

/// A finished `recvmsg`, with every owner returned and the header the
/// kernel wrote back.
pub struct RecvmsgCompleted<B, R, const N: usize> {
    bufs: [B; N],
    region: MsgRegion<R>,
    result: i32,
    wanted: PeerWanted,
}

impl<B, R, const N: usize> RecvmsgCompleted<B, R, N> {
    /// Raw CQE result: bytes received when non-negative, `-errno`
    /// otherwise.
    #[must_use]
    pub const fn raw_result(&self) -> i32 {
        self.result
    }

    /// Whether the kernel failed the request.
    ///
    /// A failure writes nothing back — verified: after `EAGAIN` the header
    /// still held the caller's own `msg_namelen` and `msg_flags`. So the
    /// header's contents mean nothing unless this is false, which is why
    /// [`received`](Self::received) refuses to report them on failure.
    #[must_use]
    pub const fn failed(&self) -> bool {
        self.result < 0
    }

    /// The header as the kernel left it.
    #[must_use]
    pub const fn header(&self) -> MsgHdr {
        self.region.header()
    }

    /// Bytes received together with what the kernel reported about them.
    ///
    /// The count alone cannot say whether data was lost: an 11-byte
    /// datagram into a 2-byte buffer reports `2`, exactly as a whole
    /// 2-byte datagram does. The flags are returned with it so the
    /// question is at least askable — see
    /// [`Received::truncated`](Received::truncated).
    ///
    /// # Errors
    ///
    /// Returns [`CompletionError::Failed`](crate::CompletionError::Failed)
    /// when the CQE carried a negative errno.
    #[allow(clippy::cast_sign_loss)]
    pub const fn received(&self) -> Result<Received, Error> {
        if self.failed() {
            return Err(Error::Completion(crate::CompletionError::Failed(
                crate::Errno::new(-self.result),
            )));
        }
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let flags = MsgOutFlags::from_raw(self.header().msg_flags as u32);
        Ok(Received {
            bytes: self.result as u32,
            flags,
        })
    }

    /// The sender's address, when room was reserved and the kernel filled
    /// it.
    ///
    /// The kernel reports the peer address's real size while writing only
    /// what was reserved, so this reports
    /// [`Truncated`](PeerAddress::Truncated) rather than handing back a
    /// prefix that would read as a malformed address.
    #[must_use]
    pub const fn peer(&self) -> PeerAddress {
        if self.failed() || matches!(self.wanted, PeerWanted::No) {
            return PeerAddress::None;
        }
        let reserved = RESERVED_NAME_LEN;
        let reported = self.header().msg_namelen;
        if reported == 0 {
            return PeerAddress::None;
        }
        if reported > reserved {
            return PeerAddress::Truncated { reported, reserved };
        }
        // Fewer bytes than the slot holds means the tail is whatever the
        // region held before, so the whole slot cannot be read as an
        // address even though every byte of it is initialised.
        let staged = self.region.staged_name();
        if reported < reserved || staged.sin_family != AF_INET_FAMILY {
            return PeerAddress::Other {
                family: staged.sin_family,
                reported,
            };
        }
        PeerAddress::V4(staged)
    }

    /// Borrow the buffers.
    #[must_use]
    pub const fn buffers(&self) -> &[B; N] {
        &self.bufs
    }

    /// The outcome alongside every owner.
    ///
    /// Returns the storage even on failure, so a failed receive never
    /// costs a buffer.
    pub fn into_parts(self) -> (Result<Received, Error>, PeerAddress, [B; N], R) {
        let received = self.received();
        let peer = self.peer();
        (received, peer, self.bufs, self.region.into_store())
    }
}

/// What a successful `recvmsg` delivered.
///
/// The byte count and the flags travel together because neither answers
/// the caller's real question alone: `bytes` says how much is readable,
/// and only [`truncated`](Self::truncated) says whether that is all there
/// was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Received {
    bytes: u32,
    flags: MsgOutFlags,
}

impl Received {
    /// Bytes written into the buffers, in descriptor order.
    #[must_use]
    pub const fn bytes(self) -> u32 {
        self.bytes
    }

    /// The `msg_flags` the kernel wrote back.
    #[must_use]
    pub const fn flags(self) -> MsgOutFlags {
        self.flags
    }

    /// Whether the kernel discarded payload that did not fit.
    ///
    /// Only datagram sockets report this. A stream socket leaves the
    /// remainder queued and sets nothing, so a short read there is not a
    /// loss.
    #[must_use]
    pub const fn truncated(self) -> bool {
        self.flags.contains(MsgOutFlags::TRUNC)
    }

    /// Whether control data was discarded for lack of room.
    #[must_use]
    pub const fn control_truncated(self) -> bool {
        self.flags.contains(MsgOutFlags::CTRUNC)
    }
}
