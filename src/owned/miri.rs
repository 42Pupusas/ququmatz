//! Miri-executable checks for the owned-request lifecycle.
//!
//! Miri cannot run this crate's syscalls — they are inline `asm!`, which it
//! refuses — so neither [`MmapBuffer`](super::MmapBuffer) nor a real ring
//! is reachable here. The lifecycle types are generic over the buffer, so
//! these tests substitute heap storage and a stand-in kernel that touches
//! the bytes through the pointer the SQE actually carries.
//!
//! That is the part worth machine-checking: whether `Pending` keeps the
//! storage alive and addressable across the whole window the kernel could
//! be using it, and whether the pointer path from buffer to SQE and back
//! preserves provenance.

extern crate std;

use core::mem::align_of;
use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::boxed::Box;
use std::vec::Vec;

use super::bind::{BindOutcome, PendingBind, PreparedBind};
use super::connect::{ConnectOutcome, PendingConnect, PreparedConnect};
use super::direct::{PendingDirectOpen, PreparedDirectOpen};
use super::epoll::{EpollChange, EpollOutcome, PendingEpollCtl, PreparedEpollCtl};
use super::event::PartialReceipt;
use super::filesupdate::{PendingFilesUpdate, PreparedFilesUpdate, TableEntry, Update};
use super::identity::{RequestId, RequestIdSource, RingId};
use super::open::{PendingOpen, PreparedOpen};
use super::openat2::{PendingOpenat2, PreparedOpenat2};
use super::path::OwnedPath;
use super::pathop::{PendingPathOp, PreparedPathOp};
use super::recvmsg::{PeerWanted, PendingRecvmsg, PreparedRecvmsg};
use super::rename::{PendingRename, PreparedRename};
use super::sendmsg::{PendingSendmsg, PreparedSendmsg, SendTarget};
use super::slot::SlotIndex;
use super::slot::SlotTarget;
use super::statx::{PendingStatx, PreparedStatx};
use super::timeout::{Count, PendingTimeout, PreparedTimeout};
use super::vectored::{PendingVectored, PreparedVectored};
use super::zerocopy::{PendingZc, PreparedZc};
use super::{
    Direction, Openat2Mode, PathOpKind, Pending, Prepared, Receipt, RenameMode, StableBuffer,
    StableBufferMut,
};
use crate::op::Sqe;
use crate::types::{
    CqeFlags, EpollEvent, EpollEvents, FileMode, IoVec, MsgFlags, MsgHdr, OpenFlags, OpenHow,
    RawFd, ResolveFlags, SockAddrIn, Statx, StatxFlags, StatxMask, Timespec,
};

/// Heap storage standing in for an `MmapBuffer`.
///
/// Deliberately holds a raw allocation rather than a `Box<[u8]>`. A `Box`
/// asserts unique access to its pointee every time it is moved, which pops
/// any previously derived raw pointer off the borrow stack — so a
/// `Box`-backed buffer would invalidate the kernel's pointer the moment the
/// ticket moved between threads. Owning the allocation directly is what
/// `MmapBuffer` does with its mapping, and is the shape `StableBuffer`
/// actually requires.
struct HeapBuffer {
    ptr: *mut u8,
    len: usize,
    align: usize,
}

impl HeapBuffer {
    fn layout_of(len: usize, align: usize) -> Layout {
        Layout::from_size_align(len, align).expect("valid layout")
    }

    fn layout(&self) -> Layout {
        Self::layout_of(self.len, self.align)
    }

    /// Byte storage, aligned to 1 like the data buffers it stands in for.
    fn with_capacity(len: usize) -> Self {
        Self::with_alignment(len, 1)
    }

    /// Storage for an `IoVec` array.
    ///
    /// Descriptor storage genuinely has to be aligned for `IoVec`, and a
    /// byte-aligned allocation is not — Miri rejects it, where the system
    /// allocator happens to hand back aligned addresses and hides the
    /// problem. `MmapBuffer` is page-aligned, so this matches what real
    /// callers pass.
    fn for_descriptors(len: usize) -> Self {
        Self::with_alignment(len, align_of::<IoVec>())
    }

    fn with_alignment(len: usize, align: usize) -> Self {
        assert!(len > 0, "zero-length test buffer");
        let ptr = unsafe { alloc_zeroed(Self::layout_of(len, align)) };
        assert!(!ptr.is_null(), "allocation failed");
        Self { ptr, len, align }
    }

    fn as_slice(&self) -> &[u8] {
        // SAFETY: `ptr` is a live allocation of `len` initialised bytes that
        // this struct solely owns.
        unsafe { core::slice::from_raw_parts(self.ptr, self.len) }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: as above, and `&mut self` proves exclusive access.
        unsafe { core::slice::from_raw_parts_mut(self.ptr, self.len) }
    }

    /// Free storage that an abandoned `Pending` deliberately leaked.
    ///
    /// Only the tests that assert the leak call this, and only once the
    /// stand-in kernel has finished. It exists so Miri's leak checker stays
    /// enabled for every other test rather than being switched off wholesale.
    ///
    /// # Safety
    ///
    /// `addr` must be a leaked `HeapBuffer` allocation of exactly `len`
    /// bytes with no live references remaining.
    unsafe fn reclaim_leaked(ptr: *mut u8, len: usize) {
        // SAFETY: the caller guarantees this pointer came from
        // `with_capacity(len)`, whose alignment is 1, and is unreachable.
        unsafe { Self::reclaim_aligned(ptr, len, 1) };
    }

    /// Free leaked descriptor storage, which has its own alignment.
    ///
    /// # Safety
    ///
    /// `ptr` must come from `for_descriptors(len)` and be unreachable.
    unsafe fn reclaim_leaked_descriptors(ptr: *mut u8, len: usize) {
        // SAFETY: as above, with the alignment `for_descriptors` used.
        unsafe { Self::reclaim_aligned(ptr, len, align_of::<IoVec>()) };
    }

    /// Free leaked storage of any alignment.
    ///
    /// # Safety
    ///
    /// `ptr` must come from `with_alignment(len, align)` and have no live
    /// references remaining.
    unsafe fn reclaim_aligned(ptr: *mut u8, len: usize, align: usize) {
        // SAFETY: the caller guarantees the pointer and layout match the
        // allocation and that nothing else references it.
        unsafe { dealloc(ptr, Self::layout_of(len, align)) };
    }
}

impl Drop for HeapBuffer {
    fn drop(&mut self) {
        // SAFETY: `ptr` came from `alloc_zeroed` with this exact layout and
        // is freed exactly once, since `Pending` never drops its buffer.
        unsafe { dealloc(self.ptr, self.layout()) };
    }
}

// SAFETY: the allocation is owned solely by this struct and never moves,
// so its address is fixed for the owner's life.
unsafe impl StableBuffer for HeapBuffer {
    fn stable_ptr(&self) -> *const u8 {
        self.ptr
    }

    fn stable_len(&self) -> usize {
        self.len
    }
}

// SAFETY: the same allocation, exclusively owned, is writable.
unsafe impl StableBufferMut for HeapBuffer {
    fn stable_mut_ptr(&mut self) -> *mut u8 {
        self.ptr
    }
}

// SAFETY: the allocation is owned exclusively and has no thread affinity,
// mirroring `MmapBuffer`.
unsafe impl Send for HeapBuffer {}

/// A stand-in for the kernel that accesses a buffer only through the
/// address published in the SQE, exactly as `io_uring` does.
///
/// Holding the `Sqe` by value mirrors the real hazard: the kernel's copy of
/// the pointer outlives the borrow that produced it.
struct FakeKernel {
    sqe: Sqe,
}

impl FakeKernel {
    const fn holding(sqe: Sqe) -> Self {
        Self { sqe }
    }

    fn addr(&self) -> u64 {
        self.sqe.0.addr
    }

    /// The published address as a pointer.
    ///
    /// The SQE stores a `u64` because that is the kernel ABI, so recovering a
    /// pointer is an int-to-pointer cast by necessity. The `ptr as u64` casts
    /// in `src/op/` expose the provenance at the source, so accesses through
    /// this pointer are checked under the default provenance mode. They are
    /// NOT checked under `-Zmiri-strict-provenance`, which rejects this cast
    /// outright; these tests are therefore run in the default mode and cannot
    /// be strengthened to strict without an ABI that carries pointers.
    fn published_ptr(&self) -> *mut u8 {
        let addr = usize::try_from(self.addr()).expect("address fits a pointer");
        core::ptr::with_exposed_provenance_mut(addr)
    }

    fn len(&self) -> usize {
        self.sqe.0.len as usize
    }

    fn user_data(&self) -> u64 {
        self.sqe.0.user_data
    }

    /// Write `fill` into the published buffer, as a `read` completion would.
    ///
    /// This is the access that must not be a use-after-free: it happens
    /// while only a `Pending` owns the storage.
    fn complete_read(&self, fill: u8) -> i32 {
        let dst = self.published_ptr();
        let len = self.len();
        for i in 0..len {
            // SAFETY: the `Pending` that owns this buffer is alive for the
            // whole call, and its contract says the bytes stay allocated,
            // writable and unaliased until it is redeemed.
            unsafe { dst.add(i).write(fill) };
        }
        i32::try_from(len).expect("test length fits in i32")
    }

    /// Read the published buffer back out, as a `write` submission would.
    fn observe_write(&self) -> Vec<u8> {
        let src = self.published_ptr().cast_const();
        let len = self.len();
        let mut seen = Vec::with_capacity(len);
        for i in 0..len {
            // SAFETY: as above; the owner outlives this call.
            seen.push(unsafe { src.add(i).read() });
        }
        seen
    }

    /// Mint the receipt this operation's CQE would authorize.
    fn post_completion(&self, ring: RingId, result: i32) -> Receipt {
        Receipt {
            ring,
            id: RequestId::from_raw(self.user_data()),
            result,
            flags: CqeFlags::from_raw(0),
        }
    }

    /// Mint the non-terminal send CQE of a zero-copy send.
    ///
    /// The real kernel sets `MORE` here to promise a notification; this
    /// carries no `Receipt`, so it cannot release the buffer.
    fn post_send(&self, ring: RingId, result: i32) -> PartialReceipt {
        PartialReceipt {
            ring,
            id: RequestId::from_raw(self.user_data()),
            result,
            flags: CqeFlags::MORE,
        }
    }

    /// Mint the notification CQE that finally releases the pages.
    fn post_notification(&self, ring: RingId) -> Receipt {
        Receipt {
            ring,
            id: RequestId::from_raw(self.user_data()),
            result: 0,
            flags: CqeFlags::NOTIF,
        }
    }
}

/// Drives a request through its whole lifecycle without a real ring.
struct Lifecycle {
    ring: RingId,
    ids: RequestIdSource,
}

impl Lifecycle {
    fn new() -> Self {
        Self {
            ring: RingId::next(),
            ids: RequestIdSource::new(),
        }
    }

    fn submit<B: StableBuffer>(&self, prepared: Prepared<B>) -> (FakeKernel, Pending<B>) {
        let (sqe, pending) = prepared.into_pending(self.ring, self.ids.next());
        (FakeKernel::holding(sqe), pending)
    }

    fn submit_zc<B: StableBuffer>(&self, prepared: PreparedZc<B>) -> (FakeKernel, PendingZc<B>) {
        let (sqe, pending) = prepared.into_pending(self.ring, self.ids.next());
        (FakeKernel::holding(sqe), pending)
    }

    fn submit_vectored<B: StableBuffer, V: StableBufferMut, const N: usize>(
        &self,
        prepared: PreparedVectored<B, V, N>,
    ) -> (FakeKernel, PendingVectored<B, V, N>) {
        let (sqe, pending) = prepared.into_pending(self.ring, self.ids.next());
        (FakeKernel::holding(sqe), pending)
    }

    fn submit_open<S: StableBuffer>(
        &self,
        prepared: PreparedOpen<S>,
    ) -> (FakeKernel, PendingOpen<S>) {
        let (sqe, pending) = prepared.into_pending(self.ring, self.ids.next());
        (FakeKernel::holding(sqe), pending)
    }

    fn submit_direct_open<S: StableBuffer>(
        &self,
        prepared: PreparedDirectOpen<S>,
    ) -> (FakeKernel, PendingDirectOpen<S>) {
        let (sqe, pending) = prepared.into_pending(self.ring, self.ids.next());
        (FakeKernel::holding(sqe), pending)
    }

    fn submit_statx<S: StableBuffer, D: StableBufferMut>(
        &self,
        prepared: PreparedStatx<S, D>,
    ) -> (FakeKernel, PendingStatx<S, D>) {
        let (sqe, pending) = prepared.into_pending(self.ring, self.ids.next());
        (FakeKernel::holding(sqe), pending)
    }

    fn submit_path_op<S: StableBuffer>(
        &self,
        prepared: PreparedPathOp<S>,
    ) -> (FakeKernel, PendingPathOp<S>) {
        let (sqe, pending) = prepared.into_pending(self.ring, self.ids.next());
        (FakeKernel::holding(sqe), pending)
    }

    fn submit_rename<F: StableBuffer, T: StableBuffer>(
        &self,
        prepared: PreparedRename<F, T>,
    ) -> (FakeKernel, PendingRename<F, T>) {
        let (sqe, pending) = prepared.into_pending(self.ring, self.ids.next());
        (FakeKernel::holding(sqe), pending)
    }

    fn submit_openat2<S: StableBuffer, H: StableBufferMut>(
        &self,
        prepared: PreparedOpenat2<S, H>,
    ) -> (FakeKernel, PendingOpenat2<S, H>) {
        let (sqe, pending) = prepared.into_pending(self.ring, self.ids.next());
        (FakeKernel::holding(sqe), pending)
    }

    fn submit_sendmsg<B: StableBuffer, R: StableBufferMut, const N: usize>(
        &self,
        prepared: PreparedSendmsg<B, R, N>,
    ) -> (FakeKernel, PendingSendmsg<B, R, N>) {
        let (sqe, pending) = prepared.into_pending(self.ring, self.ids.next());
        (FakeKernel::holding(sqe), pending)
    }

    fn submit_recvmsg<B: StableBufferMut, R: StableBufferMut, const N: usize>(
        &self,
        prepared: PreparedRecvmsg<B, R, N>,
    ) -> (FakeKernel, PendingRecvmsg<B, R, N>) {
        let (sqe, pending) = prepared.into_pending(self.ring, self.ids.next());
        (FakeKernel::holding(sqe), pending)
    }

    fn submit_timeout<S: StableBufferMut>(
        &self,
        prepared: PreparedTimeout<S>,
    ) -> (FakeKernel, PendingTimeout<S>) {
        let (sqe, pending) = prepared.into_pending(self.ring, self.ids.next());
        (FakeKernel::holding(sqe), pending)
    }

    fn submit_files_update<S: StableBufferMut, const N: usize>(
        &self,
        prepared: PreparedFilesUpdate<S, N>,
    ) -> (FakeKernel, PendingFilesUpdate<S, N>) {
        let (sqe, pending) = prepared.into_pending(self.ring, self.ids.next());
        (FakeKernel::holding(sqe), pending)
    }

    fn submit_epoll_ctl<S: StableBufferMut>(
        &self,
        prepared: PreparedEpollCtl<S>,
    ) -> (FakeKernel, PendingEpollCtl<S>) {
        let (sqe, pending) = prepared.into_pending(self.ring, self.ids.next());
        (FakeKernel::holding(sqe), pending)
    }

    fn submit_bind<S: StableBufferMut>(
        &self,
        prepared: PreparedBind<S>,
    ) -> (FakeKernel, PendingBind<S>) {
        let (sqe, pending) = prepared.into_pending(self.ring, self.ids.next());
        (FakeKernel::holding(sqe), pending)
    }

    fn submit_connect<S: StableBufferMut>(
        &self,
        prepared: PreparedConnect<S>,
    ) -> (FakeKernel, PendingConnect<S>) {
        let (sqe, pending) = prepared.into_pending(self.ring, self.ids.next());
        (FakeKernel::holding(sqe), pending)
    }
}

impl FakeKernel {
    /// Read the `epoll_event` an `epoll_ctl` publishes at `addr`.
    ///
    /// The kernel reads this for an `Add` or a `Mod` and ignores it for a
    /// `Del`, but the storage has to be live either way — nothing in the
    /// SQE distinguishes "will not be read" from "has not been read yet".
    fn read_epoll_event(&self) -> EpollEvent {
        // `PreparedEpollCtl` rejected storage that was not aligned for an
        // `EpollEvent`, so this address is aligned.
        #[allow(clippy::cast_ptr_alignment)]
        let base = self.published_ptr().cast::<EpollEvent>();
        // SAFETY: the live `PendingEpollCtl` owns storage checked for size
        // and alignment against `EpollEvent` and written before
        // submission, and keeps it allocated until redeemed.
        unsafe { base.read() }
    }

    /// The operation code the SQE carries in `len`.
    const fn published_epoll_op(&self) -> u32 {
        self.sqe.0.len
    }

    /// Read the socket address a `bind` publishes at `addr`.
    ///
    /// Copied bytewise for the same reason the kernel does it that way:
    /// the address is staged as bytes and carries no alignment promise.
    fn read_sock_addr(&self) -> [u8; 16] {
        let base = self.published_ptr();
        let mut out = [0u8; 16];
        // SAFETY: the live `PendingBind` owns storage checked to hold a
        // whole socket address and written before submission, and keeps
        // it allocated until redeemed.
        unsafe { core::ptr::copy_nonoverlapping(base, out.as_mut_ptr(), out.len()) }
        out
    }

    /// The address length the SQE carries in `addr2`.
    const fn published_addr_len(&self) -> u64 {
        self.sqe.0.off
    }
}

impl FakeKernel {
    /// Read the descriptor array a `files_update` publishes at `addr`.
    ///
    /// The kernel walks `len` entries from this address, so the array is
    /// the region whose lifetime has to outlast the ticket's travels — the
    /// descriptors it names are duplicated and belong to whoever opened
    /// them.
    fn read_fd_array(&self) -> Vec<i32> {
        // `PreparedFilesUpdate` rejected storage that was not aligned for
        // an `i32`, so this address is aligned.
        #[allow(clippy::cast_ptr_alignment)]
        let base = self.published_ptr().cast::<i32>();
        let mut seen = Vec::new();
        for i in 0..self.len() {
            // SAFETY: the live `PendingFilesUpdate` owns storage checked to
            // hold `len` aligned `i32`s and written before submission, and
            // keeps it allocated until redeemed.
            seen.push(unsafe { base.add(i).read() });
        }
        seen
    }

    /// The table offset the SQE carries, which the kernel reads from `off`
    /// rather than from the caller's memory.
    const fn published_offset(&self) -> u64 {
        self.sqe.0.off
    }
}

impl FakeKernel {
    /// Read the `Timespec` a timeout publishes at `addr`.
    ///
    /// The real kernel copies this during `io_uring_enter` rather than
    /// while the timer runs, but under SQPOLL that copy happens on the SQ
    /// thread's own schedule, after the submitting call has returned. So
    /// the read modelled here is one that can land at any point while only
    /// a `PendingTimeout` owns the storage — which is what has to stay
    /// allocated.
    fn read_timespec(&self) -> Timespec {
        // `PreparedTimeout` rejected storage that was not aligned for a
        // `Timespec`, so this address is aligned.
        #[allow(clippy::cast_ptr_alignment)]
        let base = self.published_ptr().cast::<Timespec>();
        // SAFETY: the live `PendingTimeout` owns storage checked for size
        // and alignment against `Timespec` and written before submission,
        // and keeps it allocated until redeemed.
        unsafe { base.read() }
    }

    /// The completion count the SQE carries, which the kernel reads from
    /// `off` rather than from the caller's memory.
    const fn published_count(&self) -> u64 {
        self.sqe.0.off
    }
}

impl FakeKernel {
    /// Read the `msghdr` a message request publishes at `addr`.
    ///
    /// Every other owned request puts the addresses the kernel will
    /// dereference in the SQE, where they can be checked at submission.
    /// Here they are *bytes inside this struct*, so reading it is the only
    /// way to learn where the kernel goes next — and a header whose
    /// storage was freed hands back three plausible-looking addresses.
    fn read_msghdr(&self) -> MsgHdr {
        // The `MsgRegion` that built this SQE rejected storage that was not
        // aligned for a `MsgHdr`, so this address is aligned.
        #[allow(clippy::cast_ptr_alignment)]
        let base = self.published_ptr().cast::<MsgHdr>();
        // SAFETY: the live ticket owns storage checked for size and
        // alignment against `MsgHdr` and written before submission, and
        // keeps it allocated until redeemed.
        unsafe { base.read() }
    }

    /// Follow the header to descriptor `i`, as the kernel does.
    ///
    /// Deliberately reached through `msg_iov` rather than through the
    /// SQE's own address: the array is a *second* region, and a check that
    /// re-derived its location from anything but the header would still
    /// pass if the header pointed somewhere stale.
    fn message_descriptor(&self, i: usize) -> IoVec {
        let hdr = self.read_msghdr();
        assert!(i < hdr.msg_iovlen, "descriptor index past msg_iovlen");
        // SAFETY: the header names an array of `msg_iovlen` descriptors
        // staged inside storage the live ticket owns, so `add(i)` is in
        // bounds and initialised.
        unsafe { hdr.msg_iov.add(i).read() }
    }

    /// Read every byte the message gathers, header first, exactly as a
    /// `sendmsg` does: struct, then array, then buffers.
    ///
    /// Three levels of indirection, each one a separate allocation that
    /// must still be live. Any of them freed is a Miri error here rather
    /// than a wrong byte.
    fn observe_sendmsg(&self) -> Vec<u8> {
        let hdr = self.read_msghdr();
        let mut seen = Vec::new();
        for i in 0..hdr.msg_iovlen {
            let vec = self.message_descriptor(i);
            for j in 0..vec.len() {
                // SAFETY: the descriptor names a buffer owned by the live
                // ticket, which keeps it allocated and unaliased.
                seen.push(unsafe { vec.base().add(j).read() });
            }
        }
        seen
    }

    /// Deliver `payload` the way a `recvmsg` does: read the header, follow
    /// `msg_iov` to the descriptors, fill their buffers in order, then
    /// **write back** into the header.
    ///
    /// The write-back is what separates this from `observe_sendmsg`. The
    /// staging region is a destination as well as a source, so a ticket
    /// that freed it early is caught here on a write rather than a read —
    /// and the header is written *after* the buffers, matching the order
    /// that makes a stale header visible.
    ///
    /// Returns the bytes accepted, which is less than `payload` when the
    /// descriptors do not have room; that shortfall is exactly the
    /// truncation a real datagram socket reports in `msg_flags`.
    fn deliver_recvmsg(&self, payload: &[u8], peer: Option<SockAddrIn>) -> usize {
        let hdr = self.read_msghdr();
        let mut written = 0;
        for i in 0..hdr.msg_iovlen {
            let vec = self.message_descriptor(i);
            for j in 0..vec.len() {
                if written == payload.len() {
                    break;
                }
                // SAFETY: the descriptor names a buffer owned by the live
                // ticket, which keeps it allocated and unaliased.
                unsafe { vec.base().add(j).write(payload[written]) };
                written += 1;
            }
        }

        let mut back = hdr;
        back.msg_flags = if written < payload.len() {
            crate::types::MsgOutFlags::TRUNC.bits().cast_signed()
        } else {
            0
        };
        match peer {
            Some(addr) if !hdr.msg_name.is_null() => {
                assert!(
                    hdr.msg_namelen as usize >= core::mem::size_of::<SockAddrIn>(),
                    "a reserved address slot must hold a whole SockAddrIn"
                );
                // The `MsgRegion` staged this at an 8-byte-aligned offset
                // from an address checked for the same alignment.
                #[allow(clippy::cast_ptr_alignment)]
                let slot = hdr.msg_name.cast::<SockAddrIn>();
                // SAFETY: the live ticket owns the storage this slot lies
                // in and keeps it allocated and unaliased.
                unsafe { slot.write(addr) };
                #[allow(clippy::cast_possible_truncation)]
                {
                    back.msg_namelen = core::mem::size_of::<SockAddrIn>() as u32;
                }
            }
            // A connected socket has no per-message sender, so the kernel
            // reports a zero length however much room was reserved.
            _ => back.msg_namelen = 0,
        }

        // The `MsgRegion` rejected storage not aligned for a `MsgHdr`.
        #[allow(clippy::cast_ptr_alignment)]
        let dst = self.published_ptr().cast::<MsgHdr>();
        // SAFETY: the live ticket owns storage checked for size and
        // alignment against `MsgHdr`, and keeps it allocated until redeemed.
        unsafe { dst.write(back) };
        written
    }

    /// Report an address larger than the slot the caller reserved, writing
    /// only what fits — as the kernel does for an IPv6 peer into a
    /// `sockaddr_in`.
    fn deliver_oversized_peer(&self, payload: &[u8], reported: u32) -> usize {
        self.deliver_with_reported_namelen(payload, reported, None)
    }

    /// Deliver, then claim `reported` bytes of address regardless of what
    /// was written — with `wrote` optionally stamped into the slot first.
    ///
    /// Splitting the reported length from the bytes present is what a
    /// variable-length address family does. `AF_UNIX` reports 11 into a
    /// 16-byte slot; a caller believing the family field alone would still
    /// be wrong for a family that *is* `AF_INET` but short.
    fn deliver_with_reported_namelen(
        &self,
        payload: &[u8],
        reported: u32,
        wrote: Option<SockAddrIn>,
    ) -> usize {
        let written = self.deliver_recvmsg(payload, None);
        let hdr = self.read_msghdr();
        if let Some(addr) = wrote {
            assert!(!hdr.msg_name.is_null(), "no slot to write an address into");
            #[allow(clippy::cast_ptr_alignment)]
            let slot = hdr.msg_name.cast::<SockAddrIn>();
            // SAFETY: the live ticket owns the storage this slot lies in.
            unsafe { slot.write(addr) };
        }
        let mut back = hdr;
        back.msg_namelen = reported;
        #[allow(clippy::cast_ptr_alignment)]
        let dst = self.published_ptr().cast::<MsgHdr>();
        // SAFETY: as in `deliver_recvmsg`; the live ticket owns this header.
        unsafe { dst.write(back) };
        written
    }

    /// Read the destination address the header names.
    ///
    /// Returns `None` when the message carries no address, which is what a
    /// connected send stages — the kernel must not be handed a length
    /// without a pointer.
    fn message_name(&self) -> Option<SockAddrIn> {
        let hdr = self.read_msghdr();
        if hdr.msg_name.is_null() {
            assert_eq!(hdr.msg_namelen, 0, "a null address must have zero length");
            return None;
        }
        assert_eq!(
            hdr.msg_namelen as usize,
            core::mem::size_of::<SockAddrIn>(),
            "a staged address must be a whole SockAddrIn"
        );
        // The `MsgRegion` staged this at an 8-byte-aligned offset from an
        // address checked for the same alignment.
        #[allow(clippy::cast_ptr_alignment)]
        let base = hdr.msg_name.cast::<SockAddrIn>();
        // SAFETY: the address was written into storage the live ticket owns
        // before submission, and stays allocated until redeemed.
        Some(unsafe { base.read() })
    }
}

impl FakeKernel {
    /// Read the `open_how` an `openat2` publishes at `off`.
    ///
    /// `openat2` is the only owned request whose *parameters* live in
    /// caller memory, so this region needs its own read: a check that only
    /// scanned the path at `addr` would miss an `open_how` whose storage
    /// had been freed, and the kernel would open something described by
    /// whatever replaced it.
    fn read_open_how(&self) -> OpenHow {
        let addr = usize::try_from(self.sqe.0.off).expect("address fits a pointer");
        let base = core::ptr::with_exposed_provenance::<OpenHow>(addr);
        // SAFETY: the live `PendingOpenat2` owns storage checked for size
        // and alignment against `OpenHow` and written before submission,
        // and keeps it allocated until redeemed.
        unsafe { base.read() }
    }

    /// The length the SQE tells the kernel the `open_how` is.
    ///
    /// The kernel validates this against its own `sizeof`, answering
    /// `EINVAL` when it is short and `E2BIG` when it is long, so a wrong
    /// value here is a request that cannot succeed.
    const fn published_how_size(&self) -> u32 {
        self.sqe.0.len
    }
}

impl FakeKernel {
    /// Resolve the *second* path a rename publishes, at `off`.
    ///
    /// A rename is the only owned request that has the kernel scan two
    /// NUL-terminated strings, so the destination needs its own scan: a
    /// check that only walked `addr` would miss a destination whose
    /// storage had been freed.
    fn resolve_second_path(&self) -> Vec<u8> {
        let addr = usize::try_from(self.sqe.0.off).expect("address fits a pointer");
        let base: *const u8 = core::ptr::with_exposed_provenance(addr);
        let mut seen = Vec::new();
        let mut i = 0;
        loop {
            // SAFETY: the live `PendingRename` owns storage holding a
            // NUL-terminated path, verified by `OwnedPath` before the
            // request could be built, so this scan stops inside it.
            let byte = unsafe { base.add(i).read() };
            if byte == 0 {
                return seen;
            }
            seen.push(byte);
            i += 1;
        }
    }

    /// Mint the CQE of an operation that returns only success or failure.
    fn post_status(&self, ring: RingId, result: i32) -> Receipt {
        Receipt {
            ring,
            id: RequestId::from_raw(self.user_data()),
            result,
            flags: CqeFlags::from_raw(0),
        }
    }
}

impl FakeKernel {
    /// The `addr2` destination as a pointer to a `Statx`.
    ///
    /// `statx` is the only owned request where the kernel writes through a
    /// *second* published address, so this is the access that has to be
    /// checked separately from the path scan at `addr`.
    fn published_dest(&self) -> *mut Statx {
        let addr = usize::try_from(self.sqe.0.off).expect("address fits a pointer");
        core::ptr::with_exposed_provenance_mut::<Statx>(addr)
    }

    /// Fill the destination the way a successful `statx` does: a whole
    /// fixed-size struct, with no length in the SQE to bound it.
    ///
    /// The write is `size_of::<Statx>()` bytes regardless of how much room
    /// the caller provided, which is exactly why the destination is size-
    /// and alignment-checked before the request can exist.
    fn complete_statx(&self, ring: RingId, mask: StatxMask, size: u64) -> Receipt {
        let dst = self.published_dest();
        let filled = Statx {
            stx_mask: mask.bits(),
            stx_size: size,
            stx_nlink: 1,
            ..Statx::default()
        };
        // SAFETY: the live `PendingStatx` owns storage that was checked to
        // hold an aligned `Statx`, and its contract keeps those bytes
        // allocated and unaliased until it is redeemed.
        unsafe { dst.write(filled) };
        Receipt {
            ring,
            id: RequestId::from_raw(self.user_data()),
            result: 0,
            flags: CqeFlags::from_raw(0),
        }
    }
}

impl FakeKernel {
    /// Resolve the published path the way `openat` does: read forward from
    /// the address until a NUL, with no length to stop at.
    ///
    /// The scan is the point. Every other operation is bounded by the SQE's
    /// length field, so an over-long read is impossible by construction;
    /// here the terminator is the only bound, and if it is missing this
    /// walks off the end of the allocation — which is exactly what Miri
    /// reports and what `OwnedPath` exists to prevent.
    fn resolve_path(&self) -> Vec<u8> {
        let base = self.published_ptr().cast_const();
        let mut seen = Vec::new();
        let mut i = 0;
        loop {
            // SAFETY: the live `PendingOpen` owns storage holding a
            // NUL-terminated path, verified by `OwnedPath` before the
            // request could be built, so this scan stops inside it.
            let byte = unsafe { base.add(i).read() };
            if byte == 0 {
                return seen;
            }
            seen.push(byte);
            i += 1;
        }
    }

    /// Mint the CQE of a successful open, carrying a descriptor number.
    fn post_open(&self, ring: RingId, fd: i32) -> Receipt {
        Receipt {
            ring,
            id: RequestId::from_raw(self.user_data()),
            result: fd,
            flags: CqeFlags::from_raw(0),
        }
    }
}

impl FakeKernel {
    /// Walk the published `iovec` array the way the kernel does: read the
    /// descriptor, then follow *its* pointer to the data.
    ///
    /// This double indirection is the whole reason vectored I/O is riskier
    /// than scalar. The SQE's address is the array, not the bytes, so the
    /// array has to survive independently of the buffers — and Miri only
    /// notices a stale array pointer if the access goes through this path
    /// rather than through the owner.
    fn descriptor(&self, i: usize) -> IoVec {
        // The `PreparedVectored` that built this SQE rejected storage that
        // was not aligned for `IoVec`, so this address is aligned.
        #[allow(clippy::cast_ptr_alignment)]
        let base = self.published_ptr().cast::<IoVec>();
        // SAFETY: the `PreparedVectored` that built this SQE checked the
        // storage holds `N` aligned descriptors, and the owner is alive for
        // this call, so `base.add(i)` is in bounds and initialised.
        unsafe { base.add(i).read() }
    }

    /// Fill descriptor `i`'s buffer, as a `readv` completion would.
    fn complete_readv(&self, i: usize, fill: u8) -> usize {
        let vec = self.descriptor(i);
        for j in 0..vec.len() {
            // SAFETY: the descriptor names a buffer owned by the live
            // `PendingVectored`, which keeps it allocated and unaliased.
            unsafe { vec.base().add(j).write(fill) };
        }
        vec.len()
    }

    /// Read descriptor `i`'s buffer back, as a `writev` submission would.
    fn observe_writev(&self, i: usize) -> Vec<u8> {
        let vec = self.descriptor(i);
        let mut seen = Vec::with_capacity(vec.len());
        for j in 0..vec.len() {
            // SAFETY: as above; the owner outlives this call.
            seen.push(unsafe { vec.base().add(j).read() });
        }
        seen
    }
}

#[test]
fn kernel_write_through_the_sqe_pointer_lands_in_the_owned_buffer() {
    let cycle = Lifecycle::new();
    let prepared = Prepared::read(RawFd::from_raw(7), HeapBuffer::with_capacity(64), 0);
    let (kernel, pending) = cycle.submit(prepared);

    // The buffer is reachable only by the kernel here; `pending` owns it
    // and deliberately exposes no accessor.
    let result = kernel.complete_read(0xAB);
    let receipt = kernel.post_completion(cycle.ring, result);

    let completed = pending.redeem(receipt).ok().expect("receipt matches");
    assert_eq!(completed.result().expect("ok"), 64);
    assert!(completed.buffer().as_slice().iter().all(|&b| b == 0xAB));
}

#[test]
fn the_kernel_reaches_every_vectored_buffer_through_the_published_array() {
    let cycle = Lifecycle::new();
    let bufs = [(); 3].map(|()| HeapBuffer::with_capacity(4));
    let vecs = HeapBuffer::for_descriptors(256);
    let prepared = PreparedVectored::readv(RawFd::from_raw(7), bufs, vecs, 0)
        .ok()
        .expect("storage fits");
    let (kernel, pending) = cycle.submit_vectored(prepared);

    // Each write goes array-first, so a stale or misplaced descriptor would
    // be a Miri error rather than a silently wrong byte.
    let mut total = 0usize;
    for (i, fill) in [0xA1u8, 0xB2, 0xC3].into_iter().enumerate() {
        total += kernel.complete_readv(i, fill);
    }
    let receipt = kernel.post_completion(cycle.ring, i32::try_from(total).expect("fits"));

    let completed = pending.redeem(receipt).ok().expect("receipt matches");
    assert_eq!(completed.result().expect("ok"), 12);
    let bufs = completed.buffers();
    assert!(bufs[0].as_slice().iter().all(|&b| b == 0xA1));
    assert!(bufs[1].as_slice().iter().all(|&b| b == 0xB2));
    assert!(bufs[2].as_slice().iter().all(|&b| b == 0xC3));
}

#[test]
fn a_vectored_ticket_keeps_its_array_valid_across_moves() {
    // The hazard that decided the design: a `PendingVectored` is `Send` and
    // is meant to move to a completion thread, but the kernel holds a
    // pointer *into* it. Moving the ticket must not disturb the array, and
    // under Miri a relocated or invalidated array is a hard error rather
    // than a wrong answer.
    let cycle = Lifecycle::new();
    let bufs = [(); 2].map(|()| HeapBuffer::with_capacity(8));
    let vecs = HeapBuffer::for_descriptors(256);
    let prepared = PreparedVectored::readv(RawFd::from_raw(7), bufs, vecs, 0)
        .ok()
        .expect("storage fits");
    let (kernel, pending) = cycle.submit_vectored(prepared);

    // Move it around the way an application would: into a box, out again,
    // and through another owner.
    let boxed = Box::new(pending);
    let pending = *boxed;
    let moved = core::hint::black_box(pending);

    // The kernel writes *after* all that movement, through the pointer it
    // captured before any of it.
    let mut total = 0usize;
    for i in 0..2 {
        total += kernel.complete_readv(i, 0x5A);
    }
    let receipt = kernel.post_completion(cycle.ring, i32::try_from(total).expect("fits"));

    let completed = moved.redeem(receipt).ok().expect("receipt matches");
    assert_eq!(completed.result().expect("ok"), 16);
    assert!(
        completed
            .buffers()
            .iter()
            .all(|b| b.as_slice().iter().all(|&x| x == 0x5A))
    );
}

#[test]
fn a_gather_write_publishes_the_bytes_each_buffer_staged() {
    let cycle = Lifecycle::new();
    let mut bufs = [(); 2].map(|()| HeapBuffer::with_capacity(4));
    bufs[0].as_mut_slice().copy_from_slice(b"abcd");
    bufs[1].as_mut_slice().copy_from_slice(b"efgh");
    let vecs = HeapBuffer::for_descriptors(256);
    let prepared = PreparedVectored::writev(RawFd::from_raw(1), bufs, vecs, 0)
        .ok()
        .expect("storage fits");
    let (kernel, pending) = cycle.submit_vectored(prepared);

    assert_eq!(kernel.observe_writev(0), b"abcd");
    assert_eq!(kernel.observe_writev(1), b"efgh");

    let receipt = kernel.post_completion(cycle.ring, 8);
    let completed = pending.redeem(receipt).ok().expect("receipt matches");
    assert_eq!(completed.result().expect("ok"), 8);
}

#[test]
fn abandoning_a_vectored_ticket_leaks_rather_than_freeing_live_storage() {
    // Same failure mode as the scalar case, but with two kinds of storage
    // to leak: the buffers and the array naming them. Freeing either while
    // the kernel holds a pointer would be the unsound choice.
    let cycle = Lifecycle::new();
    let bufs = [(); 2].map(|()| HeapBuffer::with_capacity(8));
    let buf_addrs = bufs.each_ref().map(|b| (b.ptr, b.len));
    let vecs = HeapBuffer::for_descriptors(256);
    let vec_addr = (vecs.ptr, vecs.len);
    let prepared = PreparedVectored::readv(RawFd::from_raw(7), bufs, vecs, 0)
        .ok()
        .expect("storage fits");
    let (kernel, pending) = cycle.submit_vectored(prepared);

    // Abandoning the ticket. `PendingVectored` holds every owner in a
    // `ManuallyDrop`, so it has no destructor of its own and this frees
    // nothing -- which is the point: the kernel still holds pointers into
    // all of it.
    #[allow(clippy::drop_non_drop)]
    drop(pending);

    // The kernel still writes, and the storage must still be there.
    for i in 0..2 {
        kernel.complete_readv(i, 0x77);
    }
    assert_eq!(kernel.observe_writev(0), [0x77; 8]);

    // Hand the leaked storage back so Miri's leak checker stays on for
    // every other test rather than being disabled wholesale.
    for (ptr, len) in buf_addrs {
        // SAFETY: the abandoned ticket leaked these and the stand-in kernel
        // has finished with them, so nothing else can reach them.
        unsafe { HeapBuffer::reclaim_leaked(ptr, len) };
    }
    // SAFETY: as above, with the descriptor array's own alignment.
    unsafe { HeapBuffer::reclaim_leaked_descriptors(vec_addr.0, vec_addr.1) };
}

#[test]
fn reclaiming_an_unpublished_vectored_request_returns_usable_storage() {
    let cycle = Lifecycle::new();
    let bufs = [(); 2].map(|()| HeapBuffer::with_capacity(8));
    let vecs = HeapBuffer::for_descriptors(256);
    let prepared = PreparedVectored::writev(RawFd::from_raw(3), bufs, vecs, 0)
        .ok()
        .expect("storage fits");
    let (_kernel, pending) = cycle.submit_vectored(prepared);

    // SAFETY: this test never publishes the SQE, so the kernel holds no
    // pointer into the storage.
    let mut recovered = unsafe { pending.reclaim_unsubmitted() };
    // The target survived the round trip rather than being reset.
    assert_eq!(recovered.fd().as_i32(), 3);
    // And the storage is writable again, so nothing was left half-owned.
    recovered.buffers_mut()[0].as_mut_slice()[0] = 1;
}

#[test]
fn kernel_reads_the_bytes_the_caller_staged_before_submission() {
    let cycle = Lifecycle::new();
    let mut prepared = Prepared::write(RawFd::from_raw(1), HeapBuffer::with_capacity(8), 0);
    prepared
        .buffer_mut()
        .as_mut_slice()
        .copy_from_slice(b"ququmatz");
    let (kernel, pending) = cycle.submit(prepared);

    assert_eq!(kernel.observe_write(), b"ququmatz");

    let receipt = kernel.post_completion(cycle.ring, 8);
    let completed = pending.redeem(receipt).ok().expect("receipt matches");
    assert_eq!(completed.buffer().as_slice(), b"ququmatz");
}

#[test]
fn buffer_survives_the_ticket_moving_between_owners() {
    let cycle = Lifecycle::new();
    let prepared = Prepared::read(RawFd::from_raw(3), HeapBuffer::with_capacity(32), 0);
    let (kernel, pending) = cycle.submit(prepared);

    // Moving the ticket is what crossing a thread boundary does to it.
    // The storage must not move with it.
    let relocated = Box::new(pending);
    let moved_again = *relocated;

    let result = kernel.complete_read(0x5A);
    let receipt = kernel.post_completion(cycle.ring, result);
    let completed = moved_again.redeem(receipt).ok().expect("receipt matches");
    assert!(completed.buffer().as_slice().iter().all(|&b| b == 0x5A));
}

#[test]
fn dropping_a_pending_ticket_does_not_free_the_kernels_buffer() {
    let cycle = Lifecycle::new();
    let prepared = Prepared::read(RawFd::from_raw(3), HeapBuffer::with_capacity(48), 0);
    let (kernel, pending) = cycle.submit(prepared);

    // The application abandons the ticket while the operation is in
    // flight. The storage must leak, not be reclaimed.
    drop(pending);

    // A late completion still writes here. Under Miri this is the
    // use-after-free check: it passes only because `Pending::drop` runs no
    // destructor for the buffer.
    let written = kernel.complete_read(0x11);
    assert_eq!(written, 48);
    assert!(kernel.observe_write().iter().all(|&b| b == 0x11));

    // SAFETY: the ticket leaked this allocation and the stand-in kernel is
    // done with it, so nothing else can reach these bytes.
    unsafe { HeapBuffer::reclaim_leaked(kernel.published_ptr(), 48) };
}

#[test]
fn forgetting_a_pending_ticket_degrades_the_same_way_as_dropping_it() {
    let cycle = Lifecycle::new();
    let prepared = Prepared::read(RawFd::from_raw(3), HeapBuffer::with_capacity(16), 0);
    let (kernel, pending) = cycle.submit(prepared);

    core::mem::forget(pending);

    let written = kernel.complete_read(0x22);
    assert_eq!(written, 16);
    assert!(kernel.observe_write().iter().all(|&b| b == 0x22));

    // SAFETY: as above — forgetting leaked it, and the kernel has finished.
    unsafe { HeapBuffer::reclaim_leaked(kernel.published_ptr(), 16) };
}

#[test]
fn reclaiming_an_unpublished_request_returns_usable_storage() {
    let cycle = Lifecycle::new();
    let prepared = Prepared::write(RawFd::from_raw(1), HeapBuffer::with_capacity(24), 0);
    let (kernel, pending) = cycle.submit(prepared);
    let addr = kernel.addr();

    // SAFETY: this SQE was never published to a ring, so no kernel-visible
    // pointer to the buffer exists.
    let mut recovered = unsafe { pending.reclaim_unsubmitted() };

    assert_eq!(recovered.buffer().stable_ptr() as u64, addr);
    recovered.buffer_mut().as_mut_slice()[0] = 0xFF;
    let buf = recovered.into_buffer();
    assert_eq!(buf.as_slice()[0], 0xFF);
    // `buf` drops normally here: reclaiming revived the destructor.
}

#[test]
fn a_rejected_receipt_leaves_the_ticket_and_its_buffer_intact() {
    let cycle = Lifecycle::new();
    let prepared = Prepared::read(RawFd::from_raw(3), HeapBuffer::with_capacity(16), 0);
    let (kernel, pending) = cycle.submit(prepared);

    let wrong = Receipt {
        ring: cycle.ring,
        id: RequestId::from_raw(pending.id().raw().wrapping_add(1)),
        result: 16,
        flags: CqeFlags::from_raw(0),
    };

    let (pending, _) = pending.redeem(wrong).err().expect("mismatch is rejected");

    // The buffer must still be the kernel's to write after a failed
    // redemption; nothing was released by the rejected attempt.
    let result = kernel.complete_read(0x33);
    let receipt = kernel.post_completion(cycle.ring, result);
    let completed = pending.redeem(receipt).ok().expect("correct receipt");
    assert!(completed.buffer().as_slice().iter().all(|&b| b == 0x33));
}

#[test]
fn transfer_length_bounds_what_the_kernel_may_touch() {
    let cycle = Lifecycle::new();
    let prepared =
        Prepared::write(RawFd::from_raw(1), HeapBuffer::with_capacity(64), 0).with_len(5);
    let (kernel, pending) = cycle.submit(prepared);

    // The SQE must describe 5 bytes, not the buffer's 64; a kernel reading
    // `len` bytes must stay inside what the caller meant to send.
    assert_eq!(kernel.len(), 5);
    assert_eq!(kernel.observe_write().len(), 5);

    let receipt = kernel.post_completion(cycle.ring, 5);
    let completed = pending.redeem(receipt).ok().expect("receipt matches");
    assert_eq!(completed.result().expect("ok"), 5);
}

#[test]
fn the_nic_may_still_read_a_zero_copy_buffer_after_the_send_cqe() {
    let cycle = Lifecycle::new();
    let mut prepared = PreparedZc::send(
        RawFd::from_raw(9),
        HeapBuffer::with_capacity(8),
        MsgFlags::default(),
    );
    prepared
        .buffer_mut()
        .as_mut_slice()
        .copy_from_slice(b"ququmatz");
    let (kernel, pending) = cycle.submit_zc(prepared);

    // The send CQE says 8 bytes were accepted. This is the moment a design
    // that treated the first completion as terminal would hand the buffer
    // back and let it drop.
    let pending = pending
        .record_sent(kernel.post_send(cycle.ring, 8))
        .ok()
        .expect("notice matches");
    assert_eq!(pending.send_result(), Some(8));

    // The NIC reads the pages *after* that. Under Miri this is the
    // use-after-free check for the whole zero-copy design: it passes only
    // because `record_sent` released nothing.
    assert_eq!(kernel.observe_write(), b"ququmatz");

    let completed = pending
        .redeem(kernel.post_notification(cycle.ring))
        .ok()
        .expect("notification matches");
    assert_eq!(completed.result().expect("ok"), 8);
    assert_eq!(completed.buffer().as_slice(), b"ququmatz");
}

#[test]
fn a_zero_copy_send_that_promises_no_notification_is_terminal_at_once() {
    let cycle = Lifecycle::new();
    let prepared = PreparedZc::send(
        RawFd::from_raw(9),
        HeapBuffer::with_capacity(4),
        MsgFlags::default(),
    );
    let (kernel, pending) = cycle.submit_zc(prepared);

    // The kernel copied instead of mapping, so it clears `MORE` and never
    // posts a notification. The completer classifies that CQE as terminal,
    // and the buffer comes straight back rather than leaking forever.
    let completed = pending
        .redeem(kernel.post_completion(cycle.ring, 4))
        .ok()
        .expect("send cqe is terminal");
    assert_eq!(completed.raw_send_result(), None);
    assert_eq!(completed.result().expect("ok"), 4);
}

#[test]
fn abandoning_a_zero_copy_send_leaks_rather_than_freeing_live_pages() {
    let cycle = Lifecycle::new();
    let prepared = PreparedZc::send(
        RawFd::from_raw(9),
        HeapBuffer::with_capacity(16),
        MsgFlags::default(),
    );
    let (kernel, pending) = cycle.submit_zc(prepared);

    let pending = pending
        .record_sent(kernel.post_send(cycle.ring, 16))
        .ok()
        .expect("notice matches");
    drop(pending);

    // A late NIC read still lands in valid storage.
    assert_eq!(kernel.observe_write().len(), 16);

    // SAFETY: the ticket leaked this allocation and the stand-in kernel is
    // done with it, so nothing else can reach these bytes.
    unsafe { HeapBuffer::reclaim_leaked(kernel.published_ptr(), 16) };
}

#[test]
fn a_send_notice_for_another_request_is_rejected_without_disturbing_the_ticket() {
    let cycle = Lifecycle::new();
    let prepared = PreparedZc::send(
        RawFd::from_raw(9),
        HeapBuffer::with_capacity(8),
        MsgFlags::default(),
    );
    let (kernel, pending) = cycle.submit_zc(prepared);

    let wrong = PartialReceipt {
        ring: cycle.ring,
        id: RequestId::from_raw(pending.id().raw().wrapping_add(1)),
        result: 8,
        flags: CqeFlags::MORE,
    };
    let (pending, _) = pending
        .record_sent(wrong)
        .err()
        .expect("mismatch is rejected");
    assert_eq!(pending.send_result(), None);

    assert_eq!(kernel.observe_write().len(), 8);
    let completed = pending
        .redeem(kernel.post_notification(cycle.ring))
        .ok()
        .expect("notification matches");
    drop(completed);
}

#[test]
fn reclaiming_an_unpublished_zero_copy_send_returns_usable_storage() {
    let cycle = Lifecycle::new();
    let prepared = PreparedZc::send(
        RawFd::from_raw(9),
        HeapBuffer::with_capacity(12),
        MsgFlags::default(),
    );
    let (kernel, pending) = cycle.submit_zc(prepared);
    let addr = kernel.addr();

    // SAFETY: this SQE was never published to a ring, so no kernel-visible
    // pointer to the buffer exists.
    let mut recovered = unsafe { pending.reclaim_unsubmitted() };

    assert_eq!(recovered.buffer().stable_ptr() as u64, addr);
    recovered.buffer_mut().as_mut_slice()[0] = 0xFF;
    let buf = recovered.into_buffer();
    assert_eq!(buf.as_slice()[0], 0xFF);
    // `buf` drops normally here: reclaiming revived the destructor.
}

/// Build a verified path in heap storage.
fn heap_path(text: &[u8]) -> OwnedPath<HeapBuffer> {
    let mut storage = HeapBuffer::with_capacity(64);
    // Filled with non-zero bytes so the terminator written by `copy_into`
    // is the *only* zero in the allocation. If it were ever missing, the
    // kernel's scan would run past the end and Miri would report an
    // out-of-bounds read rather than quietly stopping on zeroed tail bytes.
    storage.as_mut_slice().fill(0xFF);
    OwnedPath::copy_into(storage, text)
        .ok()
        .expect("storage fits")
}

#[test]
fn the_kernel_scan_stops_inside_the_storage_the_ticket_owns() {
    let cycle = Lifecycle::new();
    let prepared = PreparedOpen::cwd(
        heap_path(b"/etc/hostname"),
        OpenFlags::default(),
        FileMode::default(),
    );
    let (kernel, pending) = cycle.submit_open(prepared);

    // The unbounded scan is the access worth checking: nothing but the NUL
    // stops it, and Miri reports it if it leaves the allocation.
    assert_eq!(kernel.resolve_path(), b"/etc/hostname");

    let opened = pending
        .redeem(kernel.post_open(cycle.ring, 5))
        .ok()
        .expect("receipt matches");
    assert!(opened.is_ok());
    let (file, path) = opened.into_parts();
    assert_eq!(path.as_bytes(), b"/etc/hostname");
    // The descriptor is a fiction here, so release it without closing fd 5.
    let _ = file
        .expect("a successful open carries a descriptor")
        .into_fd();
}

#[test]
fn a_path_stays_readable_while_the_ticket_moves_between_owners() {
    let cycle = Lifecycle::new();
    let prepared = PreparedOpen::cwd(
        heap_path(b"/tmp/moved"),
        OpenFlags::CREAT,
        FileMode::OWNER_READ,
    );
    let (kernel, pending) = cycle.submit_open(prepared);

    // The hazard this design exists for: the ticket is meant to cross to a
    // completion thread, so the bytes the kernel is scanning must survive
    // the owner being boxed, moved and passed through an opaque call.
    let pending = Box::new(pending);
    let pending = core::hint::black_box(pending);
    let pending = *pending;

    assert_eq!(kernel.resolve_path(), b"/tmp/moved");

    let opened = pending
        .redeem(kernel.post_open(cycle.ring, 9))
        .ok()
        .expect("receipt matches");
    let _ = opened.into_file().expect("descriptor").into_fd();
}

#[test]
fn a_failed_open_leaves_no_descriptor_to_leak() {
    let cycle = Lifecycle::new();
    let prepared = PreparedOpen::cwd(
        heap_path(b"/nope"),
        OpenFlags::default(),
        FileMode::default(),
    );
    let (kernel, pending) = cycle.submit_open(prepared);

    // -ENOENT. A negative result is an errno, never a descriptor, so
    // nothing may be adopted from it.
    let opened = pending
        .redeem(kernel.post_open(cycle.ring, -2))
        .ok()
        .expect("receipt matches");
    assert!(!opened.is_ok());
    let (file, path) = opened.into_parts();
    assert!(file.is_none());
    // The storage still came back, so a failed open costs nothing.
    assert_eq!(path.as_bytes(), b"/nope");
    drop(path.into_storage());
}

#[test]
fn abandoning_an_open_ticket_leaks_rather_than_freeing_the_path() {
    let cycle = Lifecycle::new();
    // Taken from the allocation itself, not from `as_bytes()`: that borrow
    // is read-only and covers only the path, so freeing through it is a
    // different pointer than the one `alloc_zeroed` handed out.
    let storage = HeapBuffer::with_capacity(64);
    let leaked = (storage.ptr, storage.len);
    let path = OwnedPath::copy_into(storage, b"/tmp/abandoned")
        .ok()
        .expect("storage fits");
    let prepared = PreparedOpen::cwd(path, OpenFlags::default(), FileMode::default());
    let (kernel, pending) = cycle.submit_open(prepared);

    // Dropping the ticket frees nothing: the kernel may still be resolving
    // the path, so the storage leaks on purpose.
    drop(pending);
    assert_eq!(kernel.resolve_path(), b"/tmp/abandoned");

    // SAFETY: the abandoned ticket leaked this and the stand-in kernel has
    // finished, so nothing else can reach it.
    unsafe { HeapBuffer::reclaim_leaked(leaked.0, leaked.1) };
}

#[test]
fn a_path_ops_path_is_scanned_within_the_storage_the_ticket_owns() {
    let cycle = Lifecycle::new();
    let prepared = PreparedPathOp::unlink_cwd(heap_path(b"/tmp/doomed"));
    let (kernel, pending) = cycle.submit_path_op(prepared);

    // The kernel scans for the NUL with no length to stop it, exactly as
    // for an open: the ticket owns the storage for that whole window.
    assert_eq!(kernel.resolve_path(), b"/tmp/doomed");

    let done = pending
        .redeem(kernel.post_status(cycle.ring, 0))
        .ok()
        .expect("receipt matches");
    assert!(done.is_ok());
    drop(done.into_path().into_storage());
}

#[test]
fn a_path_op_keeps_its_path_readable_while_the_ticket_moves() {
    let cycle = Lifecycle::new();
    let prepared = PreparedPathOp::mkdir_cwd(heap_path(b"/tmp/fresh"), FileMode::OWNER_READ);
    let (kernel, pending) = cycle.submit_path_op(prepared);

    let pending = Box::new(pending);
    let pending = core::hint::black_box(pending);
    let pending = *pending;

    assert_eq!(kernel.resolve_path(), b"/tmp/fresh");

    let done = pending
        .redeem(kernel.post_status(cycle.ring, 0))
        .ok()
        .expect("receipt matches");
    assert_eq!(done.kind(), PathOpKind::Mkdir(FileMode::OWNER_READ));
    drop(done.into_path().into_storage());
}

#[test]
fn abandoning_a_path_op_leaks_rather_than_freeing_the_path() {
    let cycle = Lifecycle::new();
    let storage = HeapBuffer::with_capacity(64);
    let leaked = (storage.ptr, storage.len);
    let path = OwnedPath::copy_into(storage, b"/tmp/abandoned")
        .ok()
        .expect("storage fits");
    let (kernel, pending) = cycle.submit_path_op(PreparedPathOp::rmdir_cwd(path));

    // Dropping the ticket frees nothing: the kernel may still be resolving
    // the path, so freeing here would be a use-after-free the moment it
    // reads. Only Miri can see the difference, which is why this test
    // exists rather than a behavioural one.
    drop(pending);
    assert_eq!(kernel.resolve_path(), b"/tmp/abandoned");

    // SAFETY: the abandoned ticket leaked this and the stand-in kernel has
    // finished, so nothing else can reach it.
    unsafe { HeapBuffer::reclaim_leaked(leaked.0, leaked.1) };
}

#[test]
fn reclaiming_an_unpublished_path_op_returns_the_path_and_its_kind() {
    let cycle = Lifecycle::new();
    let prepared = PreparedPathOp::rmdir_cwd(heap_path(b"/tmp/never_sent"));
    let (_kernel, pending) = cycle.submit_path_op(prepared);

    // SAFETY: this stands in for a rejected push — the SQE was built but
    // never made visible to any kernel, so the storage is unreferenced.
    let prepared = unsafe { pending.reclaim_unsubmitted() };
    assert_eq!(prepared.kind(), PathOpKind::Rmdir);
    assert_eq!(prepared.path().as_bytes(), b"/tmp/never_sent");
    drop(prepared.into_path().into_storage());
}

#[test]
fn a_rename_keeps_both_paths_readable_at_once() {
    let cycle = Lifecycle::new();
    let prepared = PreparedRename::cwd(
        heap_path(b"/tmp/source"),
        heap_path(b"/tmp/destination"),
        RenameMode::NoReplace,
    );
    let (kernel, pending) = cycle.submit_rename(prepared);

    // Two independent allocations, both scanned by the kernel, both owned
    // by one ticket: this is the first request where losing either would
    // be a use-after-free.
    assert_eq!(kernel.resolve_path(), b"/tmp/source");
    assert_eq!(kernel.resolve_second_path(), b"/tmp/destination");

    let done = pending
        .redeem(kernel.post_status(cycle.ring, 0))
        .ok()
        .expect("receipt matches");
    let (from, to) = done.into_paths();
    assert_eq!(from.as_bytes(), b"/tmp/source");
    assert_eq!(to.as_bytes(), b"/tmp/destination");
    drop((from.into_storage(), to.into_storage()));
}

#[test]
fn a_renames_two_paths_survive_the_ticket_moving_between_owners() {
    let cycle = Lifecycle::new();
    let prepared = PreparedRename::cwd(
        heap_path(b"/tmp/moving_from"),
        heap_path(b"/tmp/moving_to"),
        RenameMode::Exchange,
    );
    let (kernel, pending) = cycle.submit_rename(prepared);

    let pending = Box::new(pending);
    let pending = core::hint::black_box(pending);
    let pending = *pending;

    assert_eq!(kernel.resolve_path(), b"/tmp/moving_from");
    assert_eq!(kernel.resolve_second_path(), b"/tmp/moving_to");

    let done = pending
        .redeem(kernel.post_status(cycle.ring, 0))
        .ok()
        .expect("receipt matches");
    let (from, to) = done.into_paths();
    drop((from.into_storage(), to.into_storage()));
}

#[test]
fn abandoning_a_rename_leaks_both_paths_rather_than_freeing_them() {
    let cycle = Lifecycle::new();
    let from_storage = HeapBuffer::with_capacity(64);
    let to_storage = HeapBuffer::with_capacity(64);
    let leaked = [
        (from_storage.ptr, from_storage.len),
        (to_storage.ptr, to_storage.len),
    ];
    let from = OwnedPath::copy_into(from_storage, b"/tmp/left")
        .ok()
        .expect("storage fits");
    let to = OwnedPath::copy_into(to_storage, b"/tmp/right")
        .ok()
        .expect("storage fits");
    let (kernel, pending) = cycle.submit_rename(PreparedRename::cwd(from, to, RenameMode::Replace));

    // Both leak, not just the first: a ticket that freed either one would
    // hand the kernel a dangling scan.
    drop(pending);
    assert_eq!(kernel.resolve_path(), b"/tmp/left");
    assert_eq!(kernel.resolve_second_path(), b"/tmp/right");

    for (ptr, len) in leaked {
        // SAFETY: the abandoned ticket leaked these and the stand-in kernel
        // has finished, so nothing else can reach them.
        unsafe { HeapBuffer::reclaim_leaked(ptr, len) };
    }
}

#[test]
fn reclaiming_an_unpublished_rename_returns_both_paths_and_its_mode() {
    let cycle = Lifecycle::new();
    let prepared = PreparedRename::cwd(
        heap_path(b"/tmp/unsent_from"),
        heap_path(b"/tmp/unsent_to"),
        RenameMode::NoReplace,
    );
    let (_kernel, pending) = cycle.submit_rename(prepared);

    // SAFETY: this stands in for a rejected push — the SQE was built but
    // never made visible to any kernel, so neither storage is referenced.
    let prepared = unsafe { pending.reclaim_unsubmitted() };
    assert_eq!(prepared.mode(), RenameMode::NoReplace);
    let (from, to) = prepared.into_paths();
    assert_eq!(from.as_bytes(), b"/tmp/unsent_from");
    assert_eq!(to.as_bytes(), b"/tmp/unsent_to");
    drop((from.into_storage(), to.into_storage()));
}

/// Heap storage aligned for an `OpenHow`, sized exactly.
fn how_store() -> HeapBuffer {
    HeapBuffer::with_alignment(core::mem::size_of::<OpenHow>(), align_of::<OpenHow>())
}

fn prepared_openat2(
    path: &[u8],
    mode: Openat2Mode,
    resolve: ResolveFlags,
) -> PreparedOpenat2<HeapBuffer, HeapBuffer> {
    PreparedOpenat2::cwd(heap_path(path), OpenFlags::RDWR, mode, resolve, how_store())
        .ok()
        .expect("how storage fits")
}

#[test]
fn an_openat2_keeps_its_path_and_its_open_how_readable_at_once() {
    let cycle = Lifecycle::new();
    let prepared = prepared_openat2(
        b"/tmp/two_regions",
        Openat2Mode::Create(FileMode::OWNER_READ),
        ResolveFlags::NO_SYMLINKS,
    );
    let (kernel, pending) = cycle.submit_openat2(prepared);

    // Two independent allocations the kernel reads for one request: the
    // path it resolves, and the struct telling it what to do with it.
    assert_eq!(kernel.resolve_path(), b"/tmp/two_regions");
    let how = kernel.read_open_how();
    assert_eq!(
        how.flags,
        u64::from(OpenFlags::RDWR.bits() | OpenFlags::CREAT.bits())
    );
    assert_eq!(how.mode, u64::from(FileMode::OWNER_READ.bits()));
    assert_eq!(how.resolve, ResolveFlags::NO_SYMLINKS.bits());
    // The kernel checks this against its own sizeof, so it is part of the
    // request being well-formed rather than an incidental field.
    assert_eq!(
        kernel.published_how_size() as usize,
        core::mem::size_of::<OpenHow>()
    );

    let done = pending
        .redeem(kernel.post_open(cycle.ring, 7))
        .ok()
        .expect("receipt matches");
    let (file, path, store) = done.into_parts();
    assert_eq!(path.as_bytes(), b"/tmp/two_regions");
    core::mem::forget(file);
    drop((path.into_storage(), store));
}

#[test]
fn an_openat2s_two_regions_survive_the_ticket_moving_between_owners() {
    let cycle = Lifecycle::new();
    let prepared = prepared_openat2(
        b"/tmp/travelling",
        Openat2Mode::Tmpfile(FileMode::OWNER_WRITE),
        ResolveFlags::BENEATH,
    );
    let (kernel, pending) = cycle.submit_openat2(prepared);

    let pending = Box::new(pending);
    let pending = core::hint::black_box(pending);
    let pending = *pending;

    // Both regions still reachable through the addresses the SQE carries,
    // after the ticket that owns them has moved.
    assert_eq!(kernel.resolve_path(), b"/tmp/travelling");
    assert_eq!(kernel.read_open_how().resolve, ResolveFlags::BENEATH.bits());

    let done = pending
        .redeem(kernel.post_open(cycle.ring, 9))
        .ok()
        .expect("receipt matches");
    let (file, path, store) = done.into_parts();
    core::mem::forget(file);
    drop((path.into_storage(), store));
}

#[test]
fn abandoning_an_openat2_leaks_both_regions_rather_than_freeing_them() {
    let cycle = Lifecycle::new();
    let path_storage = HeapBuffer::with_capacity(64);
    let how_storage = how_store();
    let leaked_path = (path_storage.ptr, path_storage.len);
    let leaked_how = (how_storage.ptr, how_storage.len, how_storage.align);
    let path = OwnedPath::copy_into(path_storage, b"/tmp/dropped")
        .ok()
        .expect("storage fits");
    let prepared = PreparedOpenat2::cwd(
        path,
        OpenFlags::RDWR,
        Openat2Mode::Create(FileMode::OWNER_READ),
        ResolveFlags::default(),
        how_storage,
    )
    .ok()
    .expect("how storage fits");
    let (kernel, pending) = cycle.submit_openat2(prepared);

    // Both leak, not just the path: a ticket that freed the `open_how`
    // would leave the kernel reading open parameters from dead memory.
    drop(pending);
    assert_eq!(kernel.resolve_path(), b"/tmp/dropped");
    assert_eq!(kernel.read_open_how().mode, 0o400);

    // SAFETY: the abandoned ticket leaked these and the stand-in kernel has
    // finished, so nothing else can reach them.
    unsafe {
        HeapBuffer::reclaim_leaked(leaked_path.0, leaked_path.1);
        dealloc(
            leaked_how.0,
            HeapBuffer::layout_of(leaked_how.1, leaked_how.2),
        );
    }
}

#[test]
fn reclaiming_an_unpublished_openat2_returns_both_storages_and_its_mode() {
    let cycle = Lifecycle::new();
    let prepared = prepared_openat2(
        b"/tmp/unsent",
        Openat2Mode::CreateNew(FileMode::OWNER_WRITE),
        ResolveFlags::IN_ROOT,
    );
    let (_kernel, pending) = cycle.submit_openat2(prepared);

    // SAFETY: this stands in for a rejected push — the SQE was built but
    // never made visible to any kernel, so neither storage is referenced.
    let prepared = unsafe { pending.reclaim_unsubmitted() };
    assert_eq!(
        prepared.mode(),
        Openat2Mode::CreateNew(FileMode::OWNER_WRITE)
    );
    assert_eq!(prepared.resolve(), ResolveFlags::IN_ROOT);
    // The published struct survived the round trip, so a retry issues the
    // same request rather than one describing stale parameters.
    assert_eq!(
        prepared.published_how().resolve,
        ResolveFlags::IN_ROOT.bits()
    );
    assert_eq!(prepared.path().as_bytes(), b"/tmp/unsent");
    let (path, store) = prepared.into_parts();
    drop((path.into_storage(), store));
}

/// Heap staging for a message header, its descriptors, and its address.
///
/// Aligned for a `MsgHdr` rather than for bytes: the region genuinely
/// requires it, and a byte-aligned allocation is where Miri catches what
/// the system allocator would hide by handing back aligned addresses
/// anyway.
fn msg_region<const N: usize>() -> HeapBuffer {
    let needed = core::mem::size_of::<MsgHdr>()
        + core::mem::size_of::<IoVec>() * N
        + core::mem::size_of::<SockAddrIn>();
    HeapBuffer::with_alignment(needed, align_of::<MsgHdr>())
}

/// A heap buffer holding exactly `bytes`.
fn heap_filled(bytes: &[u8]) -> HeapBuffer {
    let mut buf = HeapBuffer::with_capacity(bytes.len());
    buf.as_mut_slice().copy_from_slice(bytes);
    buf
}

#[test]
fn the_kernel_reaches_a_messages_bytes_by_following_the_header_it_published() {
    let cycle = Lifecycle::new();
    // Distinct contents and lengths: three copies of one buffer would pass
    // even if every descriptor named the first.
    let prepared = PreparedSendmsg::new(
        RawFd::from_raw(7),
        [
            heap_filled(b"one"),
            heap_filled(b"two!"),
            heap_filled(b"five5"),
        ],
        msg_region::<3>(),
        SendTarget::Connected,
        MsgFlags::default(),
    )
    .ok()
    .expect("staging fits");
    let (kernel, pending) = cycle.submit_sendmsg(prepared);

    // Struct, then array, then buffers — three allocations chained by
    // pointers the kernel reads out of caller memory, all reached without
    // touching the ticket that owns them.
    assert_eq!(kernel.observe_sendmsg(), b"onetwo!five5");
    assert!(kernel.message_name().is_none());

    let receipt = kernel.post_completion(cycle.ring, 12);
    let done = pending.redeem(receipt).ok().expect("receipt matches");
    assert_eq!(done.result().expect("ok"), 12);
    let (_, bufs, store) = done.into_parts();
    drop((bufs, store));
}

#[test]
fn a_messages_three_regions_survive_the_ticket_moving_between_owners() {
    // The hazard that decided the design. A `PendingSendmsg` is `Send` and
    // is meant to move to a completion thread, but the kernel holds a
    // pointer to a header whose *contents* are further pointers. If any of
    // it relocated, the kernel would read three addresses out of whatever
    // now occupied that space and follow them.
    let cycle = Lifecycle::new();
    let addr = SockAddrIn {
        sin_family: 2,
        sin_port: 4242u16.to_be(),
        sin_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        sin_zero: [0; 8],
    };
    let prepared = PreparedSendmsg::new(
        RawFd::from_raw(7),
        [heap_filled(b"travel"), heap_filled(b"ling")],
        msg_region::<2>(),
        SendTarget::To(addr),
        MsgFlags::default(),
    )
    .ok()
    .expect("staging fits");
    let (kernel, pending) = cycle.submit_sendmsg(prepared);

    let pending = Box::new(pending);
    let pending = core::hint::black_box(pending);
    let pending = *pending;

    // Every level still reachable after the move, through the one address
    // the SQE carried before any of it happened.
    assert_eq!(kernel.observe_sendmsg(), b"travelling");
    assert_eq!(kernel.message_name().expect("addressed"), addr);

    let receipt = kernel.post_completion(cycle.ring, 10);
    let done = pending.redeem(receipt).ok().expect("receipt matches");
    let (_, bufs, store) = done.into_parts();
    drop((bufs, store));
}

#[test]
fn abandoning_a_sendmsg_leaks_every_region_rather_than_freeing_them() {
    let cycle = Lifecycle::new();
    let region = msg_region::<2>();
    let first = heap_filled(b"abandon");
    let second = heap_filled(b"ed");
    let leaked_region = (region.ptr, region.len, region.align);
    let leaked_bufs = [(first.ptr, first.len), (second.ptr, second.len)];

    let prepared = PreparedSendmsg::new(
        RawFd::from_raw(7),
        [first, second],
        region,
        SendTarget::Connected,
        MsgFlags::default(),
    )
    .ok()
    .expect("staging fits");
    let (kernel, pending) = cycle.submit_sendmsg(prepared);

    // Everything leaks, not just the buffers. A ticket that freed the
    // staging region would leave the kernel reading a header from dead
    // memory and following whatever addresses it found there — and the
    // buffers being alive would not save it.
    drop(pending);
    assert_eq!(kernel.observe_sendmsg(), b"abandoned");

    // SAFETY: the abandoned ticket leaked these and the stand-in kernel has
    // finished, so nothing else can reach them.
    unsafe {
        dealloc(
            leaked_region.0,
            HeapBuffer::layout_of(leaked_region.1, leaked_region.2),
        );
        for (ptr, len) in leaked_bufs {
            HeapBuffer::reclaim_leaked(ptr, len);
        }
    }
}

#[test]
fn reclaiming_an_unpublished_sendmsg_returns_every_storage_and_its_header() {
    let cycle = Lifecycle::new();
    let prepared = PreparedSendmsg::new(
        RawFd::from_raw(7),
        [heap_filled(b"unsent")],
        msg_region::<1>(),
        SendTarget::Connected,
        MsgFlags::NOSIGNAL,
    )
    .ok()
    .expect("staging fits");
    let (_kernel, pending) = cycle.submit_sendmsg(prepared);

    // SAFETY: this stands in for a rejected push — the SQE was built but
    // never made visible to any kernel, so no storage is referenced.
    let prepared = unsafe { pending.reclaim_unsubmitted() };
    assert_eq!(prepared.flags(), MsgFlags::NOSIGNAL);
    assert_eq!(prepared.target(), SendTarget::Connected);
    // The staged header survived the round trip, so a retry sends the same
    // message rather than one describing stale addresses.
    assert_eq!(prepared.published_header().msg_iovlen, 1);
    assert_eq!(prepared.total_len(), 6);
    let (bufs, store) = prepared.into_parts();
    drop((bufs, store));
}

#[test]
fn the_kernel_fills_a_receives_buffers_by_following_the_header_it_published() {
    let cycle = Lifecycle::new();
    // Distinct sizes: equal buffers would pass even if the kernel filled
    // them in the wrong order.
    let prepared = PreparedRecvmsg::new(
        RawFd::from_raw(7),
        [
            HeapBuffer::with_capacity(3),
            HeapBuffer::with_capacity(4),
            HeapBuffer::with_capacity(5),
        ],
        msg_region::<3>(),
        PeerWanted::No,
        MsgFlags::default(),
    )
    .ok()
    .expect("staging fits");
    let (kernel, pending) = cycle.submit_recvmsg(prepared);

    // The kernel reaches every buffer through the header alone, then
    // writes back into that same header — the region is both a source it
    // reads and a destination it writes.
    let written = kernel.deliver_recvmsg(b"onetwo!five5", None);
    assert_eq!(written, 12);

    let receipt = kernel.post_completion(cycle.ring, 12);
    let done = pending.redeem(receipt).ok().expect("receipt matches");
    assert_eq!(done.received().expect("ok").bytes(), 12);
    assert!(!done.received().expect("ok").truncated());

    let (_, _, bufs, store) = done.into_parts();
    assert_eq!(bufs[0].as_slice(), b"one");
    assert_eq!(bufs[1].as_slice(), b"two!");
    assert_eq!(bufs[2].as_slice(), b"five5");
    drop(store);
}

#[test]
fn a_receives_three_regions_survive_the_ticket_moving_between_owners() {
    // The same hazard as the send side, one direction worse: the kernel
    // holds a pointer to a header whose contents are further pointers, and
    // it *writes* through all of them. A region that relocated would have
    // the kernel scribble wherever the stale addresses led.
    let cycle = Lifecycle::new();
    let prepared = PreparedRecvmsg::new(
        RawFd::from_raw(7),
        [HeapBuffer::with_capacity(6), HeapBuffer::with_capacity(4)],
        msg_region::<2>(),
        PeerWanted::Yes,
        MsgFlags::default(),
    )
    .ok()
    .expect("staging fits");
    let (kernel, pending) = cycle.submit_recvmsg(prepared);

    let pending = Box::new(pending);
    let pending = core::hint::black_box(pending);
    let pending = *pending;

    let peer = SockAddrIn {
        sin_family: 2,
        sin_port: 4242u16.to_be(),
        sin_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        sin_zero: [0; 8],
    };
    assert_eq!(kernel.deliver_recvmsg(b"travelling", Some(peer)), 10);

    let receipt = kernel.post_completion(cycle.ring, 10);
    let done = pending.redeem(receipt).ok().expect("receipt matches");
    // The address slot the kernel wrote is read back out of the region the
    // ticket carried across the move.
    assert_eq!(done.peer().v4().expect("a peer was written"), peer);

    let (_, _, bufs, store) = done.into_parts();
    assert_eq!(bufs[0].as_slice(), b"travel");
    assert_eq!(bufs[1].as_slice(), b"ling");
    drop(store);
}

#[test]
fn a_truncated_receive_reports_through_the_header_the_kernel_wrote() {
    let cycle = Lifecycle::new();
    let prepared = PreparedRecvmsg::new(
        RawFd::from_raw(7),
        [HeapBuffer::with_capacity(2)],
        msg_region::<1>(),
        PeerWanted::No,
        MsgFlags::default(),
    )
    .ok()
    .expect("staging fits");
    let (kernel, pending) = cycle.submit_recvmsg(prepared);

    // Eleven bytes offered into two. The CQE below says 2 either way; the
    // flag distinguishing loss from a whole short message lives only in
    // the header, so reading it is a second dereference of owned storage.
    assert_eq!(kernel.deliver_recvmsg(b"eleven byte", None), 2);

    let receipt = kernel.post_completion(cycle.ring, 2);
    let done = pending.redeem(receipt).ok().expect("receipt matches");
    let received = done.received().expect("ok");
    assert_eq!(received.bytes(), 2);
    assert!(received.truncated());

    let (_, _, bufs, store) = done.into_parts();
    assert_eq!(bufs[0].as_slice(), b"el");
    drop(store);
}

#[test]
fn a_peer_too_large_for_the_slot_is_not_read_out_of_the_bytes_that_did_fit() {
    let cycle = Lifecycle::new();
    let prepared = PreparedRecvmsg::new(
        RawFd::from_raw(7),
        [HeapBuffer::with_capacity(4)],
        msg_region::<1>(),
        PeerWanted::Yes,
        MsgFlags::default(),
    )
    .ok()
    .expect("staging fits");
    let (kernel, pending) = cycle.submit_recvmsg(prepared);

    // 28 reported into 16 reserved, as an IPv6 peer does. Believing the
    // reported length would read 12 bytes past the slot.
    assert_eq!(kernel.deliver_oversized_peer(b"six", 28), 3);

    let receipt = kernel.post_completion(cycle.ring, 3);
    let done = pending.redeem(receipt).ok().expect("receipt matches");
    assert!(done.peer().is_truncated());
    assert!(done.peer().v4().is_none());

    let (_, _, bufs, store) = done.into_parts();
    drop((bufs, store));
}

#[test]
fn a_short_address_is_refused_even_when_the_bytes_present_look_like_ipv4() {
    // The nastiest shape: the kernel reports fewer bytes than the slot
    // holds, but what it did write begins with AF_INET. A family check
    // alone would accept it and read a port and address out of bytes the
    // kernel never wrote. Only the reported length says otherwise.
    let cycle = Lifecycle::new();
    let prepared = PreparedRecvmsg::new(
        RawFd::from_raw(7),
        [HeapBuffer::with_capacity(4)],
        msg_region::<1>(),
        PeerWanted::Yes,
        MsgFlags::default(),
    )
    .ok()
    .expect("staging fits");
    let (kernel, pending) = cycle.submit_recvmsg(prepared);

    let looks_right = SockAddrIn {
        sin_family: 2,
        sin_port: 9999u16.to_be(),
        sin_addr: u32::from_ne_bytes([10, 1, 2, 3]),
        sin_zero: [0; 8],
    };
    assert_eq!(
        kernel.deliver_with_reported_namelen(b"four", 11, Some(looks_right)),
        4
    );

    let receipt = kernel.post_completion(cycle.ring, 4);
    let done = pending.redeem(receipt).ok().expect("receipt matches");
    assert!(
        done.peer().v4().is_none(),
        "11 of 16 bytes is not a whole address, whatever the family says"
    );
    assert!(!done.peer().is_truncated());

    let (_, _, bufs, store) = done.into_parts();
    drop((bufs, store));
}

#[test]
fn abandoning_a_recvmsg_leaks_every_region_rather_than_freeing_them() {
    let cycle = Lifecycle::new();
    let region = msg_region::<2>();
    let first = HeapBuffer::with_capacity(7);
    let second = HeapBuffer::with_capacity(2);
    let leaked_region = (region.ptr, region.len, region.align);
    let leaked_bufs = [(first.ptr, first.len), (second.ptr, second.len)];

    let prepared = PreparedRecvmsg::new(
        RawFd::from_raw(7),
        [first, second],
        region,
        PeerWanted::No,
        MsgFlags::default(),
    )
    .ok()
    .expect("staging fits");
    let (kernel, pending) = cycle.submit_recvmsg(prepared);

    // Everything leaks. A ticket that freed the staging region would leave
    // the kernel *writing* a header into dead memory, and following the
    // addresses it read from there to write further still.
    drop(pending);
    assert_eq!(kernel.deliver_recvmsg(b"abandoned", None), 9);

    // SAFETY: the abandoned ticket leaked these and the stand-in kernel has
    // finished, so nothing else can reach them.
    unsafe {
        dealloc(
            leaked_region.0,
            HeapBuffer::layout_of(leaked_region.1, leaked_region.2),
        );
        for (ptr, len) in leaked_bufs {
            HeapBuffer::reclaim_leaked(ptr, len);
        }
    }
}

#[test]
fn reclaiming_an_unpublished_recvmsg_returns_every_storage_and_its_header() {
    let cycle = Lifecycle::new();
    let prepared = PreparedRecvmsg::new(
        RawFd::from_raw(7),
        [HeapBuffer::with_capacity(6)],
        msg_region::<1>(),
        PeerWanted::Yes,
        MsgFlags::DONTWAIT,
    )
    .ok()
    .expect("staging fits");
    let (_kernel, pending) = cycle.submit_recvmsg(prepared);

    // SAFETY: this stands in for a rejected push — the SQE was built but
    // never made visible to any kernel, so no storage is referenced.
    let prepared = unsafe { pending.reclaim_unsubmitted() };
    assert_eq!(prepared.flags(), MsgFlags::DONTWAIT);
    assert_eq!(prepared.peer_wanted(), PeerWanted::Yes);
    // The staged header survived the round trip, so a retry receives into
    // the same regions rather than describing stale ones.
    assert_eq!(prepared.published_header().msg_iovlen, 1);
    assert_eq!(
        u64::from(prepared.published_header().msg_namelen),
        core::mem::size_of::<SockAddrIn>() as u64
    );
    assert_eq!(prepared.capacity(), 6);
    let (bufs, store) = prepared.into_parts();
    drop((bufs, store));
}

/// Heap storage aligned for a `Statx`, sized exactly.
fn statx_dest() -> HeapBuffer {
    HeapBuffer::with_alignment(core::mem::size_of::<Statx>(), align_of::<Statx>())
}

#[test]
fn the_kernel_writes_a_whole_statx_into_storage_the_ticket_keeps_alive() {
    let cycle = Lifecycle::new();
    let prepared = PreparedStatx::cwd(
        heap_path(b"/etc/hostname"),
        StatxFlags::default(),
        StatxMask::BASIC_STATS,
        statx_dest(),
    )
    .ok()
    .expect("destination fits");
    let (kernel, pending) = cycle.submit_statx(prepared);

    // Two separate regions, both live: the path is scanned at `addr` and
    // the struct is written at `addr2`, while only the ticket owns either.
    assert_eq!(kernel.resolve_path(), b"/etc/hostname");
    let receipt = kernel.complete_statx(cycle.ring, StatxMask::BASIC_STATS, 4096);

    let done = pending.redeem(receipt).ok().expect("receipt matches");
    let stat = done.stat().expect("a successful statx carries a struct");
    assert_eq!(stat.size(), Some(4096));
    assert_eq!(stat.nlink(), Some(1));
    let (path, dest) = done.into_parts();
    assert_eq!(path.as_bytes(), b"/etc/hostname");
    drop((path.into_storage(), dest));
}

#[test]
fn a_statx_destination_stays_writable_while_the_ticket_moves() {
    let cycle = Lifecycle::new();
    let prepared = PreparedStatx::cwd(
        heap_path(b"/tmp/moved"),
        StatxFlags::default(),
        StatxMask::SIZE,
        statx_dest(),
    )
    .ok()
    .expect("destination fits");
    let (kernel, pending) = cycle.submit_statx(prepared);

    // The hazard the design exists for, with two regions rather than one:
    // both must survive the ticket being boxed, moved and passed through
    // an opaque call before the kernel touches either.
    let pending = Box::new(pending);
    let pending = core::hint::black_box(pending);
    let pending = *pending;

    assert_eq!(kernel.resolve_path(), b"/tmp/moved");
    let receipt = kernel.complete_statx(cycle.ring, StatxMask::SIZE, 17);

    let done = pending.redeem(receipt).ok().expect("receipt matches");
    assert_eq!(done.stat().expect("statx ok").size(), Some(17));
    let (path, dest) = done.into_parts();
    drop((path.into_storage(), dest));
}

#[test]
fn a_failed_statx_reads_nothing_from_the_untouched_destination() {
    let cycle = Lifecycle::new();
    let prepared = PreparedStatx::cwd(
        heap_path(b"/nope"),
        StatxFlags::default(),
        StatxMask::BASIC_STATS,
        statx_dest(),
    )
    .ok()
    .expect("destination fits");
    let (kernel, pending) = cycle.submit_statx(prepared);

    // -ENOENT: the kernel never wrote the destination, so reading it would
    // return whatever was there before. `stat` must decline instead.
    let receipt = Receipt {
        ring: cycle.ring,
        id: RequestId::from_raw(kernel.user_data()),
        result: -2,
        flags: CqeFlags::from_raw(0),
    };
    let done = pending.redeem(receipt).ok().expect("receipt matches");
    assert!(!done.is_ok());
    assert!(done.stat().is_none());
    let (path, dest) = done.into_parts();
    drop((path.into_storage(), dest));
}

#[test]
fn abandoning_a_statx_ticket_leaks_both_regions_rather_than_freeing_them() {
    let cycle = Lifecycle::new();
    let path_storage = HeapBuffer::with_capacity(64);
    let leaked_path = (path_storage.ptr, path_storage.len);
    let dest = statx_dest();
    let leaked_dest = (dest.ptr, dest.len);

    let path = OwnedPath::copy_into(path_storage, b"/tmp/abandoned")
        .ok()
        .expect("storage fits");
    let prepared = PreparedStatx::cwd(path, StatxFlags::default(), StatxMask::SIZE, dest)
        .ok()
        .expect("destination fits");
    let (kernel, pending) = cycle.submit_statx(prepared);

    // Dropping frees neither region: the kernel may still be reading the
    // path *or* writing the struct, so both leak on purpose.
    drop(pending);
    assert_eq!(kernel.resolve_path(), b"/tmp/abandoned");
    let _ = kernel.complete_statx(cycle.ring, StatxMask::SIZE, 1);

    // SAFETY: the abandoned ticket leaked both and the stand-in kernel has
    // finished, so nothing else can reach either allocation.
    unsafe {
        HeapBuffer::reclaim_leaked(leaked_path.0, leaked_path.1);
        dealloc(
            leaked_dest.0,
            Layout::from_size_align(leaked_dest.1, align_of::<Statx>()).expect("valid layout"),
        );
    }
}

#[test]
fn reclaiming_an_unpublished_statx_returns_both_storages_and_its_target() {
    let cycle = Lifecycle::new();
    let prepared = PreparedStatx::at(
        crate::types::DirFd::Cwd,
        heap_path(b"/tmp/retry"),
        StatxFlags::SYMLINK_NOFOLLOW,
        StatxMask::INO,
        statx_dest(),
    )
    .ok()
    .expect("destination fits");
    let (_kernel, pending) = cycle.submit_statx(prepared);

    // SAFETY: this SQE was never published, so the kernel holds no pointer
    // into either region.
    let recovered = unsafe { pending.reclaim_unsubmitted() };

    // Every field survived, not just the storage: a retry must stat the
    // same path with the same flags and mask.
    assert_eq!(recovered.path().as_bytes(), b"/tmp/retry");
    assert_eq!(recovered.flags(), StatxFlags::SYMLINK_NOFOLLOW);
    assert_eq!(recovered.mask(), StatxMask::INO);
    let (path, dest) = recovered.into_parts();
    drop((path.into_storage(), dest));
}

#[test]
fn reclaiming_an_unpublished_open_returns_the_path_and_its_target() {
    let cycle = Lifecycle::new();
    let prepared = PreparedOpen::cwd(
        heap_path(b"/tmp/retry"),
        OpenFlags::CREAT | OpenFlags::RDWR,
        FileMode::OWNER_WRITE,
    );
    let (_kernel, pending) = cycle.submit_open(prepared);

    // SAFETY: this SQE was never published, so the kernel holds no pointer
    // into the path storage.
    let recovered = unsafe { pending.reclaim_unsubmitted() };

    // Every field survived, not just the storage: a retry must open the
    // same path with the same flags and mode.
    assert_eq!(recovered.path().as_bytes(), b"/tmp/retry");
    assert_eq!(recovered.flags(), OpenFlags::CREAT | OpenFlags::RDWR);
    assert_eq!(recovered.mode(), FileMode::OWNER_WRITE);
    drop(recovered.into_path().into_storage());
}

/// Prepare a direct open, unwrapping the `O_CLOEXEC` refusal.
fn direct_open(text: &[u8], target: SlotTarget) -> PreparedDirectOpen<HeapBuffer> {
    PreparedDirectOpen::cwd(
        heap_path(text),
        OpenFlags::default(),
        FileMode::default(),
        target,
    )
    .ok()
    .expect("no O_CLOEXEC")
}

#[test]
fn a_direct_opens_path_is_scanned_within_the_storage_the_ticket_owns() {
    let cycle = Lifecycle::new();
    let (kernel, pending) = cycle.submit_direct_open(direct_open(b"/etc/hosts", SlotTarget::Auto));

    // The path is read exactly as for an ordinary open — unbounded, stopped
    // only by the NUL — so the same scan is worth checking on this path.
    assert_eq!(kernel.resolve_path(), b"/etc/hosts");

    let opened = pending
        .redeem(kernel.post_open(cycle.ring, 3))
        .ok()
        .expect("receipt matches");
    assert!(opened.is_ok());
    let (slot, path) = opened.into_parts();
    // An auto target reads its index out of the result.
    assert_eq!(slot.expect("slot").index().get(), 3);
    assert_eq!(path.as_bytes(), b"/etc/hosts");
    drop(path.into_storage());
}

#[test]
fn a_direct_slot_needs_no_descriptor_to_be_released() {
    let cycle = Lifecycle::new();
    let (kernel, pending) =
        cycle.submit_direct_open(direct_open(b"/tmp/slotted", SlotTarget::Auto));

    let opened = pending
        .redeem(kernel.post_open(cycle.ring, 2))
        .ok()
        .expect("receipt matches");
    let (slot, path) = opened.into_parts();

    // The contrast with `PendingOpen` is the point: a `File` must be
    // consumed with `into_fd` here or its destructor would close a
    // descriptor this fake kernel never opened. A slot has no destructor
    // at all, because releasing one means asking the ring — so simply
    // dropping it is well-defined, and Miri's leak checker stays quiet.
    //
    // `drop_non_drop` firing here is the assertion: clippy is confirming
    // that `DirectSlot` has nothing to run.
    #[allow(clippy::drop_non_drop)]
    drop(slot);
    drop(path.into_storage());
}

#[test]
fn an_abandoned_direct_open_leaks_its_path_like_any_other_ticket() {
    let cycle = Lifecycle::new();
    // From the allocation itself, not through the narrower `as_bytes()`
    // borrow, which cannot be used to free the whole block.
    let mut storage = HeapBuffer::with_capacity(64);
    storage.as_mut_slice().fill(0xFF);
    let leaked = (storage.ptr, storage.len);
    let path = OwnedPath::copy_into(storage, b"/tmp/dropped")
        .ok()
        .expect("storage fits");
    let prepared = PreparedDirectOpen::cwd(
        path,
        OpenFlags::default(),
        FileMode::default(),
        SlotTarget::exact(1).expect("representable"),
    )
    .ok()
    .expect("no O_CLOEXEC");
    let (kernel, pending) = cycle.submit_direct_open(prepared);

    drop(pending);
    // The kernel is still resolving the path the abandoned ticket owned.
    assert_eq!(kernel.resolve_path(), b"/tmp/dropped");

    // SAFETY: the abandoned ticket leaked this and the stand-in kernel has
    // finished, so nothing else can reach it.
    unsafe { HeapBuffer::reclaim_leaked(leaked.0, leaked.1) };
}

#[test]
fn reclaiming_an_unpublished_direct_open_keeps_its_target() {
    let cycle = Lifecycle::new();
    let target = SlotTarget::exact(4).expect("representable");
    let (_kernel, pending) = cycle.submit_direct_open(direct_open(b"/tmp/again", target));

    // SAFETY: this SQE was never published, so the kernel holds no pointer
    // into the path storage.
    let recovered = unsafe { pending.reclaim_unsubmitted() };

    // The target has to survive: a retry that lost it would install the
    // file into a different slot, or ask the kernel to choose one.
    assert_eq!(recovered.target(), target);
    assert_eq!(recovered.path().as_bytes(), b"/tmp/again");
    drop(recovered.into_path().into_storage());
}

/// Storage for one `Timespec`, aligned as the real one requires.
///
/// Byte-aligned storage is what Miri rejects and what the system allocator
/// would hide by handing back aligned addresses anyway.
fn timespec_store() -> HeapBuffer {
    HeapBuffer::with_alignment(core::mem::size_of::<Timespec>(), align_of::<Timespec>())
}

#[test]
fn the_kernel_reads_a_timeouts_duration_from_storage_the_ticket_owns() {
    let cycle = Lifecycle::new();
    let prepared = PreparedTimeout::after(
        Timespec::new(9, 12_345),
        Count::Completions(4),
        timespec_store(),
    )
    .ok()
    .expect("aligned storage fits");
    let (kernel, pending) = cycle.submit_timeout(prepared);

    // The read happens while only the ticket owns the storage, which is
    // the window SQPOLL makes unbounded.
    let seen = kernel.read_timespec();
    assert_eq!(seen.tv_sec(), 9);
    assert_eq!(seen.tv_nsec(), 12_345);
    // The count travels in the SQE rather than in caller memory.
    assert_eq!(kernel.published_count(), 4);

    let receipt = kernel.post_status(cycle.ring, -62);
    let done = pending.redeem(receipt).ok().expect("receipt matches");
    assert_eq!(done.expiry(), super::Expiry::Expired);
    drop(done.into_store());
}

#[test]
fn a_timeouts_duration_survives_the_ticket_moving_between_owners() {
    let cycle = Lifecycle::new();
    let prepared = PreparedTimeout::after(Timespec::new(3, 7), Count::Timer, timespec_store())
        .ok()
        .expect("aligned storage fits");
    let (kernel, pending) = cycle.submit_timeout(prepared);

    // Moving the ticket is the hazard: an inline `Timespec` would relocate
    // the exact bytes the SQ thread is about to copy.
    let pending = Box::new(pending);
    let pending = core::hint::black_box(pending);
    let pending = *pending;

    let seen = kernel.read_timespec();
    assert_eq!(seen.tv_sec(), 3);
    assert_eq!(seen.tv_nsec(), 7);

    let receipt = kernel.post_status(cycle.ring, -62);
    let done = pending.redeem(receipt).ok().expect("receipt matches");
    drop(done.into_store());
}

#[test]
fn abandoning_a_timeout_leaks_rather_than_freeing_the_duration() {
    let cycle = Lifecycle::new();
    let store = timespec_store();
    let addr = store.stable_ptr();
    let prepared = PreparedTimeout::after(Timespec::new(1, 2), Count::Timer, store)
        .ok()
        .expect("aligned storage fits");
    let (kernel, pending) = cycle.submit_timeout(prepared);

    // Dropping an in-flight ticket must not free storage the SQ thread may
    // still be copying from.
    drop(pending);
    let seen = kernel.read_timespec();
    assert_eq!(seen.tv_sec(), 1);

    // SAFETY: the leak above is deliberate; the stand-in kernel has
    // finished and nothing else references this allocation.
    unsafe {
        HeapBuffer::reclaim_aligned(
            addr.cast_mut(),
            core::mem::size_of::<Timespec>(),
            align_of::<Timespec>(),
        );
    }
}

#[test]
fn reclaiming_an_unpublished_timeout_returns_the_storage_and_its_count() {
    let cycle = Lifecycle::new();
    let prepared = PreparedTimeout::at(
        Timespec::new(50, 500),
        Count::Completions(2),
        timespec_store(),
    )
    .ok()
    .expect("aligned storage fits");
    let (_kernel, pending) = cycle.submit_timeout(prepared);

    // SAFETY: this stands in for a rejected push — the SQE was built but
    // never made visible to any kernel, so the storage is unreferenced.
    let prepared = unsafe { pending.reclaim_unsubmitted() };
    // A retry must issue the same request, so the published duration, the
    // count, and the absolute flag all have to survive.
    assert_eq!(prepared.published().tv_sec(), 50);
    assert_eq!(prepared.published().tv_nsec(), 500);
    assert_eq!(prepared.count(), Count::Completions(2));
    assert!(prepared.is_absolute());
    drop(prepared.into_store());
}

/// Storage for a descriptor array, aligned as the real one requires.
fn fd_array_store<const N: usize>() -> HeapBuffer {
    HeapBuffer::with_alignment(core::mem::size_of::<i32>() * N, align_of::<i32>())
}

/// A table index well below the reserved sentinels.
fn slot_index(index: u32) -> SlotIndex {
    SlotIndex::new(index).expect("a small index is representable")
}

#[test]
fn the_kernel_walks_the_fd_array_inside_storage_the_ticket_owns() {
    let cycle = Lifecycle::new();
    // Distinct values: an array of three identical entries would pass even
    // if every read returned the first.
    let prepared = PreparedFilesUpdate::at(
        slot_index(4),
        [
            TableEntry::Install(RawFd::from_raw(11)),
            TableEntry::Clear,
            TableEntry::Install(RawFd::from_raw(13)),
        ],
        fd_array_store::<3>(),
    )
    .ok()
    .expect("aligned storage fits");
    let (kernel, pending) = cycle.submit_files_update(prepared);

    assert_eq!(kernel.read_fd_array(), std::vec![11, -1, 13]);
    // The offset travels in the SQE rather than in caller memory.
    assert_eq!(kernel.published_offset(), 4);

    let receipt = kernel.post_status(cycle.ring, 3);
    let done = pending.redeem(receipt).ok().expect("receipt matches");
    assert_eq!(done.update(), Update::All { count: 3 });
    drop(done.into_store());
}

#[test]
fn an_arrays_storage_survives_the_ticket_moving_between_owners() {
    let cycle = Lifecycle::new();
    let prepared = PreparedFilesUpdate::at(
        slot_index(0),
        [TableEntry::Install(RawFd::from_raw(21)), TableEntry::Clear],
        fd_array_store::<2>(),
    )
    .ok()
    .expect("aligned storage fits");
    let (kernel, pending) = cycle.submit_files_update(prepared);

    // Moving the ticket is the hazard: an inline array would relocate the
    // exact bytes the kernel is about to walk.
    let pending = Box::new(pending);
    let pending = core::hint::black_box(pending);
    let pending = *pending;

    assert_eq!(kernel.read_fd_array(), std::vec![21, -1]);

    let receipt = kernel.post_status(cycle.ring, 2);
    let done = pending.redeem(receipt).ok().expect("receipt matches");
    drop(done.into_store());
}

#[test]
fn abandoning_a_files_update_leaks_rather_than_freeing_the_array() {
    let cycle = Lifecycle::new();
    let store = fd_array_store::<2>();
    let addr = store.stable_ptr();
    let prepared = PreparedFilesUpdate::at(
        slot_index(0),
        [TableEntry::Install(RawFd::from_raw(31)), TableEntry::Clear],
        store,
    )
    .ok()
    .expect("aligned storage fits");
    let (kernel, pending) = cycle.submit_files_update(prepared);

    // Dropping an in-flight ticket must not free an array the kernel may
    // still be walking.
    drop(pending);
    assert_eq!(kernel.read_fd_array(), std::vec![31, -1]);

    // SAFETY: the leak above is deliberate; the stand-in kernel has
    // finished and nothing else references this allocation.
    unsafe {
        HeapBuffer::reclaim_aligned(
            addr.cast_mut(),
            core::mem::size_of::<i32>() * 2,
            align_of::<i32>(),
        );
    }
}

#[test]
fn reclaiming_an_unpublished_files_update_returns_the_array_and_its_offset() {
    let cycle = Lifecycle::new();
    let prepared = PreparedFilesUpdate::at(
        slot_index(6),
        [TableEntry::Install(RawFd::from_raw(41))],
        fd_array_store::<1>(),
    )
    .ok()
    .expect("aligned storage fits");
    let (_kernel, pending) = cycle.submit_files_update(prepared);

    // SAFETY: this stands in for a rejected push, so the SQE was built but
    // never made visible to any kernel and the storage is unreferenced.
    let prepared = unsafe { pending.reclaim_unsubmitted() };
    // A retry must issue the same request, so the published array and the
    // offset both have to survive.
    assert_eq!(prepared.published(), [41]);
    assert_eq!(prepared.offset().get(), 6);
    drop(prepared.into_store());
}

/// Storage for one `EpollEvent`, aligned as the real one requires.
fn epoll_event_store() -> HeapBuffer {
    HeapBuffer::with_alignment(core::mem::size_of::<EpollEvent>(), align_of::<EpollEvent>())
}

#[test]
fn the_kernel_reads_an_epoll_event_from_storage_the_ticket_owns() {
    let cycle = Lifecycle::new();
    let prepared = PreparedEpollCtl::new(
        RawFd::from_raw(3),
        RawFd::from_raw(9),
        EpollChange::Add {
            events: EpollEvents::IN,
            data: 0x1234_5678,
        },
        epoll_event_store(),
    )
    .ok()
    .expect("aligned storage fits");
    let (kernel, pending) = cycle.submit_epoll_ctl(prepared);

    let seen = kernel.read_epoll_event();
    let (events, data) = (seen.events, seen.data);
    assert_eq!(events, EpollEvents::IN.bits());
    assert_eq!(data, 0x1234_5678);
    // The operation travels in the SQE rather than in caller memory.
    assert_eq!(kernel.published_epoll_op(), 1);

    let receipt = kernel.post_status(cycle.ring, 0);
    let done = pending.redeem(receipt).ok().expect("receipt matches");
    assert_eq!(done.outcome(), EpollOutcome::Applied);
    drop(done.into_store());
}

#[test]
fn a_dels_storage_is_live_even_though_the_kernel_reads_nothing() {
    let cycle = Lifecycle::new();
    let prepared = PreparedEpollCtl::new(
        RawFd::from_raw(3),
        RawFd::from_raw(9),
        EpollChange::Del,
        epoll_event_store(),
    )
    .ok()
    .expect("aligned storage fits");
    let (kernel, pending) = cycle.submit_epoll_ctl(prepared);

    // Nothing in the SQE says "this address will not be read", so the
    // storage has to be as live as any other request's — a kernel that
    // did read it must find initialised bytes rather than a dangling
    // pointer.
    let seen = kernel.read_epoll_event();
    let events = seen.events;
    assert_eq!(events, 0);
    assert_eq!(kernel.published_epoll_op(), 2);

    let receipt = kernel.post_status(cycle.ring, 0);
    let done = pending.redeem(receipt).ok().expect("receipt matches");
    drop(done.into_store());
}

#[test]
fn an_events_storage_survives_the_ticket_moving_between_owners() {
    let cycle = Lifecycle::new();
    let prepared = PreparedEpollCtl::new(
        RawFd::from_raw(3),
        RawFd::from_raw(9),
        EpollChange::Mod {
            events: EpollEvents::OUT,
            data: 77,
        },
        epoll_event_store(),
    )
    .ok()
    .expect("aligned storage fits");
    let (kernel, pending) = cycle.submit_epoll_ctl(prepared);

    // Moving the ticket is the hazard: an inline event would relocate the
    // exact bytes the kernel is about to read.
    let pending = Box::new(pending);
    let pending = core::hint::black_box(pending);
    let pending = *pending;

    let seen = kernel.read_epoll_event();
    let (events, data) = (seen.events, seen.data);
    assert_eq!(events, EpollEvents::OUT.bits());
    assert_eq!(data, 77);

    let receipt = kernel.post_status(cycle.ring, 0);
    let done = pending.redeem(receipt).ok().expect("receipt matches");
    drop(done.into_store());
}

#[test]
fn abandoning_an_epoll_ctl_leaks_rather_than_freeing_the_event() {
    let cycle = Lifecycle::new();
    let store = epoll_event_store();
    let addr = store.stable_ptr();
    let prepared = PreparedEpollCtl::new(
        RawFd::from_raw(3),
        RawFd::from_raw(9),
        EpollChange::Add {
            events: EpollEvents::IN,
            data: 5,
        },
        store,
    )
    .ok()
    .expect("aligned storage fits");
    let (kernel, pending) = cycle.submit_epoll_ctl(prepared);

    // Dropping an in-flight ticket must not free an event the kernel may
    // still be reading.
    drop(pending);
    let seen = kernel.read_epoll_event();
    let data = seen.data;
    assert_eq!(data, 5);

    // SAFETY: the leak above is deliberate; the stand-in kernel has
    // finished and nothing else references this allocation.
    unsafe {
        HeapBuffer::reclaim_aligned(
            addr.cast_mut(),
            core::mem::size_of::<EpollEvent>(),
            align_of::<EpollEvent>(),
        );
    }
}

#[test]
fn reclaiming_an_unpublished_epoll_ctl_returns_the_storage_and_its_change() {
    let cycle = Lifecycle::new();
    let change = EpollChange::Mod {
        events: EpollEvents::HUP,
        data: 321,
    };
    let prepared = PreparedEpollCtl::new(
        RawFd::from_raw(3),
        RawFd::from_raw(9),
        change,
        epoll_event_store(),
    )
    .ok()
    .expect("aligned storage fits");
    let (_kernel, pending) = cycle.submit_epoll_ctl(prepared);

    // SAFETY: this stands in for a rejected push, so the SQE was built but
    // never made visible to any kernel and the storage is unreferenced.
    let prepared = unsafe { pending.reclaim_unsubmitted() };
    // A retry must issue the same request, so the change and the published
    // event both have to survive.
    assert_eq!(prepared.change(), change);
    let seen = prepared.published();
    let (events, data) = (seen.events, seen.data);
    assert_eq!(events, EpollEvents::HUP.bits());
    assert_eq!(data, 321);
    drop(prepared.into_store());
}

/// Storage for one socket address.
fn bind_addr_store() -> HeapBuffer {
    HeapBuffer::with_capacity(core::mem::size_of::<SockAddrIn>())
}

/// A loopback address on `port`, in the byte order the kernel expects.
fn miri_loopback(port: u16) -> SockAddrIn {
    SockAddrIn {
        sin_family: 2,
        sin_port: port.to_be(),
        sin_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        sin_zero: [0; 8],
    }
}

#[test]
fn the_kernel_reads_a_sock_addr_from_storage_the_ticket_owns() {
    let cycle = Lifecycle::new();
    let prepared = PreparedBind::new(RawFd::from_raw(3), miri_loopback(8080), bind_addr_store())
        .ok()
        .expect("storage fits");
    let (kernel, pending) = cycle.submit_bind(prepared);

    assert_eq!(kernel.read_sock_addr(), miri_loopback(8080).to_bytes());
    // The length travels in the SQE rather than in caller memory.
    assert_eq!(
        kernel.published_addr_len(),
        core::mem::size_of::<SockAddrIn>() as u64
    );

    let receipt = kernel.post_status(cycle.ring, 0);
    let done = pending.redeem(receipt).ok().expect("receipt matches");
    assert_eq!(done.outcome(), BindOutcome::Bound);
    drop(done.into_store());
}

#[test]
fn an_addresss_storage_survives_the_ticket_moving_between_owners() {
    let cycle = Lifecycle::new();
    let prepared = PreparedBind::new(RawFd::from_raw(3), miri_loopback(443), bind_addr_store())
        .ok()
        .expect("storage fits");
    let (kernel, pending) = cycle.submit_bind(prepared);

    // Moving the ticket is the hazard: an inline address would relocate
    // the exact bytes the kernel is about to read.
    let pending = Box::new(pending);
    let pending = core::hint::black_box(pending);
    let pending = *pending;

    assert_eq!(kernel.read_sock_addr(), miri_loopback(443).to_bytes());

    let receipt = kernel.post_status(cycle.ring, 0);
    let done = pending.redeem(receipt).ok().expect("receipt matches");
    drop(done.into_store());
}

#[test]
fn abandoning_a_bind_leaks_rather_than_freeing_the_address() {
    let cycle = Lifecycle::new();
    let store = bind_addr_store();
    let addr = store.stable_ptr();
    let prepared = PreparedBind::new(RawFd::from_raw(3), miri_loopback(9999), store)
        .ok()
        .expect("storage fits");
    let (kernel, pending) = cycle.submit_bind(prepared);

    // Dropping an in-flight ticket must not free an address the kernel
    // may still be reading.
    drop(pending);
    assert_eq!(kernel.read_sock_addr(), miri_loopback(9999).to_bytes());

    // SAFETY: the leak above is deliberate; the stand-in kernel has
    // finished and nothing else references this allocation.
    unsafe {
        HeapBuffer::reclaim_leaked(addr.cast_mut(), core::mem::size_of::<SockAddrIn>());
    }
}

#[test]
fn reclaiming_an_unpublished_bind_returns_the_storage_and_its_address() {
    let cycle = Lifecycle::new();
    let prepared = PreparedBind::new(RawFd::from_raw(3), miri_loopback(1234), bind_addr_store())
        .ok()
        .expect("storage fits");
    let (_kernel, pending) = cycle.submit_bind(prepared);

    // SAFETY: this stands in for a rejected push, so the SQE was built but
    // never made visible to any kernel and the storage is unreferenced.
    let prepared = unsafe { pending.reclaim_unsubmitted() };
    // A retry must issue the same request, so the address and its
    // published bytes both have to survive.
    assert_eq!(prepared.addr(), miri_loopback(1234));
    assert_eq!(prepared.published(), miri_loopback(1234).to_bytes());
    drop(prepared.into_store());
}

#[test]
fn the_kernel_reads_a_connect_address_from_storage_the_ticket_owns() {
    let cycle = Lifecycle::new();
    let prepared = PreparedConnect::new(RawFd::from_raw(3), miri_loopback(8080), bind_addr_store())
        .ok()
        .expect("storage fits");
    let (kernel, pending) = cycle.submit_connect(prepared);

    assert_eq!(kernel.read_sock_addr(), miri_loopback(8080).to_bytes());
    assert_eq!(
        kernel.published_addr_len(),
        core::mem::size_of::<SockAddrIn>() as u64
    );

    let receipt = kernel.post_status(cycle.ring, 0);
    let done = pending.redeem(receipt).ok().expect("receipt matches");
    assert_eq!(done.outcome(), ConnectOutcome::Connected);
    drop(done.into_store());
}

#[test]
fn a_connect_address_survives_the_ticket_moving_between_owners() {
    let cycle = Lifecycle::new();
    let prepared = PreparedConnect::new(RawFd::from_raw(3), miri_loopback(443), bind_addr_store())
        .ok()
        .expect("storage fits");
    let (kernel, pending) = cycle.submit_connect(prepared);

    // The ticket is meant to cross to a completion thread, so the address
    // must not ride inline where moving would relocate it.
    let pending = Box::new(pending);
    let pending = core::hint::black_box(pending);
    let pending = *pending;

    assert_eq!(kernel.read_sock_addr(), miri_loopback(443).to_bytes());

    let receipt = kernel.post_status(cycle.ring, 0);
    let done = pending.redeem(receipt).ok().expect("receipt matches");
    drop(done.into_store());
}

#[test]
fn abandoning_a_connect_leaks_rather_than_freeing_the_address() {
    let cycle = Lifecycle::new();
    let store = bind_addr_store();
    let addr = store.stable_ptr();
    let prepared = PreparedConnect::new(RawFd::from_raw(3), miri_loopback(9999), store)
        .ok()
        .expect("storage fits");
    let (kernel, pending) = cycle.submit_connect(prepared);

    // Under SQPOLL nothing proves the kernel has copied the address yet,
    // so dropping the ticket must leak rather than free it.
    drop(pending);
    assert_eq!(kernel.read_sock_addr(), miri_loopback(9999).to_bytes());

    // SAFETY: the leak above is deliberate; the stand-in kernel has
    // finished and nothing else references this allocation.
    unsafe {
        HeapBuffer::reclaim_leaked(addr.cast_mut(), core::mem::size_of::<SockAddrIn>());
    }
}

#[test]
fn reclaiming_an_unpublished_connect_returns_the_storage_and_its_address() {
    let cycle = Lifecycle::new();
    let prepared = PreparedConnect::new(RawFd::from_raw(3), miri_loopback(1234), bind_addr_store())
        .ok()
        .expect("storage fits");
    let (_kernel, pending) = cycle.submit_connect(prepared);

    // SAFETY: this stands in for a rejected push, so the SQE was built but
    // never made visible to any kernel and the storage is unreferenced.
    let prepared = unsafe { pending.reclaim_unsubmitted() };
    assert_eq!(prepared.addr(), miri_loopback(1234));
    assert_eq!(prepared.published(), miri_loopback(1234).to_bytes());
    drop(prepared.into_store());
}

#[test]
fn many_concurrent_tickets_keep_their_buffers_distinct() {
    let cycle = Lifecycle::new();
    let mut inflight = Vec::new();

    for i in 0..16u8 {
        let prepared = Prepared::read(RawFd::from_raw(3), HeapBuffer::with_capacity(8), 0);
        let (kernel, pending) = cycle.submit(prepared);
        kernel.complete_read(i);
        inflight.push((kernel, pending, i));
    }

    // Redeem out of submission order: receipts are matched by identity, not
    // by arrival position.
    inflight.reverse();
    for (kernel, pending, fill) in inflight {
        let receipt = kernel.post_completion(cycle.ring, 8);
        let completed = pending.redeem(receipt).ok().expect("receipt matches");
        assert_eq!(completed.direction(), Direction::Read);
        assert!(completed.buffer().as_slice().iter().all(|&b| b == fill));
    }
}
