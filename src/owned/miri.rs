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

use super::direct::{PendingDirectOpen, PreparedDirectOpen};
use super::event::PartialReceipt;
use super::identity::{RequestId, RequestIdSource, RingId};
use super::open::{PendingOpen, PreparedOpen};
use super::path::OwnedPath;
use super::slot::SlotTarget;
use super::statx::{PendingStatx, PreparedStatx};
use super::vectored::{PendingVectored, PreparedVectored};
use super::zerocopy::{PendingZc, PreparedZc};
use super::{Direction, Pending, Prepared, Receipt, StableBuffer, StableBufferMut};
use crate::op::Sqe;
use crate::types::{
    CqeFlags, FileMode, IoVec, MsgFlags, OpenFlags, RawFd, Statx, StatxFlags, StatxMask,
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
        // `with_capacity(len)` and is otherwise unreachable.
        unsafe { dealloc(ptr, Self::layout_of(len, 1)) };
    }

    /// Free leaked descriptor storage, which has its own alignment.
    ///
    /// # Safety
    ///
    /// `ptr` must come from `for_descriptors(len)` and be unreachable.
    unsafe fn reclaim_leaked_descriptors(ptr: *mut u8, len: usize) {
        // SAFETY: as above, with the alignment `for_descriptors` used.
        unsafe { dealloc(ptr, Self::layout_of(len, align_of::<IoVec>())) };
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
    /// The SQE stores a `u64` because that is the kernel ABI, so this is an
    /// int-to-pointer cast by necessity. Miri is told to expose the
    /// provenance at the source, which is what makes accesses through this
    /// pointer checkable rather than silently unchecked.
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
