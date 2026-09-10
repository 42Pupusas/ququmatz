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

use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::boxed::Box;
use std::vec::Vec;

use super::event::PartialReceipt;
use super::identity::{RequestId, RequestIdSource, RingId};
use super::zerocopy::{PendingZc, PreparedZc};
use super::{Direction, Pending, Prepared, Receipt, StableBuffer, StableBufferMut};
use crate::op::Sqe;
use crate::types::{CqeFlags, MsgFlags, RawFd};

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
}

impl HeapBuffer {
    fn layout(len: usize) -> Layout {
        Layout::from_size_align(len, 1).expect("valid layout")
    }

    fn with_capacity(len: usize) -> Self {
        assert!(len > 0, "zero-length test buffer");
        let ptr = unsafe { alloc_zeroed(Self::layout(len)) };
        assert!(!ptr.is_null(), "allocation failed");
        Self { ptr, len }
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
        unsafe { dealloc(ptr, Self::layout(len)) };
    }
}

impl Drop for HeapBuffer {
    fn drop(&mut self) {
        // SAFETY: `ptr` came from `alloc_zeroed` with this exact layout and
        // is freed exactly once, since `Pending` never drops its buffer.
        unsafe { dealloc(self.ptr, Self::layout(self.len)) };
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
