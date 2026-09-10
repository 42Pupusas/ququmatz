//! Behavioural tests for the owned-request lifecycle.

extern crate std;

use super::{Completed, Direction, MmapBuffer, Pending, Prepared, Receipt, RingId, StableBuffer};
use crate::error::{Error, SubmitError};
use crate::types::RawFd;

/// Static proof that a ticket crosses a thread boundary. The whole design
/// exists to make this true.
const fn assert_send<T: Send>() {}
const _: () = assert_send::<Pending<MmapBuffer>>();
const _: () = assert_send::<Completed<MmapBuffer>>();
const _: () = assert_send::<Prepared<MmapBuffer>>();
const _: () = assert_send::<Receipt>();
const _: () = assert_send::<MmapBuffer>();

#[test]
fn prepared_reports_direction_and_length() {
    let buf = MmapBuffer::with_capacity(128).expect("map");
    let read = Prepared::read(RawFd::from_raw(3), buf, 0);
    assert_eq!(read.direction(), Direction::Read);
    assert_eq!(read.len(), 128);

    let buf = MmapBuffer::with_capacity(64).expect("map");
    let write = Prepared::write(RawFd::from_raw(3), buf, 0);
    assert_eq!(write.direction(), Direction::Write);
    assert_eq!(write.len(), 64);
}

#[test]
fn prepared_buffer_is_reachable_before_submission() {
    let buf = MmapBuffer::with_capacity(32).expect("map");
    let mut prepared = Prepared::write(RawFd::from_raw(1), buf, 0);
    prepared.buffer_mut().as_mut_slice()[..3].copy_from_slice(b"abc");
    assert_eq!(&prepared.buffer().as_slice()[..3], b"abc");
}

#[test]
fn abandoning_a_prepared_request_returns_the_buffer() {
    let buf = MmapBuffer::with_capacity(16).expect("map");
    let addr = buf.stable_ptr();
    let prepared = Prepared::write(RawFd::from_raw(1), buf, 0);
    assert_eq!(prepared.into_buffer().stable_ptr(), addr);
}

#[test]
fn buffer_address_is_unchanged_by_the_prepared_wrapper() {
    let buf = MmapBuffer::with_capacity(64).expect("map");
    let addr = buf.stable_ptr();
    let prepared = Prepared::read(RawFd::from_raw(0), buf, 0);
    assert_eq!(prepared.buffer().stable_ptr(), addr);
}

#[test]
fn oversized_buffers_clamp_the_transfer_length() {
    let buf = MmapBuffer::with_capacity(4096).expect("map");
    assert_eq!(Prepared::read(RawFd::from_raw(0), buf, 0).len(), 4096);
}

#[test]
fn with_len_shortens_the_transfer_but_never_extends_it() {
    let buf = MmapBuffer::with_capacity(64).expect("map");
    let shortened = Prepared::write(RawFd::from_raw(1), buf, 0).with_len(5);
    assert_eq!(shortened.len(), 5);

    // Asking for more than the buffer holds cannot widen the kernel's view.
    let buf = MmapBuffer::with_capacity(16).expect("map");
    let clamped = Prepared::write(RawFd::from_raw(1), buf, 0).with_len(u32::MAX);
    assert_eq!(clamped.len(), 16);
}

#[test]
fn queue_full_hands_the_request_back_with_its_buffer() {
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, _comp) = ring
        .split_owned()
        .unwrap_or_else(|(_, e)| panic!("split_owned: {e}"));

    let mut tickets = alloc_tickets(&mut sub);
    let buf = MmapBuffer::with_capacity(32).expect("map");
    let addr = buf.stable_ptr();

    let Err((returned, err)) = sub.push(Prepared::write(RawFd::from_raw(1), buf, 0)) else {
        panic!("a full queue must reject the push");
    };
    assert_eq!(err, Error::Submit(SubmitError::QueueFull));
    // The buffer came back intact rather than being leaked or freed.
    assert_eq!(returned.into_buffer().stable_ptr(), addr);
    tickets.clear();
}

/// Fill the submission queue, returning the tickets so they stay alive.
fn alloc_tickets(sub: &mut super::OwnedSubmitter) -> heapless::Tickets {
    let mut tickets = heapless::Tickets::new();
    while sub.space_left() > 0 {
        let buf = MmapBuffer::with_capacity(16).expect("map");
        match sub.push(Prepared::write(RawFd::from_raw(1), buf, 0)) {
            Ok(t) => tickets.push(t),
            Err(_) => break,
        }
    }
    tickets
}

/// Minimal fixed-capacity ticket holder — the crate has no allocator.
mod heapless {
    use super::MmapBuffer;
    use crate::owned::Pending;

    pub struct Tickets {
        slots: [Option<Pending<MmapBuffer>>; 64],
        len: usize,
    }

    impl Tickets {
        pub const fn new() -> Self {
            Self {
                slots: [const { None }; 64],
                len: 0,
            }
        }

        pub fn push(&mut self, ticket: Pending<MmapBuffer>) {
            assert!(self.len < self.slots.len(), "ticket capacity exceeded");
            self.slots[self.len] = Some(ticket);
            self.len += 1;
        }

        pub fn clear(&mut self) {
            for slot in &mut self.slots {
                *slot = None;
            }
            self.len = 0;
        }
    }
}

#[test]
fn ring_identity_is_stamped_on_both_halves() {
    let ring = crate::IoUring::new(4).expect("ring");
    let (sub, comp) = ring
        .split_owned()
        .unwrap_or_else(|(_, e)| panic!("split_owned: {e}"));
    assert_eq!(sub.ring(), comp.ring());
}

#[test]
fn separate_rings_get_distinct_identities() {
    let (a, _) = crate::IoUring::new(4)
        .expect("ring a")
        .split_owned()
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    let (b, _) = crate::IoUring::new(4)
        .expect("ring b")
        .split_owned()
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    assert_ne!(a.ring(), b.ring());
}

#[test]
fn a_receipt_from_another_ring_cannot_redeem_a_ticket() {
    let (mut sub_a, _comp_a) = crate::IoUring::new(4)
        .expect("ring a")
        .split_owned()
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    let (mut sub_b, mut comp_b) = crate::IoUring::new(4)
        .expect("ring b")
        .split_owned()
        .unwrap_or_else(|(_, e)| panic!("{e}"));

    // A real, terminal completion — but from ring B.
    let nop = MmapBuffer::with_capacity(8).expect("map");
    let ticket_b = sub_b
        .push(Prepared::write(RawFd::from_raw(1), nop, 0))
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub_b.submit_and_wait(1).expect("submit b");
    let receipt_b = comp_b.reap().expect("a completion from ring b");

    // Ring A's ticket must refuse it even though both are valid values.
    let buf_a = MmapBuffer::with_capacity(8).expect("map");
    let ticket_a = sub_a
        .push(Prepared::write(RawFd::from_raw(1), buf_a, 0))
        .unwrap_or_else(|(_, e)| panic!("{e}"));

    assert!(!ticket_a.matches(&receipt_b));
    let Err((ticket_a, receipt_b)) = ticket_a.redeem(receipt_b) else {
        panic!("a cross-ring receipt must not redeem");
    };

    // And the rightful owner still can.
    assert!(ticket_b.matches(&receipt_b));
    assert!(ticket_b.redeem(receipt_b).is_ok());
    core::mem::forget(ticket_a);
}

#[test]
fn a_receipt_for_another_request_on_the_same_ring_is_rejected() {
    let ring = crate::IoUring::new(8).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let first = sub
        .push(Prepared::write(
            RawFd::from_raw(1),
            MmapBuffer::with_capacity(8).expect("map"),
            0,
        ))
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    let second = sub
        .push(Prepared::write(
            RawFd::from_raw(1),
            MmapBuffer::with_capacity(8).expect("map"),
            0,
        ))
        .unwrap_or_else(|(_, e)| panic!("{e}"));

    assert_ne!(first.id(), second.id());
    sub.submit_and_wait(2).expect("submit");

    let receipt = comp.reap().expect("first completion");
    // Exactly one of the two tickets owns this receipt.
    let owner_is_first = first.matches(&receipt);
    assert_eq!(owner_is_first, !second.matches(&receipt));

    if owner_is_first {
        assert!(first.redeem(receipt).is_ok());
        core::mem::forget(second);
    } else {
        assert!(second.redeem(receipt).is_ok());
        core::mem::forget(first);
    }
    comp.sync();
}

#[test]
fn redeemed_buffer_carries_the_kernel_result_and_survives() {
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let mut buf = MmapBuffer::with_capacity(64).expect("map");
    buf.as_mut_slice()[..5].copy_from_slice(b"hello");
    let addr = buf.stable_ptr();

    // fd 1 is stdout: a real write that reports a real byte count.
    let ticket = sub
        .push(Prepared::write(RawFd::from_raw(1), buf, 0).with_len(5))
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit().expect("submit");

    let receipt = comp.wait_one().expect("completion");
    let done = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("the matching receipt must redeem"));

    let (result, buf) = done.into_parts();
    assert_eq!(result.expect("write should succeed"), 5);
    // Same storage came back, contents intact.
    assert_eq!(buf.stable_ptr(), addr);
    assert_eq!(&buf.as_slice()[..5], b"hello");
    comp.sync();
}

#[test]
fn a_read_fills_the_owned_buffer() {
    use std::os::fd::AsRawFd as _;

    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let file = std::fs::File::open("/proc/self/cmdline").expect("open cmdline");
    let fd = RawFd::from_raw(file.as_raw_fd() as usize);

    let ticket = sub
        .push(Prepared::read(
            fd,
            MmapBuffer::with_capacity(256).expect("map"),
            0,
        ))
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit().expect("submit");

    let receipt = comp.wait_one().expect("completion");
    let done = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("matching receipt"));
    assert_eq!(done.direction(), Direction::Read);

    let (result, buf) = done.into_parts();
    let n = result.expect("read should succeed") as usize;
    assert!(n > 0, "/proc/self/cmdline is never empty");
    // The kernel wrote into storage this thread never aliased.
    assert!(buf.as_slice()[..n].iter().any(|&b| b != 0));
    comp.sync();
}

#[test]
fn completed_reports_a_kernel_error_without_losing_the_buffer() {
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let buf = MmapBuffer::with_capacity(16).expect("map");
    let addr = buf.stable_ptr();
    // A closed/invalid fd makes the kernel fail the operation.
    let ticket = sub
        .push(Prepared::write(RawFd::from_raw(0x7fff_fffe), buf, 0))
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit().expect("submit");

    let receipt = comp.wait_one().expect("completion");
    assert!(receipt.raw_result() < 0, "expected a kernel error");

    let done = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("matching receipt"));
    let (result, buf) = done.into_parts();
    assert!(result.is_err(), "the error must be reported");
    // Crucially the storage is still returned, not stranded.
    assert_eq!(buf.stable_ptr(), addr);
    comp.sync();
}

#[test]
fn tickets_survive_being_moved_to_another_thread() {
    let ring = crate::IoUring::new(8).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let mut buf = MmapBuffer::with_capacity(32).expect("map");
    buf.as_mut_slice()[..4].copy_from_slice(b"nyaa");
    let ticket = sub
        .push(Prepared::write(RawFd::from_raw(1), buf, 0).with_len(4))
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit().expect("submit");

    // The ticket and the completer both move off this thread.
    let handle = std::thread::spawn(move || {
        let receipt = comp.wait_one().expect("completion");
        let done = ticket
            .redeem(receipt)
            .unwrap_or_else(|_| panic!("matching receipt"));
        comp.sync();
        done.into_parts()
    });

    let (result, buf) = handle.join().expect("completion thread");
    assert_eq!(result.expect("write ok"), 4);
    assert_eq!(&buf.as_slice()[..4], b"nyaa");
}

#[test]
fn ring_id_is_copy_and_comparable() {
    let a = RingId::next();
    let b = a;
    assert_eq!(a, b);
}
