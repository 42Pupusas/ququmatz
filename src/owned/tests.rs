//! Behavioural tests for the owned-request lifecycle.

extern crate std;

use super::{
    Completed, Delivery, Direction, Event, MmapBuffer, Pending, PendingZc, Prepared,
    PreparedMultishot, PreparedZc, Receipt, RingId, StableBuffer, ZcCompleted,
};
use crate::error::{Error, SubmitError};
use crate::types::{MsgFlags, RawFd};

/// Static proof that a ticket crosses a thread boundary. The whole design
/// exists to make this true.
const fn assert_send<T: Send>() {}
const _: () = assert_send::<Pending<MmapBuffer>>();
const _: () = assert_send::<Completed<MmapBuffer>>();
const _: () = assert_send::<Prepared<MmapBuffer>>();
const _: () = assert_send::<Receipt>();
const _: () = assert_send::<MmapBuffer>();
const _: () = assert_send::<PendingZc<MmapBuffer>>();
const _: () = assert_send::<PreparedZc<MmapBuffer>>();
const _: () = assert_send::<ZcCompleted<MmapBuffer>>();

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

/// A connected TCP pair on loopback, for exercising real socket ops.
///
/// The client is an `Option` so a test can close it early to signal EOF
/// without the destructor closing the same fd twice.
struct SocketPair {
    client: Option<RawFd>,
    server: RawFd,
    listener: RawFd,
}

impl SocketPair {
    fn connected() -> Self {
        use crate::syscall;
        use crate::types::{self, SockAddrIn};

        let listener = syscall::socket(types::AF_INET, types::SOCK_STREAM, 0).expect("listener");
        let one: i32 = 1;
        syscall::setsockopt(
            listener,
            1,
            2,
            (&raw const one).cast(),
            core::mem::size_of::<i32>() as u32,
        )
        .expect("setsockopt");

        let addr = SockAddrIn {
            sin_family: types::AF_INET as u16,
            sin_port: 0u16.to_be(),
            sin_addr: u32::from_ne_bytes([127, 0, 0, 1]),
            sin_zero: [0; 8],
        };
        syscall::bind(
            listener,
            (&raw const addr).cast(),
            core::mem::size_of::<SockAddrIn>() as u32,
        )
        .expect("bind");
        syscall::listen(listener, 1).expect("listen");

        let mut bound = SockAddrIn::default();
        let mut len = core::mem::size_of::<SockAddrIn>() as u32;
        syscall::getsockname(listener, (&raw mut bound).cast(), &raw mut len).expect("getsockname");

        let client = syscall::socket(types::AF_INET, types::SOCK_STREAM, 0).expect("client");
        syscall::connect(
            client,
            (&raw const bound).cast(),
            core::mem::size_of::<SockAddrIn>() as u32,
        )
        .expect("connect");

        let mut peer = SockAddrIn::default();
        let mut peer_len = core::mem::size_of::<SockAddrIn>() as u32;
        let server = syscall::accept4(listener, (&raw mut peer).cast(), &raw mut peer_len, 0)
            .expect("accept");

        Self {
            client: Some(client),
            server,
            listener,
        }
    }

    /// The client fd, which is open unless a test closed it early.
    fn client(&self) -> RawFd {
        self.client.expect("client still open")
    }

    fn read_server(&self, out: &mut [u8]) -> usize {
        crate::syscall::read(self.server, out.as_mut_ptr(), out.len()).expect("read")
    }

    fn write_client(&self, bytes: &[u8]) -> usize {
        crate::syscall::write(self.client(), bytes.as_ptr(), bytes.len()).expect("write")
    }

    /// Close the client so the server sees EOF, ending a multishot.
    fn close_client(&mut self) {
        if let Some(fd) = self.client.take() {
            let _ = crate::syscall::close(fd);
        }
    }
}

impl Drop for SocketPair {
    fn drop(&mut self) {
        self.close_client();
        let _ = crate::syscall::close(self.server);
        let _ = crate::syscall::close(self.listener);
    }
}

#[test]
fn a_real_zero_copy_send_releases_its_buffer_only_on_the_terminal_cqe() {
    let pair = SocketPair::connected();
    let ring = crate::IoUring::new(8).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let msg = b"zero copy through the owned api";
    let mut buf = MmapBuffer::with_capacity(msg.len()).expect("map");
    buf.as_mut_slice().copy_from_slice(msg);
    let addr = buf.stable_ptr();

    let mut ticket = sub
        .push_zc(PreparedZc::send(pair.client(), buf, MsgFlags::NOSIGNAL))
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit().expect("submit");

    // Drive completions until a terminal one arrives. Whether the kernel
    // posts one CQE or two is its choice, not ours: `reap_event` reports
    // what actually happened and the loop ends either way.
    let done: ZcCompleted<MmapBuffer> = 'outer: loop {
        comp.wait(1).expect("wait");
        while let Some(event) = comp.reap_event() {
            match event {
                Event::Partial(notice) => {
                    ticket = ticket
                        .record_sent(notice)
                        .unwrap_or_else(|_| panic!("notice for our request"));
                }
                Event::Complete(receipt) => {
                    break 'outer ticket
                        .redeem(receipt)
                        .unwrap_or_else(|_| panic!("matching receipt"));
                }
            }
        }
        comp.sync();
    };
    comp.sync();

    // Deliberately not asserting that a notification arrived: whether the
    // kernel maps or falls back to copying is its decision, and both are
    // correct. The Miri tests pin each path deterministically.
    let (result, buf) = done.into_parts();
    assert_eq!(result.expect("send ok") as usize, msg.len());
    // The storage came back, at the address the kernel was given.
    assert_eq!(buf.stable_ptr(), addr);

    let mut seen = [0u8; 64];
    let n = pair.read_server(&mut seen[..msg.len()]);
    assert_eq!(&seen[..n], msg, "the peer received the bytes");
}

#[test]
fn a_real_multishot_recv_delivers_many_arrivals_from_one_submission() {
    let mut pair = SocketPair::connected();
    let mut ring = crate::IoUring::new(16).expect("ring");
    let pool = ring
        .register_provided_buffers(7, 8, 64)
        .expect("register pool");
    let mut pool = pool.split();
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let ticket = sub
        .push_multishot(PreparedMultishot::recv(
            pair.server,
            pool.bgid(),
            MsgFlags::default(),
        ))
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit().expect("submit");

    // Three separate writes, so one armed request must yield three CQEs.
    let sent: [&[u8]; 3] = [b"first", b"second", b"third"];
    for msg in sent {
        assert_eq!(pair.write_client(msg), msg.len());
    }

    let mut received: std::vec::Vec<std::vec::Vec<u8>> = std::vec::Vec::new();
    let mut ids_seen: std::vec::Vec<u16> = std::vec::Vec::new();
    while received.len() < sent.len() {
        comp.wait(1).expect("wait");
        while let Some(event) = comp.reap_event() {
            match ticket.record(event, &mut pool).expect("our request") {
                Delivery::Data(arrival) => {
                    ids_seen.push(arrival.buffer_id());
                    received.push(arrival.bytes().to_vec());
                    // `arrival` drops here, recycling its slot.
                }
                Delivery::Empty(res) => panic!("unexpected empty delivery: {res}"),
                Delivery::Done(fin) => panic!("ended early: {:?}", fin.result()),
            }
        }
        comp.sync();
    }

    let joined: std::vec::Vec<u8> = received.concat();
    let expected: std::vec::Vec<u8> = sent.concat();
    assert_eq!(
        joined, expected,
        "one armed request delivered every write in order"
    );
    assert_eq!(
        ids_seen.len(),
        sent.len(),
        "each arrival carried a pool buffer id"
    );

    // Closing the peer ends the multishot; the terminal CQE must be
    // reported as such rather than looking like another arrival.
    pair.close_client();
    let finished = 'outer: loop {
        comp.wait(1).expect("wait");
        while let Some(event) = comp.reap_event() {
            match ticket.record(event, &mut pool).expect("our request") {
                Delivery::Done(fin) => break 'outer fin,
                Delivery::Data(arrival) => {
                    // EOF may arrive as a zero-length arrival first.
                    assert!(arrival.is_empty(), "unexpected data after close");
                }
                Delivery::Empty(_) => {}
            }
        }
        comp.sync();
    };
    comp.sync();
    assert!(
        !Delivery::Done(finished).armed().is_armed(),
        "a finished multishot is not armed"
    );
}

#[test]
fn recycling_returns_slots_so_a_small_pool_outlasts_more_arrivals_than_it_holds() {
    // Two buffers, six messages: this can only pass if each `Arrival`
    // returned its slot on drop. Verified by `mem::forget`ing the arrival,
    // which ends the multishot at round 2 with ENOBUFS (errno 105).
    let pair = SocketPair::connected();
    let mut ring = crate::IoUring::new(16).expect("ring");
    let pool = ring
        .register_provided_buffers(11, 2, 64)
        .expect("register pool");
    let mut pool = pool.split();
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let ticket = sub
        .push_multishot(PreparedMultishot::recv(
            pair.server,
            pool.bgid(),
            MsgFlags::default(),
        ))
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit().expect("submit");

    let mut total = 0usize;
    for round in 0..6u8 {
        let msg = [b'a' + round; 4];
        pair.write_client(&msg);

        loop {
            comp.wait(1).expect("wait");
            let Some(event) = comp.reap_event() else {
                comp.sync();
                continue;
            };
            match ticket.record(event, &mut pool).expect("our request") {
                Delivery::Data(arrival) => {
                    assert_eq!(arrival.bytes(), &msg[..]);
                    total += arrival.bytes().len();
                    // `arrival` drops here, returning its slot to the pool.
                    break;
                }
                Delivery::Empty(res) => panic!("empty delivery: {res}"),
                Delivery::Done(fin) => {
                    panic!("multishot ended at round {round}: {:?}", fin.result())
                }
            }
        }
        comp.sync();
    }

    assert_eq!(
        total, 24,
        "a two-buffer pool carried six four-byte messages"
    );
}

#[test]
fn a_multishot_rejects_a_completion_belonging_to_another_request() {
    let pair = SocketPair::connected();
    let mut ring = crate::IoUring::new(8).expect("ring");
    let pool = ring
        .register_provided_buffers(13, 4, 32)
        .expect("register pool");
    let mut pool = pool.split();
    let (mut sub, _comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let first = sub
        .push_multishot(PreparedMultishot::recv(
            pair.server,
            pool.bgid(),
            MsgFlags::default(),
        ))
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    let second = sub
        .push_multishot(PreparedMultishot::recv(
            pair.server,
            pool.bgid(),
            MsgFlags::default(),
        ))
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    assert_ne!(first.id().raw(), second.id().raw());

    // A completion naming the second request must not be accepted by the
    // first, or one stream's bytes would be read as another's.
    // Built from the private fields, which only in-crate code can reach —
    // `tests/ui/partial_receipt_cannot_be_forged.rs` pins that safe callers
    // outside the crate cannot do this.
    let foreign = Event::Partial(super::event::PartialReceipt {
        ring: second.ring(),
        id: second.id(),
        result: 4,
        flags: crate::types::CqeFlags::MORE,
    });
    assert!(!first.matches(&foreign));
    assert!(first.record(foreign, &mut pool).is_err());
}

#[test]
fn a_zero_copy_push_that_does_not_fit_hands_the_buffer_back() {
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, _comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let mut held = std::vec::Vec::new();
    loop {
        let buf = MmapBuffer::with_capacity(8).expect("map");
        let addr = buf.stable_ptr();
        match sub.push_zc(PreparedZc::send(
            RawFd::from_raw(1),
            buf,
            MsgFlags::default(),
        )) {
            Ok(ticket) => held.push(ticket),
            Err((returned, e)) => {
                assert!(matches!(e, Error::Submit(SubmitError::QueueFull)));
                // The rejected request still owns its buffer, unmoved.
                assert_eq!(returned.buffer().stable_ptr(), addr);
                break;
            }
        }
    }
    core::mem::forget(held);
}

#[test]
fn ring_id_is_copy_and_comparable() {
    let a = RingId::next();
    let b = a;
    assert_eq!(a, b);
}
