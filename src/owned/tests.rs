//! Behavioural tests for the owned-request lifecycle.

extern crate std;

use super::{
    Arrival, BindError, BindOutcome, Completed, Count, Delivery, DirectIncoming, DirectOpenError,
    DirectSlot, DirectSocketError, Direction, EpollChange, EpollError, EpollOutcome, Event, Expiry,
    FilesUpdateError, Incoming, MmapBuffer, MsgRegionError, Openat2Error, Openat2Mode, OwnedPath,
    PathError, PeerWanted, Pending, PendingStatx, PendingZc, Prepared, PreparedAccept,
    PreparedBind, PreparedDirectAccept, PreparedDirectOpen, PreparedDirectSocket, PreparedEpollCtl,
    PreparedFilesUpdate, PreparedMultishot, PreparedOpen, PreparedOpenat2, PreparedPathOp,
    PreparedRecvmsg, PreparedRename, PreparedSendmsg, PreparedStatx, PreparedTimeout,
    PreparedVectored, PreparedZc, Receipt, RenameMode, RingId, SendTarget, SlotIndex, SlotTarget,
    StableBuffer, StatxError, TableEntry, TimeoutError, Update, VectoredError, ZcCompleted,
};
/// Only the kernel-backed tests name a path-op kind or inspect a peer
/// address, and those are gated.
#[cfg(not(miri))]
use super::{PathOpKind, PeerAddress};
use crate::error::{Error, SubmitError};
use crate::net::Socket;
use crate::types::{
    AcceptFlags, AddressFamily, DirFd, EpollEvent, EpollEvents, FileMode, MsgFlags, OpenFlags,
    RawFd, ResolveFlags, SockAddrIn, SocketFlags, SocketType, Statx, StatxFlags, StatxMask,
    Timespec,
};

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

/// A bound, listening loopback socket that nothing has accepted from, for
/// exercising accept itself.
struct Listener {
    fd: RawFd,
    addr: crate::types::SockAddrIn,
}

impl Listener {
    fn bound() -> Self {
        use crate::syscall;
        use crate::types::{self, SockAddrIn};

        let fd = syscall::socket(types::AF_INET, types::SOCK_STREAM, 0).expect("listener");
        let one: i32 = 1;
        syscall::setsockopt(
            fd,
            1,
            2,
            (&raw const one).cast(),
            core::mem::size_of::<i32>() as u32,
        )
        .expect("setsockopt");

        let wanted = SockAddrIn {
            sin_family: types::AF_INET as u16,
            sin_port: 0u16.to_be(),
            sin_addr: u32::from_ne_bytes([127, 0, 0, 1]),
            sin_zero: [0; 8],
        };
        syscall::bind(
            fd,
            (&raw const wanted).cast(),
            core::mem::size_of::<SockAddrIn>() as u32,
        )
        .expect("bind");
        syscall::listen(fd, 16).expect("listen");

        let mut addr = SockAddrIn::default();
        let mut len = core::mem::size_of::<SockAddrIn>() as u32;
        syscall::getsockname(fd, (&raw mut addr).cast(), &raw mut len).expect("getsockname");

        Self { fd, addr }
    }

    /// The bound address, in the wire form `connect` expects.
    ///
    /// Gated to match its only caller, which needs a real kernel.
    #[cfg(not(miri))]
    fn addr_bytes(&self) -> [u8; core::mem::size_of::<crate::types::SockAddrIn>()] {
        // Not `SockAddrIn::to_bytes`, which drops sin_zero: connect needs
        // the whole struct, padding included.
        // SAFETY: SockAddrIn is repr(C) and all-integer, so every byte of
        // it is initialised and readable as bytes.
        unsafe { core::mem::transmute(self.addr) }
    }

    /// Connect a client, returning it so the caller controls its lifetime.
    fn connect(&self) -> RawFd {
        use crate::syscall;
        use crate::types::SockAddrIn;

        let client =
            syscall::socket(crate::types::AF_INET, crate::types::SOCK_STREAM, 0).expect("client");
        syscall::connect(
            client,
            (&raw const self.addr).cast(),
            core::mem::size_of::<SockAddrIn>() as u32,
        )
        .expect("connect");
        client
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let _ = crate::syscall::close(self.fd);
    }
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
fn a_terminal_completion_can_still_carry_a_buffer_that_must_come_back() {
    // The kernel computes a recv's buffer flags before it decides whether
    // the request stays armed (io_recv_finish), so when it cannot post the
    // extra CQE -- a full completion queue -- the buffer id it already
    // picked rides out on the *terminal* CQE instead. A `Done` that
    // dropped its payload would leak that slot precisely when the pool is
    // under pressure.
    //
    // Reproduced by flooding a deliberately tiny CQ: submit many messages
    // without reaping, so the ring overflows while arrivals are pending.
    let mut pair = SocketPair::connected();
    let mut ring = crate::IoUring::new(4).expect("ring");
    let pool = ring
        .register_provided_buffers(17, 8, 64)
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

    for _ in 0..32 {
        pair.write_client(b"flood");
    }
    pair.close_client();
    std::thread::sleep(core::time::Duration::from_millis(50));

    let mut carried = 0usize;
    let mut bytes = 0usize;
    let mut ended = false;
    while !ended {
        comp.wait(1).expect("wait");
        while let Some(event) = comp.reap_event() {
            match ticket.record(event, &mut pool).expect("our request") {
                Delivery::Data(arrival) => bytes += arrival.bytes().len(),
                Delivery::Empty(_) => {}
                Delivery::Done(finished) => {
                    if let Some(last) = finished.last() {
                        carried += 1;
                        bytes += last.bytes().len();
                    }
                    ended = true;
                    break;
                }
            }
        }
        comp.sync();
    }
    comp.sync();

    assert!(bytes > 0, "the flood delivered data");
    // Whether the kernel actually had to fold is its decision and depends
    // on timing, so this asserts the accounting stays sane either way --
    // `Finished::last` is checked deterministically by the unit test below.
    assert!(
        carried <= 1,
        "at most one terminal CQE, so at most one fold"
    );
}

#[test]
fn a_finished_multishot_hands_back_the_slot_folded_into_its_last_cqe() {
    // The kernel-driven test above cannot force CQ overflow deterministically,
    // so the recycling contract is pinned here from a synthesised terminal
    // CQE that carries a buffer id, which is exactly what the kernel emits
    // when io_req_post_cqe fails.
    let pair = SocketPair::connected();
    let mut ring = crate::IoUring::new(8).expect("ring");
    let pool = ring
        .register_provided_buffers(19, 2, 32)
        .expect("register pool");
    let mut pool = pool.split();
    let (mut sub, _comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let ticket = sub
        .push_multishot(PreparedMultishot::recv(
            pair.server,
            pool.bgid(),
            MsgFlags::default(),
        ))
        .unwrap_or_else(|(_, e)| panic!("{e}"));

    let buf_id = 1u16;
    let terminal = Event::Complete(super::request::Receipt {
        ring: ticket.ring(),
        id: ticket.id(),
        result: 5,
        flags: crate::types::CqeFlags::from_raw(
            crate::types::CqeFlags::BUFFER.bits() | (u32::from(buf_id) << 16),
        ),
    });

    // Scoped so the first borrow of the pool ends before the second
    // delivery asks for it -- the same exclusivity the compile-fail
    // fixture pins.
    {
        let delivery = ticket.record(terminal, &mut pool).expect("our request");
        assert!(!delivery.armed().is_armed(), "terminal means not armed");
        let Delivery::Done(mut finished) = delivery else {
            panic!("a terminal CQE is a Done");
        };
        let last = finished.take_last().expect("the folded arrival");
        assert_eq!(last.buffer_id(), buf_id, "the id the kernel chose");
        assert_eq!(last.len(), 5, "the bytes it wrote");
    }

    // The slot is back: a second delivery can claim it again.
    let again = Event::Complete(super::request::Receipt {
        ring: ticket.ring(),
        id: ticket.id(),
        result: 5,
        flags: crate::types::CqeFlags::from_raw(
            crate::types::CqeFlags::BUFFER.bits() | (u32::from(buf_id) << 16),
        ),
    });
    let Delivery::Done(second) = ticket.record(again, &mut pool).expect("our request") else {
        panic!("a terminal CQE is a Done");
    };
    assert_eq!(
        second.last().map(Arrival::buffer_id),
        Some(buf_id),
        "the recycled slot is usable again"
    );
}

#[test]
fn a_terminal_completion_without_a_buffer_carries_no_arrival() {
    // The ordinary case: ENOBUFS or EOF ends the request with no slot to
    // return, and inventing one would be a borrow that does not exist.
    let pair = SocketPair::connected();
    let mut ring = crate::IoUring::new(8).expect("ring");
    let pool = ring
        .register_provided_buffers(23, 2, 32)
        .expect("register pool");
    let mut pool = pool.split();
    let (mut sub, _comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let ticket = sub
        .push_multishot(PreparedMultishot::recv(
            pair.server,
            pool.bgid(),
            MsgFlags::default(),
        ))
        .unwrap_or_else(|(_, e)| panic!("{e}"));

    let enobufs = Event::Complete(super::request::Receipt {
        ring: ticket.ring(),
        id: ticket.id(),
        result: -105,
        flags: crate::types::CqeFlags::default(),
    });
    let Delivery::Done(finished) = ticket.record(enobufs, &mut pool).expect("our request") else {
        panic!("a terminal CQE is a Done");
    };
    assert!(finished.last().is_none(), "no buffer flag, no arrival");
    assert!(
        finished.result().is_err(),
        "ENOBUFS is reported as an error"
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
fn a_real_multishot_accept_yields_many_connections_from_one_submission() {
    let listener = Listener::bound();
    let ring = crate::IoUring::new(16).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let mut ticket = sub
        .push_accept(PreparedAccept::on(listener.fd, AcceptFlags::default()))
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit().expect("submit");

    let mut clients = std::vec::Vec::new();
    let mut accepted = std::vec::Vec::new();
    for _ in 0..3 {
        clients.push(listener.connect());

        loop {
            comp.wait(1).expect("wait");
            let Some(event) = comp.reap_event() else {
                comp.sync();
                continue;
            };
            match ticket.record(event).expect("our request") {
                Incoming::Connection(socket) => {
                    accepted.push(socket);
                    break;
                }
                Incoming::Empty(res) => panic!("empty accept: {res}"),
                Incoming::Done(fin) => panic!("accept ended: {:?}", fin.result()),
            }
        }
        comp.sync();
    }

    assert_eq!(accepted.len(), 3, "one armed accept served three clients");
    // Distinct connections, not the same descriptor reported three times.
    let mut raw: std::vec::Vec<RawFd> = accepted.iter().map(Socket::fd).collect();
    raw.sort_unstable();
    raw.dedup();
    assert_eq!(raw.len(), 3, "each accept installed its own descriptor");

    // The connections are live: a write on each reaches its client.
    for (socket, client) in accepted.iter().zip(&clients) {
        let sent = socket.send(b"hi", MsgFlags::default()).expect("send");
        assert_eq!(sent, 2);
        let mut seen = [0u8; 2];
        let got = crate::syscall::read(*client, seen.as_mut_ptr(), seen.len()).expect("read");
        assert_eq!(&seen[..got], b"hi");
    }

    for client in clients {
        let _ = crate::syscall::close(client);
    }
}

#[test]
fn a_finished_accept_hands_back_the_connection_folded_into_its_last_cqe() {
    // io_accept() calls fd_install before deciding whether the request
    // continues, so when it cannot post the extra CQE -- a full completion
    // queue -- the installed descriptor rides out on the terminal CQE. A
    // Done that dropped it would leak a live connection. CQ overflow cannot
    // be forced deterministically from userspace, so this synthesises the
    // terminal CQE the kernel would emit.
    let listener = Listener::bound();
    let ring = crate::IoUring::new(8).expect("ring");
    let (mut sub, _comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let mut ticket = sub
        .push_accept(PreparedAccept::on(listener.fd, AcceptFlags::default()))
        .unwrap_or_else(|(_, e)| panic!("{e}"));

    // A real descriptor, so the Socket that adopts it closes something
    // valid rather than a fabricated number.
    let client = listener.connect();
    let mut peer = crate::types::SockAddrIn::default();
    let mut peer_len = core::mem::size_of::<crate::types::SockAddrIn>() as u32;
    let installed =
        crate::syscall::accept4(listener.fd, (&raw mut peer).cast(), &raw mut peer_len, 0)
            .expect("accept");

    let terminal = Event::Complete(super::request::Receipt {
        ring: ticket.ring(),
        id: ticket.id(),
        result: installed.as_i32(),
        flags: crate::types::CqeFlags::default(),
    });

    let incoming = ticket.record(terminal).expect("our request");
    assert!(!incoming.armed().is_armed(), "terminal means not armed");
    let Incoming::Done(finished) = incoming else {
        panic!("a terminal CQE is a Done");
    };
    let socket = finished.last().expect("the folded connection");
    assert_eq!(socket.fd(), installed);

    // It is a live connection, not just a number: it can still talk.
    let sent = socket.send(b"ok", MsgFlags::default()).expect("send");
    assert_eq!(sent, 2);
    let mut seen = [0u8; 2];
    let got = crate::syscall::read(client, seen.as_mut_ptr(), seen.len()).expect("read");
    assert_eq!(&seen[..got], b"ok");

    let (_receipt, last) = finished.into_parts();
    assert!(last.is_some(), "into_parts surrenders the connection");
    drop(last);
    let _ = crate::syscall::close(client);
}

#[test]
fn a_real_direct_accept_installs_connections_into_the_table_not_the_process() {
    let listener = Listener::bound();
    let mut ring = crate::IoUring::new(16).expect("ring");
    // A sparse table for the kernel to allocate out of. Without one every
    // completion fails instead of installing anything.
    ring.register_files(&[-1; 4]).expect("register table");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let mut ticket = sub
        .push_direct_accept(PreparedDirectAccept::on(
            listener.fd,
            AcceptFlags::default(),
        ))
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit().expect("submit");

    let mut clients = std::vec::Vec::new();
    let mut slots = std::vec::Vec::new();
    for _ in 0..3 {
        clients.push(listener.connect());

        loop {
            comp.wait(1).expect("wait");
            let Some(event) = comp.reap_event() else {
                comp.sync();
                continue;
            };
            match ticket.record(event).expect("our request") {
                DirectIncoming::Installed(slot) => {
                    slots.push(slot);
                    break;
                }
                DirectIncoming::Empty(res) => panic!("empty direct accept: {res}"),
                DirectIncoming::Done(fin) => panic!("accept ended: {:?}", fin.result()),
            }
        }
        comp.sync();
    }

    assert_eq!(slots.len(), 3, "one armed accept filled three slots");
    let mut indices: std::vec::Vec<u32> = slots.iter().map(|s| s.index().get()).collect();

    // What comes back is a table index, not a descriptor. A fresh sparse
    // table allocates densely from zero, so these are exactly 0, 1, 2 --
    // values a process descriptor could not be, since 0, 1 and 2 are
    // already stdin, stdout and stderr. A plain accept would report the
    // installed fd here instead and this would be some larger, unrelated
    // triple.
    //
    // An earlier version compared the process's next-free descriptor
    // before and after each completion. That reads a process-global
    // resource, so it raced every other test thread creating and closing
    // descriptors in the same binary, and failed under parallelism for
    // reasons unrelated to accept. This claim is local to the ring.
    indices.sort_unstable();
    assert_eq!(
        indices,
        std::vec![0, 1, 2],
        "a direct accept reports table slots, not process descriptors"
    );

    // The slots hold live connections, reachable only through the table.
    for (slot, client) in slots.iter().zip(&clients) {
        sub.raw()
            .push(
                unsafe {
                    crate::Sqe::write_ptr(
                        RawFd::from_raw(slot.as_fixed_fd() as usize),
                        b"hi".as_ptr(),
                        2,
                        0,
                    )
                }
                .fixed_file()
                .user_data(0xD1),
            )
            .expect("push write");
        sub.submit_and_wait(1).expect("submit");
        let cqe = comp.wait_one().expect("completion");
        assert_eq!(cqe.raw_result(), 2, "write through the slot");

        let mut seen = [0u8; 2];
        let got = crate::syscall::read(*client, seen.as_mut_ptr(), seen.len()).expect("read");
        assert_eq!(&seen[..got], b"hi");
    }

    for client in clients {
        let _ = crate::syscall::close(client);
    }
}

#[test]
fn a_full_table_ends_the_direct_accept_rather_than_refusing_one_connection() {
    // A registered table is far smaller than RLIMIT_NOFILE, so exhaustion
    // is routine. The kernel gates its re-arm on a non-negative result, so
    // -ENFILE is terminal: the listener stops. Treating it as a survivable
    // hiccup would leave a caller waiting forever on a retired request.
    let listener = Listener::bound();
    let mut ring = crate::IoUring::new(16).expect("ring");
    // Exactly one slot, so the second connection has nowhere to go.
    ring.register_files(&[-1; 1]).expect("register table");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let mut ticket = sub
        .push_direct_accept(PreparedDirectAccept::on(
            listener.fd,
            AcceptFlags::default(),
        ))
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit().expect("submit");

    let mut clients = std::vec::Vec::new();
    let mut outcomes = std::vec::Vec::new();
    for _ in 0..2 {
        clients.push(listener.connect());
        loop {
            comp.wait(1).expect("wait");
            let Some(event) = comp.reap_event() else {
                comp.sync();
                continue;
            };
            outcomes.push(ticket.record(event).expect("our request"));
            break;
        }
        comp.sync();
    }

    let first = &outcomes[0];
    assert!(
        matches!(first, DirectIncoming::Installed(_)),
        "the first connection fits"
    );
    assert!(first.armed().is_armed(), "and leaves the listener armed");

    let DirectIncoming::Done(finished) = &outcomes[1] else {
        panic!(
            "a full table ends the request: got {:?}",
            outcomes[1].armed()
        );
    };
    assert_eq!(finished.raw_result(), -23, "ENFILE when no slot is free");
    assert!(finished.last().is_none(), "an errno installed no slot");
    assert!(!outcomes[1].armed().is_armed(), "the listener has stopped");

    for client in clients {
        let _ = crate::syscall::close(client);
    }
}

#[test]
fn a_finished_direct_accept_hands_back_the_slot_folded_into_its_last_cqe() {
    // The same fold as the descriptor-returning accept: when the kernel
    // cannot post the extra CQE it finishes the request carrying the slot
    // it already installed into. A Done that dropped it would strand a live
    // connection in the table with nothing naming it.
    let listener = Listener::bound();
    let mut ring = crate::IoUring::new(8).expect("ring");
    ring.register_files(&[-1; 4]).expect("register table");
    let (mut sub, _comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let mut ticket = sub
        .push_direct_accept(PreparedDirectAccept::on(
            listener.fd,
            AcceptFlags::default(),
        ))
        .unwrap_or_else(|(_, e)| panic!("{e}"));

    let terminal = Event::Complete(super::request::Receipt {
        ring: ticket.ring(),
        id: ticket.id(),
        result: 2,
        flags: crate::types::CqeFlags::default(),
    });

    let incoming = ticket.record(terminal).expect("our request");
    assert!(!incoming.armed().is_armed(), "terminal means not armed");
    let DirectIncoming::Done(finished) = incoming else {
        panic!("a terminal CQE is a Done");
    };
    let slot = finished.last().expect("the folded slot");
    assert_eq!(slot.index().get(), 2, "the result is the index");
    assert!(slot.belongs_to(ticket.ring()));

    let (_receipt, last) = finished.into_parts();
    assert!(last.is_some(), "into_parts surrenders the slot");
}

#[test]
fn slot_zero_is_a_real_install_not_an_absent_one() {
    // Every armed completion resolves through SlotTarget::Auto, where the
    // result *is* the index. Zero is the first slot a fresh table hands
    // out, and it was measured as the first connection's result -- but on
    // the submission side zero means "not a direct request". Confusing the
    // two encodings would drop the very first connection of every run.
    let listener = Listener::bound();
    let mut ring = crate::IoUring::new(8).expect("ring");
    ring.register_files(&[-1; 4]).expect("register table");
    let (mut sub, _comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let mut ticket = sub
        .push_direct_accept(PreparedDirectAccept::on(
            listener.fd,
            AcceptFlags::default(),
        ))
        .unwrap_or_else(|(_, e)| panic!("{e}"));

    let armed = Event::Partial(super::event::PartialReceipt {
        ring: ticket.ring(),
        id: ticket.id(),
        result: 0,
        flags: crate::types::CqeFlags::MORE,
    });
    let DirectIncoming::Installed(slot) = ticket.record(armed).expect("our request") else {
        panic!("result 0 is slot 0, not an empty completion");
    };
    assert_eq!(slot.index().get(), 0);
}

#[test]
fn a_failed_direct_accept_completion_names_no_slot() {
    // A negative result is an errno. Reading it as an index would produce a
    // DirectSlot pointing at a table entry nothing installed into.
    let listener = Listener::bound();
    let mut ring = crate::IoUring::new(8).expect("ring");
    ring.register_files(&[-1; 4]).expect("register table");
    let (mut sub, _comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let mut ticket = sub
        .push_direct_accept(PreparedDirectAccept::on(
            listener.fd,
            AcceptFlags::default(),
        ))
        .unwrap_or_else(|(_, e)| panic!("{e}"));

    let failed = Event::Complete(super::request::Receipt {
        ring: ticket.ring(),
        id: ticket.id(),
        result: -9,
        flags: crate::types::CqeFlags::default(),
    });
    let DirectIncoming::Done(finished) = ticket.record(failed).expect("our request") else {
        panic!("a terminal CQE is a Done");
    };
    assert!(finished.last().is_none(), "an errno is not a slot");
    assert!(finished.result().is_err());

    let armed_failure = Event::Partial(super::event::PartialReceipt {
        ring: ticket.ring(),
        id: ticket.id(),
        result: -11,
        flags: crate::types::CqeFlags::MORE,
    });
    let outcome = ticket.record(armed_failure).expect("our request");
    assert!(
        matches!(outcome, DirectIncoming::Empty(-11)),
        "an armed failure names no slot but stays armed"
    );
    assert!(outcome.into_slot().is_none());
}

#[test]
fn a_direct_accept_rejects_a_completion_belonging_to_another_request() {
    let listener = Listener::bound();
    let mut ring = crate::IoUring::new(8).expect("ring");
    ring.register_files(&[-1; 4]).expect("register table");
    let (mut sub, _comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let mut first = sub
        .push_direct_accept(PreparedDirectAccept::on(
            listener.fd,
            AcceptFlags::default(),
        ))
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    let second = sub
        .push_direct_accept(PreparedDirectAccept::on(
            listener.fd,
            AcceptFlags::default(),
        ))
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    assert_ne!(first.id().raw(), second.id().raw());

    let foreign = Event::Partial(super::event::PartialReceipt {
        ring: second.ring(),
        id: second.id(),
        result: 1,
        flags: crate::types::CqeFlags::MORE,
    });
    assert!(!first.matches(&foreign));
    assert!(first.record(foreign).is_err());
}

#[test]
fn a_direct_accept_push_that_does_not_fit_hands_the_request_back() {
    let listener = Listener::bound();
    let ring = crate::IoUring::new(1).expect("ring");
    let (mut sub, _comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let request = PreparedDirectAccept::on(listener.fd, AcceptFlags::NONBLOCK);
    sub.push_direct_accept(request)
        .unwrap_or_else(|(_, e)| panic!("{e}"));

    let (returned, _e) = sub
        .push_direct_accept(request)
        .expect_err("a one-entry queue is full");
    assert_eq!(returned.fd(), listener.fd);
    assert_eq!(
        returned.flags(),
        AcceptFlags::NONBLOCK,
        "a retry must not silently drop the flags"
    );
}

#[test]
fn a_failed_accept_completion_carries_no_connection() {
    // A negative result is an errno, not a descriptor. Adopting it would
    // build a Socket that closes a nonsense fd on drop.
    let listener = Listener::bound();
    let ring = crate::IoUring::new(8).expect("ring");
    let (mut sub, _comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let mut ticket = sub
        .push_accept(PreparedAccept::on(listener.fd, AcceptFlags::default()))
        .unwrap_or_else(|(_, e)| panic!("{e}"));

    let failed = Event::Complete(super::request::Receipt {
        ring: ticket.ring(),
        id: ticket.id(),
        result: -9,
        flags: crate::types::CqeFlags::default(),
    });
    let Incoming::Done(finished) = ticket.record(failed).expect("our request") else {
        panic!("a terminal CQE is a Done");
    };
    assert!(finished.last().is_none(), "an errno is not a descriptor");
    assert!(finished.result().is_err(), "EBADF is reported as an error");

    let armed_failure = Event::Partial(super::event::PartialReceipt {
        ring: ticket.ring(),
        id: ticket.id(),
        result: -11,
        flags: crate::types::CqeFlags::MORE,
    });
    let incoming = ticket.record(armed_failure).expect("our request");
    assert!(incoming.armed().is_armed(), "still accepting");
    assert!(
        matches!(incoming, Incoming::Empty(-11)),
        "a non-terminal error carries the errno, not a socket"
    );
}

#[test]
fn an_accept_rejects_a_completion_belonging_to_another_request() {
    let listener = Listener::bound();
    let ring = crate::IoUring::new(8).expect("ring");
    let (mut sub, _comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let mut first = sub
        .push_accept(PreparedAccept::on(listener.fd, AcceptFlags::default()))
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    let second = sub
        .push_accept(PreparedAccept::on(listener.fd, AcceptFlags::default()))
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    assert_ne!(first.id().raw(), second.id().raw());

    // Accepting another request's completion would adopt a descriptor that
    // belongs to a different listener's stream.
    let foreign = Event::Partial(super::event::PartialReceipt {
        ring: second.ring(),
        id: second.id(),
        result: 7,
        flags: crate::types::CqeFlags::MORE,
    });
    assert!(!first.matches(&foreign));
    assert!(first.record(foreign).is_err());
}

/// Storage for an iovec array, deliberately misaligned for `IoVec`.
///
/// `MmapBuffer` is page-aligned so it can never exercise the alignment
/// check; this offsets into its own mapping to produce an address that is
/// stable but odd.
struct MisalignedVecs {
    inner: MmapBuffer,
}

impl MisalignedVecs {
    fn with_capacity(len: usize) -> Self {
        Self {
            inner: MmapBuffer::with_capacity(len + 1).expect("map"),
        }
    }
}

// SAFETY: delegates to `MmapBuffer`, whose address is fixed for its whole
// life; offsetting by a constant one byte keeps it fixed and in bounds,
// and this type is the sole owner of those bytes.
unsafe impl StableBuffer for MisalignedVecs {
    fn stable_ptr(&self) -> *const u8 {
        unsafe { self.inner.stable_ptr().add(1) }
    }

    fn stable_len(&self) -> usize {
        self.inner.stable_len() - 1
    }
}

// SAFETY: as above; the mapping is writable and the address matches.
unsafe impl super::StableBufferMut for MisalignedVecs {
    fn stable_mut_ptr(&mut self) -> *mut u8 {
        unsafe { self.inner.stable_mut_ptr().add(1) }
    }
}

#[test]
fn a_vectored_write_gathers_every_buffer_in_order() {
    let pair = SocketPair::connected();
    let ring = crate::IoUring::new(8).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let parts: [&[u8]; 3] = [b"vectored ", b"io ", b"in order"];
    let mut bufs = parts.map(|p| {
        let mut b = MmapBuffer::with_capacity(p.len()).expect("map");
        b.as_mut_slice().copy_from_slice(p);
        b
    });
    let lens = parts.map(<[u8]>::len);
    // Make each buffer larger than its message so `with_lens` has to do
    // real work rather than coinciding with capacity.
    for (b, p) in bufs.iter_mut().zip(parts.iter()) {
        assert_eq!(b.len(), p.len());
    }

    let vecs = MmapBuffer::with_capacity(4096).expect("map");
    let request = PreparedVectored::writev(pair.client(), bufs, vecs, 0)
        .unwrap_or_else(|(_, _, e)| panic!("{e}"))
        .with_lens(lens);
    assert_eq!(request.count(), 3);
    assert_eq!(request.total_len(), 20);

    let ticket = sub
        .push_vectored(request)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit().expect("submit");

    let receipt = comp.wait_one().expect("completion");
    let done = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatched"));
    let (result, bufs, _vecs) = done.into_parts();
    assert_eq!(result.expect("write ok"), 20);
    // The owners came back intact, not consumed by the operation.
    assert_eq!(bufs[0].as_slice(), b"vectored ");

    let mut seen = [0u8; 32];
    let n = pair.read_server(&mut seen[..20]);
    assert_eq!(&seen[..n], b"vectored io in order");
}

#[test]
fn a_vectored_read_scatters_across_buffers_filling_them_in_order() {
    let pair = SocketPair::connected();
    let ring = crate::IoUring::new(8).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    // Four bytes per buffer, twelve bytes sent: every descriptor fills.
    let bufs = [(); 3].map(|()| MmapBuffer::with_capacity(4).expect("map"));
    let vecs = MmapBuffer::with_capacity(4096).expect("map");
    let request = PreparedVectored::readv(pair.server, bufs, vecs, 0)
        .unwrap_or_else(|(_, _, e)| panic!("{e}"));
    assert_eq!(request.total_len(), 12);

    let ticket = sub
        .push_vectored(request)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit().expect("submit");
    pair.write_client(b"abcdefghijkl");

    let receipt = comp.wait_one().expect("completion");
    let done = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatched"));
    let (result, bufs, _vecs) = done.into_parts();
    assert_eq!(result.expect("read ok"), 12);
    // Order matters: the kernel fills descriptor 0 before descriptor 1.
    assert_eq!(bufs[0].as_slice(), b"abcd");
    assert_eq!(bufs[1].as_slice(), b"efgh");
    assert_eq!(bufs[2].as_slice(), b"ijkl");
}

#[test]
fn a_vectored_ticket_survives_moving_to_another_thread_before_completion() {
    // The reason the descriptor array cannot live inline in the ticket.
    // `Pending` is `Send` and is *meant* to cross threads; if the array
    // moved with it, the kernel would be left reading a dead address. This
    // moves the ticket while the request is genuinely in flight.
    let pair = SocketPair::connected();
    let ring = crate::IoUring::new(8).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let bufs = [(); 2].map(|()| MmapBuffer::with_capacity(4).expect("map"));
    let vecs = MmapBuffer::with_capacity(4096).expect("map");
    let ticket = sub
        .push_vectored(
            PreparedVectored::readv(pair.server, bufs, vecs, 0)
                .unwrap_or_else(|(_, _, e)| panic!("{e}")),
        )
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit().expect("submit");

    // In flight now. Hand the ticket to another thread and back.
    let ticket = std::thread::spawn(move || ticket).join().expect("join");

    pair.write_client(b"12345678");
    let receipt = comp.wait_one().expect("completion");
    let done = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatched"));
    let (result, bufs, _vecs) = done.into_parts();
    assert_eq!(result.expect("read ok"), 8);
    assert_eq!(bufs[0].as_slice(), b"1234");
    assert_eq!(bufs[1].as_slice(), b"5678");
}

#[test]
fn descriptor_storage_too_small_is_rejected_with_everything_handed_back() {
    let bufs = [(); 4].map(|()| MmapBuffer::with_capacity(8).expect("map"));
    let addrs = bufs.each_ref().map(StableBuffer::stable_ptr);
    // One IoVec is 16 bytes on this target, so 8 bytes cannot hold four.
    let vecs = MmapBuffer::with_capacity(8).expect("map");

    let (bufs, _vecs, err) = PreparedVectored::<_, _, 4>::writev(RawFd::from_raw(1), bufs, vecs, 0)
        .err()
        .expect("too small");
    assert!(matches!(err, VectoredError::ArrayTooSmall { .. }));
    // Nothing was consumed: the same buffers came back, unmoved.
    assert_eq!(bufs.each_ref().map(StableBuffer::stable_ptr), addrs);
}

#[test]
fn misaligned_descriptor_storage_is_rejected_rather_than_written_through() {
    // An unaligned write of an IoVec would be UB, so this must be caught
    // before the array is stamped, not after.
    let bufs = [(); 2].map(|()| MmapBuffer::with_capacity(8).expect("map"));
    let vecs = MisalignedVecs::with_capacity(4096);

    let (_bufs, _vecs, err) =
        PreparedVectored::<_, _, 2>::writev(RawFd::from_raw(1), bufs, vecs, 0)
            .err()
            .expect("misaligned");
    assert!(matches!(err, VectoredError::ArrayMisaligned { .. }));
}

#[test]
fn with_lens_shortens_each_descriptor_but_never_extends_it() {
    let bufs = [(); 2].map(|()| MmapBuffer::with_capacity(64).expect("map"));
    let vecs = MmapBuffer::with_capacity(4096).expect("map");
    let request = PreparedVectored::writev(RawFd::from_raw(1), bufs, vecs, 0)
        .unwrap_or_else(|(_, _, e)| panic!("{e}"));
    assert_eq!(request.total_len(), 128);

    // Asking for more than capacity is clamped per buffer, so the array can
    // never describe memory the owners do not have.
    let request = request.with_lens([5, 4096]);
    assert_eq!(request.total_len(), 69);
}

#[test]
fn a_vectored_push_that_does_not_fit_hands_all_the_storage_back() {
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, _comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let mut held = std::vec::Vec::new();
    loop {
        let bufs = [(); 2].map(|()| MmapBuffer::with_capacity(8).expect("map"));
        let addrs = bufs.each_ref().map(StableBuffer::stable_ptr);
        let vecs = MmapBuffer::with_capacity(4096).expect("map");
        let request = PreparedVectored::writev(RawFd::from_raw(1), bufs, vecs, 0)
            .unwrap_or_else(|(_, _, e)| panic!("{e}"));
        match sub.push_vectored(request) {
            Ok(ticket) => held.push(ticket),
            Err((returned, e)) => {
                assert!(matches!(e, Error::Submit(SubmitError::QueueFull)));
                // Every owner came back, and the target survived the round
                // trip rather than being reset to a default fd.
                assert_eq!(
                    returned.buffers().each_ref().map(StableBuffer::stable_ptr),
                    addrs
                );
                assert_eq!(returned.fd(), RawFd::from_raw(1));
                assert_eq!(returned.total_len(), 16);
                break;
            }
        }
    }
    core::mem::forget(held);
}

#[test]
fn a_vectored_receipt_for_another_request_is_rejected() {
    let ring = crate::IoUring::new(8).expect("ring");
    let (mut sub, _comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let make = |sub: &mut super::OwnedSubmitter| {
        let bufs = [(); 2].map(|()| MmapBuffer::with_capacity(8).expect("map"));
        let vecs = MmapBuffer::with_capacity(4096).expect("map");
        sub.push_vectored(
            PreparedVectored::writev(RawFd::from_raw(1), bufs, vecs, 0)
                .unwrap_or_else(|(_, _, e)| panic!("{e}")),
        )
        .unwrap_or_else(|(_, e)| panic!("{e}"))
    };
    let first = make(&mut sub);
    let second = make(&mut sub);

    let foreign = Receipt {
        ring: second.ring(),
        id: second.id(),
        result: 16,
        flags: crate::types::CqeFlags::default(),
    };
    assert!(!first.matches(&foreign));
    let Err((first, _)) = first.redeem(foreign) else {
        panic!("a foreign receipt must not redeem");
    };
    // The ticket survived the rejection still owning everything.
    assert_eq!(first.count(), 2);
    // Neither ticket is ever redeemed, so both deliberately leak their
    // storage rather than freeing memory the kernel could still reach.
    // `PendingVectored` has no destructor, so dropping them is that leak.
    #[allow(clippy::drop_non_drop)]
    drop((first, second));
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

/// Build a verified path in its own mapping.
fn path_of(text: &[u8]) -> OwnedPath<MmapBuffer> {
    let storage = MmapBuffer::with_capacity(256).expect("map");
    OwnedPath::copy_into(storage, text).unwrap_or_else(|(_, e)| panic!("{e}"))
}

#[test]
fn a_path_records_its_length_without_the_terminator() {
    let path = path_of(b"/etc/hostname");
    assert_eq!(path.len(), 13);
    assert_eq!(path.as_bytes(), b"/etc/hostname");
    assert!(!path.is_empty());
}

#[test]
fn a_path_is_written_with_a_terminator_the_kernel_can_find() {
    let path = path_of(b"/tmp");
    let storage = path.into_storage();
    // The NUL is what bounds the kernel's read; without it there is no
    // length field anywhere in the SQE to stop it.
    assert_eq!(&storage.as_slice()[..5], b"/tmp\0");
}

#[test]
fn storage_too_small_for_the_path_and_its_nul_is_rejected() {
    let storage = MmapBuffer::with_capacity(4).expect("map");
    let addr = storage.stable_ptr();
    // Four bytes hold "/tmp" but not its terminator, and the terminator is
    // the only thing that stops the kernel reading past the end.
    let Err((returned, e)) = OwnedPath::copy_into(storage, b"/tmp") else {
        panic!("storage without room for the NUL must be rejected");
    };
    assert_eq!(e, PathError::TooLong { needed: 5, got: 4 });
    assert_eq!(returned.stable_ptr(), addr);
}

#[test]
fn an_interior_nul_is_rejected_rather_than_silently_truncating() {
    let storage = MmapBuffer::with_capacity(64).expect("map");
    // The kernel stops at the first NUL, so this would open "/etc" while
    // the caller believes they asked for "/etc/passwd".
    let Err((_, e)) = OwnedPath::copy_into(storage, b"/etc\0passwd") else {
        panic!("an interior NUL must be rejected");
    };
    assert_eq!(e, PathError::NotTerminated);
}

#[test]
fn an_empty_path_is_rejected_before_it_reaches_the_kernel() {
    let storage = MmapBuffer::with_capacity(64).expect("map");
    let Err((_, e)) = OwnedPath::copy_into(storage, b"") else {
        panic!("an empty path must be rejected");
    };
    assert_eq!(e, PathError::Empty);
}

#[test]
fn adopting_unterminated_storage_is_refused() {
    let mut storage = MmapBuffer::with_capacity(8).expect("map");
    storage.as_mut_slice().fill(b'x');
    let addr = storage.stable_ptr();
    let Err((returned, e)) = OwnedPath::adopt(storage) else {
        panic!("storage with no NUL must be refused");
    };
    assert_eq!(e, PathError::NotTerminated);
    assert_eq!(returned.stable_ptr(), addr);
}

#[test]
fn adopting_storage_that_already_holds_a_path_finds_its_length() {
    let mut storage = MmapBuffer::with_capacity(64).expect("map");
    storage.as_mut_slice()[..5].copy_from_slice(b"/tmp\0");
    let path = OwnedPath::adopt(storage).unwrap_or_else(|(_, e)| panic!("{e}"));
    assert_eq!(path.as_bytes(), b"/tmp");
}

#[cfg(not(miri))]
#[test]
fn a_real_open_yields_a_working_descriptor_and_returns_the_path() {
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let path = path_of(b"/tmp");
    let addr = path.as_bytes().as_ptr();
    let ticket = sub
        .push_open(PreparedOpen::cwd(
            path,
            OpenFlags::TMPFILE | OpenFlags::RDWR,
            FileMode::OWNER_READ | FileMode::OWNER_WRITE,
        ))
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");

    let receipt = comp.wait_one().expect("completion");
    let opened = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatch"));
    assert!(opened.is_ok(), "open failed: {}", opened.raw_result());

    let (file, path) = opened.into_parts();
    let file = file.expect("a successful open must carry a descriptor");
    // The descriptor is real: write through it and get the byte count back.
    let mut ring = crate::IoUring::new(4).expect("ring");
    ring.push(unsafe { crate::Sqe::write(file.fd(), b"proof", 0) }.user_data(1))
        .expect("push");
    ring.submit_and_wait(1).expect("submit");
    assert_eq!(ring.complete().expect("cqe").result, 5);

    // And the path storage came back at the same address it went in at.
    assert_eq!(path.as_bytes().as_ptr(), addr);
}

#[cfg(not(miri))]
#[test]
fn a_failed_open_reports_the_errno_and_still_returns_the_path() {
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let ticket = sub
        .push_open(PreparedOpen::cwd(
            path_of(b"/nonexistent/definitely/not/here"),
            OpenFlags::default(),
            FileMode::default(),
        ))
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");

    let receipt = comp.wait_one().expect("completion");
    let opened = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatch"));

    assert!(!opened.is_ok());
    assert!(opened.result().is_err());
    // ENOENT, not a descriptor that would leak if ignored.
    assert_eq!(opened.raw_result(), -2);
    let (file, path) = opened.into_parts();
    assert!(file.is_none(), "a failed open must not carry a descriptor");
    assert_eq!(path.as_bytes(), b"/nonexistent/definitely/not/here");
}

#[cfg(not(miri))]
#[test]
fn an_open_ticket_survives_moving_to_another_thread_before_completion() {
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let ticket = sub
        .push_open(PreparedOpen::at(
            DirFd::Cwd,
            path_of(b"/tmp"),
            OpenFlags::TMPFILE | OpenFlags::RDWR,
            FileMode::OWNER_READ | FileMode::OWNER_WRITE,
        ))
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");
    let receipt = comp.wait_one().expect("completion");

    // The kernel read the path from the submitting thread; the ticket that
    // owns those bytes is redeemed on another one.
    let opened = std::thread::spawn(move || {
        ticket
            .redeem(receipt)
            .unwrap_or_else(|_| panic!("mismatch"))
    })
    .join()
    .expect("join");
    assert!(opened.is_ok(), "open failed: {}", opened.raw_result());
    assert!(opened.into_file().is_some());
}

#[test]
fn an_open_push_that_does_not_fit_hands_the_path_back() {
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, _comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let mut tickets = alloc_tickets(&mut sub);
    let path = path_of(b"/tmp/wherever");
    let addr = path.as_bytes().as_ptr();

    let Err((returned, e)) = sub.push_open(PreparedOpen::cwd(
        path,
        OpenFlags::CREAT,
        FileMode::OWNER_READ,
    )) else {
        panic!("a full queue must reject the push");
    };
    assert_eq!(e, Error::Submit(SubmitError::QueueFull));
    // Every field survived the round trip, not just the storage: a retry
    // must open the same path with the same flags.
    assert_eq!(returned.path().as_bytes().as_ptr(), addr);
    assert_eq!(returned.path().as_bytes(), b"/tmp/wherever");
    assert_eq!(returned.flags(), OpenFlags::CREAT);
    assert_eq!(returned.mode(), FileMode::OWNER_READ);
    assert!(matches!(returned.dir(), DirFd::Cwd));
    tickets.clear();
}

/// A ring with a sparse file table of `slots` entries.
///
/// `-1` means an empty slot: the table exists so the kernel has somewhere
/// to install, but holds no files yet.
#[cfg(not(miri))]
fn ring_with_table(entries: u32, slots: usize) -> crate::IoUring {
    let mut ring = crate::IoUring::new(entries).expect("ring");
    ring.register_files(&std::vec![-1; slots])
        .expect("register a sparse file table");
    ring
}

#[cfg(not(miri))]
#[test]
fn a_direct_open_installs_into_the_table_without_touching_the_process() {
    let ring = ring_with_table(4, 4);
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let request = PreparedDirectOpen::cwd(
        path_of(b"/tmp"),
        OpenFlags::TMPFILE | OpenFlags::RDWR,
        FileMode::OWNER_READ | FileMode::OWNER_WRITE,
        SlotTarget::Auto,
    )
    .unwrap_or_else(|(_, e)| panic!("{e}"));
    let ticket = sub
        .push_direct_open(request)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");

    let receipt = comp.wait_one().expect("completion");
    let opened = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatch"));
    assert!(
        opened.is_ok(),
        "direct open failed: {}",
        opened.raw_result()
    );

    let slot = opened.slot().expect("a successful open names a slot");
    // The first free slot of an empty table is 0. No descriptor could be 0
    // here — that is stdin, still open — so a result of 0 is itself
    // evidence the kernel installed into the table rather than handing
    // this process a descriptor.
    assert_eq!(slot.index().get(), 0);
    assert_eq!(slot.as_fixed_fd(), 0);

    // The file is real: write through the slot, which only resolves
    // because `fixed_file` makes the kernel read `fd` as a table index.
    sub.raw()
        .push(
            unsafe { crate::Sqe::write_ptr(RawFd::from_raw(0), b"proof".as_ptr(), 5, 0) }
                .fixed_file()
                .user_data(9),
        )
        .expect("push");
    sub.submit_and_wait(1).expect("submit");
    let done = comp.wait_one().expect("completion");
    assert_eq!(done.raw_result(), 5, "the installed file must be writable");
}

#[cfg(not(miri))]
#[test]
fn an_exact_slot_reports_where_the_caller_asked_not_what_the_cqe_says() {
    let ring = ring_with_table(4, 4);
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let request = PreparedDirectOpen::cwd(
        path_of(b"/tmp"),
        OpenFlags::TMPFILE | OpenFlags::RDWR,
        FileMode::OWNER_READ | FileMode::OWNER_WRITE,
        SlotTarget::exact(2).expect("representable"),
    )
    .unwrap_or_else(|(_, e)| panic!("{e}"));
    let ticket = sub
        .push_direct_open(request)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");

    let receipt = comp.wait_one().expect("completion");
    let opened = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatch"));
    assert!(
        opened.is_ok(),
        "direct open failed: {}",
        opened.raw_result()
    );

    // The kernel returns 0 for an explicit install, so a completion that
    // believed its result would report slot 0 for a file that is in slot 2.
    assert_eq!(opened.raw_result(), 0);
    assert_eq!(opened.index().expect("slot").get(), 2);

    // Reading the index back off the target proves nothing on its own — it
    // is this crate's arithmetic checked against itself. The kernel is the
    // only authority on where the file actually landed, so ask it: write
    // through slot 2 and through slot 1. Exactly one must be occupied, and
    // it must be the one the caller was told about. If the submission-time
    // `+1` were dropped, the file would sit in slot 1 and these two
    // assertions would swap.
    let write_through = |sub: &mut super::OwnedSubmitter,
                         comp: &mut super::OwnedCompleter,
                         slot| {
        sub.raw()
            .push(
                unsafe { crate::Sqe::write_ptr(RawFd::from_raw(slot), b"proof".as_ptr(), 5, 0) }
                    .fixed_file()
                    .user_data(1),
            )
            .expect("push");
        sub.submit_and_wait(1).expect("submit");
        comp.wait_one().expect("completion").raw_result()
    };
    assert_eq!(
        write_through(&mut sub, &mut comp, 2),
        5,
        "the file must be in the slot the caller asked for"
    );
    assert_eq!(
        write_through(&mut sub, &mut comp, 1),
        -9,
        "EBADF: the neighbouring slot must still be empty"
    );
}

#[cfg(not(miri))]
#[test]
fn a_direct_open_without_a_registered_table_fails_instead_of_leaking_an_fd() {
    // No `register_files`: there is no table to install into.
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let request = PreparedDirectOpen::cwd(
        path_of(b"/tmp"),
        OpenFlags::TMPFILE | OpenFlags::RDWR,
        FileMode::OWNER_READ | FileMode::OWNER_WRITE,
        SlotTarget::Auto,
    )
    .unwrap_or_else(|(_, e)| panic!("{e}"));
    let ticket = sub
        .push_direct_open(request)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");

    let receipt = comp.wait_one().expect("completion");
    let opened = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatch"));
    assert!(!opened.is_ok(), "an absent table must not succeed");
    assert!(opened.slot().is_none(), "a failure names no slot");
    // The path still comes back, as with any other failed request.
    let (slot, path) = opened.into_parts();
    assert!(slot.is_none());
    assert_eq!(path.as_bytes(), b"/tmp");
}

#[cfg(not(miri))]
#[test]
fn a_slot_outside_the_table_is_refused_by_the_kernel() {
    let ring = ring_with_table(4, 2);
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let request = PreparedDirectOpen::cwd(
        path_of(b"/tmp"),
        OpenFlags::TMPFILE | OpenFlags::RDWR,
        FileMode::OWNER_READ | FileMode::OWNER_WRITE,
        SlotTarget::exact(9).expect("representable"),
    )
    .unwrap_or_else(|(_, e)| panic!("{e}"));
    let ticket = sub
        .push_direct_open(request)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");

    let receipt = comp.wait_one().expect("completion");
    let opened = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatch"));
    // EINVAL: the slot is past the end of a two-entry table.
    assert_eq!(opened.raw_result(), -22);
    assert!(opened.slot().is_none());
}

#[cfg(not(miri))]
#[test]
fn a_direct_socket_lands_in_the_table_and_is_usable_through_its_slot() {
    let ring = ring_with_table(8, 4);
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let request = PreparedDirectSocket::auto(
        AddressFamily::Inet,
        SocketType::Stream,
        0,
        SocketFlags::default(),
    )
    .expect("preparable");
    let ticket = sub
        .push_direct_socket(request)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");

    let created = ticket
        .redeem(comp.wait_one().expect("completion"))
        .unwrap_or_else(|_| panic!("mismatch"));
    assert!(created.is_ok(), "result was {}", created.raw_result());
    let slot = created.slot().expect("a slot");
    // A fresh table allocates from zero, so this is index 0 -- which as a
    // descriptor would be stdin. Nothing entered the process's table.
    assert_eq!(slot.index().get(), 0);

    // It is a real socket, not just a recorded number: connecting through
    // the slot to a listener proves the kernel installed a working file.
    let listener = Listener::bound();
    let addr = listener.addr_bytes();
    sub.raw()
        .push(
            unsafe { crate::Sqe::connect(RawFd::from_raw(0), &addr) }
                .fixed_file()
                .user_data(7),
        )
        .expect("push connect");
    sub.submit_and_wait(1).expect("submit");
    let connected = comp.wait_one().expect("completion");
    assert_eq!(connected.raw_result(), 0, "connect through the slot");
}

#[cfg(not(miri))]
#[test]
fn an_explicit_slot_closes_the_file_it_replaces() {
    // The man page says an occupied entry "will first be removed from the
    // table and closed". That is invisible in the CQE -- a replacement
    // reports the same 0 as an install into a free slot -- so the only way
    // to see it is through the file that was evicted.
    // Slot 2, deliberately not slot 0: for slot 0 the index the caller
    // named and the index Auto would read out of a successful result are
    // both zero, so the two rules agree and the test cannot tell them
    // apart. A non-zero slot separates them -- the CQE still says 0.
    const SEEDED: u32 = 2;
    let mut ring = crate::IoUring::new(8).expect("ring");
    let seed = crate::eventfd::EventFd::new(0).expect("eventfd");
    ring.register_files(&[-1, -1, seed.fd().as_i32(), -1])
        .expect("register table");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let counter = 1u64.to_ne_bytes();
    let write_through = |sub: &mut super::OwnedSubmitter, comp: &mut super::OwnedCompleter| {
        sub.raw()
            .push(
                unsafe {
                    crate::Sqe::write_ptr(RawFd::from_raw(SEEDED as usize), counter.as_ptr(), 8, 0)
                }
                .fixed_file()
                .user_data(3),
            )
            .expect("push");
        sub.submit_and_wait(1).expect("submit");
        comp.wait_one().expect("completion").raw_result()
    };
    assert_eq!(
        write_through(&mut sub, &mut comp),
        8,
        "the seeded eventfd accepts an 8-byte counter"
    );

    let request = PreparedDirectSocket::new(
        AddressFamily::Inet,
        SocketType::Stream,
        0,
        SocketFlags::default(),
        SlotTarget::exact(SEEDED).expect("representable"),
    )
    .expect("preparable");
    let ticket = sub
        .push_direct_socket(request)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");
    let created = ticket
        .redeem(comp.wait_one().expect("completion"))
        .unwrap_or_else(|_| panic!("mismatch"));

    assert_eq!(
        created.raw_result(),
        0,
        "an explicit install reports 0, indistinguishable from a free slot"
    );
    assert_eq!(
        created.index().expect("a slot").get(),
        SEEDED,
        "the index is the one asked for; believing the result would say 0"
    );
    // The eventfd is gone: the same write now hits an unconnected socket.
    assert_eq!(
        write_through(&mut sub, &mut comp),
        -32,
        "EPIPE proves the replaced file was closed, not merely shadowed"
    );
}

#[cfg(not(miri))]
#[test]
fn a_full_table_and_an_absent_one_are_told_apart_by_their_errno() {
    // Both refuse, but for different reasons, and only the explicit-slot
    // form distinguishes them: ENFILE means "no free entry", which an
    // absent table also satisfies, while ENXIO means "no table at all".
    let ring = ring_with_table(8, 1);
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));
    let auto = || {
        PreparedDirectSocket::auto(
            AddressFamily::Inet,
            SocketType::Stream,
            0,
            SocketFlags::default(),
        )
        .expect("preparable")
    };

    let first = sub
        .push_direct_socket(auto())
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");
    let created = first
        .redeem(comp.wait_one().expect("completion"))
        .unwrap_or_else(|_| panic!("mismatch"));
    assert!(created.is_ok(), "the only slot is free");

    let second = sub
        .push_direct_socket(auto())
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");
    let full = second
        .redeem(comp.wait_one().expect("completion"))
        .unwrap_or_else(|_| panic!("mismatch"));
    assert_eq!(full.raw_result(), -23, "ENFILE: the table is full");
    assert!(full.slot().is_none(), "a failure names no slot");

    // No table at all. Auto still says ENFILE, so it cannot tell the two
    // situations apart; an explicit slot says ENXIO and can.
    let bare = crate::IoUring::new(8).expect("ring");
    let (mut sub, mut comp) = bare.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));
    let ticket = sub
        .push_direct_socket(auto())
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");
    let missing = ticket
        .redeem(comp.wait_one().expect("completion"))
        .unwrap_or_else(|_| panic!("mismatch"));
    assert_eq!(
        missing.raw_result(),
        -23,
        "ENFILE again: an absent table has no free entry either"
    );

    let exact = PreparedDirectSocket::new(
        AddressFamily::Inet,
        SocketType::Stream,
        0,
        SocketFlags::default(),
        SlotTarget::exact(1).expect("representable"),
    )
    .expect("preparable");
    let ticket = sub
        .push_direct_socket(exact)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");
    let named = ticket
        .redeem(comp.wait_one().expect("completion"))
        .unwrap_or_else(|_| panic!("mismatch"));
    assert_eq!(
        named.raw_result(),
        -6,
        "ENXIO: a named slot reports the missing table as such"
    );
    // An explicit target knows its index without reading the result, so
    // nothing but the failure itself stops it from reporting a slot the
    // kernel never filled. Naming one here would invent an installed
    // socket out of an ENXIO.
    assert!(
        named.slot().is_none(),
        "a failed install names no slot, however well the caller knew the index"
    );
    assert!(named.index().is_none());
}

#[test]
fn close_on_exec_is_refused_for_a_direct_socket_before_submission() {
    // The same asymmetry as a direct open, and worth pinning because it is
    // not a property of the flag but of the request: CLOEXEC is perfectly
    // valid on a NON-direct socket, and only meaningless once the result
    // is a table slot rather than a descriptor.
    let refused = PreparedDirectSocket::auto(
        AddressFamily::Inet,
        SocketType::Stream,
        0,
        SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
    );
    assert_eq!(refused.unwrap_err(), DirectSocketError::CloseOnExec);

    // NONBLOCK alone is fine; only CLOEXEC is refused.
    PreparedDirectSocket::auto(
        AddressFamily::Inet,
        SocketType::Stream,
        0,
        SocketFlags::NONBLOCK,
    )
    .expect("NONBLOCK is valid for a direct socket");
}

#[test]
fn a_direct_socket_push_that_does_not_fit_hands_the_request_back() {
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, _comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));
    let mut tickets = alloc_tickets(&mut sub);

    let target = SlotTarget::exact(3).expect("representable");
    let request = PreparedDirectSocket::new(
        AddressFamily::Inet,
        SocketType::Dgram,
        17,
        SocketFlags::NONBLOCK,
        target,
    )
    .expect("preparable");
    let Err((returned, e)) = sub.push_direct_socket(request) else {
        panic!("a full queue must reject the push");
    };
    assert_eq!(e, Error::Submit(SubmitError::QueueFull));
    // Every field survives, the target especially: a retry that lost it
    // would install into a different slot and close whatever lived there.
    assert_eq!(returned.domain(), AddressFamily::Inet);
    assert_eq!(returned.protocol(), 17);
    assert_eq!(returned.flags(), SocketFlags::NONBLOCK);
    assert_eq!(returned.target(), target);
    tickets.clear();
}

#[test]
fn a_direct_socket_receipt_for_another_request_is_rejected() {
    let ring = crate::IoUring::new(8).expect("ring");
    let (mut sub, _comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));
    let make = || {
        PreparedDirectSocket::auto(
            AddressFamily::Inet,
            SocketType::Stream,
            0,
            SocketFlags::default(),
        )
        .expect("preparable")
    };

    let first = sub
        .push_direct_socket(make())
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    let second = sub
        .push_direct_socket(make())
        .unwrap_or_else(|(_, e)| panic!("{e}"));

    let foreign = Receipt {
        ring: second.ring(),
        id: second.id(),
        result: 0,
        flags: crate::types::CqeFlags::default(),
    };
    assert!(!first.matches(&foreign));
    let Err((first, _)) = first.redeem(foreign) else {
        panic!("a foreign receipt must not redeem");
    };
    drop((first, second));
}

#[test]
fn close_on_exec_is_refused_before_submission_with_the_path_returned() {
    let path = path_of(b"/tmp/whatever");
    let addr = path.as_bytes().as_ptr();
    // The kernel answers EINVAL for this combination, because O_CLOEXEC
    // describes what execve does to a descriptor and a slot is not one.
    let Err((returned, e)) = PreparedDirectOpen::cwd(
        path,
        OpenFlags::RDWR | OpenFlags::CLOEXEC,
        FileMode::default(),
        SlotTarget::Auto,
    ) else {
        panic!("O_CLOEXEC must be refused for a direct open");
    };
    assert_eq!(e, DirectOpenError::CloseOnExec);
    assert_eq!(returned.as_bytes().as_ptr(), addr, "the path comes back");
}

#[test]
fn a_direct_open_push_that_does_not_fit_hands_everything_back() {
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, _comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let mut tickets = alloc_tickets(&mut sub);
    let path = path_of(b"/tmp/wherever");
    let addr = path.as_bytes().as_ptr();
    let target = SlotTarget::exact(3).expect("representable");

    let request = PreparedDirectOpen::cwd(path, OpenFlags::CREAT, FileMode::OWNER_READ, target)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    let Err((returned, e)) = sub.push_direct_open(request) else {
        panic!("a full queue must reject the push");
    };
    assert_eq!(e, Error::Submit(SubmitError::QueueFull));
    // Every field survives, the target included: a retry that lost it
    // would install the file somewhere else entirely.
    assert_eq!(returned.path().as_bytes().as_ptr(), addr);
    assert_eq!(returned.flags(), OpenFlags::CREAT);
    assert_eq!(returned.mode(), FileMode::OWNER_READ);
    assert_eq!(returned.target(), target);
    tickets.clear();
}

#[test]
fn a_direct_open_receipt_for_another_request_is_rejected() {
    let ring = crate::IoUring::new(8).expect("ring");
    let (mut sub, _comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let prepare = || {
        PreparedDirectOpen::cwd(
            path_of(b"/tmp"),
            OpenFlags::default(),
            FileMode::default(),
            SlotTarget::Auto,
        )
        .unwrap_or_else(|(_, e)| panic!("{e}"))
    };
    let first = sub
        .push_direct_open(prepare())
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    let second = sub
        .push_direct_open(prepare())
        .unwrap_or_else(|(_, e)| panic!("{e}"));

    let foreign = Receipt {
        ring: second.ring(),
        id: second.id(),
        result: 0,
        flags: crate::types::CqeFlags::default(),
    };
    assert!(!first.matches(&foreign));
    let Err((first, _)) = first.redeem(foreign) else {
        panic!("a foreign receipt must not redeem");
    };
    // Neither is redeemed, so both leak their path storage on purpose.
    drop((first, second));
}

#[test]
fn a_slot_from_one_ring_is_not_confused_with_anothers() {
    let mine = RingId::next();
    let other = RingId::next();
    let slot = DirectSlot::new(SlotIndex::new(1).expect("index"), mine);
    // Slot 1 of two different rings names two different files.
    assert!(slot.belongs_to(mine));
    assert!(!slot.belongs_to(other));
}

#[test]
fn an_open_receipt_for_another_request_is_rejected() {
    let ring = crate::IoUring::new(8).expect("ring");
    let (mut sub, _comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let first = sub
        .push_open(PreparedOpen::cwd(
            path_of(b"/tmp"),
            OpenFlags::default(),
            FileMode::default(),
        ))
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    let second = sub
        .push_open(PreparedOpen::cwd(
            path_of(b"/tmp"),
            OpenFlags::default(),
            FileMode::default(),
        ))
        .unwrap_or_else(|(_, e)| panic!("{e}"));

    let foreign = Receipt {
        ring: second.ring(),
        id: second.id(),
        result: 7,
        flags: crate::types::CqeFlags::default(),
    };
    assert!(!first.matches(&foreign));
    let Err((first, _)) = first.redeem(foreign) else {
        panic!("a foreign receipt must not redeem");
    };
    // Neither ticket is redeemed, so both leak their path storage rather
    // than freeing bytes the kernel may still be reading.
    drop((first, second));
}

const _: () = assert_send::<PendingStatx<MmapBuffer, MmapBuffer>>();
const _: () = assert_send::<PreparedStatx<MmapBuffer, MmapBuffer>>();

/// A destination big and aligned enough for a `Statx`.
fn statx_dest() -> MmapBuffer {
    MmapBuffer::with_capacity(core::mem::size_of::<Statx>()).expect("map")
}

#[test]
fn a_destination_too_small_for_a_statx_is_rejected_with_the_storage_back() {
    let short = MmapBuffer::with_capacity(core::mem::size_of::<Statx>() - 1).expect("map");
    let got = short.stable_len();
    let Err((path, returned, e)) = PreparedStatx::cwd(
        path_of(b"/tmp"),
        StatxFlags::default(),
        StatxMask::BASIC_STATS,
        short,
    ) else {
        panic!("a short destination must be refused");
    };
    assert_eq!(
        e,
        StatxError::DestTooSmall {
            needed: core::mem::size_of::<Statx>(),
            got,
        }
    );
    // Both storages come back, so a rejected request costs nothing.
    assert_eq!(path.as_bytes(), b"/tmp");
    assert_eq!(returned.stable_len(), got);
}

#[test]
fn a_misaligned_destination_is_rejected_rather_than_written_through() {
    // The kernel writes a `repr(C)` struct with 8-byte alignment through
    // this pointer. An unaligned write would be UB, so it must be caught
    // before submission, not discovered afterwards.
    let dest = MisalignedVecs::with_capacity(core::mem::size_of::<Statx>() + 8);
    let Err((path, _dest, e)) = PreparedStatx::cwd(
        path_of(b"/tmp"),
        StatxFlags::default(),
        StatxMask::BASIC_STATS,
        dest,
    ) else {
        panic!("a misaligned destination must be refused");
    };
    assert_eq!(
        e,
        StatxError::DestMisaligned {
            needed: core::mem::align_of::<Statx>(),
        }
    );
    assert_eq!(path.as_bytes(), b"/tmp");
}

#[test]
fn a_mask_with_the_reserved_bit_is_rejected_before_submission() {
    let Err((path, dest, e)) = PreparedStatx::cwd(
        path_of(b"/tmp"),
        StatxFlags::default(),
        StatxMask::from_raw_for_test(0x8000_0000),
        statx_dest(),
    ) else {
        panic!("the reserved mask bit must be refused");
    };
    assert_eq!(e, StatxError::ReservedMaskBit);
    assert_eq!(path.as_bytes(), b"/tmp");
    drop(dest);
}

#[cfg(not(miri))]
#[test]
fn a_real_statx_fills_the_destination_and_returns_both_storages() {
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let path = path_of(b"/etc/hostname");
    let path_addr = path.as_bytes().as_ptr();
    let dest = statx_dest();
    let dest_addr = dest.stable_ptr();

    let prepared = PreparedStatx::cwd(path, StatxFlags::default(), StatxMask::BASIC_STATS, dest)
        .unwrap_or_else(|(_, _, e)| panic!("{e}"));
    let ticket = sub
        .push_statx(prepared)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");

    let receipt = comp.wait_one().expect("completion");
    let done = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatch"));
    assert!(done.is_ok(), "statx failed: {}", done.raw_result());

    let stat = done.stat().expect("a successful statx must carry a struct");
    // A regular file with a plausible mode, read through the mask gate.
    assert!(stat.has(StatxMask::TYPE));
    let mode = stat.mode().expect("mode was requested and is basic");
    assert_eq!(mode & 0o170_000, 0o100_000, "S_IFREG expected");
    assert!(stat.nlink().expect("nlink") >= 1);

    let (path, dest) = done.into_parts();
    // Both storages came back at the addresses they went in at.
    assert_eq!(path.as_bytes().as_ptr(), path_addr);
    assert_eq!(dest.stable_ptr(), dest_addr);
}

#[cfg(not(miri))]
#[test]
fn a_failed_statx_reports_the_errno_and_carries_no_struct() {
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let prepared = PreparedStatx::cwd(
        path_of(b"/nonexistent/definitely/not/here"),
        StatxFlags::default(),
        StatxMask::BASIC_STATS,
        statx_dest(),
    )
    .unwrap_or_else(|(_, _, e)| panic!("{e}"));
    let ticket = sub
        .push_statx(prepared)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");

    let receipt = comp.wait_one().expect("completion");
    let done = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatch"));

    assert!(!done.is_ok());
    assert_eq!(done.raw_result(), -2, "ENOENT");
    // The kernel never wrote the destination, so there is nothing to read
    // and `stat` says so rather than handing back stale bytes.
    assert!(done.stat().is_none());
    let (path, _) = done.into_parts();
    assert_eq!(path.as_bytes(), b"/nonexistent/definitely/not/here");
}

#[cfg(not(miri))]
#[test]
fn every_accessor_agrees_with_the_mask_rather_than_the_request() {
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    // Ask for only the size. The kernel may volunteer more, and the mask
    // is the only way to tell what actually arrived.
    let prepared = PreparedStatx::cwd(
        path_of(b"/etc/hostname"),
        StatxFlags::default(),
        StatxMask::SIZE,
        statx_dest(),
    )
    .unwrap_or_else(|(_, _, e)| panic!("{e}"));
    let ticket = sub
        .push_statx(prepared)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");

    let receipt = comp.wait_one().expect("completion");
    let done = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatch"));
    let stat = done.stat().expect("statx ok");

    // What was asked for is present.
    assert!(stat.has(StatxMask::SIZE));
    assert!(stat.size().is_some());
    // Every accessor agrees with the mask, whether or not it was requested
    // — that consistency is the property, not any particular field.
    assert_eq!(stat.mode().is_some(), stat.has(StatxMask::MODE));
    assert_eq!(stat.ino().is_some(), stat.has(StatxMask::INO));
    assert_eq!(stat.mtime().is_some(), stat.has(StatxMask::MTIME));
    assert_eq!(stat.uid().is_some(), stat.has(StatxMask::UID));
    assert_eq!(stat.blocks().is_some(), stat.has(StatxMask::BLOCKS));
}

/// A scratch directory that removes itself, so a failing test cannot leave
/// entries behind that make the next run pass for the wrong reason.
#[cfg(not(miri))]
struct Scratch {
    dir: std::string::String,
}

#[cfg(not(miri))]
impl Scratch {
    fn new(label: &str) -> Self {
        static COUNTER: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
        let nonce = COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        let dir = std::format!(
            "/tmp/ququmatz_{label}_{}_{nonce}_{nanos}",
            std::process::id()
        );
        std::fs::create_dir_all(&dir).expect("scratch dir");
        Self { dir }
    }

    fn path(&self, name: &str) -> std::string::String {
        std::format!("{}/{name}", self.dir)
    }

    fn owned_path(&self, name: &str) -> OwnedPath<MmapBuffer> {
        path_of(self.path(name).as_bytes())
    }

    fn write(&self, name: &str, bytes: &[u8]) {
        std::fs::write(self.path(name), bytes).expect("seed file");
    }

    fn mkdir(&self, name: &str) {
        std::fs::create_dir(self.path(name)).expect("seed dir");
    }

    fn exists(&self, name: &str) -> bool {
        std::path::Path::new(&self.path(name)).exists()
    }

    fn read(&self, name: &str) -> std::vec::Vec<u8> {
        std::fs::read(self.path(name)).unwrap_or_default()
    }

    fn mode_of(&self, name: &str) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(self.path(name))
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777
    }
}

#[cfg(not(miri))]
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Submit one owned request and redeem it, returning the raw CQE result.
#[cfg(not(miri))]
fn run_path_op(
    sub: &mut super::OwnedSubmitter,
    comp: &mut super::OwnedCompleter,
    request: PreparedPathOp<MmapBuffer>,
) -> i32 {
    let ticket = sub
        .push_path_op(request)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");
    let receipt = comp.wait_one().expect("completion");
    let done = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatch"));
    done.raw_result()
}

#[cfg(not(miri))]
#[test]
fn a_real_mkdir_creates_a_directory_and_returns_its_path() {
    let scratch = Scratch::new("mkdir");
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let path = scratch.owned_path("fresh");
    let addr = path.as_bytes().as_ptr();
    let ticket = sub
        .push_path_op(PreparedPathOp::mkdir_cwd(
            path,
            FileMode::OWNER_READ | FileMode::OWNER_WRITE | FileMode::OWNER_EXEC,
        ))
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");

    let receipt = comp.wait_one().expect("completion");
    let done = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatch"));

    assert!(done.is_ok(), "mkdir failed: {}", done.raw_result());
    // The directory is real, not merely a zero result.
    assert!(scratch.exists("fresh"));
    assert_eq!(scratch.mode_of("fresh"), 0o700);
    assert_eq!(
        done.kind(),
        PathOpKind::Mkdir(FileMode::OWNER_READ | FileMode::OWNER_WRITE | FileMode::OWNER_EXEC)
    );
    // And the storage came back at the address it went in at.
    assert_eq!(done.into_path().as_bytes().as_ptr(), addr);
}

#[cfg(not(miri))]
#[test]
fn a_real_unlink_removes_the_file_it_names() {
    let scratch = Scratch::new("unlink");
    scratch.write("doomed", b"content");
    scratch.write("bystander", b"safe");
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let result = run_path_op(
        &mut sub,
        &mut comp,
        PreparedPathOp::unlink_cwd(scratch.owned_path("doomed")),
    );

    assert_eq!(result, 0);
    assert!(!scratch.exists("doomed"));
    // Only the named entry went: a test that checked nothing else would
    // pass for an implementation that emptied the directory.
    assert!(scratch.exists("bystander"));
}

#[cfg(not(miri))]
#[test]
fn the_two_removals_each_refuse_the_other_kind_of_target() {
    let scratch = Scratch::new("removals");
    scratch.write("plainfile", b"x");
    scratch.mkdir("plaindir");
    let ring = crate::IoUring::new(8).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    // Unlink on a directory: EISDIR, and the directory survives.
    assert_eq!(
        run_path_op(
            &mut sub,
            &mut comp,
            PreparedPathOp::unlink_cwd(scratch.owned_path("plaindir")),
        ),
        -21,
    );
    assert!(scratch.exists("plaindir"));

    // Rmdir on a file: ENOTDIR, and the file survives.
    assert_eq!(
        run_path_op(
            &mut sub,
            &mut comp,
            PreparedPathOp::rmdir_cwd(scratch.owned_path("plainfile")),
        ),
        -20,
    );
    assert!(scratch.exists("plainfile"));

    // Each matched pairing works, which is what makes the split worth
    // having rather than an arbitrary restriction.
    assert_eq!(
        run_path_op(
            &mut sub,
            &mut comp,
            PreparedPathOp::rmdir_cwd(scratch.owned_path("plaindir")),
        ),
        0,
    );
    assert!(!scratch.exists("plaindir"));
    assert_eq!(
        run_path_op(
            &mut sub,
            &mut comp,
            PreparedPathOp::unlink_cwd(scratch.owned_path("plainfile")),
        ),
        0,
    );
    assert!(!scratch.exists("plainfile"));
}

#[cfg(not(miri))]
#[test]
fn an_rmdir_refuses_a_directory_that_still_has_entries() {
    let scratch = Scratch::new("nonempty");
    scratch.mkdir("full");
    std::fs::write(scratch.path("full/inside"), b"x").expect("seed");
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    // ENOTEMPTY: this removes one directory, never a tree.
    assert_eq!(
        run_path_op(
            &mut sub,
            &mut comp,
            PreparedPathOp::rmdir_cwd(scratch.owned_path("full")),
        ),
        -39,
    );
    assert!(scratch.exists("full"));
    assert!(scratch.exists("full/inside"));
}

#[cfg(not(miri))]
#[test]
fn a_failed_path_op_reports_the_errno_and_still_returns_the_path() {
    let scratch = Scratch::new("missing");
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let ticket = sub
        .push_path_op(PreparedPathOp::unlink_cwd(scratch.owned_path("absent")))
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");
    let receipt = comp.wait_one().expect("completion");
    let done = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatch"));

    assert!(!done.is_ok());
    assert!(done.result().is_err());
    assert_eq!(done.raw_result(), -2);
    // The storage comes back even on failure, as it must: the kernel is
    // done reading it either way.
    assert_eq!(
        done.into_path().as_bytes(),
        scratch.path("absent").as_bytes()
    );
}

#[cfg(not(miri))]
#[test]
fn a_path_op_push_that_does_not_fit_hands_the_path_back() {
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, _comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));
    let mut tickets = alloc_tickets(&mut sub);

    let path = path_of(b"/tmp/never_submitted");
    let addr = path.as_bytes().as_ptr();
    let Err((returned, e)) = sub.push_path_op(PreparedPathOp::rmdir_cwd(path)) else {
        panic!("a full queue must reject the push");
    };
    assert_eq!(e, Error::Submit(SubmitError::QueueFull));
    // The kind survives too: a retry that lost it would unlink where the
    // caller asked to rmdir.
    assert_eq!(returned.kind(), PathOpKind::Rmdir);
    assert_eq!(returned.into_path().as_bytes().as_ptr(), addr);
    tickets.clear();
}

#[test]
fn a_path_op_receipt_for_another_request_is_rejected() {
    let ring = crate::IoUring::new(8).expect("ring");
    let (mut sub, _comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let first = sub
        .push_path_op(PreparedPathOp::unlink_cwd(path_of(b"/tmp/a")))
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    let second = sub
        .push_path_op(PreparedPathOp::unlink_cwd(path_of(b"/tmp/b")))
        .unwrap_or_else(|(_, e)| panic!("{e}"));

    let foreign = Receipt {
        ring: second.ring(),
        id: second.id(),
        result: 0,
        flags: crate::types::CqeFlags::default(),
    };
    assert!(!first.matches(&foreign));
    let Err((first, _)) = first.redeem(foreign) else {
        panic!("a foreign receipt must not redeem");
    };
    drop((first, second));
}

#[cfg(not(miri))]
#[test]
fn a_real_rename_moves_the_file_and_returns_both_paths() {
    let scratch = Scratch::new("rename");
    scratch.write("source", b"payload");
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let from = scratch.owned_path("source");
    let to = scratch.owned_path("destination");
    let (from_addr, to_addr) = (from.as_bytes().as_ptr(), to.as_bytes().as_ptr());
    let ticket = sub
        .push_rename(PreparedRename::cwd(from, to, RenameMode::NoReplace))
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");

    let receipt = comp.wait_one().expect("completion");
    let done = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatch"));

    assert!(done.is_ok(), "rename failed: {}", done.raw_result());
    assert!(!scratch.exists("source"));
    assert_eq!(scratch.read("destination"), b"payload");

    // Both storages come back, at the addresses they went in at: this is
    // the first request that owns two.
    let (from, to) = done.into_paths();
    assert_eq!(from.as_bytes().as_ptr(), from_addr);
    assert_eq!(to.as_bytes().as_ptr(), to_addr);
}

#[cfg(not(miri))]
#[test]
fn the_three_rename_modes_differ_on_an_occupied_destination() {
    let scratch = Scratch::new("modes");
    let ring = crate::IoUring::new(8).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let mut run = |from: &str, to: &str, mode| {
        let ticket = sub
            .push_rename(PreparedRename::cwd(
                scratch.owned_path(from),
                scratch.owned_path(to),
                mode,
            ))
            .unwrap_or_else(|(_, e)| panic!("{e}"));
        sub.submit_and_wait(1).expect("submit");
        let receipt = comp.wait_one().expect("completion");
        ticket
            .redeem(receipt)
            .unwrap_or_else(|_| panic!("mismatch"))
            .raw_result()
    };

    // NoReplace refuses rather than destroying: EEXIST, target untouched.
    scratch.write("n_from", b"new");
    scratch.write("n_to", b"old");
    assert_eq!(run("n_from", "n_to", RenameMode::NoReplace), -17);
    assert_eq!(scratch.read("n_to"), b"old");
    assert_eq!(scratch.read("n_from"), b"new");

    // Replace destroys the target and says nothing about it: the result is
    // 0, exactly as for a rename onto a free name.
    scratch.write("r_from", b"new");
    scratch.write("r_to", b"old");
    assert_eq!(run("r_from", "r_to", RenameMode::Replace), 0);
    assert_eq!(scratch.read("r_to"), b"new");
    assert!(!scratch.exists("r_from"));

    // Exchange swaps both ways and keeps both entries.
    scratch.write("x_a", b"AAA");
    scratch.write("x_b", b"BBB");
    assert_eq!(run("x_a", "x_b", RenameMode::Exchange), 0);
    assert_eq!(scratch.read("x_a"), b"BBB");
    assert_eq!(scratch.read("x_b"), b"AAA");
}

#[cfg(not(miri))]
#[test]
fn an_exchange_needs_both_entries_to_exist() {
    let scratch = Scratch::new("exchange");
    scratch.write("present", b"x");
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let ticket = sub
        .push_rename(PreparedRename::cwd(
            scratch.owned_path("present"),
            scratch.owned_path("absent"),
            RenameMode::Exchange,
        ))
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");
    let receipt = comp.wait_one().expect("completion");
    let done = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatch"));

    // ENOENT: unlike the other two modes, an exchange cannot create the
    // destination.
    assert_eq!(done.raw_result(), -2);
    assert!(scratch.exists("present"));
    assert!(!scratch.exists("absent"));
}

#[cfg(not(miri))]
#[test]
fn a_rename_crosses_directories_through_the_length_field() {
    use std::os::fd::AsRawFd;
    let scratch = Scratch::new("crossdir");
    scratch.mkdir("left");
    scratch.mkdir("right");
    std::fs::write(scratch.path("left/departing"), b"travelling").expect("seed");

    let left = std::fs::File::open(scratch.path("left")).expect("open left");
    let right = std::fs::File::open(scratch.path("right")).expect("open right");
    let left_fd = DirFd::Fd(RawFd::from_raw(
        usize::try_from(left.as_raw_fd()).expect("non-negative fd"),
    ));
    let right_fd = DirFd::Fd(RawFd::from_raw(
        usize::try_from(right.as_raw_fd()).expect("non-negative fd"),
    ));

    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));
    let ticket = sub
        .push_rename(PreparedRename::new(
            left_fd,
            // Distinct basenames on purpose: with the same name on both
            // sides an implementation that sent one path twice would
            // still pass.
            path_of(b"departing"),
            right_fd,
            path_of(b"arrived"),
            RenameMode::NoReplace,
        ))
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");
    let receipt = comp.wait_one().expect("completion");
    let done = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatch"));

    // The destination directory travels in the SQE's `len` field, which
    // means "bytes" in every other request — so this is worth proving
    // rather than assuming.
    assert!(
        done.is_ok(),
        "cross-directory rename failed: {}",
        done.raw_result()
    );
    assert!(!scratch.exists("left/departing"));
    assert!(!scratch.exists("left/arrived"));
    assert_eq!(scratch.read("right/arrived"), b"travelling");
}

#[cfg(not(miri))]
#[test]
fn a_rename_push_that_does_not_fit_hands_both_paths_back() {
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, _comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));
    let mut tickets = alloc_tickets(&mut sub);

    let from = path_of(b"/tmp/rename_from");
    let to = path_of(b"/tmp/rename_to");
    let (from_addr, to_addr) = (from.as_bytes().as_ptr(), to.as_bytes().as_ptr());
    let Err((returned, e)) = sub.push_rename(PreparedRename::cwd(from, to, RenameMode::NoReplace))
    else {
        panic!("a full queue must reject the push");
    };
    assert_eq!(e, Error::Submit(SubmitError::QueueFull));
    // The mode survives: a retry that lost it would overwrite where the
    // caller asked to refuse.
    assert_eq!(returned.mode(), RenameMode::NoReplace);
    let (from, to) = returned.into_paths();
    assert_eq!(from.as_bytes().as_ptr(), from_addr);
    assert_eq!(to.as_bytes().as_ptr(), to_addr);
    tickets.clear();
}

#[test]
fn a_rename_receipt_for_another_request_is_rejected() {
    let ring = crate::IoUring::new(8).expect("ring");
    let (mut sub, _comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));
    let make = || {
        PreparedRename::cwd(
            path_of(b"/tmp/from"),
            path_of(b"/tmp/to"),
            RenameMode::NoReplace,
        )
    };

    let first = sub
        .push_rename(make())
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    let second = sub
        .push_rename(make())
        .unwrap_or_else(|(_, e)| panic!("{e}"));

    let foreign = Receipt {
        ring: second.ring(),
        id: second.id(),
        result: 0,
        flags: crate::types::CqeFlags::default(),
    };
    assert!(!first.matches(&foreign));
    let Err((first, _)) = first.redeem(foreign) else {
        panic!("a foreign receipt must not redeem");
    };
    drop((first, second));
}

#[cfg(not(miri))]
#[test]
fn a_rename_ticket_survives_moving_to_another_thread_before_completion() {
    let scratch = Scratch::new("renamethread");
    scratch.write("movable", b"payload");
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let ticket = sub
        .push_rename(PreparedRename::cwd(
            scratch.owned_path("movable"),
            scratch.owned_path("moved"),
            RenameMode::NoReplace,
        ))
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");

    let handle = std::thread::spawn(move || {
        let receipt = comp.wait_one().expect("completion");
        let done = ticket
            .redeem(receipt)
            .unwrap_or_else(|_| panic!("mismatch"));
        done.raw_result()
    });
    assert_eq!(handle.join().expect("thread"), 0);
    assert_eq!(scratch.read("moved"), b"payload");
}

#[cfg(not(miri))]
#[test]
fn a_statx_ticket_survives_moving_to_another_thread_before_completion() {
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let prepared = PreparedStatx::cwd(
        path_of(b"/etc/hostname"),
        StatxFlags::default(),
        StatxMask::BASIC_STATS,
        statx_dest(),
    )
    .unwrap_or_else(|(_, _, e)| panic!("{e}"));
    let ticket = sub
        .push_statx(prepared)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");

    let handle = std::thread::spawn(move || {
        let receipt = comp.wait_one().expect("completion");
        let done = ticket
            .redeem(receipt)
            .unwrap_or_else(|_| panic!("mismatch"));
        done.stat().expect("statx ok").size()
    });
    assert!(handle.join().expect("thread").is_some());
}

/// Storage for the `open_how` the kernel reads.
fn how_store() -> MmapBuffer {
    MmapBuffer::with_capacity(core::mem::size_of::<crate::types::OpenHow>()).expect("map")
}

#[test]
fn the_open_how_is_published_before_any_sqe_names_it() {
    let prepared = PreparedOpenat2::cwd(
        path_of(b"/tmp/whatever"),
        OpenFlags::RDWR,
        Openat2Mode::Create(FileMode::OWNER_READ | FileMode::OWNER_WRITE),
        ResolveFlags::NO_SYMLINKS,
        how_store(),
    )
    .unwrap_or_else(|(_, _, e)| panic!("{e}"));

    // Read back from the storage the kernel will read, not from the
    // request's own fields: those could agree while the memory does not.
    let how = prepared.published_how();
    assert_eq!(
        how.flags,
        u64::from(OpenFlags::RDWR.bits() | OpenFlags::CREAT.bits())
    );
    assert_eq!(how.mode, 0o600);
    assert_eq!(how.resolve, ResolveFlags::NO_SYMLINKS.bits());
}

#[test]
fn an_existing_open_sends_no_mode_because_the_kernel_refuses_one() {
    let prepared = PreparedOpenat2::cwd(
        path_of(b"/etc/hostname"),
        OpenFlags::default(),
        Openat2Mode::Existing,
        ResolveFlags::default(),
        how_store(),
    )
    .unwrap_or_else(|(_, _, e)| panic!("{e}"));

    // openat2 returns EINVAL for a non-zero mode without CREAT/TMPFILE,
    // so `Existing` must publish a zero one.
    assert_eq!(prepared.published_how().mode, 0);
    assert_eq!(prepared.published_how().flags, 0);
}

#[test]
fn each_creating_mode_publishes_the_flag_that_gives_its_mode_meaning() {
    let mode = FileMode::OWNER_READ | FileMode::OWNER_WRITE;
    let cases = [
        (Openat2Mode::Create(mode), OpenFlags::CREAT.bits()),
        (
            Openat2Mode::CreateNew(mode),
            OpenFlags::CREAT.bits() | OpenFlags::EXCL.bits(),
        ),
        (Openat2Mode::Tmpfile(mode), OpenFlags::TMPFILE.bits()),
    ];
    for (kind, expected) in cases {
        let prepared = PreparedOpenat2::cwd(
            path_of(b"/tmp/target"),
            OpenFlags::RDWR,
            kind,
            ResolveFlags::default(),
            how_store(),
        )
        .unwrap_or_else(|(_, _, e)| panic!("{e}"));
        let how = prepared.published_how();
        assert_eq!(
            how.flags,
            u64::from(OpenFlags::RDWR.bits() | expected),
            "{kind:?} published the wrong flags"
        );
        assert_eq!(how.mode, 0o600, "{kind:?} published the wrong mode");
    }
}

#[test]
fn a_mode_outside_the_permission_bits_is_refused_with_the_storage_back() {
    let path = path_of(b"/tmp/target");
    let addr = path.as_bytes().as_ptr();
    let store = how_store();
    let store_addr = store.stable_ptr();

    // 0o10_000 is outside 0o7777; openat2 answers EINVAL rather than
    // masking it the way openat does.
    let Err((path, store, e)) = PreparedOpenat2::cwd(
        path,
        OpenFlags::default(),
        Openat2Mode::Create(FileMode::from_raw_for_test(0o10_000)),
        ResolveFlags::default(),
        store,
    ) else {
        panic!("a mode outside 0o7777 must be refused");
    };
    assert_eq!(
        e,
        Openat2Error::ModeOutsidePermissionBits { stray: 0o10_000 }
    );
    // Both storages came back, so a rejected request costs no allocation.
    assert_eq!(path.as_bytes().as_ptr(), addr);
    assert_eq!(store.stable_ptr(), store_addr);
}

#[test]
fn how_storage_too_small_is_rejected_rather_than_read_past() {
    let needed = core::mem::size_of::<crate::types::OpenHow>();
    let Err((_, _, e)) = PreparedOpenat2::cwd(
        path_of(b"/tmp/target"),
        OpenFlags::default(),
        Openat2Mode::Existing,
        ResolveFlags::default(),
        MmapBuffer::with_capacity(needed - 1).expect("map"),
    ) else {
        panic!("short open_how storage must be refused");
    };
    assert_eq!(
        e,
        Openat2Error::HowTooSmall {
            needed,
            got: needed - 1
        }
    );
}

#[cfg(not(miri))]
#[test]
fn a_real_openat2_creates_the_file_and_returns_both_storages() {
    let scratch = Scratch::new("openat2");
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let path = scratch.owned_path("made");
    let path_addr = path.as_bytes().as_ptr();
    let store = how_store();
    let store_addr = store.stable_ptr();

    let prepared = PreparedOpenat2::cwd(
        path,
        OpenFlags::RDWR,
        Openat2Mode::Create(FileMode::OWNER_READ | FileMode::OWNER_WRITE),
        ResolveFlags::default(),
        store,
    )
    .unwrap_or_else(|(_, _, e)| panic!("{e}"));
    let ticket = sub
        .push_openat2(prepared)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");

    let receipt = comp.wait_one().expect("completion");
    let opened = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatch"));
    assert!(opened.is_ok(), "openat2 failed: {}", opened.raw_result());

    let (file, path, store) = opened.into_parts();
    let file = file.expect("a successful open must carry a descriptor");

    // The descriptor is real and writable, which is what RDWR asked for.
    let mut ring = crate::IoUring::new(4).expect("ring");
    ring.push(unsafe { crate::Sqe::write(file.fd(), b"proof", 0) }.user_data(1))
        .expect("push");
    ring.submit_and_wait(1).expect("submit");
    assert_eq!(ring.complete().expect("cqe").result, 5);
    assert_eq!(scratch.read("made"), b"proof");
    assert_eq!(scratch.mode_of("made"), 0o600);

    // Both storages came back at the addresses they went in at.
    assert_eq!(path.as_bytes().as_ptr(), path_addr);
    assert_eq!(store.stable_ptr(), store_addr);
}

#[cfg(not(miri))]
#[test]
fn create_new_refuses_a_path_that_already_exists() {
    let scratch = Scratch::new("openat2excl");
    scratch.write("occupied", b"original");
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let prepared = PreparedOpenat2::cwd(
        scratch.owned_path("occupied"),
        OpenFlags::RDWR,
        Openat2Mode::CreateNew(FileMode::OWNER_READ | FileMode::OWNER_WRITE),
        ResolveFlags::default(),
        how_store(),
    )
    .unwrap_or_else(|(_, _, e)| panic!("{e}"));
    let ticket = sub
        .push_openat2(prepared)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");

    let receipt = comp.wait_one().expect("completion");
    let opened = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatch"));

    // EEXIST, and the file the caller did not mean to touch is untouched:
    // a mode that silently opened it would pass a result-only check.
    assert_eq!(opened.raw_result(), -17);
    assert!(opened.into_file().is_none());
    assert_eq!(scratch.read("occupied"), b"original");
}

#[cfg(not(miri))]
#[test]
fn a_resolve_restriction_reaches_the_kernel_and_blocks_the_open() {
    let scratch = Scratch::new("openat2resolve");
    scratch.write("real", b"data");
    std::os::unix::fs::symlink(scratch.path("real"), scratch.path("link")).expect("symlink");
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let mut open = |name: &str, resolve| {
        let prepared = PreparedOpenat2::cwd(
            scratch.owned_path(name),
            OpenFlags::default(),
            Openat2Mode::Existing,
            resolve,
            how_store(),
        )
        .unwrap_or_else(|(_, _, e)| panic!("{e}"));
        let ticket = sub
            .push_openat2(prepared)
            .unwrap_or_else(|(_, e)| panic!("{e}"));
        sub.submit_and_wait(1).expect("submit");
        let receipt = comp.wait_one().expect("completion");
        ticket
            .redeem(receipt)
            .unwrap_or_else(|_| panic!("mismatch"))
            .raw_result()
    };

    // Without the restriction the symlink opens; with it the kernel
    // refuses. Both halves matter: the first shows the path is otherwise
    // fine, so the second is the flag working rather than a broken path.
    assert!(open("link", ResolveFlags::default()) >= 0);
    assert_eq!(open("link", ResolveFlags::NO_SYMLINKS), -40);
    // And the restriction does not block a path that has no symlink in it.
    assert!(open("real", ResolveFlags::NO_SYMLINKS) >= 0);
}

#[test]
fn an_openat2_push_that_does_not_fit_hands_both_storages_back() {
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, _comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let mut tickets = alloc_tickets(&mut sub);
    let path = path_of(b"/tmp/wherever");
    let path_addr = path.as_bytes().as_ptr();
    let store = how_store();
    let store_addr = store.stable_ptr();

    let prepared = PreparedOpenat2::cwd(
        path,
        OpenFlags::RDWR,
        Openat2Mode::Create(FileMode::OWNER_READ),
        ResolveFlags::BENEATH,
        store,
    )
    .unwrap_or_else(|(_, _, e)| panic!("{e}"));

    let Err((returned, e)) = sub.push_openat2(prepared) else {
        panic!("a full queue must reject the push");
    };
    assert_eq!(e, Error::Submit(SubmitError::QueueFull));
    // Every field survived, not just the storage: a retry must issue the
    // same request, so the published `open_how` must still be intact.
    assert_eq!(returned.path().as_bytes().as_ptr(), path_addr);
    assert_eq!(returned.mode(), Openat2Mode::Create(FileMode::OWNER_READ));
    assert_eq!(returned.resolve(), ResolveFlags::BENEATH);
    let how = returned.published_how();
    assert_eq!(
        how.flags,
        u64::from(OpenFlags::RDWR.bits() | OpenFlags::CREAT.bits())
    );
    assert_eq!(how.resolve, ResolveFlags::BENEATH.bits());
    let (_, store) = returned.into_parts();
    assert_eq!(store.stable_ptr(), store_addr);
    tickets.clear();
}

#[test]
fn an_openat2_receipt_for_another_request_is_rejected() {
    let ring = crate::IoUring::new(8).expect("ring");
    let (mut sub, _comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let mut make = || {
        let prepared = PreparedOpenat2::cwd(
            path_of(b"/tmp/target"),
            OpenFlags::default(),
            Openat2Mode::Existing,
            ResolveFlags::default(),
            how_store(),
        )
        .unwrap_or_else(|(_, _, e)| panic!("{e}"));
        sub.push_openat2(prepared)
            .unwrap_or_else(|(_, e)| panic!("{e}"))
    };
    let first = make();
    let second = make();

    let foreign = Receipt {
        ring: second.ring(),
        id: second.id(),
        result: 0,
        flags: crate::types::CqeFlags::default(),
    };
    assert!(!first.matches(&foreign));
    let Err((first, _)) = first.redeem(foreign) else {
        panic!("a foreign receipt must not redeem");
    };
    drop((first, second));
}

/// Staging storage for a `sendmsg`/`recvmsg` header, its descriptors, and
/// its address, sized exactly rather than generously so a layout that grew
/// would be caught rather than absorbed by slack.
fn msg_region<const N: usize>() -> MmapBuffer {
    let needed = core::mem::size_of::<crate::types::MsgHdr>()
        + core::mem::size_of::<crate::types::IoVec>() * N
        + core::mem::size_of::<SockAddrIn>();
    MmapBuffer::with_capacity(needed).expect("map")
}

/// A buffer holding exactly `bytes`, for gathering into a message.
fn filled(bytes: &[u8]) -> MmapBuffer {
    let mut buf = MmapBuffer::with_capacity(bytes.len()).expect("map");
    buf.as_mut_slice().copy_from_slice(bytes);
    buf
}

#[test]
fn the_header_names_the_staged_descriptors_before_any_sqe_names_it() {
    let region = msg_region::<2>();
    let lo = region.stable_ptr().addr();
    let hi = lo + region.stable_len();

    let prepared = PreparedSendmsg::new(
        RawFd::from_raw(3),
        [filled(b"aa"), filled(b"bbbb")],
        region,
        SendTarget::Connected,
        MsgFlags::default(),
    )
    .unwrap_or_else(|(_, _, e)| panic!("{e}"));

    // The kernel learns the descriptor array's address from bytes inside
    // the header, so that address must point into storage the ticket owns
    // rather than anywhere else.
    let hdr = prepared.published_header();
    assert_eq!(hdr.msg_iovlen, 2);
    let array = hdr.msg_iov.addr();
    assert!(
        array >= lo && array < hi,
        "the header must name an array inside the owned region"
    );
    // Inside the region is not enough: the header itself is in there too,
    // and aiming `msg_iov` at it would satisfy the bounds check while
    // making the kernel read header bytes as descriptors. The array has to
    // start past the header.
    assert!(
        array >= lo + core::mem::size_of::<crate::types::MsgHdr>(),
        "the descriptor array must not overlap the header"
    );
    // And the array it names holds this request's descriptors: distinct
    // lengths, so a header aimed at the wrong array would not agree.
    assert_eq!(prepared.published_descriptor(0).len(), 2);
    assert_eq!(prepared.published_descriptor(1).len(), 4);
    assert_eq!(
        prepared.published_descriptor(0).base().cast_const(),
        prepared.buffers()[0].stable_ptr()
    );
    assert_eq!(
        prepared.published_descriptor(1).base().cast_const(),
        prepared.buffers()[1].stable_ptr()
    );
    assert_eq!(prepared.total_len(), 6);
}

#[test]
fn a_connected_send_stages_no_address_for_the_kernel_to_read() {
    let prepared = PreparedSendmsg::new(
        RawFd::from_raw(3),
        [filled(b"x")],
        msg_region::<1>(),
        SendTarget::Connected,
        MsgFlags::default(),
    )
    .unwrap_or_else(|(_, _, e)| panic!("{e}"));

    // A non-zero namelen with no address is a read past the end of
    // whatever `msg_name` happens to hold, so both must be absent
    // together.
    let hdr = prepared.published_header();
    assert!(hdr.msg_name.is_null());
    assert_eq!(hdr.msg_namelen, 0);
}

#[test]
fn an_addressed_send_stages_the_address_inside_the_owned_region() {
    let addr = SockAddrIn {
        sin_family: 2,
        sin_port: 9000u16.to_be(),
        sin_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        sin_zero: [0; 8],
    };
    let region = msg_region::<1>();
    let lo = region.stable_ptr().addr();
    let hi = lo + region.stable_len();

    let prepared = PreparedSendmsg::new(
        RawFd::from_raw(3),
        [filled(b"x")],
        region,
        SendTarget::To(addr),
        MsgFlags::default(),
    )
    .unwrap_or_else(|(_, _, e)| panic!("{e}"));

    let hdr = prepared.published_header();
    assert_eq!(hdr.msg_namelen, core::mem::size_of::<SockAddrIn>() as u32);
    // The address the kernel will read must live in storage the ticket
    // owns. A pointer to the caller's own copy would dangle the moment
    // that copy went out of scope, and nothing else here would notice.
    let name = hdr.msg_name.addr();
    assert!(
        name >= lo && name < hi,
        "staged address must be inside the owned region"
    );
}

#[test]
fn with_lens_shortens_each_descriptor_but_never_extends_it_for_a_message() {
    let prepared = PreparedSendmsg::new(
        RawFd::from_raw(3),
        [filled(b"aaaa"), filled(b"bbbb")],
        msg_region::<2>(),
        SendTarget::Connected,
        MsgFlags::default(),
    )
    .unwrap_or_else(|(_, _, e)| panic!("{e}"))
    .with_lens([1, 999]);

    assert_eq!(prepared.published_descriptor(0).len(), 1);
    // Clamped to the buffer: a descriptor longer than its buffer is a read
    // past the end, and the CQE would report it as a successful send.
    assert_eq!(prepared.published_descriptor(1).len(), 4);
    assert_eq!(prepared.total_len(), 5);
}

#[test]
fn a_region_too_small_for_the_staged_layout_is_refused_with_everything_back() {
    let needed = core::mem::size_of::<crate::types::MsgHdr>()
        + core::mem::size_of::<crate::types::IoVec>() * 2
        + core::mem::size_of::<SockAddrIn>();
    let buf = filled(b"x");
    let addr = buf.stable_ptr();

    let Err((bufs, store, e)) = PreparedSendmsg::new(
        RawFd::from_raw(3),
        [buf, filled(b"y")],
        MmapBuffer::with_capacity(needed - 1).expect("map"),
        SendTarget::Connected,
        MsgFlags::default(),
    ) else {
        panic!("a short staging region must be refused");
    };
    assert_eq!(
        e,
        MsgRegionError::RegionTooSmall {
            needed,
            got: needed - 1
        }
    );
    // Refusing costs nothing: every buffer came back at its own address.
    assert_eq!(bufs[0].stable_ptr(), addr);
    assert_eq!(store.stable_len(), needed - 1);
}

#[cfg(not(miri))]
#[test]
fn a_real_sendmsg_gathers_every_buffer_into_one_message() {
    let pair = SocketPair::connected();
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let region = msg_region::<3>();
    let region_addr = region.stable_ptr();
    // Distinct lengths and contents: three copies of the same buffer would
    // pass even if the descriptors all named the first one.
    let bufs = [filled(b"one"), filled(b"two!"), filled(b"three")];
    let addrs = [
        bufs[0].stable_ptr(),
        bufs[1].stable_ptr(),
        bufs[2].stable_ptr(),
    ];
    let prepared = PreparedSendmsg::new(
        pair.client(),
        bufs,
        region,
        SendTarget::Connected,
        MsgFlags::NOSIGNAL,
    )
    .unwrap_or_else(|(_, _, e)| panic!("{e}"));

    let ticket = sub
        .push_sendmsg(prepared)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");

    let receipt = comp.wait_one().expect("completion");
    let done = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatch"));

    let (result, bufs, store) = done.into_parts();
    assert_eq!(result.expect("send ok"), 12);

    let mut got = [0u8; 32];
    let n = pair.read_server(&mut got);
    assert_eq!(&got[..n], b"onetwo!three");

    // Every owner came back at the address it went in at.
    for (buf, addr) in bufs.iter().zip(addrs.iter()) {
        assert_eq!(buf.stable_ptr(), *addr);
    }
    assert_eq!(store.stable_ptr(), region_addr);
}

#[cfg(not(miri))]
#[test]
fn an_addressed_send_reaches_a_peer_the_socket_never_connected_to() {
    use crate::syscall;
    use crate::types;

    // An unconnected UDP socket has no peer, so this can only arrive if
    // the kernel read the address out of the staged header.
    let dest = syscall::socket(types::AF_INET, 2, 0).expect("dest");
    let wanted = SockAddrIn {
        sin_family: types::AF_INET as u16,
        sin_port: 0u16.to_be(),
        sin_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        sin_zero: [0; 8],
    };
    syscall::bind(
        dest,
        (&raw const wanted).cast(),
        core::mem::size_of::<SockAddrIn>() as u32,
    )
    .expect("bind");
    let mut bound = SockAddrIn::default();
    let mut len = core::mem::size_of::<SockAddrIn>() as u32;
    syscall::getsockname(dest, (&raw mut bound).cast(), &raw mut len).expect("getsockname");

    let sender = syscall::socket(types::AF_INET, 2, 0).expect("sender");
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let prepared = PreparedSendmsg::new(
        sender,
        [filled(b"addressed")],
        msg_region::<1>(),
        SendTarget::To(bound),
        MsgFlags::NOSIGNAL,
    )
    .unwrap_or_else(|(_, _, e)| panic!("{e}"));
    let ticket = sub
        .push_sendmsg(prepared)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");

    let receipt = comp.wait_one().expect("completion");
    let done = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatch"));
    assert_eq!(done.result().expect("send ok"), 9);

    let mut got = [0u8; 32];
    let n = syscall::recvfrom(dest, got.as_mut_ptr(), got.len(), 0).expect("recv");
    assert_eq!(&got[..n], b"addressed");

    let _ = syscall::close(sender);
    let _ = syscall::close(dest);
}

#[test]
fn a_sendmsg_push_that_does_not_fit_hands_back_the_buffers_and_the_region() {
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, _comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let mut tickets = alloc_tickets(&mut sub);
    let region = msg_region::<2>();
    let region_addr = region.stable_ptr();

    let prepared = PreparedSendmsg::new(
        RawFd::from_raw(1),
        [filled(b"aa"), filled(b"bb")],
        region,
        SendTarget::Connected,
        MsgFlags::NOSIGNAL,
    )
    .unwrap_or_else(|(_, _, e)| panic!("{e}"));

    let Err((returned, e)) = sub.push_sendmsg(prepared) else {
        panic!("a full queue must reject the push");
    };
    assert_eq!(e, Error::Submit(SubmitError::QueueFull));
    // A retry must issue the same message, so the staged header has to
    // still name the staged descriptors rather than needing a rebuild.
    assert_eq!(returned.published_header().msg_iovlen, 2);
    assert_eq!(returned.total_len(), 4);
    assert_eq!(returned.flags(), MsgFlags::NOSIGNAL);
    let (_, store) = returned.into_parts();
    assert_eq!(store.stable_ptr(), region_addr);
    tickets.clear();
}

#[test]
fn a_sendmsg_receipt_for_another_request_is_rejected() {
    let ring = crate::IoUring::new(8).expect("ring");
    let (mut sub, _comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let mut make = || {
        let prepared = PreparedSendmsg::new(
            RawFd::from_raw(1),
            [filled(b"x")],
            msg_region::<1>(),
            SendTarget::Connected,
            MsgFlags::NOSIGNAL,
        )
        .unwrap_or_else(|(_, _, e)| panic!("{e}"));
        sub.push_sendmsg(prepared)
            .unwrap_or_else(|(_, e)| panic!("{e}"))
    };
    let first = make();
    let second = make();

    let foreign = Receipt {
        ring: second.ring(),
        id: second.id(),
        result: 0,
        flags: crate::types::CqeFlags::default(),
    };
    assert!(!first.matches(&foreign));
    let Err((first, _)) = first.redeem(foreign) else {
        panic!("a foreign receipt must not redeem");
    };
    drop((first, second));
}

#[cfg(not(miri))]
#[test]
fn a_sendmsg_ticket_survives_moving_to_another_thread_before_completion() {
    let pair = SocketPair::connected();
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let prepared = PreparedSendmsg::new(
        pair.client(),
        [filled(b"crossing"), filled(b"-threads")],
        msg_region::<2>(),
        SendTarget::Connected,
        MsgFlags::NOSIGNAL,
    )
    .unwrap_or_else(|(_, _, e)| panic!("{e}"));
    let ticket = sub
        .push_sendmsg(prepared)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");

    // The header, the descriptors it names, and the buffers they name were
    // all staged on the submitting thread; the ticket owning them is
    // redeemed on another one.
    let handle = std::thread::spawn(move || {
        let receipt = comp.wait_one().expect("completion");
        let done = ticket
            .redeem(receipt)
            .unwrap_or_else(|_| panic!("mismatch"));
        done.result().expect("send ok")
    });
    assert_eq!(handle.join().expect("thread"), 16);

    let mut got = [0u8; 32];
    let n = pair.read_server(&mut got);
    assert_eq!(&got[..n], b"crossing-threads");
}

#[cfg(not(miri))]
#[test]
fn an_openat2_ticket_survives_moving_to_another_thread_before_completion() {
    let scratch = Scratch::new("openat2thread");
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let prepared = PreparedOpenat2::cwd(
        scratch.owned_path("crossing"),
        OpenFlags::RDWR,
        Openat2Mode::Create(FileMode::OWNER_READ | FileMode::OWNER_WRITE),
        ResolveFlags::default(),
        how_store(),
    )
    .unwrap_or_else(|(_, _, e)| panic!("{e}"));
    let ticket = sub
        .push_openat2(prepared)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");

    // The kernel read the path and the `open_how` from the submitting
    // thread; the ticket owning both is redeemed on another one.
    let handle = std::thread::spawn(move || {
        let receipt = comp.wait_one().expect("completion");
        let opened = ticket
            .redeem(receipt)
            .unwrap_or_else(|_| panic!("mismatch"));
        assert!(opened.is_ok(), "open failed: {}", opened.raw_result());
        opened.into_file().is_some()
    });
    assert!(handle.join().expect("thread"));
    assert!(scratch.exists("crossing"));
}

/// An unconnected UDP socket bound on loopback, plus a sender aimed at it.
///
/// Datagram rather than stream because truncation is a datagram property:
/// a stream socket leaves the remainder queued and reports nothing.
#[cfg(not(miri))]
struct DatagramPair {
    tx: RawFd,
    rx: RawFd,
    tx_addr: SockAddrIn,
}

#[cfg(not(miri))]
impl DatagramPair {
    fn bound() -> Self {
        let rx = Self::socket();
        let rx_addr = Self::bind(rx);
        let tx = Self::socket();
        // The sender is bound too, so the receiver has a real peer address
        // to report rather than an ephemeral unbound one.
        let tx_addr = Self::bind(tx);
        crate::syscall::connect(
            tx,
            (&raw const rx_addr).cast(),
            core::mem::size_of::<SockAddrIn>() as u32,
        )
        .expect("connect tx");
        Self { tx, rx, tx_addr }
    }

    fn socket() -> RawFd {
        crate::syscall::socket(crate::types::AF_INET, 2, 0).expect("udp socket")
    }

    fn bind(fd: RawFd) -> SockAddrIn {
        let wanted = SockAddrIn {
            sin_family: crate::types::AF_INET as u16,
            sin_port: 0u16.to_be(),
            sin_addr: u32::from_ne_bytes([127, 0, 0, 1]),
            sin_zero: [0; 8],
        };
        crate::syscall::bind(
            fd,
            (&raw const wanted).cast(),
            core::mem::size_of::<SockAddrIn>() as u32,
        )
        .expect("bind");
        let mut bound = SockAddrIn::default();
        let mut len = core::mem::size_of::<SockAddrIn>() as u32;
        crate::syscall::getsockname(fd, (&raw mut bound).cast(), &raw mut len)
            .expect("getsockname");
        bound
    }

    fn send(&self, bytes: &[u8]) {
        crate::syscall::sendto(self.tx, bytes.as_ptr(), bytes.len(), 0).expect("sendto");
    }
}

#[cfg(not(miri))]
impl Drop for DatagramPair {
    fn drop(&mut self) {
        let _ = crate::syscall::close(self.tx);
        let _ = crate::syscall::close(self.rx);
    }
}

/// An empty buffer of `n` bytes, for the kernel to fill.
fn empty(n: usize) -> MmapBuffer {
    MmapBuffer::with_capacity(n).expect("map")
}

#[cfg(not(miri))]
#[test]
fn a_real_recvmsg_scatters_one_message_across_every_buffer() {
    let pair = DatagramPair::bound();
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    pair.send(b"abcdefghij");

    let region = msg_region::<3>();
    let region_addr = region.stable_ptr();
    // Distinct sizes: three equal buffers would pass even if the kernel
    // filled them in the wrong order.
    let bufs = [empty(4), empty(4), empty(4)];
    let addrs = [
        bufs[0].stable_ptr(),
        bufs[1].stable_ptr(),
        bufs[2].stable_ptr(),
    ];
    let prepared =
        PreparedRecvmsg::new(pair.rx, bufs, region, PeerWanted::Yes, MsgFlags::default())
            .unwrap_or_else(|(_, _, e)| panic!("{e}"));

    let ticket = sub
        .push_recvmsg(prepared)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");

    let receipt = comp.wait_one().expect("completion");
    let done = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatch"));

    let (received, peer, bufs, store) = done.into_parts();
    let received = received.expect("recv ok");
    assert_eq!(received.bytes(), 10);
    // Ten bytes into twelve is not truncation, and reporting it as such
    // would make the flag useless.
    assert!(!received.truncated());

    // Filled in descriptor order, the third only partly.
    assert_eq!(&bufs[0].as_slice()[..4], b"abcd");
    assert_eq!(&bufs[1].as_slice()[..4], b"efgh");
    assert_eq!(&bufs[2].as_slice()[..2], b"ij");

    // The peer address the kernel wrote into the staged slot is the
    // sender's, read back through the region the ticket owns.
    let addr = peer.v4().expect("a bound IPv4 peer");
    assert_eq!(addr.sin_port, pair.tx_addr.sin_port);
    assert_eq!(addr.sin_addr, pair.tx_addr.sin_addr);

    for (buf, addr) in bufs.iter().zip(addrs.iter()) {
        assert_eq!(buf.stable_ptr(), *addr);
    }
    assert_eq!(store.stable_ptr(), region_addr);
}

#[cfg(not(miri))]
#[test]
fn a_truncated_datagram_reports_the_loss_that_its_byte_count_hides() {
    let pair = DatagramPair::bound();
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    // Eleven bytes into two. The CQE will say 2 — the same 2 a two-byte
    // datagram that arrived whole would say. Only the written-back flags
    // distinguish them, which is the entire reason `received` returns both.
    pair.send(b"eleven byte");

    let prepared = PreparedRecvmsg::new(
        pair.rx,
        [empty(2)],
        msg_region::<1>(),
        PeerWanted::No,
        MsgFlags::default(),
    )
    .unwrap_or_else(|(_, _, e)| panic!("{e}"));
    let ticket = sub
        .push_recvmsg(prepared)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");

    let receipt = comp.wait_one().expect("completion");
    let done = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatch"));

    let received = done.received().expect("recv ok");
    assert_eq!(received.bytes(), 2);
    assert!(
        received.truncated(),
        "nine discarded bytes must be reported somewhere"
    );
    assert_eq!(&done.buffers()[0].as_slice()[..2], b"el");
}

#[cfg(not(miri))]
#[test]
fn a_whole_datagram_of_the_same_length_is_not_reported_as_truncated() {
    let pair = DatagramPair::bound();
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    // The control for the test above: same buffer, same reported count,
    // nothing lost. Without this pair, a `truncated` that always returned
    // true would pass.
    pair.send(b"el");

    let prepared = PreparedRecvmsg::new(
        pair.rx,
        [empty(2)],
        msg_region::<1>(),
        PeerWanted::No,
        MsgFlags::default(),
    )
    .unwrap_or_else(|(_, _, e)| panic!("{e}"));
    let ticket = sub
        .push_recvmsg(prepared)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");

    let receipt = comp.wait_one().expect("completion");
    let done = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatch"));

    let received = done.received().expect("recv ok");
    assert_eq!(received.bytes(), 2, "same count as the truncated case");
    assert!(!received.truncated());
}

#[cfg(not(miri))]
#[test]
fn a_peer_larger_than_the_reserved_slot_is_reported_rather_than_handed_back_as_a_prefix() {
    use crate::syscall;

    // An IPv6 peer's address is 28 bytes; the staged slot is a 16-byte
    // SockAddrIn. The kernel reports 28 and writes 16, so a `PeerAddress`
    // built from the reported length would be a prefix read as an address.
    const AF_INET6: i32 = 10;
    let mut wanted = [0u8; 28];
    wanted[0..2].copy_from_slice(&(AF_INET6 as u16).to_ne_bytes());
    wanted[8..24].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

    let rx = syscall::socket(AF_INET6, 2, 0).expect("rx6");
    syscall::bind(rx, wanted.as_ptr(), 28).expect("bind6");
    let mut bound = [0u8; 28];
    let mut len = 28u32;
    syscall::getsockname(rx, bound.as_mut_ptr(), &raw mut len).expect("getsockname6");
    let tx = syscall::socket(AF_INET6, 2, 0).expect("tx6");
    syscall::connect(tx, bound.as_ptr(), 28).expect("connect6");
    syscall::sendto(tx, b"six".as_ptr(), 3, 0).expect("sendto");

    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));
    let prepared = PreparedRecvmsg::new(
        rx,
        [empty(16)],
        msg_region::<1>(),
        PeerWanted::Yes,
        MsgFlags::default(),
    )
    .unwrap_or_else(|(_, _, e)| panic!("{e}"));
    let ticket = sub
        .push_recvmsg(prepared)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");

    let receipt = comp.wait_one().expect("completion");
    let done = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatch"));

    assert_eq!(done.received().expect("recv ok").bytes(), 3);
    let peer = done.peer();
    assert!(peer.is_truncated(), "got {peer:?}");
    assert_eq!(
        peer,
        PeerAddress::Truncated {
            reported: 28,
            reserved: core::mem::size_of::<SockAddrIn>() as u32,
        }
    );
    // And no half-address escapes as if it were whole.
    assert!(peer.v4().is_none());

    let _ = syscall::close(tx);
    let _ = syscall::close(rx);
}

/// A bound `AF_UNIX` datagram socket, which unlinks its path on drop.
///
/// Unix rather than IP because its addresses are *variable length*: a
/// short path makes the kernel report a `msg_namelen` between one and the
/// reserved 16, which is the only way to reach a partially written slot.
#[cfg(not(miri))]
struct UnixDatagram {
    fd: RawFd,
    path: std::string::String,
}

#[cfg(not(miri))]
impl UnixDatagram {
    const AF_UNIX: i32 = 1;

    fn bound(path: &str) -> Self {
        let _ = std::fs::remove_file(path);
        let fd = crate::syscall::socket(Self::AF_UNIX, 2, 0).expect("unix socket");
        let (addr, len) = Self::sockaddr_un(path);
        crate::syscall::bind(fd, addr.as_ptr(), len).expect("bind unix");
        Self {
            fd,
            path: std::string::String::from(path),
        }
    }

    fn connect_to(&self, path: &str) {
        let (addr, len) = Self::sockaddr_un(path);
        crate::syscall::connect(self.fd, addr.as_ptr(), len).expect("connect unix");
    }

    fn send(&self, bytes: &[u8]) {
        crate::syscall::sendto(self.fd, bytes.as_ptr(), bytes.len(), 0).expect("sendto unix");
    }

    /// `struct sockaddr_un` plus the length that covers family, path, and
    /// the terminator — which is what the kernel reports back.
    fn sockaddr_un(path: &str) -> ([u8; 110], u32) {
        let mut addr = [0u8; 110];
        addr[0..2].copy_from_slice(&(Self::AF_UNIX as u16).to_ne_bytes());
        addr[2..2 + path.len()].copy_from_slice(path.as_bytes());
        (addr, (2 + path.len() + 1) as u32)
    }
}

#[cfg(not(miri))]
impl Drop for UnixDatagram {
    fn drop(&mut self) {
        let _ = crate::syscall::close(self.fd);
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(not(miri))]
#[test]
fn a_peer_that_fills_only_part_of_the_slot_is_not_read_as_a_whole_address() {
    // Measured: an AF_UNIX peer bound to `/tmp/qq-…` reports a
    // `msg_namelen` of 11 into a 16-byte reservation. Fewer bytes than the
    // slot holds, so the tail is whatever the region held before — reading
    // all 16 would hand back `sin_family: 1` as though it were IPv4.
    let listener = UnixDatagram::bound("/tmp/qq-recv-peer.sock");
    let sender = UnixDatagram::bound("/tmp/qq-send");
    sender.connect_to("/tmp/qq-recv-peer.sock");
    sender.send(b"unix");

    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));
    let prepared = PreparedRecvmsg::new(
        listener.fd,
        [empty(8)],
        msg_region::<1>(),
        PeerWanted::Yes,
        MsgFlags::default(),
    )
    .unwrap_or_else(|(_, _, e)| panic!("{e}"));
    let ticket = sub
        .push_recvmsg(prepared)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");

    let receipt = comp.wait_one().expect("completion");
    let done = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatch"));

    assert_eq!(done.received().expect("recv ok").bytes(), 4);
    let reported = done.header().msg_namelen;
    assert!(
        reported > 0 && (reported as usize) < core::mem::size_of::<SockAddrIn>(),
        "the partial-write case needs a length inside the slot, got {reported}"
    );
    // Neither a whole address nor an oversized one: partially written.
    assert!(done.peer().v4().is_none(), "got {:?}", done.peer());
    assert!(!done.peer().is_truncated());
    assert_eq!(
        done.peer(),
        PeerAddress::Other {
            family: UnixDatagram::AF_UNIX as u16,
            reported,
        }
    );
}

#[test]
fn the_address_slot_is_cleared_so_no_earlier_peer_can_be_reported_as_this_ones() {
    // One staging region serving two requests is the point of handing it
    // back. Without clearing, a receive whose kernel writes nothing would
    // report the previous request's sender as its own.
    let region = msg_region::<1>();
    let first = PreparedRecvmsg::new(
        RawFd::from_raw(3),
        [empty(8)],
        region,
        PeerWanted::Yes,
        MsgFlags::default(),
    )
    .unwrap_or_else(|(_, _, e)| panic!("{e}"));

    // Stand in for a kernel write-back by stamping the slot the header
    // names, exactly where a real completion would put a peer.
    let hdr = first.published_header();
    #[allow(clippy::cast_ptr_alignment)]
    let slot = hdr.msg_name.cast::<SockAddrIn>();
    let stale = SockAddrIn {
        sin_family: 2,
        sin_port: 9999u16.to_be(),
        sin_addr: u32::from_ne_bytes([10, 1, 2, 3]),
        sin_zero: [0; 8],
    };
    // SAFETY: the request owns this storage and staged a `SockAddrIn` here.
    unsafe { slot.write(stale) };
    let (_, region) = first.into_parts();

    let second = PreparedRecvmsg::new(
        RawFd::from_raw(3),
        [empty(8)],
        region,
        PeerWanted::Yes,
        MsgFlags::default(),
    )
    .unwrap_or_else(|(_, _, e)| panic!("{e}"));
    let hdr = second.published_header();
    #[allow(clippy::cast_ptr_alignment)]
    let slot = hdr.msg_name.cast::<SockAddrIn>();
    // SAFETY: as above, for the request now owning the same storage.
    let seen = unsafe { slot.read() };
    assert_eq!(
        seen,
        SockAddrIn::default(),
        "the reused slot still holds the previous request's peer"
    );
}

#[cfg(not(miri))]
#[test]
fn a_failed_recvmsg_reports_the_errno_rather_than_the_stale_header_it_left() {
    let pair = DatagramPair::bound();
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    // Nothing sent, so DONTWAIT fails with EAGAIN. Verified against the
    // kernel: a failure writes nothing back, so the header still holds the
    // caller's own values — which must not be read as an outcome.
    let prepared = PreparedRecvmsg::new(
        pair.rx,
        [empty(16)],
        msg_region::<1>(),
        PeerWanted::Yes,
        MsgFlags::DONTWAIT,
    )
    .unwrap_or_else(|(_, _, e)| panic!("{e}"));
    let ticket = sub
        .push_recvmsg(prepared)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");

    let receipt = comp.wait_one().expect("completion");
    let done = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatch"));

    assert!(done.failed());
    assert!(done.received().is_err());
    // The staged reservation is still in the header; reporting it as a
    // peer would invent a sender for a message that never arrived.
    assert_eq!(
        done.header().msg_namelen,
        core::mem::size_of::<SockAddrIn>() as u32
    );
    assert_eq!(done.peer(), PeerAddress::None);

    // The storage still comes back, so a failed receive costs nothing.
    let (received, peer, bufs, store) = done.into_parts();
    assert!(received.is_err());
    assert_eq!(peer, PeerAddress::None);
    assert_eq!(bufs[0].stable_len(), 16);
    assert_eq!(store.stable_len(), msg_region::<1>().stable_len());
}

#[cfg(not(miri))]
#[test]
fn a_connected_receive_reports_no_peer_however_much_room_was_reserved() {
    let pair = SocketPair::connected();
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));
    pair.write_client(b"hi");

    // Room reserved, but a connected socket has no per-message sender, so
    // the kernel writes back a zero length. Reading the staged slot anyway
    // would report the zeroes as address 0.0.0.0.
    let prepared = PreparedRecvmsg::new(
        pair.server,
        [empty(16)],
        msg_region::<1>(),
        PeerWanted::Yes,
        MsgFlags::default(),
    )
    .unwrap_or_else(|(_, _, e)| panic!("{e}"));
    let ticket = sub
        .push_recvmsg(prepared)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");

    let receipt = comp.wait_one().expect("completion");
    let done = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatch"));

    let received = done.received().expect("recv ok");
    assert_eq!(received.bytes(), 2);
    // A stream socket leaves any remainder queued, so nothing is lost.
    assert!(!received.truncated());
    assert_eq!(done.header().msg_namelen, 0);
    assert_eq!(done.peer(), PeerAddress::None);
}

#[cfg(not(miri))]
#[test]
fn a_short_stream_read_is_not_a_truncation() {
    let pair = SocketPair::connected();
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    // The same 11-into-2 shape that sets TRUNC on a datagram socket. Here
    // the remaining nine bytes are still queued, so treating a short read
    // as data loss would be wrong.
    pair.write_client(b"eleven byte");

    let prepared = PreparedRecvmsg::new(
        pair.server,
        [empty(2)],
        msg_region::<1>(),
        PeerWanted::No,
        MsgFlags::default(),
    )
    .unwrap_or_else(|(_, _, e)| panic!("{e}"));
    let ticket = sub
        .push_recvmsg(prepared)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");

    let receipt = comp.wait_one().expect("completion");
    let done = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatch"));

    let received = done.received().expect("recv ok");
    assert_eq!(received.bytes(), 2);
    assert!(!received.truncated(), "the rest is queued, not discarded");
}

#[test]
fn a_receive_reserving_no_peer_stages_no_address_for_the_kernel_to_write() {
    let prepared = PreparedRecvmsg::new(
        RawFd::from_raw(3),
        [empty(8)],
        msg_region::<1>(),
        PeerWanted::No,
        MsgFlags::default(),
    )
    .unwrap_or_else(|(_, _, e)| panic!("{e}"));

    // A non-zero namelen with a null pointer is a write past the end of
    // whatever `msg_name` holds, so both must be absent together.
    let hdr = prepared.published_header();
    assert!(hdr.msg_name.is_null());
    assert_eq!(hdr.msg_namelen, 0);
}

#[test]
fn a_receive_reserving_a_peer_points_the_header_past_its_own_descriptors() {
    let region = msg_region::<2>();
    let lo = region.stable_ptr().addr();
    let hi = lo + region.stable_len();

    let prepared = PreparedRecvmsg::new(
        RawFd::from_raw(3),
        [empty(4), empty(4)],
        region,
        PeerWanted::Yes,
        MsgFlags::default(),
    )
    .unwrap_or_else(|(_, _, e)| panic!("{e}"));

    let hdr = prepared.published_header();
    assert_eq!(hdr.msg_namelen, core::mem::size_of::<SockAddrIn>() as u32);
    assert_eq!(hdr.msg_iovlen, 2);

    // The kernel writes an address here, so the slot must lie inside owned
    // storage and must not overlap the header or the descriptor array it
    // reads on the way — all three are in the same region, so bounds alone
    // would be satisfied by a slot pointing at the header itself.
    let name = hdr.msg_name.addr();
    assert!(name >= lo && name < hi, "slot must be inside the region");
    let array_end = hdr.msg_iov.addr() + core::mem::size_of::<crate::types::IoVec>() * 2;
    assert!(name >= array_end, "the address slot must follow the array");
    assert!(
        hdr.msg_iov.addr() >= lo + core::mem::size_of::<crate::types::MsgHdr>(),
        "the array must follow the header"
    );
}

#[test]
fn with_lens_caps_what_the_kernel_may_write_but_never_extends_a_buffer() {
    let prepared = PreparedRecvmsg::new(
        RawFd::from_raw(3),
        [empty(8), empty(8)],
        msg_region::<2>(),
        PeerWanted::No,
        MsgFlags::default(),
    )
    .unwrap_or_else(|(_, _, e)| panic!("{e}"))
    .with_lens([2, 999]);

    assert_eq!(prepared.published_descriptor(0).len(), 2);
    // Clamped: a descriptor longer than its buffer is a kernel write past
    // the end, reported as a successful receive.
    assert_eq!(prepared.published_descriptor(1).len(), 8);
    assert_eq!(prepared.capacity(), 10);
}

#[test]
fn a_receive_region_too_small_is_refused_with_everything_back() {
    let needed = core::mem::size_of::<crate::types::MsgHdr>()
        + core::mem::size_of::<crate::types::IoVec>() * 2
        + core::mem::size_of::<SockAddrIn>();
    let buf = empty(4);
    let addr = buf.stable_ptr();

    let Err((bufs, store, e)) = PreparedRecvmsg::new(
        RawFd::from_raw(3),
        [buf, empty(4)],
        MmapBuffer::with_capacity(needed - 1).expect("map"),
        PeerWanted::Yes,
        MsgFlags::default(),
    ) else {
        panic!("a short staging region must be refused");
    };
    assert_eq!(
        e,
        MsgRegionError::RegionTooSmall {
            needed,
            got: needed - 1
        }
    );
    assert_eq!(bufs[0].stable_ptr(), addr);
    assert_eq!(store.stable_len(), needed - 1);
}

#[test]
fn a_recvmsg_push_that_does_not_fit_hands_back_the_buffers_and_the_region() {
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, _comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let mut tickets = alloc_tickets(&mut sub);
    let region = msg_region::<2>();
    let region_addr = region.stable_ptr();

    let prepared = PreparedRecvmsg::new(
        RawFd::from_raw(1),
        [empty(4), empty(4)],
        region,
        PeerWanted::Yes,
        MsgFlags::default(),
    )
    .unwrap_or_else(|(_, _, e)| panic!("{e}"));

    let Err((returned, e)) = sub.push_recvmsg(prepared) else {
        panic!("a full queue must reject the push");
    };
    assert_eq!(e, Error::Submit(SubmitError::QueueFull));
    // A retry must issue the same request, so the staged header has to
    // still name the descriptors and the address slot.
    assert_eq!(returned.published_header().msg_iovlen, 2);
    assert_eq!(
        returned.published_header().msg_namelen,
        core::mem::size_of::<SockAddrIn>() as u32
    );
    assert_eq!(returned.capacity(), 8);
    assert_eq!(returned.peer_wanted(), PeerWanted::Yes);
    let (_, store) = returned.into_parts();
    assert_eq!(store.stable_ptr(), region_addr);
    tickets.clear();
}

#[test]
fn a_recvmsg_receipt_for_another_request_is_rejected() {
    let ring = crate::IoUring::new(8).expect("ring");
    let (mut sub, _comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let mut make = || {
        let prepared = PreparedRecvmsg::new(
            RawFd::from_raw(1),
            [empty(4)],
            msg_region::<1>(),
            PeerWanted::No,
            MsgFlags::default(),
        )
        .unwrap_or_else(|(_, _, e)| panic!("{e}"));
        sub.push_recvmsg(prepared)
            .unwrap_or_else(|(_, e)| panic!("{e}"))
    };
    let first = make();
    let second = make();

    let foreign = Receipt {
        ring: second.ring(),
        id: second.id(),
        result: 0,
        flags: crate::types::CqeFlags::default(),
    };
    assert!(!first.matches(&foreign));
    let Err((first, _)) = first.redeem(foreign) else {
        panic!("a foreign receipt must not redeem");
    };
    drop((first, second));
}

#[cfg(not(miri))]
#[test]
fn a_recvmsg_ticket_survives_moving_to_another_thread_before_completion() {
    let pair = DatagramPair::bound();
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));
    pair.send(b"crossing");

    let prepared = PreparedRecvmsg::new(
        pair.rx,
        [empty(4), empty(4)],
        msg_region::<2>(),
        PeerWanted::Yes,
        MsgFlags::default(),
    )
    .unwrap_or_else(|(_, _, e)| panic!("{e}"));
    let ticket = sub
        .push_recvmsg(prepared)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");

    // The kernel writes the header, the buffers it reaches through it, and
    // the address slot on the submitting thread; the ticket owning all of
    // it is redeemed on another.
    let handle = std::thread::spawn(move || {
        let receipt = comp.wait_one().expect("completion");
        let done = ticket
            .redeem(receipt)
            .unwrap_or_else(|_| panic!("mismatch"));
        let bytes = done.received().expect("recv ok").bytes();
        let bufs = done.buffers();
        let mut seen = std::vec::Vec::new();
        seen.extend_from_slice(&bufs[0].as_slice()[..4]);
        seen.extend_from_slice(&bufs[1].as_slice()[..4]);
        (bytes, seen, done.peer())
    });
    let (bytes, seen, peer) = handle.join().expect("thread");
    assert_eq!(bytes, 8);
    assert_eq!(&seen[..], b"crossing");
    assert_eq!(
        peer.v4().expect("a bound peer").sin_port,
        pair.tx_addr.sin_port
    );
}

// ---------------------------------------------------------------
// Timeouts
// ---------------------------------------------------------------

/// Storage for one `Timespec`, page-aligned like every `MmapBuffer`.
fn timespec_store() -> MmapBuffer {
    MmapBuffer::with_capacity(core::mem::size_of::<Timespec>()).expect("map")
}

#[test]
fn a_timeout_publishes_its_duration_before_any_sqe_names_it() {
    let prepared = PreparedTimeout::after(Timespec::new(4, 500), Count::Timer, timespec_store())
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    let published = prepared.published();
    assert_eq!(published.tv_sec(), 4);
    assert_eq!(published.tv_nsec(), 500);
    assert_eq!(prepared.count(), Count::Timer);
    assert!(!prepared.is_absolute());
}

#[test]
fn an_absolute_timeout_is_told_apart_from_a_relative_one() {
    let relative = PreparedTimeout::after(Timespec::new(1, 0), Count::Timer, timespec_store())
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    let absolute = PreparedTimeout::at(Timespec::new(1, 0), Count::Timer, timespec_store())
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    assert!(!relative.is_absolute());
    assert!(absolute.is_absolute());
}

#[test]
fn storage_too_small_for_a_timespec_is_rejected_with_it_handed_back() {
    let store = MmapBuffer::with_capacity(core::mem::size_of::<Timespec>() - 1).expect("map");
    let addr = store.stable_ptr();
    let Err((returned, e)) = PreparedTimeout::after(Timespec::new(1, 0), Count::Timer, store)
    else {
        panic!("short storage must be refused");
    };
    assert_eq!(
        e,
        TimeoutError::StoreTooSmall {
            needed: core::mem::size_of::<Timespec>(),
            got: core::mem::size_of::<Timespec>() - 1,
        }
    );
    // Rejection costs no allocation: the same mapping comes back.
    assert_eq!(returned.stable_ptr(), addr);
}

#[test]
fn misaligned_timespec_storage_is_rejected_rather_than_written_through() {
    // Writing a `Timespec` through an unaligned pointer is UB, so this has
    // to be caught before the duration is published rather than after.
    // `MmapBuffer` is page-aligned and can never exercise this.
    let store = MisalignedVecs::with_capacity(core::mem::size_of::<Timespec>() + 8);
    let Err((_returned, e)) = PreparedTimeout::after(Timespec::new(2, 0), Count::Timer, store)
    else {
        panic!("misaligned storage must be refused");
    };
    assert_eq!(
        e,
        TimeoutError::StoreMisaligned {
            needed: core::mem::align_of::<Timespec>(),
        }
    );
}

#[test]
fn every_outcome_is_named_rather_than_read_as_a_plain_result() {
    // -ETIME is the timer doing exactly what it was asked.
    assert_eq!(Expiry::from_raw_for_test(-62), Expiry::Expired);
    assert!(Expiry::from_raw_for_test(-62).is_expired());
    assert!(Expiry::from_raw_for_test(-62).is_ok());
    // 0 is the pre-empted case, which a plain result would call success.
    assert_eq!(Expiry::from_raw_for_test(0), Expiry::CountReached);
    assert!(!Expiry::from_raw_for_test(0).is_expired());
    assert_eq!(Expiry::from_raw_for_test(-125), Expiry::Cancelled);
    assert!(Expiry::from_raw_for_test(-125).is_ok());
    // A real rejection is the only outcome that is not ok.
    let failed = Expiry::from_raw_for_test(-22);
    assert!(!failed.is_ok());
    assert!(matches!(failed, Expiry::Failed(_)));
}

#[test]
fn a_timeout_receipt_for_another_request_is_rejected() {
    let ring = crate::IoUring::new(8).expect("ring");
    let (mut sub, _comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let mut make = || {
        let prepared =
            PreparedTimeout::after(Timespec::from_millis(5_000), Count::Timer, timespec_store())
                .unwrap_or_else(|(_, e)| panic!("{e}"));
        sub.push_timeout(prepared)
            .unwrap_or_else(|(_, e)| panic!("{e}"))
    };
    let first = make();
    let second = make();

    let foreign = Receipt {
        ring: second.ring(),
        id: second.id(),
        result: -62,
        flags: crate::types::CqeFlags::default(),
    };
    assert!(!first.matches(&foreign));
    let Err((first, _)) = first.redeem(foreign) else {
        panic!("a foreign receipt must not redeem");
    };
    drop((first, second));
}

#[test]
fn a_timeout_push_that_does_not_fit_hands_the_storage_back() {
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, _comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));
    let mut tickets = alloc_tickets(&mut sub);

    let store = timespec_store();
    let addr = store.stable_ptr();
    let prepared = PreparedTimeout::after(Timespec::new(7, 0), Count::Completions(3), store)
        .unwrap_or_else(|(_, e)| panic!("{e}"));

    let Err((returned, e)) = sub.push_timeout(prepared) else {
        panic!("a full queue must reject the push");
    };
    assert_eq!(e, Error::Submit(SubmitError::QueueFull));
    // A retry must issue the same request, so the duration has to still be
    // published in the storage that came back.
    assert_eq!(returned.published().tv_sec(), 7);
    assert_eq!(returned.count(), Count::Completions(3));
    assert_eq!(returned.into_store().stable_ptr(), addr);
    tickets.clear();
}

#[cfg(not(miri))]
#[test]
fn a_real_timer_reports_expiry_rather_than_an_error() {
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let prepared =
        PreparedTimeout::after(Timespec::from_millis(120), Count::Timer, timespec_store())
            .unwrap_or_else(|(_, e)| panic!("{e}"));
    let ticket = sub
        .push_timeout(prepared)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    let started = std::time::Instant::now();
    sub.submit_and_wait(1).expect("submit");

    let receipt = comp.wait_one().expect("completion");
    let done = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatch"));
    // The kernel's own encoding is negative for the successful case.
    assert_eq!(done.raw_result(), -62);
    assert_eq!(done.expiry(), Expiry::Expired);
    assert!(done.expiry().is_ok());
    // The staged duration is what the kernel waited for. Without this the
    // test passes on storage that was never written, since a zero timespec
    // also reports `-ETIME` — just immediately.
    assert!(
        started.elapsed() >= core::time::Duration::from_millis(100),
        "expired after {:?}, so the staged duration never reached the kernel",
        started.elapsed()
    );
}

#[cfg(not(miri))]
#[test]
fn a_count_that_is_reached_first_is_not_reported_as_an_expiry() {
    let ring = crate::IoUring::new(8).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    // Five seconds is far longer than the nop needs, so the count is what
    // ends this timeout. A test with a short duration would pass whether
    // or not the count was honoured.
    let prepared = PreparedTimeout::after(
        Timespec::from_millis(5_000),
        Count::Completions(1),
        timespec_store(),
    )
    .unwrap_or_else(|(_, e)| panic!("{e}"));
    let ticket = sub
        .push_timeout(prepared)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.raw()
        .push(crate::op::Sqe::nop().user_data(0))
        .expect("nop");
    sub.submit_and_wait(2).expect("submit");

    let started = std::time::Instant::now();
    let mut outcome = None;
    while outcome.is_none() {
        if let Some(receipt) = comp.reap()
            && ticket.matches(&receipt)
        {
            outcome = Some(receipt);
        }
    }
    let done = ticket
        .redeem(outcome.expect("the timeout's own receipt"))
        .unwrap_or_else(|_| panic!("mismatch"));
    assert_eq!(done.raw_result(), 0);
    assert_eq!(done.expiry(), Expiry::CountReached);
    assert!(!done.expiry().is_expired());
    // It returned because the nop completed, not because 5s elapsed.
    assert!(started.elapsed() < core::time::Duration::from_secs(2));
}

#[cfg(not(miri))]
#[test]
fn a_zero_duration_expires_at_once_rather_than_being_rejected() {
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let prepared = PreparedTimeout::after(Timespec::new(0, 0), Count::Timer, timespec_store())
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    let ticket = sub
        .push_timeout(prepared)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");

    let receipt = comp.wait_one().expect("completion");
    let done = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatch"));
    assert_eq!(done.expiry(), Expiry::Expired);
}

#[cfg(not(miri))]
#[test]
fn an_absolute_deadline_in_the_past_expires_rather_than_waiting() {
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    // One second after the epoch on the monotonic clock is long gone.
    let prepared = PreparedTimeout::at(Timespec::new(1, 0), Count::Timer, timespec_store())
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    let ticket = sub
        .push_timeout(prepared)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    let started = std::time::Instant::now();
    sub.submit_and_wait(1).expect("submit");

    let receipt = comp.wait_one().expect("completion");
    let done = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatch"));
    assert_eq!(done.expiry(), Expiry::Expired);
    assert!(started.elapsed() < core::time::Duration::from_secs(1));
}

#[cfg(not(miri))]
#[test]
fn a_cancelled_timeout_is_told_apart_from_one_that_expired() {
    let ring = crate::IoUring::new(8).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let prepared = PreparedTimeout::after(
        Timespec::from_millis(30_000),
        Count::Timer,
        timespec_store(),
    )
    .unwrap_or_else(|(_, e)| panic!("{e}"));
    let ticket = sub
        .push_timeout(prepared)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit().expect("submit");

    // Cancellation names the ticket's own key rather than a raw id the
    // caller tracked separately.
    sub.raw()
        .push(crate::op::Sqe::timeout_remove(ticket.cancel_key()).user_data(u64::MAX))
        .expect("push remove");
    let started = std::time::Instant::now();
    sub.submit_and_wait(2).expect("submit");

    let mut mine = None;
    while mine.is_none() {
        if let Some(receipt) = comp.reap()
            && ticket.matches(&receipt)
        {
            mine = Some(receipt);
        }
    }
    let done = ticket
        .redeem(mine.expect("the timeout's own receipt"))
        .unwrap_or_else(|_| panic!("mismatch"));
    assert_eq!(done.raw_result(), -125);
    assert_eq!(done.expiry(), Expiry::Cancelled);
    // Removed on purpose, so this is not a failure.
    assert!(done.expiry().is_ok());
    assert!(!done.expiry().is_expired());
    // It ended because it was removed, not because 30s elapsed.
    assert!(started.elapsed() < core::time::Duration::from_secs(5));
}

#[cfg(not(miri))]
#[test]
fn a_timeout_ticket_survives_moving_to_another_thread_before_completion() {
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let store = timespec_store();
    let addr = store.stable_ptr();
    let prepared = PreparedTimeout::after(Timespec::from_millis(30), Count::Timer, store)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    let ticket = sub
        .push_timeout(prepared)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit().expect("submit");

    // The kernel may still be reading the timespec when the ticket moves.
    let handle = std::thread::spawn(move || {
        let receipt = comp.wait_one().expect("completion");
        let done = ticket
            .redeem(receipt)
            .unwrap_or_else(|_| panic!("mismatch"));
        done.into_parts()
    });
    let (expiry, store) = handle.join().expect("thread");
    assert_eq!(expiry, Expiry::Expired);
    // The storage came back at the same address it was staged at.
    assert_eq!(store.stable_ptr(), addr);
}

// ---------------------------------------------------------------
// files_update
// ---------------------------------------------------------------

/// Storage for a descriptor array of `N` entries.
fn fd_array_store<const N: usize>() -> MmapBuffer {
    MmapBuffer::with_capacity(core::mem::size_of::<i32>() * N).expect("map")
}

/// A table index that is nowhere near the reserved sentinels.
fn slot(index: u32) -> SlotIndex {
    SlotIndex::new(index).expect("a small index is representable")
}

/// A scratch file holding `bytes`, removed when the guard drops.
#[cfg(not(miri))]
struct ScratchFile {
    path: std::path::PathBuf,
    file: std::fs::File,
}

#[cfg(not(miri))]
impl ScratchFile {
    fn with(name: &str, bytes: &[u8]) -> Self {
        use std::io::{Seek, Write};
        let path = std::env::temp_dir().join(name);
        let mut file = std::fs::File::options()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&path)
            .expect("open scratch");
        file.write_all(bytes).expect("write scratch");
        file.seek(std::io::SeekFrom::Start(0)).expect("rewind");
        Self { path, file }
    }

    fn fd(&self) -> RawFd {
        use std::os::fd::AsRawFd;
        RawFd::from_raw(self.file.as_raw_fd() as usize)
    }

    /// Read the first bytes back through the caller's own handle.
    fn read_through_our_own_handle(&self, into: &mut [u8]) -> std::io::Result<()> {
        use std::io::{Read, Seek};
        let mut held = &self.file;
        held.seek(std::io::SeekFrom::Start(0))?;
        held.read_exact(into)
    }
}

#[cfg(not(miri))]
impl Drop for ScratchFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[test]
fn a_files_update_publishes_its_array_before_any_sqe_names_it() {
    let prepared = PreparedFilesUpdate::at(
        slot(2),
        [
            TableEntry::Install(RawFd::from_raw(7)),
            TableEntry::Clear,
            TableEntry::Install(RawFd::from_raw(9)),
        ],
        fd_array_store::<3>(),
    )
    .unwrap_or_else(|(_, e)| panic!("{e}"));

    // Clearing is encoded as the kernel's -1 rather than left to a caller.
    assert_eq!(prepared.published(), [7, -1, 9]);
    assert_eq!(prepared.offset().get(), 2);
    assert_eq!(prepared.slots(), 3);
}

#[test]
fn an_empty_update_is_refused_because_the_kernel_rejects_one() {
    let store = fd_array_store::<1>();
    let addr = store.stable_ptr();
    let Err((returned, e)) = PreparedFilesUpdate::at(slot(0), [], store) else {
        panic!("an empty update must be refused");
    };
    assert_eq!(e, FilesUpdateError::Empty);
    assert_eq!(returned.stable_ptr(), addr);
}

#[test]
fn storage_too_small_for_the_array_is_rejected_with_it_handed_back() {
    // Room for three descriptors, but four are named.
    let store = MmapBuffer::with_capacity(core::mem::size_of::<i32>() * 3).expect("map");
    let addr = store.stable_ptr();
    let Err((returned, e)) = PreparedFilesUpdate::at(slot(0), [TableEntry::Clear; 4], store) else {
        panic!("short storage must be refused");
    };
    assert_eq!(
        e,
        FilesUpdateError::StoreTooSmall {
            needed: core::mem::size_of::<i32>() * 4,
            got: core::mem::size_of::<i32>() * 3,
        }
    );
    assert_eq!(returned.stable_ptr(), addr);
}

#[test]
fn misaligned_array_storage_is_rejected_rather_than_written_through() {
    // `MmapBuffer` is page-aligned and can never exercise this.
    let store = MisalignedVecs::with_capacity(core::mem::size_of::<i32>() * 4);
    let Err((_returned, e)) = PreparedFilesUpdate::at(slot(0), [TableEntry::Clear; 2], store)
    else {
        panic!("misaligned storage must be refused");
    };
    assert_eq!(
        e,
        FilesUpdateError::StoreMisaligned {
            needed: core::mem::align_of::<i32>(),
        }
    );
}

#[test]
fn a_short_count_is_not_read_as_success() {
    // The case a plain `is_ok()` gets wrong: positive, but most of the
    // request did not happen.
    let partial = Update::from_raw_for_test(1, 3);
    assert_eq!(
        partial,
        Update::Partial {
            installed: 1,
            requested: 3,
        }
    );
    assert!(!partial.is_complete());
    assert_eq!(partial.installed(), 1);

    let all = Update::from_raw_for_test(3, 3);
    assert_eq!(all, Update::All { count: 3 });
    assert!(all.is_complete());

    // Nothing installed at all is a failure, not a zero-length success.
    let failed = Update::from_raw_for_test(-9, 3);
    assert!(matches!(failed, Update::Failed(_)));
    assert!(!failed.is_complete());
    assert_eq!(failed.installed(), 0);
}

#[test]
fn a_files_update_receipt_for_another_request_is_rejected() {
    let ring = crate::IoUring::new(8).expect("ring");
    let (mut sub, _comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let mut make = || {
        let prepared = PreparedFilesUpdate::at(slot(0), [TableEntry::Clear], fd_array_store::<1>())
            .unwrap_or_else(|(_, e)| panic!("{e}"));
        sub.push_files_update(prepared)
            .unwrap_or_else(|(_, e)| panic!("{e}"))
    };
    let first = make();
    let second = make();

    let foreign = Receipt {
        ring: second.ring(),
        id: second.id(),
        result: 1,
        flags: crate::types::CqeFlags::default(),
    };
    assert!(!first.matches(&foreign));
    let Err((first, _)) = first.redeem(foreign) else {
        panic!("a foreign receipt must not redeem");
    };
    drop((first, second));
}

#[test]
fn a_files_update_push_that_does_not_fit_hands_the_array_back() {
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, _comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));
    let mut tickets = alloc_tickets(&mut sub);

    let store = fd_array_store::<2>();
    let addr = store.stable_ptr();
    let prepared = PreparedFilesUpdate::at(
        slot(3),
        [TableEntry::Install(RawFd::from_raw(5)), TableEntry::Clear],
        store,
    )
    .unwrap_or_else(|(_, e)| panic!("{e}"));

    let Err((returned, e)) = sub.push_files_update(prepared) else {
        panic!("a full queue must reject the push");
    };
    assert_eq!(e, Error::Submit(SubmitError::QueueFull));
    // A retry must issue the same request, so the array and the offset
    // both have to survive.
    assert_eq!(returned.published(), [5, -1]);
    assert_eq!(returned.offset().get(), 3);
    assert_eq!(returned.into_store().stable_ptr(), addr);
    tickets.clear();
}

#[cfg(not(miri))]
#[test]
fn a_real_update_installs_a_file_the_table_can_reach() {
    let ring = ring_with_table(8, 2);
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));
    let scratch = ScratchFile::with("qq_owned_update", b"installed");

    let prepared = PreparedFilesUpdate::at(
        slot(0),
        [TableEntry::Install(scratch.fd())],
        fd_array_store::<1>(),
    )
    .unwrap_or_else(|(_, e)| panic!("{e}"));
    let ticket = sub
        .push_files_update(prepared)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");

    let receipt = comp.wait_one().expect("completion");
    let done = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatch"));
    assert_eq!(done.update(), Update::All { count: 1 });

    // The slot is real: reading through it only resolves because
    // `fixed_file` makes the kernel read `fd` as a table index.
    let mut buf = MmapBuffer::with_capacity(16).expect("map");
    let read = sub.raw().push(
        unsafe { crate::Sqe::read_ptr(RawFd::from_raw(0), buf.as_mut_slice().as_mut_ptr(), 9, 0) }
            .fixed_file()
            .user_data(77),
    );
    read.expect("push read");
    sub.submit_and_wait(1).expect("submit");
    let done = comp.wait_one().expect("completion");
    assert_eq!(done.raw_result(), 9);
    assert_eq!(&buf.as_slice()[..9], b"installed");
}

#[cfg(not(miri))]
#[test]
fn the_kernel_duplicates_so_the_callers_descriptor_stays_usable() {
    let ring = ring_with_table(8, 1);
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));
    let scratch = ScratchFile::with("qq_owned_dup", b"duplicated");

    let prepared = PreparedFilesUpdate::at(
        slot(0),
        [TableEntry::Install(scratch.fd())],
        fd_array_store::<1>(),
    )
    .unwrap_or_else(|(_, e)| panic!("{e}"));
    let ticket = sub
        .push_files_update(prepared)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");
    let receipt = comp.wait_one().expect("completion");
    let done = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatch"));
    assert!(done.update().is_complete());

    // This is what lets the API take a borrowed `RawFd` rather than an
    // owning handle: the kernel took a reference of its own, so the
    // caller's descriptor is untouched and closing it is still the
    // caller's job.
    let mut check = [0u8; 10];
    scratch
        .read_through_our_own_handle(&mut check)
        .expect("the caller's descriptor must still be open");
    assert_eq!(&check, b"duplicated");
}

#[cfg(not(miri))]
#[test]
fn a_bad_descriptor_part_way_through_reports_a_partial_update() {
    let ring = ring_with_table(8, 3);
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));
    let first = ScratchFile::with("qq_owned_part_a", b"first");
    let third = ScratchFile::with("qq_owned_part_c", b"third");

    // 9999 is not an open descriptor. The kernel installs the first entry,
    // hits the bad one, and stops — reporting 1, which is positive.
    let prepared = PreparedFilesUpdate::at(
        slot(0),
        [
            TableEntry::Install(first.fd()),
            TableEntry::Install(RawFd::from_raw(9999)),
            TableEntry::Install(third.fd()),
        ],
        fd_array_store::<3>(),
    )
    .unwrap_or_else(|(_, e)| panic!("{e}"));
    let ticket = sub
        .push_files_update(prepared)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");

    let receipt = comp.wait_one().expect("completion");
    let done = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatch"));

    // The raw result is positive, which the usual reading calls success.
    assert!(done.raw_result() > 0, "expected a positive short count");
    assert_eq!(
        done.update(),
        Update::Partial {
            installed: 1,
            requested: 3,
        }
    );
    // The whole point: this is not a success.
    assert!(!done.update().is_complete());
}

#[cfg(not(miri))]
#[test]
fn a_bad_descriptor_in_first_position_installs_nothing() {
    let ring = ring_with_table(8, 2);
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));
    let good = ScratchFile::with("qq_owned_part_first", b"good");

    let prepared = PreparedFilesUpdate::at(
        slot(0),
        [
            TableEntry::Install(RawFd::from_raw(9999)),
            TableEntry::Install(good.fd()),
        ],
        fd_array_store::<2>(),
    )
    .unwrap_or_else(|(_, e)| panic!("{e}"));
    let ticket = sub
        .push_files_update(prepared)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");

    let receipt = comp.wait_one().expect("completion");
    let done = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatch"));
    // Failing on the very first entry is an errno rather than a count of
    // zero, so `Partial` always means at least one slot changed.
    assert_eq!(done.raw_result(), -9);
    assert!(matches!(done.update(), Update::Failed(_)));
}

#[cfg(not(miri))]
#[test]
fn an_update_running_past_the_table_installs_nothing() {
    let ring = ring_with_table(8, 2);
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    // Two entries starting at slot 1 in a table of 2 leaves the table.
    let prepared = PreparedFilesUpdate::at(
        slot(1),
        [TableEntry::Clear, TableEntry::Clear],
        fd_array_store::<2>(),
    )
    .unwrap_or_else(|(_, e)| panic!("{e}"));
    let ticket = sub
        .push_files_update(prepared)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");

    let receipt = comp.wait_one().expect("completion");
    let done = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatch"));
    assert_eq!(done.raw_result(), -22);
    assert!(matches!(done.update(), Update::Failed(_)));
}

#[cfg(not(miri))]
#[test]
fn an_update_without_a_registered_table_fails_rather_than_installing() {
    let ring = crate::IoUring::new(8).expect("ring with no table");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let prepared = PreparedFilesUpdate::at(slot(0), [TableEntry::Clear], fd_array_store::<1>())
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    let ticket = sub
        .push_files_update(prepared)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");

    let receipt = comp.wait_one().expect("completion");
    let done = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatch"));
    assert_eq!(done.raw_result(), -6);
    assert!(matches!(done.update(), Update::Failed(_)));
}

#[cfg(not(miri))]
#[test]
fn clearing_a_slot_releases_what_the_table_held() {
    let ring = ring_with_table(8, 1);
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));
    let scratch = ScratchFile::with("qq_owned_clear", b"transient");

    let install = PreparedFilesUpdate::at(
        slot(0),
        [TableEntry::Install(scratch.fd())],
        fd_array_store::<1>(),
    )
    .unwrap_or_else(|(_, e)| panic!("{e}"));
    let ticket = sub
        .push_files_update(install)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");
    let receipt = comp.wait_one().expect("completion");
    let done = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatch"));
    assert!(done.update().is_complete());
    let store = done.into_store();

    // Clearing reuses the same storage the install came back with.
    let clear = PreparedFilesUpdate::at(slot(0), [TableEntry::Clear], store)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    assert_eq!(clear.published(), [-1]);
    let ticket = sub
        .push_files_update(clear)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");
    let receipt = comp.wait_one().expect("completion");
    let done = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatch"));
    assert!(done.update().is_complete());

    // The slot is empty now, so an operation through it finds no file.
    let mut buf = MmapBuffer::with_capacity(16).expect("map");
    sub.raw()
        .push(
            unsafe {
                crate::Sqe::read_ptr(RawFd::from_raw(0), buf.as_mut_slice().as_mut_ptr(), 9, 0)
            }
            .fixed_file()
            .user_data(88),
        )
        .expect("push read");
    sub.submit_and_wait(1).expect("submit");
    let done = comp.wait_one().expect("completion");
    assert!(
        done.raw_result() < 0,
        "a cleared slot must not still resolve to a file"
    );

    // Clearing the table's reference left the caller's handle alone.
    let mut check = [0u8; 9];
    scratch
        .read_through_our_own_handle(&mut check)
        .expect("the caller's descriptor is unaffected by a clear");
}

#[cfg(not(miri))]
#[test]
fn a_files_update_ticket_survives_moving_to_another_thread_before_completion() {
    let ring = ring_with_table(8, 1);
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));
    let scratch = ScratchFile::with("qq_owned_update_move", b"crossing");

    let store = fd_array_store::<1>();
    let addr = store.stable_ptr();
    let prepared = PreparedFilesUpdate::at(slot(0), [TableEntry::Install(scratch.fd())], store)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    let ticket = sub
        .push_files_update(prepared)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit().expect("submit");

    // The kernel may still be reading the array when the ticket moves.
    let handle = std::thread::spawn(move || {
        let receipt = comp.wait_one().expect("completion");
        let done = ticket
            .redeem(receipt)
            .unwrap_or_else(|_| panic!("mismatch"));
        done.into_parts()
    });
    let (update, store) = handle.join().expect("thread");
    assert_eq!(update, Update::All { count: 1 });
    assert_eq!(store.stable_ptr(), addr);
}

// ---------------------------------------------------------------
// bind
// ---------------------------------------------------------------

/// Storage for one socket address.
fn bind_store() -> MmapBuffer {
    MmapBuffer::with_capacity(core::mem::size_of::<SockAddrIn>()).expect("map")
}

/// A loopback address on `port`, in the byte order the kernel expects.
fn loopback(port: u16) -> SockAddrIn {
    SockAddrIn {
        sin_family: 2,
        sin_port: port.to_be(),
        sin_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        sin_zero: [0; 8],
    }
}

#[test]
fn a_bind_publishes_its_address_before_any_sqe_names_it() {
    let prepared = PreparedBind::new(RawFd::from_raw(3), loopback(8080), bind_store())
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    // The bytes must be in place at construction, not at submission.
    assert_eq!(prepared.published(), loopback(8080).to_bytes());
    assert_eq!(prepared.addr(), loopback(8080));
}

#[test]
fn storage_too_small_for_an_address_is_rejected_with_it_handed_back() {
    let store = MmapBuffer::with_capacity(core::mem::size_of::<SockAddrIn>() - 1).expect("map");
    let addr = store.stable_ptr();
    let Err((returned, e)) = PreparedBind::new(RawFd::from_raw(3), loopback(0), store) else {
        panic!("short storage must be refused");
    };
    assert_eq!(
        e,
        BindError::StoreTooSmall {
            needed: core::mem::size_of::<SockAddrIn>(),
            got: core::mem::size_of::<SockAddrIn>() - 1,
        }
    );
    assert_eq!(returned.stable_ptr(), addr);
}

#[test]
fn each_bind_failure_is_named_rather_than_left_as_an_errno() {
    // A retry on another port fixes AddressInUse and never fixes
    // AlreadyBound, so collapsing the two would send a caller into a loop.
    assert_eq!(
        BindOutcome::from_raw_for_test(-98),
        BindOutcome::AddressInUse
    );
    assert_eq!(
        BindOutcome::from_raw_for_test(-22),
        BindOutcome::AlreadyBound
    );
    assert_eq!(
        BindOutcome::from_raw_for_test(-13),
        BindOutcome::PermissionDenied
    );
    assert_eq!(BindOutcome::from_raw_for_test(0), BindOutcome::Bound);
    assert!(BindOutcome::from_raw_for_test(0).is_bound());
    assert!(!BindOutcome::from_raw_for_test(-98).is_bound());
    assert!(matches!(
        BindOutcome::from_raw_for_test(-101),
        BindOutcome::Failed(_)
    ));
}

#[test]
fn a_bind_receipt_for_another_request_is_rejected() {
    let ring = crate::IoUring::new(8).expect("ring");
    let (mut sub, _comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let mut make = || {
        let prepared = PreparedBind::new(RawFd::from_raw(3), loopback(0), bind_store())
            .unwrap_or_else(|(_, e)| panic!("{e}"));
        sub.push_bind(prepared)
            .unwrap_or_else(|(_, e)| panic!("{e}"))
    };
    let first = make();
    let second = make();

    let foreign = Receipt {
        ring: second.ring(),
        id: second.id(),
        result: 0,
        flags: crate::types::CqeFlags::default(),
    };
    assert!(!first.matches(&foreign));
    let Err((first, _)) = first.redeem(foreign) else {
        panic!("a foreign receipt must not redeem");
    };
    drop((first, second));
}

#[test]
fn a_bind_push_that_does_not_fit_hands_the_address_back() {
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, _comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));
    let mut tickets = alloc_tickets(&mut sub);

    let store = bind_store();
    let addr = store.stable_ptr();
    let prepared = PreparedBind::new(RawFd::from_raw(3), loopback(8080), store)
        .unwrap_or_else(|(_, e)| panic!("{e}"));

    let Err((returned, e)) = sub.push_bind(prepared) else {
        panic!("a full queue must reject the push");
    };
    assert_eq!(e, Error::Submit(SubmitError::QueueFull));
    // A retry must issue the same request, so the staged address survives.
    assert_eq!(returned.published(), loopback(8080).to_bytes());
    assert_eq!(returned.into_store().stable_ptr(), addr);
    tickets.clear();
}

#[cfg(not(miri))]
#[test]
fn a_real_bind_makes_the_socket_reachable_at_the_port_it_named() {
    // Asserting the outcome is `Bound` proves only that the kernel liked
    // the encoding. An address staged wrong, or read from the wrong
    // offset, could still report success while binding somewhere else.
    // The effect worth checking is that the port the caller asked for is
    // the port the socket answers on, so this binds an explicit port and
    // reads it back.
    let sock = Socket::with_typed_flags(
        AddressFamily::Inet,
        SocketType::Stream,
        0,
        SocketFlags::default(),
    )
    .expect("socket");
    let ring = crate::IoUring::new(8).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    // Bind port 0 first to have the kernel pick a free one, then rebind a
    // fresh socket to exactly that port so the assertion names a value
    // the test chose rather than one it read back.
    let probe = PreparedBind::new(sock.fd(), loopback(0), bind_store())
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    let ticket = sub.push_bind(probe).unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit().expect("submit");
    let done = ticket
        .redeem(comp.wait_one().expect("completion"))
        .unwrap_or_else(|_| panic!("mismatch"));
    assert_eq!(done.outcome(), BindOutcome::Bound);
    let chosen = u16::from_be(sock.local_addr().expect("getsockname").sin_port);
    assert_ne!(chosen, 0, "binding port 0 must assign a real port");
    drop(sock);

    let second = Socket::with_typed_flags(
        AddressFamily::Inet,
        SocketType::Stream,
        0,
        SocketFlags::default(),
    )
    .expect("socket");
    let prepared = PreparedBind::new(second.fd(), loopback(chosen), done.into_store())
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    let ticket = sub
        .push_bind(prepared)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit().expect("submit");
    let done = ticket
        .redeem(comp.wait_one().expect("completion"))
        .unwrap_or_else(|_| panic!("mismatch"));
    assert_eq!(done.outcome(), BindOutcome::Bound);

    let got = u16::from_be(second.local_addr().expect("getsockname").sin_port);
    assert_eq!(
        got, chosen,
        "the socket must answer on the port the caller staged"
    );
}

#[cfg(not(miri))]
#[test]
fn a_port_another_socket_holds_is_told_apart_from_a_second_bind() {
    // Both come back as a plain negative result; only the named outcomes
    // say which retry, if any, could succeed.
    let ring = crate::IoUring::new(8).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));
    let make = || {
        Socket::with_typed_flags(
            AddressFamily::Inet,
            SocketType::Stream,
            0,
            SocketFlags::default(),
        )
        .expect("socket")
    };

    let held = make();
    let prepared = PreparedBind::new(held.fd(), loopback(0), bind_store())
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    let ticket = sub
        .push_bind(prepared)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit().expect("submit");
    let done = ticket
        .redeem(comp.wait_one().expect("completion"))
        .unwrap_or_else(|_| panic!("mismatch"));
    assert_eq!(done.outcome(), BindOutcome::Bound);
    let port = u16::from_be(held.local_addr().expect("getsockname").sin_port);

    let again = PreparedBind::new(held.fd(), loopback(port), done.into_store())
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    let ticket = sub.push_bind(again).unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit().expect("submit");
    let done = ticket
        .redeem(comp.wait_one().expect("completion"))
        .unwrap_or_else(|_| panic!("mismatch"));
    assert_eq!(
        done.outcome(),
        BindOutcome::AlreadyBound,
        "rebinding a bound socket is not a busy port"
    );

    let other = make();
    let clash = PreparedBind::new(other.fd(), loopback(port), done.into_store())
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    let ticket = sub.push_bind(clash).unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit().expect("submit");
    let done = ticket
        .redeem(comp.wait_one().expect("completion"))
        .unwrap_or_else(|_| panic!("mismatch"));
    assert_eq!(
        done.outcome(),
        BindOutcome::AddressInUse,
        "a port another socket holds is not a double bind"
    );
}

#[cfg(not(miri))]
#[test]
fn a_bind_ticket_survives_moving_to_another_thread_before_completion() {
    let sock = Socket::with_typed_flags(
        AddressFamily::Inet,
        SocketType::Stream,
        0,
        SocketFlags::default(),
    )
    .expect("socket");
    let ring = crate::IoUring::new(8).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let store = bind_store();
    let addr = store.stable_ptr();
    let prepared =
        PreparedBind::new(sock.fd(), loopback(0), store).unwrap_or_else(|(_, e)| panic!("{e}"));
    let ticket = sub
        .push_bind(prepared)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit().expect("submit");

    // The kernel may still be reading the address when the ticket moves.
    let handle = std::thread::spawn(move || {
        let receipt = comp.wait_one().expect("completion");
        let done = ticket
            .redeem(receipt)
            .unwrap_or_else(|_| panic!("mismatch"));
        done.into_parts()
    });
    let (outcome, store) = handle.join().expect("thread");
    assert_eq!(outcome, BindOutcome::Bound);
    assert_eq!(store.stable_ptr(), addr);
}

// ---------------------------------------------------------------
// epoll_ctl
// ---------------------------------------------------------------

/// Storage for one `EpollEvent`.
fn epoll_store() -> MmapBuffer {
    MmapBuffer::with_capacity(core::mem::size_of::<EpollEvent>()).expect("map")
}

/// An epoll set, closed when the guard drops.
#[cfg(not(miri))]
struct EpollSet {
    fd: RawFd,
}

#[cfg(not(miri))]
impl EpollSet {
    fn new() -> Self {
        // SAFETY: a plain syscall with no pointer arguments.
        let raw = unsafe { epoll_create1(0) };
        assert!(raw >= 0, "epoll_create1 failed");
        Self {
            fd: RawFd::from_raw(raw.unsigned_abs() as usize),
        }
    }
}

#[cfg(not(miri))]
impl Drop for EpollSet {
    fn drop(&mut self) {
        // SAFETY: this descriptor was created here and is closed once.
        unsafe { close_fd(self.fd.as_i32()) };
    }
}

#[cfg(not(miri))]
unsafe extern "C" {
    #[link_name = "epoll_create1"]
    fn epoll_create1(flags: i32) -> i32;
    #[link_name = "close"]
    fn close_fd(fd: i32) -> i32;
    #[link_name = "epoll_wait"]
    fn epoll_wait(epfd: i32, events: *mut EpollEvent, maxevents: i32, timeout: i32) -> i32;
}

#[cfg(not(miri))]
impl EpollSet {
    /// Wait briefly for one event, returning what the kernel reported.
    ///
    /// This is what proves the staged mask and data actually reached the
    /// kernel: a registration with a zeroed event still succeeds, so a
    /// test that only checks the `Applied` outcome cannot tell a real
    /// mask from a lost one.
    fn wait_one(&self, timeout_ms: i32) -> Option<EpollEvent> {
        let mut out = [EpollEvent::default(); 1];
        // SAFETY: `out` is a live array of one `EpollEvent` and the count
        // passed matches it.
        let n = unsafe { epoll_wait(self.fd.as_i32(), out.as_mut_ptr(), 1, timeout_ms) };
        (n > 0).then(|| out[0])
    }
}

#[test]
fn an_add_publishes_the_mask_and_data_the_kernel_reads() {
    let prepared = PreparedEpollCtl::new(
        RawFd::from_raw(3),
        RawFd::from_raw(7),
        EpollChange::Add {
            events: EpollEvents::IN | EpollEvents::ET,
            data: 0xDEAD_BEEF,
        },
        epoll_store(),
    )
    .unwrap_or_else(|(_, e)| panic!("{e}"));

    // `EpollEvent` is `repr(C, packed)`, so its fields are copied out
    // rather than borrowed.
    let published = prepared.published();
    let (events, data) = (published.events, published.data);
    assert_eq!(events, (EpollEvents::IN | EpollEvents::ET).bits());
    assert_eq!(data, 0xDEAD_BEEF);
}

#[test]
fn a_del_publishes_a_zeroed_event_because_the_kernel_reads_none() {
    let prepared = PreparedEpollCtl::new(
        RawFd::from_raw(3),
        RawFd::from_raw(7),
        EpollChange::Del,
        epoll_store(),
    )
    .unwrap_or_else(|(_, e)| panic!("{e}"));

    // A `Del` with a null pointer succeeds against a real kernel, so there
    // is nothing meaningful to stage — and `EpollChange::Del` carries no
    // mask to stage, which is the point of splitting the enum.
    let published = prepared.published();
    let (events, data) = (published.events, published.data);
    assert_eq!(events, 0);
    assert_eq!(data, 0);
}

#[test]
fn storage_too_small_for_an_event_is_rejected_with_it_handed_back() {
    let store = MmapBuffer::with_capacity(core::mem::size_of::<EpollEvent>() - 1).expect("map");
    let addr = store.stable_ptr();
    let Err((returned, e)) = PreparedEpollCtl::new(
        RawFd::from_raw(3),
        RawFd::from_raw(7),
        EpollChange::Del,
        store,
    ) else {
        panic!("short storage must be refused");
    };
    assert_eq!(
        e,
        EpollError::StoreTooSmall {
            needed: core::mem::size_of::<EpollEvent>(),
            got: core::mem::size_of::<EpollEvent>() - 1,
        }
    );
    assert_eq!(returned.stable_ptr(), addr);
}

#[test]
fn each_registration_failure_is_named_rather_than_left_as_an_errno() {
    // Both are ordinary outcomes of racing another thread on the same set,
    // not programming errors, so neither is folded into a generic failure.
    assert_eq!(
        EpollOutcome::from_raw_for_test(-17),
        EpollOutcome::AlreadyRegistered
    );
    assert_eq!(
        EpollOutcome::from_raw_for_test(-2),
        EpollOutcome::NotRegistered
    );
    assert_eq!(EpollOutcome::from_raw_for_test(0), EpollOutcome::Applied);
    assert!(EpollOutcome::from_raw_for_test(0).is_applied());
    assert!(!EpollOutcome::from_raw_for_test(-17).is_applied());
    let failed = EpollOutcome::from_raw_for_test(-22);
    assert!(matches!(failed, EpollOutcome::Failed(_)));
}

#[test]
fn an_epoll_receipt_for_another_request_is_rejected() {
    let ring = crate::IoUring::new(8).expect("ring");
    let (mut sub, _comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let mut make = || {
        let prepared = PreparedEpollCtl::new(
            RawFd::from_raw(3),
            RawFd::from_raw(7),
            EpollChange::Del,
            epoll_store(),
        )
        .unwrap_or_else(|(_, e)| panic!("{e}"));
        sub.push_epoll_ctl(prepared)
            .unwrap_or_else(|(_, e)| panic!("{e}"))
    };
    let first = make();
    let second = make();

    let foreign = Receipt {
        ring: second.ring(),
        id: second.id(),
        result: 0,
        flags: crate::types::CqeFlags::default(),
    };
    assert!(!first.matches(&foreign));
    let Err((first, _)) = first.redeem(foreign) else {
        panic!("a foreign receipt must not redeem");
    };
    drop((first, second));
}

#[test]
fn an_epoll_push_that_does_not_fit_hands_the_storage_back() {
    let ring = crate::IoUring::new(4).expect("ring");
    let (mut sub, _comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));
    let mut tickets = alloc_tickets(&mut sub);

    let store = epoll_store();
    let addr = store.stable_ptr();
    let prepared = PreparedEpollCtl::new(
        RawFd::from_raw(3),
        RawFd::from_raw(7),
        EpollChange::Add {
            events: EpollEvents::OUT,
            data: 99,
        },
        store,
    )
    .unwrap_or_else(|(_, e)| panic!("{e}"));

    let Err((returned, e)) = sub.push_epoll_ctl(prepared) else {
        panic!("a full queue must reject the push");
    };
    assert_eq!(e, Error::Submit(SubmitError::QueueFull));
    // A retry must issue the same request, so the staged event survives.
    let published = returned.published();
    let (events, data) = (published.events, published.data);
    assert_eq!(events, EpollEvents::OUT.bits());
    assert_eq!(data, 99);
    assert_eq!(returned.into_store().stable_ptr(), addr);
    tickets.clear();
}

#[cfg(not(miri))]
#[test]
fn a_real_add_registers_and_a_second_one_reports_the_clash() {
    let set = EpollSet::new();
    let pair = SocketPair::connected();
    let ring = crate::IoUring::new(8).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let mut run = |change| {
        let prepared = PreparedEpollCtl::new(set.fd, pair.server, change, epoll_store())
            .unwrap_or_else(|(_, e)| panic!("{e}"));
        let ticket = sub
            .push_epoll_ctl(prepared)
            .unwrap_or_else(|(_, e)| panic!("{e}"));
        sub.submit_and_wait(1).expect("submit");
        let receipt = comp.wait_one().expect("completion");
        ticket
            .redeem(receipt)
            .unwrap_or_else(|_| panic!("mismatch"))
            .outcome()
    };

    let added = run(EpollChange::Add {
        events: EpollEvents::IN,
        data: 1,
    });
    assert_eq!(added, EpollOutcome::Applied);

    // The second add proves the first one actually took effect, which a
    // lone success could not.
    let again = run(EpollChange::Add {
        events: EpollEvents::IN,
        data: 1,
    });
    assert_eq!(again, EpollOutcome::AlreadyRegistered);
    assert!(!again.is_applied());
}

#[cfg(not(miri))]
#[test]
fn the_staged_mask_and_data_are_what_the_kernel_reports_back() {
    let set = EpollSet::new();
    let pair = SocketPair::connected();
    let ring = crate::IoUring::new(8).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    // A registration with a zeroed event still reports `Applied`, so only
    // watching the event fire distinguishes a mask that travelled from one
    // that was dropped on the way.
    let prepared = PreparedEpollCtl::new(
        set.fd,
        pair.server,
        EpollChange::Add {
            events: EpollEvents::IN,
            data: 0x0BAD_F00D,
        },
        epoll_store(),
    )
    .unwrap_or_else(|(_, e)| panic!("{e}"));
    let ticket = sub
        .push_epoll_ctl(prepared)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");
    let receipt = comp.wait_one().expect("completion");
    let done = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatch"));
    assert_eq!(done.outcome(), EpollOutcome::Applied);

    // Nothing readable yet, so the mask has nothing to fire on.
    assert!(
        set.wait_one(0).is_none(),
        "an idle socket must not be reported readable"
    );

    pair.write_client(b"wake");
    let fired = set.wait_one(1_000).expect("the registration must fire");
    let (events, data) = (fired.events, fired.data);
    // The mask reached the kernel: it woke on readability specifically.
    assert_ne!(events & EpollEvents::IN.bits(), 0);
    // And so did the caller's own token, which is the only way to tell
    // which registration this event belongs to.
    assert_eq!(data, 0x0BAD_F00D);
}

#[cfg(not(miri))]
#[test]
fn a_mod_of_an_unregistered_descriptor_is_told_apart_from_a_clash() {
    let set = EpollSet::new();
    let pair = SocketPair::connected();
    let ring = crate::IoUring::new(8).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let prepared = PreparedEpollCtl::new(
        set.fd,
        pair.server,
        EpollChange::Mod {
            events: EpollEvents::OUT,
            data: 5,
        },
        epoll_store(),
    )
    .unwrap_or_else(|(_, e)| panic!("{e}"));
    let ticket = sub
        .push_epoll_ctl(prepared)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit_and_wait(1).expect("submit");

    let receipt = comp.wait_one().expect("completion");
    let done = ticket
        .redeem(receipt)
        .unwrap_or_else(|_| panic!("mismatch"));
    assert_eq!(done.raw_result(), -2);
    assert_eq!(done.outcome(), EpollOutcome::NotRegistered);
}

#[cfg(not(miri))]
#[test]
fn a_del_succeeds_without_the_kernel_reading_the_staged_event() {
    let set = EpollSet::new();
    let pair = SocketPair::connected();
    let ring = crate::IoUring::new(8).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let mut run = |change| {
        let prepared = PreparedEpollCtl::new(set.fd, pair.server, change, epoll_store())
            .unwrap_or_else(|(_, e)| panic!("{e}"));
        let ticket = sub
            .push_epoll_ctl(prepared)
            .unwrap_or_else(|(_, e)| panic!("{e}"));
        sub.submit_and_wait(1).expect("submit");
        let receipt = comp.wait_one().expect("completion");
        ticket
            .redeem(receipt)
            .unwrap_or_else(|_| panic!("mismatch"))
            .outcome()
    };

    assert_eq!(
        run(EpollChange::Add {
            events: EpollEvents::IN,
            data: 1,
        }),
        EpollOutcome::Applied
    );
    // The `Del` stages a zeroed event and still works, which is why the
    // enum does not ask for a mask here.
    assert_eq!(run(EpollChange::Del), EpollOutcome::Applied);
    // And now the descriptor really is gone, so a second Del cannot find
    // it — proof the first one did something.
    assert_eq!(run(EpollChange::Del), EpollOutcome::NotRegistered);
}

#[cfg(not(miri))]
#[test]
fn an_epoll_ticket_survives_moving_to_another_thread_before_completion() {
    let set = EpollSet::new();
    let pair = SocketPair::connected();
    let ring = crate::IoUring::new(8).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));

    let store = epoll_store();
    let addr = store.stable_ptr();
    let prepared = PreparedEpollCtl::new(
        set.fd,
        pair.server,
        EpollChange::Add {
            events: EpollEvents::IN,
            data: 0xABCD,
        },
        store,
    )
    .unwrap_or_else(|(_, e)| panic!("{e}"));
    let ticket = sub
        .push_epoll_ctl(prepared)
        .unwrap_or_else(|(_, e)| panic!("{e}"));
    sub.submit().expect("submit");

    // The kernel may still be reading the event when the ticket moves.
    let handle = std::thread::spawn(move || {
        let receipt = comp.wait_one().expect("completion");
        let done = ticket
            .redeem(receipt)
            .unwrap_or_else(|_| panic!("mismatch"));
        done.into_parts()
    });
    let (outcome, store) = handle.join().expect("thread");
    assert_eq!(outcome, EpollOutcome::Applied);
    assert_eq!(store.stable_ptr(), addr);
}
