#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

//! Realistic-workload benchmarks: ququmatz vs io-uring on shapes an
//! application actually runs, rather than isolated single-opcode calls.
//!
//! Gated to `x86_64` for the same reason as `comparison.rs`: the `io-uring`
//! crate ships prebuilt ABI bindings only for that architecture.
//!
//! Three workloads:
//!
//! - `echo_roundtrip`: a TCP client writes a small request, a loopback
//!   "server" ring receives it and echoes it back, the client reads the
//!   reply. This is the request/response shape a network service actually
//!   runs — recv, then send, then wait for the next recv — not a single
//!   isolated syscall.
//! - `log_append`: open a fresh file, write a record, fsync it, close it.
//!   This is the shape of an append-only log or WAL writer: durability
//!   requires all four steps every time, so benchmarking `write` alone
//!   would understate the real cost.
//! - `echo_roundtrip_concurrent`: the same echo shape, but K connections in
//!   flight per iteration instead of one. This is the case `io_uring`
//!   actually exists for — one ring batching K recvs into one syscall,
//!   then K sends into another — compared against K OS threads each
//!   blocking on its own socket. The first two workloads above never
//!   submit more than one operation at a time, so they cannot show this;
//!   this one dials K up (1/8/32/128) to see where, if anywhere, batching
//!   pays for its own complexity.

#[cfg(target_arch = "x86_64")]
mod workloads {
    use std::net::{TcpListener, TcpStream};
    use std::os::unix::io::IntoRawFd as _;

    use ququmatz::types::RawFd;

    pub const REQUEST: &[u8] = b"GET /ping HTTP/1.1\r\n\r\n";

    /// A connected loopback pair: `(client_std_stream, server_raw_fd)`.
    ///
    /// The client side stays a plain blocking `TcpStream` so each benchmark
    /// iteration can write the request and read the reply without needing
    /// its own ring — only the server side (the accept/recv/send loop) is
    /// what each library implements.
    pub fn connected_pair() -> (TcpStream, i32) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let client = TcpStream::connect(addr).expect("connect");
        let (server, _peer) = listener.accept().expect("accept");
        client.set_nodelay(true).expect("nodelay");
        let server_fd = server.into_raw_fd();
        (client, server_fd)
    }

    pub fn tmp_log_path(tag: &str, i: u64) -> String {
        format!("/tmp/ququmatz-bench-log-{tag}-{i}")
    }

    /// `O_CREAT | O_RDWR | O_TRUNC` as a raw value, for the `io-uring` and
    /// `std` variants, which take the kernel's own flag encoding directly.
    pub const fn open_flags_create_rdwr_raw() -> i32 {
        const O_CREAT: i32 = 0o100;
        const O_RDWR: i32 = 0o2;
        const O_TRUNC: i32 = 0o1000;
        O_CREAT | O_RDWR | O_TRUNC
    }

    pub const RECORD: &[u8] = b"2024-01-01T00:00:00Z append-only log record\n";

    pub const fn as_rawfd(fd: i32) -> RawFd {
        RawFd::from_raw(fd as usize)
    }

    /// `k` connected loopback pairs, for the concurrent-workload benchmarks.
    pub fn connected_pairs(k: usize) -> Vec<(TcpStream, i32)> {
        (0..k).map(|_| connected_pair()).collect()
    }
}

#[cfg(target_arch = "x86_64")]
mod echo_roundtrip {
    use super::workloads::{REQUEST, as_rawfd, connected_pair};
    use ququmatz::types::MsgFlags;
    use ququmatz::{IoUring, Sqe};
    use std::io::{Read as _, Write as _};

    /// One recv-then-send round trip through ququmatz, driven by a real
    /// ring: the server fd is recv'd into a buffer, then the same bytes
    /// are sent back — the request/response shape, not an isolated call.
    #[divan::bench]
    fn ququmatz(bencher: divan::Bencher) {
        let (mut client, server_fd) = connected_pair();
        let fd = as_rawfd(server_fd);
        let mut ring = IoUring::new(8).expect("setup");
        let mut recv_buf = [0u8; 256];
        let mut reply_buf = [0u8; 256];

        bencher.bench_local(|| {
            client.write_all(REQUEST).unwrap();

            ring.push(
                unsafe {
                    Sqe::recv_ptr(
                        fd,
                        recv_buf.as_mut_ptr(),
                        recv_buf.len() as u32,
                        MsgFlags::default(),
                    )
                }
                .user_data(1),
            )
            .unwrap();
            ring.submit_and_wait(1).unwrap();
            let n = ring.complete().unwrap().into_result().unwrap() as usize;

            ring.push(
                unsafe { Sqe::send_ptr(fd, recv_buf.as_ptr(), n as u32, MsgFlags::default()) }
                    .user_data(2),
            )
            .unwrap();
            ring.submit_and_wait(1).unwrap();
            divan::black_box(ring.complete().unwrap().into_result().unwrap());

            client.read_exact(&mut reply_buf[..n]).unwrap();
            assert_eq!(&reply_buf[..n], REQUEST);
        });
    }

    #[divan::bench]
    fn io_uring(bencher: divan::Bencher) {
        let (mut client, server_fd) = connected_pair();
        let mut ring = io_uring::IoUring::new(8).expect("setup");
        let mut recv_buf = [0u8; 256];
        let mut reply_buf = [0u8; 256];

        bencher.bench_local(|| {
            client.write_all(REQUEST).unwrap();

            let recv_e = io_uring::opcode::Recv::new(
                io_uring::types::Fd(server_fd),
                recv_buf.as_mut_ptr(),
                recv_buf.len() as u32,
            )
            .build()
            .user_data(1);
            unsafe { ring.submission().push(&recv_e).unwrap() };
            ring.submit_and_wait(1).unwrap();
            let cqe = ring.completion().next().unwrap();
            let n = cqe.result() as usize;

            let send_e = io_uring::opcode::Send::new(
                io_uring::types::Fd(server_fd),
                recv_buf.as_ptr(),
                n as u32,
            )
            .build()
            .user_data(2);
            unsafe { ring.submission().push(&send_e).unwrap() };
            ring.submit_and_wait(1).unwrap();
            divan::black_box(ring.completion().next().unwrap().result());

            client.read_exact(&mut reply_buf[..n]).unwrap();
            assert_eq!(&reply_buf[..n], REQUEST);
        });
    }

    /// Plain blocking `read`/`write` syscalls through std, no `io_uring` at
    /// all. This is the baseline every uring-based approach has to beat to
    /// be worth its complexity for a workload this small.
    #[divan::bench]
    fn std_blocking(bencher: divan::Bencher) {
        use std::os::fd::FromRawFd as _;
        let (mut client, server_fd) = connected_pair();
        let mut server = unsafe { std::net::TcpStream::from_raw_fd(server_fd) };
        let mut recv_buf = [0u8; 256];
        let mut reply_buf = [0u8; 256];

        bencher.bench_local(|| {
            client.write_all(REQUEST).unwrap();
            let n = server.read(&mut recv_buf).unwrap();
            server.write_all(&recv_buf[..n]).unwrap();
            client.read_exact(&mut reply_buf[..n]).unwrap();
            divan::black_box(n);
            assert_eq!(&reply_buf[..n], REQUEST);
        });
    }
}

/// The same echo shape as [`echo_roundtrip`], but `K` connections are
/// driven per iteration instead of one. This is what `io_uring` is for:
/// one ring batches `K` recvs into a single `enter` syscall and `K` sends
/// into another, where a thread-per-connection design pays `K` blocking
/// syscalls (and `K` thread wakeups) for the same work.
///
/// `K` sweeps 1/8/32/128 so the crossover point, if any, is visible rather
/// than asserted.
#[cfg(target_arch = "x86_64")]
mod echo_roundtrip_concurrent {
    use super::workloads::{REQUEST, as_rawfd, connected_pairs};
    use ququmatz::types::MsgFlags;
    use ququmatz::{IoUring, Sqe};
    use std::io::{Read as _, Write as _};
    use std::thread;

    const CONCURRENCY: [usize; 4] = [1, 8, 32, 128];

    /// One ring driving `k` connections: push `k` recvs, submit once, drain
    /// `k` completions by `user_data`, then the same for `k` sends. This is
    /// the batching `io_uring` exists to provide -- never realized when only
    /// one operation is ever in flight, as in [`super::echo_roundtrip`].
    #[divan::bench(args = CONCURRENCY)]
    fn ququmatz(bencher: divan::Bencher, k: usize) {
        let mut pairs = connected_pairs(k);
        let mut ring = IoUring::new((k * 2).max(8) as u32).expect("setup");
        let mut recv_bufs = vec![[0u8; 256]; k];
        let mut reply_bufs = vec![[0u8; 256]; k];

        bencher.bench_local(|| {
            for (client, _) in &mut pairs {
                client.write_all(REQUEST).unwrap();
            }

            for (i, ((_, server_fd), recv_buf)) in pairs.iter().zip(&mut recv_bufs).enumerate() {
                let fd = as_rawfd(*server_fd);
                ring.push(
                    unsafe {
                        Sqe::recv_ptr(
                            fd,
                            recv_buf.as_mut_ptr(),
                            recv_buf.len() as u32,
                            MsgFlags::default(),
                        )
                    }
                    .user_data(i as u64),
                )
                .unwrap();
            }
            ring.submit_and_wait(k as u32).unwrap();
            let mut lens = vec![0usize; k];
            for c in ring.completions() {
                lens[c.user_data as usize] = c.into_result().unwrap() as usize;
            }

            for (i, ((_, server_fd), recv_buf)) in pairs.iter().zip(&recv_bufs).enumerate() {
                let fd = as_rawfd(*server_fd);
                ring.push(
                    unsafe {
                        Sqe::send_ptr(fd, recv_buf.as_ptr(), lens[i] as u32, MsgFlags::default())
                    }
                    .user_data(i as u64),
                )
                .unwrap();
            }
            ring.submit_and_wait(k as u32).unwrap();
            for c in ring.completions() {
                divan::black_box(c.into_result().unwrap());
            }

            for (i, (client, _)) in pairs.iter_mut().enumerate() {
                let n = lens[i];
                client.read_exact(&mut reply_bufs[i][..n]).unwrap();
                assert_eq!(&reply_bufs[i][..n], REQUEST);
            }
        });
    }

    /// The same batching shape as [`ququmatz`] above, built on the
    /// `io-uring` crate directly: push `k` recvs, submit once, drain `k`
    /// completions by `user_data`, then the same for `k` sends. Needed
    /// because "ququmatz batches well" is only half a claim if it is only
    /// ever checked against a thread-per-connection baseline and never
    /// against the other `io_uring` binding doing the same batching.
    #[divan::bench(args = CONCURRENCY)]
    fn io_uring(bencher: divan::Bencher, k: usize) {
        let mut pairs = connected_pairs(k);
        let mut ring = io_uring::IoUring::new((k * 2).max(8) as u32).expect("setup");
        let mut recv_bufs = vec![[0u8; 256]; k];
        let mut reply_bufs = vec![[0u8; 256]; k];

        bencher.bench_local(|| {
            for (client, _) in &mut pairs {
                client.write_all(REQUEST).unwrap();
            }

            for (i, ((_, server_fd), recv_buf)) in pairs.iter().zip(&mut recv_bufs).enumerate() {
                let recv_e = io_uring::opcode::Recv::new(
                    io_uring::types::Fd(*server_fd),
                    recv_buf.as_mut_ptr(),
                    recv_buf.len() as u32,
                )
                .build()
                .user_data(i as u64);
                unsafe { ring.submission().push(&recv_e).unwrap() };
            }
            ring.submit_and_wait(k).unwrap();
            let mut lens = vec![0usize; k];
            for cqe in ring.completion() {
                let n = cqe.result();
                assert!(n >= 0);
                lens[cqe.user_data() as usize] = n as usize;
            }

            for (i, ((_, server_fd), recv_buf)) in pairs.iter().zip(&recv_bufs).enumerate() {
                let send_e = io_uring::opcode::Send::new(
                    io_uring::types::Fd(*server_fd),
                    recv_buf.as_ptr(),
                    lens[i] as u32,
                )
                .build()
                .user_data(i as u64);
                unsafe { ring.submission().push(&send_e).unwrap() };
            }
            ring.submit_and_wait(k).unwrap();
            for cqe in ring.completion() {
                let n = cqe.result();
                assert!(n >= 0);
                divan::black_box(n);
            }

            for (i, (client, _)) in pairs.iter_mut().enumerate() {
                let n = lens[i];
                client.read_exact(&mut reply_bufs[i][..n]).unwrap();
                assert_eq!(&reply_bufs[i][..n], REQUEST);
            }
        });
    }

    /// Describes one submitted batch on the [`ququmatz_split`] bench: which
    /// phase it belongs to and how many completions to wait for.
    struct SplitTicket {
        phase: SplitPhase,
        count: u32,
    }

    #[derive(Clone, Copy)]
    enum SplitPhase {
        Recv,
        Send,
    }

    /// A raw pointer to the shared recv-buffer storage, `Send` because the
    /// submission thread is the only one that ever dereferences it (the
    /// kernel fills a buffer directly from the recv SQE's pointer; the
    /// completion thread only ever touches CQE result codes).
    #[derive(Clone, Copy)]
    struct SplitRecvBufs {
        ptr: *mut [u8; 256],
    }

    unsafe impl Send for SplitRecvBufs {}

    impl SplitRecvBufs {
        unsafe fn slot(self, i: usize) -> &'static mut [u8; 256] {
            unsafe { &mut *self.ptr.add(i) }
        }
    }

    /// The submission-thread half of [`ququmatz_split`]: owns the
    /// `Submitter`, the server fds, and the shared recv-buffer storage.
    struct SplitSubmitWorker {
        submitter: ququmatz::Submitter,
        server_fds: Vec<i32>,
        recv_bufs: SplitRecvBufs,
    }

    impl SplitSubmitWorker {
        fn push_phase(&mut self, phase: SplitPhase, lens: &[u32]) {
            for (i, &fd_raw) in self.server_fds.iter().enumerate() {
                let fd = as_rawfd(fd_raw);
                let buf = unsafe { self.recv_bufs.slot(i) };
                let sqe = match phase {
                    SplitPhase::Recv => unsafe {
                        Sqe::recv_ptr(fd, buf.as_mut_ptr(), buf.len() as u32, MsgFlags::default())
                    },
                    SplitPhase::Send => unsafe {
                        Sqe::send_ptr(fd, buf.as_ptr(), lens[i], MsgFlags::default())
                    },
                };
                self.submitter.push(sqe.user_data(i as u64)).unwrap();
            }
            self.submitter.submit().unwrap();
        }

        const fn ticket(&self, phase: SplitPhase) -> SplitTicket {
            SplitTicket {
                phase,
                count: self.server_fds.len() as u32,
            }
        }
    }

    /// The completion-thread half of [`ququmatz_split`]: owns the
    /// `Completer` and reports recv byte counts back through `lens_tx`.
    struct SplitCompleteWorker {
        completer: ququmatz::Completer,
        lens_tx: std::sync::mpsc::Sender<Vec<u32>>,
        done_tx: std::sync::mpsc::Sender<()>,
    }

    impl SplitCompleteWorker {
        fn handle(&mut self, ticket: &SplitTicket) {
            self.completer.wait(ticket.count).unwrap();
            match ticket.phase {
                SplitPhase::Recv => {
                    let mut lens = vec![0u32; ticket.count as usize];
                    for c in self.completer.completions() {
                        lens[c.user_data as usize] = c.into_result().unwrap();
                    }
                    self.completer.sync_cq();
                    self.lens_tx.send(lens).expect("submit thread alive");
                }
                SplitPhase::Send => {
                    for c in self.completer.completions() {
                        divan::black_box(c.into_result().unwrap());
                    }
                    self.completer.sync_cq();
                    self.done_tx.send(()).expect("main thread alive");
                }
            }
        }
    }

    /// A submitter/completer split across two persistent OS threads, wired
    /// by a `quetzalcoatl` SPSC ring instead of a channel from `std`. The
    /// submission thread pushes and submits each phase's SQEs, then hands
    /// the completion thread a ticket describing what to wait for; the
    /// completion thread reaps that phase's CQEs and reports the recv byte
    /// counts back so the submission thread can build the send phase. This
    /// is the shape `ququmatz_split` in `comparison.rs` only gestures at by
    /// calling `Submitter`/`Completer` from one thread -- here they
    /// genuinely live on separate threads for the whole benchmark, not
    /// just per call.
    #[divan::bench(args = CONCURRENCY)]
    fn ququmatz_split(bencher: divan::Bencher, k: usize) {
        use quetzalcoatl::capacity::Capacity;
        use quetzalcoatl::spsc::RingBuffer;
        use std::sync::mpsc as std_mpsc;

        let mut pairs = connected_pairs(k);
        let ring = IoUring::new((k * 2).max(8) as u32).expect("setup");
        let (submitter, completer) = ring.split().unwrap_or_else(|(_, e)| panic!("split: {e}"));

        let mut recv_bufs = vec![[0u8; 256]; k];
        let recv_bufs_raw = SplitRecvBufs {
            ptr: recv_bufs.as_mut_ptr(),
        };
        let server_fds: Vec<i32> = pairs.iter().map(|(_, fd)| *fd).collect();

        let (ticket_tx, mut ticket_rx) = RingBuffer::<SplitTicket>::new(Capacity::exact(4)).split();
        let (go_tx, go_rx) = std_mpsc::channel::<()>();
        let (lens_tx, lens_rx) = std_mpsc::channel::<Vec<u32>>();
        let (done_tx, done_rx) = std_mpsc::channel::<()>();

        let submit_thread = thread::spawn(move || {
            let mut worker = SplitSubmitWorker {
                submitter,
                server_fds,
                recv_bufs: recv_bufs_raw,
            };
            while go_rx.recv().is_ok() {
                worker.push_phase(SplitPhase::Recv, &[]);
                ticket_tx
                    .push(worker.ticket(SplitPhase::Recv))
                    .unwrap_or_else(|_| panic!("ticket ring full"));

                let lens = lens_rx.recv().expect("completion thread alive");

                worker.push_phase(SplitPhase::Send, &lens);
                ticket_tx
                    .push(worker.ticket(SplitPhase::Send))
                    .unwrap_or_else(|_| panic!("ticket ring full"));
            }
            worker.submitter
        });

        let complete_thread = thread::spawn(move || {
            let mut worker = SplitCompleteWorker {
                completer,
                lens_tx,
                done_tx,
            };
            while let Some(ticket) = ticket_rx.pop_block() {
                worker.handle(&ticket);
            }
            worker.completer
        });

        bencher.bench_local(|| {
            for (client, _) in &mut pairs {
                client.write_all(REQUEST).unwrap();
            }
            go_tx.send(()).expect("submit thread alive");
            done_rx.recv().expect("completion thread alive");

            for (client, _) in &mut pairs {
                let mut reply_buf = [0u8; 256];
                client.read_exact(&mut reply_buf[..REQUEST.len()]).unwrap();
                assert_eq!(&reply_buf[..REQUEST.len()], REQUEST);
            }
        });

        drop(go_tx);
        let _submitter = submit_thread.join().expect("submit thread");
        let _completer = complete_thread.join().expect("complete thread");
    }

    /// `k` OS threads, each blocking on its own connection with plain
    /// `read`/`write` -- no `io_uring` anywhere. The baseline a batching
    /// ring has to beat once there is enough concurrency for thread
    /// overhead and scheduler contention to show up.
    #[divan::bench(args = CONCURRENCY)]
    fn std_blocking_threads(bencher: divan::Bencher, k: usize) {
        use std::os::fd::FromRawFd as _;
        let mut clients = Vec::with_capacity(k);
        let mut servers = Vec::with_capacity(k);
        for (client, server_fd) in connected_pairs(k) {
            clients.push(client);
            servers.push(unsafe { std::net::TcpStream::from_raw_fd(server_fd) });
        }

        bencher.bench_local(|| {
            for client in &mut clients {
                client.write_all(REQUEST).unwrap();
            }

            thread::scope(|scope| {
                for server in &mut servers {
                    scope.spawn(move || {
                        let mut recv_buf = [0u8; 256];
                        let n = server.read(&mut recv_buf).unwrap();
                        server.write_all(&recv_buf[..n]).unwrap();
                        n
                    });
                }
            });

            for client in &mut clients {
                let mut reply_buf = [0u8; 256];
                client.read_exact(&mut reply_buf[..REQUEST.len()]).unwrap();
                assert_eq!(&reply_buf[..REQUEST.len()], REQUEST);
            }
        });
    }
}

#[cfg(target_arch = "x86_64")]
mod log_append {
    use super::workloads::{RECORD, as_rawfd, open_flags_create_rdwr_raw, tmp_log_path};
    use ququmatz::types::{FileMode, FsyncFlags, OpenFlags};
    use ququmatz::{IoUring, Sqe};
    use std::ffi::CString;

    /// open -> write -> fsync -> close, chained on one ring via `IOSQE_IO_LINK`
    /// so all four execute as a single submission: the durable-append shape a
    /// log or write-ahead-log writer actually needs, not an isolated `write()`.
    #[divan::bench]
    fn ququmatz(bencher: divan::Bencher) {
        let mut ring = IoUring::new(8).expect("setup");
        let mut i = 0u64;

        bencher.bench_local(|| {
            i += 1;
            let path = tmp_log_path("qq", i);
            let cpath = CString::new(path.clone()).unwrap();

            // openat returns a plain fd; the crate has no owned/no-link
            // shortcut for "open, use the fd, close" in one push batch, so
            // this drives it the way a real caller must: open first, read
            // the fd back, then chain write+fsync+close against it.
            let flags = OpenFlags::CREAT
                .union_const(OpenFlags::RDWR)
                .union_const(OpenFlags::TRUNC);
            let mode = FileMode::OWNER_READ.union_const(FileMode::OWNER_WRITE);
            ring.push(
                unsafe { Sqe::openat(ququmatz::types::DirFd::Cwd, cpath.as_c_str(), flags, mode) }
                    .user_data(1),
            )
            .unwrap();
            ring.submit_and_wait(1).unwrap();
            let fd = as_rawfd(ring.complete().unwrap().into_result().unwrap() as i32);

            ring.push(
                unsafe { Sqe::write_ptr(fd, RECORD.as_ptr(), RECORD.len() as u32, 0) }
                    .user_data(2)
                    .link(),
            )
            .unwrap();
            ring.push(Sqe::fsync(fd, FsyncFlags::empty()).user_data(3).link())
                .unwrap();
            ring.push(Sqe::close(fd).user_data(4)).unwrap();
            ring.submit_and_wait(3).unwrap();
            for c in ring.completions() {
                assert!(c.result >= 0, "op {} failed: {}", c.user_data, c.result);
            }

            let _ = std::fs::remove_file(&path);
        });
    }

    #[divan::bench]
    fn io_uring(bencher: divan::Bencher) {
        let mut ring = io_uring::IoUring::new(8).expect("setup");
        let mut i = 0u64;

        bencher.bench_local(|| {
            i += 1;
            let path = tmp_log_path("iu", i);
            let cpath = CString::new(path.clone()).unwrap();

            let open_e =
                io_uring::opcode::OpenAt::new(io_uring::types::Fd(libc_at_fdcwd()), cpath.as_ptr())
                    .flags(open_flags_create_rdwr_raw())
                    .mode(0o600)
                    .build()
                    .user_data(1);
            unsafe { ring.submission().push(&open_e).unwrap() };
            ring.submit_and_wait(1).unwrap();
            let fd = ring.completion().next().unwrap().result();

            let write_e = io_uring::opcode::Write::new(
                io_uring::types::Fd(fd),
                RECORD.as_ptr(),
                RECORD.len() as u32,
            )
            .offset(0)
            .build()
            .user_data(2)
            .flags(io_uring::squeue::Flags::IO_LINK);
            let fsync_e = io_uring::opcode::Fsync::new(io_uring::types::Fd(fd))
                .build()
                .user_data(3)
                .flags(io_uring::squeue::Flags::IO_LINK);
            let close_e = io_uring::opcode::Close::new(io_uring::types::Fd(fd))
                .build()
                .user_data(4);
            unsafe {
                ring.submission().push(&write_e).unwrap();
                ring.submission().push(&fsync_e).unwrap();
                ring.submission().push(&close_e).unwrap();
            }
            ring.submit_and_wait(3).unwrap();
            for c in ring.completion() {
                assert!(
                    c.result() >= 0,
                    "op {} failed: {}",
                    c.user_data(),
                    c.result()
                );
            }

            let _ = std::fs::remove_file(&path);
        });
    }

    /// Plain blocking syscalls through std: open, write, `fsync`, close —
    /// the baseline durable-write path with no `io_uring` involved.
    #[divan::bench]
    fn std_blocking(bencher: divan::Bencher) {
        let mut i = 0u64;
        bencher.bench_local(|| {
            i += 1;
            let path = tmp_log_path("std", i);
            let file = std::fs::File::options()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(&path)
                .unwrap();
            let mut file = file;
            std::io::Write::write_all(&mut file, RECORD).unwrap();
            file.sync_data().unwrap();
            drop(file);
            let _ = std::fs::remove_file(&path);
        });
    }

    const fn libc_at_fdcwd() -> i32 {
        -100
    }
}

fn main() {
    #[cfg(target_arch = "x86_64")]
    divan::main();
}
