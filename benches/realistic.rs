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
//! Two workloads:
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
