#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

//! Head-to-head benchmarks: ququmatz (raw syscall) vs io-uring crate.

use ququmatz::types::RawFd;
use std::os::unix::io::IntoRawFd;

fn open_tmpfile(path: &str) -> i32 {
    std::fs::File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .expect("failed to open tmpfile")
        .into_raw_fd()
}

fn drain_cq(cq: &mut io_uring::cqueue::CompletionQueue<'_>) -> usize {
    let mut n = 0;
    while cq.next().is_some() {
        n += 1;
    }
    n
}

mod ring_setup {
    #[divan::bench]
    fn ququmatz() {
        divan::black_box(ququmatz::IoUring::new(32).expect("setup"));
    }

    #[divan::bench]
    fn io_uring() {
        divan::black_box(io_uring::IoUring::new(32).expect("setup"));
    }
}

mod sqe_build_nop {
    #[divan::bench]
    fn ququmatz() {
        divan::black_box(ququmatz::Sqe::nop().user_data(1));
    }

    #[divan::bench]
    fn io_uring() {
        divan::black_box(io_uring::opcode::Nop::new().build().user_data(1));
    }
}

mod sqe_build_read {
    use super::RawFd;

    #[divan::bench]
    fn ququmatz() {
        let mut buf = [0u8; 4096];
        divan::black_box(
            unsafe { ququmatz::Sqe::read_ptr(RawFd::from_raw(3), buf.as_mut_ptr(), 4096, 0) }
                .user_data(1),
        );
    }

    #[divan::bench]
    fn io_uring() {
        let mut buf = [0u8; 4096];
        divan::black_box(
            io_uring::opcode::Read::new(io_uring::types::Fd(3), buf.as_mut_ptr(), 4096)
                .offset(0)
                .build()
                .user_data(1),
        );
    }
}

mod sqe_build_write {
    use super::RawFd;

    static BUF: [u8; 4096] = [0u8; 4096];

    #[divan::bench]
    fn ququmatz() {
        divan::black_box(
            unsafe { ququmatz::Sqe::write_ptr(RawFd::from_raw(3), BUF.as_ptr(), 4096, 0) }
                .user_data(1),
        );
    }

    #[divan::bench]
    fn io_uring() {
        divan::black_box(
            io_uring::opcode::Write::new(io_uring::types::Fd(3), BUF.as_ptr(), 4096)
                .offset(0)
                .build()
                .user_data(1),
        );
    }
}

mod nop_single {
    use super::drain_cq;

    #[divan::bench]
    fn ququmatz(bencher: divan::Bencher) {
        let mut ring = ququmatz::IoUring::new(32).expect("setup");
        bencher.bench_local(|| {
            ring.push(ququmatz::Sqe::nop().user_data(1)).unwrap();
            ring.submit_and_wait(1).unwrap();
            divan::black_box(ring.complete().unwrap());
        });
    }

    #[divan::bench]
    fn io_uring(bencher: divan::Bencher) {
        let mut ring = io_uring::IoUring::new(32).expect("setup");
        let (submitter, mut sq, mut cq) = ring.split();
        bencher.bench_local(|| {
            sq.sync();
            let entry = io_uring::opcode::Nop::new().build().user_data(1);
            unsafe { sq.push(&entry).unwrap() };
            sq.sync();
            submitter.submit_and_wait(1).unwrap();
            cq.sync();
            divan::black_box(drain_cq(&mut cq));
        });
    }
}

mod nop_batch_32 {
    use super::drain_cq;

    #[divan::bench]
    fn ququmatz(bencher: divan::Bencher) {
        let mut ring = ququmatz::IoUring::new(32).expect("setup");
        bencher.bench_local(|| {
            for i in 0..32u64 {
                ring.push(ququmatz::Sqe::nop().user_data(i)).unwrap();
            }
            ring.submit_and_wait(32).unwrap();
            divan::black_box(ring.completions().count());
        });
    }

    #[divan::bench]
    fn io_uring(bencher: divan::Bencher) {
        let mut ring = io_uring::IoUring::new(32).expect("setup");
        let (submitter, mut sq, mut cq) = ring.split();
        bencher.bench_local(|| {
            sq.sync();
            for i in 0..32u64 {
                let entry = io_uring::opcode::Nop::new().build().user_data(i);
                unsafe { sq.push(&entry).unwrap() };
            }
            sq.sync();
            submitter.submit_and_wait(32).unwrap();
            cq.sync();
            divan::black_box(drain_cq(&mut cq));
        });
    }
}

mod nop_batch_128 {
    use super::drain_cq;

    #[divan::bench]
    fn ququmatz(bencher: divan::Bencher) {
        let mut ring = ququmatz::IoUring::new(128).expect("setup");
        bencher.bench_local(|| {
            for i in 0..128u64 {
                ring.push(ququmatz::Sqe::nop().user_data(i)).unwrap();
            }
            ring.submit_and_wait(128).unwrap();
            divan::black_box(ring.completions().count());
        });
    }

    #[divan::bench]
    fn io_uring(bencher: divan::Bencher) {
        let mut ring = io_uring::IoUring::new(128).expect("setup");
        let (submitter, mut sq, mut cq) = ring.split();
        bencher.bench_local(|| {
            sq.sync();
            for i in 0..128u64 {
                let entry = io_uring::opcode::Nop::new().build().user_data(i);
                unsafe { sq.push(&entry).unwrap() };
            }
            sq.sync();
            submitter.submit_and_wait(128).unwrap();
            cq.sync();
            divan::black_box(drain_cq(&mut cq));
        });
    }
}

mod write_4k {
    use super::{RawFd, drain_cq, open_tmpfile};

    static WRITE_BUF: [u8; 4096] = [0xABu8; 4096];

    #[divan::bench]
    fn ququmatz(bencher: divan::Bencher) {
        let fd = open_tmpfile("/tmp/ququmatz-cmp-write-qq");
        let mut ring = ququmatz::IoUring::new(32).expect("setup");
        bencher.bench_local(|| {
            ring.push(
                unsafe {
                    ququmatz::Sqe::write_ptr(
                        RawFd::from_raw(fd as usize),
                        WRITE_BUF.as_ptr(),
                        4096,
                        0,
                    )
                }
                .user_data(1),
            )
            .unwrap();
            ring.submit_and_wait(1).unwrap();
            divan::black_box(ring.complete().unwrap());
        });
    }

    #[divan::bench]
    fn ququmatz_split(bencher: divan::Bencher) {
        let fd = open_tmpfile("/tmp/ququmatz-cmp-write-qq-split");
        let (mut submitter, mut completer) = ququmatz::IoUring::new(32).expect("setup").split();
        bencher.bench_local(|| {
            submitter
                .push(
                    unsafe {
                        ququmatz::Sqe::write_ptr(
                            RawFd::from_raw(fd as usize),
                            WRITE_BUF.as_ptr(),
                            4096,
                            0,
                        )
                    }
                    .user_data(1),
                )
                .unwrap();
            submitter.submit_and_wait(1).unwrap();
            divan::black_box(completer.complete());
        });
    }

    #[divan::bench]
    fn io_uring(bencher: divan::Bencher) {
        let fd = open_tmpfile("/tmp/ququmatz-cmp-write-iu");
        let mut ring = io_uring::IoUring::new(32).expect("setup");
        let (submitter, mut sq, mut cq) = ring.split();
        bencher.bench_local(|| {
            sq.sync();
            let entry =
                io_uring::opcode::Write::new(io_uring::types::Fd(fd), WRITE_BUF.as_ptr(), 4096)
                    .offset(0)
                    .build()
                    .user_data(1);
            unsafe { sq.push(&entry).unwrap() };
            sq.sync();
            submitter.submit_and_wait(1).unwrap();
            cq.sync();
            divan::black_box(drain_cq(&mut cq));
        });
    }
}

mod read_4k {
    use super::{RawFd, drain_cq, open_tmpfile};

    static SEED_BUF: [u8; 4096] = [0xCDu8; 4096];

    #[divan::bench]
    fn ququmatz(bencher: divan::Bencher) {
        let fd = open_tmpfile("/tmp/ququmatz-cmp-read-qq");
        let mut ring = ququmatz::IoUring::new(32).expect("setup");
        ring.push(
            unsafe {
                ququmatz::Sqe::write_ptr(RawFd::from_raw(fd as usize), SEED_BUF.as_ptr(), 4096, 0)
            }
            .user_data(0),
        )
        .unwrap();
        ring.submit_and_wait(1).unwrap();
        ring.complete().unwrap();

        let mut read_buf = [0u8; 4096];
        bencher.bench_local(|| {
            ring.push(
                unsafe {
                    ququmatz::Sqe::read_ptr(
                        RawFd::from_raw(fd as usize),
                        read_buf.as_mut_ptr(),
                        4096,
                        0,
                    )
                }
                .user_data(1),
            )
            .unwrap();
            ring.submit_and_wait(1).unwrap();
            divan::black_box(ring.complete().unwrap());
        });
    }

    #[divan::bench]
    fn io_uring(bencher: divan::Bencher) {
        let fd = open_tmpfile("/tmp/ququmatz-cmp-read-iu");
        let mut seed_ring = ququmatz::IoUring::new(32).expect("setup");
        seed_ring
            .push(
                unsafe {
                    ququmatz::Sqe::write_ptr(
                        RawFd::from_raw(fd as usize),
                        SEED_BUF.as_ptr(),
                        4096,
                        0,
                    )
                }
                .user_data(0),
            )
            .unwrap();
        seed_ring.submit_and_wait(1).unwrap();
        seed_ring.complete().unwrap();
        drop(seed_ring);

        let mut ring = io_uring::IoUring::new(32).expect("setup");
        let (submitter, mut sq, mut cq) = ring.split();
        let mut read_buf = [0u8; 4096];
        bencher.bench_local(|| {
            sq.sync();
            let entry =
                io_uring::opcode::Read::new(io_uring::types::Fd(fd), read_buf.as_mut_ptr(), 4096)
                    .offset(0)
                    .build()
                    .user_data(1);
            unsafe { sq.push(&entry).unwrap() };
            sq.sync();
            submitter.submit_and_wait(1).unwrap();
            cq.sync();
            divan::black_box(drain_cq(&mut cq));
        });
    }
}

mod writev_2x2k {
    use super::{RawFd, drain_cq, open_tmpfile};

    #[divan::bench]
    fn ququmatz(bencher: divan::Bencher) {
        let fd = open_tmpfile("/tmp/ququmatz-cmp-writev-qq");
        let mut ring = ququmatz::IoUring::new(32).expect("setup");
        let mut buf_a = [0xAAu8; 2048];
        let mut buf_b = [0xBBu8; 2048];
        let vecs = unsafe {
            [
                ququmatz::IoVec::new(buf_a.as_mut_ptr(), buf_a.len()),
                ququmatz::IoVec::new(buf_b.as_mut_ptr(), buf_b.len()),
            ]
        };
        bencher.bench_local(|| {
            ring.push(
                unsafe {
                    ququmatz::Sqe::writev_ptr(RawFd::from_raw(fd as usize), vecs.as_ptr(), 2, 0)
                }
                .user_data(1),
            )
            .unwrap();
            ring.submit_and_wait(1).unwrap();
            divan::black_box(ring.complete().unwrap());
        });
    }

    #[divan::bench]
    fn io_uring(bencher: divan::Bencher) {
        let fd = open_tmpfile("/tmp/ququmatz-cmp-writev-iu");
        let mut ring = io_uring::IoUring::new(32).expect("setup");
        let (submitter, mut sq, mut cq) = ring.split();
        let buf_a = [0xAAu8; 2048];
        let buf_b = [0xBBu8; 2048];
        let vecs = [std::io::IoSlice::new(&buf_a), std::io::IoSlice::new(&buf_b)];
        bencher.bench_local(|| {
            sq.sync();
            let entry =
                io_uring::opcode::Writev::new(io_uring::types::Fd(fd), vecs.as_ptr().cast(), 2)
                    .offset(0)
                    .build()
                    .user_data(1);
            unsafe { sq.push(&entry).unwrap() };
            sq.sync();
            submitter.submit_and_wait(1).unwrap();
            cq.sync();
            divan::black_box(drain_cq(&mut cq));
        });
    }
}

mod linked_nops_3 {
    use super::drain_cq;

    #[divan::bench]
    fn ququmatz(bencher: divan::Bencher) {
        let mut ring = ququmatz::IoUring::new(32).expect("setup");
        bencher.bench_local(|| {
            ring.push(ququmatz::Sqe::nop().user_data(1).link()).unwrap();
            ring.push(ququmatz::Sqe::nop().user_data(2).link()).unwrap();
            ring.push(ququmatz::Sqe::nop().user_data(3)).unwrap();
            ring.submit_and_wait(3).unwrap();
            divan::black_box(ring.completions().count());
        });
    }

    #[divan::bench]
    fn io_uring(bencher: divan::Bencher) {
        let mut ring = io_uring::IoUring::new(32).expect("setup");
        let (submitter, mut sq, mut cq) = ring.split();
        bencher.bench_local(|| {
            sq.sync();
            let e1 = io_uring::opcode::Nop::new()
                .build()
                .user_data(1)
                .flags(io_uring::squeue::Flags::IO_LINK);
            let e2 = io_uring::opcode::Nop::new()
                .build()
                .user_data(2)
                .flags(io_uring::squeue::Flags::IO_LINK);
            let e3 = io_uring::opcode::Nop::new().build().user_data(3);
            unsafe {
                sq.push(&e1).unwrap();
                sq.push(&e2).unwrap();
                sq.push(&e3).unwrap();
            }
            sq.sync();
            submitter.submit_and_wait(3).unwrap();
            cq.sync();
            divan::black_box(drain_cq(&mut cq));
        });
    }
}

mod struct_sizes {
    #[divan::bench]
    fn size_validation() {
        let ours = core::mem::size_of::<ququmatz::types::IoUringSqe>();
        let theirs = core::mem::size_of::<io_uring::squeue::Entry>();
        assert_eq!(
            ours, theirs,
            "SQE size mismatch: ours={ours}, theirs={theirs}"
        );
        assert_eq!(ours, 64, "SQE must be 64 bytes");

        let our_cqe = core::mem::size_of::<ququmatz::types::IoUringCqe>();
        let their_cqe = core::mem::size_of::<io_uring::cqueue::Entry>();
        assert_eq!(
            our_cqe, their_cqe,
            "CQE size mismatch: ours={our_cqe}, theirs={their_cqe}"
        );
        divan::black_box((ours, theirs, our_cqe, their_cqe));
    }
}

fn main() {
    divan::main();
}
