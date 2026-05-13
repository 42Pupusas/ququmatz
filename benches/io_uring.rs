#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use ququmatz::{IoUring, IoVec, Sqe, types::RawFd};
use std::os::unix::io::IntoRawFd;

fn open_tmpfile() -> i32 {
    std::fs::File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open("/tmp/ququmatz-bench-tmpfile")
        .expect("failed to open tmpfile")
        .into_raw_fd()
}

#[divan::bench]
fn ring_setup_teardown() {
    divan::black_box(IoUring::new(32).expect("setup failed"));
}

mod sqe_build {
    use super::*;

    #[divan::bench]
    fn nop() {
        divan::black_box(Sqe::nop().user_data(1));
    }

    #[divan::bench]
    fn read() {
        let mut buf = [0u8; 4096];
        divan::black_box(
            unsafe { Sqe::read_ptr(RawFd::from_raw(3), buf.as_mut_ptr(), 4096, 0) }.user_data(1),
        );
    }

    #[divan::bench]
    fn write() {
        let mut buf = [0u8; 4096];
        divan::black_box(
            unsafe { Sqe::write_ptr(RawFd::from_raw(3), buf.as_mut_ptr(), 4096, 0) }.user_data(1),
        );
    }
}

#[divan::bench]
fn nop_push_submit_complete(bencher: divan::Bencher) {
    let mut ring = IoUring::new(32).expect("setup failed");
    bencher.bench_local(|| {
        ring.push(Sqe::nop().user_data(1)).unwrap();
        ring.submit_and_wait(1).unwrap();
        divan::black_box(ring.complete().unwrap());
    });
}

mod nop_batch {
    use super::*;

    #[divan::bench]
    fn batch_32(bencher: divan::Bencher) {
        let mut ring = IoUring::new(32).expect("setup failed");
        bencher.bench_local(|| {
            for i in 0..32u64 {
                ring.push(Sqe::nop().user_data(i)).unwrap();
            }
            ring.submit_and_wait(32).unwrap();
            divan::black_box(ring.completions().count());
        });
    }

    #[divan::bench]
    fn batch_128(bencher: divan::Bencher) {
        let mut ring = IoUring::new(128).expect("setup failed");
        bencher.bench_local(|| {
            for i in 0..128u64 {
                ring.push(Sqe::nop().user_data(i)).unwrap();
            }
            ring.submit_and_wait(128).unwrap();
            divan::black_box(ring.completions().count());
        });
    }
}

#[divan::bench]
fn write_4k(bencher: divan::Bencher) {
    let fd = open_tmpfile();
    let mut ring = IoUring::new(32).expect("setup failed");
    let write_buf = [0xABu8; 4096];
    bencher.bench_local(|| {
        ring.push(
            unsafe { Sqe::write_ptr(RawFd::from_raw(fd as usize), write_buf.as_ptr(), 4096, 0) }
                .user_data(1),
        )
        .unwrap();
        ring.submit_and_wait(1).unwrap();
        divan::black_box(ring.complete().unwrap());
    });
}

#[divan::bench]
fn read_4k(bencher: divan::Bencher) {
    let fd = open_tmpfile();
    let mut ring = IoUring::new(32).expect("setup failed");
    let write_buf = [0xABu8; 4096];
    ring.push(
        unsafe { Sqe::write_ptr(RawFd::from_raw(fd as usize), write_buf.as_ptr(), 4096, 0) }
            .user_data(0),
    )
    .unwrap();
    ring.submit_and_wait(1).unwrap();
    ring.complete().unwrap();

    let mut read_buf = [0u8; 4096];
    bencher.bench_local(|| {
        ring.push(
            unsafe { Sqe::read_ptr(RawFd::from_raw(fd as usize), read_buf.as_mut_ptr(), 4096, 0) }
                .user_data(1),
        )
        .unwrap();
        ring.submit_and_wait(1).unwrap();
        divan::black_box(ring.complete().unwrap());
    });
}

#[divan::bench]
fn writev_2x2k(bencher: divan::Bencher) {
    let fd = open_tmpfile();
    let mut ring = IoUring::new(32).expect("setup failed");
    let mut buf_a = [0xAAu8; 2048];
    let mut buf_b = [0xBBu8; 2048];
    let vecs = unsafe {
        [
            IoVec::new(buf_a.as_mut_ptr(), buf_a.len()),
            IoVec::new(buf_b.as_mut_ptr(), buf_b.len()),
        ]
    };
    bencher.bench_local(|| {
        ring.push(
            unsafe { Sqe::writev_ptr(RawFd::from_raw(fd as usize), vecs.as_ptr(), 2, 0) }
                .user_data(1),
        )
        .unwrap();
        ring.submit_and_wait(1).unwrap();
        divan::black_box(ring.complete().unwrap());
    });
}

fn main() {
    divan::main();
}
