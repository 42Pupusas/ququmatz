#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use ququmatz::{IoUring, IoVec, Sqe};
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

fn bench_ring_setup(c: &mut Criterion) {
    c.bench_function("ring_setup_teardown", |b| {
        b.iter(|| {
            let ring = IoUring::new(black_box(32)).expect("setup failed");
            drop(black_box(ring));
        });
    });
}

fn bench_sqe_construction(c: &mut Criterion) {
    let mut buf = [0u8; 4096];
    let ptr = buf.as_mut_ptr();

    c.bench_function("sqe_build_nop", |b| {
        b.iter(|| black_box(Sqe::nop().user_data(1)));
    });

    c.bench_function("sqe_build_read", |b| {
        b.iter(|| black_box(unsafe { Sqe::read(3, ptr, 4096, 0) }.user_data(1)));
    });

    c.bench_function("sqe_build_write", |b| {
        b.iter(|| black_box(unsafe { Sqe::write(3, ptr, 4096, 0) }.user_data(1)));
    });
}

fn bench_nop_single(c: &mut Criterion) {
    let mut ring = IoUring::new(32).expect("setup failed");

    c.bench_function("nop_push_submit_complete", |b| {
        b.iter(|| {
            ring.push(Sqe::nop().user_data(1)).unwrap();
            ring.submit_and_wait(1).unwrap();
            black_box(ring.complete().unwrap());
        });
    });
}

fn bench_nop_batch(c: &mut Criterion) {
    c.bench_function("nop_batch_32", |b| {
        let mut ring = IoUring::new(32).expect("setup failed");
        b.iter(|| {
            for i in 0..32 {
                ring.push(Sqe::nop().user_data(i)).unwrap();
            }
            ring.submit_and_wait(32).unwrap();
            let count = ring.completions().count();
            black_box(count);
        });
    });

    c.bench_function("nop_batch_128", |b| {
        let mut ring = IoUring::new(128).expect("setup failed");
        b.iter(|| {
            for i in 0..128 {
                ring.push(Sqe::nop().user_data(i)).unwrap();
            }
            ring.submit_and_wait(128).unwrap();
            let count = ring.completions().count();
            black_box(count);
        });
    });
}

fn bench_read_write(c: &mut Criterion) {
    let fd = open_tmpfile();
    let mut ring = IoUring::new(32).expect("setup failed");

    // Pre-write some data so reads have something to return
    let write_buf = [0xABu8; 4096];
    ring.push(unsafe { Sqe::write(fd, write_buf.as_ptr(), 4096, 0) }.user_data(0))
        .unwrap();
    ring.submit_and_wait(1).unwrap();
    ring.complete().unwrap();

    c.bench_function("write_4k", |b| {
        b.iter(|| {
            ring.push(unsafe { Sqe::write(fd, write_buf.as_ptr(), 4096, 0) }.user_data(1))
                .unwrap();
            ring.submit_and_wait(1).unwrap();
            black_box(ring.complete().unwrap());
        });
    });

    c.bench_function("read_4k", |b| {
        let mut read_buf = [0u8; 4096];
        b.iter(|| {
            ring.push(unsafe { Sqe::read(fd, read_buf.as_mut_ptr(), 4096, 0) }.user_data(1))
                .unwrap();
            ring.submit_and_wait(1).unwrap();
            black_box(ring.complete().unwrap());
        });
    });
}

fn bench_vectored_write(c: &mut Criterion) {
    let fd = open_tmpfile();
    let mut ring = IoUring::new(32).expect("setup failed");

    let mut buf_a = [0xAAu8; 2048];
    let mut buf_b = [0xBBu8; 2048];

    c.bench_function("writev_2x2k", |b| {
        let vecs = unsafe {
            [
                IoVec::new(buf_a.as_mut_ptr(), buf_a.len()),
                IoVec::new(buf_b.as_mut_ptr(), buf_b.len()),
            ]
        };
        b.iter(|| {
            ring.push(unsafe { Sqe::writev(fd, vecs.as_ptr(), 2, 0) }.user_data(1))
                .unwrap();
            ring.submit_and_wait(1).unwrap();
            black_box(ring.complete().unwrap());
        });
    });
}

criterion_group!(
    benches,
    bench_ring_setup,
    bench_sqe_construction,
    bench_nop_single,
    bench_nop_batch,
    bench_read_write,
    bench_vectored_write,
);
criterion_main!(benches);
