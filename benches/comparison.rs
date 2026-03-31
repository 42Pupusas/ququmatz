#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

//! Head-to-head benchmarks: ququmatz (raw syscall) vs io-uring crate.
//!
//! Each benchmark runs the same logical operation through both libraries so the
//! numbers are directly comparable. Criterion's comparison reports will show
//! the relative difference.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use std::os::unix::io::IntoRawFd;

// ── helpers ──────────────────────────────────────────────────────────────────

/// Open an anonymous tmpfile for benchmarking.
fn open_tmpfile_raw() -> i32 {
    std::fs::File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open("/tmp/ququmatz-cmp-bench-tmpfile")
        .expect("failed to open tmpfile")
        .into_raw_fd()
}

/// Drain all completions from an io-uring CompletionQueue without consuming it.
fn drain_cq(cq: &mut io_uring::cqueue::CompletionQueue<'_>) -> usize {
    let mut n = 0;
    while cq.next().is_some() {
        n += 1;
    }
    n
}

// ── 1. Ring setup / teardown ─────────────────────────────────────────────────

fn bench_ring_setup(c: &mut Criterion) {
    let mut g = c.benchmark_group("ring_setup");

    g.bench_function("ququmatz", |b| {
        b.iter(|| {
            let ring = ququmatz::IoUring::new(black_box(32)).expect("setup");
            drop(black_box(ring));
        });
    });

    g.bench_function("io-uring", |b| {
        b.iter(|| {
            let ring = io_uring::IoUring::new(black_box(32)).expect("setup");
            drop(black_box(ring));
        });
    });

    g.finish();
}

// ── 2. SQE construction (no kernel round-trip) ──────────────────────────────

fn bench_sqe_build(c: &mut Criterion) {
    let mut buf = [0u8; 4096];
    let ptr = buf.as_mut_ptr();

    {
        let mut g = c.benchmark_group("sqe_build_nop");

        g.bench_function("ququmatz", |b| {
            b.iter(|| black_box(ququmatz::Sqe::nop().user_data(1)));
        });

        g.bench_function("io-uring", |b| {
            b.iter(|| {
                black_box(
                    io_uring::opcode::Nop::new()
                        .build()
                        .user_data(1),
                )
            });
        });

        g.finish();
    }

    {
        let mut g = c.benchmark_group("sqe_build_read");

        g.bench_function("ququmatz", |b| {
            b.iter(|| black_box(unsafe { ququmatz::Sqe::read(3, ptr, 4096, 0) }.user_data(1)));
        });

        g.bench_function("io-uring", |b| {
            b.iter(|| {
                black_box(
                    io_uring::opcode::Read::new(io_uring::types::Fd(3), ptr, 4096)
                        .offset(0)
                        .build()
                        .user_data(1),
                )
            });
        });

        g.finish();
    }

    {
        let mut g = c.benchmark_group("sqe_build_write");

        g.bench_function("ququmatz", |b| {
            b.iter(|| black_box(unsafe { ququmatz::Sqe::write(3, ptr, 4096, 0) }.user_data(1)));
        });

        g.bench_function("io-uring", |b| {
            b.iter(|| {
                black_box(
                    io_uring::opcode::Write::new(io_uring::types::Fd(3), ptr, 4096)
                        .offset(0)
                        .build()
                        .user_data(1),
                )
            });
        });

        g.finish();
    }
}

// ── 3. Single NOP round-trip ─────────────────────────────────────────────────

fn bench_nop_single(c: &mut Criterion) {
    let mut g = c.benchmark_group("nop_single");

    {
        let mut ring = ququmatz::IoUring::new(32).expect("setup");
        g.bench_function("ququmatz", |b| {
            b.iter(|| {
                ring.push(ququmatz::Sqe::nop().user_data(1)).unwrap();
                ring.submit_and_wait(1).unwrap();
                black_box(ring.complete().unwrap());
            });
        });
    }

    {
        let mut ring = io_uring::IoUring::new(32).expect("setup");
        let (submitter, mut sq, mut cq) = ring.split();
        g.bench_function("io-uring", |b| {
            b.iter(|| {
                sq.sync();
                let entry = io_uring::opcode::Nop::new().build().user_data(1);
                unsafe { sq.push(&entry).unwrap() };
                sq.sync();
                submitter.submit_and_wait(1).unwrap();
                cq.sync();
                black_box(drain_cq(&mut cq));
            });
        });
    }

    g.finish();
}

// ── 4. NOP batch (32 and 128) ────────────────────────────────────────────────

fn bench_nop_batch(c: &mut Criterion) {
    {
        let mut g = c.benchmark_group("nop_batch_32");

        g.bench_function("ququmatz", |b| {
            let mut ring = ququmatz::IoUring::new(32).expect("setup");
            b.iter(|| {
                for i in 0..32u64 {
                    ring.push(ququmatz::Sqe::nop().user_data(i)).unwrap();
                }
                ring.submit_and_wait(32).unwrap();
                black_box(ring.completions().count());
            });
        });

        g.bench_function("io-uring", |b| {
            let mut ring = io_uring::IoUring::new(32).expect("setup");
            let (submitter, mut sq, mut cq) = ring.split();
            b.iter(|| {
                sq.sync();
                for i in 0..32u64 {
                    let entry = io_uring::opcode::Nop::new().build().user_data(i);
                    unsafe { sq.push(&entry).unwrap() };
                }
                sq.sync();
                submitter.submit_and_wait(32).unwrap();
                cq.sync();
                black_box(drain_cq(&mut cq));
            });
        });

        g.finish();
    }

    {
        let mut g = c.benchmark_group("nop_batch_128");

        g.bench_function("ququmatz", |b| {
            let mut ring = ququmatz::IoUring::new(128).expect("setup");
            b.iter(|| {
                for i in 0..128u64 {
                    ring.push(ququmatz::Sqe::nop().user_data(i)).unwrap();
                }
                ring.submit_and_wait(128).unwrap();
                black_box(ring.completions().count());
            });
        });

        g.bench_function("io-uring", |b| {
            let mut ring = io_uring::IoUring::new(128).expect("setup");
            let (submitter, mut sq, mut cq) = ring.split();
            b.iter(|| {
                sq.sync();
                for i in 0..128u64 {
                    let entry = io_uring::opcode::Nop::new().build().user_data(i);
                    unsafe { sq.push(&entry).unwrap() };
                }
                sq.sync();
                submitter.submit_and_wait(128).unwrap();
                cq.sync();
                black_box(drain_cq(&mut cq));
            });
        });

        g.finish();
    }
}

// ── 5. 4 KB write ────────────────────────────────────────────────────────────

fn bench_write_4k(c: &mut Criterion) {
    let mut g = c.benchmark_group("write_4k");
    let write_buf = [0xABu8; 4096];

    {
        let fd = open_tmpfile_raw();
        let mut ring = ququmatz::IoUring::new(32).expect("setup");
        g.bench_function("ququmatz", |b| {
            b.iter(|| {
                ring.push(unsafe { ququmatz::Sqe::write(fd, write_buf.as_ptr(), 4096, 0) }.user_data(1))
                    .unwrap();
                ring.submit_and_wait(1).unwrap();
                black_box(ring.complete().unwrap());
            });
        });
    }

    {
        let fd = open_tmpfile_raw();
        let mut ring = io_uring::IoUring::new(32).expect("setup");
        let (submitter, mut sq, mut cq) = ring.split();
        g.bench_function("io-uring", |b| {
            b.iter(|| {
                sq.sync();
                let entry =
                    io_uring::opcode::Write::new(io_uring::types::Fd(fd), write_buf.as_ptr(), 4096)
                        .offset(0)
                        .build()
                        .user_data(1);
                unsafe { sq.push(&entry).unwrap() };
                sq.sync();
                submitter.submit_and_wait(1).unwrap();
                cq.sync();
                black_box(drain_cq(&mut cq));
            });
        });
    }

    g.finish();
}

// ── 6. 4 KB read ─────────────────────────────────────────────────────────────

fn bench_read_4k(c: &mut Criterion) {
    let mut g = c.benchmark_group("read_4k");

    let seed_buf = [0xCDu8; 4096];

    {
        let fd = open_tmpfile_raw();
        let mut ring = ququmatz::IoUring::new(32).expect("setup");
        // seed
        ring.push(unsafe { ququmatz::Sqe::write(fd, seed_buf.as_ptr(), 4096, 0) }.user_data(0))
            .unwrap();
        ring.submit_and_wait(1).unwrap();
        ring.complete().unwrap();

        let mut read_buf = [0u8; 4096];
        g.bench_function("ququmatz", |b| {
            b.iter(|| {
                ring.push(
                    unsafe { ququmatz::Sqe::read(fd, read_buf.as_mut_ptr(), 4096, 0) }.user_data(1),
                )
                .unwrap();
                ring.submit_and_wait(1).unwrap();
                black_box(ring.complete().unwrap());
            });
        });
    }

    {
        let fd = open_tmpfile_raw();
        let mut ring_setup = ququmatz::IoUring::new(32).expect("setup");
        ring_setup
            .push(unsafe { ququmatz::Sqe::write(fd, seed_buf.as_ptr(), 4096, 0) }.user_data(0))
            .unwrap();
        ring_setup.submit_and_wait(1).unwrap();
        ring_setup.complete().unwrap();
        drop(ring_setup);

        let mut ring = io_uring::IoUring::new(32).expect("setup");
        let (submitter, mut sq, mut cq) = ring.split();
        let mut read_buf = [0u8; 4096];
        g.bench_function("io-uring", |b| {
            b.iter(|| {
                sq.sync();
                let entry = io_uring::opcode::Read::new(
                    io_uring::types::Fd(fd),
                    read_buf.as_mut_ptr(),
                    4096,
                )
                .offset(0)
                .build()
                .user_data(1);
                unsafe { sq.push(&entry).unwrap() };
                sq.sync();
                submitter.submit_and_wait(1).unwrap();
                cq.sync();
                black_box(drain_cq(&mut cq));
            });
        });
    }

    g.finish();
}

// ── 7. Vectored write (2x2K) ────────────────────────────────────────────────

fn bench_writev(c: &mut Criterion) {
    let mut g = c.benchmark_group("writev_2x2k");

    {
        let fd = open_tmpfile_raw();
        let mut ring = ququmatz::IoUring::new(32).expect("setup");
        let mut buf_a = [0xAAu8; 2048];
        let mut buf_b = [0xBBu8; 2048];

        g.bench_function("ququmatz", |b| {
            let vecs = [
                ququmatz::IoVec {
                    base: buf_a.as_mut_ptr(),
                    len: buf_a.len(),
                },
                ququmatz::IoVec {
                    base: buf_b.as_mut_ptr(),
                    len: buf_b.len(),
                },
            ];
            b.iter(|| {
                ring.push(unsafe { ququmatz::Sqe::writev(fd, vecs.as_ptr(), 2, 0) }.user_data(1))
                    .unwrap();
                ring.submit_and_wait(1).unwrap();
                black_box(ring.complete().unwrap());
            });
        });
    }

    {
        let fd = open_tmpfile_raw();
        let mut ring = io_uring::IoUring::new(32).expect("setup");
        let (submitter, mut sq, mut cq) = ring.split();
        let buf_a = [0xAAu8; 2048];
        let buf_b = [0xBBu8; 2048];

        g.bench_function("io-uring", |b| {
            let vecs = [
                std::io::IoSlice::new(&buf_a),
                std::io::IoSlice::new(&buf_b),
            ];
            b.iter(|| {
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
                black_box(drain_cq(&mut cq));
            });
        });
    }

    g.finish();
}

// ── 8. Linked chain (3 NOPs) ────────────────────────────────────────────────

fn bench_linked_chain(c: &mut Criterion) {
    let mut g = c.benchmark_group("linked_nops_3");

    {
        let mut ring = ququmatz::IoUring::new(32).expect("setup");
        g.bench_function("ququmatz", |b| {
            b.iter(|| {
                ring.push(ququmatz::Sqe::nop().user_data(1).link()).unwrap();
                ring.push(ququmatz::Sqe::nop().user_data(2).link()).unwrap();
                ring.push(ququmatz::Sqe::nop().user_data(3)).unwrap();
                ring.submit_and_wait(3).unwrap();
                black_box(ring.completions().count());
            });
        });
    }

    {
        let mut ring = io_uring::IoUring::new(32).expect("setup");
        let (submitter, mut sq, mut cq) = ring.split();
        g.bench_function("io-uring", |b| {
            b.iter(|| {
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
                black_box(drain_cq(&mut cq));
            });
        });
    }

    g.finish();
}

// ── 9. SQE struct size (compile-time safety check) ──────────────────────────
//
// Not a runtime benchmark — validates that our SQE is the same size as the
// kernel's, compared to io-uring crate's representation.

fn bench_struct_sizes(c: &mut Criterion) {
    let mut g = c.benchmark_group("struct_size_check");

    g.bench_function("size_validation", |b| {
        b.iter(|| {
            let ours = core::mem::size_of::<ququmatz::types::IoUringSqe>();
            let theirs = core::mem::size_of::<io_uring::squeue::Entry>();
            assert_eq!(ours, theirs, "SQE size mismatch: ours={ours}, theirs={theirs}");
            assert_eq!(ours, 64, "SQE must be 64 bytes");

            let our_cqe = core::mem::size_of::<ququmatz::types::IoUringCqe>();
            let their_cqe = core::mem::size_of::<io_uring::cqueue::Entry>();
            assert_eq!(
                our_cqe, their_cqe,
                "CQE size mismatch: ours={our_cqe}, theirs={their_cqe}"
            );
            black_box((ours, theirs, our_cqe, their_cqe));
        });
    });

    g.finish();
}

// ── groups ───────────────────────────────────────────────────────────────────

criterion_group!(
    benches,
    bench_ring_setup,
    bench_sqe_build,
    bench_nop_single,
    bench_nop_batch,
    bench_write_4k,
    bench_read_4k,
    bench_writev,
    bench_linked_chain,
    bench_struct_sizes,
);
criterion_main!(benches);
