//! Heap-allocation comparison: ququmatz vs io-uring crate.
//!
//! Run with:
//!   cargo run --example `dhat_comparison` --features dhat-heap
//!
//! Each section profiles one logical operation through both libraries and
//! prints a side-by-side table of dhat's heap stats.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

#[cfg(feature = "dhat-heap")]
use ququmatz::types::RawFd;
#[cfg(feature = "dhat-heap")]
use std::os::unix::io::IntoRawFd;

#[cfg(feature = "dhat-heap")]
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

#[cfg(feature = "dhat-heap")]
fn drain_cq(cq: &mut io_uring::cqueue::CompletionQueue<'_>) {
    while cq.next().is_some() {}
}

// ── dhat helpers ─────────────────────────────────────────────────────────────

#[cfg(feature = "dhat-heap")]
struct Stats {
    total_bytes: u64,
    total_blocks: u64,
    peak_bytes: usize,
    peak_blocks: usize,
}

#[cfg(feature = "dhat-heap")]
fn capture(profiler: dhat::Profiler) -> Stats {
    let stats = dhat::HeapStats::get();
    drop(profiler);
    Stats {
        total_bytes: stats.total_bytes,
        total_blocks: stats.total_blocks,
        peak_bytes: stats.max_bytes,
        peak_blocks: stats.max_blocks,
    }
}

#[cfg(feature = "dhat-heap")]
fn print_row(label: &str, qq: &Stats, iu: &Stats) {
    println!(
        "{label:<30}  qq: {qb:>8} B / {qbl:>4} blk (peak {qpb:>8} B)   \
         iu: {ib:>8} B / {ibl:>4} blk (peak {ipb:>8} B)",
        qb = qq.total_bytes,
        qbl = qq.total_blocks,
        qpb = qq.peak_bytes,
        ib = iu.total_bytes,
        ibl = iu.total_blocks,
        ipb = iu.peak_bytes,
    );
}

#[cfg(not(feature = "dhat-heap"))]
fn main() {
    eprintln!("Run with: cargo run --example dhat_comparison --features dhat-heap");
}

#[cfg(feature = "dhat-heap")]
fn main() {
    println!("{:-<90}", "");
    println!("{:<30}  {:<42}  {}", "operation", "ququmatz", "io-uring");
    println!("{:-<90}", "");

    // ── 1. Ring setup / teardown ──────────────────────────────────────────────
    {
        let profiler = dhat::Profiler::new_heap();
        let ring = ququmatz::IoUring::new(32).expect("setup");
        drop(ring);
        let qq = capture(profiler);

        let profiler = dhat::Profiler::new_heap();
        let ring = io_uring::IoUring::new(32).expect("setup");
        drop(ring);
        let iu = capture(profiler);

        print_row("ring_setup_teardown", &qq, &iu);
    }

    // ── 2. NOP single round-trip ──────────────────────────────────────────────
    {
        let mut ring_qq = ququmatz::IoUring::new(32).expect("setup");
        let mut ring_iu = io_uring::IoUring::new(32).expect("setup");

        let profiler = dhat::Profiler::new_heap();
        ring_qq.push(ququmatz::Sqe::nop().user_data(1)).unwrap();
        ring_qq.submit_and_wait(1).unwrap();
        ring_qq.complete().unwrap();
        let qq = capture(profiler);

        let (submitter, mut sq, mut cq) = ring_iu.split();
        let profiler = dhat::Profiler::new_heap();
        sq.sync();
        let entry = io_uring::opcode::Nop::new().build().user_data(1);
        unsafe { sq.push(&entry).unwrap() };
        sq.sync();
        submitter.submit_and_wait(1).unwrap();
        cq.sync();
        drain_cq(&mut cq);
        let iu = capture(profiler);

        print_row("nop_single_roundtrip", &qq, &iu);
    }

    // ── 3. NOP batch 32 ──────────────────────────────────────────────────────
    {
        let mut ring_qq = ququmatz::IoUring::new(32).expect("setup");
        let mut ring_iu = io_uring::IoUring::new(32).expect("setup");

        let profiler = dhat::Profiler::new_heap();
        for i in 0..32u64 {
            ring_qq.push(ququmatz::Sqe::nop().user_data(i)).unwrap();
        }
        ring_qq.submit_and_wait(32).unwrap();
        ring_qq.completions().count();
        let qq = capture(profiler);

        let (submitter, mut sq, mut cq) = ring_iu.split();
        let profiler = dhat::Profiler::new_heap();
        sq.sync();
        for i in 0..32u64 {
            let entry = io_uring::opcode::Nop::new().build().user_data(i);
            unsafe { sq.push(&entry).unwrap() };
        }
        sq.sync();
        submitter.submit_and_wait(32).unwrap();
        cq.sync();
        drain_cq(&mut cq);
        let iu = capture(profiler);

        print_row("nop_batch_32", &qq, &iu);
    }

    // ── 4. NOP batch 128 ─────────────────────────────────────────────────────
    {
        let mut ring_qq = ququmatz::IoUring::new(128).expect("setup");
        let mut ring_iu = io_uring::IoUring::new(128).expect("setup");

        let profiler = dhat::Profiler::new_heap();
        for i in 0..128u64 {
            ring_qq.push(ququmatz::Sqe::nop().user_data(i)).unwrap();
        }
        ring_qq.submit_and_wait(128).unwrap();
        ring_qq.completions().count();
        let qq = capture(profiler);

        let (submitter, mut sq, mut cq) = ring_iu.split();
        let profiler = dhat::Profiler::new_heap();
        sq.sync();
        for i in 0..128u64 {
            let entry = io_uring::opcode::Nop::new().build().user_data(i);
            unsafe { sq.push(&entry).unwrap() };
        }
        sq.sync();
        submitter.submit_and_wait(128).unwrap();
        cq.sync();
        drain_cq(&mut cq);
        let iu = capture(profiler);

        print_row("nop_batch_128", &qq, &iu);
    }

    // ── 5. Write 4K ──────────────────────────────────────────────────────────
    {
        let fd_qq = open_tmpfile("/tmp/ququmatz-dhat-write-qq");
        let fd_iu = open_tmpfile("/tmp/ququmatz-dhat-write-iu");
        let write_buf = [0xABu8; 4096];
        let mut ring_qq = ququmatz::IoUring::new(32).expect("setup");
        let mut ring_iu = io_uring::IoUring::new(32).expect("setup");

        let profiler = dhat::Profiler::new_heap();
        ring_qq
            .push(
                unsafe {
                    ququmatz::Sqe::write_ptr(
                        RawFd::from_raw(fd_qq as usize),
                        write_buf.as_ptr(),
                        4096,
                        0,
                    )
                }
                .user_data(1),
            )
            .unwrap();
        ring_qq.submit_and_wait(1).unwrap();
        ring_qq.complete().unwrap();
        let qq = capture(profiler);

        let (submitter, mut sq, mut cq) = ring_iu.split();
        let profiler = dhat::Profiler::new_heap();
        sq.sync();
        let entry =
            io_uring::opcode::Write::new(io_uring::types::Fd(fd_iu), write_buf.as_ptr(), 4096)
                .offset(0)
                .build()
                .user_data(1);
        unsafe { sq.push(&entry).unwrap() };
        sq.sync();
        submitter.submit_and_wait(1).unwrap();
        cq.sync();
        drain_cq(&mut cq);
        let iu = capture(profiler);

        print_row("write_4k", &qq, &iu);
    }

    // ── 6. Read 4K ───────────────────────────────────────────────────────────
    {
        let seed = [0xCDu8; 4096];
        let fd_qq = open_tmpfile("/tmp/ququmatz-dhat-read-qq");
        let fd_iu = open_tmpfile("/tmp/ququmatz-dhat-read-iu");

        // seed both files
        {
            let mut r = ququmatz::IoUring::new(32).expect("setup");
            r.push(
                unsafe {
                    ququmatz::Sqe::write_ptr(
                        RawFd::from_raw(fd_qq as usize),
                        seed.as_ptr(),
                        4096,
                        0,
                    )
                }
                .user_data(0),
            )
            .unwrap();
            r.submit_and_wait(1).unwrap();
            r.complete().unwrap();
            r.push(
                unsafe {
                    ququmatz::Sqe::write_ptr(
                        RawFd::from_raw(fd_iu as usize),
                        seed.as_ptr(),
                        4096,
                        0,
                    )
                }
                .user_data(0),
            )
            .unwrap();
            r.submit_and_wait(1).unwrap();
            r.complete().unwrap();
        }

        let mut ring_qq = ququmatz::IoUring::new(32).expect("setup");
        let mut ring_iu = io_uring::IoUring::new(32).expect("setup");
        let mut read_buf = [0u8; 4096];

        let profiler = dhat::Profiler::new_heap();
        ring_qq
            .push(
                unsafe {
                    ququmatz::Sqe::read_ptr(
                        RawFd::from_raw(fd_qq as usize),
                        read_buf.as_mut_ptr(),
                        4096,
                        0,
                    )
                }
                .user_data(1),
            )
            .unwrap();
        ring_qq.submit_and_wait(1).unwrap();
        ring_qq.complete().unwrap();
        let qq = capture(profiler);

        let (submitter, mut sq, mut cq) = ring_iu.split();
        let profiler = dhat::Profiler::new_heap();
        sq.sync();
        let entry =
            io_uring::opcode::Read::new(io_uring::types::Fd(fd_iu), read_buf.as_mut_ptr(), 4096)
                .offset(0)
                .build()
                .user_data(1);
        unsafe { sq.push(&entry).unwrap() };
        sq.sync();
        submitter.submit_and_wait(1).unwrap();
        cq.sync();
        drain_cq(&mut cq);
        let iu = capture(profiler);

        print_row("read_4k", &qq, &iu);
    }

    // ── 7. Writev 2×2K ───────────────────────────────────────────────────────
    {
        let fd_qq = open_tmpfile("/tmp/ququmatz-dhat-writev-qq");
        let fd_iu = open_tmpfile("/tmp/ququmatz-dhat-writev-iu");
        let mut ring_qq = ququmatz::IoUring::new(32).expect("setup");
        let mut ring_iu = io_uring::IoUring::new(32).expect("setup");
        let mut buf_a = [0xAAu8; 2048];
        let mut buf_b = [0xBBu8; 2048];

        let vecs_qq = unsafe {
            [
                ququmatz::IoVec::new(buf_a.as_mut_ptr(), buf_a.len()),
                ququmatz::IoVec::new(buf_b.as_mut_ptr(), buf_b.len()),
            ]
        };
        let vecs_iu = [std::io::IoSlice::new(&buf_a), std::io::IoSlice::new(&buf_b)];

        let profiler = dhat::Profiler::new_heap();
        ring_qq
            .push(
                unsafe {
                    ququmatz::Sqe::writev_ptr(
                        RawFd::from_raw(fd_qq as usize),
                        vecs_qq.as_ptr(),
                        2,
                        0,
                    )
                }
                .user_data(1),
            )
            .unwrap();
        ring_qq.submit_and_wait(1).unwrap();
        ring_qq.complete().unwrap();
        let qq = capture(profiler);

        let (submitter, mut sq, mut cq) = ring_iu.split();
        let profiler = dhat::Profiler::new_heap();
        sq.sync();
        let entry =
            io_uring::opcode::Writev::new(io_uring::types::Fd(fd_iu), vecs_iu.as_ptr().cast(), 2)
                .offset(0)
                .build()
                .user_data(1);
        unsafe { sq.push(&entry).unwrap() };
        sq.sync();
        submitter.submit_and_wait(1).unwrap();
        cq.sync();
        drain_cq(&mut cq);
        let iu = capture(profiler);

        print_row("writev_2x2k", &qq, &iu);
    }

    // ── 8. Linked chain 3 NOPs ────────────────────────────────────────────────
    {
        let mut ring_qq = ququmatz::IoUring::new(32).expect("setup");
        let mut ring_iu = io_uring::IoUring::new(32).expect("setup");

        let profiler = dhat::Profiler::new_heap();
        ring_qq
            .push(ququmatz::Sqe::nop().user_data(1).link())
            .unwrap();
        ring_qq
            .push(ququmatz::Sqe::nop().user_data(2).link())
            .unwrap();
        ring_qq.push(ququmatz::Sqe::nop().user_data(3)).unwrap();
        ring_qq.submit_and_wait(3).unwrap();
        ring_qq.completions().count();
        let qq = capture(profiler);

        let (submitter, mut sq, mut cq) = ring_iu.split();
        let profiler = dhat::Profiler::new_heap();
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
        drain_cq(&mut cq);
        let iu = capture(profiler);

        print_row("linked_nops_3", &qq, &iu);
    }

    println!("{:-<90}", "");
    println!("columns: total_bytes / total_blocks (peak_bytes)");
}
