//! Concurrent submit / complete across two threads, sharing a kernel-owned
//! buffer pool — the pattern that a lifetime-erased `Sqe` alone cannot express.
//!
//! Run with:
//!   cargo run --example `split_pbuf_concurrent`
//!
//! # The problem this demonstrates
//!
//! `Sqe` stores a raw pointer and erases the buffer's lifetime, so the only
//! safe per-op API (`do_read` & friends) borrows the buffer across the *entire*
//! submit-and-wait cycle — one operation in flight at a time. That serializes
//! everything, even after `IoUring::split` hands you `Send` submit/complete
//! halves.
//!
//! Provided buffers sidestep the lifetime entirely: the bytes live in a pinned
//! mmap the kernel owns, referenced by *id*, not pointer. Nothing the caller
//! holds has to outlive a completion. So the pool can be split off as a `Send`
//! `BufferConsumer` and moved to the completion thread, while the submit thread
//! only ever names the pool by `bgid`. Many recvs are in flight at once; no
//! buffer is shared across the thread boundary as a borrow.
//!
//! # Shape
//!
//! ```text
//!   main: TcpStream pair (writer end stays here, drip-feeds N messages)
//!     |
//!     +-- submit thread:  push recv_multishot(server_fd).buffer_select(BGID)
//!     |                   submit once; the kernel pulls a pool buffer per msg
//!     |
//!     +-- complete thread: owns BufferConsumer; for each CQE, read the chosen
//!                          buffer by id, verify, recycle the id back to kernel
//! ```

#![allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]

use std::io::Write as _;
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd as _;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use ququmatz::types::{CqeFlags, MsgFlags, RawFd};
use ququmatz::{IoUring, Sqe};

const BGID: u16 = 1;
const POOL_ENTRIES: u32 = 8; // power of two
const BUF_SIZE: u32 = 64;
const MESSAGES: usize = 16; // more than the pool, to prove recycling works
const RECV_USER_DATA: u64 = 42;

/// Completion -> submission signal: re-arm the multishot recv, or stop.
enum RearmMsg {
    Rearm,
    Stop,
}

fn main() {
    // --- A connected TCP pair over loopback ----------------------------------
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let client = TcpStream::connect(addr).expect("connect");
    let (server, _peer) = listener.accept().expect("accept");
    // Keep the server fd alive for the whole run; io_uring borrows it by number.
    let server_fd = RawFd::from_raw(server.as_raw_fd() as usize);

    // --- Ring setup, then split ----------------------------------------------
    let ring = IoUring::new(16).expect("ring setup");
    let (mut submitter, mut completer) = ring.split();

    // Register the pool *through the Submitter* (the IoUring is already
    // consumed by split()), then hand its consumer half to the completion side.
    let pool = submitter
        .register_provided_buffers(BGID, POOL_ENTRIES, BUF_SIZE)
        .expect("register provided buffers");
    let mut consumer = pool.split(); // Send — moves to the completion thread

    // --- Submission thread ---------------------------------------------------
    // Arms a multishot recv, then re-arms whenever the completion thread asks.
    //
    // A multishot recv yields a CQE per arrival *until* the kernel terminates
    // it — it posts a final CQE with IORING_CQE_F_MORE clear (commonly
    // -ECANCELED, or -ENOBUFS if the pool ran dry). Per the io_uring contract,
    // the app must then submit a fresh multishot SQE. Because submission lives
    // on this thread, the completion thread signals us through `rearm_rx`.
    let (rearm_tx, rearm_rx) = mpsc::channel::<RearmMsg>();
    let submit = thread::spawn(move || {
        let arm = |s: &mut ququmatz::Submitter| {
            let sqe = Sqe::recv_multishot(server_fd, MsgFlags::default())
                .buffer_select(BGID)
                .user_data(RECV_USER_DATA);
            s.push(sqe).expect("push multishot recv");
            s.submit().expect("submit");
        };

        arm(&mut submitter); // initial arm
        // Re-arm on demand until the completion thread says we're done.
        while let Ok(msg) = rearm_rx.recv() {
            match msg {
                RearmMsg::Rearm => {
                    println!("[submit ] re-arming multishot recv");
                    arm(&mut submitter);
                }
                RearmMsg::Stop => break,
            }
        }
        submitter // hold the ring fd open until join
    });

    // --- Completion thread ---------------------------------------------------
    let (done_tx, done_rx) = mpsc::channel::<usize>();
    let complete = thread::spawn(move || {
        let mut received = 0usize;
        while received < MESSAGES {
            // Block in the kernel until at least one completion is ready.
            completer.wait(1).expect("wait");
            for cqe in completer.completions() {
                if cqe.user_data != RECV_USER_DATA {
                    continue;
                }
                let more = cqe.flags.contains(CqeFlags::MORE);

                if cqe.is_err() {
                    // Multishot terminated (e.g. -ECANCELED / -ENOBUFS). If the
                    // peer is still feeding us, re-arm and keep going.
                    println!(
                        "[complete] multishot ended: result={} (errno {}) more={more}",
                        cqe.result, -cqe.result
                    );
                    if received < MESSAGES {
                        rearm_tx.send(RearmMsg::Rearm).expect("submit thread alive");
                    }
                    continue;
                }

                let buf_id = cqe
                    .buffer_id()
                    .expect("multishot recv must report a buffer id");
                let len = cqe.result as u32;
                let payload = consumer.buffer(buf_id, len).expect("buffer slice in range");
                let text = core::str::from_utf8(payload).unwrap_or("<non-utf8>");
                println!(
                    "[complete] msg {received:2} -> buf #{buf_id} ({len} bytes) more={more}: {text:?}"
                );

                // Return the id so the kernel can reuse it for a later message.
                consumer.recycle_and_commit(buf_id);
                received += 1;

                // A data CQE without MORE means the multishot is gone too; the
                // next arrival needs a freshly armed request.
                if !more && received < MESSAGES {
                    rearm_tx.send(RearmMsg::Rearm).expect("submit thread alive");
                }
            }
        }
        rearm_tx.send(RearmMsg::Stop).expect("submit thread alive");
        let _ = done_tx.send(received);
        completer
    });

    // --- Drive traffic from the main thread ----------------------------------
    // Drip messages so several buffers are genuinely in flight / recycling,
    // rather than all arriving in one batch.
    let mut writer = client;
    for i in 0..MESSAGES {
        let msg = format!("message-{i:02}");
        writer.write_all(msg.as_bytes()).expect("write");
        writer.flush().expect("flush");
        thread::sleep(Duration::from_millis(5));
    }

    let received = done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("completion thread should finish");

    // Join both halves; dropping them releases the ring and the pool.
    let _submitter = submit.join().expect("submit thread");
    let _completer = complete.join().expect("complete thread");

    println!("\n[main] received {received}/{MESSAGES} messages across the split");
    assert_eq!(received, MESSAGES, "all messages should arrive");
    println!("[main] OK — concurrent submit/complete over a shared buffer pool");
}
