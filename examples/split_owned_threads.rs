//! Independent submit and complete loops on two OS threads, with no
//! `unsafe` anywhere in this file.
//!
//! Run with:
//!   cargo run --example `split_owned_threads`
//!
//! # What this demonstrates
//!
//! `Sqe`'s pointer-bearing constructors are `unsafe` because an `Sqe` is
//! `Copy` and carries no lifetime: the borrow taken to build one ends when
//! the constructor returns, but the kernel reads the pointer much later.
//! The only *safe* way to use them is to block until the completion lands,
//! which defeats the point of splitting the ring.
//!
//! The owned API removes the borrow. A buffer moves into the request, the
//! request becomes a `Pending` ticket that owns the storage, and the ticket
//! travels to the completion thread through an ordinary channel. Neither
//! thread waits on the other, and the crate holds no slab — this file
//! decides where tickets live.
//!
//! # Shape
//!
//! ```text
//!   submit thread                        complete thread
//!   -------------                        ---------------
//!   buffer -> Prepared::write            recv ticket
//!   push   -> Pending ticket ---------->
//!   submit (never blocks on completion)  wait_one -> Receipt
//!                                        ticket.redeem(receipt)
//!                                        -> Completed -> buffer back
//! ```

use std::sync::mpsc;
use std::thread;

use ququmatz::IoUring;
use ququmatz::owned::{MmapBuffer, Pending, Prepared};
use ququmatz::types::RawFd;

const MESSAGES: usize = 32;
const BUF_SIZE: usize = 64;

fn main() {
    let ring = IoUring::new(16).expect("ring setup");
    let (mut submitter, mut completer) = ring
        .split_owned()
        .unwrap_or_else(|(_, e)| panic!("split_owned: {e}"));

    // The application owns the in-flight tickets, not the crate.
    let (ticket_tx, ticket_rx) = mpsc::channel::<Pending<MmapBuffer>>();
    // Completed buffers cycle back for reuse instead of being remapped.
    let (recycle_tx, recycle_rx) = mpsc::channel::<MmapBuffer>();

    let submit = thread::spawn(move || {
        for i in 0..MESSAGES {
            // Reuse a returned buffer once the completion thread frees one.
            let mut buf = recycle_rx
                .try_recv()
                .unwrap_or_else(|_| MmapBuffer::with_capacity(BUF_SIZE).expect("map buffer"));

            let msg = format!("message-{i:02}\n");
            let n = u32::try_from(msg.len()).expect("message fits in u32");
            buf.as_mut_slice()[..msg.len()].copy_from_slice(msg.as_bytes());

            // The buffer moves into the request; no alias is left behind.
            let request = Prepared::write(RawFd::from_raw(1), buf, u64::MAX).with_len(n);

            let ticket = match submitter.push(request) {
                Ok(ticket) => ticket,
                Err((returned, e)) => {
                    // Queue full: the request came back owning its buffer,
                    // so nothing leaked and it can be retried.
                    eprintln!("[submit ] queue full ({e}), draining");
                    submitter.submit().expect("submit");
                    submitter
                        .push(returned)
                        .unwrap_or_else(|(_, e)| panic!("retry push: {e}"))
                }
            };

            ticket_tx.send(ticket).expect("completion thread alive");
            submitter.submit().expect("submit");
        }
        drop(ticket_tx);
        submitter
    });

    let complete = thread::spawn(move || {
        let mut done = 0usize;
        let mut bytes = 0u64;

        // Tickets arrive independently of completions; both are awaited
        // here without the submission thread ever blocking on us.
        while let Ok(ticket) = ticket_rx.recv() {
            let receipt = completer.wait_one().expect("wait for completion");

            let finished = match ticket.redeem(receipt) {
                Ok(finished) => finished,
                Err((ticket, receipt)) => {
                    // Out-of-order delivery would land here; this example
                    // submits strictly in order, so it should not happen.
                    panic!(
                        "receipt {:?} did not match ticket {:?}",
                        receipt.id(),
                        ticket.id()
                    );
                }
            };

            let (result, buf) = finished.into_parts();
            bytes += u64::from(result.expect("write should succeed"));
            done += 1;

            // Hand the storage back for the next submission.
            let _ = recycle_tx.send(buf);
            completer.sync();
        }
        (done, bytes, completer)
    });

    let _submitter = submit.join().expect("submit thread");
    let (done, bytes, _completer) = complete.join().expect("complete thread");

    println!("\n[main] completed {done}/{MESSAGES} writes, {bytes} bytes");
    assert_eq!(done, MESSAGES, "every request should complete");
    println!("[main] OK — independent submit/complete threads, zero unsafe");
}
