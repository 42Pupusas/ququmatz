//! Safe owned-buffer submission for split submit/complete threads.
//!
//! [`Sqe`](crate::Sqe)'s pointer-bearing constructors are `unsafe` because
//! an `Sqe` is `Copy`, carries no lifetime, and is read by the kernel long
//! after the constructor's borrow ended. This module removes that problem
//! by transferring buffer *ownership* into the request instead of
//! borrowing, which is what lets submission and completion sit on
//! independent OS threads with no `unsafe` at the call site.
//!
//! # The three states
//!
//! | State | Owns the buffer | Buffer reachable |
//! |---|---|---|
//! | [`Prepared`] | yes | yes — fill it before submitting |
//! | [`Pending`] | yes | no — the kernel may be using it |
//! | [`Completed`] | yes | yes — the kernel is done |
//!
//! [`Pending`] is the ticket the application moves between threads. It is
//! `Send` whenever its buffer is, so any ordinary channel works; the crate
//! keeps no slab and imposes no storage policy.
//!
//! # Redemption is authenticated
//!
//! [`Completion`](crate::Completion) is a public struct any safe code can
//! construct, so matching `user_data` is not proof of anything. A
//! [`Receipt`] can only be minted by [`OwnedCompleter::reap`] from a CQE it
//! actually reaped, and it carries both the request and ring identity.
//! [`Pending::redeem`] rejects a receipt from another request or another
//! ring, so a forged or stale value cannot release a live buffer.
//!
//! # Zero-copy sends hold their buffer longer
//!
//! [`Prepared`] covers `read` and `write`, where one CQE means the kernel
//! is done. A zero-copy send is different: the send CQE reports only how
//! much was accepted, while the NIC may still be reading the pages, so the
//! buffer is released by a later notification. [`PreparedZc`] and
//! [`PendingZc`] model that second step, and [`OwnedCompleter::reap_event`]
//! tells the two completions apart by the kernel's `MORE` flag rather than
//! by counting. A send that promises no notification is terminal
//! immediately, so nothing waits forever for a CQE that will not arrive.
//!
//! # `MORE` is the general question
//!
//! That flag is not really about zero-copy sends. It answers "will more
//! completions follow?", which is exactly "may this CQE release anything?",
//! so every request whose life spans several CQEs is classified the same
//! way: non-terminal completions become [`PartialReceipt`], which nothing
//! accepts where a release is required, and only a [`Receipt`] frees
//! storage. What a CQE *carries* is a separate axis — a multishot arrival
//! brings a pool buffer id along — so [`PartialReceipt`] keeps the kernel's
//! flags rather than discarding them.
//!
//! # Vectored I/O has a second thing to keep still
//!
//! A scalar request hands the kernel one pointer. [`PreparedVectored`]
//! hands it a pointer to an **array of `IoVec`**, which the kernel
//! dereferences to reach the data — so two separate regions must stay put,
//! the buffers and the array naming them. The buffers are already covered:
//! [`StableBuffer`] promises the bytes do not move even when the owner
//! does, so `[B; N]` sits inline in the ticket.
//!
//! The array cannot. A ticket is `Send` and is *meant* to be moved to a
//! completion thread, so an inline array would relocate the exact bytes the
//! kernel is about to read. That is the same guarantee [`StableBuffer`]
//! already encodes, so the array's storage is required to implement it
//! rather than getting a new trait, and it is checked for size and
//! alignment before anything is written into it.
//!
//! # Multishot borrows instead of owning
//!
//! [`PreparedMultishot`] is the exception to the ownership rule above: one
//! SQE stays armed across many arrivals, and the kernel draws a buffer from
//! a registered pool for each one. The resource is therefore not an
//! allocation but a borrow of a pool slot that must be recycled exactly
//! once, so [`Arrival`] is a guard that returns its slot on drop rather
//! than a value that owns storage. A terminal CQE means the request is
//! over and must be re-submitted — [`Delivery::Done`] says so, and the
//! enum is exhaustive so callers cannot quietly ignore it and leave a
//! socket deaf. "Terminal" and "carries a buffer" are independent too: the
//! kernel folds the last arrival into the terminal CQE when it cannot post
//! a separate one, so [`Finished`] hands that slot back rather than
//! dropping it.
//!
//! [`PreparedAccept`] shares that state machine but not the ownership
//! story, which is why it is a separate type rather than a parameter on
//! the other. A recv arrival *borrows* a pool slot the kernel is waiting
//! to reuse; an accepted connection is *owned* outright, already installed
//! into this process by the kernel, releasable only by `close`. So
//! [`Incoming::Connection`] carries a plain [`Socket`](crate::net::Socket)
//! with no lifetime, and dropping it closes rather than recycles.
//!
//! # Opening produces a resource as well as returning one
//!
//! [`PreparedOpen`] is the first request whose *result* is itself a
//! resource. The path storage goes in and comes back, but the completion
//! also carries a descriptor the kernel created, so two independent things
//! are reclaimable from one CQE — and they fail differently. Losing the
//! storage leaks memory; losing the descriptor consumes a slot in a table
//! bounded by `RLIMIT_NOFILE`, which runs out first. So
//! [`Opened::into_parts`] hands back both, and the descriptor arrives as an
//! owning [`File`](crate::fs::File) that closes if it is never used.
//!
//! The path is also the first buffer the kernel reads **without a length**.
//! `openat` takes only an address and scans for a NUL, so the terminator is
//! the entire bound: an unterminated path is not a short read but a walk off
//! the end of the allocation. [`OwnedPath`] carries the proof that a NUL is
//! present, and a request cannot be built without one.
//!
//! # Abandonment leaks instead of corrupting
//!
//! Dropping or [`forget`](core::mem::forget)ting a [`Pending`] does not
//! free its buffer. The kernel may still write to those bytes, and the
//! crate keeps no registry that could reclaim them later, so the storage
//! leaks on purpose. That is the safe failure mode, and it is the reason
//! this design survives `mem::forget` where a borrowed-guard design cannot.
//! Normal redemption reclaims everything.
//!
//! # Example
//!
//! ```no_run
//! use ququmatz::owned::{MmapBuffer, Prepared};
//! use ququmatz::{IoUring, types::RawFd};
//!
//! let ring = IoUring::new(8).expect("ring");
//! let (mut sub, mut comp) = ring.split_owned().unwrap_or_else(|(_, e)| panic!("{e}"));
//!
//! let mut buf = MmapBuffer::with_capacity(64).expect("buffer");
//! buf.as_mut_slice()[..5].copy_from_slice(b"hello");
//!
//! // The buffer moves into the request, then into the ticket.
//! let ticket = sub
//!     .push(Prepared::write(RawFd::from_raw(1), buf, 0))
//!     .unwrap_or_else(|(_, e)| panic!("{e}"));
//! sub.submit().expect("submit");
//!
//! // On the completion thread: a receipt unlocks the buffer.
//! let receipt = comp.wait_one().expect("completion");
//! let done = ticket.redeem(receipt).unwrap_or_else(|_| panic!("mismatched"));
//! let (written, buf) = done.into_parts();
//! assert_eq!(written.expect("write ok"), 5);
//! drop(buf);
//! ```

mod accept;
mod buffer;
mod direct;
mod event;
mod identity;
mod multishot;
mod open;
mod path;
mod queue;
mod request;
mod slot;
mod vectored;
mod zerocopy;

#[cfg(test)]
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
mod tests;

#[cfg(test)]
mod event_tests;

#[cfg(test)]
mod miri;

pub use accept::{AcceptFinished, Incoming, MultishotAccept, PreparedAccept};
pub use buffer::{MmapBuffer, StableBuffer, StableBufferMut};
pub use direct::{DirectOpenError, DirectOpened, PendingDirectOpen, PreparedDirectOpen};
pub use event::{Event, PartialReceipt};
pub use identity::{RequestId, RingId};
pub use multishot::{Armed, Arrival, Delivery, Finished, MultishotRecv, PreparedMultishot};
pub use open::{Opened, PendingOpen, PreparedOpen};
pub use path::{OwnedPath, PathError};
pub use queue::{OwnedCompleter, OwnedSubmitter};
pub use request::{Completed, Direction, Pending, Prepared, Receipt};
pub use slot::{DirectSlot, SlotIndex, SlotTarget};
pub use vectored::{PendingVectored, PreparedVectored, VectoredCompleted, VectoredError};
pub use zerocopy::{PendingZc, PreparedZc, ZcCompleted};
