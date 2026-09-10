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

mod buffer;
mod identity;
mod queue;
mod request;

#[cfg(test)]
#[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
mod tests;

pub use buffer::{MmapBuffer, StableBuffer, StableBufferMut};
pub use identity::{RequestId, RingId};
pub use queue::{OwnedCompleter, OwnedSubmitter};
pub use request::{Completed, Direction, Pending, Prepared, Receipt};
