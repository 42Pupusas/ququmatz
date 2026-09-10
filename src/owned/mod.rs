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
//! # A message header holds the addresses, not the SQE
//!
//! [`PreparedSendmsg`] is where the indirection stops being something the
//! SQE describes. Every request above puts the addresses the kernel will
//! dereference into SQE fields, where they can be checked when the request
//! is built. A `sendmsg` puts one address there — a `struct msghdr` — and
//! the kernel reads *that* to learn where the `iovec` array and the
//! destination address are, then follows those to reach the data.
//!
//! So the addresses are bytes in caller memory that happen to be pointers,
//! and nothing in the type system relates them to what they point at. A
//! header that moved would leave the kernel reading three plausible
//! addresses out of whatever now occupied that space. The header, the
//! descriptors, and the address are therefore staged together in one
//! caller-supplied region whose stability is checked once and which comes
//! back at the end; the payload buffers stay inline, since
//! [`StableBuffer`] already covers them.
//!
//! What `sendmsg` adds over [`PreparedVectored`] is what a socket needs and
//! a file does not: a per-message destination, so one unconnected socket
//! can be sent from without a `connect` per peer, and flags that belong to
//! the message rather than the descriptor.
//!
//! # A received message answers in the header, not the result
//!
//! [`PreparedRecvmsg`] chains the same three regions the other direction,
//! and the difference is not symmetry. The kernel **writes** the header as
//! well as reading it, so the staging region is a destination too — which
//! is why the completion's most important field is not in the CQE.
//!
//! An 11-byte datagram delivered into a 2-byte buffer completes with `2`.
//! So does a 2-byte datagram that arrived whole. The nine discarded bytes
//! appear nowhere in the result; only [`MsgOutFlags::TRUNC`], written back
//! into `msg_flags`, tells them apart. [`RecvmsgCompleted::received`]
//! therefore returns the count and the flags together as [`Received`],
//! because the count alone cannot answer the question a caller has. The
//! same shape on a *stream* socket sets no flag and loses nothing: the
//! remainder stays queued, so a short read there is not a loss.
//!
//! The peer address is the other place the header outranks the result.
//! [`PeerWanted`] reserves one `SockAddrIn`, and what comes back may be
//! less than that, more, or nothing:
//!
//! - a connected socket writes no address and reports `0`, however much
//!   room was reserved;
//! - an IPv6 peer reports `28` while writing only the 16 bytes it was
//!   given, leaving the rest of the slot untouched;
//! - an `AF_UNIX` peer with a short path reports a length *between* the
//!   two, filling part of the slot and no more.
//!
//! Reading the whole slot in the last two cases mixes the kernel's bytes
//! with whatever preceded them. [`PeerAddress`] makes that unreachable:
//! [`V4`](PeerAddress::V4) exists only when the reported length is exactly
//! a whole `SockAddrIn` and the family written is `AF_INET`, and the other
//! variants say why not rather than handing back a plausible-looking
//! address.
//!
//! A *failed* receive writes nothing back at all, so the header still
//! holds whatever the caller staged. That is why the outcome is reported
//! through [`received`](RecvmsgCompleted::received) rather than by reading
//! the header: after `EAGAIN`, the reserved length is still sitting there
//! and would otherwise be read as a sender.
//!
//! [`MsgOutFlags::TRUNC`]: crate::types::MsgOutFlags::TRUNC
//!
//! # `statx` writes a struct, not bytes
//!
//! Every other request is bounded by the SQE's length field, so a
//! destination that is too small yields a short transfer. `statx` has no
//! length for its destination at all: the kernel writes a whole
//! [`Statx`](crate::types::Statx) at `addr2` and reports only success or
//! `-errno`, so undersized or misaligned storage is a fixed-size write past
//! the end rather than anything the result reveals. [`PreparedStatx`]
//! checks both before the request can exist.
//!
//! What comes back differs too. A read's byte count describes bytes that
//! are all meaningful; a `statx` result is *partially* valid, and which
//! fields the kernel filled is reported in-band by `stx_mask` — which need
//! not match what was asked for. The mask-gated accessors on `Statx` return
//! `Option` for that reason and are the intended way to read one.
//!
//! # A direct accept can stop without failing
//!
//! [`DirectAccept`] installs each connection into a slot of the ring's file
//! table rather than into this process, so what arrives is a
//! [`DirectSlot`] and there is no descriptor to close. The slot is always
//! kernel-chosen: one armed request accepts many connections and they
//! cannot share a slot.
//!
//! The consequence worth knowing is that exhausting the table **ends the
//! request**. The kernel gates its re-arm on a non-negative result, so a
//! full table reports `-ENFILE` on a terminal CQE and the listener stops —
//! and a registered table is far smaller than `RLIMIT_NOFILE`, so this is
//! routine rather than exotic. Waiting for further completions after that
//! blocks forever, which is why [`DirectIncoming::Done`] is a variant
//! callers must name.
//!
//! # A direct socket can quietly destroy what it replaces
//!
//! [`PreparedDirectSocket`] creates a socket straight into the ring's file
//! table, so it owns no memory and nothing leaks if the ticket is dropped
//! — but the slot it fills does need recording, since an unnamed slot
//! stays occupied until the ring dies.
//!
//! The sharp edge is an explicit [`SlotTarget::Exact`]: the kernel removes
//! and closes whatever file already occupies that slot, and reports the
//! same `0` it reports for any other success. Nothing in the completion
//! says a live file was destroyed, so [`SlotTarget::Auto`] is the safer
//! choice unless the caller knows the slot is free.
//!
//! # Directory-entry work produces nothing but can destroy something
//!
//! [`PreparedPathOp`] and [`PreparedRename`] own path storage like an
//! open, but their completions carry no resource at all — only `0` or
//! `-errno`. Abandoning a ticket therefore leaks just the storage the
//! caller supplied, with no descriptor and no table slot going with it.
//!
//! What they can do is destroy data, so the destructive choices are named
//! rather than defaulted. A [`RenameMode::Replace`] overwrites the
//! destination and reports the same `0` as a rename onto a free name, and
//! [`RenameMode::NoReplace`] is the atomic way to avoid that. The modes
//! are an enum because the kernel rejects `NOREPLACE` and `EXCHANGE`
//! together, so the broken combination cannot be written.
//!
//! [`PathOpKind`] splits removals the same way: `AT_REMOVEDIR` reads like
//! an option but the kernel refuses both mismatches, failing `EISDIR`
//! without it on a directory and `ENOTDIR` with it on a file. Separating
//! [`PathOpKind::Unlink`] from [`PathOpKind::Rmdir`] makes the two working
//! combinations the only two reachable ones.
//!
//! # `openat2` describes itself in caller memory
//!
//! [`PreparedOpen`] puts its flags and mode in the SQE. `openat2` puts
//! them in a `struct open_how` in the caller's memory and stores only its
//! address, so the kernel dereferences a *second* region to learn what the
//! request is. That is the vectored-array hazard rather than an open's:
//! an inline struct would move when the `Send` ticket moved, and the
//! kernel would open whatever the parameters at that address described.
//! [`PreparedOpenat2`] therefore takes owned, size- and alignment-checked
//! storage for it, like [`PreparedVectored`] does for its descriptors.
//!
//! `openat2` also validates what `openat` ignores — a mode without
//! `CREAT`, a mode above `0o7777`, an unknown flag or resolve bit are all
//! `EINVAL` rather than silently dropped. [`Openat2Mode`] pairs the mode
//! with the flag that gives it meaning so the first cannot be written, and
//! the `how_size` the kernel checks is this crate's own `size_of` rather
//! than a caller parameter.
//!
//! # A timeout's result reads backwards
//!
//! Every request above treats a negative result as a failure. A timeout
//! inverts that: the kernel reports `-ETIME` when the timer ran to
//! completion — the thing that was asked for — and `0` when it did not,
//! because enough other completions arrived first. A `Result` would call
//! the working case an error and the pre-empted case a success, so
//! [`TimeoutCompleted::expiry`] yields [`Expiry`] instead, which names all
//! four outcomes. [`Count`] names the barrier for the same reason: `0` is
//! a different kind of request, not a smaller number of one.
//!
//! The storage is the interesting part. Measured on a live ring, the
//! kernel copies the `Timespec` during `io_uring_enter` and never reads it
//! again — a timeout staged at 300ms, submitted, then overwritten with
//! 9000ms still fires at 300ms. That almost argues for a borrow. It fails
//! on SQPOLL: [`split_owned`](crate::IoUring::split_owned) accepts a
//! polling ring, and there the submitting thread never enters the kernel
//! at all, so no call's return proves the copy has happened and a borrow
//! has nowhere safe to end. [`PreparedTimeout`] owns its storage until the
//! completion like everything else.
//!
//! Linked timeouts stay on the [`Sqe`](crate::Sqe) surface: they must be
//! submitted *immediately after* the operation they cancel, and nothing
//! here expresses "these two SQEs are adjacent and in this order".
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
mod direct_accept;
mod direct_socket;
mod event;
mod identity;
mod msgregion;
mod multishot;
mod open;
mod openat2;
mod path;
mod pathop;
mod queue;
mod recvmsg;
mod rename;
mod request;
mod sendmsg;
mod slot;
mod statx;
mod timeout;
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
pub use direct_accept::{DirectAccept, DirectAcceptFinished, DirectIncoming, PreparedDirectAccept};
pub use direct_socket::{
    DirectSocketCreated, DirectSocketError, PendingDirectSocket, PreparedDirectSocket,
};
pub use event::{Event, PartialReceipt};
pub use identity::{RequestId, RingId};
pub use msgregion::{MAX_IOV, MsgRegionError};
pub use multishot::{Armed, Arrival, Delivery, Finished, MultishotRecv, PreparedMultishot};
pub use open::{Opened, PendingOpen, PreparedOpen};
pub use openat2::{Openat2Error, Openat2Mode, Opened2, PendingOpenat2, PreparedOpenat2};
pub use path::{OwnedPath, PathError};
pub use pathop::{PathOpCompleted, PathOpKind, PendingPathOp, PreparedPathOp};
pub use queue::{OwnedCompleter, OwnedSubmitter};
pub use recvmsg::{
    PeerAddress, PeerWanted, PendingRecvmsg, PreparedRecvmsg, Received, RecvmsgCompleted,
};
pub use rename::{PendingRename, PreparedRename, RenameCompleted, RenameMode};
pub use request::{Completed, Direction, Pending, Prepared, Receipt};
pub use sendmsg::{PendingSendmsg, PreparedSendmsg, SendTarget, SendmsgCompleted};
pub use slot::{DirectSlot, SlotIndex, SlotTarget};
pub use statx::{PendingStatx, PreparedStatx, StatxCompleted, StatxError};
pub use timeout::{Count, Expiry, PendingTimeout, PreparedTimeout, TimeoutCompleted, TimeoutError};
pub use vectored::{PendingVectored, PreparedVectored, VectoredCompleted, VectoredError};
pub use zerocopy::{PendingZc, PreparedZc, ZcCompleted};
