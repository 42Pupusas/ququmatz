//! `connect`, the last pointer-bearing operation to get an owned form.
//!
//! The kernel is handed a socket address at `addr` and its length in
//! `off` — note the difference from [`bind`](super::bind), which carries
//! the length in `addr2`. Everything else in the SQE stays zero.
//!
//! # `EINPROGRESS` is not reachable, so it is not in the outcome
//!
//! `connect(2)` on a non-blocking socket reports `EINPROGRESS` and leaves
//! the caller to poll for the result, which invites an `InProgress`
//! variant. Measured against a real kernel, that variant would be dead
//! code: `io_uring` arms a poll internally and retries, so the CQE is not
//! posted until the handshake has actually resolved. A socket created
//! with `SOCK_NONBLOCK` completes with `0`, not `-EINPROGRESS`.
//!
//! The same measurement shows the cost of that convenience: connecting to
//! an address nothing answers for does not complete promptly. The request
//! stays in flight until the kernel gives up, so a caller who needs a
//! deadline wants a linked timeout rather than a non-blocking socket.
//!
//! # A second connect reports `EISCONN`, not `EALREADY`
//!
//! Measured on a live ring:
//!
//! | request | result |
//! |---|---|
//! | connect to a listening socket | `0` |
//! | connect that socket a second time | `-EISCONN` |
//! | connect with `SOCK_NONBLOCK` set | `0` |
//! | connect to a port nothing listens on | `-ECONNREFUSED` |
//! | connect with a bad `sin_family` | `-EAFNOSUPPORT` |
//! | connect on a listening socket | `-EISCONN` |
//!
//! [`ConnectOutcome`] keeps `ConnectionRefused` apart from
//! `AlreadyConnected` because they call for opposite responses: retrying
//! reaches a listener that has since come up, and never un-connects a
//! socket that is already connected.
//!
//! The typed [`SockAddrIn`] rules out the `EAFNOSUPPORT` row at
//! construction, the same way it does for `bind`.
//!
//! # Storage is owned for the same reason bind's is
//!
//! Measured: an address overwritten *after* `submit` returned still
//! connects to the address originally staged, and one overwritten between
//! `push` and `submit` fails with `EAFNOSUPPORT`. The read happens inside
//! `io_uring_enter`.
//!
//! That is not enough for a borrow.
//! [`split_owned`](crate::IoUring::split_owned) accepts an SQPOLL ring,
//! where the submitting thread never enters the kernel and the SQ thread
//! reads the SQE on its own schedule. No call's return proves the copy has
//! happened, so the storage is owned until the completion.

use core::mem::{ManuallyDrop, size_of};

use super::buffer::StableBufferMut;
use super::identity::{RequestId, RingId};
use super::request::Receipt;
use crate::error::Errno;
use crate::op::Sqe;
use crate::types::{RawFd, SockAddrIn};

/// `-ECONNREFUSED`: nothing is listening on that address.
const ECONNREFUSED: i32 = -111;
/// `-EISCONN`: this socket is connected already.
const EISCONN: i32 = -106;
/// `-ETIMEDOUT`: the peer never answered.
const ETIMEDOUT: i32 = -110;
/// `-ENETUNREACH`: no route to that address.
const ENETUNREACH: i32 = -101;

/// Bytes of socket address the kernel is given.
const ADDR_LEN: usize = size_of::<SockAddrIn>();

/// The same length in the width the SQE carries it in.
///
/// Declared as `u32` so there is no narrowing cast to justify; the
/// assertion pins it to the real struct rather than to a literal that
/// could drift away from it.
const ADDR_LEN_U32: u32 = 16;
const _: () = assert!(ADDR_LEN_U32 as usize == ADDR_LEN);

/// How a `connect` ended.
///
/// There is deliberately no `InProgress`: `io_uring` resolves the handshake
/// before posting the CQE, so a non-blocking socket reports `0` rather
/// than `EINPROGRESS`. See the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectOutcome {
    /// The socket is connected to the requested address.
    Connected,
    /// Nothing is listening on that address.
    ///
    /// Worth retrying: a listener that starts later will answer.
    ConnectionRefused,
    /// This socket is connected already.
    ///
    /// Retrying never helps. A listening socket reports this too.
    AlreadyConnected,
    /// The peer never answered before the kernel gave up.
    TimedOut,
    /// There is no route to that address.
    NetworkUnreachable,
    /// The kernel rejected the request for another reason.
    Failed(Errno),
}

impl ConnectOutcome {
    /// Classify a raw CQE result.
    const fn from_raw(result: i32) -> Self {
        match result {
            ECONNREFUSED => Self::ConnectionRefused,
            EISCONN => Self::AlreadyConnected,
            ETIMEDOUT => Self::TimedOut,
            ENETUNREACH => Self::NetworkUnreachable,
            other if other < 0 => Self::Failed(Errno::new(-other)),
            _ => Self::Connected,
        }
    }

    /// Classify a raw result directly, for tests that need an outcome the
    /// kernel is hard to coax into producing on demand.
    #[cfg(test)]
    pub(crate) const fn from_raw_for_test(result: i32) -> Self {
        Self::from_raw(result)
    }

    /// Whether the socket is now connected to the requested address.
    #[must_use]
    pub const fn is_connected(self) -> bool {
        matches!(self, Self::Connected)
    }
}

impl core::fmt::Display for ConnectOutcome {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Connected => f.write_str("socket connected"),
            Self::ConnectionRefused => f.write_str("connection refused"),
            Self::AlreadyConnected => f.write_str("socket is already connected"),
            Self::TimedOut => f.write_str("connection timed out"),
            Self::NetworkUnreachable => f.write_str("network is unreachable"),
            Self::Failed(e) => write!(f, "connect failed: {e}"),
        }
    }
}

/// Why a `connect` request could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectError {
    /// The storage cannot hold a whole socket address.
    StoreTooSmall {
        /// Bytes a socket address needs.
        needed: usize,
        /// Bytes the supplied storage has.
        got: usize,
    },
}

impl core::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::StoreTooSmall { needed, got } => {
                write!(f, "connect address storage needs {needed} bytes, got {got}")
            }
        }
    }
}

/// A `connect` that owns its address storage, not yet queued.
pub struct PreparedConnect<S> {
    store: S,
    fd: RawFd,
    addr: SockAddrIn,
    /// Address of the published bytes, cached where the stability bound is
    /// in scope and checked for size before it was formed.
    staged: *mut u8,
}

// SAFETY: the pointer refers into storage this struct exclusively owns, so
// it stays valid wherever the value goes. The struct adds no thread
// affinity of its own, leaving `S` to decide.
unsafe impl<S: Send> Send for PreparedConnect<S> {}

impl<S: StableBufferMut> PreparedConnect<S> {
    /// Prepare a connect of `fd` to `addr`.
    ///
    /// Takes ownership of `store`, which the kernel reads the address from
    /// after submission, so no caller alias to it may survive. The
    /// descriptor is not taken: `connect` borrows it for the call.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectError`] with the storage handed back if `store` is
    /// too small for a socket address.
    pub fn new(fd: RawFd, addr: SockAddrIn, mut store: S) -> Result<Self, (S, ConnectError)> {
        let got = store.stable_len();
        if got < ADDR_LEN {
            return Err((
                store,
                ConnectError::StoreTooSmall {
                    needed: ADDR_LEN,
                    got,
                },
            ));
        }
        let staged = store.stable_mut_ptr();
        let mut prepared = Self {
            store,
            fd,
            addr,
            staged,
        };
        prepared.publish();
        Ok(prepared)
    }
}

impl<S> PreparedConnect<S> {
    /// Write the address into the storage the kernel will read.
    ///
    /// Done at construction so the bytes are in place before any SQE can
    /// name them. The address is staged as bytes rather than as a struct,
    /// which is why this needs no alignment check: the kernel copies it
    /// bytewise, and so does this.
    fn publish(&mut self) {
        let bytes = self.addr.to_bytes();
        // SAFETY: `staged` points into storage this request owns
        // exclusively and was checked to hold at least `ADDR_LEN` bytes,
        // so the copy stays in bounds and nothing else can observe it. No
        // SQE naming it exists yet, so the kernel is not reading
        // concurrently.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), self.staged, ADDR_LEN) }
    }

    /// The socket this request connects.
    #[must_use]
    pub const fn fd(&self) -> RawFd {
        self.fd
    }

    /// The address this request connects to.
    #[must_use]
    pub const fn addr(&self) -> SockAddrIn {
        self.addr
    }

    /// The address bytes exactly as the kernel will read them.
    ///
    /// Reads back the published storage rather than rebuilding it, so it
    /// shows what was actually written.
    #[must_use]
    pub const fn published(&self) -> [u8; ADDR_LEN] {
        let mut out = [0u8; ADDR_LEN];
        // SAFETY: `staged` points into storage this request owns and was
        // written by `publish` at construction, so `ADDR_LEN` initialised
        // bytes are readable there.
        unsafe { core::ptr::copy_nonoverlapping(self.staged, out.as_mut_ptr(), ADDR_LEN) }
        out
    }

    /// Give the storage back, abandoning the request.
    #[must_use]
    pub fn into_store(self) -> S {
        self.store
    }

    /// Build the SQE and move to the pending state.
    pub(crate) fn into_pending(self, ring: RingId, id: RequestId) -> (Sqe, PendingConnect<S>) {
        // SAFETY: `staged` was checked to hold a whole socket address,
        // written by `publish`, and points into storage this request owns
        // exclusively. The storage moves into `PendingConnect`, whose
        // destructor is suppressed unless a receipt proves the kernel
        // finished.
        let sqe = unsafe { Sqe::connect_ptr(self.fd, self.staged.cast_const(), ADDR_LEN_U32) };
        let pending = PendingConnect {
            store: ManuallyDrop::new(self.store),
            ring,
            id,
            fd: self.fd,
            addr: self.addr,
            staged: self.staged,
        };
        (sqe.user_data(id.raw()), pending)
    }
}

/// A submitted `connect` whose address storage the kernel may be reading.
///
/// # Drop and `forget` both leak rather than free
///
/// Dropping this runs no destructor for the storage. Under SQPOLL the
/// submitting thread never enters the kernel, so nothing here can prove
/// the address has been read, and the storage leaks on purpose — the same
/// failure mode as every other in-flight ticket.
///
/// No descriptor goes with it: `connect` borrows the socket rather than
/// taking it, so only the storage is at stake.
#[must_use = "dropping the ticket leaks the address storage"]
pub struct PendingConnect<S> {
    store: ManuallyDrop<S>,
    ring: RingId,
    id: RequestId,
    fd: RawFd,
    addr: SockAddrIn,
    staged: *mut u8,
}

// SAFETY: the pointer refers into storage this ticket exclusively owns and
// keeps alive at a fixed address, so moving the ticket to another thread
// keeps it valid; `S` decides whether that move is allowed.
unsafe impl<S: Send> Send for PendingConnect<S> {}

impl<S> PendingConnect<S> {
    /// Identity the kernel echoes back in this request's CQE.
    #[must_use]
    pub const fn id(&self) -> RequestId {
        self.id
    }

    /// Identity of the queue that accepted this request.
    #[must_use]
    pub const fn ring(&self) -> RingId {
        self.ring
    }

    /// The address this request connects to.
    #[must_use]
    pub const fn addr(&self) -> SockAddrIn {
        self.addr
    }

    /// Whether `receipt` authenticates this exact request.
    #[must_use]
    pub const fn matches(&self, receipt: &Receipt) -> bool {
        receipt.id().raw() == self.id.raw() && receipt.ring().raw() == self.ring.raw()
    }

    /// Take the storage back without a receipt, undoing a failed push.
    ///
    /// # Safety
    ///
    /// The kernel must never have seen this request's SQE. Calling this
    /// after publication hands back storage the kernel may still read.
    pub(crate) unsafe fn reclaim_unsubmitted(self) -> PreparedConnect<S> {
        let mut this = ManuallyDrop::new(self);
        // SAFETY: `this` is wrapped in `ManuallyDrop` so the no-op `Drop`
        // cannot observe the moved-out field. The caller guarantees no
        // kernel-visible pointer to the storage exists.
        let store = unsafe { ManuallyDrop::take(&mut this.store) };
        PreparedConnect {
            store,
            fd: this.fd,
            addr: this.addr,
            staged: this.staged,
        }
    }

    /// Trade a matching receipt for the outcome and the storage.
    ///
    /// # Errors
    ///
    /// Returns the ticket and receipt unchanged if the receipt belongs to
    /// another request or another ring.
    pub fn redeem(self, receipt: Receipt) -> Result<ConnectDone<S>, (Self, Receipt)> {
        if !self.matches(&receipt) {
            return Err((self, receipt));
        }
        let mut this = ManuallyDrop::new(self);
        // SAFETY: `this` is wrapped in `ManuallyDrop`, so `Drop` will not
        // run and cannot observe the moved-out field. The receipt proves
        // the kernel finished with these bytes.
        let store = unsafe { ManuallyDrop::take(&mut this.store) };
        Ok(ConnectDone {
            store,
            addr: this.addr,
            id: this.id,
            result: receipt.raw_result(),
        })
    }
}

impl<S> Drop for PendingConnect<S> {
    fn drop(&mut self) {
        // Intentionally no `ManuallyDrop::drop`. See the type docs: the
        // kernel may still be reading the address, so the storage leaks
        // rather than being freed underneath an in-flight request.
    }
}

/// A finished `connect`: how it ended, and the storage back.
pub struct ConnectDone<S> {
    store: S,
    addr: SockAddrIn,
    id: RequestId,
    result: i32,
}

impl<S> ConnectDone<S> {
    /// Identity of the request this completes.
    #[must_use]
    pub const fn id(&self) -> RequestId {
        self.id
    }

    /// Raw CQE result: `0` on success, `-errno` otherwise.
    #[must_use]
    pub const fn raw_result(&self) -> i32 {
        self.result
    }

    /// How the request ended.
    #[must_use]
    pub const fn outcome(&self) -> ConnectOutcome {
        ConnectOutcome::from_raw(self.result)
    }

    /// The address this request connected to.
    #[must_use]
    pub const fn addr(&self) -> SockAddrIn {
        self.addr
    }

    /// Take the storage back for reuse.
    #[must_use]
    pub fn into_store(self) -> S {
        self.store
    }

    /// Take the outcome and the storage together.
    #[must_use]
    pub fn into_parts(self) -> (ConnectOutcome, S) {
        (self.outcome(), self.store)
    }
}
