//! `bind`, whose address the kernel copies while servicing the request.
//!
//! The kernel is handed a socket address at `addr` and its length in
//! `addr2`. It rejects a non-zero `len`, `buf_index`, `rw_flags`, or
//! `splice_fd_in` outright, so the SQE carries the address and nothing
//! else.
//!
//! # There is no owned `listen`
//!
//! `listen` reads no caller memory at all — the kernel takes the backlog
//! from `len` and rejects a request that carries an address. It owns
//! nothing, so it has nothing to model and stays a safe
//! [`Sqe::listen`](crate::Sqe::listen).
//!
//! # Storage is owned for the same reason a timeout's is
//!
//! Measured on a live ring, `io_bind_prep` copies the address into the
//! kernel during `io_uring_enter`: an address overwritten with `0xFF`
//! *after* `submit` returned still binds the port originally staged.
//! Overwriting it between `push` and `submit` instead fails with
//! `EAFNOSUPPORT`, which locates the read precisely — inside the submit
//! call, not at push.
//!
//! That is *almost* an argument for a plain borrow, and it fails for the
//! same reason the timeout's does:
//! [`split_owned`](crate::IoUring::split_owned) accepts an SQPOLL ring,
//! where the submitting thread never enters the kernel and the SQ thread
//! reads the SQE on its own schedule. No call's return proves the copy has
//! happened, so the storage is owned until the completion.
//!
//! # A typed address makes one failure unrepresentable
//!
//! The request takes a [`SockAddrIn`] rather than raw bytes. A malformed
//! address is then impossible to construct, which matters because the
//! kernel reports it with the same `EINVAL` it uses for a socket that is
//! already bound. Measured against a real kernel:
//!
//! | request | result |
//! |---|---|
//! | bind a fresh socket | `0` |
//! | bind the same socket again | `-EINVAL` |
//! | bind a port another socket holds | `-EADDRINUSE` |
//! | bind a privileged port unprivileged | `-EACCES` |
//! | a zero-length or null address | `-EINVAL` / `-EFAULT` |
//!
//! The last row is what the typed address rules out. The two middle rows
//! are different errnos for what a caller might lump together as "the
//! bind did not take", and [`BindOutcome`] keeps them apart: a retry on a
//! different port fixes one and loops forever on the other.

use core::mem::{ManuallyDrop, size_of};

use super::buffer::StableBufferMut;
use super::identity::{RequestId, RingId};
use super::request::Receipt;
use crate::error::Errno;
use crate::op::Sqe;
use crate::types::{RawFd, SockAddrIn};

/// `-EADDRINUSE`: another socket holds this address.
const EADDRINUSE: i32 = -98;
/// `-EINVAL`: this socket is already bound.
const EINVAL: i32 = -22;
/// `-EACCES`: binding this address needs privilege.
const EACCES: i32 = -13;

/// Bytes of socket address the kernel is given.
const ADDR_LEN: usize = size_of::<SockAddrIn>();

/// The same length in the width the SQE carries it in.
///
/// Built from the `u32` side so there is no narrowing cast to justify;
/// the assertion pins it to the real struct rather than to a literal
/// that could drift away from it.
const ADDR_LEN_U32: u32 = 16;
const _: () = assert!(ADDR_LEN_U32 as usize == ADDR_LEN);

/// How a `bind` ended.
///
/// The three named failures are routine and call for different responses,
/// so they are distinguished rather than folded into one error a caller
/// has to decode. Retrying a different port resolves
/// [`AddressInUse`](Self::AddressInUse) and never resolves
/// [`AlreadyBound`](Self::AlreadyBound).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindOutcome {
    /// The socket is bound to the requested address.
    Bound,
    /// Another socket already holds this address.
    AddressInUse,
    /// This socket has been bound once already.
    ///
    /// The kernel spends `EINVAL` on both this and a malformed address;
    /// [`PreparedBind`] takes a typed [`SockAddrIn`], so the second cannot
    /// be constructed and this reading is the only one left.
    AlreadyBound,
    /// Binding this address requires privilege the process does not have.
    PermissionDenied,
    /// The kernel rejected the request for another reason.
    Failed(Errno),
}

impl BindOutcome {
    /// Classify a raw CQE result.
    const fn from_raw(result: i32) -> Self {
        match result {
            EADDRINUSE => Self::AddressInUse,
            EINVAL => Self::AlreadyBound,
            EACCES => Self::PermissionDenied,
            other if other < 0 => Self::Failed(Errno::new(-other)),
            _ => Self::Bound,
        }
    }

    /// Classify a raw result directly, for tests that need an outcome the
    /// kernel is hard to coax into producing on demand.
    #[cfg(test)]
    pub(crate) const fn from_raw_for_test(result: i32) -> Self {
        Self::from_raw(result)
    }

    /// Whether the socket is now bound to the requested address.
    #[must_use]
    pub const fn is_bound(self) -> bool {
        matches!(self, Self::Bound)
    }
}

impl core::fmt::Display for BindOutcome {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Bound => f.write_str("socket bound"),
            Self::AddressInUse => f.write_str("address is already in use"),
            Self::AlreadyBound => f.write_str("socket is already bound"),
            Self::PermissionDenied => f.write_str("binding this address requires privilege"),
            Self::Failed(e) => write!(f, "bind failed: {e}"),
        }
    }
}

/// Why a `bind` request could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindError {
    /// The storage cannot hold a whole socket address.
    StoreTooSmall {
        /// Bytes a socket address needs.
        needed: usize,
        /// Bytes the supplied storage has.
        got: usize,
    },
}

impl core::fmt::Display for BindError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::StoreTooSmall { needed, got } => {
                write!(f, "bind address storage needs {needed} bytes, got {got}")
            }
        }
    }
}

/// A `bind` that owns its address storage, not yet queued.
pub struct PreparedBind<S> {
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
unsafe impl<S: Send> Send for PreparedBind<S> {}

impl<S: StableBufferMut> PreparedBind<S> {
    /// Prepare a bind of `fd` to `addr`.
    ///
    /// Takes ownership of `store`, which the kernel reads the address from
    /// after submission, so no caller alias to it may survive. The
    /// descriptor is not taken: `bind` borrows it for the call.
    ///
    /// # Errors
    ///
    /// Returns [`BindError`] with the storage handed back if `store` is
    /// too small for a socket address.
    pub fn new(fd: RawFd, addr: SockAddrIn, mut store: S) -> Result<Self, (S, BindError)> {
        let got = store.stable_len();
        if got < ADDR_LEN {
            return Err((
                store,
                BindError::StoreTooSmall {
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

impl<S> PreparedBind<S> {
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

    /// The socket this request binds.
    #[must_use]
    pub const fn fd(&self) -> RawFd {
        self.fd
    }

    /// The address this request binds to.
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
    pub(crate) fn into_pending(self, ring: RingId, id: RequestId) -> (Sqe, PendingBind<S>) {
        // SAFETY: `staged` was checked to hold a whole socket address,
        // written by `publish`, and points into storage this request owns
        // exclusively. The storage moves into `PendingBind`, whose
        // destructor is suppressed unless a receipt proves the kernel
        // finished.
        let sqe = unsafe { Sqe::bind_ptr(self.fd, self.staged.cast_const(), ADDR_LEN_U32) };
        let pending = PendingBind {
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

/// A submitted `bind` whose address storage the kernel may be reading.
///
/// # Drop and `forget` both leak rather than free
///
/// Dropping this runs no destructor for the storage. Under SQPOLL the
/// submitting thread never enters the kernel, so nothing here can prove
/// the address has been read, and the storage leaks on purpose — the same
/// failure mode as every other in-flight ticket.
///
/// No descriptor goes with it: `bind` borrows the socket rather than
/// taking it, so only the storage is at stake.
#[must_use = "dropping the ticket leaks the address storage"]
pub struct PendingBind<S> {
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
unsafe impl<S: Send> Send for PendingBind<S> {}

impl<S> PendingBind<S> {
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

    /// The address this request binds to.
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
    pub(crate) unsafe fn reclaim_unsubmitted(self) -> PreparedBind<S> {
        let mut this = ManuallyDrop::new(self);
        // SAFETY: `this` is wrapped in `ManuallyDrop` so the no-op `Drop`
        // cannot observe the moved-out field. The caller guarantees no
        // kernel-visible pointer to the storage exists.
        let store = unsafe { ManuallyDrop::take(&mut this.store) };
        PreparedBind {
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
    pub fn redeem(self, receipt: Receipt) -> Result<BindDone<S>, (Self, Receipt)> {
        if !self.matches(&receipt) {
            return Err((self, receipt));
        }
        let mut this = ManuallyDrop::new(self);
        // SAFETY: `this` is wrapped in `ManuallyDrop`, so `Drop` will not
        // run and cannot observe the moved-out field. The receipt proves
        // the kernel finished with these bytes.
        let store = unsafe { ManuallyDrop::take(&mut this.store) };
        Ok(BindDone {
            store,
            addr: this.addr,
            id: this.id,
            result: receipt.raw_result(),
        })
    }
}

impl<S> Drop for PendingBind<S> {
    fn drop(&mut self) {
        // Intentionally no `ManuallyDrop::drop`. See the type docs: the
        // kernel may still be reading the address, so the storage leaks
        // rather than being freed underneath an in-flight request.
    }
}

/// A finished `bind`: how it ended, and the storage back.
pub struct BindDone<S> {
    store: S,
    addr: SockAddrIn,
    id: RequestId,
    result: i32,
}

impl<S> BindDone<S> {
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
    pub const fn outcome(&self) -> BindOutcome {
        BindOutcome::from_raw(self.result)
    }

    /// The address this request bound to.
    ///
    /// A port of `0` asks the kernel to choose one, and the choice is not
    /// reported here — read it back with `getsockname` once bound.
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
    pub fn into_parts(self) -> (BindOutcome, S) {
        (self.outcome(), self.store)
    }
}
