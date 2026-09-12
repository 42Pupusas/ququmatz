//! `IORING_OP_FIXED_FD_INSTALL`, the reverse of a direct open or direct
//! socket: it promotes a slot already in the ring's file table to a real
//! process file descriptor, rather than installing a new file *into* the
//! table.
//!
//! # This request owns no memory
//!
//! Like [`PendingCancel`](super::PendingCancel) and
//! [`PendingMsgRing`](super::PendingMsgRing), the whole request is
//! described by two integers — the slot and a flags word — so there is no
//! buffer for a ticket to hold across submission and nothing a dropped
//! ticket leaks.
//!
//! # What it produces is not nothing, though
//!
//! Unlike a cancel or a `msg_ring`, a successful completion here hands back
//! a real descriptor this process now owns. [`FixedFdInstalled::into_file`]
//! wraps it in [`File`], so ignoring the completion closes it rather than
//! leaking it — the same shape [`Opened`](super::Opened) already gives an
//! `openat` completion, but with nothing beside the descriptor to hand back
//! since this request had no storage of its own.
//!
//! # The slot is untouched
//!
//! Promoting a slot to a descriptor does not remove it from the table or
//! close anything there — the file gains a second owner (the returned
//! descriptor) alongside the one the table already held. Closing the
//! returned descriptor later, or letting it drop, does not un-register the
//! slot.

use super::identity::{RequestId, RingId};
use super::request::Receipt;
use super::slot::DirectSlot;
use crate::fs::File;
use crate::op::Sqe;
use crate::types::{InstallFdFlags, RawFd};

/// A fixed-fd install that has not been queued yet.
///
/// `Copy`, because it owns no resource — a rejected push simply hands back
/// an identical copy.
#[derive(Debug, Clone, Copy)]
pub struct PreparedFixedFdInstall {
    slot: RawFd,
    flags: InstallFdFlags,
}

impl PreparedFixedFdInstall {
    /// Prepare an install of `slot` into a real process descriptor.
    ///
    /// `slot` is a plain table index — the same number
    /// [`DirectSlot::index`] reports — not the kernel's off-by-one wire
    /// encoding, which this request has no use for since it names a file
    /// already in the table rather than allocating a new slot.
    #[must_use]
    pub const fn new(slot: RawFd, flags: InstallFdFlags) -> Self {
        Self { slot, flags }
    }

    /// Prepare an install of an already-occupied [`DirectSlot`].
    #[must_use]
    pub const fn of(slot: &DirectSlot, flags: InstallFdFlags) -> Self {
        Self::new(RawFd::from_raw(slot.index().get() as usize), flags)
    }

    /// The slot this request installs.
    #[must_use]
    pub const fn slot(&self) -> RawFd {
        self.slot
    }

    /// The flags this request was prepared with.
    #[must_use]
    pub const fn flags(&self) -> InstallFdFlags {
        self.flags
    }

    /// Build the SQE and move to the pending state.
    pub(crate) fn into_pending(self, ring: RingId, id: RequestId) -> (Sqe, PendingFixedFdInstall) {
        let sqe = Sqe::fixed_fd_install(self.slot, self.flags);
        let pending = PendingFixedFdInstall {
            ring,
            id,
            slot: self.slot,
        };
        (sqe.user_data(id.raw()), pending)
    }
}

/// A submitted fixed-fd install.
///
/// Owns nothing, so dropping it leaks nothing on this side — but if the
/// kernel does finish the request after the ticket is gone, the descriptor
/// it produced has no owner and leaks for the life of the process, same as
/// any other abandoned completion that yields a `File`.
#[derive(Debug)]
pub struct PendingFixedFdInstall {
    ring: RingId,
    id: RequestId,
    slot: RawFd,
}

impl PendingFixedFdInstall {
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

    /// The slot this request installs.
    #[must_use]
    pub const fn slot(&self) -> RawFd {
        self.slot
    }

    /// Whether `receipt` authenticates this exact request.
    #[must_use]
    pub const fn matches(&self, receipt: &Receipt) -> bool {
        receipt.belongs_to(self.ring, self.id)
    }

    /// Trade a matching receipt for the descriptor it installed.
    ///
    /// # Errors
    ///
    /// Returns the ticket and receipt unchanged if the receipt belongs to
    /// another request or another ring.
    pub fn redeem(self, receipt: Receipt) -> Result<FixedFdInstalled, (Self, Receipt)> {
        if !self.matches(&receipt) {
            return Err((self, receipt));
        }
        let result = receipt.raw_result();
        let file = Self::claim(result);
        Ok(FixedFdInstalled {
            slot: self.slot,
            file,
            id: self.id,
            result,
        })
    }

    /// Adopt the descriptor this completion installed, if it installed one.
    fn claim(result: i32) -> Option<File> {
        let fd = u32::try_from(result).ok()?;
        // SAFETY: a non-negative result is a descriptor the kernel just
        // installed into this process's file table. The CQE is reaped
        // once, so nothing else holds it and taking ownership here is the
        // only claim.
        Some(unsafe { File::from_fd(RawFd::from_raw(fd as usize)) })
    }
}

/// A finished fixed-fd install: the descriptor it produced, if any.
#[derive(Debug)]
pub struct FixedFdInstalled {
    slot: RawFd,
    file: Option<File>,
    id: RequestId,
    result: i32,
}

impl FixedFdInstalled {
    /// Identity of the request this completes.
    #[must_use]
    pub const fn id(&self) -> RequestId {
        self.id
    }

    /// The slot this request installed.
    #[must_use]
    pub const fn slot(&self) -> RawFd {
        self.slot
    }

    /// Raw CQE result: a descriptor when non-negative, `-errno` otherwise.
    #[must_use]
    pub const fn raw_result(&self) -> i32 {
        self.result
    }

    /// Whether the install succeeded.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        crate::Error::cqe_is_ok(self.result)
    }

    /// Why the install failed, if it did.
    ///
    /// # Errors
    ///
    /// Returns [`CompletionError::Failed`](crate::CompletionError::Failed)
    /// when the CQE carried a negative errno.
    pub const fn result(&self) -> Result<(), crate::Error> {
        match crate::Error::from_failed_cqe(self.result) {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Borrow the installed descriptor, if the request succeeded.
    #[must_use]
    pub const fn file(&self) -> Option<&File> {
        self.file.as_ref()
    }

    /// Take the installed descriptor.
    #[must_use]
    pub fn into_file(self) -> Option<File> {
        self.file
    }
}
