//! A socket created straight into the ring's file table.
//!
//! The direct sibling of [`Sqe::socket`](crate::Sqe::socket). The kernel
//! creates the socket and installs it into a slot of the ring's
//! registered-file table, so what comes back is a [`DirectSlot`] and no
//! descriptor ever enters this process.
//!
//! # This request owns no memory
//!
//! Unlike every other prepared request in this module there is no buffer,
//! no path and no destination struct: a socket is described entirely by
//! three integers. So there is no in-flight storage to protect, no
//! `ManuallyDrop`, and no reason for the ticket to leak on drop. What must
//! still be tracked is the *result*, because a slot nobody records stays
//! occupied until the ring dies.
//!
//! # An explicit slot destroys what it replaces
//!
//! [`SlotTarget::Auto`] takes a free slot, but an explicit
//! [`SlotTarget::Exact`] does not check whether the slot is in use — the
//! kernel removes and closes the file already there:
//!
//! > If a specified entry already contains a file, the file will first be
//! > removed from the table and closed. It's consistent with the behavior
//! > of updating an existing file with `io_uring_register_files_update(3)`.
//!
//! That was measured rather than taken on trust: seeding a slot with an
//! eventfd, installing a socket over it, and writing through the slot
//! again turns a working 8-byte write into `-EPIPE`. The replacement is
//! silent and the CQE result is `0`, the same as any other success, so
//! nothing in the completion reveals that a live file was destroyed.
//! Choosing the slot is therefore a claim the caller makes, and
//! [`Auto`](SlotTarget::Auto) is the safer default.
//!
//! # A full table is an ordinary failure here
//!
//! Exhaustion reports `-ENFILE`, as it does for a direct accept, but it
//! means less: this is a one-shot, so there is no armed request to retire
//! and nothing to re-submit. The distinction that matters is which errno
//! says the table is missing rather than full — `Auto` on a ring with no
//! registered table reports `-ENFILE` (no free entry, because there are no
//! entries), while an explicit slot on the same ring reports `-ENXIO`.

use super::identity::{RequestId, RingId};
use super::request::Receipt;
use super::slot::{DirectSlot, SlotIndex, SlotTarget};
use crate::op::Sqe;
use crate::types::{AddressFamily, SocketFlags, SocketType};

/// A direct socket creation that has not been queued yet.
///
/// `Copy`: it owns nothing, which is what lets a rejected push hand the
/// request back exactly as it was given.
#[derive(Debug, Clone, Copy)]
pub struct PreparedDirectSocket {
    domain: AddressFamily,
    sock_type: SocketType,
    protocol: i32,
    flags: SocketFlags,
    target: SlotTarget,
}

/// Why a direct socket could not be prepared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectSocketError {
    /// `SOCK_CLOEXEC` was requested for a slot that is not a descriptor.
    ///
    /// The same refusal a direct open gets, for the same reason: the flag
    /// describes what `execve` does to a *descriptor*, and a table slot is
    /// not one. The kernel answers `EINVAL`, so it is caught here rather
    /// than after a round trip.
    CloseOnExec,
}

impl core::fmt::Display for DirectSocketError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CloseOnExec => {
                write!(f, "SOCK_CLOEXEC is meaningless for a file-table slot")
            }
        }
    }
}

impl PreparedDirectSocket {
    /// Prepare a socket that installs into the ring's file table.
    ///
    /// `protocol` is the kernel protocol number; pass `0` for the default
    /// protocol of `sock_type`. Requires a registered file table — see
    /// [`IoUring::register_files`](crate::IoUring::register_files).
    ///
    /// # Errors
    ///
    /// Returns [`DirectSocketError::CloseOnExec`] if `flags` contains
    /// `CLOEXEC`, which the kernel refuses for a direct socket.
    pub const fn new(
        domain: AddressFamily,
        sock_type: SocketType,
        protocol: i32,
        flags: SocketFlags,
        target: SlotTarget,
    ) -> Result<Self, DirectSocketError> {
        if flags.contains(SocketFlags::CLOEXEC) {
            return Err(DirectSocketError::CloseOnExec);
        }
        Ok(Self {
            domain,
            sock_type,
            protocol,
            flags,
            target,
        })
    }

    /// Prepare a socket in a kernel-chosen slot.
    ///
    /// # Errors
    ///
    /// As [`new`](Self::new).
    pub const fn auto(
        domain: AddressFamily,
        sock_type: SocketType,
        protocol: i32,
        flags: SocketFlags,
    ) -> Result<Self, DirectSocketError> {
        Self::new(domain, sock_type, protocol, flags, SlotTarget::Auto)
    }

    /// The address family this socket will be created in.
    #[must_use]
    pub const fn domain(&self) -> AddressFamily {
        self.domain
    }

    /// The socket type this request was prepared with.
    #[must_use]
    pub const fn sock_type(&self) -> SocketType {
        self.sock_type
    }

    /// The protocol number this request was prepared with.
    #[must_use]
    pub const fn protocol(&self) -> i32 {
        self.protocol
    }

    /// The socket flags this request was prepared with.
    #[must_use]
    pub const fn flags(&self) -> SocketFlags {
        self.flags
    }

    /// Which slot this socket installs into.
    #[must_use]
    pub const fn target(&self) -> SlotTarget {
        self.target
    }

    /// Build the SQE and move to the pending state.
    pub(crate) fn into_pending(self, ring: RingId, id: RequestId) -> (Sqe, PendingDirectSocket) {
        let sqe = Sqe::socket_direct_at(
            self.domain,
            self.sock_type,
            self.protocol,
            self.flags,
            self.target.raw(),
        )
        .user_data(id.raw());
        (
            sqe,
            PendingDirectSocket {
                ring,
                id,
                target: self.target,
            },
        )
    }
}

/// A submitted direct socket creation.
///
/// Dropping this frees nothing and corrupts nothing — the request owns no
/// memory the kernel could be reading. What it loses is the *record* of a
/// slot: if the completion succeeds after the ticket is gone, the socket
/// sits in the table with nothing naming it until the ring is torn down.
#[derive(Debug)]
#[must_use = "dropping the ticket loses track of the slot the socket lands in"]
pub struct PendingDirectSocket {
    ring: RingId,
    id: RequestId,
    target: SlotTarget,
}

impl PendingDirectSocket {
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

    /// Which slot this socket installs into.
    #[must_use]
    pub const fn target(&self) -> SlotTarget {
        self.target
    }

    /// Whether `receipt` authenticates this exact request.
    #[must_use]
    pub const fn matches(&self, receipt: &Receipt) -> bool {
        receipt.id().raw() == self.id.raw() && receipt.ring().raw() == self.ring.raw()
    }

    /// Trade a matching receipt for the slot the socket was installed into.
    ///
    /// # Errors
    ///
    /// Returns the ticket and receipt unchanged if the receipt belongs to
    /// another request or another ring.
    pub fn redeem(self, receipt: Receipt) -> Result<DirectSocketCreated, (Self, Receipt)> {
        if !self.matches(&receipt) {
            return Err((self, receipt));
        }
        let result = receipt.raw_result();
        let slot = if result < 0 {
            None
        } else {
            self.target
                .resolve(result)
                .map(|index| DirectSlot::new(index, self.ring))
        };
        Ok(DirectSocketCreated {
            slot,
            id: self.id,
            result,
        })
    }
}

/// A finished direct socket creation: the slot it filled.
#[derive(Debug)]
pub struct DirectSocketCreated {
    slot: Option<DirectSlot>,
    id: RequestId,
    result: i32,
}

impl DirectSocketCreated {
    /// Identity of the request this completes.
    #[must_use]
    pub const fn id(&self) -> RequestId {
        self.id
    }

    /// Raw CQE result.
    ///
    /// A slot index for [`SlotTarget::Auto`], `0` for an explicit slot, and
    /// `-errno` on failure — which is why [`slot`](Self::slot) is the right
    /// way to learn where the socket landed.
    #[must_use]
    pub const fn raw_result(&self) -> i32 {
        self.result
    }

    /// Whether the socket was created.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.result >= 0
    }

    /// Why the creation failed, if it did.
    ///
    /// `ENFILE` means the ring's file table has no free slot — including
    /// the case where no table is registered at all, since a table that
    /// does not exist has no free entries. An explicit slot distinguishes
    /// the two: it reports `ENXIO` when there is no table and `EINVAL`
    /// when the slot lies outside one.
    ///
    /// # Errors
    ///
    /// Returns [`CompletionError::Failed`](crate::CompletionError::Failed)
    /// when the CQE carried a negative errno.
    pub const fn result(&self) -> Result<(), crate::Error> {
        if self.result < 0 {
            Err(crate::Error::Completion(crate::CompletionError::Failed(
                crate::Errno::new(-self.result),
            )))
        } else {
            Ok(())
        }
    }

    /// Where the socket was installed, if the request succeeded.
    #[must_use]
    pub const fn slot(&self) -> Option<&DirectSlot> {
        self.slot.as_ref()
    }

    /// The index the socket was installed at, if the request succeeded.
    #[must_use]
    pub fn index(&self) -> Option<SlotIndex> {
        self.slot.as_ref().map(DirectSlot::index)
    }

    /// Take the slot, giving up the rest of the completion.
    #[must_use]
    pub const fn into_slot(self) -> Option<DirectSlot> {
        self.slot
    }
}
