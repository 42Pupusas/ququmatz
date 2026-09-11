//! `IORING_OP_MSG_RING`: post a CQE (and optionally a descriptor) to
//! another ring, or this one.
//!
//! The kernel reads no caller memory for this operation — `len` and `data`
//! travel in SQE fields, not through a pointer — so every constructor here
//! is a safe `fn`, the same as [`Sqe::nop`](Sqe::nop) or
//! [`Sqe::close`](Sqe::close).

use super::{Sqe, ZEROED};
use crate::types::{MsgRingFlags, Opcode, RawFd};

/// `sqe->addr` sentinel selecting the descriptor-transfer form of the
/// request over the plain-data form.
const IORING_MSG_SEND_FD: u64 = 1;

impl Sqe {
    /// Prepare a message to another ring (or this one).
    ///
    /// Posts a CQE on `target_ring`'s completion queue with `res` set to
    /// `len` and `user_data` set to `data`. `target_ring` must itself be an
    /// `io_uring` file descriptor — any ring the caller has access to,
    /// including the ring this SQE is submitted on.
    ///
    /// The pairing (`len`, `data`) carries 32+64 bits of caller-chosen
    /// payload to the other side; what they mean is entirely up to the two
    /// ends. A common use is simply waking whoever is waiting on
    /// `target_ring` with no payload beyond that.
    #[must_use]
    pub fn msg_ring(target_ring: RawFd, len: u32, data: u64) -> Self {
        Self::msg_ring_with_flags(target_ring, len, data, MsgRingFlags::empty())
    }

    /// Prepare a message to another ring, with explicit [`MsgRingFlags`].
    #[must_use]
    pub fn msg_ring_with_flags(
        target_ring: RawFd,
        len: u32,
        data: u64,
        flags: MsgRingFlags,
    ) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::MsgRing.into();
        sqe.fd = target_ring.as_i32();
        sqe.len = len;
        sqe.off = data;
        sqe.op_flags = flags.bits();
        Self(sqe)
    }

    /// Prepare a message to another ring that also sets the target CQE's
    /// `flags` field.
    ///
    /// Sets [`MsgRingFlags::FLAGS_PASS`] automatically. The kernel may set
    /// additional bits of its own beyond `cqe_flags`.
    #[must_use]
    pub fn msg_ring_cqe_flags(target_ring: RawFd, len: u32, data: u64, cqe_flags: u32) -> Self {
        let mut sqe =
            Self::msg_ring_with_flags(target_ring, len, data, MsgRingFlags::FLAGS_PASS);
        // `file_index` aliases `splice_fd_in`; this form repurposes it to
        // carry the requested CQE flags rather than a fixed-file slot.
        #[allow(clippy::cast_possible_wrap)]
        {
            sqe.0.splice_fd_in = cqe_flags as i32;
        }
        sqe
    }

    /// Prepare sending a registered (fixed) descriptor to another ring.
    ///
    /// `source_fd` is an index into *this* ring's registered-file table.
    /// The kernel installs a fixed descriptor pointing at the same file
    /// into `target_ring`'s table at `target`, and posts a CQE there with
    /// `res = 0` and `user_data = data`.
    ///
    /// Returns [`None`](Option::None) from the target ring's completion
    /// resolving nothing further: unlike [`msg_ring`](Self::msg_ring), the
    /// slot installed is not reported back to *this* ring at all — the
    /// receiving side reads it via `target`, or, for an auto-allocated
    /// target, from its own CQE result.
    ///
    /// `target` is the encoded `file_index` value expected by the target
    /// ring's table, using the same off-by-one convention as
    /// [`Sqe::socket_direct_at`](Sqe::socket_direct_at):
    /// [`owned::SlotTarget::raw`](crate::owned::SlotTarget) produces it, or
    /// pass `-1` (`IORING_FILE_INDEX_ALLOC`) directly to let the target
    /// ring choose.
    #[must_use]
    pub fn msg_ring_fd(target_ring: RawFd, source_fd: RawFd, target: i32, data: u64) -> Self {
        Self::msg_ring_fd_with_flags(target_ring, source_fd, target, data, MsgRingFlags::empty())
    }

    /// Prepare sending a registered descriptor to another ring, with
    /// explicit [`MsgRingFlags`].
    #[must_use]
    pub fn msg_ring_fd_with_flags(
        target_ring: RawFd,
        source_fd: RawFd,
        target: i32,
        data: u64,
        flags: MsgRingFlags,
    ) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::MsgRing.into();
        sqe.fd = target_ring.as_i32();
        sqe.addr = IORING_MSG_SEND_FD;
        sqe.off = data;
        #[allow(clippy::cast_sign_loss)]
        {
            sqe.addr3 = source_fd.as_i32() as u64;
        }
        sqe.splice_fd_in = target;
        sqe.op_flags = flags.bits();
        Self(sqe)
    }
}
