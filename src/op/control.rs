//! Control-plane SQEs: nop, cancel, poll, timeout.

use super::{Sqe, ZEROED};
use crate::types::{CancelFlags, Opcode, PollMask, RawFd, TimeoutFlags, Timespec};

impl Sqe {
    /// Prepare a no-op operation.
    #[must_use]
    pub fn nop() -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Nop.into();
        Self(sqe)
    }

    /// Prepare a timeout removal.
    ///
    /// Cancels a previously submitted timeout identified by its `user_data`.
    #[must_use]
    pub fn timeout_remove(target_user_data: u64) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::TimeoutRemove.into();
        sqe.addr = target_user_data;
        Self(sqe)
    }

    /// Prepare an async cancellation, matching by `user_data`.
    ///
    /// Cancels a previously submitted operation identified by its
    /// `user_data`. Use [`Sqe::cancel_with_flags`] to also set
    /// [`CancelFlags::ALL`](crate::types::CancelFlags::ALL) and cancel
    /// every request sharing this `user_data` rather than just the first
    /// match.
    #[must_use]
    pub fn cancel(target_user_data: u64) -> Self {
        Self::cancel_with_flags(target_user_data, CancelFlags::empty())
    }

    /// Prepare an async cancellation matching by `user_data`, with explicit
    /// [`CancelFlags`](crate::types::CancelFlags).
    ///
    /// `flags` should not set `FD` or `ANY` — those change what
    /// `target_user_data` means and are set automatically by
    /// [`Sqe::cancel_fd`] and [`Sqe::cancel_any`] respectively.
    #[must_use]
    pub fn cancel_with_flags(target_user_data: u64, flags: CancelFlags) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::AsyncCancel.into();
        sqe.addr = target_user_data;
        sqe.op_flags = flags.bits();
        Self(sqe)
    }

    /// Prepare an async cancellation matching every in-flight request on
    /// `fd`, rather than one `user_data`.
    ///
    /// Sets [`CancelFlags::FD`](crate::types::CancelFlags::FD)
    /// automatically. Combine `extra` with
    /// [`CancelFlags::ALL`](crate::types::CancelFlags::ALL) to cancel every
    /// matching request instead of just the first, or with
    /// [`CancelFlags::FD_FIXED`](crate::types::CancelFlags::FD_FIXED) if
    /// `fd` names a registered/fixed file index.
    ///
    /// Closing `fd` does **not** cancel requests still using it — the
    /// kernel holds its own reference per request — so this is the
    /// intended way to stop pending work before a close.
    #[must_use]
    pub fn cancel_fd(fd: RawFd, extra: CancelFlags) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::AsyncCancel.into();
        sqe.fd = fd.as_i32();
        sqe.op_flags = (CancelFlags::FD | extra).bits();
        Self(sqe)
    }

    /// Prepare an async cancellation that matches any single in-flight
    /// request, ignoring `user_data` entirely.
    ///
    /// Sets [`CancelFlags::ANY`](crate::types::CancelFlags::ANY)
    /// automatically. Combine `extra` with
    /// [`CancelFlags::ALL`](crate::types::CancelFlags::ALL) to drain every
    /// request on the ring — the usual way to cancel everything before
    /// shutdown.
    #[must_use]
    pub fn cancel_any(extra: CancelFlags) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::AsyncCancel.into();
        sqe.op_flags = (CancelFlags::ANY | extra).bits();
        Self(sqe)
    }

    /// Narrow an existing cancel request to only match the given original
    /// opcode.
    ///
    /// Sets [`CancelFlags::OP`](crate::types::CancelFlags::OP) and stores
    /// `opcode` in the SQE's `len` field, which is where the kernel reads
    /// it back from for this flag (available since Linux 6.6). Chain onto
    /// [`Sqe::cancel`], [`Sqe::cancel_fd`], or [`Sqe::cancel_any`].
    #[must_use]
    pub const fn cancel_matching_opcode(mut self, opcode: Opcode) -> Self {
        self.0.op_flags |= CancelFlags::OP.bits();
        self.0.len = opcode as u32;
        self
    }

    /// Prepare a poll add operation.
    ///
    /// Waits for events matching `mask` on the given fd.
    #[must_use]
    pub fn poll_add(fd: RawFd, mask: PollMask) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::PollAdd.into();
        sqe.fd = fd.as_i32();
        sqe.op_flags = mask.bits();
        Self(sqe)
    }

    /// Prepare a poll remove operation.
    ///
    /// Removes a previously added poll request identified by `user_data`.
    #[must_use]
    pub fn poll_remove(target_user_data: u64) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::PollRemove.into();
        sqe.addr = target_user_data;
        Self(sqe)
    }

    /// Prepare a timeout operation.
    ///
    /// Completes when either `count` completions have occurred or the timeout
    /// expires, whichever comes first. Use `count = 0` for a pure timer.
    ///
    /// # Safety
    ///
    /// `ts` is borrowed only for this call — the returned `Sqe` stores a
    /// raw pointer derived from it, not the borrow itself. The caller must
    /// ensure the memory `ts` points to remains valid until the kernel
    /// posts the completion for this operation.
    #[must_use]
    pub unsafe fn timeout(ts: &Timespec, count: u32, flags: TimeoutFlags) -> Self {
        unsafe { Self::timeout_ptr(core::ptr::from_ref(ts), count, flags) }
    }

    /// Prepare a linked timeout.
    ///
    /// Must be submitted immediately after a linked SQE. If the timeout fires
    /// before the linked operation completes, the linked operation is cancelled.
    ///
    /// # Safety
    ///
    /// `ts` is borrowed only for this call — the returned `Sqe` stores a
    /// raw pointer derived from it, not the borrow itself. The caller must
    /// ensure the memory `ts` points to remains valid until the kernel
    /// posts the completion for this operation.
    #[must_use]
    pub unsafe fn link_timeout(ts: &Timespec, flags: TimeoutFlags) -> Self {
        unsafe { Self::link_timeout_ptr(core::ptr::from_ref(ts), flags) }
    }

    /// Prepare a timeout operation from a raw pointer.
    ///
    /// # Safety
    ///
    /// `ts` must point to a valid `Timespec` that remains valid until the
    /// operation completes.
    #[must_use]
    pub unsafe fn timeout_ptr(ts: *const Timespec, count: u32, flags: TimeoutFlags) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Timeout.into();
        sqe.addr = ts as u64;
        sqe.len = 1;
        sqe.off = u64::from(count);
        sqe.op_flags = flags.bits();
        Self(sqe)
    }

    /// Prepare a linked timeout from a raw pointer.
    ///
    /// # Safety
    ///
    /// `ts` must point to a valid `Timespec` that remains valid until the
    /// operation completes.
    #[must_use]
    pub unsafe fn link_timeout_ptr(ts: *const Timespec, flags: TimeoutFlags) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::LinkTimeout.into();
        sqe.addr = ts as u64;
        sqe.len = 1;
        sqe.op_flags = flags.bits();
        Self(sqe)
    }
}
