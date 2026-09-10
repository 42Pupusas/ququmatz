//! Control-plane SQEs: nop, cancel, poll, timeout.

use super::{Sqe, ZEROED};
use crate::types::{Opcode, PollMask, RawFd, TimeoutFlags, Timespec};

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

    /// Prepare an async cancellation.
    ///
    /// Cancels a previously submitted operation identified by its `user_data`.
    #[must_use]
    pub fn cancel(target_user_data: u64) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::AsyncCancel.into();
        sqe.addr = target_user_data;
        Self(sqe)
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
