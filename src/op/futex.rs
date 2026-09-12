//! `IORING_OP_FUTEX_WAIT` / `FUTEX_WAKE` / `FUTEX_WAITV`.
//!
//! All three share `io_futex_prep`'s field layout for the single-futex
//! forms, confirmed against `io_uring/futex.c`: `addr` is the futex word's
//! address, `addr2` is the expected value (wait) or the wake count (wake),
//! `addr3` is a bitset mask, and `fd` carries the futex2 flags (word size,
//! private/shared, NUMA) rather than a descriptor — a different field
//! layout from every other op in the crate. `len`, `buf_index`,
//! `file_index`, and the `futex_flags` slot in the `op_flags` union must
//! all be zero or the kernel answers `EINVAL`. `FUTEX_WAITV` is shaped
//! differently again: `addr` points to an array of [`FutexWaitv`] and
//! `len` is its count, with every other field forced to zero.

use super::{Sqe, ZEROED};
use crate::types::{Futex2Flags, FutexWaitv, Opcode};

impl Sqe {
    /// Prepare an async `futex_wait`: block until the `u32` at `uaddr` no
    /// longer equals `val`, or `mask` selects a matching wake.
    ///
    /// `mask` must be non-zero — the kernel rejects a zero bitset with
    /// `EINVAL`, since it could never match any wake. Use
    /// `u32::MAX` to match any wake, mirroring `FUTEX_BITSET_MATCH_ANY`.
    ///
    /// Available since Linux 6.7.
    ///
    /// # Safety
    ///
    /// `uaddr` is borrowed only for this call — the returned `Sqe` stores
    /// the raw pointer, not the borrow itself. The caller must ensure the
    /// memory it points to remains valid and readable, and that its
    /// address is stable, until the kernel posts the completion for this
    /// operation.
    #[must_use]
    pub unsafe fn futex_wait(uaddr: *const u32, val: u64, mask: u64, flags: Futex2Flags) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::FutexWait.into();
        sqe.addr = uaddr as u64;
        sqe.off = val;
        sqe.addr3 = mask;
        #[allow(clippy::cast_possible_wrap)]
        {
            sqe.fd = flags.bits() as i32;
        }
        Self(sqe)
    }

    /// Prepare a `futex_wake`: wake waiters on the `u32` at `uaddr` whose
    /// bitset matches `mask`, up to `count` of them.
    ///
    /// `mask` must be non-zero for the same reason as
    /// [`futex_wait`](Self::futex_wait). Use `u32::MAX` to wake any
    /// waiter regardless of the bitset it waited with.
    ///
    /// Available since Linux 6.7.
    ///
    /// # Safety
    ///
    /// `uaddr` is borrowed only for this call — the returned `Sqe` stores
    /// the raw pointer, not the borrow itself. The caller must ensure the
    /// memory it points to remains valid and readable until the kernel
    /// posts the completion for this operation.
    #[must_use]
    pub unsafe fn futex_wake(uaddr: *const u32, count: u64, mask: u64, flags: Futex2Flags) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::FutexWake.into();
        sqe.addr = uaddr as u64;
        sqe.off = count;
        sqe.addr3 = mask;
        #[allow(clippy::cast_possible_wrap)]
        {
            sqe.fd = flags.bits() as i32;
        }
        Self(sqe)
    }

    /// Prepare a `futex_waitv`: block until any one of `waiters` changes,
    /// reporting which index woke it.
    ///
    /// Unlike `futex_wait`, each waiter carries its own flags and there is
    /// no shared mask — every entry in `waiters` selects its own futex,
    /// value, and word size independently.
    ///
    /// Available since Linux 6.7.
    ///
    /// # Safety
    ///
    /// `waiters` and every futex word each entry names are borrowed only
    /// for this call — the returned `Sqe` stores a raw pointer derived
    /// from `waiters`, not the borrow itself. The caller must ensure
    /// `waiters` and every futex word it points to remain valid and
    /// readable, at a stable address, until the kernel posts the
    /// completion for this operation.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub unsafe fn futex_waitv(waiters: &[FutexWaitv]) -> Self {
        debug_assert!(waiters.len() <= u32::MAX as usize);
        unsafe { Self::futex_waitv_ptr(waiters.as_ptr(), waiters.len() as u32) }
    }

    /// Prepare a `futex_waitv` from a raw pointer.
    ///
    /// # Safety
    ///
    /// `waiters` must point to at least `count` valid [`FutexWaitv`]
    /// entries, and every futex word they name must remain valid and
    /// readable, at a stable address, until the operation completes.
    #[must_use]
    pub unsafe fn futex_waitv_ptr(waiters: *const FutexWaitv, count: u32) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::FutexWaitv.into();
        sqe.addr = waiters as u64;
        sqe.len = count;
        Self(sqe)
    }
}
