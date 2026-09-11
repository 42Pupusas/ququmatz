//! `IORING_OP_WAITID`: async `waitid(2)`.

use super::{Sqe, ZEROED};
use crate::types::{IdType, Opcode, WaitOptions, WaitidSiginfo};

impl Sqe {
    /// Prepare an async `waitid`.
    ///
    /// `id_type`/`id` select which child(ren) to wait for, exactly as the
    /// `waitid(2)` arguments of the same name; `options` chooses which
    /// state changes to report and must include at least one of
    /// [`WaitOptions::EXITED`], [`WaitOptions::UNTRACED`], or
    /// [`WaitOptions::CONTINUED`], or the kernel rejects the request with
    /// `EINVAL`. On success the kernel fills `infop` with the reported
    /// child's info; `infop` may be null to discard it.
    ///
    /// Available since Linux 6.7.
    ///
    /// # Safety
    ///
    /// `infop`, if non-null, is borrowed only for this call — the returned
    /// `Sqe` stores the raw pointer, not the borrow itself. The caller
    /// must ensure the memory it points to remains valid, writable, and
    /// exclusively accessible until the kernel posts the completion for
    /// this operation.
    #[must_use]
    pub unsafe fn waitid(
        id_type: IdType,
        id: i32,
        infop: *mut WaitidSiginfo,
        options: WaitOptions,
    ) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::WaitId.into();
        sqe.fd = id;
        sqe.len = id_type.as_raw();
        // `file_index` aliases `splice_fd_in`; the kernel reads it as the
        // `waitid` options here rather than a fixed-file slot.
        #[allow(clippy::cast_possible_wrap)]
        {
            sqe.splice_fd_in = options.bits() as i32;
        }
        sqe.off = infop as u64;
        Self(sqe)
    }
}
