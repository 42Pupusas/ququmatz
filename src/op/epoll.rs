//! Epoll-control SQE.

use super::{Sqe, ZEROED};
use crate::types::{EpollEvent, EpollOp, Opcode};

impl Sqe {
    /// Prepare an `epoll_ctl` operation.
    ///
    /// `epfd` is the epoll fd, `op` is Add/Del/Mod, `fd` is the target fd,
    /// and `event` is the event to register (ignored for `Del`).
    #[must_use]
    pub fn epoll_ctl(epfd: i32, op: EpollOp, fd: i32, event: &EpollEvent) -> Self {
        unsafe { Self::epoll_ctl_ptr(epfd, op, fd, core::ptr::from_ref(event)) }
    }

    /// Prepare an `epoll_ctl` operation from a raw pointer.
    ///
    /// # Safety
    ///
    /// `event` must point to a valid `EpollEvent` that remains valid until
    /// the operation completes.
    #[must_use]
    pub unsafe fn epoll_ctl_ptr(epfd: i32, op: EpollOp, fd: i32, event: *const EpollEvent) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::EpollCtl.into();
        sqe.fd = epfd;
        sqe.off = fd as u64;
        sqe.addr = event as u64;
        sqe.len = op.into();
        Self(sqe)
    }
}
