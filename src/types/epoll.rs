//! epoll control op and event types.

use super::bitflags;

/// epoll control operations for `IORING_OP_EPOLL_CTL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum EpollOp {
    Add = 1,
    Del = 2,
    Mod = 3,
}

impl From<EpollOp> for u32 {
    fn from(op: EpollOp) -> Self {
        op as Self
    }
}

bitflags! {
    /// Event mask for epoll (matches `EPOLLIN`, `EPOLLOUT`, etc.).
    pub struct EpollEvents(u32);
    const IN = 0x0001;
    const OUT = 0x0004;
    const ERR = 0x0008;
    const HUP = 0x0010;
    const RDHUP = 0x2000;
    const ET = 1 << 31;
    const ONESHOT = 1 << 30;
}

/// Kernel `epoll_event` struct (packed: 4-byte events + 8-byte data).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C, packed)]
pub struct EpollEvent {
    pub events: u32,
    /// User data associated with this event (fd, pointer, etc.).
    pub data: u64,
}
