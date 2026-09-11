//! epoll control op and event types.

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

/// Kernel `struct epoll_event`.
///
/// The kernel packs this on `x86_64` only. `include/uapi/linux/eventpoll.h`
/// defines `EPOLL_PACKED` as `__attribute__((packed))` under `#ifdef
/// __x86_64__` and as nothing otherwise, so that the 64-bit struct keeps
/// the same alignment as the 32-bit one and 32-bit emulation stays easy.
/// Everywhere else `data` sits at its natural 8-byte alignment, leaving a
/// four-byte gap after `events`. Packing unconditionally would put `data`
/// at offset 4 on aarch64, riscv64 and arm, where the kernel reads it
/// from offset 8.
#[derive(Debug, Clone, Copy, Default)]
#[cfg_attr(target_arch = "x86_64", repr(C, packed))]
#[cfg_attr(not(target_arch = "x86_64"), repr(C))]
pub struct EpollEvent {
    pub events: u32,
    /// User data associated with this event (fd, pointer, etc.).
    pub data: u64,
}

const _: () = assert!(
    core::mem::offset_of!(EpollEvent, data) == if cfg!(target_arch = "x86_64") { 4 } else { 8 },
    "epoll_event.data is packed to offset 4 only on x86_64; every other architecture leaves it at its natural 8-byte alignment"
);

