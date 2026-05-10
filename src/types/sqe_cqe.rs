//! Kernel SQE/CQE/params layout and CQE flag bits.

use super::bitflags;
use super::buffers::{IoCqringOffsets, IoSqringOffsets};

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct IoUringParams {
    pub sq_entries: u32,
    pub cq_entries: u32,
    pub flags: u32,
    pub sq_thread_cpu: u32,
    pub sq_thread_idle: u32,
    pub features: u32,
    pub wq_fd: u32,
    pub resv: [u32; 3],
    pub sq_off: IoSqringOffsets,
    pub cq_off: IoCqringOffsets,
}

/// Submission queue entry. Flat layout with padding to match the 64-byte kernel struct.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct IoUringSqe {
    pub opcode: u8,
    pub flags: u8,
    pub ioprio: u16,
    pub fd: i32,
    pub off: u64,
    pub addr: u64,
    pub len: u32,
    pub op_flags: u32,
    pub user_data: u64,
    pub buf_index: u16,
    pub personality: u16,
    pub splice_fd_in: i32,
    pub addr3: u64,
    pub(crate) _pad2: [u64; 1],
}

impl Default for IoUringSqe {
    fn default() -> Self {
        // Safety: zero-initialized SQE is valid (opcode 0 = NOP)
        unsafe { core::mem::zeroed() }
    }
}

/// Completion queue entry.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct IoUringCqe {
    pub user_data: u64,
    pub res: i32,
    pub flags: u32,
}

bitflags! {
    /// Flags on a completed CQE, set by the kernel.
    pub struct CqeFlags(u32);
    /// The buffer index is stored in the upper 16 bits of `flags`.
    const BUFFER = 1 << 0;
    /// More completions will follow from this request (multishot).
    const MORE = 1 << 1;
    /// Socket has more data ready to read (recv/accept).
    const SOCK_NONEMPTY = 1 << 2;
    /// Notification-only CQE (e.g. zero-copy send confirmation).
    const NOTIF = 1 << 3;
}

impl CqeFlags {
    /// Construct from the raw value in the CQE.
    pub(crate) const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }
}
