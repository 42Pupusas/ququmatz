//! Kernel SQE/CQE/params layout and CQE flag bits.

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
    /// Shares its eight bytes with the rw-attribute pointer
    /// (`sqe->attr_ptr`) — the kernel's own layout is a union here
    /// (`addr3`/`__pad2` vs. `attr_ptr`/`attr_type_mask`), so this crate
    /// exposes both pairs of named accessors
    /// ([`attr_ptr`](Self::attr_ptr)/[`attr_type_mask`](Self::attr_type_mask))
    /// over the same two `u64` slots rather than only one. A read/write op
    /// that sets `attr_ptr`/`attr_type_mask` must not also rely on
    /// `addr3`/`_pad2` meaning anything, and vice versa — see
    /// [`super::RwAttrFlags`].
    pub addr3: u64,
    /// Shares its eight bytes with the rw-attribute type mask
    /// (`sqe->attr_type_mask`) — see [`attr_type_mask`](Self::attr_type_mask).
    /// Named without the crate's usual `_pad`-prefix-means-never-read
    /// convention specifically because this field genuinely is read now,
    /// through that accessor.
    pub(crate) pad2: [u64; 1],
}

impl IoUringSqe {
    /// Read `addr3`'s union alias as the rw-attribute pointer
    /// (`sqe->attr_ptr`).
    #[must_use]
    pub const fn attr_ptr(&self) -> u64 {
        self.addr3
    }

    /// Write the rw-attribute pointer (`sqe->attr_ptr`), which overlaps
    /// `addr3` in the kernel's own union.
    pub const fn set_attr_ptr(&mut self, ptr: u64) {
        self.addr3 = ptr;
    }

    /// Read `pad2`'s union alias as the rw-attribute type mask
    /// (`sqe->attr_type_mask`).
    #[must_use]
    pub const fn attr_type_mask(&self) -> u64 {
        self.pad2[0]
    }

    /// Write the rw-attribute type mask (`sqe->attr_type_mask`), which
    /// overlaps `pad2` in the kernel's own union.
    pub const fn set_attr_type_mask(&mut self, mask: u64) {
        self.pad2[0] = mask;
    }

    /// Read the `IORING_OP_URING_CMD` sub-opcode (`sqe->cmd_op`), a union
    /// alias over the low 32 bits of `off` meaningful only for that opcode
    /// (confirmed against the kernel's `struct io_uring_sqe` off union:
    /// `{ off; addr2; struct { cmd_op; __pad1; }; }`, `cmd_op` first and
    /// therefore lowest-addressed on every target this crate supports).
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub const fn cmd_op(&self) -> u32 {
        self.off as u32
    }

    /// Write the `IORING_OP_URING_CMD` sub-opcode, overlapping the low 32
    /// bits of `off`. The high 32 bits (`__pad1`) are left untouched, which
    /// is correct only starting from a zeroed SQE — every `uring_cmd_sock_*`
    /// constructor in this crate starts from [`super::super::op::ZEROED`].
    pub const fn set_cmd_op(&mut self, op: u32) {
        self.off = (self.off & 0xFFFF_FFFF_0000_0000) | op as u64;
    }

    /// Read the socket-ioctl `level` (`sqe->level`), a union alias over the
    /// low 32 bits of `addr` — meaningful only for
    /// `SOCKET_URING_OP_GETSOCKOPT`/`SETSOCKOPT`.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub const fn sock_level(&self) -> u32 {
        self.addr as u32
    }

    /// Write the socket-ioctl `level`, overlapping the low 32 bits of `addr`.
    pub const fn set_sock_level(&mut self, level: u32) {
        self.addr = (self.addr & 0xFFFF_FFFF_0000_0000) | level as u64;
    }

    /// Read the socket-ioctl `optname` (`sqe->optname`), a union alias over
    /// the high 32 bits of `addr`.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub const fn sock_optname(&self) -> u32 {
        (self.addr >> 32) as u32
    }

    /// Write the socket-ioctl `optname`, overlapping the high 32 bits of
    /// `addr`.
    pub const fn set_sock_optname(&mut self, optname: u32) {
        self.addr = (self.addr & 0xFFFF_FFFF) | ((optname as u64) << 32);
    }

    /// Read the socket-ioctl option length (`sqe->optlen`), a union alias
    /// over `splice_fd_in`.
    #[must_use]
    pub const fn optlen(&self) -> u32 {
        self.splice_fd_in.cast_unsigned()
    }

    /// Write the socket-ioctl option length, overlapping `splice_fd_in`.
    pub const fn set_optlen(&mut self, len: u32) {
        self.splice_fd_in = len.cast_signed();
    }

    /// Read the socket-ioctl option value pointer (`sqe->optval`), a union
    /// alias over the *same* eight bytes as [`attr_ptr`](Self::attr_ptr) —
    /// confirmed against the kernel's own union, which lists `optval`
    /// alongside `addr3`/`attr_ptr` as three names for one slot. Given a
    /// thin name of its own here rather than reusing `attr_ptr` at call
    /// sites, since "this is a PI attribute pointer" and "this is a
    /// sockopt buffer pointer" are unrelated claims that happen to share
    /// storage, not the same fact spelled two ways.
    #[must_use]
    pub const fn sock_optval(&self) -> u64 {
        self.addr3
    }

    /// Write the socket-ioctl option value pointer, overlapping `addr3`/`attr_ptr`.
    pub const fn set_sock_optval(&mut self, optval: u64) {
        self.addr3 = optval;
    }
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
    /// The completed buffer id is still partially unconsumed and will
    /// generate further completions before it returns to the pool.
    ///
    /// Only set for buffers taken from a ring registered with
    /// [`PbufRingFlags::INC`](super::PbufRingFlags::INC) — for any other
    /// provided-buffer setup every completion that carries a buffer id
    /// hands the whole buffer back and this flag never appears. While
    /// it is set, do not recycle the id: the kernel still owns it and
    /// will keep writing to the same slot.
    const BUF_MORE = 1 << 4;
}

impl CqeFlags {
    /// Construct from the raw value in the CQE.
    #[must_use]
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    /// The provided-buffer id packed into the upper 16 bits.
    ///
    /// `Some` only when [`BUFFER`](Self::BUFFER) is set, which is what
    /// distinguishes "the kernel chose slot 0" from "the kernel chose no
    /// slot" — both leave those bits zero. The id names a pool buffer that
    /// is out of circulation until it is recycled, so losing it drains the
    /// pool.
    #[must_use]
    pub const fn buffer_id(self) -> Option<u16> {
        if self.contains(Self::BUFFER) {
            #[allow(clippy::cast_possible_truncation)]
            Some((self.bits() >> 16) as u16)
        } else {
            None
        }
    }
}
