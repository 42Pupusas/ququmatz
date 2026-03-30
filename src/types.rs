use core::ops::BitOr;

// ---------------------------------------------------------------------------
// io_uring opcodes
// ---------------------------------------------------------------------------

/// `io_uring` submission queue operation codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    Nop = 0,
    Readv = 1,
    Writev = 2,
    Timeout = 11,
    TimeoutRemove = 12,
    Accept = 13,
    AsyncCancel = 14,
    LinkTimeout = 15,
    Openat = 18,
    Close = 19,
    Read = 22,
    Write = 23,
}

impl PartialEq<u8> for Opcode {
    fn eq(&self, other: &u8) -> bool {
        *self as u8 == *other
    }
}

impl From<Opcode> for u8 {
    fn from(op: Opcode) -> Self {
        op as Self
    }
}

// ---------------------------------------------------------------------------
// io_uring_enter flags
// ---------------------------------------------------------------------------

/// Flags for `io_uring_enter`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EnterFlags(u32);

impl EnterFlags {
    pub const GETEVENTS: Self = Self(1 << 0);

    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }
}

impl PartialEq<u32> for EnterFlags {
    fn eq(&self, other: &u32) -> bool {
        self.0 == *other
    }
}

impl BitOr for EnterFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

// ---------------------------------------------------------------------------
// SQE flags (for linking, drain, async)
// ---------------------------------------------------------------------------

/// Flags set on individual SQEs to control execution ordering and behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SqeFlags(u8);

impl SqeFlags {
    /// Drain the submission queue before executing this SQE.
    pub const IO_DRAIN: Self = Self(1 << 1);
    /// Link this SQE to the next one — if this fails, the next is cancelled.
    pub const IO_LINK: Self = Self(1 << 2);
    /// Hard-link: like `IO_LINK` but the chain continues even on failure.
    pub const IO_HARDLINK: Self = Self(1 << 3);
    /// Force async execution even if the op could complete inline.
    pub const IO_ASYNC: Self = Self(1 << 4);

    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }
}

impl PartialEq<u8> for SqeFlags {
    fn eq(&self, other: &u8) -> bool {
        self.0 == *other
    }
}

impl From<SqeFlags> for u8 {
    fn from(f: SqeFlags) -> Self {
        f.0
    }
}

impl BitOr for SqeFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

// ---------------------------------------------------------------------------
// mmap protection flags
// ---------------------------------------------------------------------------

/// Memory protection flags for `mmap`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Prot(i32);

impl Prot {
    pub const READ: Self = Self(0x1);
    pub const WRITE: Self = Self(0x2);

    #[must_use]
    pub const fn bits(self) -> i32 {
        self.0
    }
}

impl PartialEq<i32> for Prot {
    fn eq(&self, other: &i32) -> bool {
        self.0 == *other
    }
}

impl BitOr for Prot {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

// ---------------------------------------------------------------------------
// mmap mapping flags
// ---------------------------------------------------------------------------

/// Mapping flags for `mmap`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MapFlags(i32);

impl MapFlags {
    pub const SHARED: Self = Self(0x01);
    pub const POPULATE: Self = Self(0x0000_8000);

    #[must_use]
    pub const fn bits(self) -> i32 {
        self.0
    }
}

impl PartialEq<i32> for MapFlags {
    fn eq(&self, other: &i32) -> bool {
        self.0 == *other
    }
}

impl BitOr for MapFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

// ---------------------------------------------------------------------------
// io_uring mmap offsets
// ---------------------------------------------------------------------------

/// Magic offsets for `mmap`ing `io_uring` ring regions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum RingOffset {
    SqRing = 0,
    CqRing = 0x0800_0000,
    Sqes = 0x1000_0000,
}

impl PartialEq<u64> for RingOffset {
    fn eq(&self, other: &u64) -> bool {
        *self as u64 == *other
    }
}

impl From<RingOffset> for u64 {
    fn from(off: RingOffset) -> Self {
        off as Self
    }
}

// ---------------------------------------------------------------------------
// openat flags
// ---------------------------------------------------------------------------

/// File open flags for `openat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OpenFlags(i32);

impl OpenFlags {
    pub const RDONLY: Self = Self(0);
    pub const WRONLY: Self = Self(1);
    pub const RDWR: Self = Self(2);
    pub const CREAT: Self = Self(0o100);
    pub const TRUNC: Self = Self(0o1000);
    pub const TMPFILE: Self = Self(0o20_200_000);

    #[must_use]
    pub const fn bits(self) -> i32 {
        self.0
    }
}

impl PartialEq<i32> for OpenFlags {
    fn eq(&self, other: &i32) -> bool {
        self.0 == *other
    }
}

impl BitOr for OpenFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// Special directory fd meaning "current working directory".
pub const AT_FDCWD: i32 = -100;

// ---------------------------------------------------------------------------
// File mode bits
// ---------------------------------------------------------------------------

/// File permission mode bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FileMode(u32);

impl FileMode {
    pub const OWNER_READ: Self = Self(0o400);
    pub const OWNER_WRITE: Self = Self(0o200);

    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }
}

impl PartialEq<u32> for FileMode {
    fn eq(&self, other: &u32) -> bool {
        self.0 == *other
    }
}

impl BitOr for FileMode {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

// ---------------------------------------------------------------------------
// Kernel structs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct IoSqringOffsets {
    pub head: u32,
    pub tail: u32,
    pub ring_mask: u32,
    pub ring_entries: u32,
    pub flags: u32,
    pub dropped: u32,
    pub array: u32,
    pub resv1: u32,
    pub user_addr: u64,
}

#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct IoCqringOffsets {
    pub head: u32,
    pub tail: u32,
    pub ring_mask: u32,
    pub ring_entries: u32,
    pub overflow: u32,
    pub cqes: u32,
    pub flags: u32,
    pub resv1: u32,
    pub user_addr: u64,
}

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
#[derive(Clone, Copy)]
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

/// I/O vector for vectored read/write operations.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct IoVec {
    pub base: *mut u8,
    pub len: usize,
}

/// Kernel timespec for timeout operations.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

impl Timespec {
    /// Create a timespec from seconds and nanoseconds.
    #[must_use]
    pub const fn new(sec: i64, nsec: i64) -> Self {
        Self {
            tv_sec: sec,
            tv_nsec: nsec,
        }
    }

    /// Create a timespec from milliseconds.
    #[must_use]
    #[allow(clippy::cast_possible_wrap)]
    pub const fn from_millis(ms: u64) -> Self {
        Self {
            tv_sec: (ms / 1000) as i64,
            tv_nsec: ((ms % 1000) * 1_000_000) as i64,
        }
    }
}

// ---------------------------------------------------------------------------
// Timeout flags
// ---------------------------------------------------------------------------

/// Flags for timeout operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TimeoutFlags(u32);

impl TimeoutFlags {
    /// Use an absolute timeout instead of relative.
    pub const ABS: Self = Self(1 << 0);

    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }
}

impl PartialEq<u32> for TimeoutFlags {
    fn eq(&self, other: &u32) -> bool {
        self.0 == *other
    }
}

impl BitOr for TimeoutFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}
