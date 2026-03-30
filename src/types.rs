// io_uring opcodes
pub const IORING_OP_NOP: u8 = 0;
pub const IORING_OP_READV: u8 = 1;
pub const IORING_OP_WRITEV: u8 = 2;
pub const IORING_OP_OPENAT: u8 = 18;
pub const IORING_OP_CLOSE: u8 = 19;
pub const IORING_OP_READ: u8 = 22;
pub const IORING_OP_WRITE: u8 = 23;

// io_uring_enter flags
pub const IORING_ENTER_GETEVENTS: u32 = 1 << 0;

// mmap prot flags
pub const PROT_READ: i32 = 0x1;
pub const PROT_WRITE: i32 = 0x2;

// mmap map flags
pub const MAP_SHARED: i32 = 0x01;
pub const MAP_POPULATE: i32 = 0x0000_8000;

// io_uring mmap offsets
pub const IORING_OFF_SQ_RING: u64 = 0;
pub const IORING_OFF_CQ_RING: u64 = 0x0800_0000;
pub const IORING_OFF_SQES: u64 = 0x1000_0000;

// openat constants
pub const AT_FDCWD: i32 = -100;
pub const O_RDONLY: i32 = 0;
pub const O_WRONLY: i32 = 1;
pub const O_RDWR: i32 = 2;
pub const O_CREAT: i32 = 0o100;
pub const O_TRUNC: i32 = 0o1000;
pub const O_TMPFILE: i32 = 0o20_200_000;

// file mode
pub const S_IRUSR: u32 = 0o400;
pub const S_IWUSR: u32 = 0o200;

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
