//! Kernel opcode enums for SQEs and the register syscall.

/// `io_uring` submission queue operation codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u8)]
pub enum Opcode {
    Nop = 0,
    Readv = 1,
    Writev = 2,
    Fsync = 3,
    ReadFixed = 4,
    WriteFixed = 5,
    PollAdd = 6,
    PollRemove = 7,
    SendMsg = 9,
    RecvMsg = 10,
    Timeout = 11,
    TimeoutRemove = 12,
    Accept = 13,
    AsyncCancel = 14,
    LinkTimeout = 15,
    Connect = 16,
    Fallocate = 17,
    Openat = 18,
    Close = 19,
    FilesUpdate = 20,
    Statx = 21,
    Read = 22,
    Write = 23,
    Fadvise = 24,
    Madvise = 25,
    Send = 26,
    Recv = 27,
    Openat2 = 28,
    EpollCtl = 29,
    Splice = 30,
    ProvideBuffers = 31,
    RemoveBuffers = 32,
    Tee = 33,
    Shutdown = 34,
    Renameat = 35,
    Unlinkat = 36,
    Mkdirat = 37,
    Socket = 45,
    UringCmd = 46,
    SendZc = 47,
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

/// Opcodes for `io_uring_register`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RegisterOp {
    RegisterBuffers = 0,
    UnregisterBuffers = 1,
    RegisterFiles = 2,
    UnregisterFiles = 3,
    RegisterEventFd = 4,
    UnregisterEventFd = 5,
    RegisterFilesUpdate = 6,
    RegisterEventFdAsync = 7,
    RegisterRestrictions = 11,
    RegisterBuffersUpdate = 16,
    RegisterIowqMaxWorkers = 19,
    /// Register the ring fd itself as a fixed fd (saves file-table lookup on enter).
    RegisterRingFds = 20,
    /// Register a provided-buffer ring (kernel 5.19+).
    RegisterPbufRing = 22,
    /// Unregister a provided-buffer ring.
    UnregisterPbufRing = 23,
}

impl From<RegisterOp> for u32 {
    fn from(op: RegisterOp) -> Self {
        op as Self
    }
}

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
