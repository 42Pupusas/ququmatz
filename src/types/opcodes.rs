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
    SyncFileRange = 8,
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
    Symlinkat = 38,
    Linkat = 39,
    MsgRing = 40,
    Fsetxattr = 41,
    Setxattr = 42,
    Fgetxattr = 43,
    Getxattr = 44,
    Socket = 45,
    UringCmd = 46,
    SendZc = 47,
    SendmsgZc = 48,
    ReadMultishot = 49,
    WaitId = 50,
    FutexWait = 51,
    FutexWake = 52,
    FutexWaitv = 53,
    FixedFdInstall = 54,
    Ftruncate = 55,
    Bind = 56,
    Listen = 57,
    EpollWait = 59,
    ReadvFixed = 60,
    WritevFixed = 61,
    Pipe = 62,
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
    /// Ask the kernel which SQE opcodes it supports.
    RegisterProbe = 8,
    RegisterRestrictions = 11,
    /// Start a ring created with `SetupFlags::R_DISABLED` actually accepting
    /// submissions.
    RegisterEnableRings = 12,
    /// Register files with per-resource death tags (kernel 5.13+): like
    /// `RegisterFiles`, but through `struct io_uring_rsrc_register` so
    /// each descriptor can carry a caller-chosen tag posted back as a
    /// CQE once that slot is replaced or the table is torn down and the
    /// kernel is done with it.
    RegisterFiles2 = 13,
    /// Update a subset of a tagged file table (kernel 5.13+): like
    /// `RegisterFilesUpdate`, but through `struct io_uring_rsrc_update2`
    /// so the replaced slots' tags are posted once the kernel is done
    /// with what they named.
    RegisterFilesUpdate2 = 14,
    /// Register buffers with per-resource death tags (kernel 5.13+): like
    /// `RegisterBuffers`, but through `struct io_uring_rsrc_register` so
    /// each buffer can carry a caller-chosen tag posted back as a CQE
    /// once that slot is replaced or the table is torn down and the
    /// kernel is done with it.
    RegisterBuffers2 = 15,
    /// Update a subset of a tagged buffer table (kernel 5.13+): like
    /// `RegisterBuffers2` but targeting an offset within an
    /// already-registered table rather than replacing it wholesale.
    RegisterBuffersUpdate = 16,
    /// Pin this ring's io-wq worker threads to a caller-supplied CPU mask.
    RegisterIowqAff = 17,
    /// Undo `RegisterIowqAff`, releasing the io-wq threads back to the
    /// process's own affinity.
    UnregisterIowqAff = 18,
    RegisterIowqMaxWorkers = 19,
    /// Register the ring fd itself as a fixed fd (saves file-table lookup on enter).
    RegisterRingFds = 20,
    /// Undo `RegisterRingFds`, releasing the registered-fd slots it took.
    UnregisterRingFds = 21,
    /// Register a provided-buffer ring (kernel 5.19+).
    RegisterPbufRing = 22,
    /// Unregister a provided-buffer ring.
    UnregisterPbufRing = 23,
    /// Synchronous cancel-and-wait: cancels a request and blocks the
    /// calling thread until either it is cancelled or a timeout elapses,
    /// with no separate submit/poll round trip (kernel 6.0+).
    RegisterSyncCancel = 24,
    /// Set the allowable range for fixed-file-index auto-allocation
    /// (`IORING_FILE_INDEX_ALLOC`) so newly instantiated direct descriptors
    /// land in a caller-chosen slice of the file table (kernel 6.0+).
    RegisterFileAllocRange = 25,
    /// Query a provided-buffer ring's current consumer head (kernel 6.8+).
    RegisterPbufStatus = 26,
    /// Set or update NAPI busy-poll tracking for this ring's sockets
    /// (kernel 6.9+, requires `CONFIG_NET_RX_BUSY_POLL`).
    RegisterNapi = 27,
    /// Stop NAPI busy-poll tracking, restoring irq-driven completion.
    UnregisterNapi = 28,
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
