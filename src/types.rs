// ---------------------------------------------------------------------------
// Bitflag newtype macro — eliminates per-type boilerplate.
// ---------------------------------------------------------------------------

macro_rules! bitflags {
    (
        $(#[$meta:meta])*
        $vis:vis struct $Name:ident($inner:ty);
        $(
            $(#[$cmeta:meta])*
            const $FLAG:ident = $value:expr;
        )*
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
        $vis struct $Name($inner);

        impl $Name {
            $(
                $(#[$cmeta])*
                pub const $FLAG: Self = Self($value);
            )*

            /// Returns the raw underlying value.
            #[must_use]
            pub const fn bits(self) -> $inner {
                self.0
            }

            /// Check whether all bits in `flag` are set.
            #[must_use]
            pub const fn contains(self, flag: Self) -> bool {
                (self.0 & flag.0) == flag.0
            }
        }

        impl PartialEq<$inner> for $Name {
            fn eq(&self, other: &$inner) -> bool {
                self.0 == *other
            }
        }

        impl core::ops::BitOr for $Name {
            type Output = Self;
            fn bitor(self, rhs: Self) -> Self {
                Self(self.0 | rhs.0)
            }
        }

        impl core::ops::BitOrAssign for $Name {
            fn bitor_assign(&mut self, rhs: Self) {
                self.0 |= rhs.0;
            }
        }

        impl core::ops::BitAnd for $Name {
            type Output = Self;
            fn bitand(self, rhs: Self) -> Self {
                Self(self.0 & rhs.0)
            }
        }

        impl core::ops::BitAndAssign for $Name {
            fn bitand_assign(&mut self, rhs: Self) {
                self.0 &= rhs.0;
            }
        }

        impl core::ops::Not for $Name {
            type Output = Self;
            fn not(self) -> Self {
                Self(!self.0)
            }
        }
    };
}

// ---------------------------------------------------------------------------
// io_uring opcodes
// ---------------------------------------------------------------------------

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
    Statx = 21,
    Read = 22,
    Write = 23,
    Send = 26,
    Recv = 27,
    Shutdown = 34,
    Renameat = 35,
    Unlinkat = 36,
    Mkdirat = 37,
    Socket = 45,
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

bitflags! {
    /// Flags for `io_uring_enter`.
    pub struct EnterFlags(u32);
    const GETEVENTS = 1 << 0;
    /// Wake a sleeping SQPOLL thread.
    const SQ_WAKEUP = 1 << 1;
}

// ---------------------------------------------------------------------------
// io_uring setup flags
// ---------------------------------------------------------------------------

bitflags! {
    /// Flags for `io_uring_setup`.
    pub struct SetupFlags(u32);
    /// Kernel-side SQ polling thread.
    const SQPOLL = 1 << 1;
    /// Bind SQPOLL thread to a specific CPU.
    const SQ_AFF = 1 << 2;
    /// Use user-specified CQ ring size.
    const CQSIZE = 1 << 3;
    /// Clamp SQ/CQ ring sizes to implementation limits.
    const CLAMP = 1 << 4;
    /// Attach to an existing workqueue.
    const ATTACH_WQ = 1 << 5;
    /// Single-issuer hint (5.18+).
    const SINGLE_ISSUER = 1 << 12;
}

// ---------------------------------------------------------------------------
// io_uring feature flags (returned by kernel in params.features)
// ---------------------------------------------------------------------------

bitflags! {
    /// Feature flags reported by the kernel after `io_uring_setup`.
    pub struct Features(u32);
    const SINGLE_MMAP = 1 << 0;
    const NODROP = 1 << 1;
    const SUBMIT_STABLE = 1 << 2;
    const RW_CUR_POS = 1 << 3;
    const CUR_PERSONALITY = 1 << 4;
    const FAST_POLL = 1 << 5;
    const POLL_32BITS = 1 << 6;
    const SQPOLL_NONFIXED = 1 << 7;
    const EXT_ARG = 1 << 8;
    const NATIVE_WORKERS = 1 << 9;
}

impl Features {
    /// Construct from the raw value returned by the kernel.
    pub(crate) const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }
}

// ---------------------------------------------------------------------------
// SQE flags (for linking, drain, async)
// ---------------------------------------------------------------------------

bitflags! {
    /// Flags set on individual SQEs to control execution ordering and behavior.
    pub struct SqeFlags(u8);
    /// Use a registered/fixed file descriptor.
    const FIXED_FILE = 1 << 0;
    /// Drain the submission queue before executing this SQE.
    const IO_DRAIN = 1 << 1;
    /// Link this SQE to the next one — if this fails, the next is cancelled.
    const IO_LINK = 1 << 2;
    /// Hard-link: like `IO_LINK` but the chain continues even on failure.
    const IO_HARDLINK = 1 << 3;
    /// Force async execution even if the op could complete inline.
    const IO_ASYNC = 1 << 4;
    /// Select a buffer from a registered provided-buffer ring.
    ///
    /// When set, the kernel picks a buffer from the group identified by
    /// `sqe.buf_group` (aliased with `buf_index`) and reports the chosen
    /// buffer id in the upper 16 bits of the CQE flags.
    const BUFFER_SELECT = 1 << 5;
}

// ---------------------------------------------------------------------------
// io_uring_register opcodes
// ---------------------------------------------------------------------------

/// Opcodes for `io_uring_register`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RegisterOp {
    RegisterBuffers = 0,
    UnregisterBuffers = 1,
    RegisterFiles = 2,
    UnregisterFiles = 3,
    RegisterFilesUpdate = 6,
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

// ---------------------------------------------------------------------------
// mmap protection flags
// ---------------------------------------------------------------------------

bitflags! {
    /// Memory protection flags for `mmap`.
    pub struct Prot(u32);
    const READ = 0x1;
    const WRITE = 0x2;
}

// ---------------------------------------------------------------------------
// mmap mapping flags
// ---------------------------------------------------------------------------

bitflags! {
    /// Mapping flags for `mmap`.
    pub struct MapFlags(u32);
    const SHARED = 0x01;
    const PRIVATE = 0x02;
    const ANONYMOUS = 0x20;
    const POPULATE = 0x0000_8000;
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

bitflags! {
    /// File open flags for `openat`.
    ///
    /// Note: `O_RDONLY` (0) is not included because it is the *absence* of
    /// `WRONLY` and `RDWR`, not a flag bit. Use `OpenFlags::default()` for
    /// read-only access. `WRONLY` and `RDWR` are mutually exclusive access
    /// modes, not combinable flags.
    pub struct OpenFlags(u32);
    const WRONLY = 1;
    const RDWR = 2;
    const CREAT = 0o100;
    const TRUNC = 0o1000;
    const TMPFILE = 0o20_200_000;
}

/// Special directory fd meaning "current working directory".
pub const AT_FDCWD: i32 = -100;

// ---------------------------------------------------------------------------
// File mode bits
// ---------------------------------------------------------------------------

bitflags! {
    /// File permission mode bits.
    pub struct FileMode(u32);
    const OWNER_READ = 0o400;
    const OWNER_WRITE = 0o200;
    const OWNER_EXEC = 0o100;
    const GROUP_READ = 0o040;
    const GROUP_WRITE = 0o020;
    const GROUP_EXEC = 0o010;
    const OTHER_READ = 0o004;
    const OTHER_WRITE = 0o002;
    const OTHER_EXEC = 0o001;
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

/// Argument struct for `IORING_REGISTER_PBUF_RING`.
///
/// The kernel treats this as a 40-byte struct; fields after `flags` are
/// reserved and must be zero.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct IoUringBufReg {
    /// User-space virtual address of the buffer ring (`ring_entries` × 16 bytes).
    pub ring_addr: u64,
    /// Number of entries in the ring. Must be a power of two.
    pub ring_entries: u32,
    /// Buffer group id that SQEs will reference via `buf_group`.
    pub bgid: u16,
    /// Reserved / flags — leave zero for user-allocated rings.
    pub flags: u16,
    pub(crate) resv: [u64; 3],
}

/// A single buffer descriptor inside a provided-buffer ring.
///
/// The first entry in the ring is special: its `resv` field aliases the
/// ring's producer `tail` (the last 2 bytes). Callers should only write
/// real buffers starting from index 1, or — if using index 0 — never
/// touch its `resv` field.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct IoUringBuf {
    /// User-space address of the buffer.
    pub addr: u64,
    /// Length of the buffer in bytes.
    pub len: u32,
    /// Buffer id — reported back in the upper 16 bits of CQE flags.
    pub bid: u16,
    /// Reserved (aliases the ring tail in entry 0).
    pub resv: u16,
}

/// Completion queue entry.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct IoUringCqe {
    pub user_data: u64,
    pub res: i32,
    pub flags: u32,
}

// ---------------------------------------------------------------------------
// CQE flags (returned by kernel in cqe.flags)
// ---------------------------------------------------------------------------

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

/// Raw file descriptor type alias.
pub type RawFd = i32;

/// I/O vector for vectored read/write operations.
///
/// Fields are private because an `IoVec` with a dangling or mismatched
/// pointer/length is instant UB when submitted to the kernel. Use
/// [`new`](Self::new) to construct.
///
/// **Lifetime warning:** `IoVec` implements `Clone` and `Copy` (required
/// for use in arrays and kernel registration). Cloning an `IoVec` does
/// *not* extend the lifetime of the underlying buffer — it is the
/// caller's responsibility to ensure the buffer outlives all copies.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct IoVec {
    base: *mut u8,
    len: usize,
}

impl IoVec {
    /// Create a new I/O vector from a pointer and length.
    ///
    /// # Safety
    ///
    /// `base` must point to at least `len` bytes of valid memory that
    /// remains valid for the duration of any I/O operation that uses
    /// this vector.
    #[must_use]
    pub const unsafe fn new(base: *mut u8, len: usize) -> Self {
        Self { base, len }
    }

    /// Returns the base pointer.
    #[must_use]
    pub const fn base(&self) -> *mut u8 {
        self.base
    }

    /// Returns the length in bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the length is zero.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Kernel timespec for timeout operations.
///
/// Fields are private to enforce the nanosecond range invariant
/// (`0 <= tv_nsec < 1_000_000_000`). Use [`new`](Self::new) or
/// [`from_millis`](Self::from_millis) to construct.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

impl Timespec {
    /// Create a timespec from seconds and nanoseconds.
    ///
    /// # Panics
    ///
    /// Panics if `nsec` is not in `0..1_000_000_000`.
    #[must_use]
    pub const fn new(sec: i64, nsec: i64) -> Self {
        assert!(
            nsec >= 0 && nsec < 1_000_000_000,
            "nsec out of range 0..1_000_000_000"
        );
        Self {
            tv_sec: sec,
            tv_nsec: nsec,
        }
    }

    /// Create a timespec from milliseconds.
    #[must_use]
    #[allow(clippy::cast_possible_wrap)]
    pub const fn from_millis(ms: u64) -> Self {
        Self::new((ms / 1000) as i64, ((ms % 1000) * 1_000_000) as i64)
    }

    /// Returns the seconds component.
    #[must_use]
    pub const fn tv_sec(&self) -> i64 {
        self.tv_sec
    }

    /// Returns the nanoseconds component (always in `0..1_000_000_000`).
    #[must_use]
    pub const fn tv_nsec(&self) -> i64 {
        self.tv_nsec
    }
}

// ---------------------------------------------------------------------------
// Timeout flags
// ---------------------------------------------------------------------------

bitflags! {
    /// Flags for timeout operations.
    pub struct TimeoutFlags(u32);
    /// Use an absolute timeout instead of relative.
    const ABS = 1 << 0;
}

// ---------------------------------------------------------------------------
// Fsync flags
// ---------------------------------------------------------------------------

bitflags! {
    /// Flags for fsync operations.
    pub struct FsyncFlags(u32);
    /// Only sync file data, not metadata (fdatasync behavior).
    const DATASYNC = 1 << 0;
}

// ---------------------------------------------------------------------------
// Poll mask
// ---------------------------------------------------------------------------

bitflags! {
    /// Event mask for poll operations (matches Linux poll event bits).
    pub struct PollMask(u32);
    const IN = 0x0001;
    const OUT = 0x0004;
    const ERR = 0x0008;
    const HUP = 0x0010;
    const RDHUP = 0x2000;
}

// ---------------------------------------------------------------------------
// Fallocate mode
// ---------------------------------------------------------------------------

bitflags! {
    /// Mode flags for fallocate operations.
    ///
    /// Use `FallocateMode::default()` for the default allocation mode
    /// (`FALLOC_FL_DEFAULT = 0`), which is the absence of any mode flags.
    pub struct FallocateMode(u32);
    /// Keep file size unchanged.
    const KEEP_SIZE = 0x01;
    /// Punch a hole (deallocate).
    const PUNCH_HOLE = 0x02;
    /// Zero a range (do not deallocate).
    const ZERO_RANGE = 0x10;
}

// ---------------------------------------------------------------------------
// Statx
// ---------------------------------------------------------------------------

bitflags! {
    /// Flags for statx requests.
    pub struct StatxFlags(u32);
    const EMPTY_PATH = 0x1000;
    const SYMLINK_NOFOLLOW = 0x100;
}

bitflags! {
    /// Mask for which statx fields to populate.
    pub struct StatxMask(u32);
    const TYPE = 0x0001;
    const MODE = 0x0002;
    const NLINK = 0x0004;
    const UID = 0x0008;
    const GID = 0x0010;
    const ATIME = 0x0020;
    const MTIME = 0x0040;
    const CTIME = 0x0080;
    const INO = 0x0100;
    const SIZE = 0x0200;
    const BLOCKS = 0x0400;
    const BASIC_STATS = 0x07FF;
    const ALL = 0x0FFF;
}

/// Kernel `statx` timestamp.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct StatxTimestamp {
    pub tv_sec: i64,
    pub tv_nsec: u32,
    pub(crate) _reserved: i32,
}

/// Kernel `statx` result structure.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Statx {
    pub stx_mask: u32,
    pub stx_blksize: u32,
    pub stx_attributes: u64,
    pub stx_nlink: u32,
    pub stx_uid: u32,
    pub stx_gid: u32,
    pub stx_mode: u16,
    pub(crate) _spare0: u16,
    pub stx_ino: u64,
    pub stx_size: u64,
    pub stx_blocks: u64,
    pub stx_attributes_mask: u64,
    pub stx_atime: StatxTimestamp,
    pub stx_btime: StatxTimestamp,
    pub stx_ctime: StatxTimestamp,
    pub stx_mtime: StatxTimestamp,
    pub stx_rdev_major: u32,
    pub stx_rdev_minor: u32,
    pub stx_dev_major: u32,
    pub stx_dev_minor: u32,
    pub stx_mnt_id: u64,
    pub stx_dio_mem_align: u32,
    pub stx_dio_offset_align: u32,
    pub(crate) _spare3: [u64; 12],
}

// ---------------------------------------------------------------------------
// Rename / unlink flags
// ---------------------------------------------------------------------------

bitflags! {
    /// Flags for renameat2.
    pub struct RenameFlags(u32);
    const NOREPLACE = 1 << 0;
    const EXCHANGE = 1 << 1;
}

bitflags! {
    /// Flags for unlinkat.
    pub struct UnlinkFlags(u32);
    /// Remove a directory instead of a file.
    const REMOVEDIR = 0x200;
}

// ---------------------------------------------------------------------------
// Networking constants
// ---------------------------------------------------------------------------

/// Address family constants.
pub const AF_INET: i32 = 2;
pub const AF_INET6: i32 = 10;

/// Socket type constants.
pub const SOCK_STREAM: i32 = 1;
pub const SOCK_DGRAM: i32 = 2;
pub const SOCK_NONBLOCK: i32 = 0o4000;

/// Socket option levels and options.
pub const SOL_SOCKET: i32 = 1;
pub const SO_REUSEADDR: i32 = 2;

/// Shutdown modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ShutdownHow {
    Read = 0,
    Write = 1,
    Both = 2,
}

impl From<ShutdownHow> for u32 {
    fn from(how: ShutdownHow) -> Self {
        how as Self
    }
}

bitflags! {
    /// Send/recv flags.
    ///
    /// Use `MsgFlags::default()` for no flags.
    pub struct MsgFlags(u32);
    const DONTWAIT = 0x40;
    const NOSIGNAL = 0x4000;
    const WAITALL = 0x100;
}

bitflags! {
    /// Accept flags (same as socket flags that make sense for accept4).
    ///
    /// Use `AcceptFlags::default()` for no flags.
    pub struct AcceptFlags(u32);
    const NONBLOCK = 0o4000;
}

bitflags! {
    /// Flags for `IORING_OP_SOCKET` (passed via `sqe.rw_flags`).
    ///
    /// These modify the created socket's behavior independently of the
    /// socket type passed in `sock_type`.
    pub struct SocketFlags(u32);
    /// Set the socket to non-blocking mode (`SOCK_NONBLOCK`).
    const NONBLOCK = 0o4000;
    /// Set close-on-exec on the new file descriptor (`SOCK_CLOEXEC`).
    const CLOEXEC = 0o2_000_000;
}

/// IPv4 socket address.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct SockAddrIn {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: u32,
    pub sin_zero: [u8; 8],
}

/// Message header for sendmsg/recvmsg.
///
/// The padding fields match the `x86_64` C ABI layout of `struct msghdr`:
/// the compiler inserts padding after `msg_namelen` (u32) to align
/// `msg_iov` (pointer) to 8 bytes, and after `msg_flags` (i32) to bring
/// the struct size to a multiple of 8 (the alignment of pointer fields).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct MsgHdr {
    pub msg_name: *mut u8,
    pub msg_namelen: u32,
    /// Alignment padding after u32 `msg_namelen` to align `msg_iov` to 8 bytes.
    pub(crate) _pad1: u32,
    pub msg_iov: *mut IoVec,
    pub msg_iovlen: usize,
    pub msg_control: *mut u8,
    pub msg_controllen: usize,
    pub msg_flags: i32,
    /// Trailing padding after i32 `msg_flags` for 8-byte struct alignment.
    pub(crate) _pad2: u32,
}

impl Default for MsgHdr {
    fn default() -> Self {
        // Safety: all fields are integer or pointer types; zero is valid.
        unsafe { core::mem::zeroed() }
    }
}

// ---------------------------------------------------------------------------
// Inotify
// ---------------------------------------------------------------------------

bitflags! {
    /// Event mask for inotify watches.
    pub struct WatchMask(u32);
    /// File was accessed.
    const ACCESS = 0x0000_0001;
    /// File was modified.
    const MODIFY = 0x0000_0002;
    /// Metadata changed.
    const ATTRIB = 0x0000_0004;
    /// Writable file was closed.
    const CLOSE_WRITE = 0x0000_0008;
    /// Non-writable file was closed.
    const CLOSE_NOWRITE = 0x0000_0010;
    /// File was opened.
    const OPEN = 0x0000_0020;
    /// File was moved from watched directory.
    const MOVED_FROM = 0x0000_0040;
    /// File was moved to watched directory.
    const MOVED_TO = 0x0000_0080;
    /// File was created in watched directory.
    const CREATE = 0x0000_0100;
    /// File was deleted from watched directory.
    const DELETE = 0x0000_0200;
    /// Watched file/directory was deleted.
    const DELETE_SELF = 0x0000_0400;
    /// Watched file/directory was moved.
    const MOVE_SELF = 0x0000_0800;
    /// Shorthand for `CLOSE_WRITE | CLOSE_NOWRITE`.
    const CLOSE = 0x0000_0018;
    /// Shorthand for `MOVED_FROM | MOVED_TO`.
    const MOVE = 0x0000_00C0;
    /// All events.
    const ALL_EVENTS = 0x0000_0FFF;
}

/// Fixed-size header of a kernel `inotify_event`.
///
/// The kernel appends a variable-length null-terminated name after this
/// header when the event is for a file inside a watched directory.
/// The `len` field gives the total size of that name (including padding
/// and the null terminator). When `len` is 0 the event targets the
/// watched inode itself and there is no trailing name.
///
/// To parse events from a read buffer, advance by
/// `size_of::<InotifyEvent>() + event.len as usize` for each event.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct InotifyEvent {
    /// Watch descriptor that matched.
    pub wd: i32,
    /// Bitmask of events (same bits as [`WatchMask`], plus kernel-set flags).
    pub mask: u32,
    /// Cookie for pairing `MOVED_FROM`/`MOVED_TO` events.
    pub cookie: u32,
    /// Length of the optional name following this struct.
    pub len: u32,
}

/// `IN_NONBLOCK` flag for `inotify_init1`.
pub const IN_NONBLOCK: i32 = 0o4000;
/// `IN_CLOEXEC` flag for `inotify_init1`.
pub const IN_CLOEXEC: i32 = 0o2_000_000;

// ---------------------------------------------------------------------------
// Eventfd
// ---------------------------------------------------------------------------

bitflags! {
    /// Flags for `eventfd2`.
    pub struct EventFdFlags(i32);
    /// Set the file descriptor to non-blocking mode.
    const NONBLOCK = 0o4000;
    /// Set close-on-exec on the new file descriptor.
    const CLOEXEC = 0o2_000_000;
    /// Provide semaphore-like semantics: each `read` decrements by 1.
    const SEMAPHORE = 1;
}
