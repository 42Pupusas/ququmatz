//! Ring offsets, `IoVec`, and buffer-registration kernel structs.

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
    /// Registration flags — see [`PbufRingFlags`].
    pub flags: u16,
    pub(crate) resv: [u64; 3],
}

bitflags! {
    /// Flags for `IORING_REGISTER_PBUF_RING` (`struct io_uring_buf_reg::flags`).
    pub struct PbufRingFlags(u16);
    /// The buffers in this ring can be incrementally consumed
    /// (`IOU_PBUF_RING_INC`, kernel 6.12+).
    ///
    /// Without this flag, a completion that selects a buffer always
    /// hands the whole thing over and the id returns to the pool once
    /// the application calls `recycle`. With it, a single buffer can
    /// satisfy many completions in turn — each one picks up where the
    /// last left off — and the kernel keeps the id out of the recycle
    /// pool for as long as the completion's `BUF_MORE` flag is set;
    /// only recycle once a completion for that id arrives without that
    /// flag.
    const INC = 1 << 1;
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

/// An owned raw file descriptor.
///
/// A newtype wrapping `usize` so that file descriptors cannot be accidentally
/// mixed with arbitrary integers. Construct with [`RawFd::from_raw`]; convert
/// back with [`RawFd::as_usize`] or [`RawFd::as_i32`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RawFd(usize);

impl RawFd {
    /// Wrap a raw fd value.
    #[must_use]
    pub const fn from_raw(fd: usize) -> Self {
        Self(fd)
    }

    /// Return the fd as a `usize` (for passing to syscall wrappers).
    #[must_use]
    pub const fn as_usize(self) -> usize {
        self.0
    }

    /// Return the fd as an `i32` (for kernel ABI fields such as SQE `fd`).
    #[must_use]
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    pub const fn as_i32(self) -> i32 {
        self.0 as i32
    }
}

impl core::fmt::Display for RawFd {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

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

/// Argument for `IORING_REGISTER_FILES_UPDATE`.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct IoUringFilesUpdate {
    pub offset: u32,
    pub resv: u32,
    /// Pointer to the array of fds (as `u64` to match the kernel ABI).
    pub fds: u64,
}

/// Generic resource-update argument (used for `IORING_REGISTER_RING_FDS`).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct IoUringRsrcUpdate {
    /// Slot offset; pass `u32::MAX` to let the kernel pick one.
    pub offset: u32,
    pub resv: u32,
    pub data: u64,
}

/// Argument for `IORING_REGISTER_FILE_ALLOC_RANGE`
/// (`struct io_uring_file_index_range`).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct IoUringFileIndexRange {
    pub off: u32,
    pub len: u32,
    pub resv: u64,
}

/// Argument for `IORING_REGISTER_PBUF_STATUS` (`struct io_uring_buf_status`).
///
/// `buf_group` is the input (which buffer group to query); `head` is the
/// kernel's output, the ring's current consumer head — how far the kernel
/// has advanced into the buffers the application published.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct IoUringBufStatus {
    pub buf_group: u32,
    pub head: u32,
    pub resv: [u32; 8],
}
