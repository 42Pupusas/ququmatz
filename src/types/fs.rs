//! Filesystem op flags and structs: openat/openat2, statx, rename/unlink,
//! file mode, fsync, fallocate, fadvise/madvise.

use super::buffers::RawFd;

bitflags! {
    /// File open flags for `openat` / `openat2`.
    ///
    /// Note: `O_RDONLY` (0) is not included because it is the *absence* of
    /// `WRONLY` and `RDWR`, not a flag bit. Use `OpenFlags::default()` for
    /// read-only access. `WRONLY` and `RDWR` are mutually exclusive access
    /// modes, not combinable flags.
    pub struct OpenFlags(u32);
    const WRONLY = 1;
    const RDWR = 2;
    const CREAT = 0o100;
    const EXCL = 0o200;
    const TRUNC = 0o1000;
    const APPEND = 0o2000;
    const NONBLOCK = 0o4000;
    const NOFOLLOW = 0o400_000;
    const CLOEXEC = 0o2_000_000;
    const DIRECTORY = 0o200_000;
    const PATH = 0o10_000_000;
    const TMPFILE = 0o20_200_000;
}

/// Sentinel passed to `*at` syscalls meaning "interpret path relative to CWD".
/// Internal — public callers use [`DirFd::Cwd`].
pub const AT_FDCWD: i32 = -100;

/// Directory file descriptor for `*at`-family operations.
///
/// Use [`DirFd::Cwd`] to resolve a path relative to the current working
/// directory, or [`DirFd::Fd`] to anchor it to an open directory fd.
#[derive(Debug, Clone, Copy)]
pub enum DirFd {
    /// Resolve relative to the current working directory.
    Cwd,
    /// Resolve relative to this open directory descriptor.
    Fd(RawFd),
}

impl DirFd {
    /// Return the raw kernel value (`AT_FDCWD` or the wrapped fd).
    #[must_use]
    pub const fn as_raw(self) -> i32 {
        match self {
            Self::Cwd => AT_FDCWD,
            Self::Fd(fd) => fd.as_i32(),
        }
    }
}

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

bitflags! {
    /// Flags for fsync operations.
    pub struct FsyncFlags(u32);
    /// Only sync file data, not metadata (fdatasync behavior).
    const DATASYNC = 1 << 0;
}

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

impl StatxMask {
    /// Construct from an arbitrary raw value, including bits with no
    /// associated named constant.
    ///
    /// Test-only: exercises the reserved-bit rejection in
    /// [`PreparedStatx`](crate::owned::PreparedStatx) against a bit that
    /// cannot be spelled through the named constants, since real callers
    /// only ever OR those together.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn from_raw_for_test(bits: u32) -> Self {
        Self(bits)
    }
}

impl Statx {
    /// Whether the kernel filled every field in `wanted`.
    ///
    /// The kernel may decline a requested field or volunteer an
    /// unrequested one, so this is the only way to know.
    #[must_use]
    pub const fn has(&self, wanted: StatxMask) -> bool {
        self.stx_mask & wanted.bits() == wanted.bits()
    }

    /// File size, or `None` if the kernel did not fill it.
    #[must_use]
    pub const fn size(&self) -> Option<u64> {
        if self.has(StatxMask::SIZE) {
            Some(self.stx_size)
        } else {
            None
        }
    }

    /// File type and mode bits, or `None` if not filled.
    #[must_use]
    pub const fn mode(&self) -> Option<u16> {
        if self.has(StatxMask::MODE) {
            Some(self.stx_mode)
        } else {
            None
        }
    }

    /// Hard link count, or `None` if not filled.
    #[must_use]
    pub const fn nlink(&self) -> Option<u32> {
        if self.has(StatxMask::NLINK) {
            Some(self.stx_nlink)
        } else {
            None
        }
    }

    /// Owning user id, or `None` if not filled.
    #[must_use]
    pub const fn uid(&self) -> Option<u32> {
        if self.has(StatxMask::UID) {
            Some(self.stx_uid)
        } else {
            None
        }
    }

    /// Owning group id, or `None` if not filled.
    #[must_use]
    pub const fn gid(&self) -> Option<u32> {
        if self.has(StatxMask::GID) {
            Some(self.stx_gid)
        } else {
            None
        }
    }

    /// Inode number, or `None` if not filled.
    #[must_use]
    pub const fn ino(&self) -> Option<u64> {
        if self.has(StatxMask::INO) {
            Some(self.stx_ino)
        } else {
            None
        }
    }

    /// Allocated 512-byte blocks, or `None` if not filled.
    #[must_use]
    pub const fn blocks(&self) -> Option<u64> {
        if self.has(StatxMask::BLOCKS) {
            Some(self.stx_blocks)
        } else {
            None
        }
    }

    /// Last modification time, or `None` if not filled.
    #[must_use]
    pub const fn mtime(&self) -> Option<StatxTimestamp> {
        if self.has(StatxMask::MTIME) {
            Some(self.stx_mtime)
        } else {
            None
        }
    }

    /// Last access time, or `None` if not filled.
    #[must_use]
    pub const fn atime(&self) -> Option<StatxTimestamp> {
        if self.has(StatxMask::ATIME) {
            Some(self.stx_atime)
        } else {
            None
        }
    }

    /// Last status change time, or `None` if not filled.
    #[must_use]
    pub const fn ctime(&self) -> Option<StatxTimestamp> {
        if self.has(StatxMask::CTIME) {
            Some(self.stx_ctime)
        } else {
            None
        }
    }
}

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

/// Arguments for `IORING_OP_OPENAT2` (mirrors kernel `struct open_how`).
///
/// Pass to [`Sqe::openat2`](crate::op::Sqe::openat2) / [`Sqe::openat2_ptr`](crate::op::Sqe::openat2_ptr).
/// The `flags` field accepts the same bits as [`OpenFlags`]; `mode` is only
/// meaningful when `flags` includes `OpenFlags::CREAT` or `OpenFlags::TMPFILE`.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct OpenHow {
    /// Open flags (same bits as [`OpenFlags`], but stored as `u64`).
    pub flags: u64,
    /// File mode (only used with `O_CREAT` / `O_TMPFILE`).
    pub mode: u64,
    /// Path resolution restrictions (`RESOLVE_*` constants).
    pub resolve: u64,
}

/// `resolve` field constants for [`OpenHow`].
pub mod resolve {
    /// Block mount-point crossings.
    pub const NO_XDEV: u64 = 0x01;
    /// Block traversal through magic-links (e.g. `/proc/self/fd/*`).
    pub const NO_MAGICLINKS: u64 = 0x02;
    /// Block symlink traversal entirely.
    pub const NO_SYMLINKS: u64 = 0x04;
    /// Treat the path as relative to `dfd` even if it starts with `/`.
    pub const BENEATH: u64 = 0x08;
    /// Require the path to be inside `dfd` (implies `BENEATH`).
    pub const IN_ROOT: u64 = 0x10;
    /// Avoid blocking on slow filesystems (returns `EAGAIN` instead).
    pub const CACHED: u64 = 0x20;
}

/// Advice values for `IORING_OP_FADVISE` (mirrors `posix_fadvise` advice).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FadviseAdvice {
    Normal = 0,
    Random = 1,
    Sequential = 2,
    WillNeed = 3,
    DontNeed = 4,
    NoReuse = 5,
}

impl From<FadviseAdvice> for u32 {
    fn from(a: FadviseAdvice) -> Self {
        a as Self
    }
}

/// Advice values for `IORING_OP_MADVISE` (mirrors `madvise` advice).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MadviseAdvice {
    Normal = 0,
    Random = 1,
    Sequential = 2,
    WillNeed = 3,
    DontNeed = 4,
    Free = 8,
    DontDump = 16,
    DoFork = 11,
    DontFork = 10,
}

impl From<MadviseAdvice> for u32 {
    fn from(a: MadviseAdvice) -> Self {
        a as Self
    }
}
