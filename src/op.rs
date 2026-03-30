#![allow(clippy::cast_sign_loss)]

use crate::types::{
    IORING_OP_CLOSE, IORING_OP_NOP, IORING_OP_OPENAT, IORING_OP_READ, IORING_OP_READV,
    IORING_OP_WRITE, IORING_OP_WRITEV, IoUringSqe, IoVec,
};

/// A prepared submission queue entry, ready to be pushed onto the ring.
///
/// Use the constructor methods to create an `Sqe` for a specific operation,
/// then chain modifiers like `user_data()` before pushing.
pub struct Sqe(pub(crate) IoUringSqe);

impl Sqe {
    /// Prepare a no-op operation.
    #[must_use]
    pub fn nop() -> Self {
        Self(IoUringSqe {
            opcode: IORING_OP_NOP,
            ..IoUringSqe::default()
        })
    }

    /// Prepare a read operation.
    ///
    /// Reads up to `len` bytes from `fd` at `offset` into `buf`.
    /// Use offset `u64::MAX` (`-1` as unsigned) for current file position.
    #[must_use]
    pub fn read(fd: i32, buf: *mut u8, len: u32, offset: u64) -> Self {
        Self(IoUringSqe {
            opcode: IORING_OP_READ,
            fd,
            addr: buf as u64,
            len,
            off: offset,
            ..IoUringSqe::default()
        })
    }

    /// Prepare a write operation.
    ///
    /// Writes `len` bytes from `buf` to `fd` at `offset`.
    /// Use offset `u64::MAX` (`-1` as unsigned) for current file position.
    #[must_use]
    pub fn write(fd: i32, buf: *const u8, len: u32, offset: u64) -> Self {
        Self(IoUringSqe {
            opcode: IORING_OP_WRITE,
            fd,
            addr: buf as u64,
            len,
            off: offset,
            ..IoUringSqe::default()
        })
    }

    /// Prepare a vectored read operation.
    ///
    /// Reads from `fd` at `offset` into the buffers described by `iovecs`.
    #[must_use]
    pub fn readv(fd: i32, iovecs: *const IoVec, nr_vecs: u32, offset: u64) -> Self {
        Self(IoUringSqe {
            opcode: IORING_OP_READV,
            fd,
            addr: iovecs as u64,
            len: nr_vecs,
            off: offset,
            ..IoUringSqe::default()
        })
    }

    /// Prepare a vectored write operation.
    ///
    /// Writes to `fd` at `offset` from the buffers described by `iovecs`.
    #[must_use]
    pub fn writev(fd: i32, iovecs: *const IoVec, nr_vecs: u32, offset: u64) -> Self {
        Self(IoUringSqe {
            opcode: IORING_OP_WRITEV,
            fd,
            addr: iovecs as u64,
            len: nr_vecs,
            off: offset,
            ..IoUringSqe::default()
        })
    }

    /// Prepare an `openat` operation.
    ///
    /// Opens a file relative to directory fd `dfd`. Use `AT_FDCWD` for the
    /// current working directory. `path` must be a null-terminated C string.
    #[must_use]
    pub fn openat(dfd: i32, path: *const u8, flags: i32, mode: u32) -> Self {
        Self(IoUringSqe {
            opcode: IORING_OP_OPENAT,
            fd: dfd,
            addr: path as u64,
            len: mode,
            op_flags: flags as u32,
            ..IoUringSqe::default()
        })
    }

    /// Prepare a close operation on a file descriptor.
    #[must_use]
    pub fn close(fd: i32) -> Self {
        Self(IoUringSqe {
            opcode: IORING_OP_CLOSE,
            fd,
            ..IoUringSqe::default()
        })
    }

    /// Set the `user_data` field, used to correlate completions with submissions.
    #[must_use]
    pub const fn user_data(mut self, data: u64) -> Self {
        self.0.user_data = data;
        self
    }

    /// Set SQE flags (e.g., for linked operations).
    #[must_use]
    pub const fn flags(mut self, flags: u8) -> Self {
        self.0.flags = flags;
        self
    }
}
