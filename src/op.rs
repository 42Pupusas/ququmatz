#![allow(clippy::cast_sign_loss)]

use crate::types::{
    AcceptFlags, FallocateMode, FsyncFlags, IoUringSqe, IoVec, MsgFlags, MsgHdr, Opcode, OpenFlags,
    PollMask, RenameFlags, ShutdownHow, SqeFlags, StatxFlags, StatxMask, TimeoutFlags, Timespec,
    UnlinkFlags,
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
            opcode: Opcode::Nop.into(),
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
            opcode: Opcode::Read.into(),
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
            opcode: Opcode::Write.into(),
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
            opcode: Opcode::Readv.into(),
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
            opcode: Opcode::Writev.into(),
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
    pub fn openat(dfd: i32, path: *const u8, flags: OpenFlags, mode: u32) -> Self {
        Self(IoUringSqe {
            opcode: Opcode::Openat.into(),
            fd: dfd,
            addr: path as u64,
            len: mode,
            op_flags: flags.bits() as u32,
            ..IoUringSqe::default()
        })
    }

    /// Prepare a close operation on a file descriptor.
    #[must_use]
    pub fn close(fd: i32) -> Self {
        Self(IoUringSqe {
            opcode: Opcode::Close.into(),
            fd,
            ..IoUringSqe::default()
        })
    }

    /// Prepare a timeout operation.
    ///
    /// Completes when either `count` completions have occurred or the timeout
    /// expires, whichever comes first. Use `count = 0` for a pure timer.
    #[must_use]
    pub fn timeout(ts: *const Timespec, count: u32, flags: TimeoutFlags) -> Self {
        Self(IoUringSqe {
            opcode: Opcode::Timeout.into(),
            addr: ts as u64,
            len: 1,
            off: u64::from(count),
            op_flags: flags.bits(),
            ..IoUringSqe::default()
        })
    }

    /// Prepare a linked timeout.
    ///
    /// Must be submitted immediately after a linked SQE. If the timeout fires
    /// before the linked operation completes, the linked operation is cancelled.
    #[must_use]
    pub fn link_timeout(ts: *const Timespec, flags: TimeoutFlags) -> Self {
        Self(IoUringSqe {
            opcode: Opcode::LinkTimeout.into(),
            addr: ts as u64,
            len: 1,
            op_flags: flags.bits(),
            ..IoUringSqe::default()
        })
    }

    /// Prepare a timeout removal.
    ///
    /// Cancels a previously submitted timeout identified by its `user_data`.
    #[must_use]
    pub fn timeout_remove(target_user_data: u64) -> Self {
        Self(IoUringSqe {
            opcode: Opcode::TimeoutRemove.into(),
            addr: target_user_data,
            ..IoUringSqe::default()
        })
    }

    /// Prepare an async cancellation.
    ///
    /// Cancels a previously submitted operation identified by its `user_data`.
    #[must_use]
    pub fn cancel(target_user_data: u64) -> Self {
        Self(IoUringSqe {
            opcode: Opcode::AsyncCancel.into(),
            addr: target_user_data,
            ..IoUringSqe::default()
        })
    }

    /// Prepare an fsync operation.
    #[must_use]
    pub fn fsync(fd: i32, flags: FsyncFlags) -> Self {
        Self(IoUringSqe {
            opcode: Opcode::Fsync.into(),
            fd,
            op_flags: flags.bits(),
            ..IoUringSqe::default()
        })
    }

    /// Prepare an fdatasync operation (convenience for fsync + DATASYNC flag).
    #[must_use]
    pub fn fdatasync(fd: i32) -> Self {
        Self::fsync(fd, FsyncFlags::DATASYNC)
    }

    /// Prepare a poll add operation.
    ///
    /// Waits for events matching `mask` on the given fd.
    #[must_use]
    #[allow(clippy::cast_sign_loss)]
    pub fn poll_add(fd: i32, mask: PollMask) -> Self {
        Self(IoUringSqe {
            opcode: Opcode::PollAdd.into(),
            fd,
            // poll_events is stored in the lower 32 bits of op_flags,
            // but io_uring expects it as __poll_t in a specific field.
            // For io_uring, poll32_events goes in op_flags.
            op_flags: mask.bits(),
            ..IoUringSqe::default()
        })
    }

    /// Prepare a poll remove operation.
    ///
    /// Removes a previously added poll request identified by `user_data`.
    #[must_use]
    pub fn poll_remove(target_user_data: u64) -> Self {
        Self(IoUringSqe {
            opcode: Opcode::PollRemove.into(),
            addr: target_user_data,
            ..IoUringSqe::default()
        })
    }

    /// Prepare a fallocate operation.
    #[must_use]
    #[allow(clippy::cast_sign_loss)]
    pub fn fallocate(fd: i32, mode: FallocateMode, offset: u64, len: u64) -> Self {
        Self(IoUringSqe {
            opcode: Opcode::Fallocate.into(),
            fd,
            off: offset,
            addr: len,
            len: mode.bits() as u32,
            ..IoUringSqe::default()
        })
    }

    /// Prepare a statx operation.
    ///
    /// `dfd` is the directory fd (use `AT_FDCWD` for cwd). `path` must be
    /// null-terminated. `statx_buf` is where the result will be written.
    #[must_use]
    #[allow(clippy::cast_sign_loss)]
    pub fn statx(
        dfd: i32,
        path: *const u8,
        flags: StatxFlags,
        mask: StatxMask,
        statx_buf: *mut crate::types::Statx,
    ) -> Self {
        Self(IoUringSqe {
            opcode: Opcode::Statx.into(),
            fd: dfd,
            off: statx_buf as u64,
            addr: path as u64,
            len: mask.bits(),
            op_flags: flags.bits() as u32,
            ..IoUringSqe::default()
        })
    }

    /// Prepare a renameat operation.
    #[must_use]
    pub fn renameat(
        old_dfd: i32,
        old_path: *const u8,
        new_dfd: i32,
        new_path: *const u8,
        flags: RenameFlags,
    ) -> Self {
        Self(IoUringSqe {
            opcode: Opcode::Renameat.into(),
            fd: old_dfd,
            addr: old_path as u64,
            len: new_dfd as u32,
            off: new_path as u64,
            op_flags: flags.bits(),
            ..IoUringSqe::default()
        })
    }

    /// Prepare an unlinkat operation.
    #[must_use]
    #[allow(clippy::cast_sign_loss)]
    pub fn unlinkat(dfd: i32, path: *const u8, flags: UnlinkFlags) -> Self {
        Self(IoUringSqe {
            opcode: Opcode::Unlinkat.into(),
            fd: dfd,
            addr: path as u64,
            op_flags: flags.bits() as u32,
            ..IoUringSqe::default()
        })
    }

    /// Prepare an accept operation.
    ///
    /// Accepts a connection on a listening socket. `addr` and `addrlen` can be
    /// null/null if you don't need the peer address.
    #[must_use]
    #[allow(clippy::cast_sign_loss)]
    pub fn accept(fd: i32, addr: *mut u8, addrlen: *mut u32, flags: AcceptFlags) -> Self {
        Self(IoUringSqe {
            opcode: Opcode::Accept.into(),
            fd,
            addr: addr as u64,
            off: addrlen as u64,
            op_flags: flags.bits() as u32,
            ..IoUringSqe::default()
        })
    }

    /// Prepare a connect operation.
    #[must_use]
    pub fn connect(fd: i32, addr: *const u8, addrlen: u32) -> Self {
        Self(IoUringSqe {
            opcode: Opcode::Connect.into(),
            fd,
            addr: addr as u64,
            off: u64::from(addrlen),
            ..IoUringSqe::default()
        })
    }

    /// Prepare a send operation.
    #[must_use]
    #[allow(clippy::cast_sign_loss)]
    pub fn send(fd: i32, buf: *const u8, len: u32, flags: MsgFlags) -> Self {
        Self(IoUringSqe {
            opcode: Opcode::Send.into(),
            fd,
            addr: buf as u64,
            len,
            op_flags: flags.bits() as u32,
            ..IoUringSqe::default()
        })
    }

    /// Prepare a recv operation.
    #[must_use]
    #[allow(clippy::cast_sign_loss)]
    pub fn recv(fd: i32, buf: *mut u8, len: u32, flags: MsgFlags) -> Self {
        Self(IoUringSqe {
            opcode: Opcode::Recv.into(),
            fd,
            addr: buf as u64,
            len,
            op_flags: flags.bits() as u32,
            ..IoUringSqe::default()
        })
    }

    /// Prepare a sendmsg operation.
    #[must_use]
    #[allow(clippy::cast_sign_loss)]
    pub fn sendmsg(fd: i32, msg: *const MsgHdr, flags: MsgFlags) -> Self {
        Self(IoUringSqe {
            opcode: Opcode::SendMsg.into(),
            fd,
            addr: msg as u64,
            len: 1,
            op_flags: flags.bits() as u32,
            ..IoUringSqe::default()
        })
    }

    /// Prepare a recvmsg operation.
    #[must_use]
    #[allow(clippy::cast_sign_loss)]
    pub fn recvmsg(fd: i32, msg: *mut MsgHdr, flags: MsgFlags) -> Self {
        Self(IoUringSqe {
            opcode: Opcode::RecvMsg.into(),
            fd,
            addr: msg as u64,
            len: 1,
            op_flags: flags.bits() as u32,
            ..IoUringSqe::default()
        })
    }

    /// Prepare a socket creation operation.
    #[must_use]
    #[allow(clippy::cast_sign_loss)]
    pub fn socket(domain: i32, sock_type: i32, protocol: i32, flags: u32) -> Self {
        Self(IoUringSqe {
            opcode: Opcode::Socket.into(),
            fd: domain,
            off: sock_type as u64,
            len: protocol as u32,
            op_flags: flags,
            ..IoUringSqe::default()
        })
    }

    /// Prepare a shutdown operation.
    #[must_use]
    pub fn shutdown(fd: i32, how: ShutdownHow) -> Self {
        Self(IoUringSqe {
            opcode: Opcode::Shutdown.into(),
            fd,
            len: how as u32,
            ..IoUringSqe::default()
        })
    }

    /// Prepare a mkdirat operation.
    #[must_use]
    pub fn mkdirat(dfd: i32, path: *const u8, mode: u32) -> Self {
        Self(IoUringSqe {
            opcode: Opcode::Mkdirat.into(),
            fd: dfd,
            addr: path as u64,
            len: mode,
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
    pub const fn flags(mut self, flags: SqeFlags) -> Self {
        self.0.flags = flags.bits();
        self
    }

    /// Link this SQE to the next one in the submission queue.
    ///
    /// If this operation fails, the linked successor is cancelled.
    #[must_use]
    pub const fn link(mut self) -> Self {
        self.0.flags |= SqeFlags::IO_LINK.bits();
        self
    }

    /// Hard-link this SQE to the next one.
    ///
    /// Like `link()`, but the chain continues executing even if this op fails.
    #[must_use]
    pub const fn hardlink(mut self) -> Self {
        self.0.flags |= SqeFlags::IO_HARDLINK.bits();
        self
    }

    /// Drain all prior submissions before executing this SQE.
    #[must_use]
    pub const fn drain(mut self) -> Self {
        self.0.flags |= SqeFlags::IO_DRAIN.bits();
        self
    }
}
