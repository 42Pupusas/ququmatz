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

/// Create a zeroed SQE. This is a single `const` value that the compiler can
/// inline as an immediate, avoiding a runtime `memset` on every builder call.
const ZEROED: IoUringSqe = unsafe { core::mem::zeroed() };

impl Sqe {
    /// Prepare a no-op operation.
    #[must_use]
    pub fn nop() -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Nop.into();
        Self(sqe)
    }

    /// Prepare a read operation.
    ///
    /// Reads up to `len` bytes from `fd` at `offset` into `buf`.
    /// Use offset `u64::MAX` (`-1` as unsigned) for current file position.
    ///
    /// # Safety
    ///
    /// The caller must ensure `buf` points to at least `len` bytes of valid,
    /// writable memory that remains valid until the operation completes.
    #[must_use]
    pub unsafe fn read(fd: i32, buf: *mut u8, len: u32, offset: u64) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Read.into();
        sqe.fd = fd;
        sqe.addr = buf as u64;
        sqe.len = len;
        sqe.off = offset;
        Self(sqe)
    }

    /// Prepare a write operation.
    ///
    /// Writes `len` bytes from `buf` to `fd` at `offset`.
    /// Use offset `u64::MAX` (`-1` as unsigned) for current file position.
    ///
    /// # Safety
    ///
    /// The caller must ensure `buf` points to at least `len` bytes of valid,
    /// readable memory that remains valid until the operation completes.
    #[must_use]
    pub unsafe fn write(fd: i32, buf: *const u8, len: u32, offset: u64) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Write.into();
        sqe.fd = fd;
        sqe.addr = buf as u64;
        sqe.len = len;
        sqe.off = offset;
        Self(sqe)
    }

    /// Prepare a vectored read operation.
    ///
    /// Reads from `fd` at `offset` into the buffers described by `iovecs`.
    ///
    /// # Safety
    ///
    /// The caller must ensure `iovecs` and all referenced buffers remain valid
    /// until the operation completes.
    #[must_use]
    pub unsafe fn readv(fd: i32, iovecs: *const IoVec, nr_vecs: u32, offset: u64) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Readv.into();
        sqe.fd = fd;
        sqe.addr = iovecs as u64;
        sqe.len = nr_vecs;
        sqe.off = offset;
        Self(sqe)
    }

    /// Prepare a vectored write operation.
    ///
    /// Writes to `fd` at `offset` from the buffers described by `iovecs`.
    ///
    /// # Safety
    ///
    /// The caller must ensure `iovecs` and all referenced buffers remain valid
    /// until the operation completes.
    #[must_use]
    pub unsafe fn writev(fd: i32, iovecs: *const IoVec, nr_vecs: u32, offset: u64) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Writev.into();
        sqe.fd = fd;
        sqe.addr = iovecs as u64;
        sqe.len = nr_vecs;
        sqe.off = offset;
        Self(sqe)
    }

    /// Prepare an `openat` operation.
    ///
    /// Opens a file relative to directory fd `dfd`. Use `AT_FDCWD` for the
    /// current working directory.
    ///
    /// # Safety
    ///
    /// `path` must be a valid, null-terminated C string that remains valid
    /// until the operation completes.
    #[must_use]
    pub unsafe fn openat(dfd: i32, path: *const u8, flags: OpenFlags, mode: u32) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Openat.into();
        sqe.fd = dfd;
        sqe.addr = path as u64;
        sqe.len = mode;
        sqe.op_flags = flags.bits() as u32;
        Self(sqe)
    }

    /// Prepare a close operation on a file descriptor.
    #[must_use]
    pub fn close(fd: i32) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Close.into();
        sqe.fd = fd;
        Self(sqe)
    }

    /// Prepare a fixed-buffer read operation.
    ///
    /// Like `read`, but uses a pre-registered buffer identified by `buf_index`.
    ///
    /// # Safety
    ///
    /// `buf` must point to at least `len` bytes of valid, writable memory
    /// within the registered buffer at `buf_index`, and must remain valid
    /// until the operation completes.
    #[must_use]
    pub unsafe fn read_fixed(fd: i32, buf: *mut u8, len: u32, offset: u64, buf_index: u16) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::ReadFixed.into();
        sqe.fd = fd;
        sqe.addr = buf as u64;
        sqe.len = len;
        sqe.off = offset;
        sqe.buf_index = buf_index;
        Self(sqe)
    }

    /// Prepare a fixed-buffer write operation.
    ///
    /// Like `write`, but uses a pre-registered buffer identified by `buf_index`.
    ///
    /// # Safety
    ///
    /// `buf` must point to at least `len` bytes of valid, readable memory
    /// within the registered buffer at `buf_index`, and must remain valid
    /// until the operation completes.
    #[must_use]
    pub unsafe fn write_fixed(fd: i32, buf: *const u8, len: u32, offset: u64, buf_index: u16) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::WriteFixed.into();
        sqe.fd = fd;
        sqe.addr = buf as u64;
        sqe.len = len;
        sqe.off = offset;
        sqe.buf_index = buf_index;
        Self(sqe)
    }

    /// Prepare a timeout operation.
    ///
    /// Completes when either `count` completions have occurred or the timeout
    /// expires, whichever comes first. Use `count = 0` for a pure timer.
    ///
    /// # Safety
    ///
    /// `ts` must point to a valid `Timespec` that remains valid until the
    /// operation completes.
    #[must_use]
    pub unsafe fn timeout(ts: *const Timespec, count: u32, flags: TimeoutFlags) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Timeout.into();
        sqe.addr = ts as u64;
        sqe.len = 1;
        sqe.off = u64::from(count);
        sqe.op_flags = flags.bits();
        Self(sqe)
    }

    /// Prepare a linked timeout.
    ///
    /// Must be submitted immediately after a linked SQE. If the timeout fires
    /// before the linked operation completes, the linked operation is cancelled.
    ///
    /// # Safety
    ///
    /// `ts` must point to a valid `Timespec` that remains valid until the
    /// operation completes.
    #[must_use]
    pub unsafe fn link_timeout(ts: *const Timespec, flags: TimeoutFlags) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::LinkTimeout.into();
        sqe.addr = ts as u64;
        sqe.len = 1;
        sqe.op_flags = flags.bits();
        Self(sqe)
    }

    /// Prepare a timeout removal.
    ///
    /// Cancels a previously submitted timeout identified by its `user_data`.
    #[must_use]
    pub fn timeout_remove(target_user_data: u64) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::TimeoutRemove.into();
        sqe.addr = target_user_data;
        Self(sqe)
    }

    /// Prepare an async cancellation.
    ///
    /// Cancels a previously submitted operation identified by its `user_data`.
    #[must_use]
    pub fn cancel(target_user_data: u64) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::AsyncCancel.into();
        sqe.addr = target_user_data;
        Self(sqe)
    }

    /// Prepare an fsync operation.
    #[must_use]
    pub fn fsync(fd: i32, flags: FsyncFlags) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Fsync.into();
        sqe.fd = fd;
        sqe.op_flags = flags.bits();
        Self(sqe)
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
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::PollAdd.into();
        sqe.fd = fd;
        sqe.op_flags = mask.bits();
        Self(sqe)
    }

    /// Prepare a poll remove operation.
    ///
    /// Removes a previously added poll request identified by `user_data`.
    #[must_use]
    pub fn poll_remove(target_user_data: u64) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::PollRemove.into();
        sqe.addr = target_user_data;
        Self(sqe)
    }

    /// Prepare a fallocate operation.
    #[must_use]
    #[allow(clippy::cast_sign_loss)]
    pub fn fallocate(fd: i32, mode: FallocateMode, offset: u64, len: u64) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Fallocate.into();
        sqe.fd = fd;
        sqe.off = offset;
        sqe.addr = len;
        sqe.len = mode.bits() as u32;
        Self(sqe)
    }

    /// Prepare a statx operation.
    ///
    /// `dfd` is the directory fd (use `AT_FDCWD` for cwd).
    ///
    /// # Safety
    ///
    /// `path` must be a valid, null-terminated C string and `statx_buf` must
    /// point to a valid `Statx`. Both must remain valid until the operation
    /// completes.
    #[must_use]
    #[allow(clippy::cast_sign_loss)]
    pub unsafe fn statx(
        dfd: i32,
        path: *const u8,
        flags: StatxFlags,
        mask: StatxMask,
        statx_buf: *mut crate::types::Statx,
    ) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Statx.into();
        sqe.fd = dfd;
        sqe.off = statx_buf as u64;
        sqe.addr = path as u64;
        sqe.len = mask.bits();
        sqe.op_flags = flags.bits() as u32;
        Self(sqe)
    }

    /// Prepare a renameat operation.
    ///
    /// # Safety
    ///
    /// `old_path` and `new_path` must be valid, null-terminated C strings
    /// that remain valid until the operation completes.
    #[must_use]
    pub unsafe fn renameat(
        old_dfd: i32,
        old_path: *const u8,
        new_dfd: i32,
        new_path: *const u8,
        flags: RenameFlags,
    ) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Renameat.into();
        sqe.fd = old_dfd;
        sqe.addr = old_path as u64;
        sqe.len = new_dfd as u32;
        sqe.off = new_path as u64;
        sqe.op_flags = flags.bits();
        Self(sqe)
    }

    /// Prepare an unlinkat operation.
    ///
    /// # Safety
    ///
    /// `path` must be a valid, null-terminated C string that remains valid
    /// until the operation completes.
    #[must_use]
    #[allow(clippy::cast_sign_loss)]
    pub unsafe fn unlinkat(dfd: i32, path: *const u8, flags: UnlinkFlags) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Unlinkat.into();
        sqe.fd = dfd;
        sqe.addr = path as u64;
        sqe.op_flags = flags.bits() as u32;
        Self(sqe)
    }

    /// Prepare an accept operation.
    ///
    /// Accepts a connection on a listening socket. `addr` and `addrlen` can be
    /// null/null if you don't need the peer address.
    ///
    /// # Safety
    ///
    /// If non-null, `addr` must point to a buffer large enough for the peer
    /// address and `addrlen` must point to its size. Both must remain valid
    /// until the operation completes.
    #[must_use]
    #[allow(clippy::cast_sign_loss)]
    pub unsafe fn accept(fd: i32, addr: *mut u8, addrlen: *mut u32, flags: AcceptFlags) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Accept.into();
        sqe.fd = fd;
        sqe.addr = addr as u64;
        sqe.off = addrlen as u64;
        sqe.op_flags = flags.bits() as u32;
        Self(sqe)
    }

    /// Prepare a connect operation.
    ///
    /// # Safety
    ///
    /// `addr` must point to a valid socket address of `addrlen` bytes that
    /// remains valid until the operation completes.
    #[must_use]
    pub unsafe fn connect(fd: i32, addr: *const u8, addrlen: u32) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Connect.into();
        sqe.fd = fd;
        sqe.addr = addr as u64;
        sqe.off = u64::from(addrlen);
        Self(sqe)
    }

    /// Prepare a send operation.
    ///
    /// # Safety
    ///
    /// `buf` must point to at least `len` bytes of valid, readable memory
    /// that remains valid until the operation completes.
    #[must_use]
    #[allow(clippy::cast_sign_loss)]
    pub unsafe fn send(fd: i32, buf: *const u8, len: u32, flags: MsgFlags) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Send.into();
        sqe.fd = fd;
        sqe.addr = buf as u64;
        sqe.len = len;
        sqe.op_flags = flags.bits() as u32;
        Self(sqe)
    }

    /// Prepare a recv operation.
    ///
    /// # Safety
    ///
    /// `buf` must point to at least `len` bytes of valid, writable memory
    /// that remains valid until the operation completes.
    #[must_use]
    #[allow(clippy::cast_sign_loss)]
    pub unsafe fn recv(fd: i32, buf: *mut u8, len: u32, flags: MsgFlags) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Recv.into();
        sqe.fd = fd;
        sqe.addr = buf as u64;
        sqe.len = len;
        sqe.op_flags = flags.bits() as u32;
        Self(sqe)
    }

    /// Prepare a sendmsg operation.
    ///
    /// # Safety
    ///
    /// `msg` and all buffers it references must remain valid until the
    /// operation completes.
    #[must_use]
    #[allow(clippy::cast_sign_loss)]
    pub unsafe fn sendmsg(fd: i32, msg: *const MsgHdr, flags: MsgFlags) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::SendMsg.into();
        sqe.fd = fd;
        sqe.addr = msg as u64;
        sqe.len = 1;
        sqe.op_flags = flags.bits() as u32;
        Self(sqe)
    }

    /// Prepare a recvmsg operation.
    ///
    /// # Safety
    ///
    /// `msg` and all buffers it references must remain valid until the
    /// operation completes.
    #[must_use]
    #[allow(clippy::cast_sign_loss)]
    pub unsafe fn recvmsg(fd: i32, msg: *mut MsgHdr, flags: MsgFlags) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::RecvMsg.into();
        sqe.fd = fd;
        sqe.addr = msg as u64;
        sqe.len = 1;
        sqe.op_flags = flags.bits() as u32;
        Self(sqe)
    }

    /// Prepare a socket creation operation.
    #[must_use]
    #[allow(clippy::cast_sign_loss)]
    pub fn socket(domain: i32, sock_type: i32, protocol: i32, flags: u32) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Socket.into();
        sqe.fd = domain;
        sqe.off = sock_type as u64;
        sqe.len = protocol as u32;
        sqe.op_flags = flags;
        Self(sqe)
    }

    /// Prepare a shutdown operation.
    #[must_use]
    pub fn shutdown(fd: i32, how: ShutdownHow) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Shutdown.into();
        sqe.fd = fd;
        sqe.len = how as u32;
        Self(sqe)
    }

    /// Prepare a mkdirat operation.
    ///
    /// # Safety
    ///
    /// `path` must be a valid, null-terminated C string that remains valid
    /// until the operation completes.
    #[must_use]
    pub unsafe fn mkdirat(dfd: i32, path: *const u8, mode: u32) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Mkdirat.into();
        sqe.fd = dfd;
        sqe.addr = path as u64;
        sqe.len = mode;
        Self(sqe)
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

    /// Use a registered/fixed file descriptor for this SQE.
    ///
    /// The `fd` field is interpreted as an index into the registered file table.
    #[must_use]
    pub const fn fixed_file(mut self) -> Self {
        self.0.flags |= SqeFlags::FIXED_FILE.bits();
        self
    }

    /// Drain all prior submissions before executing this SQE.
    #[must_use]
    pub const fn drain(mut self) -> Self {
        self.0.flags |= SqeFlags::IO_DRAIN.bits();
        self
    }
}
