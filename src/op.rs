#![allow(clippy::cast_sign_loss, clippy::checked_conversions)]

use crate::types::{
    AcceptFlags, FallocateMode, FileMode, FsyncFlags, IoUringSqe, IoVec, MsgFlags, MsgHdr, Opcode,
    OpenFlags, PollMask, RenameFlags, ShutdownHow, SocketFlags, SqeFlags, StatxFlags, StatxMask,
    TimeoutFlags, Timespec, UnlinkFlags,
};

/// A prepared submission queue entry, ready to be pushed onto the ring.
///
/// Use the constructor methods to create an `Sqe` for a specific operation,
/// then chain modifiers like `user_data()` before pushing.
///
/// # Safe vs `_ptr` constructors
///
/// Most operations have two constructor variants:
///
/// - **Safe** (e.g. [`read`](Self::read)) — accepts slices, `&CStr`, or
///   references. Prevents length mismatches and null-termination bugs at
///   compile time.
/// - **`_ptr`** (e.g. [`read_ptr`](Self::read_ptr)) — accepts raw pointers.
///   Marked `unsafe`. Use these when you need full control or are working
///   with pre-registered buffers.
///
/// **Lifetime note:** The safe constructors borrow the underlying data *only
/// for the duration of the constructor call* — the resulting `Sqe` stores a
/// raw pointer internally. The caller must ensure the data remains valid
/// until the io\_uring operation completes. The [`IoUring::do_read`] family
/// of methods enforces this automatically by borrowing across the full
/// submit-and-wait cycle.
pub struct Sqe(pub(crate) IoUringSqe);

/// Create a zeroed SQE. All fields are integer primitives, so zero-init is
/// valid. This `const` lets the compiler inline it as an immediate, avoiding
/// a runtime `memset` on every builder call.
const ZEROED: IoUringSqe = unsafe { core::mem::zeroed() };

impl Sqe {
    // -----------------------------------------------------------------
    // Operations that are inherently safe (no pointers)
    // -----------------------------------------------------------------

    /// Prepare a no-op operation.
    #[must_use]
    pub fn nop() -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Nop.into();
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
    ///
    /// # Field mapping
    ///
    /// The kernel's fallocate SQE reuses fields unconventionally:
    /// `sqe.addr` carries the byte length (not an address) because
    /// `sqe.len` is only u32 and fallocate needs a 64-bit length.
    /// `sqe.len` carries the mode flags instead.
    #[must_use]
    pub fn fallocate(fd: i32, mode: FallocateMode, offset: u64, len: u64) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Fallocate.into();
        sqe.fd = fd;
        sqe.off = offset;
        sqe.addr = len; // byte length (u64), not an address
        sqe.len = mode.bits(); // mode flags, not a length
        Self(sqe)
    }

    /// Prepare a socket creation operation.
    ///
    /// `domain` is the address family (e.g., `AF_INET`), `sock_type` is the
    /// socket type (e.g., `SOCK_STREAM`), and `flags` controls socket-level
    /// options like `NONBLOCK` and `CLOEXEC`.
    #[must_use]
    pub fn socket(domain: i32, sock_type: i32, protocol: i32, flags: SocketFlags) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Socket.into();
        sqe.fd = domain;
        sqe.off = sock_type as u64;
        sqe.len = protocol as u32;
        sqe.op_flags = flags.bits();
        Self(sqe)
    }

    /// Prepare a shutdown operation.
    #[must_use]
    pub fn shutdown(fd: i32, how: ShutdownHow) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Shutdown.into();
        sqe.fd = fd;
        sqe.len = how.into();
        Self(sqe)
    }

    // -----------------------------------------------------------------
    // Safe constructors — buffer operations (slices)
    // -----------------------------------------------------------------

    /// Prepare a read operation.
    ///
    /// Reads up to `buf.len()` bytes from `fd` at `offset` into `buf`.
    /// Use offset `u64::MAX` (`-1` as unsigned) for current file position.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn read(fd: i32, buf: &mut [u8], offset: u64) -> Self {
        debug_assert!(buf.len() <= u32::MAX as usize);
        unsafe { Self::read_ptr(fd, buf.as_mut_ptr(), buf.len() as u32, offset) }
    }

    /// Prepare a write operation.
    ///
    /// Writes `buf.len()` bytes from `buf` to `fd` at `offset`.
    /// Use offset `u64::MAX` (`-1` as unsigned) for current file position.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn write(fd: i32, buf: &[u8], offset: u64) -> Self {
        debug_assert!(buf.len() <= u32::MAX as usize);
        unsafe { Self::write_ptr(fd, buf.as_ptr(), buf.len() as u32, offset) }
    }

    /// Prepare a vectored read operation.
    ///
    /// Reads from `fd` at `offset` into the buffers described by `iovecs`.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn readv(fd: i32, iovecs: &[IoVec], offset: u64) -> Self {
        debug_assert!(iovecs.len() <= u32::MAX as usize);
        unsafe { Self::readv_ptr(fd, iovecs.as_ptr(), iovecs.len() as u32, offset) }
    }

    /// Prepare a vectored write operation.
    ///
    /// Writes to `fd` at `offset` from the buffers described by `iovecs`.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn writev(fd: i32, iovecs: &[IoVec], offset: u64) -> Self {
        debug_assert!(iovecs.len() <= u32::MAX as usize);
        unsafe { Self::writev_ptr(fd, iovecs.as_ptr(), iovecs.len() as u32, offset) }
    }

    /// Prepare a send operation.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn send(fd: i32, buf: &[u8], flags: MsgFlags) -> Self {
        debug_assert!(buf.len() <= u32::MAX as usize);
        unsafe { Self::send_ptr(fd, buf.as_ptr(), buf.len() as u32, flags) }
    }

    /// Prepare a recv operation.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn recv(fd: i32, buf: &mut [u8], flags: MsgFlags) -> Self {
        debug_assert!(buf.len() <= u32::MAX as usize);
        unsafe { Self::recv_ptr(fd, buf.as_mut_ptr(), buf.len() as u32, flags) }
    }

    // -----------------------------------------------------------------
    // Safe constructors — path operations (&CStr)
    // -----------------------------------------------------------------

    /// Prepare an `openat` operation.
    ///
    /// Opens a file relative to directory fd `dfd`. Use `AT_FDCWD` for the
    /// current working directory.
    #[must_use]
    pub fn openat(dfd: i32, path: &core::ffi::CStr, flags: OpenFlags, mode: FileMode) -> Self {
        unsafe { Self::openat_ptr(dfd, path.as_ptr().cast(), flags, mode) }
    }

    /// Prepare a statx operation.
    ///
    /// `dfd` is the directory fd (use `AT_FDCWD` for cwd).
    #[must_use]
    pub fn statx(
        dfd: i32,
        path: &core::ffi::CStr,
        flags: StatxFlags,
        mask: StatxMask,
        statx_buf: &mut crate::types::Statx,
    ) -> Self {
        unsafe {
            Self::statx_ptr(
                dfd,
                path.as_ptr().cast(),
                flags,
                mask,
                core::ptr::from_mut(statx_buf),
            )
        }
    }

    /// Prepare a renameat operation.
    #[must_use]
    pub fn renameat(
        old_dfd: i32,
        old_path: &core::ffi::CStr,
        new_dfd: i32,
        new_path: &core::ffi::CStr,
        flags: RenameFlags,
    ) -> Self {
        unsafe {
            Self::renameat_ptr(
                old_dfd,
                old_path.as_ptr().cast(),
                new_dfd,
                new_path.as_ptr().cast(),
                flags,
            )
        }
    }

    /// Prepare an unlinkat operation.
    #[must_use]
    pub fn unlinkat(dfd: i32, path: &core::ffi::CStr, flags: UnlinkFlags) -> Self {
        unsafe { Self::unlinkat_ptr(dfd, path.as_ptr().cast(), flags) }
    }

    /// Prepare a mkdirat operation.
    #[must_use]
    pub fn mkdirat(dfd: i32, path: &core::ffi::CStr, mode: FileMode) -> Self {
        unsafe { Self::mkdirat_ptr(dfd, path.as_ptr().cast(), mode) }
    }

    // -----------------------------------------------------------------
    // Safe constructors — struct references
    // -----------------------------------------------------------------

    /// Prepare a timeout operation.
    ///
    /// Completes when either `count` completions have occurred or the timeout
    /// expires, whichever comes first. Use `count = 0` for a pure timer.
    #[must_use]
    pub fn timeout(ts: &Timespec, count: u32, flags: TimeoutFlags) -> Self {
        unsafe { Self::timeout_ptr(core::ptr::from_ref(ts), count, flags) }
    }

    /// Prepare a linked timeout.
    ///
    /// Must be submitted immediately after a linked SQE. If the timeout fires
    /// before the linked operation completes, the linked operation is cancelled.
    #[must_use]
    pub fn link_timeout(ts: &Timespec, flags: TimeoutFlags) -> Self {
        unsafe { Self::link_timeout_ptr(core::ptr::from_ref(ts), flags) }
    }

    /// Prepare a connect operation.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn connect(fd: i32, addr: &[u8]) -> Self {
        unsafe { Self::connect_ptr(fd, addr.as_ptr(), addr.len() as u32) }
    }

    /// Prepare an accept operation without capturing the peer address.
    ///
    /// For accept with peer address, use [`accept_ptr`](Self::accept_ptr).
    #[must_use]
    pub fn accept(fd: i32, flags: AcceptFlags) -> Self {
        unsafe { Self::accept_ptr(fd, core::ptr::null_mut(), core::ptr::null_mut(), flags) }
    }

    /// Prepare a sendmsg operation.
    #[must_use]
    pub fn sendmsg(fd: i32, msg: &MsgHdr, flags: MsgFlags) -> Self {
        unsafe { Self::sendmsg_ptr(fd, core::ptr::from_ref(msg), flags) }
    }

    /// Prepare a recvmsg operation.
    #[must_use]
    pub fn recvmsg(fd: i32, msg: &mut MsgHdr, flags: MsgFlags) -> Self {
        unsafe { Self::recvmsg_ptr(fd, core::ptr::from_mut(msg), flags) }
    }

    // -----------------------------------------------------------------
    // Unsafe _ptr constructors — raw pointer variants
    // -----------------------------------------------------------------

    /// Prepare a read operation from raw pointers.
    ///
    /// # Safety
    ///
    /// The caller must ensure `buf` points to at least `len` bytes of valid,
    /// writable memory that remains valid until the operation completes.
    #[must_use]
    pub unsafe fn read_ptr(fd: i32, buf: *mut u8, len: u32, offset: u64) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Read.into();
        sqe.fd = fd;
        sqe.addr = buf as u64;
        sqe.len = len;
        sqe.off = offset;
        Self(sqe)
    }

    /// Prepare a write operation from raw pointers.
    ///
    /// # Safety
    ///
    /// The caller must ensure `buf` points to at least `len` bytes of valid,
    /// readable memory that remains valid until the operation completes.
    #[must_use]
    pub unsafe fn write_ptr(fd: i32, buf: *const u8, len: u32, offset: u64) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Write.into();
        sqe.fd = fd;
        sqe.addr = buf as u64;
        sqe.len = len;
        sqe.off = offset;
        Self(sqe)
    }

    /// Prepare a vectored read operation from raw pointers.
    ///
    /// # Safety
    ///
    /// The caller must ensure `iovecs` and all referenced buffers remain valid
    /// until the operation completes.
    #[must_use]
    pub unsafe fn readv_ptr(fd: i32, iovecs: *const IoVec, nr_vecs: u32, offset: u64) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Readv.into();
        sqe.fd = fd;
        sqe.addr = iovecs as u64;
        sqe.len = nr_vecs;
        sqe.off = offset;
        Self(sqe)
    }

    /// Prepare a vectored write operation from raw pointers.
    ///
    /// # Safety
    ///
    /// The caller must ensure `iovecs` and all referenced buffers remain valid
    /// until the operation completes.
    #[must_use]
    pub unsafe fn writev_ptr(fd: i32, iovecs: *const IoVec, nr_vecs: u32, offset: u64) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Writev.into();
        sqe.fd = fd;
        sqe.addr = iovecs as u64;
        sqe.len = nr_vecs;
        sqe.off = offset;
        Self(sqe)
    }

    /// Prepare an `openat` operation from raw pointers.
    ///
    /// # Safety
    ///
    /// `path` must be a valid, null-terminated C string that remains valid
    /// until the operation completes.
    #[must_use]
    pub unsafe fn openat_ptr(dfd: i32, path: *const u8, flags: OpenFlags, mode: FileMode) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Openat.into();
        sqe.fd = dfd;
        sqe.addr = path as u64;
        sqe.len = mode.bits();
        sqe.op_flags = flags.bits();
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
    pub unsafe fn write_fixed(
        fd: i32,
        buf: *const u8,
        len: u32,
        offset: u64,
        buf_index: u16,
    ) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::WriteFixed.into();
        sqe.fd = fd;
        sqe.addr = buf as u64;
        sqe.len = len;
        sqe.off = offset;
        sqe.buf_index = buf_index;
        Self(sqe)
    }

    /// Prepare a timeout operation from a raw pointer.
    ///
    /// # Safety
    ///
    /// `ts` must point to a valid `Timespec` that remains valid until the
    /// operation completes.
    #[must_use]
    pub unsafe fn timeout_ptr(ts: *const Timespec, count: u32, flags: TimeoutFlags) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Timeout.into();
        sqe.addr = ts as u64;
        sqe.len = 1;
        sqe.off = u64::from(count);
        sqe.op_flags = flags.bits();
        Self(sqe)
    }

    /// Prepare a linked timeout from a raw pointer.
    ///
    /// # Safety
    ///
    /// `ts` must point to a valid `Timespec` that remains valid until the
    /// operation completes.
    #[must_use]
    pub unsafe fn link_timeout_ptr(ts: *const Timespec, flags: TimeoutFlags) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::LinkTimeout.into();
        sqe.addr = ts as u64;
        sqe.len = 1;
        sqe.op_flags = flags.bits();
        Self(sqe)
    }

    /// Prepare a statx operation from raw pointers.
    ///
    /// # Safety
    ///
    /// `path` must be a valid, null-terminated C string and `statx_buf` must
    /// point to a valid `Statx`. Both must remain valid until the operation
    /// completes.
    #[must_use]
    pub unsafe fn statx_ptr(
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
        sqe.op_flags = flags.bits();
        Self(sqe)
    }

    /// Prepare a renameat operation from raw pointers.
    ///
    /// # Safety
    ///
    /// `old_path` and `new_path` must be valid, null-terminated C strings
    /// that remain valid until the operation completes.
    #[must_use]
    pub unsafe fn renameat_ptr(
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
        // Kernel reads sqe.len as the new directory fd (reinterpreted as i32).
        sqe.len = new_dfd as u32;
        sqe.off = new_path as u64;
        sqe.op_flags = flags.bits();
        Self(sqe)
    }

    /// Prepare an unlinkat operation from a raw pointer.
    ///
    /// # Safety
    ///
    /// `path` must be a valid, null-terminated C string that remains valid
    /// until the operation completes.
    #[must_use]
    pub unsafe fn unlinkat_ptr(dfd: i32, path: *const u8, flags: UnlinkFlags) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Unlinkat.into();
        sqe.fd = dfd;
        sqe.addr = path as u64;
        sqe.op_flags = flags.bits();
        Self(sqe)
    }

    /// Prepare an accept operation from raw pointers.
    ///
    /// # Safety
    ///
    /// If non-null, `addr` must point to a buffer large enough for the peer
    /// address and `addrlen` must point to its size. Both must remain valid
    /// until the operation completes.
    #[must_use]
    pub unsafe fn accept_ptr(
        fd: i32,
        addr: *mut u8,
        addrlen: *mut u32,
        flags: AcceptFlags,
    ) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Accept.into();
        sqe.fd = fd;
        sqe.addr = addr as u64;
        sqe.off = addrlen as u64;
        sqe.op_flags = flags.bits();
        Self(sqe)
    }

    /// Prepare a connect operation from raw pointers.
    ///
    /// # Safety
    ///
    /// `addr` must point to a valid socket address of `addrlen` bytes that
    /// remains valid until the operation completes.
    #[must_use]
    pub unsafe fn connect_ptr(fd: i32, addr: *const u8, addrlen: u32) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Connect.into();
        sqe.fd = fd;
        sqe.addr = addr as u64;
        sqe.off = u64::from(addrlen);
        Self(sqe)
    }

    /// Prepare a send operation from raw pointers.
    ///
    /// # Safety
    ///
    /// `buf` must point to at least `len` bytes of valid, readable memory
    /// that remains valid until the operation completes.
    #[must_use]
    pub unsafe fn send_ptr(fd: i32, buf: *const u8, len: u32, flags: MsgFlags) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Send.into();
        sqe.fd = fd;
        sqe.addr = buf as u64;
        sqe.len = len;
        sqe.op_flags = flags.bits();
        Self(sqe)
    }

    /// Prepare a recv operation from raw pointers.
    ///
    /// # Safety
    ///
    /// `buf` must point to at least `len` bytes of valid, writable memory
    /// that remains valid until the operation completes.
    #[must_use]
    pub unsafe fn recv_ptr(fd: i32, buf: *mut u8, len: u32, flags: MsgFlags) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Recv.into();
        sqe.fd = fd;
        sqe.addr = buf as u64;
        sqe.len = len;
        sqe.op_flags = flags.bits();
        Self(sqe)
    }

    /// Prepare a sendmsg operation from a raw pointer.
    ///
    /// # Safety
    ///
    /// `msg` and all buffers it references must remain valid until the
    /// operation completes.
    #[must_use]
    pub unsafe fn sendmsg_ptr(fd: i32, msg: *const MsgHdr, flags: MsgFlags) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::SendMsg.into();
        sqe.fd = fd;
        sqe.addr = msg as u64;
        sqe.len = 1;
        sqe.op_flags = flags.bits();
        Self(sqe)
    }

    /// Prepare a recvmsg operation from a raw pointer.
    ///
    /// # Safety
    ///
    /// `msg` and all buffers it references must remain valid until the
    /// operation completes.
    #[must_use]
    pub unsafe fn recvmsg_ptr(fd: i32, msg: *mut MsgHdr, flags: MsgFlags) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::RecvMsg.into();
        sqe.fd = fd;
        sqe.addr = msg as u64;
        sqe.len = 1;
        sqe.op_flags = flags.bits();
        Self(sqe)
    }

    /// Prepare a mkdirat operation from a raw pointer.
    ///
    /// # Safety
    ///
    /// `path` must be a valid, null-terminated C string that remains valid
    /// until the operation completes.
    #[must_use]
    pub unsafe fn mkdirat_ptr(dfd: i32, path: *const u8, mode: FileMode) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Mkdirat.into();
        sqe.fd = dfd;
        sqe.addr = path as u64;
        sqe.len = mode.bits();
        Self(sqe)
    }

    // -----------------------------------------------------------------
    // SQE modifiers (chainable)
    // -----------------------------------------------------------------

    /// Set the `user_data` field, used to correlate completions with submissions.
    #[must_use]
    pub const fn user_data(mut self, data: u64) -> Self {
        self.0.user_data = data;
        self
    }

    /// Add SQE flags (OR'd with any existing flags).
    #[must_use]
    pub const fn flags(mut self, flags: SqeFlags) -> Self {
        self.0.flags |= flags.bits();
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

    /// Select a buffer from a registered provided-buffer ring.
    ///
    /// Sets the `IOSQE_BUFFER_SELECT` flag and stores `group_id` in the
    /// SQE's `buf_group` field (aliased with `buf_index`). On completion
    /// the kernel reports the chosen buffer id in the upper 16 bits of
    /// the CQE flags — use [`Completion::buffer_id`] to decode it.
    ///
    /// Only valid on operations that support buffer selection (notably
    /// `recv`, `read`, `recvmsg`).
    #[must_use]
    pub const fn buffer_select(mut self, group_id: u16) -> Self {
        self.0.flags |= SqeFlags::BUFFER_SELECT.bits();
        self.0.buf_index = group_id;
        self
    }
}
