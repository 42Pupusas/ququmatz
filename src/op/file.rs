//! Filesystem SQEs: read/write (with fixed/vectored variants), open/close,
//! `statx`, rename/unlink/mkdir, `fsync`, `fadvise`/`madvise`, `fallocate`,
//! `splice`/`tee`.

use super::{Sqe, ZEROED};
use crate::types::{
    DirFd, FadviseAdvice, FallocateMode, FileMode, FsyncFlags, IoVec, MadviseAdvice, Opcode,
    OpenFlags, OpenHow, RawFd, RenameFlags, SpliceFlags, Statx, StatxFlags, StatxMask, UnlinkFlags,
};

impl Sqe {
    /// Prepare a close operation on a file descriptor.
    #[must_use]
    pub fn close(fd: RawFd) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Close.into();
        sqe.fd = fd.as_i32();
        Self(sqe)
    }

    /// Prepare an fsync operation.
    #[must_use]
    pub fn fsync(fd: RawFd, flags: FsyncFlags) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Fsync.into();
        sqe.fd = fd.as_i32();
        sqe.op_flags = flags.bits();
        Self(sqe)
    }

    /// Prepare an fdatasync operation (convenience for fsync + DATASYNC flag).
    #[must_use]
    pub fn fdatasync(fd: RawFd) -> Self {
        Self::fsync(fd, FsyncFlags::DATASYNC)
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
    pub fn fallocate(fd: RawFd, mode: FallocateMode, offset: u64, len: u64) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Fallocate.into();
        sqe.fd = fd.as_i32();
        sqe.off = offset;
        sqe.addr = len; // byte length (u64), not an address
        sqe.len = mode.bits(); // mode flags, not a length
        Self(sqe)
    }

    /// Prepare a read operation.
    ///
    /// Reads up to `buf.len()` bytes from `fd` at `offset` into `buf`.
    /// Use offset `u64::MAX` (`-1` as unsigned) for current file position.
    ///
    /// # Safety
    ///
    /// `buf` is borrowed only for this call — the returned `Sqe` stores a
    /// raw pointer derived from it, not the borrow itself. The caller must
    /// ensure the memory `buf` points to remains valid, writable, and
    /// exclusively accessible (no other live reference to it) until the
    /// kernel posts the completion for this operation.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub unsafe fn read(fd: RawFd, buf: &mut [u8], offset: u64) -> Self {
        debug_assert!(buf.len() <= u32::MAX as usize);
        unsafe { Self::read_ptr(fd, buf.as_mut_ptr(), buf.len() as u32, offset) }
    }

    /// Prepare a write operation.
    ///
    /// Writes `buf.len()` bytes from `buf` to `fd` at `offset`.
    /// Use offset `u64::MAX` (`-1` as unsigned) for current file position.
    ///
    /// # Safety
    ///
    /// `buf` is borrowed only for this call — the returned `Sqe` stores a
    /// raw pointer derived from it, not the borrow itself. The caller must
    /// ensure the memory `buf` points to remains valid and readable until
    /// the kernel posts the completion for this operation.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub unsafe fn write(fd: RawFd, buf: &[u8], offset: u64) -> Self {
        debug_assert!(buf.len() <= u32::MAX as usize);
        unsafe { Self::write_ptr(fd, buf.as_ptr(), buf.len() as u32, offset) }
    }

    /// Prepare a vectored read operation.
    ///
    /// Reads from `fd` at `offset` into the buffers described by `iovecs`.
    ///
    /// # Safety
    ///
    /// `iovecs` and every buffer each `IoVec` describes must remain valid,
    /// writable, and exclusively accessible until the kernel posts the
    /// completion for this operation. Borrowing `iovecs` here does not
    /// extend to the resulting `Sqe`.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub unsafe fn readv(fd: RawFd, iovecs: &[IoVec], offset: u64) -> Self {
        debug_assert!(iovecs.len() <= u32::MAX as usize);
        unsafe { Self::readv_ptr(fd, iovecs.as_ptr(), iovecs.len() as u32, offset) }
    }

    /// Prepare a vectored write operation.
    ///
    /// Writes to `fd` at `offset` from the buffers described by `iovecs`.
    ///
    /// # Safety
    ///
    /// `iovecs` and every buffer each `IoVec` describes must remain valid
    /// and readable until the kernel posts the completion for this
    /// operation. Borrowing `iovecs` here does not extend to the resulting
    /// `Sqe`.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub unsafe fn writev(fd: RawFd, iovecs: &[IoVec], offset: u64) -> Self {
        debug_assert!(iovecs.len() <= u32::MAX as usize);
        unsafe { Self::writev_ptr(fd, iovecs.as_ptr(), iovecs.len() as u32, offset) }
    }

    /// Prepare a read operation from raw pointers.
    ///
    /// # Safety
    ///
    /// The caller must ensure `buf` points to at least `len` bytes of valid,
    /// writable memory that remains valid until the operation completes.
    #[must_use]
    pub unsafe fn read_ptr(fd: RawFd, buf: *mut u8, len: u32, offset: u64) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Read.into();
        sqe.fd = fd.as_i32();
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
    pub unsafe fn write_ptr(fd: RawFd, buf: *const u8, len: u32, offset: u64) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Write.into();
        sqe.fd = fd.as_i32();
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
    pub unsafe fn readv_ptr(fd: RawFd, iovecs: *const IoVec, nr_vecs: u32, offset: u64) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Readv.into();
        sqe.fd = fd.as_i32();
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
    pub unsafe fn writev_ptr(fd: RawFd, iovecs: *const IoVec, nr_vecs: u32, offset: u64) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Writev.into();
        sqe.fd = fd.as_i32();
        sqe.addr = iovecs as u64;
        sqe.len = nr_vecs;
        sqe.off = offset;
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
    pub unsafe fn read_fixed(
        fd: RawFd,
        buf: *mut u8,
        len: u32,
        offset: u64,
        buf_index: u16,
    ) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::ReadFixed.into();
        sqe.fd = fd.as_i32();
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
        fd: RawFd,
        buf: *const u8,
        len: u32,
        offset: u64,
        buf_index: u16,
    ) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::WriteFixed.into();
        sqe.fd = fd.as_i32();
        sqe.addr = buf as u64;
        sqe.len = len;
        sqe.off = offset;
        sqe.buf_index = buf_index;
        Self(sqe)
    }

    /// Prepare an `openat` operation.
    ///
    /// Opens a file relative to `dfd`. Use [`DirFd::Cwd`] to resolve the
    /// path relative to the current working directory.
    ///
    /// # Safety
    ///
    /// `path` is borrowed only for this call — the returned `Sqe` stores a
    /// raw pointer derived from it, not the borrow itself. The caller must
    /// ensure the memory `path` points to remains valid until the kernel
    /// posts the completion for this operation.
    #[must_use]
    pub unsafe fn openat(
        dfd: DirFd,
        path: &core::ffi::CStr,
        flags: OpenFlags,
        mode: FileMode,
    ) -> Self {
        unsafe { Self::openat_ptr(dfd.as_raw(), path.as_ptr().cast(), flags, mode) }
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

    /// Prepare an openat2 operation.
    ///
    /// Like `openat` but accepts an [`OpenHow`] struct for extended control
    /// over flags, mode, and path resolution.
    ///
    /// # Safety
    ///
    /// `path` and `how` are borrowed only for this call — the returned
    /// `Sqe` stores raw pointers derived from them, not the borrows
    /// themselves. The caller must ensure both remain valid until the
    /// kernel posts the completion for this operation.
    #[must_use]
    pub unsafe fn openat2(dfd: i32, path: &core::ffi::CStr, how: &OpenHow) -> Self {
        unsafe {
            Self::openat2_ptr(
                dfd,
                path.as_ptr().cast(),
                core::ptr::from_ref(how),
                #[allow(clippy::cast_possible_truncation)]
                {
                    core::mem::size_of::<OpenHow>() as u32
                },
            )
        }
    }

    /// Prepare an openat2 operation from raw pointers.
    ///
    /// # Safety
    ///
    /// `path` must be a valid null-terminated C string and `how` must point
    /// to a valid `OpenHow` of `how_size` bytes. Both must remain valid until
    /// the operation completes.
    #[must_use]
    pub unsafe fn openat2_ptr(
        dfd: i32,
        path: *const u8,
        how: *const OpenHow,
        how_size: u32,
    ) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Openat2.into();
        sqe.fd = dfd;
        sqe.addr = path as u64;
        sqe.off = how as u64;
        sqe.len = how_size;
        Self(sqe)
    }

    /// Prepare a statx operation.
    ///
    /// # Safety
    ///
    /// `path` and `statx_buf` are borrowed only for this call — the
    /// returned `Sqe` stores raw pointers derived from them, not the
    /// borrows themselves. The caller must ensure `path` remains valid and
    /// `statx_buf` remains valid, writable, and exclusively accessible
    /// until the kernel posts the completion for this operation.
    #[must_use]
    pub unsafe fn statx(
        dfd: DirFd,
        path: &core::ffi::CStr,
        flags: StatxFlags,
        mask: StatxMask,
        statx_buf: &mut Statx,
    ) -> Self {
        unsafe {
            Self::statx_ptr(
                dfd.as_raw(),
                path.as_ptr().cast(),
                flags,
                mask,
                core::ptr::from_mut(statx_buf),
            )
        }
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
        statx_buf: *mut Statx,
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

    /// Prepare a renameat operation.
    ///
    /// # Safety
    ///
    /// `old_path` and `new_path` are borrowed only for this call — the
    /// returned `Sqe` stores raw pointers derived from them, not the
    /// borrows themselves. The caller must ensure both remain valid until
    /// the kernel posts the completion for this operation.
    #[must_use]
    pub unsafe fn renameat(
        old_dfd: DirFd,
        old_path: &core::ffi::CStr,
        new_dfd: DirFd,
        new_path: &core::ffi::CStr,
        flags: RenameFlags,
    ) -> Self {
        unsafe {
            Self::renameat_ptr(
                old_dfd.as_raw(),
                old_path.as_ptr().cast(),
                new_dfd.as_raw(),
                new_path.as_ptr().cast(),
                flags,
            )
        }
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

    /// Prepare an unlinkat operation.
    ///
    /// # Safety
    ///
    /// `path` is borrowed only for this call — the returned `Sqe` stores a
    /// raw pointer derived from it, not the borrow itself. The caller must
    /// ensure the memory `path` points to remains valid until the kernel
    /// posts the completion for this operation.
    #[must_use]
    pub unsafe fn unlinkat(dfd: DirFd, path: &core::ffi::CStr, flags: UnlinkFlags) -> Self {
        unsafe { Self::unlinkat_ptr(dfd.as_raw(), path.as_ptr().cast(), flags) }
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

    /// Prepare a mkdirat operation.
    ///
    /// # Safety
    ///
    /// `path` is borrowed only for this call — the returned `Sqe` stores a
    /// raw pointer derived from it, not the borrow itself. The caller must
    /// ensure the memory `path` points to remains valid until the kernel
    /// posts the completion for this operation.
    #[must_use]
    pub unsafe fn mkdirat(dfd: DirFd, path: &core::ffi::CStr, mode: FileMode) -> Self {
        unsafe { Self::mkdirat_ptr(dfd.as_raw(), path.as_ptr().cast(), mode) }
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

    /// Prepare a fadvise operation.
    ///
    /// Advises the kernel about the expected access pattern for the given
    /// byte range `[offset, offset+len)` of `fd`.
    #[must_use]
    pub fn fadvise(fd: RawFd, offset: u64, len: u32, advice: FadviseAdvice) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Fadvise.into();
        sqe.fd = fd.as_i32();
        sqe.off = offset;
        sqe.len = len;
        sqe.op_flags = advice.into();
        Self(sqe)
    }

    /// Prepare a madvise operation.
    ///
    /// Advises the kernel about the expected usage of the memory range
    /// starting at `addr` for `len` bytes.
    ///
    /// # Safety
    ///
    /// `addr` must be page-aligned and the range must be valid mapped memory.
    #[must_use]
    pub unsafe fn madvise(addr: *mut u8, len: u32, advice: MadviseAdvice) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Madvise.into();
        sqe.addr = addr as u64;
        sqe.len = len;
        sqe.op_flags = advice.into();
        Self(sqe)
    }

    /// Prepare a splice operation (zero-copy between two fds).
    ///
    /// `fd_in` is the source; `off_in` is the read offset (`u64::MAX` for current pos).
    /// `fd` (the SQE fd field) is the destination; `off` is the write offset.
    /// Set `SpliceFlags::FD_IN_FIXED` in `flags` if `fd_in` is a registered fd.
    #[must_use]
    pub fn splice(
        fd_out: RawFd,
        off_out: u64,
        fd_in: RawFd,
        off_in: u64,
        len: u32,
        flags: SpliceFlags,
    ) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Splice.into();
        sqe.fd = fd_out.as_i32();
        sqe.off = off_out;
        sqe.splice_fd_in = fd_in.as_i32();
        sqe.addr = off_in;
        sqe.len = len;
        sqe.op_flags = flags.bits();
        Self(sqe)
    }

    /// Prepare a tee operation (duplicate pipe data without consuming it).
    ///
    /// Both `fd_in` and `fd` must be pipe fds.
    #[must_use]
    pub fn tee(fd_out: RawFd, fd_in: RawFd, len: u32, flags: SpliceFlags) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::Tee.into();
        sqe.fd = fd_out.as_i32();
        sqe.splice_fd_in = fd_in.as_i32();
        sqe.len = len;
        sqe.op_flags = flags.bits();
        Self(sqe)
    }
}
