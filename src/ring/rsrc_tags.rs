//! `IoUring::register_*_tagged`/`update_*_tagged` methods: the tagged
//! variants of file and buffer registration (kernel 5.13+).
//!
//! A tagged registration carries one caller-chosen `u64` per slot. Once
//! that slot is replaced (by an update) or its whole table is torn down
//! (by unregistering or dropping the ring) and the kernel is done with
//! whatever it named, a CQE is posted with `user_data` set to the slot's
//! tag and every other field zeroed. A zero tag opts a slot out of this
//! notification. The caller picks these completions up through the same
//! `complete()`/`Completions` path as any other CQE — nothing here
//! changes how completions are drained, only what gets registered.

use super::IoUring;
use crate::error::Error;
use crate::syscall;
use crate::types::{IoUringRsrcRegister, IoUringRsrcUpdate2, IoVec, RegisterOp};

impl IoUring {
    /// Register files for `IOSQE_FIXED_FILE`, tagging each slot with the
    /// matching entry in `tags`.
    ///
    /// `fds` and `tags` must have the same length. A `0` tag disables the
    /// death notification for that one slot; any other value is posted
    /// back as a CQE's `user_data` once that slot's file is replaced or
    /// the table is unregistered and the kernel has released it.
    ///
    /// # Panics
    ///
    /// Panics if `fds.len() != tags.len()`.
    ///
    /// # Errors
    ///
    /// Returns an error if registration fails (e.g. too many files,
    /// already registered).
    #[allow(clippy::cast_possible_truncation)]
    pub fn register_files_tagged(&mut self, fds: &[i32], tags: &[u64]) -> Result<(), Error> {
        assert_eq!(
            fds.len(),
            tags.len(),
            "register_files_tagged: fds and tags must have the same length"
        );
        let arg = IoUringRsrcRegister {
            nr: fds.len() as u32,
            flags: 0,
            resv2: 0,
            data: fds.as_ptr() as u64,
            tags: tags.as_ptr() as u64,
        };
        syscall::io_uring_register(
            self.fd,
            RegisterOp::RegisterFiles2.into(),
            core::ptr::addr_of!(arg) as usize,
            core::mem::size_of::<IoUringRsrcRegister>() as u32,
        )?;
        Ok(())
    }

    /// Update a subset of a tagged file table, starting at `offset`,
    /// tagging each replaced slot with the matching entry in `tags`.
    ///
    /// `fds` and `tags` must have the same length. Use `-1` in `fds` to
    /// clear a slot. See [`register_files_tagged`](Self::register_files_tagged)
    /// for the tag death-notification contract.
    ///
    /// # Panics
    ///
    /// Panics if `fds.len() != tags.len()`.
    ///
    /// # Errors
    ///
    /// Returns an error if no tagged file table is registered or the
    /// range is invalid.
    #[allow(clippy::cast_possible_truncation)]
    pub fn update_registered_files_tagged(
        &mut self,
        fds: &[i32],
        tags: &[u64],
        offset: u32,
    ) -> Result<(), Error> {
        assert_eq!(
            fds.len(),
            tags.len(),
            "update_registered_files_tagged: fds and tags must have the same length"
        );
        let arg = IoUringRsrcUpdate2 {
            offset,
            resv: 0,
            data: fds.as_ptr() as u64,
            tags: tags.as_ptr() as u64,
            nr: fds.len() as u32,
            resv2: 0,
        };
        syscall::io_uring_register(
            self.fd,
            RegisterOp::RegisterFilesUpdate2.into(),
            core::ptr::addr_of!(arg) as usize,
            core::mem::size_of::<IoUringRsrcUpdate2>() as u32,
        )?;
        Ok(())
    }

    /// Register buffers for `read_fixed`/`write_fixed`, tagging each slot
    /// with the matching entry in `tags`.
    ///
    /// `bufs` and `tags` must have the same length. See
    /// [`register_files_tagged`](Self::register_files_tagged) for the tag
    /// death-notification contract.
    ///
    /// # Panics
    ///
    /// Panics if `bufs.len() != tags.len()`.
    ///
    /// # Errors
    ///
    /// Returns an error if registration fails (e.g. too many buffers,
    /// already registered).
    #[allow(clippy::cast_possible_truncation)]
    pub fn register_buffers_tagged(&mut self, bufs: &[IoVec], tags: &[u64]) -> Result<(), Error> {
        assert_eq!(
            bufs.len(),
            tags.len(),
            "register_buffers_tagged: bufs and tags must have the same length"
        );
        let arg = IoUringRsrcRegister {
            nr: bufs.len() as u32,
            flags: 0,
            resv2: 0,
            data: bufs.as_ptr() as u64,
            tags: tags.as_ptr() as u64,
        };
        syscall::io_uring_register(
            self.fd,
            RegisterOp::RegisterBuffers2.into(),
            core::ptr::addr_of!(arg) as usize,
            core::mem::size_of::<IoUringRsrcRegister>() as u32,
        )?;
        Ok(())
    }

    /// Update a subset of a tagged buffer table, starting at `offset`,
    /// tagging each replaced slot with the matching entry in `tags`.
    ///
    /// `bufs` and `tags` must have the same length. See
    /// [`register_files_tagged`](Self::register_files_tagged) for the tag
    /// death-notification contract.
    ///
    /// # Panics
    ///
    /// Panics if `bufs.len() != tags.len()`.
    ///
    /// # Errors
    ///
    /// Returns an error if no tagged buffer table is registered or the
    /// range is invalid.
    #[allow(clippy::cast_possible_truncation)]
    pub fn update_registered_buffers_tagged(
        &mut self,
        bufs: &[IoVec],
        tags: &[u64],
        offset: u32,
    ) -> Result<(), Error> {
        assert_eq!(
            bufs.len(),
            tags.len(),
            "update_registered_buffers_tagged: bufs and tags must have the same length"
        );
        let arg = IoUringRsrcUpdate2 {
            offset,
            resv: 0,
            data: bufs.as_ptr() as u64,
            tags: tags.as_ptr() as u64,
            nr: bufs.len() as u32,
            resv2: 0,
        };
        syscall::io_uring_register(
            self.fd,
            RegisterOp::RegisterBuffersUpdate.into(),
            core::ptr::addr_of!(arg) as usize,
            core::mem::size_of::<IoUringRsrcUpdate2>() as u32,
        )?;
        Ok(())
    }
}
