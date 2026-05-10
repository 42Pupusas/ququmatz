//! Buffer-registration SQEs: `provide_buffers`, `remove_buffers`, `files_update`.

use super::{Sqe, ZEROED};
use crate::types::Opcode;

impl Sqe {
    /// Prepare a `provide_buffers` operation (legacy buffer registration, pre-5.19).
    ///
    /// Registers `count` buffers of `buf_size` bytes each, starting at `addr`,
    /// under group id `bgid`. The first buffer gets id `buf_id`.
    ///
    /// # Safety
    ///
    /// `addr` must point to at least `count * buf_size` bytes of valid memory
    /// that remains valid until the buffers are consumed or removed.
    #[must_use]
    #[allow(clippy::similar_names)]
    pub unsafe fn provide_buffers(
        addr: *mut u8,
        buf_size: u32,
        count: u16,
        bgid: u16,
        buf_id: u16,
    ) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::ProvideBuffers.into();
        sqe.fd = i32::from(count);
        sqe.addr = addr as u64;
        sqe.len = buf_size;
        sqe.off = u64::from(buf_id);
        sqe.buf_index = bgid;
        Self(sqe)
    }

    /// Prepare a `remove_buffers` operation (legacy buffer removal, pre-5.19).
    ///
    /// Removes up to `count` buffers from group `bgid`.
    #[must_use]
    pub fn remove_buffers(count: u16, bgid: u16) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::RemoveBuffers.into();
        sqe.fd = i32::from(count);
        sqe.buf_index = bgid;
        Self(sqe)
    }

    /// Prepare a `files_update` operation.
    ///
    /// Updates a slice of the registered file table starting at `offset`
    /// without re-registering the entire table. Each element of `fds` that
    /// is `-1` is interpreted as a slot to clear.
    ///
    /// # Safety
    ///
    /// `fds` must remain valid until the operation completes.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub unsafe fn files_update_ptr(fds: *const i32, nr_fds: u32, offset: u32) -> Self {
        let mut sqe = ZEROED;
        sqe.opcode = Opcode::FilesUpdate.into();
        sqe.addr = fds as u64;
        sqe.len = nr_fds;
        sqe.off = u64::from(offset);
        Self(sqe)
    }

    /// Prepare a `files_update` operation from a slice.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn files_update(fds: &[i32], offset: u32) -> Self {
        debug_assert!(fds.len() <= u32::MAX as usize);
        unsafe { Self::files_update_ptr(fds.as_ptr(), fds.len() as u32, offset) }
    }
}
