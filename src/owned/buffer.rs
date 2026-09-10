//! Address-stable owned storage for in-flight operations.

use crate::error::{Error, InvalidArgKind, SetupError};
use crate::syscall;
use crate::types::{MapFlags, Prot};

/// Storage whose bytes keep one address for as long as the owner is alive.
///
/// # Safety
///
/// Implementors must uphold all of the following:
///
/// - [`stable_ptr`](Self::stable_ptr) returns the same address every call,
///   and moving `Self` must not change it. A `[u8; N]` held inline cannot
///   implement this: moving the owner moves the bytes.
/// - The `stable_len` bytes at that address stay allocated and readable
///   until `Self` is dropped, even while `Self` is moved between threads.
/// - `Self` is the sole owner of those bytes. No alias capable of reading
///   or writing them may exist while `Self` is alive, because the kernel
///   may access them concurrently with any Rust code that holds one.
///
/// The in-flight request types keep the owner alive across the kernel's
/// whole access window, so these guarantees are what make the safe
/// submission API sound.
pub unsafe trait StableBuffer {
    /// Address of the first byte. Constant for the owner's whole life.
    fn stable_ptr(&self) -> *const u8;

    /// Number of bytes readable at [`stable_ptr`](Self::stable_ptr).
    fn stable_len(&self) -> usize;
}

/// [`StableBuffer`] whose bytes may also be written by the kernel.
///
/// # Safety
///
/// In addition to [`StableBuffer`]'s contract, `stable_mut_ptr` must return
/// the same address as `stable_ptr` and the bytes must be writable.
pub unsafe trait StableBufferMut: StableBuffer {
    /// Mutable address of the first byte.
    fn stable_mut_ptr(&mut self) -> *mut u8;
}

/// An owned anonymous mmap usable as an in-flight I/O buffer.
///
/// The bytes live in their own mapping rather than inline in the struct, so
/// moving an `MmapBuffer` — including sending it to another thread — moves
/// only the address, never the storage. That is what lets it satisfy
/// [`StableBuffer`] and therefore be handed to the kernel for the duration
/// of an operation.
///
/// This crate is `no_std` and allocator-free, so this type maps its own
/// pages instead of using a heap. Callers who already have a heap can
/// implement [`StableBuffer`] for their own owner instead.
pub struct MmapBuffer {
    addr: usize,
    len: usize,
    mapped: usize,
}

impl MmapBuffer {
    const PAGE: usize = 4096;

    /// Map `len` writable bytes of zeroed anonymous memory.
    ///
    /// The mapping is rounded up to a page boundary; `len` is what
    /// [`len`](Self::len) and the I/O operations use.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidArgKind::BufferSizeZero`] for `len == 0`,
    /// [`InvalidArgKind::BufferRingSizeOverflow`] if page-rounding `len`
    /// overflows `usize`, or the `mmap` errno on failure.
    pub fn with_capacity(len: usize) -> Result<Self, Error> {
        if len == 0 {
            return Err(SetupError::InvalidArg(InvalidArgKind::BufferSizeZero).into());
        }
        let mapped = len
            .checked_next_multiple_of(Self::PAGE)
            .ok_or(SetupError::InvalidArg(
                InvalidArgKind::BufferRingSizeOverflow,
            ))?;
        let addr = syscall::mmap(
            0,
            mapped,
            Prot::READ | Prot::WRITE,
            MapFlags::PRIVATE | MapFlags::ANONYMOUS,
            usize::MAX,
            0,
        )
        .map_err(SetupError::Syscall)?;
        Ok(Self { addr, len, mapped })
    }

    /// Number of usable bytes.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Always `false` — [`with_capacity`](Self::with_capacity) rejects zero.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Borrow the bytes immutably.
    #[must_use]
    pub const fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.addr as *const u8, self.len) }
    }

    /// Borrow the bytes mutably.
    #[must_use]
    pub const fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.addr as *mut u8, self.len) }
    }
}

impl Drop for MmapBuffer {
    fn drop(&mut self) {
        let _ = syscall::munmap(self.addr, self.mapped);
    }
}

// SAFETY: the bytes live in their own mapping, so `addr` is fixed for the
// life of the value and unaffected by moving the struct. `Drop` unmaps
// exactly once, and no other owner of these pages exists.
unsafe impl StableBuffer for MmapBuffer {
    fn stable_ptr(&self) -> *const u8 {
        self.addr as *const u8
    }

    fn stable_len(&self) -> usize {
        self.len
    }
}

// SAFETY: the mapping is PROT_READ | PROT_WRITE and the address matches
// `stable_ptr`.
unsafe impl StableBufferMut for MmapBuffer {
    fn stable_mut_ptr(&mut self) -> *mut u8 {
        self.addr as *mut u8
    }
}

#[cfg(test)]
mod mmap_buffer_tests {
    use super::{MmapBuffer, StableBuffer, StableBufferMut};
    use crate::error::{Error, InvalidArgKind, SetupError};

    #[test]
    fn zero_capacity_is_rejected() {
        assert_eq!(
            MmapBuffer::with_capacity(0).map(|_| ()).unwrap_err(),
            Error::Setup(SetupError::InvalidArg(InvalidArgKind::BufferSizeZero))
        );
    }

    #[test]
    fn round_trip_write_then_read() {
        let mut buf = MmapBuffer::with_capacity(64).expect("map");
        buf.as_mut_slice()[..5].copy_from_slice(b"hello");
        assert_eq!(&buf.as_slice()[..5], b"hello");
    }

    #[test]
    fn fresh_mapping_is_zeroed() {
        let buf = MmapBuffer::with_capacity(128).expect("map");
        assert!(buf.as_slice().iter().all(|&b| b == 0));
    }

    #[test]
    fn len_is_the_requested_length_not_the_page_rounded_one() {
        let buf = MmapBuffer::with_capacity(100).expect("map");
        assert_eq!(buf.len(), 100);
        assert_eq!(buf.as_slice().len(), 100);
        assert_eq!(buf.stable_len(), 100);
    }

    #[test]
    fn sub_page_and_multi_page_sizes_both_map() {
        assert_eq!(MmapBuffer::with_capacity(1).expect("map").len(), 1);
        assert_eq!(MmapBuffer::with_capacity(4097).expect("map").len(), 4097);
    }

    #[test]
    fn address_survives_moving_the_owner() {
        let mut buf = MmapBuffer::with_capacity(32).expect("map");
        let before = buf.stable_ptr();
        buf.as_mut_slice()[0] = 7;

        let moved = buf;
        assert_eq!(moved.stable_ptr(), before);
        assert_eq!(moved.as_slice()[0], 7);
    }

    #[test]
    fn mutable_and_immutable_pointers_agree() {
        let mut buf = MmapBuffer::with_capacity(16).expect("map");
        assert_eq!(buf.stable_ptr().cast_mut(), buf.stable_mut_ptr());
    }

    #[test]
    fn separate_buffers_do_not_alias() {
        let mut a = MmapBuffer::with_capacity(64).expect("map a");
        let mut b = MmapBuffer::with_capacity(64).expect("map b");
        a.as_mut_slice().fill(0xAA);
        b.as_mut_slice().fill(0xBB);
        assert!(a.as_slice().iter().all(|&x| x == 0xAA));
        assert!(b.as_slice().iter().all(|&x| x == 0xBB));
    }
}
