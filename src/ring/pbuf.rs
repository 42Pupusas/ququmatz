//! Provided-buffer ring: kernel-registered buffer pool selectable per-SQE.

use super::IoUring;
use crate::error::{Error, InvalidArgKind, SetupError};
use crate::syscall;
use crate::types::{IoUringBuf, IoUringBufReg, MapFlags, Prot, RawFd, RegisterOp};

impl IoUring {
    /// Register a provided-buffer ring for buffer-selectable operations.
    ///
    /// Allocates a pool of `count` buffers of `buf_size` bytes each, along
    /// with a ring of `count` producer entries, and registers the ring
    /// with the kernel under group id `bgid`. Submitting an SQE with
    /// [`Sqe::buffer_select`](crate::op::Sqe::buffer_select) referencing
    /// the same `bgid` tells the kernel to pick one of these buffers for
    /// the operation; the chosen buffer id is returned in the CQE via
    /// [`Completion::buffer_id`](super::Completion::buffer_id).
    ///
    /// All buffers start in the pool. Call
    /// [`ProvidedBufferRing::recycle`] after consuming a buffer to return
    /// it. Dropping the returned ring unregisters it and frees all
    /// memory.
    ///
    /// `count` must be a power of two (kernel ABI requirement) and both
    /// `count` and `buf_size` must be non-zero.
    ///
    /// # Errors
    ///
    /// Returns an error if `count` is not a power of two, if mmap fails,
    /// or if the kernel rejects registration (e.g. `bgid` already in
    /// use, kernel < 5.19).
    #[allow(clippy::cast_possible_truncation)]
    pub fn register_provided_buffers(
        &mut self,
        bgid: u16,
        count: u32,
        buf_size: u32,
    ) -> Result<ProvidedBufferRing, Error> {
        if count == 0 {
            return Err(SetupError::InvalidArg(InvalidArgKind::BufferCountZero).into());
        }
        if buf_size == 0 {
            return Err(SetupError::InvalidArg(InvalidArgKind::BufferSizeZero).into());
        }
        if !count.is_power_of_two() {
            return Err(SetupError::InvalidArg(InvalidArgKind::BufferCountNotPowerOfTwo).into());
        }

        let prot = Prot::READ | Prot::WRITE;
        let map = MapFlags::PRIVATE | MapFlags::ANONYMOUS;

        // Ring of `count` entries, each 16 bytes (sizeof IoUringBuf).
        let ring_bytes = (count as usize) * core::mem::size_of::<IoUringBuf>();
        let ring_addr =
            syscall::mmap(0, ring_bytes, prot, map, usize::MAX, 0).map_err(SetupError::Syscall)?;

        // Backing region for the buffers themselves.
        let bufs_bytes = (count as usize) * (buf_size as usize);
        let bufs_addr = match syscall::mmap(0, bufs_bytes, prot, map, usize::MAX, 0) {
            Ok(a) => a,
            Err(e) => {
                let _ = syscall::munmap(ring_addr, ring_bytes);
                return Err(SetupError::Syscall(e).into());
            }
        };

        let mut reg = IoUringBufReg {
            ring_addr: ring_addr as u64,
            ring_entries: count,
            bgid,
            flags: 0,
            resv: [0; 3],
        };

        if let Err(e) = syscall::io_uring_register(
            self.fd,
            RegisterOp::RegisterPbufRing.into(),
            core::ptr::from_mut(&mut reg) as usize,
            1,
        ) {
            let _ = syscall::munmap(bufs_addr, bufs_bytes);
            let _ = syscall::munmap(ring_addr, ring_bytes);
            return Err(SetupError::Syscall(e).into());
        }

        let mut pbuf = ProvidedBufferRing {
            fd: self.fd,
            bgid,
            mask: count - 1,
            entries: count,
            ring_addr,
            ring_bytes,
            bufs_addr,
            bufs_bytes,
            buf_size,
            tail_local: 0,
        };

        // Pre-populate the ring with all `count` buffers.
        for i in 0..count {
            // SAFETY: each buffer id `i` maps to the i-th slot in the
            // backing region; `bufs_addr + i*buf_size` is valid for
            // `buf_size` bytes.
            let addr = (bufs_addr + (i as usize) * (buf_size as usize)) as u64;
            #[allow(clippy::cast_possible_truncation)]
            pbuf.recycle_raw(addr, buf_size, i as u16);
        }
        pbuf.commit();

        Ok(pbuf)
    }

    /// Unregister a provided-buffer ring by group id.
    ///
    /// Normally you should just drop the [`ProvidedBufferRing`] — its
    /// `Drop` calls this. Use this method only for the rare case where
    /// you need to unregister without freeing the backing memory.
    ///
    /// # Errors
    ///
    /// Returns an error if no ring is registered under `bgid`.
    pub fn unregister_provided_buffers(&mut self, bgid: u16) -> Result<(), Error> {
        let mut reg = IoUringBufReg {
            bgid,
            ..Default::default()
        };
        syscall::io_uring_register(
            self.fd,
            RegisterOp::UnregisterPbufRing.into(),
            core::ptr::from_mut(&mut reg) as usize,
            1,
        )?;
        Ok(())
    }
}

/// A kernel-registered provided-buffer ring.
///
/// Owns the mmap'd producer ring and the backing buffer region for a
/// group of buffers selectable via
/// [`Sqe::buffer_select`](crate::op::Sqe::buffer_select). Dropping this
/// handle unregisters the ring and unmaps its memory.
///
/// # Thread safety
///
/// Like [`IoUring`], this type is `!Send` and `!Sync`. Recycling a
/// buffer from a thread other than the one draining completions would
/// race on `tail_local` and on the kernel-visible tail atomic.
pub struct ProvidedBufferRing {
    fd: RawFd,
    bgid: u16,
    mask: u32,
    entries: u32,
    ring_addr: usize,
    ring_bytes: usize,
    bufs_addr: usize,
    bufs_bytes: usize,
    buf_size: u32,
    /// Cached next producer position; published to the ring's `tail`
    /// slot on [`commit`](Self::commit).
    tail_local: u32,
}

impl ProvidedBufferRing {
    /// Returns the group id this ring is registered under.
    #[must_use]
    pub const fn bgid(&self) -> u16 {
        self.bgid
    }

    /// Returns the number of buffers in the pool.
    #[must_use]
    pub const fn entries(&self) -> u32 {
        self.entries
    }

    /// Returns the size of each buffer in bytes.
    #[must_use]
    pub const fn buf_size(&self) -> u32 {
        self.buf_size
    }

    /// Borrow the contents of a completed buffer.
    ///
    /// `len` should be the CQE `result` (byte count) for the completion
    /// that chose buffer `buf_id`. Returns `None` if `buf_id` is out of
    /// range or `len` exceeds [`buf_size`](Self::buf_size).
    #[must_use]
    pub fn buffer(&self, buf_id: u16, len: u32) -> Option<&[u8]> {
        // SAFETY: `bufs_addr` points to a region of `entries * buf_size`
        // bytes that outlives `self`. The helper bounds-checks `buf_id`
        // and `len` before constructing the slice.
        unsafe {
            buffer_slice(
                self.bufs_addr as *const u8,
                self.entries,
                self.buf_size,
                buf_id,
                len,
            )
        }
    }

    /// Mutably borrow a completed buffer.
    ///
    /// Same bounds as [`buffer`](Self::buffer). The `&mut self` borrow
    /// keeps this race-free with [`recycle`](Self::recycle): you can't
    /// hand the same buffer back to the kernel while still writing to
    /// it.
    #[must_use]
    pub fn buffer_mut(&mut self, buf_id: u16, len: u32) -> Option<&mut [u8]> {
        // SAFETY: same region guarantees as `buffer`, plus `&mut self`
        // which rules out any aliasing `&[u8]` / `&mut [u8]` previously
        // handed out.
        unsafe {
            buffer_slice_mut(
                self.bufs_addr as *mut u8,
                self.entries,
                self.buf_size,
                buf_id,
                len,
            )
        }
    }

    /// Return a buffer to the pool so the kernel can reuse it.
    ///
    /// Call this after you've consumed the bytes the kernel wrote into
    /// the buffer. The recycle does not issue a syscall — it just
    /// appends to the producer ring and, on [`commit`](Self::commit),
    /// publishes the tail with a Release store.
    ///
    /// # Panics
    ///
    /// Panics if `buf_id` is out of range.
    pub fn recycle(&mut self, buf_id: u16) {
        assert!(
            u32::from(buf_id) < self.entries,
            "buf_id out of range for provided-buffer ring"
        );
        let off = (buf_id as usize) * (self.buf_size as usize);
        let addr = (self.bufs_addr + off) as u64;
        self.recycle_raw(addr, self.buf_size, buf_id);
    }

    /// Recycle a buffer and immediately publish the tail.
    pub fn recycle_and_commit(&mut self, buf_id: u16) {
        self.recycle(buf_id);
        self.commit();
    }

    /// Publish all pending recycles to the kernel.
    ///
    /// Writes the local tail to the ring's producer tail slot with a
    /// Release store. Call this after one or more
    /// [`recycle`](Self::recycle) calls before the next
    /// submit / wait cycle.
    pub fn commit(&self) {
        // SAFETY: `tail_ptr` points into the mmap'd ring region, aligned
        // at offset 14 inside entry[0] (a u16). The region is live for
        // the lifetime of `self`.
        let tail_ptr = self.tail_ptr();
        #[allow(clippy::cast_possible_truncation)]
        let tail = self.tail_local as u16;
        unsafe { &*tail_ptr }.store(tail, core::sync::atomic::Ordering::Release);
    }

    /// Internal: write a buf descriptor without touching the `resv`
    /// field that aliases the ring tail in entry 0.
    fn recycle_raw(&mut self, addr: u64, len: u32, bid: u16) {
        let idx = self.tail_local & self.mask;
        // SAFETY: `idx < entries`, so the write stays within the mmap'd
        // ring region. We write fields individually rather than a full
        // `IoUringBuf` struct so that entry 0's `resv` (which aliases
        // the producer `tail` half-word) is not clobbered.
        unsafe {
            let entry = (self.ring_addr as *mut IoUringBuf).add(idx as usize);
            core::ptr::addr_of_mut!((*entry).addr).write(addr);
            core::ptr::addr_of_mut!((*entry).len).write(len);
            core::ptr::addr_of_mut!((*entry).bid).write(bid);
        }
        self.tail_local = self.tail_local.wrapping_add(1);
    }

    /// Pointer to the ring's producer tail (last 2 bytes of entry 0).
    const fn tail_ptr(&self) -> *const core::sync::atomic::AtomicU16 {
        // `tail` lives at offset 14 within `io_uring_buf_ring`, which
        // aliases `bufs[0].resv`.
        const TAIL_OFFSET: usize = 14;
        (self.ring_addr + TAIL_OFFSET) as *const core::sync::atomic::AtomicU16
    }
}

impl Drop for ProvidedBufferRing {
    fn drop(&mut self) {
        let mut reg = IoUringBufReg {
            bgid: self.bgid,
            ..Default::default()
        };
        let _ = syscall::io_uring_register(
            self.fd,
            RegisterOp::UnregisterPbufRing.into(),
            core::ptr::from_mut(&mut reg) as usize,
            1,
        );
        let _ = syscall::munmap(self.bufs_addr, self.bufs_bytes);
        let _ = syscall::munmap(self.ring_addr, self.ring_bytes);
    }
}

/// Slice a buffer out of a contiguous `entries × buf_size` backing
/// region given its id and the kernel-reported byte count.
///
/// # Safety
///
/// `base` must point to at least `entries * buf_size` bytes of memory
/// that remains valid for the returned slice's lifetime, and must not
/// be aliased by another live `&mut [u8]` over the chosen range.
unsafe fn buffer_slice<'a>(
    base: *const u8,
    entries: u32,
    buf_size: u32,
    buf_id: u16,
    len: u32,
) -> Option<&'a [u8]> {
    if u32::from(buf_id) >= entries || len > buf_size {
        return None;
    }
    let off = (buf_id as usize) * (buf_size as usize);
    // SAFETY: caller guarantees `base + entries * buf_size` is in-bounds
    // and the bounds check above keeps `off + len` within that region.
    unsafe { Some(core::slice::from_raw_parts(base.add(off), len as usize)) }
}

/// Mutable counterpart of [`buffer_slice`].
///
/// # Safety
///
/// Same as [`buffer_slice`], plus `base` must not be aliased by any
/// other live reference (shared or exclusive) over the chosen range.
unsafe fn buffer_slice_mut<'a>(
    base: *mut u8,
    entries: u32,
    buf_size: u32,
    buf_id: u16,
    len: u32,
) -> Option<&'a mut [u8]> {
    if u32::from(buf_id) >= entries || len > buf_size {
        return None;
    }
    let off = (buf_id as usize) * (buf_size as usize);
    // SAFETY: see caller safety doc; bounds check keeps us inside the region.
    unsafe { Some(core::slice::from_raw_parts_mut(base.add(off), len as usize)) }
}

#[cfg(test)]
mod buffer_slice_tests {
    //! Tests for [`buffer_slice`] / [`buffer_slice_mut`] — the internal
    //! helpers behind [`ProvidedBufferRing::buffer`] and
    //! [`ProvidedBufferRing::buffer_mut`]. These run on a heap
    //! allocation instead of an mmap region so Miri can check them.
    //!
    //! Miri doesn't support the `mmap` syscall, so the real
    //! `ProvidedBufferRing` can't be exercised under Miri. Factoring
    //! the slice construction out into these helpers lets us verify
    //! the provenance / aliasing / bounds logic — which is where the
    //! actual unsafety lives — under Miri regardless.
    extern crate std;
    use std::{vec, vec::Vec};

    use super::{buffer_slice, buffer_slice_mut};

    const ENTRIES: u32 = 4;
    const BUF_SIZE: u32 = 8;

    fn backing() -> Vec<u8> {
        vec![0u8; (ENTRIES * BUF_SIZE) as usize]
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn round_trip_write_then_read() {
        let mut mem = backing();
        let base = mem.as_mut_ptr();

        // Write distinct patterns into every slot via `buffer_slice_mut`.
        for id in 0..ENTRIES as u16 {
            // SAFETY: `mem` lives for the whole test; no other
            // reference aliases `base` while the returned slice is in
            // use (we drop it before the next iteration).
            let slot =
                unsafe { buffer_slice_mut::<'_>(base, ENTRIES, BUF_SIZE, id, BUF_SIZE) }.unwrap();
            slot.fill(id as u8 + 1);
        }

        // Read them back via the shared variant.
        for id in 0..ENTRIES as u16 {
            // SAFETY: only shared slices are live at once.
            let slot =
                unsafe { buffer_slice::<'_>(base.cast_const(), ENTRIES, BUF_SIZE, id, BUF_SIZE) }
                    .unwrap();
            assert!(slot.iter().all(|&b| b == id as u8 + 1));
        }
    }

    #[test]
    fn partial_len_returns_prefix() {
        let mut mem = backing();
        let base = mem.as_mut_ptr();
        // SAFETY: no aliasing refs live here.
        let slot = unsafe { buffer_slice_mut::<'_>(base, ENTRIES, BUF_SIZE, 2, BUF_SIZE) }.unwrap();
        slot.copy_from_slice(b"ABCDEFGH");

        // CQE reports only 3 bytes were actually filled.
        // SAFETY: prior `&mut` dropped; no aliasing.
        let got =
            unsafe { buffer_slice::<'_>(base.cast_const(), ENTRIES, BUF_SIZE, 2, 3) }.unwrap();
        assert_eq!(got, b"ABC");
        assert_eq!(got.len(), 3);
    }

    #[test]
    fn zero_len_is_empty_slice_not_none() {
        let mut mem = backing();
        let base = mem.as_mut_ptr();
        // SAFETY: no aliasing.
        let slot =
            unsafe { buffer_slice::<'_>(base.cast_const(), ENTRIES, BUF_SIZE, 0, 0) }.unwrap();
        assert!(slot.is_empty());
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn out_of_range_buf_id_returns_none() {
        let mut mem = backing();
        let base = mem.as_mut_ptr();
        // SAFETY: bounds-check rejects before any pointer arithmetic.
        let got =
            unsafe { buffer_slice::<'_>(base.cast_const(), ENTRIES, BUF_SIZE, ENTRIES as u16, 1) };
        assert!(got.is_none());
    }

    #[test]
    fn len_exceeding_buf_size_returns_none() {
        let mut mem = backing();
        let base = mem.as_mut_ptr();
        // SAFETY: bounds-check rejects before any pointer arithmetic.
        let got =
            unsafe { buffer_slice::<'_>(base.cast_const(), ENTRIES, BUF_SIZE, 0, BUF_SIZE + 1) };
        assert!(got.is_none());
    }

    #[test]
    fn adjacent_slots_are_disjoint() {
        // If two mutable borrows of different slots aliased, Miri's
        // Stacked Borrows would flag it. Write to both simultaneously.
        let mut mem = backing();
        let base = mem.as_mut_ptr();
        // SAFETY: buf_ids 0 and 1 occupy disjoint ranges
        // `[0, 8)` and `[8, 16)` of `mem`; the two slices do not alias.
        let a = unsafe { buffer_slice_mut::<'_>(base, ENTRIES, BUF_SIZE, 0, BUF_SIZE) }.unwrap();
        let b = unsafe { buffer_slice_mut::<'_>(base, ENTRIES, BUF_SIZE, 1, BUF_SIZE) }.unwrap();
        a.fill(0xAA);
        b.fill(0xBB);
        assert!(a.iter().all(|&x| x == 0xAA));
        assert!(b.iter().all(|&x| x == 0xBB));
    }
}
