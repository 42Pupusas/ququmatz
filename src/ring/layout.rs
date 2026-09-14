//! SQ/CQ ring memory layout: sizing, mmap'ing, and pointer parsing.
//!
//! Three steps, one after another, all working from the same
//! kernel-filled `IoUringParams`:
//!
//! 1. [`map_rings`] sizes and `mmap`s the SQ ring, CQ ring, and SQE array
//!    for a freshly set-up ring fd (the ordinary path; `NO_MMAP` bypasses
//!    this entirely and is handled by [`super::no_mmap`] instead).
//! 2. [`parse_sq`] and [`parse_cq`] turn the resulting mapped regions into
//!    the typed atomic/array pointers `IoUring` actually reads and writes.
//!
//! This module owns the layout math and pointer arithmetic; it does not
//! own cleanup on failure (`IoUring::from_params`'s [`super::SetupGuard`]
//! does, via the `guard` parameter [`map_rings`] fills in as it goes) or
//! steady-state resource ownership (`super::RingResources` does, once
//! setup succeeds).

use super::resources::{MappedRegion, SetupGuard};
use crate::error::Error;
use crate::syscall;
use crate::types::{
    Features, IoUringCqe, IoUringParams, IoUringSqe, MapFlags, Prot, RawFd, RingOffset, SetupFlags,
};
use core::sync::atomic::{AtomicU32, Ordering};

/// Compute the byte size of a ring region: a base `offset` (the kernel's
/// position of the trailing array within the ring) plus `count` elements of
/// `elem_size` bytes.
///
/// This is the one audited place where the kernel's `u32` ABI fields are
/// widened to `usize` for size arithmetic. The widening is always lossless:
/// `u32` fits in `usize` on every supported target (`usize` is 32 bits on
/// `arm`, 64 on the rest), so a plain `as usize` cannot truncate. Centralizing
/// it here keeps the size formulas free of inline casts.
#[allow(clippy::cast_possible_truncation)]
const fn ring_bytes(offset: u32, count: u32, elem_size: usize) -> usize {
    offset as usize + count as usize * elem_size
}

/// Map the SQ ring, CQ ring, and SQE array for a freshly set-up ring fd.
///
/// Returns `(sq_ring_ptr, mmap_sz, cq_ring_ptr, cq_ring_region, sqes_ptr, sqes_sz)`.
/// On success the caller owns all three mappings; on error the `guard` cleans them up.
#[allow(clippy::cast_ptr_alignment)]
pub(super) fn map_rings(
    fd: RawFd,
    params: &IoUringParams,
    features: Features,
    setup_flags: u32,
    guard: &mut SetupGuard,
) -> Result<(usize, usize, usize, MappedRegion, usize, usize), Error> {
    let prot = Prot::READ | Prot::WRITE;
    let map = MapFlags::SHARED | MapFlags::POPULATE;

    // Under SetupFlags::NO_SQARRAY the kernel omits the indirection array
    // entirely and reports sq_off.array == 0 (confirmed against
    // io_uring/io_uring.c's rings_size, which leaves sq_array_offset
    // untouched -- effectively 0 -- when the flag is set, and against
    // io_get_sqe, which skips the array lookup outright and indexes
    // sq_sqes directly by the masked head). Adding an array's worth of
    // bytes on top of that offset in this mode would map a region larger
    // than the kernel actually backs -- and the array does not need to be
    // mapped there is nothing to read or write.
    let has_sq_array = !SetupFlags::from_raw(setup_flags).contains(SetupFlags::NO_SQARRAY);
    let sq_ring_sz = if has_sq_array {
        ring_bytes(
            params.sq_off.array,
            params.sq_entries,
            core::mem::size_of::<u32>(),
        )
    } else {
        ring_bytes(params.sq_off.array, 0, core::mem::size_of::<u32>())
    };
    let cq_ring_sz = ring_bytes(
        params.cq_off.cqes,
        params.cq_entries,
        core::mem::size_of::<IoUringCqe>(),
    );

    let single_mmap = features.contains(Features::SINGLE_MMAP);
    let mmap_sz = if single_mmap {
        sq_ring_sz.max(cq_ring_sz)
    } else {
        sq_ring_sz
    };

    // Safety: `addr` 0 lets the kernel pick a fresh range; `fd` is the
    // just-created ring fd and `RingOffset::SqRing` is the offset the
    // kernel documents for mapping its SQ ring, so this maps kernel memory
    // the process does not otherwise reference.
    let sq_ring_ptr = unsafe {
        syscall::mmap(
            0,
            mmap_sz,
            prot,
            map,
            fd.as_usize(),
            RingOffset::SqRing.into(),
        )
    }?;
    guard.sq_ring = MappedRegion::new(sq_ring_ptr, mmap_sz);

    let (cq_ring_ptr, cq_ring_region) = if single_mmap {
        (sq_ring_ptr, MappedRegion::new(0, 0))
    } else {
        // Safety: same reasoning as the SQ-ring mapping above, using the
        // kernel-documented `RingOffset::CqRing` offset.
        let ptr = unsafe {
            syscall::mmap(
                0,
                cq_ring_sz,
                prot,
                map,
                fd.as_usize(),
                RingOffset::CqRing.into(),
            )
        }?;
        guard.cq_ring = MappedRegion::new(ptr, cq_ring_sz);
        (ptr, MappedRegion::new(ptr, cq_ring_sz))
    };

    let sqes_sz = ring_bytes(0, params.sq_entries, core::mem::size_of::<IoUringSqe>());
    // Safety: same reasoning as the SQ-ring mapping above, using the
    // kernel-documented `RingOffset::Sqes` offset.
    let sqes_ptr = unsafe {
        syscall::mmap(
            0,
            sqes_sz,
            prot,
            map,
            fd.as_usize(),
            RingOffset::Sqes.into(),
        )
    }?;
    guard.sqes = MappedRegion::new(sqes_ptr, sqes_sz);

    Ok((
        sq_ring_ptr,
        mmap_sz,
        cq_ring_ptr,
        cq_ring_region,
        sqes_ptr,
        sqes_sz,
    ))
}

/// Parse SQ-side pointers out of the mapped SQ ring region.
///
/// Returns `(sq_head, sq_tail, sq_mask, sq_flags, sqes, sq_tail_local)`.
///
/// `has_sq_array` distinguishes the conventional layout (where the kernel
/// reads `sq_array[tail & mask]` to find which SQE slot to consume) from
/// `SetupFlags::NO_SQARRAY` (where the kernel indexes `sq_sqes` directly by
/// the masked head, confirmed against `io_uring/io_uring.c`'s `io_get_sqe`).
/// When `false`, `sq_off.array` is `0` and does not name a real region to
/// read or write — skip the array entirely rather than aliasing `sq_head`.
///
/// # Safety
///
/// `sq_ring_ptr` must point to a valid SQ ring mmap and `sqes_ptr` to the SQE array mmap,
/// both sized according to `params`. Pointers remain valid for the life of the ring.
#[allow(clippy::cast_ptr_alignment, clippy::type_complexity)]
pub(super) unsafe fn parse_sq(
    sq_ring_ptr: usize,
    sqes_ptr: usize,
    params: &IoUringParams,
    has_sq_array: bool,
) -> (
    *const AtomicU32,
    *const AtomicU32,
    u32,
    *const AtomicU32,
    *mut IoUringSqe,
    u32,
) {
    let base = sq_ring_ptr as *const u8;
    let sq_head = unsafe { base.add(params.sq_off.head as usize) }.cast::<AtomicU32>();
    let sq_tail = unsafe { base.add(params.sq_off.tail as usize) }.cast::<AtomicU32>();
    let sq_mask = unsafe { *base.add(params.sq_off.ring_mask as usize).cast::<u32>() };
    let sq_flags = unsafe { base.add(params.sq_off.flags as usize) }.cast::<AtomicU32>();

    debug_assert!(sq_head.is_aligned(), "sq_head not aligned");
    debug_assert!(sq_tail.is_aligned(), "sq_tail not aligned");
    debug_assert!(sq_flags.is_aligned(), "sq_flags not aligned");

    if has_sq_array {
        let sq_array = unsafe { base.add(params.sq_off.array as usize) } as *mut u32;
        debug_assert!(sq_array.is_aligned(), "sq_array not aligned");

        // Pre-fill sq_array with identity mapping (sq_array[i] = i).
        //
        // The kernel reads sq_array[tail & mask] to find which SQE slot to
        // consume. Because push() always writes sqes[tail & mask] and the
        // identity mapping means sq_array[j] == j for all j < sq_entries,
        // the kernel always picks up the right slot without us ever
        // touching sq_array again.
        //
        // SAFETY: this invariant breaks if push() ever writes to a slot
        // other than (tail & mask), or if SQE reordering is added later.
        for i in 0..params.sq_entries {
            unsafe { sq_array.add(i as usize).write(i) };
        }
    }
    // With NO_SQARRAY there is no array to fill: the kernel reads
    // sq_sqes[cached_sq_head & mask] directly, which is exactly the slot
    // push() already writes to (tail & mask, before advancing tail becomes
    // the kernel's next head) -- the same identity relationship the array
    // fill exists to establish, just without a middleman to populate.

    let sq_tail_local = unsafe { &*sq_tail }.load(Ordering::Acquire);
    let sqes = sqes_ptr as *mut IoUringSqe;

    (sq_head, sq_tail, sq_mask, sq_flags, sqes, sq_tail_local)
}

/// Parse CQ-side pointers out of the mapped CQ ring region.
///
/// Returns `(cq_head, cq_tail, cq_mask, cqes, cq_head_local)`.
///
/// # Safety
///
/// `cq_ring_ptr` must point to a valid CQ ring mmap sized according to `params`.
#[allow(clippy::cast_ptr_alignment, clippy::type_complexity)]
pub(super) unsafe fn parse_cq(
    cq_ring_ptr: usize,
    params: &IoUringParams,
) -> (
    *const AtomicU32,
    *const AtomicU32,
    u32,
    *const IoUringCqe,
    u32,
) {
    let base = cq_ring_ptr as *const u8;
    let cq_head = unsafe { base.add(params.cq_off.head as usize) }.cast::<AtomicU32>();
    let cq_tail = unsafe { base.add(params.cq_off.tail as usize) }.cast::<AtomicU32>();
    let cq_mask = unsafe { *base.add(params.cq_off.ring_mask as usize).cast::<u32>() };
    let cqes = unsafe { base.add(params.cq_off.cqes as usize) }.cast::<IoUringCqe>();

    debug_assert!(cq_head.is_aligned(), "cq_head not aligned");
    debug_assert!(cq_tail.is_aligned(), "cq_tail not aligned");
    debug_assert!(cqes.is_aligned(), "cqes not aligned");

    let cq_head_local = unsafe { &*cq_head }.load(Ordering::Acquire);
    (cq_head, cq_tail, cq_mask, cqes, cq_head_local)
}
