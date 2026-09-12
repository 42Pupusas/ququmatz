//! Caller-provided ring memory for `SetupFlags::NO_MMAP`.
//!
//! Under this flag the kernel does not allocate the SQ/CQ ring or the SQE
//! array itself — it pins whatever pages the caller already mapped at
//! `params.sq_off.user_addr` (the SQE array) and `params.cq_off.user_addr`
//! (the combined SQ/CQ ring region), confirmed against
//! `io_uring/io_uring.c`'s `io_allocate_scq_urings` and
//! `io_uring/memmap.c`'s `io_region_pin_pages`
//! (`pin_user_pages_fast(reg->user_addr, size, FOLL_WRITE | FOLL_LONGTERM, ...)`).
//! Both regions must exist, be page-aligned, and be at least as large as
//! the kernel's own internal layout (`rings_size` in `io_uring/io_uring.c`)
//! *before* `io_uring_setup` is called — there is no opportunity to resize
//! after the fact, and undersizing risks the pin call reading unrelated
//! mapped memory next door rather than failing cleanly.
//!
//! This module supplies that memory: it predicts the SQ/CQ entry counts the
//! kernel will settle on (mirroring `io_uring_fill_params`'s rounding), then
//! sizes and anonymously mmaps two regions generously -- overestimating
//! rather than replicating the kernel's exact internal offsets bit-for-bit,
//! since a too-large buffer only wastes memory while a too-small one is a
//! kernel-side memory safety hazard.

use super::MappedRegion;
use crate::error::Error;
use crate::syscall;
use crate::types::{IoUringCqe, IoUringParams, IoUringSqe, MapFlags, Prot, SetupFlags};

const PAGE_SIZE: usize = 4096;
const IORING_MAX_ENTRIES: u32 = 32768;
const IORING_MAX_CQ_ENTRIES: u32 = 2 * IORING_MAX_ENTRIES;

/// Conservative stand-in for `sizeof(struct io_rings)` up to (but not
/// including) the trailing `cqes` array -- the kernel's own value is
/// smaller (its header fields total well under this), but this crate has
/// no way to observe the exact number without a kernel this new mapping
/// code cannot yet ask, so it rounds generously up instead of matching it
/// exactly. Doubled again below with a full extra page of slack.
const RINGS_HEADER_SLACK: usize = 128;

/// Predict the SQ/CQ entry counts `io_uring_setup` will settle on for
/// `requested` entries and the given `params`, mirroring
/// `io_uring/io_uring.c`'s `io_uring_fill_params` rounding (clamp to the
/// kernel's max, then round up to a power of two; double for CQ unless
/// `CQSIZE` requests an explicit size).
///
/// Deliberately never fails: any combination this crate's guess gets
/// wrong (e.g. requesting more than the kernel's maximum without `CLAMP`)
/// is something `io_uring_setup` itself rejects moments later, at which
/// point the memory this module allocated is simply unmapped unused --
/// there's no need for a second, duplicate validation path here.
fn predict_entries(requested: u32, params: &IoUringParams) -> (u32, u32) {
    let clamp = SetupFlags::from_raw(params.flags).contains(SetupFlags::CLAMP);

    let mut entries = requested;
    if entries > IORING_MAX_ENTRIES && clamp {
        entries = IORING_MAX_ENTRIES;
    }
    let sq_entries = entries.next_power_of_two();

    let cqsize = SetupFlags::from_raw(params.flags).contains(SetupFlags::CQSIZE);
    let cq_entries = if cqsize && params.cq_entries > 0 {
        let mut cq = params.cq_entries;
        if cq > IORING_MAX_CQ_ENTRIES && clamp {
            cq = IORING_MAX_CQ_ENTRIES;
        }
        cq.next_power_of_two().max(sq_entries)
    } else {
        sq_entries.saturating_mul(2)
    };

    (sq_entries, cq_entries)
}

const fn page_align(len: usize) -> usize {
    len.next_multiple_of(PAGE_SIZE)
}

/// Size the combined SQ/CQ ring region generously: header slack, the CQE
/// array, and the SQ indirection array unless `SetupFlags::NO_SQARRAY` also
/// removes it -- then round up to a whole page and add one more full page
/// of margin.
const fn ring_region_size(sq_entries: u32, cq_entries: u32, has_sq_array: bool) -> usize {
    let mut size = RINGS_HEADER_SLACK * 2;
    size += cq_entries as usize * core::mem::size_of::<IoUringCqe>();
    if has_sq_array {
        size += sq_entries as usize * core::mem::size_of::<u32>();
    }
    page_align(size) + PAGE_SIZE
}

/// Size the SQE array region: a plain, header-free array, so no slack
/// beyond page rounding is needed.
const fn sqes_region_size(sq_entries: u32) -> usize {
    page_align(sq_entries as usize * core::mem::size_of::<IoUringSqe>())
}

fn alloc_anon(len: usize) -> Result<MappedRegion, Error> {
    let addr = syscall::mmap(
        0,
        len,
        Prot::READ | Prot::WRITE,
        MapFlags::PRIVATE | MapFlags::ANONYMOUS,
        usize::MAX,
        0,
    )?;
    Ok(MappedRegion::new(addr, len))
}

/// The two anonymous regions this crate allocates on the caller's behalf
/// for a `SetupFlags::NO_MMAP` ring: the combined SQ/CQ ring region (goes
/// in `params.cq_off.user_addr`) and the SQE array (goes in
/// `params.sq_off.user_addr`) -- the kernel's cross-wired naming, not a
/// mistake in this crate; see `io_allocate_scq_urings`.
pub(super) struct NoMmapRegions {
    pub(super) ring_region: MappedRegion,
    pub(super) sqes_region: MappedRegion,
}

/// Unwinds a [`NoMmapRegions`] allocation if `io_uring_setup` fails before
/// ownership passes to `SetupGuard`/`RingResources`.
///
/// `io_uring_setup` itself never frees this memory on failure -- under
/// `NO_MMAP` the kernel only pins pages the caller already owns, it never
/// allocates them -- so this crate remains responsible for unmapping it
/// until the syscall has actually succeeded.
pub(super) struct NoMmapGuard {
    regions: NoMmapRegions,
}

impl NoMmapGuard {
    /// Allocate both regions for the given entry request and fill their
    /// addresses into `params` before the caller invokes `io_uring_setup`.
    ///
    /// Call [`disarm`](Self::disarm) once `io_uring_setup` has succeeded;
    /// dropping this guard beforehand unmaps both regions, unwinding the
    /// allocation.
    pub(super) fn alloc(entries: u32, params: &mut IoUringParams) -> Result<Self, Error> {
        let has_sq_array = !SetupFlags::from_raw(params.flags).contains(SetupFlags::NO_SQARRAY);
        let (sq_entries, cq_entries) = predict_entries(entries, params);

        let ring_region = alloc_anon(ring_region_size(sq_entries, cq_entries, has_sq_array))?;
        let sqes_region = match alloc_anon(sqes_region_size(sq_entries)) {
            Ok(region) => region,
            Err(err) => {
                let _ = syscall::munmap(ring_region.addr, ring_region.len);
                return Err(err);
            }
        };

        params.cq_off.user_addr = ring_region.addr as u64;
        params.sq_off.user_addr = sqes_region.addr as u64;

        Ok(Self {
            regions: NoMmapRegions {
                ring_region,
                sqes_region,
            },
        })
    }

    /// Take the regions out without running cleanup, for handing off to
    /// `SetupGuard` once `io_uring_setup` has succeeded.
    pub(super) const fn disarm(self) -> NoMmapRegions {
        let regions = MappedRegion::new(self.regions.ring_region.addr, self.regions.ring_region.len);
        let sqes = MappedRegion::new(self.regions.sqes_region.addr, self.regions.sqes_region.len);
        core::mem::forget(self);
        NoMmapRegions {
            ring_region: regions,
            sqes_region: sqes,
        }
    }
}

impl Drop for NoMmapGuard {
    fn drop(&mut self) {
        let _ = syscall::munmap(self.regions.sqes_region.addr, self.regions.sqes_region.len);
        let _ = syscall::munmap(self.regions.ring_region.addr, self.regions.ring_region.len);
    }
}
