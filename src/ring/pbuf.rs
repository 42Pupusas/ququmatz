//! Provided-buffer ring: kernel-registered buffer pool selectable per-SQE.

use super::{IoUring, RingResources, Submitter};
use crate::error::{Error, InvalidArgKind, SetupError};
use crate::syscall;
use crate::types::{
    IoUringBuf, IoUringBufReg, IoUringBufStatus, MapFlags, PbufRingFlags, Prot, RawFd, RecvmsgOut,
    RecvmsgParts, RegisterOp,
};

/// Kernel-enforced limit for `IORING_REGISTER_PBUF_RING`: the ring must be
/// a power of two up to 32768 (2^15) entries.
const MAX_PBUF_RING_ENTRIES: u32 = 1 << 15;

/// Bytes needed for one ledger bit per possible `buf_id`, at the kernel's
/// own maximum ring size. Fixed rather than sized to each pool's actual
/// `entries` so `acknowledge`'s ledger needs no extra mmap, no extra
/// `Drop` cleanup, and no extra constructor failure path -- it is 4 KiB
/// of plain memory embedded in the struct, the same way `tail_local` is
/// a plain field rather than its own allocation.
const LEDGER_BYTES: usize = (MAX_PBUF_RING_ENTRIES as usize) / 8;

/// Compute `count * elem_size` as a `usize`, rejecting overflow rather than
/// wrapping.
///
/// Both inputs are bounded `u32`s (buffer counts and sizes never exceed
/// that in this crate's API), but the product must fit in `usize` to be a
/// valid mmap length — which is not guaranteed on a target where `usize`
/// is narrower than 64 bits. Pure and free of syscalls so it can be unit
/// tested directly against `u32::MAX`-scale inputs regardless of the host
/// architecture's actual pointer width.
///
/// # Errors
///
/// Returns [`InvalidArgKind::BufferRingSizeOverflow`] if the product does
/// not fit in `usize`.
fn checked_ring_bytes(count: u32, elem_size: usize) -> Result<usize, InvalidArgKind> {
    (count as usize)
        .checked_mul(elem_size)
        .ok_or(InvalidArgKind::BufferRingSizeOverflow)
}

/// Allocate, mmap, and register a provided-buffer ring against the ring
/// whose shared resources `resources` points at.
///
/// Shared by [`IoUring::register_provided_buffers`] and
/// [`Submitter::register_provided_buffers`] — registration only needs the
/// ring fd, so both entry points funnel here. See the public wrappers for
/// the argument contract and error conditions.
///
/// `resources` must be a live `RingResources` allocation (i.e. the parent
/// `IoUring`/`Submitter`/`Completer` that owns it, or a share of it, has
/// not yet dropped its last reference). On success the returned pool
/// retains its own share (see [`RingResources::retain`]), which is what
/// keeps the ring fd open and the ring's own mmaps alive for as long as
/// the pool exists — even past the parent ring being dropped — rather
/// than the pool tracking a copy of the fd that can go stale (Q-05: a
/// bare copied fd does not stop the kernel from recycling that fd number
/// for an unrelated open file once the parent ring's own last reference
/// closes it).
#[allow(clippy::cast_possible_truncation)]
fn register_provided_buffers_on(
    resources: *mut RingResources,
    bgid: u16,
    count: u32,
    buf_size: u32,
    flags: PbufRingFlags,
) -> Result<ProvidedBufferRing, Error> {
    // Safety: caller guarantees `resources` is a live allocation.
    let fd = unsafe { RingResources::fd(resources) };
    if count == 0 {
        return Err(SetupError::InvalidArg(InvalidArgKind::BufferCountZero).into());
    }
    if buf_size == 0 {
        return Err(SetupError::InvalidArg(InvalidArgKind::BufferSizeZero).into());
    }
    if !count.is_power_of_two() {
        return Err(SetupError::InvalidArg(InvalidArgKind::BufferCountNotPowerOfTwo).into());
    }
    if count > MAX_PBUF_RING_ENTRIES {
        return Err(SetupError::InvalidArg(InvalidArgKind::BufferCountTooLarge).into());
    }

    let prot = Prot::READ | Prot::WRITE;
    let map = MapFlags::PRIVATE | MapFlags::ANONYMOUS;

    // Ring of `count` entries, each 16 bytes (sizeof IoUringBuf). Checked:
    // on a 32-bit target `count as usize * size_of::<IoUringBuf>()` can
    // overflow `usize` even though `count` itself passed the u32 checks
    // above — catch that before it silently wraps into a too-small mmap
    // request that the ring-entry writes below would then walk past.
    let ring_bytes = checked_ring_bytes(count, core::mem::size_of::<IoUringBuf>())
        .map_err(SetupError::InvalidArg)?;
    // Safety: `addr` 0 and `MapFlags::ANONYMOUS` mean the kernel picks a
    // fresh, unused range; nothing existing can be clobbered.
    let ring_addr = unsafe { syscall::mmap(0, ring_bytes, prot, map, usize::MAX, 0) }
        .map_err(SetupError::Syscall)?;

    // Backing region for the buffers themselves. Same overflow concern as
    // `ring_bytes`, and more reachable here since `buf_size` is a
    // caller-supplied u32 with no upper bound of its own.
    let bufs_bytes = match checked_ring_bytes(count, buf_size as usize) {
        Ok(bytes) => bytes,
        Err(kind) => {
            // Safety: `ring_addr..ring_addr + ring_bytes` is this function's
            // own just-allocated mapping, unmapped exactly once here.
            let _ = unsafe { syscall::munmap(ring_addr, ring_bytes) };
            return Err(SetupError::InvalidArg(kind).into());
        }
    };
    // Safety: `addr` 0 and `MapFlags::ANONYMOUS` mean the kernel picks a
    // fresh, unused range; nothing existing can be clobbered.
    let bufs_addr = match unsafe { syscall::mmap(0, bufs_bytes, prot, map, usize::MAX, 0) } {
        Ok(a) => a,
        Err(e) => {
            // Safety: this function's own just-allocated mapping, unmapped
            // exactly once here.
            let _ = unsafe { syscall::munmap(ring_addr, ring_bytes) };
            return Err(SetupError::Syscall(e).into());
        }
    };

    let mut reg = IoUringBufReg {
        ring_addr: ring_addr as u64,
        ring_entries: count,
        bgid,
        flags: flags.bits(),
        resv: [0; 3],
    };

    // Safety: `reg` is a live local `IoUringBufReg`, and this opcode reads
    // exactly one instance of it.
    if let Err(e) = unsafe {
        syscall::io_uring_register(
            fd,
            RegisterOp::RegisterPbufRing.into(),
            core::ptr::from_mut(&mut reg) as usize,
            1,
        )
    } {
        // Safety: both regions are this function's own just-allocated
        // mappings, each unmapped exactly once here.
        let _ = unsafe { syscall::munmap(bufs_addr, bufs_bytes) };
        let _ = unsafe { syscall::munmap(ring_addr, ring_bytes) };
        return Err(SetupError::Syscall(e).into());
    }

    // Take our own share of the parent ring's resources so the pool's fd
    // and the memory it registers against outlive the parent ring's own
    // handle, rather than the pool tracking a bare copied fd number that
    // the kernel is free to recycle once the parent's last reference
    // closes it (Q-05).
    // Safety: caller guarantees `resources` is a live allocation; this
    // adds one more owner to its refcount.
    unsafe { RingResources::retain(resources) };

    let mut pbuf = ProvidedBufferRing {
        resources,
        fd,
        bgid,
        mask: count - 1,
        entries: count,
        ring_addr,
        ring_bytes,
        bufs_addr,
        bufs_bytes,
        buf_size,
        tail_local: 0,
        delivered: [0; LEDGER_BYTES],
    };

    // Pre-populate the ring with all `count` buffers.
    for i in 0..count {
        // SAFETY: each buffer id `i` maps to the i-th slot in the backing
        // region; `bufs_addr + i*buf_size` is valid for `buf_size` bytes.
        let addr = (bufs_addr + (i as usize) * (buf_size as usize)) as u64;
        pbuf.recycle_raw(addr, buf_size, i as u16);
    }
    pbuf.commit();

    Ok(pbuf)
}

impl Submitter {
    /// Register a provided-buffer ring from the submission half of a split ring.
    ///
    /// [`IoUring::split`](super::IoUring::split) consumes the `IoUring`, so a
    /// pool you want to drive concurrently can't be registered through it.
    /// Registration only needs the ring fd, which the `Submitter` still holds,
    /// so register here, then immediately [`split`](ProvidedBufferRing::split)
    /// the returned pool into a [`BufferConsumer`] and move that to the
    /// completion thread. The `Submitter` itself keeps no handle — it only ever
    /// references the pool by `bgid` via
    /// [`Sqe::buffer_select`](crate::op::Sqe::buffer_select).
    ///
    /// See [`IoUring::register_provided_buffers`] for the argument contract.
    ///
    /// # Errors
    ///
    /// Returns an error if `count` is not a power of two, if mmap fails, or if
    /// the kernel rejects registration.
    pub fn register_provided_buffers(
        &self,
        bgid: u16,
        count: u32,
        buf_size: u32,
    ) -> Result<ProvidedBufferRing, Error> {
        register_provided_buffers_on(
            self.resources,
            bgid,
            count,
            buf_size,
            PbufRingFlags::empty(),
        )
    }

    /// Register a provided-buffer ring that supports incremental buffer
    /// consumption (`IOU_PBUF_RING_INC`, kernel 6.12+).
    ///
    /// See [`IoUring::register_incremental_buffers`] for the argument
    /// contract and how incremental consumption changes the recycle
    /// contract.
    ///
    /// # Errors
    ///
    /// Returns an error if `count` is not a power of two, if mmap fails, or if
    /// the kernel rejects registration (e.g. the running kernel predates
    /// incremental buffer support).
    pub fn register_incremental_buffers(
        &self,
        bgid: u16,
        count: u32,
        buf_size: u32,
    ) -> Result<ProvidedBufferRing, Error> {
        register_provided_buffers_on(self.resources, bgid, count, buf_size, PbufRingFlags::INC)
    }
}

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
    pub fn register_provided_buffers(
        &mut self,
        bgid: u16,
        count: u32,
        buf_size: u32,
    ) -> Result<ProvidedBufferRing, Error> {
        register_provided_buffers_on(
            self.resources,
            bgid,
            count,
            buf_size,
            PbufRingFlags::empty(),
        )
    }

    /// Register a provided-buffer ring that supports incremental buffer
    /// consumption (`IOU_PBUF_RING_INC`, kernel 6.12+).
    ///
    /// Ordinarily a completion that selects a pool buffer consumes the
    /// whole thing — a recv or similar hands back at most `buf_size` bytes,
    /// and once you've read them the id goes straight back to the pool via
    /// [`ProvidedBufferRing::recycle`]. With incremental consumption a
    /// single large buffer can back many completions in turn — each recv
    /// picks up where the last one left off inside the same buffer — which
    /// is useful for streaming protocols where allocating one buffer per
    /// read would be wasteful.
    ///
    /// The contract for recycling changes to match: check
    /// [`CqeFlags::BUF_MORE`](crate::types::CqeFlags::BUF_MORE) on each
    /// completion. While it is set, the kernel still owns the buffer and
    /// will write further data into it on a later completion — do not
    /// recycle. Only call [`ProvidedBufferRing::recycle`] once a
    /// completion for that buffer id arrives *without* that flag,
    /// signalling the kernel is done with it.
    ///
    /// Otherwise identical to [`register_provided_buffers`](Self::register_provided_buffers):
    /// `count` must be a power of two and both `count` and `buf_size` must
    /// be non-zero.
    ///
    /// # Errors
    ///
    /// Returns an error if `count` is not a power of two, if mmap fails, or if
    /// the kernel rejects registration (e.g. the running kernel predates
    /// incremental buffer support).
    pub fn register_incremental_buffers(
        &mut self,
        bgid: u16,
        count: u32,
        buf_size: u32,
    ) -> Result<ProvidedBufferRing, Error> {
        register_provided_buffers_on(self.resources, bgid, count, buf_size, PbufRingFlags::INC)
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
        // Safety: `reg` is a live local `IoUringBufReg`, and this opcode
        // reads exactly one instance of it.
        unsafe {
            syscall::io_uring_register(
                self.fd,
                RegisterOp::UnregisterPbufRing.into(),
                core::ptr::from_mut(&mut reg) as usize,
                1,
            )
        }?;
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
    /// The parent ring's shared resources, retained for as long as this
    /// pool exists.
    ///
    /// A provided-buffer registration is meaningless once the ring fd it
    /// was registered against is closed -- the kernel drops the
    /// registration along with the fd. Earlier this struct carried only
    /// a copied `fd: RawFd`, which kept the pool usable exactly as long
    /// as the *number* stayed valid: nothing stopped the parent
    /// `IoUring`/`Submitter`/`Completer` from dropping its own last
    /// reference, closing that fd, and the kernel recycling the same
    /// number for an unrelated file, all while this pool object looked
    /// perfectly fine to its own caller (Q-05). Holding a `RingResources`
    /// share here instead means the fd close is deferred until this pool
    /// (or its `BufferConsumer` half) is itself dropped, exactly like the
    /// `Submitter`/`Completer` split halves already do.
    resources: *mut RingResources,
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
    /// Per-`buf_id` ledger bit backing [`acknowledge`](Self::acknowledge):
    /// set when a real completion's delivery has been acknowledged and not
    /// yet recycled, cleared by [`recycle`](Self::recycle)/[`recycle_and_commit`](Self::recycle_and_commit).
    /// Unlike [`CompletedBuffer`], this state does not depend on a borrow
    /// staying alive -- it persists across a `mem::forget`'d
    /// `AcknowledgedBuffer` exactly as it persists across an ordinary one,
    /// so `recycle` can reject a double-recycle regardless of how the
    /// caller got there. Ids never explicitly acknowledged read as clear,
    /// which is what keeps every pre-existing `buffer`/`buffer_mut`/`claim`/
    /// `recycle` call site working unchanged -- the ledger only rejects a
    /// `recycle` for an id `acknowledge` marked and nothing has since
    /// cleared, it never rejects a `recycle` the ledger simply has no
    /// opinion about.
    delivered: [u8; LEDGER_BYTES],
}

impl ProvidedBufferRing {
    /// Split off the consumer half so the buffer pool can be driven from the
    /// thread that owns the [`Completer`](super::Completer).
    ///
    /// After [`IoUring::split`](super::IoUring::split), completions — and the
    /// recycling that follows them — happen on the completion thread, but the
    /// buffer ring itself is `!Send` and was created on the now-consumed
    /// `IoUring`. This method hands the whole pool over as a [`BufferConsumer`],
    /// which *is* `Send`: once split, exactly one thread reads bytes out of the
    /// pool and recycles ids back into the producer ring, so the `tail_local`
    /// race the `!Send` bound guards against cannot occur.
    ///
    /// The submission thread needs nothing from the pool — it just pushes
    /// `recv`/`recv_multishot` SQEs carrying
    /// [`buffer_select(bgid)`](crate::op::Sqe::buffer_select). The kernel pulls
    /// a buffer per arrival; the `BufferConsumer` on the other thread reads it
    /// and returns it.
    ///
    /// Ownership of the mmap regions and the kernel registration moves into the
    /// `BufferConsumer`, so dropping *it* (not the original handle) is what
    /// unregisters and frees. `self` is consumed.
    #[must_use]
    pub const fn split(self) -> BufferConsumer {
        // The consumer takes the ring whole. We must not run our own Drop —
        // it would unregister the ring and unmap the very memory the consumer
        // needs — so move `self` in and let `BufferConsumer`'s Drop handle
        // teardown instead.
        BufferConsumer { inner: self }
    }

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

    /// Query the kernel's current consumer head for this buffer group
    /// (`IORING_REGISTER_PBUF_STATUS`, kernel 6.8+).
    ///
    /// The head is how far the kernel has advanced into the buffers this
    /// pool published, mod its entry count — the same value this crate
    /// tracks locally as it recycles buffers, but read straight from the
    /// kernel's side of the ring rather than inferred from completions.
    /// Useful for diagnosing whether the application and kernel agree on
    /// how many buffers are outstanding.
    ///
    /// # Errors
    ///
    /// Returns an error if `bgid` does not name a registered buffer *ring*
    /// (as opposed to a classic linked-list buffer group, which this API
    /// does not support).
    pub fn status(&self) -> Result<u32, Error> {
        let mut arg = IoUringBufStatus {
            buf_group: u32::from(self.bgid),
            head: 0,
            resv: [0; 8],
        };
        // Safety: `arg` is a live local `IoUringBufStatus`, and this opcode
        // reads and writes exactly one instance of it.
        unsafe {
            syscall::io_uring_register(
                self.fd,
                RegisterOp::RegisterPbufStatus.into(),
                core::ptr::addr_of_mut!(arg) as usize,
                1,
            )
        }
        .map_err(SetupError::Syscall)?;
        Ok(arg.head)
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

    /// Parse a buffer delivered by
    /// [`recvmsg_multishot`](crate::op::Sqe::recvmsg_multishot).
    ///
    /// Multishot `recvmsg` prepends a [`RecvmsgOut`] header and fixed-width
    /// name/control regions ahead of the payload; reading the buffer raw (via
    /// [`buffer`](Self::buffer)) would return that header in front of the data.
    /// Pass the chosen `buf_id`, the CQE `result` as `len`, and the
    /// `msg_namelen` / `msg_controllen` from the submitted `MsgHdr` to get back
    /// validated name / control / payload slices. See
    /// [`BufferConsumer::recvmsg_parts`] for the split-side equivalent.
    ///
    /// Returns `None` if `buf_id`/`len` are out of range or the buffer is too
    /// small to be valid.
    #[must_use]
    pub fn recvmsg_parts(
        &self,
        buf_id: u16,
        len: u32,
        msg_namelen: u32,
        msg_controllen: u32,
    ) -> Option<RecvmsgParts<'_>> {
        let buf = self.buffer(buf_id, len)?;
        RecvmsgOut::parse(buf, msg_namelen, msg_controllen)
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

    /// Borrow a completed buffer as a lease that recycles itself exactly
    /// once, rather than a bare `buf_id` the caller must remember to hand
    /// back.
    ///
    /// [`buffer`](Self::buffer)/[`buffer_mut`](Self::buffer_mut)/[`recycle`](Self::recycle)
    /// trust the caller to pass a `buf_id` a completion actually named and
    /// to recycle it exactly once; nothing stops calling `recycle` twice on
    /// the same id, which hands the kernel a buffer it already believes it
    /// owns, or reading a `buf_id` a completion never chose. [`claim`] closes
    /// that gap the same way [`Arrival`](crate::owned::multishot::Arrival)
    /// already does for multishot receive: the returned [`CompletedBuffer`]
    /// holds `self` by exclusive borrow, so no other call into this pool
    /// (including a second `claim`) can happen while it is alive, and its
    /// `Drop` recycles the slot exactly once — there is no path that skips
    /// the recycle or repeats it.
    ///
    /// Pass the CQE `result` (byte count) as `len`. Returns `None` if
    /// `buf_id` is out of range or `len` exceeds
    /// [`buf_size`](Self::buf_size) — the same bounds
    /// [`buffer`](Self::buffer) checks, since a completion that failed
    /// those checks did not hand back a slot this pool actually owns.
    ///
    /// [`claim`]: Self::claim
    #[must_use]
    pub fn claim(&mut self, buf_id: u16, len: u32) -> Option<CompletedBuffer<'_>> {
        if u32::from(buf_id) >= self.entries || len > self.buf_size {
            return None;
        }
        Some(CompletedBuffer {
            pool: self,
            buf_id,
            len,
        })
    }

    /// Record that a real completion delivered `buf_id`, and return a
    /// token that is the only way to recycle it back through this method
    /// pair.
    ///
    /// [`claim`](Self::claim)'s [`CompletedBuffer`] rules out double-recycle
    /// only for as long as its borrow is alive: `mem::forget`ing one skips
    /// the recycle silently (a leak, the documented degrade-safely
    /// behavior every lease in this crate shares), and any call site that
    /// has not adopted `claim` falls straight back to the fully
    /// trust-based `recycle`, which has no memory of which ids a
    /// completion actually named at all. `acknowledge` closes the gap a
    /// borrow cannot: the ledger bit it sets is a plain field on the pool,
    /// not tied to any borrow's lifetime, so it survives a forgotten
    /// token exactly as it survives a dropped one.
    ///
    /// Call this once per real delivery -- the CQE `result` as `len`, same
    /// bounds as [`buffer`](Self::buffer) -- and recycle the id only
    /// through [`recycle_acknowledged`](Self::recycle_acknowledged), passing
    /// the returned [`AcknowledgedBuffer`] back by value. A second
    /// `acknowledge` of the same id before that recycle happens is
    /// rejected: the ledger bit is already set, so there is no way to mint
    /// a second token for a delivery this pool believes is still
    /// outstanding, which is exactly the shape of bug this exists to catch.
    ///
    /// This is opt-in on purpose. An id this method is never called for is
    /// one the ledger has no opinion about, so every existing
    /// `buffer`/`buffer_mut`/`claim`/`recycle` call site -- including the
    /// common "recv into a buffer I don't need to read, recycle straight
    /// from the CQE's `buffer_id()`" pattern -- keeps working unchanged.
    /// `recycle` itself does not consult the ledger at all: mixing
    /// `acknowledge` with the raw `recycle` on the same id (rather than
    /// routing through `recycle_acknowledged`) leaves that id's bit stuck
    /// set, which makes every later `acknowledge` of that id fail loudly
    /// rather than silently permitting a double-recycle -- a caller who
    /// mixes the two APIs gets a stuck slot they can diagnose, not silent
    /// corruption.
    ///
    /// # Errors
    ///
    /// Returns [`AcknowledgeError::OutOfRange`] if `buf_id`/`len` are out
    /// of range (mirrors [`claim`](Self::claim)'s bounds), or
    /// [`AcknowledgeError::AlreadyAcknowledged`] if `buf_id` was already
    /// acknowledged and no [`recycle_acknowledged`](Self::recycle_acknowledged)
    /// has cleared it since.
    pub fn acknowledge(
        &mut self,
        buf_id: u16,
        len: u32,
    ) -> Result<AcknowledgedBuffer, AcknowledgeError> {
        if u32::from(buf_id) >= self.entries || len > self.buf_size {
            return Err(AcknowledgeError::OutOfRange { buf_id, len });
        }
        if self.ledger_get(buf_id) {
            return Err(AcknowledgeError::AlreadyAcknowledged { buf_id });
        }
        self.ledger_set(buf_id, true);
        Ok(AcknowledgedBuffer { buf_id, len })
    }

    /// Read the ledger bit for `buf_id`.
    ///
    /// `buf_id` is always in `0..MAX_PBUF_RING_ENTRIES` by construction --
    /// every caller has already passed it through the same `entries`
    /// bounds check `acknowledge` itself enforces, and `entries` is capped
    /// at `MAX_PBUF_RING_ENTRIES` at registration -- so the index below
    /// never reaches past `delivered`.
    const fn ledger_get(&self, buf_id: u16) -> bool {
        let byte = (buf_id as usize) / 8;
        let bit = (buf_id as usize) % 8;
        self.delivered[byte] & (1 << bit) != 0
    }

    /// Set or clear the ledger bit for `buf_id`. See [`ledger_get`](Self::ledger_get).
    const fn ledger_set(&mut self, buf_id: u16, value: bool) {
        let byte = (buf_id as usize) / 8;
        let bit = (buf_id as usize) % 8;
        if value {
            self.delivered[byte] |= 1 << bit;
        } else {
            self.delivered[byte] &= !(1 << bit);
        }
    }

    /// Read the bytes an [`acknowledge`](Self::acknowledge)d delivery
    /// carries, without recycling it yet.
    ///
    /// Same bounds as [`buffer`](Self::buffer); cannot fail, since `token`
    /// can only exist for an id and length `acknowledge` already validated.
    #[must_use]
    pub fn acknowledged_bytes(&self, token: &AcknowledgedBuffer) -> &[u8] {
        self.buffer(token.buf_id, token.len).unwrap_or(&[])
    }

    /// Recycle an [`acknowledge`](Self::acknowledge)d delivery, consuming
    /// its token and clearing the ledger bit so the same id can be
    /// acknowledged again for its next real delivery.
    ///
    /// Takes `token` by value rather than a bare `buf_id`: there is no
    /// `AcknowledgedBuffer` left afterward to pass to a second call, which
    /// is what rules out recycling the same acknowledged delivery twice
    /// through this path -- the same reasoning
    /// [`CompletedBuffer::recycle_and_commit`](CompletedBuffer::recycle_and_commit)
    /// uses, applied to a token that does not need a live borrow to stay
    /// valid. Takes the token itself rather than a `&AcknowledgedBuffer`:
    /// the value is a spent one-time permission, not data to read, so
    /// nothing calls it by reference.
    #[allow(clippy::needless_pass_by_value)]
    pub fn recycle_acknowledged(&mut self, token: AcknowledgedBuffer) {
        self.ledger_set(token.buf_id, false);
        self.recycle(token.buf_id);
    }

    /// Recycle an acknowledged delivery and immediately publish the tail.
    pub fn recycle_acknowledged_and_commit(&mut self, token: AcknowledgedBuffer) {
        self.recycle_acknowledged(token);
        self.commit();
    }

    /// Return a buffer to the pool so the kernel can reuse it.
    ///
    /// Call this after you've consumed the bytes the kernel wrote into
    /// the buffer. The recycle does not issue a syscall — it just
    /// appends to the producer ring and, on [`commit`](Self::commit),
    /// publishes the tail with a Release store.
    ///
    /// Prefer [`claim`](Self::claim) (or, for a lease that survives being
    /// forgotten, [`acknowledge`](Self::acknowledge)) over calling this
    /// directly: this method trusts the caller not to recycle the same
    /// `buf_id` twice and does not consult the acknowledgment ledger at
    /// all, so it recycles an id exactly as it always has whether or not
    /// that id was ever acknowledged.
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

/// A completed buffer borrowed from a [`ProvidedBufferRing`] until it is
/// read, recycling itself on drop.
///
/// Produced by [`ProvidedBufferRing::claim`]. Exclusively borrows the pool
/// for its whole life, so no other claim, recycle, or raw `buffer`/`recycle`
/// call on the same pool can happen while it is alive — the compiler, not
/// caller discipline, is what rules out reading a slot that has already
/// been handed back to the kernel or recycling one twice. Mirrors
/// [`Arrival`](crate::owned::multishot::Arrival), which solves the same
/// problem for multishot receive specifically; this is the same guard for
/// the plain provided-buffer surface any other operation using
/// [`Sqe::buffer_select`](crate::op::Sqe::buffer_select) draws from.
pub struct CompletedBuffer<'pool> {
    pool: &'pool mut ProvidedBufferRing,
    buf_id: u16,
    len: u32,
}

impl core::fmt::Debug for CompletedBuffer<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CompletedBuffer")
            .field("buffer_id", &self.buf_id)
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl CompletedBuffer<'_> {
    /// The bytes the kernel wrote into this slot.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.pool.buffer(self.buf_id, self.len).unwrap_or(&[])
    }

    /// Mutably borrow this slot's bytes, e.g. to consume them in place
    /// before the lease drops and recycles the slot.
    #[must_use]
    pub fn bytes_mut(&mut self) -> &mut [u8] {
        self.pool
            .buffer_mut(self.buf_id, self.len)
            .unwrap_or(&mut [])
    }

    /// The pool slot this lease occupies.
    #[must_use]
    pub const fn buffer_id(&self) -> u16 {
        self.buf_id
    }

    /// How many bytes the kernel wrote.
    #[must_use]
    pub const fn len(&self) -> u32 {
        self.len
    }

    /// Whether the kernel wrote no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Recycle the slot now instead of waiting for `Drop`, and publish the
    /// tail immediately.
    ///
    /// Equivalent to letting the lease drop except for the timing: useful
    /// when the caller wants the kernel to see the buffer back in the pool
    /// before doing more work in the same scope, rather than only at scope
    /// exit.
    pub fn recycle_and_commit(self) {
        // `drop` runs the recycle; consuming `self` here (rather than
        // exposing a `&mut self` recycle-without-consuming method) is what
        // keeps a second recycle of the same slot unreachable -- there is
        // no `self` left to call it on afterwards.
        drop(self);
    }
}

impl Drop for CompletedBuffer<'_> {
    fn drop(&mut self) {
        // The slot goes back to the kernel exactly once: this is the only
        // place a `CompletedBuffer` ever calls `recycle_and_commit`, and
        // exclusive ownership of `pool` for this lease's whole life is what
        // stops a second lease on the same id existing to recycle it again.
        self.pool.recycle_and_commit(self.buf_id);
    }
}

/// A `buf_id` [`ProvidedBufferRing::acknowledge`] has recorded as
/// currently outstanding, but not yet recycled.
///
/// Unlike [`CompletedBuffer`], this carries no borrow of the pool -- its
/// validity comes from the pool's own ledger bit, a plain field that
/// exists independent of this value's lifetime, not from a live
/// `&mut ProvidedBufferRing`. That is what lets it survive `mem::forget`:
/// forgetting a `CompletedBuffer` silently loses the pool's only memory
/// that a recycle is owed, since nothing else records it, while
/// forgetting an `AcknowledgedBuffer` leaves the ledger bit set exactly
/// as it would have been with the token still in hand -- the pool still
/// knows this id is outstanding, and a second
/// [`acknowledge`](ProvidedBufferRing::acknowledge) of the same id before
/// a [`recycle_acknowledged`](ProvidedBufferRing::recycle_acknowledged)
/// clears it is rejected rather than silently accepted.
///
/// There is deliberately no `Drop` impl. A dropped or forgotten token
/// both leak the recycle in the same way every other in-flight ticket in
/// this crate degrades on abandonment -- the buffer never returns to the
/// pool -- but neither corrupts the producer ring the way a double
/// `recycle` would, and the stuck ledger bit is diagnosable (a later
/// `acknowledge` of that id fails loudly) rather than silent.
#[must_use = "an unrecycled buffer stays reserved in the pool's ledger"]
#[derive(Debug)]
pub struct AcknowledgedBuffer {
    buf_id: u16,
    len: u32,
}

impl AcknowledgedBuffer {
    /// The pool slot this token names.
    #[must_use]
    pub const fn buffer_id(&self) -> u16 {
        self.buf_id
    }

    /// How many bytes the kernel wrote.
    #[must_use]
    pub const fn len(&self) -> u32 {
        self.len
    }

    /// Whether the kernel wrote no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Why [`ProvidedBufferRing::acknowledge`] refused to mint an
/// [`AcknowledgedBuffer`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcknowledgeError {
    /// `buf_id` is outside the pool's entry count, or `len` exceeds
    /// [`ProvidedBufferRing::buf_size`].
    OutOfRange {
        /// The id that was rejected.
        buf_id: u16,
        /// The length that was rejected.
        len: u32,
    },
    /// `buf_id` was already acknowledged and no
    /// [`recycle_acknowledged`](ProvidedBufferRing::recycle_acknowledged)
    /// has cleared it since -- acknowledging the same delivery twice
    /// before it is recycled.
    AlreadyAcknowledged {
        /// The id that was rejected.
        buf_id: u16,
    },
}

impl core::fmt::Display for AcknowledgeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OutOfRange { buf_id, len } => {
                write!(f, "buf_id {buf_id} or len {len} out of range")
            }
            Self::AlreadyAcknowledged { buf_id } => {
                write!(
                    f,
                    "buf_id {buf_id} was already acknowledged and not yet recycled"
                )
            }
        }
    }
}

impl core::error::Error for AcknowledgeError {}

impl Drop for ProvidedBufferRing {
    fn drop(&mut self) {
        let mut reg = IoUringBufReg {
            bgid: self.bgid,
            ..Default::default()
        };
        // Safety: `reg` is a live local `IoUringBufReg`, and this opcode
        // reads exactly one instance of it.
        let _ = unsafe {
            syscall::io_uring_register(
                self.fd,
                RegisterOp::UnregisterPbufRing.into(),
                core::ptr::from_mut(&mut reg) as usize,
                1,
            )
        };
        // Safety: both regions are this value's own mappings from
        // registration, each unmapped exactly once here.
        let _ = unsafe { syscall::munmap(self.bufs_addr, self.bufs_bytes) };
        let _ = unsafe { syscall::munmap(self.ring_addr, self.ring_bytes) };
        // Release this pool's share of the parent ring's resources,
        // acquired in `register_provided_buffers_on`. The ring fd (and,
        // if this was the last share, the parent's own mmaps) is only
        // actually closed/unmapped once every share -- the parent ring
        // and every pool registered against it -- has dropped.
        // Safety: this pool retained exactly one share at construction
        // and has not released it before now.
        unsafe { RingResources::release(self.resources) };
    }
}

/// The `Send` consumer half of a [`ProvidedBufferRing`], produced by
/// [`ProvidedBufferRing::split`].
///
/// Lives on the thread that owns the [`Completer`](super::Completer). Reading a
/// completed buffer ([`buffer`](Self::buffer)) and returning it to the kernel
/// ([`recycle`](Self::recycle)) both happen here, against the pinned mmap that
/// backs the pool — so there is no per-operation buffer lifetime for the caller
/// to track. The buffer simply lives in the pool until you recycle its id.
///
/// # Thread safety
///
/// Unlike [`ProvidedBufferRing`], this *is* `Send`: after the split a single
/// thread owns the producer ring's `tail_local`, so the race that makes the
/// un-split handle `!Send` cannot occur. It remains `!Sync` — recycling is
/// `&mut self` and must not happen from two threads at once.
pub struct BufferConsumer {
    inner: ProvidedBufferRing,
}

// SAFETY: after split() exactly one thread owns the producer ring, so the
// `tail_local` / kernel-tail race that keeps ProvidedBufferRing `!Send` is gone.
// The backing mmap and ring mmap are plain memory owned solely by this struct.
// The `resources: *mut RingResources` field this struct carries (through
// `ProvidedBufferRing`) is exactly the same kind of pointer `Submitter` and
// `Completer` already send across threads: `RingResources` is a refcounted,
// heap-external allocation whose fields are only ever touched through its
// own atomic refcount and (for the mmap regions it tracks) plain integers,
// so moving the pointer itself carries no thread-local state.
#[allow(clippy::non_send_fields_in_send_ty)]
unsafe impl Send for BufferConsumer {}

impl BufferConsumer {
    /// Returns the group id this pool is registered under — the value to pass
    /// to [`Sqe::buffer_select`](crate::op::Sqe::buffer_select) on the
    /// submission thread.
    #[must_use]
    pub const fn bgid(&self) -> u16 {
        self.inner.bgid
    }

    /// Returns the number of buffers in the pool.
    #[must_use]
    pub const fn entries(&self) -> u32 {
        self.inner.entries
    }

    /// Returns the size of each buffer in bytes.
    #[must_use]
    pub const fn buf_size(&self) -> u32 {
        self.inner.buf_size
    }

    /// Query the kernel's current consumer head for this buffer group. See
    /// [`ProvidedBufferRing::status`].
    ///
    /// # Errors
    ///
    /// Returns an error if the registration was lost (should not happen for
    /// a live pool).
    pub fn status(&self) -> Result<u32, Error> {
        self.inner.status()
    }

    /// Borrow the bytes the kernel wrote into buffer `buf_id`.
    ///
    /// Pass the CQE `result` (byte count) as `len`. Returns `None` if `buf_id`
    /// is out of range or `len` exceeds [`buf_size`](Self::buf_size).
    #[must_use]
    pub fn buffer(&self, buf_id: u16, len: u32) -> Option<&[u8]> {
        self.inner.buffer(buf_id, len)
    }

    /// Mutably borrow buffer `buf_id` (e.g. to consume bytes in place before
    /// recycling). Same bounds as [`buffer`](Self::buffer).
    #[must_use]
    pub fn buffer_mut(&mut self, buf_id: u16, len: u32) -> Option<&mut [u8]> {
        self.inner.buffer_mut(buf_id, len)
    }

    /// Borrow a completed buffer as a self-recycling lease. See
    /// [`ProvidedBufferRing::claim`].
    #[must_use]
    pub fn claim(&mut self, buf_id: u16, len: u32) -> Option<CompletedBuffer<'_>> {
        self.inner.claim(buf_id, len)
    }

    /// Parse a buffer delivered by
    /// [`recvmsg_multishot`](crate::op::Sqe::recvmsg_multishot).
    ///
    /// Multishot `recvmsg` does **not** write a bare payload like
    /// [`recv_multishot`](crate::op::Sqe::recv_multishot) does — the kernel
    /// prepends a [`RecvmsgOut`] header, then the name and control regions,
    /// then the payload. Reading the buffer as raw bytes (via
    /// [`buffer`](Self::buffer)) would hand back that header garbage in front of
    /// the data. Use this instead: pass the chosen `buf_id`, the CQE `result`
    /// as `len`, and the `msg_namelen` / `msg_controllen` from the [`MsgHdr`]
    /// you submitted, and get back validated name / control / payload slices.
    ///
    /// Returns `None` if `buf_id`/`len` are out of range or the buffer is too
    /// small to be valid (an internal kernel truncation).
    ///
    /// [`MsgHdr`]: crate::types::MsgHdr
    #[must_use]
    pub fn recvmsg_parts(
        &self,
        buf_id: u16,
        len: u32,
        msg_namelen: u32,
        msg_controllen: u32,
    ) -> Option<RecvmsgParts<'_>> {
        let buf = self.inner.buffer(buf_id, len)?;
        RecvmsgOut::parse(buf, msg_namelen, msg_controllen)
    }

    /// Return buffer `buf_id` to the pool *and* publish it to the kernel.
    ///
    /// This is the common path on the completion thread: once you've consumed
    /// the bytes, hand the id straight back so the kernel can reuse it. For
    /// batching, see [`recycle`](Self::recycle) + [`commit`](Self::commit).
    ///
    /// # Panics
    ///
    /// Panics if `buf_id` is out of range.
    pub fn recycle_and_commit(&mut self, buf_id: u16) {
        self.inner.recycle_and_commit(buf_id);
    }

    /// Queue buffer `buf_id` for return without publishing yet.
    ///
    /// Call [`commit`](Self::commit) once after a batch of `recycle`s to make
    /// them all visible to the kernel with a single Release store.
    ///
    /// # Panics
    ///
    /// Panics if `buf_id` is out of range.
    pub fn recycle(&mut self, buf_id: u16) {
        self.inner.recycle(buf_id);
    }

    /// Publish all pending [`recycle`](Self::recycle)s to the kernel.
    pub fn commit(&self) {
        self.inner.commit();
    }

    /// Record that a real completion delivered `buf_id`. See
    /// [`ProvidedBufferRing::acknowledge`].
    ///
    /// # Errors
    ///
    /// See [`ProvidedBufferRing::acknowledge`].
    pub fn acknowledge(
        &mut self,
        buf_id: u16,
        len: u32,
    ) -> Result<AcknowledgedBuffer, AcknowledgeError> {
        self.inner.acknowledge(buf_id, len)
    }

    /// Read the bytes an acknowledged delivery carries. See
    /// [`ProvidedBufferRing::acknowledged_bytes`].
    #[must_use]
    pub fn acknowledged_bytes(&self, token: &AcknowledgedBuffer) -> &[u8] {
        self.inner.acknowledged_bytes(token)
    }

    /// Recycle an acknowledged delivery. See
    /// [`ProvidedBufferRing::recycle_acknowledged`].
    pub fn recycle_acknowledged(&mut self, token: AcknowledgedBuffer) {
        self.inner.recycle_acknowledged(token);
    }

    /// Recycle an acknowledged delivery and publish the tail. See
    /// [`ProvidedBufferRing::recycle_acknowledged_and_commit`].
    pub fn recycle_acknowledged_and_commit(&mut self, token: AcknowledgedBuffer) {
        self.inner.recycle_acknowledged_and_commit(token);
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

#[cfg(test)]
mod checked_ring_bytes_tests {
    //! Tests for [`checked_ring_bytes`] (Q-09): the overflow guard behind
    //! the provided-buffer ring's mmap sizing. Exercises the `u32 x usize`
    //! product directly with `u32::MAX`-scale inputs so the boundary is
    //! verified without depending on the host's actual pointer width —
    //! on a 64-bit host `u32 * u32` alone can never overflow `usize`, so a
    //! test that only drove the real registration path could not reach
    //! this guard at all.
    use super::checked_ring_bytes;
    use crate::error::InvalidArgKind;

    #[test]
    fn ordinary_sizes_multiply_normally() {
        assert_eq!(checked_ring_bytes(4, 64), Ok(256));
        assert_eq!(checked_ring_bytes(0, 64), Ok(0));
        assert_eq!(checked_ring_bytes(4, 0), Ok(0));
    }

    #[test]
    fn fits_exactly_at_usize_boundary_on_a_32_bit_sized_product() {
        // Simulate the narrowest realistic target: usize::MAX as if it
        // were 32-bit-sized, by using elem_size values that only barely
        // fit. `checked_mul` is what actually enforces the boundary on the
        // host's real usize width; this confirms the exact-fit case does
        // not spuriously reject.
        let elem_size = usize::MAX / 4;
        assert_eq!(checked_ring_bytes(4, elem_size), Ok(elem_size * 4));
    }

    #[test]
    fn overflow_is_rejected_not_wrapped() {
        // Choose an elem_size guaranteed to overflow usize when multiplied
        // by a count > 1, regardless of host pointer width, by using
        // usize::MAX itself as the per-element size.
        let err = checked_ring_bytes(2, usize::MAX).unwrap_err();
        assert_eq!(err, InvalidArgKind::BufferRingSizeOverflow);
    }

    #[test]
    fn u32_max_count_times_small_elem_size_fits_in_64_bit_usize() {
        // On a 64-bit host this product (~8.6e9) is nowhere near
        // usize::MAX (~1.8e19), so it must succeed, not be misclassified
        // as overflow — a checked_mul call is only correct if it also
        // accepts values that genuinely fit. `try_from` (rather than `as`)
        // keeps this assertion honest on a hypothetical narrower `usize`
        // too: if the product didn't fit there either, the conversion
        // itself would fail loudly instead of silently truncating.
        let expected = u64::from(u32::MAX) * 2;
        let Ok(expected) = usize::try_from(expected) else {
            // Product doesn't fit in this host's usize at all — nothing to
            // assert; checked_ring_bytes should also report overflow.
            assert_eq!(
                checked_ring_bytes(u32::MAX, 2),
                Err(InvalidArgKind::BufferRingSizeOverflow)
            );
            return;
        };
        assert_eq!(checked_ring_bytes(u32::MAX, 2), Ok(expected));
    }

    #[test]
    fn u32_max_count_times_elem_size_that_overflows_is_rejected() {
        // Pick an elem_size that forces the product past usize::MAX
        // regardless of host width, by scaling from usize::MAX itself.
        let elem_size = usize::MAX / 2;
        let err = checked_ring_bytes(u32::MAX, elem_size).unwrap_err();
        assert_eq!(err, InvalidArgKind::BufferRingSizeOverflow);
    }
}
