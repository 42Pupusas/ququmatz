//! The fixed-size regions a `msghdr` request makes the kernel dereference.
//!
//! A vectored read hands the kernel one pointer to an array. A `sendmsg`
//! hands it a pointer to a `struct msghdr` which *itself* holds pointers —
//! to an `iovec` array, and to a socket address — and the kernel follows
//! all of them after submission. So the header is not just one more region
//! that must stay put: it is a region whose *contents* are addresses that
//! must also stay put, and nothing in the type system relates the two.
//!
//! Splitting them across separate caller allocations would mean three
//! independent stability obligations to check and hand back. They are
//! instead staged in one caller-supplied [`StableBufferMut`], laid out
//! back to back:
//!
//! ```text
//!   offset 0                56              56 + 16*N
//!   +----------------------+---------------+-------------+
//!   | MsgHdr               | IoVec x N     | SockAddrIn  |
//!   +----------------------+---------------+-------------+
//! ```
//!
//! Every type in that picture has 8-byte alignment and a size that is a
//! multiple of 8, so checking the base address once makes all three
//! sub-regions aligned. The whole thing is checked for size and alignment
//! before a request can exist, and comes back to the caller at the end, so
//! one allocation can serve many requests.
//!
//! The payload buffers are *not* staged here. They are owned inline by the
//! request as `[B; N]`, exactly as [`PreparedVectored`] owns them, because
//! [`StableBuffer`](super::StableBuffer) already promises their bytes do
//! not move when their owner does.
//!
//! [`PreparedVectored`]: super::PreparedVectored

use core::mem::{align_of, size_of};

use super::buffer::StableBufferMut;
use crate::types::{IoVec, MsgHdr, SockAddrIn};

/// Most `iovec` entries the kernel accepts (`UIO_MAXIOV`).
///
/// Beyond this the request fails with `EMSGSIZE` rather than transferring
/// a prefix, so it is refused where the caller still holds the storage.
pub const MAX_IOV: usize = 1024;

/// Why a `msghdr` request's staging storage was refused.
///
/// Each hands the caller's storage back rather than consuming it, so a
/// rejected request never costs an allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgRegionError {
    /// The staging storage cannot hold the header, the descriptors, and
    /// the address.
    ///
    /// The kernel reads a whole `msghdr` from this address and then
    /// follows the pointers inside it, so a short region is a read past
    /// the end of the allocation rather than a truncated request.
    RegionTooSmall {
        /// Bytes the staged layout needs.
        needed: usize,
        /// Bytes the supplied storage has.
        got: usize,
    },
    /// The staging storage is not aligned for a `MsgHdr`.
    ///
    /// [`MmapBuffer`](super::MmapBuffer) is page-aligned and always
    /// satisfies this; a hand-written [`StableBufferMut`] might not.
    RegionMisaligned {
        /// Alignment the staged layout requires.
        needed: usize,
    },
    /// More descriptors than `UIO_MAXIOV`.
    ///
    /// The kernel answers this with `EMSGSIZE`, so it is caught here
    /// instead.
    TooManyDescriptors {
        /// Descriptors asked for.
        got: usize,
        /// The most the kernel accepts.
        max: usize,
    },
}

impl core::fmt::Display for MsgRegionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RegionTooSmall { needed, got } => {
                write!(f, "msghdr staging needs {needed} bytes, got {got}")
            }
            Self::RegionMisaligned { needed } => {
                write!(f, "msghdr staging must be {needed}-byte aligned")
            }
            Self::TooManyDescriptors { got, max } => {
                write!(f, "{got} descriptors exceeds the kernel's limit of {max}")
            }
        }
    }
}

/// Caller storage holding the header, descriptors, and address together.
///
/// Owns the storage and the addresses of the three sub-regions inside it,
/// which are valid for as long as this value owns the storage.
pub struct MsgRegion<R> {
    store: R,
    hdr: *mut MsgHdr,
    vecs: *mut IoVec,
    name: *mut SockAddrIn,
    count: usize,
}

// SAFETY: every pointer refers into `store`, which this value exclusively
// owns, so they stay valid wherever it goes. It adds no thread affinity of
// its own, leaving `R` to decide.
unsafe impl<R: Send> Send for MsgRegion<R> {}

impl<R: StableBufferMut> MsgRegion<R> {
    /// Check `store` against the staged layout and take ownership of it.
    ///
    /// # Errors
    ///
    /// Returns the storage untouched alongside [`MsgRegionError`] if it is
    /// too small, misaligned, or `count` exceeds `UIO_MAXIOV`.
    pub(crate) fn stage(mut store: R, count: usize) -> Result<Self, (R, MsgRegionError)> {
        if count > MAX_IOV {
            return Err((
                store,
                MsgRegionError::TooManyDescriptors {
                    got: count,
                    max: MAX_IOV,
                },
            ));
        }
        let needed = Self::bytes_for(count);
        let got = store.stable_len();
        if got < needed {
            return Err((store, MsgRegionError::RegionTooSmall { needed, got }));
        }
        let base = store.stable_mut_ptr();
        let align = align_of::<MsgHdr>();
        // Checked on the address rather than by casting first: the casts
        // below are only well-defined once this has passed.
        if !base.addr().is_multiple_of(align) {
            return Err((store, MsgRegionError::RegionMisaligned { needed: align }));
        }
        // Each offset is a multiple of 8 and the base was just checked, so
        // every sub-region inherits the alignment its type requires.
        #[allow(clippy::cast_ptr_alignment)]
        let hdr = base.cast::<MsgHdr>();
        // SAFETY: `store` holds at least `needed` bytes, so both offsets
        // land inside the allocation.
        let (vecs, name) = unsafe {
            #[allow(clippy::cast_ptr_alignment)]
            let vecs = base.add(size_of::<MsgHdr>()).cast::<IoVec>();
            #[allow(clippy::cast_ptr_alignment)]
            let name = base.add(Self::name_offset(count)).cast::<SockAddrIn>();
            (vecs, name)
        };
        Ok(Self {
            store,
            hdr,
            vecs,
            name,
            count,
        })
    }
}

impl<R> MsgRegion<R> {
    /// Bytes the staged layout occupies for `count` descriptors.
    pub(crate) const fn bytes_for(count: usize) -> usize {
        Self::name_offset(count) + size_of::<SockAddrIn>()
    }

    const fn name_offset(count: usize) -> usize {
        size_of::<MsgHdr>() + size_of::<IoVec>() * count
    }

    /// Point descriptor `index` at `len` bytes starting at `base`.
    ///
    /// # Safety
    ///
    /// `index` must be below the count this region was staged for, and
    /// `base` must stay valid for `len` bytes until the kernel is done.
    pub(crate) unsafe fn write_descriptor(&mut self, index: usize, base: *mut u8, len: usize) {
        debug_assert!(index < self.count);
        // SAFETY: `index` is in range by the caller's guarantee, and the
        // array was sized for `count` entries inside owned storage.
        unsafe { self.vecs.add(index).write(IoVec::new(base, len)) }
    }

    /// Read descriptor `index` back out of the staged array.
    pub(crate) fn descriptor(&self, index: usize) -> IoVec {
        debug_assert!(index < self.count);
        // SAFETY: every entry below `count` was written before this value
        // was handed out, and the array lives in storage this value owns.
        unsafe { self.vecs.add(index).read() }
    }

    /// Copy `addr` into the staged address slot.
    pub(crate) const fn write_name(&mut self, addr: SockAddrIn) {
        // SAFETY: the slot was sized and aligned for a `SockAddrIn` inside
        // storage this value owns exclusively.
        unsafe { self.name.write(addr) }
    }

    /// Write the header the kernel will read, wiring it to the staged
    /// descriptor array and, when `named`, to the staged address.
    ///
    /// `flags` is deliberately not a parameter: `msg_flags` is an output
    /// field on `recvmsg` and ignored on `sendmsg`, so a caller value
    /// there would be silently discarded.
    pub(crate) fn publish_header(&mut self, named: bool) {
        let mut hdr = MsgHdr::default();
        if named {
            hdr.msg_name = self.name.cast::<u8>();
            #[allow(clippy::cast_possible_truncation)]
            {
                hdr.msg_namelen = size_of::<SockAddrIn>() as u32;
            }
        }
        hdr.msg_iov = self.vecs;
        hdr.msg_iovlen = self.count;
        // SAFETY: `hdr` was sized and aligned for a `MsgHdr` inside storage
        // this value owns exclusively, and no SQE naming it exists yet, so
        // the kernel is not reading concurrently.
        unsafe { self.hdr.write(hdr) }
    }

    /// The header exactly as the kernel will read it — or, after a
    /// completion, exactly as the kernel left it.
    pub(crate) const fn header(&self) -> MsgHdr {
        // SAFETY: written by `publish_header` before this value was handed
        // out, in storage this value owns.
        unsafe { self.hdr.read() }
    }

    /// Address of the header, for the SQE.
    pub(crate) const fn header_ptr(&self) -> *mut MsgHdr {
        self.hdr
    }

    /// Give the storage back.
    pub(crate) fn into_store(self) -> R {
        self.store
    }

    /// Rebuild from parts that were split apart by a state transition.
    pub(crate) const fn from_parts(
        store: R,
        hdr: *mut MsgHdr,
        vecs: *mut IoVec,
        name: *mut SockAddrIn,
        count: usize,
    ) -> Self {
        Self {
            store,
            hdr,
            vecs,
            name,
            count,
        }
    }

    /// Split into the storage and the cached addresses, so a ticket can
    /// suppress the storage's destructor without losing the layout.
    pub(crate) fn into_raw_parts(self) -> (R, *mut MsgHdr, *mut IoVec, *mut SockAddrIn, usize) {
        // Destructuring rather than field reads so adding a field is a
        // compile error here rather than a silently dropped one.
        let Self {
            store,
            hdr,
            vecs,
            name,
            count,
        } = self;
        (store, hdr, vecs, name, count)
    }
}

#[cfg(test)]
mod msg_region_tests {
    use super::{MAX_IOV, MsgRegion, MsgRegionError};
    use crate::owned::{MmapBuffer, StableBuffer};
    use crate::types::{IoVec, MsgHdr, SockAddrIn};

    /// Storage large enough for `count` descriptors, so a rejection can
    /// only come from the count itself rather than from a short region.
    fn ample(count: usize) -> MmapBuffer {
        MmapBuffer::with_capacity(MsgRegion::<MmapBuffer>::bytes_for(count)).expect("map")
    }

    #[test]
    fn more_descriptors_than_the_kernel_accepts_are_refused_with_the_storage_back() {
        // Measured: an `iovlen` of 1025 makes the kernel answer EMSGSIZE
        // rather than transferring the first 1024, so the whole message
        // fails. Catching it here leaves the caller holding the storage.
        let store = ample(MAX_IOV + 1);
        let len = store.stable_len();
        let Err((store, e)) = MsgRegion::stage(store, MAX_IOV + 1) else {
            panic!("a count past UIO_MAXIOV must be refused");
        };
        assert_eq!(
            e,
            MsgRegionError::TooManyDescriptors {
                got: MAX_IOV + 1,
                max: MAX_IOV,
            }
        );
        assert_eq!(store.stable_len(), len);
    }

    #[test]
    fn exactly_the_kernels_limit_is_accepted() {
        // The boundary is the point: refusing 1024 as well would reject
        // messages the kernel would have taken.
        let mut region = MsgRegion::stage(ample(MAX_IOV), MAX_IOV)
            .ok()
            .expect("the limit itself must be allowed");
        region.publish_header(false);
        assert_eq!(region.header().msg_iovlen, MAX_IOV);
    }

    #[test]
    fn each_sub_region_lies_inside_the_storage_and_none_overlap() {
        let mut region = MsgRegion::stage(ample(3), 3)
            .ok()
            .expect("ample storage fits");
        region.publish_header(true);

        // The header's own bytes are addresses the kernel dereferences, so
        // a descriptor array or address overlapping it would have the
        // kernel read pointers as data.
        let hdr = region.header();
        let header_end = region.header_ptr().addr() + core::mem::size_of::<MsgHdr>();
        assert!(hdr.msg_iov.addr() >= header_end);
        assert!(hdr.msg_name.addr() >= hdr.msg_iov.addr() + core::mem::size_of::<IoVec>() * 3);
    }

    #[test]
    fn the_staged_address_is_reachable_by_following_the_header() {
        let mut region = MsgRegion::stage(ample(1), 1)
            .ok()
            .expect("ample storage fits");
        let addr = SockAddrIn {
            sin_family: 2,
            sin_port: 8080u16.to_be(),
            sin_addr: u32::from_ne_bytes([10, 0, 0, 1]),
            sin_zero: [0; 8],
        };
        region.write_name(addr);
        region.publish_header(true);

        // Read it the way the kernel does — through the header's own
        // pointer — rather than through a field the region kept, which
        // would agree even if the header named somewhere else entirely.
        let hdr = region.header();
        // The region staged this slot at an 8-byte-aligned offset from a
        // base it checked, so the cast is sound.
        #[allow(clippy::cast_ptr_alignment)]
        let slot = hdr.msg_name.cast::<SockAddrIn>();
        // SAFETY: the region wrote a `SockAddrIn` at this address and still
        // owns the storage holding it.
        let seen = unsafe { slot.read() };
        assert_eq!(seen, addr);
    }
}
