//! Slots in the ring's registered-file table.
//!
//! A direct request does not hand the process a file descriptor. It
//! installs the file into a table the ring owns and names it by index, so
//! what comes back is a number that means something only to one ring.
//!
//! That is a third kind of resource, distinct from both of the earlier
//! ones. A pool buffer is *borrowed*: the kernel wants it back, and
//! [`Arrival`](super::Arrival) recycles it on drop. A descriptor is
//! *owned by the process*: [`File`](crate::fs::File) closes it on drop, and
//! it outlives the ring that produced it. A table slot is owned by the
//! **ring** — nothing in this process holds it, `close(2)` does not apply
//! to it, and tearing the ring down releases every slot at once.
//!
//! # The wire encoding is off by one
//!
//! The kernel reads the slot from `sqe->file_index`, which aliases
//! `splice_fd_in`, and decides what to do by testing it against zero:
//!
//! ```text
//! open->file_slot = READ_ONCE(sqe->file_index);
//! ...
//! bool fixed = !!open->file_slot;
//! ```
//!
//! So zero cannot mean "slot 0" — it already means "not a direct request,
//! give me a normal descriptor". Every explicit slot is therefore sent as
//! `index + 1`, and `__io_fixed_fd_install` subtracts it back:
//!
//! ```text
//! bool alloc_slot = file_slot == IORING_FILE_INDEX_ALLOC;
//! if (alloc_slot) { ... } else { file_slot--; }
//! ```
//!
//! Two values in that space are therefore spoken for: `0` and
//! `IORING_FILE_INDEX_ALLOC` (`u32::MAX`). [`SlotIndex`] rejects the
//! indices that would encode to either, so a request cannot silently
//! become a different kind of request.

use super::identity::RingId;

/// The kernel's "allocate a slot for me" sentinel, `IORING_FILE_INDEX_ALLOC`.
const FILE_INDEX_ALLOC: u32 = u32::MAX;

/// A zero-based index into a ring's registered-file table.
///
/// This is the number the caller thinks in and the number
/// [`Sqe::fixed_file`](crate::Sqe::fixed_file) operations expect. The
/// off-by-one the kernel wants on submission is applied by
/// [`SlotTarget::raw`] and never leaks out here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SlotIndex(u32);

impl SlotIndex {
    /// Largest representable index.
    ///
    /// One less than would be expected, because the encoded form is
    /// `index + 1` and the top encoded value is the kernel's
    /// allocate-for-me sentinel.
    pub const MAX: u32 = u32::MAX - 2;

    /// Wrap a table index.
    ///
    /// # Errors
    ///
    /// Returns `None` above [`MAX`](Self::MAX), where the encoded form
    /// would collide with the kernel's sentinel.
    #[must_use]
    pub const fn new(index: u32) -> Option<Self> {
        if index > Self::MAX {
            None
        } else {
            Some(Self(index))
        }
    }

    /// The index as the kernel's table offset.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl core::fmt::Display for SlotIndex {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Which table slot a direct request should install its file into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotTarget {
    /// Let the kernel pick a free slot and report which one.
    ///
    /// The chosen index arrives in the CQE result.
    Auto,
    /// Install into this exact slot, replacing whatever occupies it.
    ///
    /// The CQE result is `0` on success, not the index — the caller
    /// already knows it.
    Exact(SlotIndex),
}

impl SlotTarget {
    /// Install into slot `index`, if it is representable.
    ///
    /// # Errors
    ///
    /// Returns `None` above [`SlotIndex::MAX`].
    #[must_use]
    pub const fn exact(index: u32) -> Option<Self> {
        match SlotIndex::new(index) {
            Some(slot) => Some(Self::Exact(slot)),
            None => None,
        }
    }

    /// The value the kernel reads out of `sqe->file_index`.
    ///
    /// Stored in the SQE as `i32` because that is the field's declared
    /// type; the kernel reads the same bits back as `u32`.
    #[must_use]
    #[allow(clippy::cast_possible_wrap)]
    pub(crate) const fn raw(self) -> i32 {
        match self {
            Self::Auto => FILE_INDEX_ALLOC as i32,
            Self::Exact(slot) => (slot.get() + 1) as i32,
        }
    }

    /// The index this target resolves to, given a successful CQE result.
    ///
    /// Only [`Auto`](Self::Auto) reads the result: an explicit install
    /// returns `0` from `io_install_fixed_file`, so believing the result
    /// there would report every file as landing in slot 0.
    pub(crate) const fn resolve(self, result: i32) -> Option<SlotIndex> {
        match self {
            Self::Exact(slot) => Some(slot),
            #[allow(clippy::cast_sign_loss)]
            Self::Auto => {
                if result < 0 {
                    None
                } else {
                    SlotIndex::new(result as u32)
                }
            }
        }
    }
}

/// An occupied slot in one ring's registered-file table.
///
/// # Releasing one is not `close`
///
/// There is no descriptor here to close, and no `Drop` that can free
/// anything: releasing a slot means asking the ring to do it, which needs a
/// submitter this value does not hold. Dropping a `DirectSlot` therefore
/// leaves the file installed until the slot is overwritten or the ring's
/// table is torn down.
///
/// That is a milder leak than an abandoned [`File`](crate::fs::File), and
/// the difference is worth being precise about: a leaked descriptor lives
/// as long as the *process*, while a leaked slot dies with the *ring*. Both
/// are bounded resources, but only one of them survives everything you
/// might do to recover it.
///
/// # The index is ring-scoped
///
/// Slot 3 of one ring and slot 3 of another are different files. This value
/// records which ring's table it indexes so that a mix-up can be caught
/// rather than quietly acting on the wrong file.
#[derive(Debug)]
#[must_use = "a dropped slot stays occupied until the ring's table is torn down"]
pub struct DirectSlot {
    index: SlotIndex,
    ring: RingId,
}

impl DirectSlot {
    /// Record a slot the kernel installed a file into.
    pub(crate) const fn new(index: SlotIndex, ring: RingId) -> Self {
        Self { index, ring }
    }

    /// The table index, for use with
    /// [`Sqe::fixed_file`](crate::Sqe::fixed_file) operations.
    #[must_use]
    pub const fn index(&self) -> SlotIndex {
        self.index
    }

    /// Identity of the ring whose table this indexes.
    #[must_use]
    pub const fn ring(&self) -> RingId {
        self.ring
    }

    /// Whether this slot belongs to `ring`'s table.
    #[must_use]
    pub const fn belongs_to(&self, ring: RingId) -> bool {
        self.ring.raw() == ring.raw()
    }

    /// The raw `fd` field value for an operation on this slot.
    ///
    /// Pair with [`Sqe::fixed_file`](crate::Sqe::fixed_file), which tells
    /// the kernel to read `fd` as a table index rather than a descriptor.
    #[must_use]
    #[allow(clippy::cast_possible_wrap)]
    pub const fn as_fixed_fd(&self) -> i32 {
        self.index.get() as i32
    }
}

#[cfg(test)]
mod slot_tests {
    use super::{DirectSlot, FILE_INDEX_ALLOC, SlotIndex, SlotTarget};
    use crate::owned::identity::RingId;

    #[test]
    fn auto_encodes_as_the_kernels_allocate_sentinel() {
        assert_eq!(SlotTarget::Auto.raw().cast_unsigned(), FILE_INDEX_ALLOC);
        assert_eq!(SlotTarget::Auto.raw(), -1);
    }

    #[test]
    fn an_exact_slot_is_sent_one_higher_than_it_is_named() {
        let target = SlotTarget::exact(7).expect("representable");
        assert_eq!(target.raw(), 8);
    }

    #[test]
    fn slot_zero_is_representable_and_does_not_read_as_unfixed() {
        let target = SlotTarget::exact(0).expect("representable");
        assert_ne!(target.raw(), 0, "zero on the wire means 'not a direct op'");
        assert_eq!(target.raw(), 1);
    }

    #[test]
    fn the_two_reserved_encodings_cannot_be_named() {
        assert_eq!(SlotIndex::new(u32::MAX), None);
        assert_eq!(SlotIndex::new(u32::MAX - 1), None);
        assert!(SlotIndex::new(SlotIndex::MAX).is_some());
    }

    #[test]
    fn the_largest_index_stops_short_of_the_sentinel() {
        let target = SlotTarget::exact(SlotIndex::MAX).expect("representable");
        assert_ne!(target.raw().cast_unsigned(), FILE_INDEX_ALLOC);
        assert_eq!(target.raw().cast_unsigned(), FILE_INDEX_ALLOC - 1);
    }

    #[test]
    fn an_auto_target_reads_its_index_from_the_result() {
        let resolved = SlotTarget::Auto.resolve(4).expect("index");
        assert_eq!(resolved.get(), 4);
    }

    #[test]
    fn an_exact_target_keeps_its_index_rather_than_believing_the_result() {
        let target = SlotTarget::exact(9).expect("representable");
        let resolved = target.resolve(0).expect("index");
        assert_eq!(resolved.get(), 9, "an explicit install returns 0, not 9");
    }

    #[test]
    fn a_slot_knows_which_rings_table_it_indexes() {
        let mine = RingId::next();
        let other = RingId::next();
        let slot = DirectSlot::new(SlotIndex::new(2).expect("index"), mine);
        assert!(slot.belongs_to(mine));
        assert!(!slot.belongs_to(other));
    }

    #[test]
    fn a_slot_addresses_the_table_by_its_plain_index() {
        let slot = DirectSlot::new(SlotIndex::new(5).expect("index"), RingId::next());
        assert_eq!(slot.as_fixed_fd(), 5, "the +1 is a submission-only detail");
    }
}
