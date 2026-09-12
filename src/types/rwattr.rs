//! Read/write PI (protection information) attribute metadata (kernel 6.14+).
//!
//! Confirmed against `io_uring/rw.c`'s `__io_prep_rw`/`io_prep_rw_pi`: the
//! attribute mechanism rides the *ordinary* 64-byte SQE. `sqe->attr_ptr` and
//! `sqe->attr_type_mask` are a union alias over the same eight bytes every
//! other op already uses as `addr3` plus the trailing padding word — no
//! `IORING_SETUP_SQE128` stride widening is needed, only a fresh way to
//! address that existing pair of fields for the rw-prep opcodes
//! (`read`/`write`/`readv`/`writev`/`read_fixed`/`write_fixed`/
//! `readv_fixed`/`writev_fixed`, all of which route through `__io_prep_rw`).
//! `IORING_RW_ATTR_FLAG_PI` is the only attribute type the kernel currently
//! defines; any other bit in `attr_type_mask` is rejected with `-EINVAL`,
//! as is a nonzero `rsvd` in the attribute struct itself.

bitflags! {
    /// `sqe->attr_type_mask` bits — which kinds of attribute follow at
    /// `attr_ptr`. Only [`PI`](Self::PI) exists today.
    pub struct RwAttrFlags(u64);
    const PI = 1 << 0;
}

/// PI (protection information) attribute struct, matching
/// `struct io_uring_attr_pi` byte-for-byte.
///
/// Describes a second, separately-addressed buffer of PI metadata
/// (checksums/tags a storage device verifies or generates alongside the
/// ordinary data transfer) that rides beside the read/write's own
/// `addr`/`len`. The kernel copies this struct in by value at prep time —
/// it does not need to stay alive past the `Sqe` constructor call, only
/// the metadata buffer its `addr`/`len` describe does.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct RwAttrPi {
    /// Per-request PI flags (device/protocol specific).
    pub flags: u16,
    /// Application tag, passed through to/verified against the device.
    pub app_tag: u16,
    /// Length in bytes of the metadata buffer at `addr`.
    pub len: u32,
    /// Address of the metadata buffer.
    pub addr: u64,
    /// Initial reference tag seed.
    pub seed: u64,
    /// Reserved — the kernel rejects a nonzero value with `-EINVAL`.
    pub rsvd: u64,
}
