//! Types for `IORING_OP_FUTEX_WAIT` / `FUTEX_WAKE` / `FUTEX_WAITV`.

bitflags! {
    /// `futex2` flags, packed into `sqe->fd` for a single-futex wait/wake.
    ///
    /// The low two bits name the futex word's width (only `SIZE_U32` is
    /// implemented by the kernel today; any other size is rejected with
    /// `EINVAL`), and the crate always sends it — there is no "unset" size
    /// that would mean something else. `PRIVATE` mirrors `FUTEX_PRIVATE_FLAG`:
    /// its *absence* means the futex is process-shared, so this bit is the
    /// one that inverts the usual "0 is the safe default" reading. `NUMA`
    /// selects the futex2 NUMA-aware variant, where the word doubles to
    /// carry a node hint alongside the value.
    pub struct Futex2Flags(u32);
    /// The futex word is a `u32` — the only width the kernel implements.
    const SIZE_U32 = 0x02;
    /// The futex is process-private rather than shared across processes.
    const PRIVATE = 0x80;
    /// NUMA-aware: the futex word carries a node hint alongside its value.
    const NUMA = 0x04;
}

impl Futex2Flags {
    /// `SIZE_U32`: the only word width the kernel accepts, so a caller
    /// who does not care about NUMA or process-sharing still submits a
    /// request the kernel does not reject outright.
    ///
    /// Not `Default` because the all-zero bit pattern the derive would
    /// give is `SIZE_U8`, a width the kernel rejects with `EINVAL` — the
    /// "empty set" reading a bitflag type usually wants is not a request
    /// this kernel op can ever accept.
    #[must_use]
    pub const fn default_size() -> Self {
        Self::SIZE_U32
    }
}

/// One waiter for `IORING_OP_FUTEX_WAITV`, matching the kernel's
/// `struct futex_waitv` byte for byte.
///
/// Fields are private because a waiter with a stray `__reserved` bit is
/// rejected by the kernel outright rather than silently ignored, and
/// [`new`](Self::new) is the only way to build one with that field forced
/// to zero.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FutexWaitv {
    val: u64,
    uaddr: u64,
    flags: u32,
    reserved: u32,
}

impl FutexWaitv {
    /// A waiter expecting `val` at `uaddr`, using `flags` (the same
    /// [`Futex2Flags`] a single wait/wake takes).
    ///
    /// # Safety
    ///
    /// `uaddr` is borrowed only for this call, exactly as
    /// [`IoVec::new`](crate::types::IoVec::new) borrows its buffer — this
    /// value stores the raw address, not the borrow itself. The caller
    /// must ensure the memory it points to remains valid and readable, at
    /// a stable address, until the kernel posts the completion for
    /// whichever `FUTEX_WAITV` request this entry is submitted with.
    #[must_use]
    pub unsafe fn new(uaddr: *const u32, val: u64, flags: Futex2Flags) -> Self {
        Self {
            val,
            uaddr: uaddr as u64,
            flags: flags.bits(),
            reserved: 0,
        }
    }
}

/// Most waiters `IORING_OP_FUTEX_WAITV` accepts (`FUTEX_WAITV_MAX`).
///
/// Beyond this the kernel rejects the whole request with `EINVAL` rather
/// than waiting on a prefix.
pub const FUTEX_WAITV_MAX: usize = 128;
