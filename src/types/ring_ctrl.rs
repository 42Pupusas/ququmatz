//! Ring setup, enter, and feature flags.

bitflags! {
    /// Flags for `io_uring_enter`.
    pub struct EnterFlags(u32);
    const GETEVENTS = 1 << 0;
    /// Wake a sleeping SQPOLL thread.
    const SQ_WAKEUP = 1 << 1;
    /// Pass an `io_uring_getevents_arg` struct for timeout without a SQE (6.0+).
    const EXT_ARG = 1 << 3;
    /// Use the registered ring fd (saved file-table lookup on each enter).
    const REGISTERED_RING = 1 << 4;
    /// Skip the `iowait`-state accounting `io_uring_enter` normally does
    /// while blocked in `GETEVENTS` (kernel 6.14+). Marking the calling
    /// thread as iowaiting nudges the scheduler and power governors to
    /// treat the wait as I/O-bound, which is the right default for most
    /// blocking waits but wrong for a low-latency poll loop that spends
    /// most of its time here by design; this flag opts such a loop out of
    /// that accounting. Requires [`Features::NO_IOWAIT`](super::Features::NO_IOWAIT).
    const NO_IOWAIT = 1 << 7;
}

bitflags! {
    /// Flags for `io_uring_setup`.
    pub struct SetupFlags(u32);
    /// Polled I/O completion. The device driver polls for completions
    /// instead of waiting on an interrupt; requires files opened with
    /// `O_DIRECT` and hardware/filesystem support for polling. See
    /// [`IoUringBuilder::iopoll`](crate::ring::IoUringBuilder::iopoll).
    const IOPOLL = 1 << 0;
    /// Kernel-side SQ polling thread.
    const SQPOLL = 1 << 1;
    /// Bind SQPOLL thread to a specific CPU.
    const SQ_AFF = 1 << 2;
    /// Use user-specified CQ ring size.
    const CQSIZE = 1 << 3;
    /// Clamp SQ/CQ ring sizes to implementation limits.
    const CLAMP = 1 << 4;
    /// Attach to an existing workqueue.
    const ATTACH_WQ = 1 << 5;
    /// Start the ring rejecting `io_uring_enter` until
    /// [`IoUring::enable_rings`](crate::ring::IoUring::enable_rings) is
    /// called, so buffers, files, or other resources can finish
    /// registering before any submitted request can run against them.
    const R_DISABLED = 1 << 6;
    /// Keep submitting the rest of a batch even after one entry in the
    /// middle is rejected, instead of stopping at the first failure.
    /// Without this, [`IoUring::submit`](crate::ring::IoUring::submit) and
    /// [`submit_and_wait`](crate::ring::IoUring::submit_and_wait) can
    /// report a short count with entries after the failure left unsent.
    const SUBMIT_ALL = 1 << 7;
    /// Cooperative task-run: don't force preemption when processing completions (6.0+).
    const COOP_TASKRUN = 1 << 8;
    /// Surface pending task-work through `IORING_SQ_TASKRUN` in the SQ
    /// ring's flags rather than requiring a kernel transition to discover
    /// it. Only meaningful combined with `COOP_TASKRUN` or
    /// `DEFER_TASKRUN` — the kernel rejects it alone.
    const TASKRUN_FLAG = 1 << 9;
    /// Single-issuer hint (5.18+).
    const SINGLE_ISSUER = 1 << 12;
    /// Defer task-run work to `io_uring_enter` — biggest latency win on 6.1+.
    const DEFER_TASKRUN = 1 << 13;
    /// Don't mmap the rings; user provides the memory.
    const NO_MMAP = 1 << 14;
    /// Abolish the indirection SQ array; kernel reads SQEs directly by the
    /// masked SQ head rather than through `sq_array[head & mask]` (6.6+).
    /// Saves the array's memory and one indirect load per submitted SQE;
    /// no different for callers of this crate, since `push()` already
    /// writes each SQE to the slot the kernel would read either way.
    const NO_SQARRAY = 1 << 16;
}

impl SetupFlags {
    /// Flags this crate's setup path actually implements.
    ///
    /// `NO_MMAP` *is* implemented: confirmed against
    /// `io_uring/io_uring.c`'s `io_allocate_scq_urings` and
    /// `io_uring/memmap.c`'s `io_region_pin_pages`, the kernel under this
    /// flag pins caller-supplied pages named by `params.sq_off.user_addr`
    /// (the SQE array) and `params.cq_off.user_addr` (the combined SQ/CQ
    /// ring region) instead of allocating its own. `IoUring::from_params`
    /// allocates and describes that memory on the caller's behalf before
    /// the setup syscall runs (see the `ring::no_mmap` module), sized
    /// generously against a userspace prediction of the kernel's own
    /// entry-count rounding and internal layout math (`rings_size`) so the
    /// pin can never read past what this crate actually backs. Any other
    /// currently-unnamed bit remains unimplemented by definition.
    ///
    /// `NO_SQARRAY` *is* implemented: confirmed against
    /// `io_uring/io_uring.c`'s `rings_size` (which leaves the SQ indirection
    /// array's size out of the mapped region entirely under this flag) and
    /// `io_get_sqe` (which skips the array lookup and indexes `sq_sqes`
    /// directly by the masked head), the ring mapping/parsing code
    /// special-cases it: the SQ region is sized without the array's bytes,
    /// and no identity array is written into memory that does not back one.
    ///
    /// [`IoUring::from_params`](crate::ring::IoUring) rejects flags outside
    /// this mask before the setup syscall runs, so an accepted `IoUring`
    /// never has a layout its mapping code cannot handle.
    pub(crate) const SUPPORTED_MASK: Self = Self(
        Self::IOPOLL.0
            | Self::SQPOLL.0
            | Self::SQ_AFF.0
            | Self::CQSIZE.0
            | Self::CLAMP.0
            | Self::ATTACH_WQ.0
            | Self::R_DISABLED.0
            | Self::SUBMIT_ALL.0
            | Self::COOP_TASKRUN.0
            | Self::TASKRUN_FLAG.0
            | Self::SINGLE_ISSUER.0
            | Self::DEFER_TASKRUN.0
            | Self::NO_MMAP.0
            | Self::NO_SQARRAY.0,
    );

    /// Construct from an arbitrary raw value, including bits with no
    /// associated named constant.
    ///
    /// Test-only: exercises the unsupported-flag rejection path in
    /// [`IoUring::from_params`](crate::ring::IoUring) against a bit that
    /// cannot be spelled through the public builder API, since real
    /// callers only ever OR together named constants.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn from_raw_for_test(bits: u32) -> Self {
        Self(bits)
    }

    /// Construct from the raw value the ring was actually created with.
    ///
    /// Used by [`IoUring::setup_flags`](crate::ring::IoUring::setup_flags)
    /// to hand callers a typed view of the flags `io_uring_setup` accepted,
    /// which may include bits this crate does not name.
    pub(crate) const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }
}

bitflags! {
    /// Feature flags reported by the kernel after `io_uring_setup`.
    pub struct Features(u32);
    const SINGLE_MMAP = 1 << 0;
    const NODROP = 1 << 1;
    const SUBMIT_STABLE = 1 << 2;
    const RW_CUR_POS = 1 << 3;
    const CUR_PERSONALITY = 1 << 4;
    const FAST_POLL = 1 << 5;
    const POLL_32BITS = 1 << 6;
    const SQPOLL_NONFIXED = 1 << 7;
    const EXT_ARG = 1 << 8;
    const NATIVE_WORKERS = 1 << 9;
    const RSRC_TAGS = 1 << 10;
    const CQE_SKIP = 1 << 11;
    const LINKED_FILE = 1 << 12;
    const REG_REG_RING = 1 << 13;
    const RECVSEND_BUNDLE = 1 << 14;
    const MIN_TIMEOUT = 1 << 15;
    /// The kernel understands `sqe->attr_ptr`/`attr_type_mask` on rw-prep
    /// opcodes (kernel 6.14+). See [`super::RwAttrFlags`].
    const RW_ATTR = 1 << 16;
    /// `IORING_ENTER_NO_IOWAIT` is accepted by `io_uring_enter` (kernel
    /// 6.14+): see [`EnterFlags::NO_IOWAIT`].
    const NO_IOWAIT = 1 << 17;
}

impl Features {
    /// Construct from the raw value returned by the kernel.
    pub(crate) const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }
}

bitflags! {
    /// Flags set on individual SQEs to control execution ordering and behavior.
    pub struct SqeFlags(u8);
    /// Use a registered/fixed file descriptor.
    const FIXED_FILE = 1 << 0;
    /// Drain the submission queue before executing this SQE.
    const IO_DRAIN = 1 << 1;
    /// Link this SQE to the next one — if this fails, the next is cancelled.
    const IO_LINK = 1 << 2;
    /// Hard-link: like `IO_LINK` but the chain continues even on failure.
    const IO_HARDLINK = 1 << 3;
    /// Force async execution even if the op could complete inline.
    const IO_ASYNC = 1 << 4;
    /// Select a buffer from a registered provided-buffer ring.
    ///
    /// When set, the kernel picks a buffer from the group identified by
    /// `sqe.buf_group` (aliased with `buf_index`) and reports the chosen
    /// buffer id in the upper 16 bits of the CQE flags.
    const BUFFER_SELECT = 1 << 5;
    /// Suppress the CQE when this request succeeds (fire-and-forget chains).
    const CQE_SKIP_SUCCESS = 1 << 6;
}
