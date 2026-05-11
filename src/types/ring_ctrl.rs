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
}

bitflags! {
    /// Flags for `io_uring_setup`.
    pub struct SetupFlags(u32);
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
    /// Cooperative task-run: don't force preemption when processing completions (6.0+).
    const COOP_TASKRUN = 1 << 8;
    /// Single-issuer hint (5.18+).
    const SINGLE_ISSUER = 1 << 12;
    /// Defer task-run work to `io_uring_enter` — biggest latency win on 6.1+.
    const DEFER_TASKRUN = 1 << 13;
    /// Don't mmap the rings; user provides the memory.
    const NO_MMAP = 1 << 14;
    /// Abolish the indirection SQ array; kernel reads SQEs directly (6.6+).
    const NO_SQARRAY = 1 << 16;
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
