//! Configuration builder for [`IoUring`].

use super::IoUring;
use crate::error::Error;
use crate::types::{IoUringParams, SetupFlags};

/// Builder for configuring an `io_uring` instance before creation.
///
/// ```no_run
/// # use ququmatz::IoUring;
/// let ring = IoUring::builder(32)
///     .cq_entries(64)
///     .clamp()
///     .build()
///     .expect("setup failed");
/// ```
pub struct IoUringBuilder {
    pub(super) entries: u32,
    pub(super) params: IoUringParams,
}

impl IoUringBuilder {
    /// Start building an `io_uring` with the given queue depth.
    ///
    /// # Panics
    ///
    /// Panics if `entries` is 0.
    #[must_use]
    pub fn new(entries: u32) -> Self {
        assert!(entries > 0, "io_uring entries must be > 0");
        Self {
            entries,
            params: IoUringParams::default(),
        }
    }

    /// Enable polled I/O completion mode.
    ///
    /// Instead of the kernel posting completions asynchronously (typically
    /// off an interrupt), it polls the device for completions only when
    /// asked — every call that would otherwise block for completions
    /// (`submit_and_wait`, `Completer::wait`) drives that poll because it
    /// already issues `io_uring_enter` with `GETEVENTS`. A plain `submit`
    /// with no wait does not reap anything: nothing arrives in the CQ
    /// until something asks the kernel to poll for it.
    ///
    /// Requires files opened with `O_DIRECT` for read/write opcodes, and a
    /// block device/driver that supports polling — most other opcodes
    /// (network I/O, timeouts, polling primitives) are not iopoll-capable
    /// and are rejected by the kernel on a ring created with this flag.
    #[must_use]
    pub const fn iopoll(mut self) -> Self {
        self.params.flags |= SetupFlags::IOPOLL.bits();
        self
    }

    /// Enable kernel-side SQ polling with the given idle timeout in milliseconds.
    ///
    /// When SQPOLL is active, the kernel polls the SQ for new entries without
    /// requiring `io_uring_enter` calls, reducing syscall overhead.
    #[must_use]
    pub const fn sqpoll(mut self, idle_ms: u32) -> Self {
        self.params.flags |= SetupFlags::SQPOLL.bits();
        self.params.sq_thread_idle = idle_ms;
        self
    }

    /// Pin the SQPOLL thread to a specific CPU.
    #[must_use]
    pub const fn sqpoll_cpu(mut self, cpu: u32) -> Self {
        self.params.flags |= SetupFlags::SQPOLL.bits() | SetupFlags::SQ_AFF.bits();
        self.params.sq_thread_cpu = cpu;
        self
    }

    /// Set a custom CQ ring size (must be >= SQ size).
    #[must_use]
    pub const fn cq_entries(mut self, n: u32) -> Self {
        self.params.flags |= SetupFlags::CQSIZE.bits();
        self.params.cq_entries = n;
        self
    }

    /// Clamp SQ/CQ sizes to kernel implementation limits instead of failing.
    #[must_use]
    pub const fn clamp(mut self) -> Self {
        self.params.flags |= SetupFlags::CLAMP.bits();
        self
    }

    /// Hint that only one thread will submit to this ring (5.18+).
    #[must_use]
    pub const fn single_issuer(mut self) -> Self {
        self.params.flags |= SetupFlags::SINGLE_ISSUER.bits();
        self
    }

    /// Enable cooperative task-run (6.0+).
    ///
    /// The kernel will not force preemption when processing completions,
    /// reducing latency at the cost of fairness under heavy load.
    #[must_use]
    pub const fn coop_taskrun(mut self) -> Self {
        self.params.flags |= SetupFlags::COOP_TASKRUN.bits();
        self
    }

    /// Enable deferred task-run (6.1+).
    ///
    /// Defers all task-work to `io_uring_enter`, giving the application full
    /// control over when completions are processed. Biggest latency win for
    /// single-threaded event loops. Implies `COOP_TASKRUN`.
    #[must_use]
    pub const fn defer_taskrun(mut self) -> Self {
        self.params.flags |= SetupFlags::DEFER_TASKRUN.bits() | SetupFlags::COOP_TASKRUN.bits();
        self
    }

    /// Attach to an existing `io_uring` workqueue (share its worker threads).
    #[must_use]
    pub const fn attach_wq(mut self, wq_fd: u32) -> Self {
        self.params.flags |= SetupFlags::ATTACH_WQ.bits();
        self.params.wq_fd = wq_fd;
        self
    }

    /// Create the ring disabled: it rejects `io_uring_enter` until
    /// [`IoUring::enable_rings`](crate::ring::IoUring::enable_rings) is
    /// called.
    ///
    /// This gives a caller a window to finish registering buffers, files,
    /// or other resources before any submitted request can execute against
    /// them.
    #[must_use]
    pub const fn r_disabled(mut self) -> Self {
        self.params.flags |= SetupFlags::R_DISABLED.bits();
        self
    }

    /// Keep submitting the rest of a batch even after one entry in the
    /// middle is rejected, instead of stopping at the first failure.
    ///
    /// Without this flag, [`IoUring::submit`](crate::ring::IoUring::submit)
    /// can report a short count that leaves later, otherwise-valid entries
    /// unsent until a further `submit` call retries them; with it, the
    /// kernel pushes through the whole batch in one pass regardless of any
    /// individual failure.
    #[must_use]
    pub const fn submit_all(mut self) -> Self {
        self.params.flags |= SetupFlags::SUBMIT_ALL.bits();
        self
    }

    /// Surface pending task-work through `IORING_SQ_TASKRUN` in the SQ
    /// ring's flags rather than requiring a kernel transition to discover
    /// it.
    ///
    /// Only meaningful combined with [`coop_taskrun`](Self::coop_taskrun) or
    /// [`defer_taskrun`](Self::defer_taskrun) — the kernel rejects this flag
    /// alone, so call one of those first (or let `defer_taskrun` set
    /// `COOP_TASKRUN` for you).
    #[must_use]
    pub const fn taskrun_flag(mut self) -> Self {
        self.params.flags |= SetupFlags::TASKRUN_FLAG.bits();
        self
    }

    /// Set raw setup flags directly.
    ///
    /// Accepts any bit, including ones this crate's ring mapping/parsing
    /// code does not implement (e.g. `NO_MMAP`, `NO_SQARRAY`, or an unnamed
    /// future flag). [`build`](Self::build) rejects those before the setup
    /// syscall runs, so an unsupported combination surfaces as an error
    /// here rather than as a corrupted ring later.
    #[must_use]
    pub const fn setup_flags(mut self, flags: SetupFlags) -> Self {
        self.params.flags |= flags.bits();
        self
    }

    /// Build the `io_uring` instance.
    ///
    /// # Errors
    ///
    /// Returns [`SetupError::InvalidArg`](crate::SetupError::InvalidArg)
    /// wrapping [`InvalidArgKind::UnsupportedSetupFlags`](crate::InvalidArgKind::UnsupportedSetupFlags)
    /// if any requested setup flag is not implemented by this crate's ring
    /// mapping/parsing code, and an error if the kernel rejects the
    /// parameters.
    pub fn build(mut self) -> Result<IoUring, Error> {
        IoUring::from_params(self.entries, &mut self.params)
    }
}
