//! Types for `IORING_OP_WAITID`: async `waitid(2)`.

bitflags! {
    /// Options controlling which child state changes `waitid` reports,
    /// mirroring the flags accepted by the `waitid(2)` syscall.
    ///
    /// At least one of `EXITED`, `UNTRACED`, or `CONTINUED` must be set, or
    /// the kernel rejects the request with `EINVAL` — there being nothing
    /// left to report otherwise.
    pub struct WaitOptions(u32);
    /// Do not block if no matching child has changed state yet; complete
    /// at once with a `0` result and no useful state instead.
    const NOHANG = 0x0000_0001;
    /// Report children that have stopped due to a signal.
    const UNTRACED = 0x0000_0002;
    /// Report children that have exited.
    const EXITED = 0x0000_0004;
    /// Report children that were resumed by `SIGCONT`.
    const CONTINUED = 0x0000_0008;
    /// Leave the reported child reapable: its state is reported but it is
    /// not removed from the process table, so a later `waitid` can see it
    /// again.
    const NOWAIT = 0x0100_0000;
}

/// Which children a `waitid` selects, mirroring `idtype_t`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum IdType {
    /// Any child; the id is ignored.
    All = 0,
    /// The single child whose pid is the given id.
    Pid = 1,
    /// Every child in the process group named by the given id.
    Pgid = 2,
    /// The child referenced by the pidfd named by the given id.
    PidFd = 3,
}

impl IdType {
    /// The raw kernel value.
    #[must_use]
    pub const fn as_raw(self) -> u32 {
        self as u32
    }
}

/// How a reported child's state changed, decoded from `si_code`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildEvent {
    /// The child exited normally (`CLD_EXITED`); `si_status` is its exit code.
    Exited,
    /// The child was killed by a signal (`CLD_KILLED`); `si_status` is the signal.
    Killed,
    /// The child was killed by a signal and dumped core (`CLD_DUMPED`).
    Dumped,
    /// A traced child hit a trap (`CLD_TRAPPED`).
    Trapped,
    /// The child stopped due to a signal (`CLD_STOPPED`).
    Stopped,
    /// A stopped child was resumed by `SIGCONT` (`CLD_CONTINUED`).
    Continued,
    /// A code this crate does not name.
    Other(i32),
}

impl ChildEvent {
    /// Decode a raw `si_code` value.
    #[must_use]
    pub const fn from_code(code: i32) -> Self {
        match code {
            1 => Self::Exited,
            2 => Self::Killed,
            3 => Self::Dumped,
            4 => Self::Trapped,
            5 => Self::Stopped,
            6 => Self::Continued,
            other => Self::Other(other),
        }
    }
}

/// The kernel's `siginfo_t`-shaped result for a reaped child.
///
/// The kernel writes to this destination through
/// `user_write_access_begin(infop, sizeof(*infop))`, and `sizeof(*infop)`
/// is `sizeof(siginfo_t)` — 128 bytes, `SI_MAX_SIZE` — regardless of how
/// many of those bytes a `SIGCHLD` report actually fills. So the
/// destination must be at least that large even though only the seven
/// fields below are ever written; the difference is reserved padding this
/// crate never reads. Their offsets match glibc's `siginfo_t` exactly, so
/// the fields the kernel writes land where they are declared here.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct WaitidSiginfo {
    pub si_signo: i32,
    pub si_errno: i32,
    pub si_code: i32,
    _pad0: i32,
    pub si_pid: i32,
    pub si_uid: u32,
    pub si_status: i32,
    _reserved: [u8; 100],
}

impl Default for WaitidSiginfo {
    fn default() -> Self {
        // SAFETY: every field is an integer primitive or an array of one,
        // so the all-zero bit pattern is a valid value.
        unsafe { core::mem::zeroed() }
    }
}

impl WaitidSiginfo {
    /// How the reported child's state changed.
    #[must_use]
    pub const fn event(&self) -> ChildEvent {
        ChildEvent::from_code(self.si_code)
    }
}
