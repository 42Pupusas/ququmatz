//! Flags and outcomes for `IORING_OP_ASYNC_CANCEL`, and the argument for
//! its synchronous register-level sibling `IORING_REGISTER_SYNC_CANCEL`.

use super::buffers::RawFd;
use super::opcodes::Opcode;
use super::timeout::Timespec;
use crate::error::Errno;

bitflags! {
    /// Flags for `IORING_OP_ASYNC_CANCEL`, carried in the SQE's `op_flags`.
    ///
    /// The key a cancellation matches against — `user_data`, an `fd`, or
    /// "any request" — is chosen by which [`Sqe`](crate::Sqe) constructor
    /// built the request ([`Sqe::cancel`](crate::Sqe::cancel),
    /// [`Sqe::cancel_fd`](crate::Sqe::cancel_fd),
    /// [`Sqe::cancel_any`](crate::Sqe::cancel_any)), which set the matching
    /// bit (`FD`/`ANY`) automatically. These flags are the tunables that
    /// compose with any of those: cancel everything that matches instead of
    /// just the first hit, or treat the `fd` as a registered index.
    pub struct CancelFlags(u32);
    /// Cancel every request that matches the key, not just the first
    /// found. The cancel CQE's result becomes the number cancelled.
    const ALL = 1 << 0;
    /// Match requests by `fd` instead of `user_data`. Set automatically by
    /// [`Sqe::cancel_fd`](crate::Sqe::cancel_fd) — exposed for callers
    /// building a cancel SQE by hand.
    const FD = 1 << 1;
    /// Cancel any single request, ignoring the usual key entirely. Set
    /// automatically by [`Sqe::cancel_any`](crate::Sqe::cancel_any).
    const ANY = 1 << 2;
    /// The `fd` given is a registered/fixed file index rather than a
    /// regular descriptor. Combine with [`Sqe::cancel_fd`](crate::Sqe::cancel_fd).
    const FD_FIXED = 1 << 3;
    /// Match on `user_data` explicitly. This is the default key when
    /// neither `FD` nor `ANY` is set, so this bit is rarely needed.
    const USERDATA = 1 << 4;
    /// Also require the original request's opcode to match. Combine with
    /// [`Sqe::cancel_matching_opcode`](crate::Sqe::cancel_matching_opcode),
    /// which sets this bit together with the opcode value. Linux 6.6+.
    const OP = 1 << 5;
}

/// How an `IORING_OP_ASYNC_CANCEL` request ended.
///
/// Cancellation is inherently racy — the target may complete, fail, or
/// already be past the point of no return between submitting the cancel
/// and the kernel processing it — so the two informative failures are
/// named rather than folded into a generic error, the same way
/// [`EpollOutcome`](crate::owned::EpollOutcome) separates registration
/// races from other failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelOutcome {
    /// A non-negative result. Without [`CancelFlags::ALL`] this is always
    /// `0` and means the single match was cancelled; with `ALL` it is the
    /// number of requests cancelled, which may legitimately be `0`.
    Applied(u32),
    /// `-ENOENT`: no request matched the given key.
    NotFound,
    /// `-EALREADY`: a match was found but was already completing, too
    /// late to cancel.
    AlreadyCompleting,
    /// The kernel rejected the request for another reason.
    Failed(Errno),
}

/// `-ENOENT`.
const ENOENT: i32 = -2;
/// `-EALREADY`.
const EALREADY: i32 = -114;

impl CancelOutcome {
    /// Classify a raw CQE result from a cancel request.
    #[must_use]
    #[allow(clippy::cast_sign_loss)]
    pub const fn from_raw(result: i32) -> Self {
        match result {
            ENOENT => Self::NotFound,
            EALREADY => Self::AlreadyCompleting,
            other if other < 0 => Self::Failed(Errno::new(-other)),
            other => Self::Applied(other as u32),
        }
    }

    /// Whether the request found and cancelled something.
    #[must_use]
    pub const fn is_applied(self) -> bool {
        matches!(self, Self::Applied(_))
    }
}

impl core::fmt::Display for CancelOutcome {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Applied(0) => f.write_str("cancelled"),
            Self::Applied(n) => write!(f, "cancelled {n} request(s)"),
            Self::NotFound => f.write_str("no matching request found"),
            Self::AlreadyCompleting => f.write_str("matching request was already completing"),
            Self::Failed(e) => write!(f, "cancel failed: {e}"),
        }
    }
}

/// A `struct __kernel_timespec`-shaped pair the kernel reads for
/// `IORING_REGISTER_SYNC_CANCEL`'s timeout.
///
/// [`Timespec`] cannot represent this: its nanosecond field forbids
/// negative values, but `tv_sec == -1 && tv_nsec == -1` is the kernel's
/// documented sentinel for "wait indefinitely", so "no timeout" needs its
/// own tiny raw representation rather than an invariant-violating
/// `Timespec`.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
struct RawTimeout {
    tv_sec: i64,
    tv_nsec: i64,
}

impl RawTimeout {
    /// `-1/-1`: wait as long as it takes.
    const NONE: Self = Self {
        tv_sec: -1,
        tv_nsec: -1,
    };
}

impl From<Timespec> for RawTimeout {
    fn from(ts: Timespec) -> Self {
        Self {
            tv_sec: ts.tv_sec(),
            tv_nsec: ts.tv_nsec(),
        }
    }
}

/// Which request `IORING_REGISTER_SYNC_CANCEL` targets — the same three
/// keys `IORING_OP_ASYNC_CANCEL` supports, resolved synchronously inside
/// the register syscall instead of through a submitted SQE and its own
/// completion.
#[derive(Debug, Clone, Copy)]
enum SyncCancelKey {
    UserData(u64),
    Fd(RawFd),
    Any,
}

/// Argument for [`IoUring::sync_cancel`](crate::IoUring::sync_cancel).
///
/// Builds the kernel's `io_uring_sync_cancel_reg` without exposing its
/// padding: every reserved byte the kernel rejects when nonzero
/// (`sc.pad`/`sc.pad2`) is zeroed by construction, so a caller cannot
/// accidentally trip `-EINVAL` by handing the kernel an uninitialized
/// struct.
#[derive(Debug, Clone, Copy)]
pub struct SyncCancelReg {
    key: SyncCancelKey,
    flags: CancelFlags,
    opcode: Option<Opcode>,
    timeout: Option<Timespec>,
}

impl SyncCancelReg {
    /// Cancel synchronously by the target's `user_data`.
    #[must_use]
    pub const fn user_data(target_user_data: u64, flags: CancelFlags) -> Self {
        Self {
            key: SyncCancelKey::UserData(target_user_data),
            flags,
            opcode: None,
            timeout: None,
        }
    }

    /// Cancel synchronously every in-flight request on `fd`.
    ///
    /// As with [`Sqe::cancel_fd`](crate::Sqe::cancel_fd), closing `fd`
    /// does not by itself cancel requests still using it.
    #[must_use]
    pub const fn fd(target: RawFd, flags: CancelFlags) -> Self {
        Self {
            key: SyncCancelKey::Fd(target),
            flags,
            opcode: None,
            timeout: None,
        }
    }

    /// Cancel synchronously any single in-flight request, ignoring
    /// `user_data` entirely.
    #[must_use]
    pub const fn any(flags: CancelFlags) -> Self {
        Self {
            key: SyncCancelKey::Any,
            flags,
            opcode: None,
            timeout: None,
        }
    }

    /// Narrow the match to only the given original opcode (Linux 6.6+).
    #[must_use]
    pub const fn matching_opcode(mut self, opcode: Opcode) -> Self {
        self.opcode = Some(opcode);
        self
    }

    /// Bound how long the kernel will wait once it has found a match that
    /// is already too late to cancel outright (`-EALREADY`) and is
    /// instead being waited out. Without this the kernel waits
    /// indefinitely; if the bound elapses first, [`IoUring::sync_cancel`]
    /// reports it through [`CancelOutcome::Failed`] carrying `-ETIME`.
    ///
    /// [`IoUring::sync_cancel`]: crate::ring::IoUring::sync_cancel
    #[must_use]
    pub const fn timeout(mut self, ts: Timespec) -> Self {
        self.timeout = Some(ts);
        self
    }

    /// Build the raw kernel argument.
    pub(crate) fn as_raw(&self) -> RawSyncCancelReg {
        let mut flags = self.flags;
        let (addr, fd) = match self.key {
            SyncCancelKey::UserData(target) => (target, 0),
            SyncCancelKey::Fd(target) => {
                flags |= CancelFlags::FD;
                (0, target.as_i32())
            }
            SyncCancelKey::Any => {
                flags |= CancelFlags::ANY;
                (0, 0)
            }
        };
        let opcode = self.opcode.map_or(0, |op| {
            flags |= CancelFlags::OP;
            u8::from(op)
        });
        RawSyncCancelReg {
            addr,
            fd,
            flags: flags.bits(),
            timeout: self.timeout.map_or(RawTimeout::NONE, RawTimeout::from),
            opcode,
            pad: [0; 7],
            pad2: [0; 3],
        }
    }
}

/// Raw `io_uring_sync_cancel_reg` argument, byte-for-byte.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct RawSyncCancelReg {
    addr: u64,
    fd: i32,
    flags: u32,
    timeout: RawTimeout,
    opcode: u8,
    pad: [u8; 7],
    pad2: [u64; 3],
}
