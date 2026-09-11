//! Flags and outcomes for `IORING_OP_ASYNC_CANCEL`.

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
