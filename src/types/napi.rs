//! Argument and reported state for `IORING_REGISTER_NAPI` /
//! `IORING_UNREGISTER_NAPI` — busy-poll tuning for socket-bound rings.

/// Which busy-poll tracking strategy a caller may request via
/// [`IoUring::register_napi`](crate::ring::IoUring::register_napi).
///
/// `Dynamic` discovers each socket's NAPI id the first time the ring polls
/// it; `Static` instead only busy-polls NAPI ids the caller has explicitly
/// added with
/// [`IoUring::napi_add_static_id`](crate::ring::IoUring::napi_add_static_id).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum NapiTrackingStrategy {
    Dynamic = 0,
    Static = 1,
}

/// The busy-poll tracking state as the kernel reports it back.
///
/// Either one of the two strategies a caller can request, or `Inactive` if
/// NAPI tracking has never been registered on this ring (or was just
/// unregistered). `Inactive` has no `NapiTrackingStrategy` counterpart —
/// it is a report-only state the kernel names `255`, never something a
/// caller asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NapiTrackingMode {
    Dynamic,
    Static,
    Inactive,
}

impl NapiTrackingMode {
    const fn from_raw(raw: u32) -> Self {
        match raw {
            0 => Self::Dynamic,
            1 => Self::Static,
            _ => Self::Inactive,
        }
    }
}

/// A ring's NAPI busy-poll configuration, as reported by the kernel.
///
/// Both [`register_napi`](crate::ring::IoUring::register_napi) and
/// [`unregister_napi`](crate::ring::IoUring::unregister_napi) hand this
/// back describing the settings that were in effect *before* the call
/// took effect — the same before/after-swap contract the kernel's own
/// `struct io_uring_napi` argument carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NapiSettings {
    /// How long, in microseconds, a busy-poll loop is allowed to spin
    /// before giving up. The kernel caps this at 10,000 microseconds.
    pub busy_poll_timeout_usec: u32,
    /// If set, prefer NAPI busy polling over irq-driven completion even
    /// when it would not otherwise be attempted.
    pub prefer_busy_poll: bool,
    /// The tracking strategy currently in effect.
    pub tracking: NapiTrackingMode,
}

impl NapiSettings {
    pub(crate) const fn from_raw(raw: &RawNapi) -> Self {
        Self {
            busy_poll_timeout_usec: raw.busy_poll_to,
            prefer_busy_poll: raw.prefer_busy_poll != 0,
            tracking: NapiTrackingMode::from_raw(raw.op_param),
        }
    }
}

/// `io_uring_napi_op` — which action a `RawNapi` argument requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NapiOp {
    /// Backward-compatible register/unregister opcode: set the tracking
    /// strategy, busy-poll timeout, and busy-poll preference.
    Register = 0,
    /// Add a NAPI id to the static tracking list. Only valid once
    /// `Static` tracking has been registered.
    StaticAddId = 1,
    /// Remove a NAPI id from the static tracking list.
    StaticDelId = 2,
}

/// Raw `io_uring_napi` argument, byte-for-byte.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct RawNapi {
    pub busy_poll_to: u32,
    pub prefer_busy_poll: u8,
    pub opcode: u8,
    pub pad: [u8; 2],
    pub op_param: u32,
    pub resv: u32,
}

impl RawNapi {
    pub(crate) const fn register(
        busy_poll_timeout_usec: u32,
        prefer_busy_poll: bool,
        tracking: NapiTrackingStrategy,
    ) -> Self {
        Self {
            busy_poll_to: busy_poll_timeout_usec,
            prefer_busy_poll: prefer_busy_poll as u8,
            opcode: NapiOp::Register as u8,
            pad: [0; 2],
            op_param: tracking as u32,
            resv: 0,
        }
    }

    pub(crate) const fn static_id(op: NapiOp, napi_id: u32) -> Self {
        Self {
            busy_poll_to: 0,
            prefer_busy_poll: 0,
            opcode: op as u8,
            pad: [0; 2],
            op_param: napi_id,
            resv: 0,
        }
    }
}
