//! Timespec and timeout flags.

/// Kernel timespec for timeout operations.
///
/// Fields are private to enforce the nanosecond range invariant
/// (`0 <= tv_nsec < 1_000_000_000`). Use [`new`](Self::new) or
/// [`from_millis`](Self::from_millis) to construct.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

impl Timespec {
    /// Create a timespec from seconds and nanoseconds.
    ///
    /// # Panics
    ///
    /// Panics if `nsec` is not in `0..1_000_000_000`.
    #[must_use]
    pub const fn new(sec: i64, nsec: i64) -> Self {
        assert!(
            nsec >= 0 && nsec < 1_000_000_000,
            "nsec out of range 0..1_000_000_000"
        );
        Self {
            tv_sec: sec,
            tv_nsec: nsec,
        }
    }

    /// Create a timespec from milliseconds.
    #[must_use]
    #[allow(clippy::cast_possible_wrap)]
    pub const fn from_millis(ms: u64) -> Self {
        Self::new((ms / 1000) as i64, ((ms % 1000) * 1_000_000) as i64)
    }

    /// Returns the seconds component.
    #[must_use]
    pub const fn tv_sec(&self) -> i64 {
        self.tv_sec
    }

    /// Returns the nanoseconds component (always in `0..1_000_000_000`).
    #[must_use]
    pub const fn tv_nsec(&self) -> i64 {
        self.tv_nsec
    }
}

bitflags! {
    /// Flags for timeout operations.
    pub struct TimeoutFlags(u32);
    /// Use an absolute timeout instead of relative.
    const ABS = 1 << 0;
}
