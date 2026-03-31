use core::fmt;

/// An error from a Linux syscall, wrapping a raw errno value.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Error(pub(crate) i32);

impl Error {
    pub const EPERM: Self = Self(1);
    pub const ENOENT: Self = Self(2);
    pub const EINTR: Self = Self(4);
    pub const ENOMEM: Self = Self(12);
    pub const EACCES: Self = Self(13);
    pub const EFAULT: Self = Self(14);
    pub const EBUSY: Self = Self(16);
    pub const EINVAL: Self = Self(22);
    pub const ENOSYS: Self = Self(38);
    pub const EAGAIN: Self = Self(11);

    /// Returns the raw errno value.
    #[must_use]
    pub const fn raw(self) -> i32 {
        self.0
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Error(errno={})", self.0)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "os error {}", self.0)
    }
}

impl core::error::Error for Error {}
