use core::fmt;

/// Raw kernel errno value.
///
/// Wraps the `i32` returned by Linux syscalls when they fail. Keeps the raw
/// number so unknown errnos round-trip; named associated constants are
/// provided for the values this crate or its callers commonly match against.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Errno(pub(crate) i32);

impl Errno {
    /// `ENOENT` — no such file or directory.
    pub const ENOENT: Self = Self(2);
    /// `EAGAIN` — resource temporarily unavailable / try again.
    pub const EAGAIN: Self = Self(11);
    /// `EINVAL` — invalid argument.
    pub const EINVAL: Self = Self(22);

    /// Returns the raw errno value.
    #[must_use]
    pub const fn raw(self) -> i32 {
        self.0
    }
}

impl fmt::Debug for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Errno({})", self.0)
    }
}

impl fmt::Display for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "os error {}", self.0)
    }
}

/// Caller-supplied argument that violates a precondition of a setup call.
///
/// These are programmer errors detected before any kernel interaction —
/// they are not synthesized errnos.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub enum InvalidArgKind {
    /// A buffer count argument was zero.
    BufferCountZero,
    /// A buffer size argument was zero.
    BufferSizeZero,
    /// A buffer count argument was not a power of two.
    BufferCountNotPowerOfTwo,
}

impl fmt::Display for InvalidArgKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferCountZero => f.write_str("buffer count must be non-zero"),
            Self::BufferSizeZero => f.write_str("buffer size must be non-zero"),
            Self::BufferCountNotPowerOfTwo => f.write_str("buffer count must be a power of two"),
        }
    }
}

/// Error from pushing or submitting work to the ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmitError {
    /// The submission queue is full; drain completions and retry.
    QueueFull,
    /// `io_uring_enter` (or a related syscall) failed.
    Syscall(Errno),
}

impl fmt::Display for SubmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QueueFull => f.write_str("submission queue is full"),
            Self::Syscall(e) => write!(f, "submit syscall failed: {e}"),
        }
    }
}

/// Error from waiting on or interpreting a completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletionError {
    /// No completion was available when one was expected.
    NoCompletion,
    /// The kernel reported a negative errno inside the CQE.
    Failed(Errno),
}

impl fmt::Display for CompletionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCompletion => f.write_str("no completion available"),
            Self::Failed(e) => write!(f, "operation failed: {e}"),
        }
    }
}

/// Error from setting up or registering ring resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupError {
    /// A caller-supplied argument violated a precondition.
    InvalidArg(InvalidArgKind),
    /// `io_uring_setup`, `mmap`, `io_uring_register`, etc. failed.
    Syscall(Errno),
}

impl fmt::Display for SetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArg(k) => write!(f, "invalid argument: {k}"),
            Self::Syscall(e) => write!(f, "setup syscall failed: {e}"),
        }
    }
}

/// Top-level crate error.
///
/// Use this at API boundaries that compose multiple failure modes. Internal
/// modules return their narrower types ([`SubmitError`], [`CompletionError`],
/// [`SetupError`]) and rely on the `From` impls below for `?` propagation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A submission-side failure ([`SubmitError`]).
    Submit(SubmitError),
    /// A completion-side failure ([`CompletionError`]).
    Completion(CompletionError),
    /// A setup or registration failure ([`SetupError`]).
    Setup(SetupError),
    /// A leaf-helper syscall (e.g. `inotify_add_watch`, `eventfd` read,
    /// `Socket::send`) returned a kernel errno.
    Syscall(Errno),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Submit(e) => fmt::Display::fmt(e, f),
            Self::Completion(e) => fmt::Display::fmt(e, f),
            Self::Setup(e) => fmt::Display::fmt(e, f),
            Self::Syscall(e) => write!(f, "syscall failed: {e}"),
        }
    }
}

impl core::error::Error for Errno {}
impl core::error::Error for SubmitError {}
impl core::error::Error for CompletionError {}
impl core::error::Error for SetupError {}
impl core::error::Error for Error {}

impl From<SubmitError> for Error {
    fn from(e: SubmitError) -> Self {
        Self::Submit(e)
    }
}
impl From<CompletionError> for Error {
    fn from(e: CompletionError) -> Self {
        Self::Completion(e)
    }
}
impl From<SetupError> for Error {
    fn from(e: SetupError) -> Self {
        Self::Setup(e)
    }
}

impl From<Errno> for Error {
    fn from(e: Errno) -> Self {
        Self::Syscall(e)
    }
}
