//! Eventfd init flags.

bitflags! {
    /// Flags for `eventfd2`.
    pub struct EventFdFlags(i32);
    /// Set the file descriptor to non-blocking mode.
    const NONBLOCK = 0o4000;
    /// Set close-on-exec on the new file descriptor.
    const CLOEXEC = 0o2_000_000;
    /// Provide semaphore-like semantics: each `read` decrements by 1.
    const SEMAPHORE = 1;
}
