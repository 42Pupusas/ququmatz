//! splice/tee flags.

bitflags! {
    /// Flags for `IORING_OP_SPLICE` and `IORING_OP_TEE`.
    pub struct SpliceFlags(u32);
    /// Move pages instead of copying (best-effort).
    const MOVE = 1;
    /// Don't block if the pipe is full/empty.
    const NONBLOCK = 2;
    /// Hint that more data will follow (like `MSG_MORE`).
    const MORE = 4;
    /// The source fd is a fixed (registered) fd.
    const FD_IN_FIXED = 1 << 31;
}
