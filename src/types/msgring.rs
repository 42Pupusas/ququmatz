//! Flags for `IORING_OP_MSG_RING`.

bitflags! {
    /// Flags for `IORING_OP_MSG_RING`, carried in the SQE's `msg_ring_flags`
    /// (the `op_flags` field).
    pub struct MsgRingFlags(u32);
    /// Do not post a CQE to the target ring for this message.
    ///
    /// Meaningless for a plain data message — the whole point is the CQE
    /// arriving on the other side — but relevant when [`Sqe::msg_ring_fd`]
    /// is used purely to hand over a descriptor and the sender does not
    /// want the target woken.
    const CQE_SKIP = 1 << 0;
    /// Pass explicit CQE flags through to the target's completion, as set
    /// by [`Sqe::msg_ring_cqe_flags`]. Set automatically by that
    /// constructor; exposed for callers building the SQE by hand.
    const FLAGS_PASS = 1 << 1;
}
