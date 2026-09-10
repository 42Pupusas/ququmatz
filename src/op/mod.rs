#![allow(clippy::cast_sign_loss, clippy::checked_conversions)]

//! Submission queue entry builder.
//!
//! `Sqe` is an opaque wrapper around the kernel `IoUringSqe` layout.
//! Constructors live in submodules grouped by kernel concern (file, net,
//! control, buffers, epoll). Modifiers (`user_data`, `link`, `with`, etc.)
//! live in this file.

use crate::types::{
    IORING_RECVSEND_FIXED_BUF, IORING_RECVSEND_POLL_FIRST, IORING_SEND_ZC_REPORT_USAGE, IoUringSqe,
    SendRecvFlag, SqeFlags,
};

mod buffers;
mod control;
mod epoll;
mod file;
mod net;

/// A prepared submission queue entry, ready to be pushed onto the ring.
///
/// Use the constructor methods to create an `Sqe` for a specific operation,
/// then chain modifiers like `user_data()` before pushing.
///
/// # Every pointer-bearing constructor is `unsafe`
///
/// `Sqe` carries no lifetime parameter — it is `Copy`, gets pushed into a
/// queue, and is read back by the kernel at an unspecified later point,
/// possibly after the constructor call (and any borrow it performed) has
/// long since ended. A constructor that accepts a slice or `&CStr` and
/// stores a raw pointer derived from it therefore cannot make the
/// resulting `Sqe` safe merely by taking a reference: the reference expires
/// at the end of the constructor call, not at the end of the operation.
///
/// Accordingly, **every constructor that stores a pointer to caller data**
/// — whether it takes a structured reference/slice/`&CStr` or a raw
/// pointer directly — is `unsafe fn`. The safety contract is the same for
/// both forms: the referenced memory must remain valid, exclusively owned
/// as required by the operation (readable for sources, writable for
/// destinations, not aliased by other live references), and unmoved until
/// the kernel has posted the completion (or, for multishot/zero-copy
/// operations, until the terminal completion that releases the buffer).
/// Structured-argument constructors are still worth using over the raw
/// `_ptr` twins — they prevent length mismatches and null-termination bugs
/// — but they do not remove the caller's obligation to uphold that
/// lifetime themselves.
///
/// A handful of constructors genuinely have no such obligation, because
/// they store no pointer at all (e.g. [`nop`](Self::nop), [`close`](Self::close),
/// [`fsync`](Self::fsync)) or because the pointer they store is opaque
/// `user_data`/`fd`/`id` correlation state rather than kernel-dereferenced
/// memory (e.g. [`cancel`](Self::cancel), [`poll_remove`](Self::poll_remove)).
/// Those remain safe `fn`s.
///
/// The [`IoUring::do_read`] family of methods builds its unsafe SQEs
/// internally and upholds this contract by borrowing the buffer across the
/// full submit-and-wait cycle — see that module's documentation for the
/// residual caveat about completion correlation.
#[derive(Clone, Copy, Debug)]
pub struct Sqe(pub(crate) IoUringSqe);

/// Create a zeroed SQE. All fields are integer primitives, so zero-init is
/// valid. This `const` lets the compiler inline it as an immediate, avoiding
/// a runtime `memset` on every builder call.
pub(crate) const ZEROED: IoUringSqe = unsafe { core::mem::zeroed() };

impl Sqe {
    /// Consume this builder and return the raw kernel SQE.
    ///
    /// Useful for lock-free protocols that write SQEs directly
    /// into the mmap'd SQE array.
    #[must_use]
    pub const fn into_inner(self) -> IoUringSqe {
        self.0
    }

    /// Construct an `Sqe` from a raw kernel SQE.
    ///
    /// # Safety
    ///
    /// `sqe` must be a completely valid submission for its `opcode`: every
    /// field the kernel reads for that opcode must be set correctly,
    /// including any `addr`/`off`/`splice_fd_in` fields that the kernel
    /// interprets as pointers. If any such pointer is set, the memory it
    /// references must remain valid, correctly sized, and exclusively
    /// owned as the operation requires until the kernel posts the
    /// completion. This constructor performs no validation at all — it is
    /// the least-checked way to build an `Sqe` and should be reserved for
    /// lock-free protocols that write the kernel layout directly.
    #[must_use]
    pub const unsafe fn from_raw(sqe: IoUringSqe) -> Self {
        Self(sqe)
    }

    // -----------------------------------------------------------------
    // SQE modifiers (chainable)
    // -----------------------------------------------------------------

    /// Set the `user_data` field, used to correlate completions with submissions.
    #[must_use]
    pub const fn user_data(mut self, data: u64) -> Self {
        self.0.user_data = data;
        self
    }

    /// Read back the `user_data` field.
    #[must_use]
    pub const fn get_user_data(&self) -> u64 {
        self.0.user_data
    }

    /// Add SQE flags (OR'd with any existing flags).
    #[must_use]
    pub const fn flags(mut self, flags: SqeFlags) -> Self {
        self.0.flags |= flags.bits();
        self
    }

    /// Link this SQE to the next one in the submission queue.
    ///
    /// If this operation fails, the linked successor is cancelled.
    #[must_use]
    pub const fn link(mut self) -> Self {
        self.0.flags |= SqeFlags::IO_LINK.bits();
        self
    }

    /// Hard-link this SQE to the next one.
    ///
    /// Like `link()`, but the chain continues executing even if this op fails.
    #[must_use]
    pub const fn hardlink(mut self) -> Self {
        self.0.flags |= SqeFlags::IO_HARDLINK.bits();
        self
    }

    /// Use a registered/fixed file descriptor for this SQE.
    ///
    /// The `fd` field is interpreted as an index into the registered file table.
    #[must_use]
    pub const fn fixed_file(mut self) -> Self {
        self.0.flags |= SqeFlags::FIXED_FILE.bits();
        self
    }

    /// Drain all prior submissions before executing this SQE.
    #[must_use]
    pub const fn drain(mut self) -> Self {
        self.0.flags |= SqeFlags::IO_DRAIN.bits();
        self
    }

    /// Suppress the CQE when this request succeeds (fire-and-forget).
    ///
    /// No completion is posted if the operation succeeds; a CQE is still
    /// posted on failure. Useful for write/send chains where you only care
    /// about errors, not byte counts.
    #[must_use]
    pub const fn cqe_skip_success(mut self) -> Self {
        self.0.flags |= SqeFlags::CQE_SKIP_SUCCESS.bits();
        self
    }

    /// Select a buffer from a registered provided-buffer ring.
    ///
    /// Sets the `IOSQE_BUFFER_SELECT` flag and stores `group_id` in the
    /// SQE's `buf_group` field (aliased with `buf_index`). On completion
    /// the kernel reports the chosen buffer id in the upper 16 bits of
    /// the CQE flags — use [`Completion::buffer_id`] to decode it.
    ///
    /// Only valid on operations that support buffer selection (notably
    /// `recv`, `read`, `recvmsg`).
    #[must_use]
    pub const fn buffer_select(mut self, group_id: u16) -> Self {
        self.0.flags |= SqeFlags::BUFFER_SELECT.bits();
        self.0.buf_index = group_id;
        self
    }

    /// Apply a [`SendRecvFlag`] tunable to a send/recv-family op.
    ///
    /// Composes — call multiple times to set several flags. See
    /// [`SendRecvFlag`] for which ops accept which variants.
    #[must_use]
    pub const fn with(mut self, flag: SendRecvFlag) -> Self {
        match flag {
            SendRecvFlag::PollFirst => self.0.ioprio |= IORING_RECVSEND_POLL_FIRST,
            SendRecvFlag::FixedBuf(idx) => {
                self.0.ioprio |= IORING_RECVSEND_FIXED_BUF;
                self.0.buf_index = idx;
            }
            SendRecvFlag::ReportUsage => self.0.ioprio |= IORING_SEND_ZC_REPORT_USAGE,
        }
        self
    }

    /// Run this op under a registered personality (credentials/capabilities).
    ///
    /// `id` is the personality id returned by `IORING_REGISTER_PERSONALITY`.
    /// The kernel will execute the op with the credentials of the registering
    /// task at registration time, regardless of the submitting task.
    #[must_use]
    pub const fn personality(mut self, id: u16) -> Self {
        self.0.personality = id;
        self
    }
}
