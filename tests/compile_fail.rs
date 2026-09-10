//! Compile-fail regression coverage for the crate's two safety boundaries.
//!
//! **Q-01** — every `Sqe` constructor that stores a pointer derived from
//! caller data must require an `unsafe` block to call, because the borrow it
//! takes does not extend to the returned `Sqe` (see `src/op/mod.rs`'s module
//! documentation). If one of those ever compiles without `unsafe`, the
//! containment fixed for Q-01 has regressed.
//!
//! **Owned requests** — the safe `owned` API's guarantees are only real if
//! the compiler enforces them. These pin that an in-flight buffer is
//! unreachable and unextractable, and that a `Receipt` can be neither forged
//! by safe code nor spent twice.
//!
//! **Non-terminal completions** — a CQE carrying `IORING_CQE_F_MORE`
//! promises more to come, so it cannot release anything: a `send_zc` buffer
//! stays live past its send CQE, and a multishot keeps using its request.
//! `PartialReceipt` must therefore not be usable where a release is
//! required. That separation is the whole safety argument for the type, and
//! it is a type error rather than a convention only if this keeps failing.

#[test]
fn pointer_bearing_constructors_require_unsafe() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/*_requires_unsafe.rs");
}

#[test]
fn in_flight_buffers_and_receipts_are_compiler_enforced() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/pending_*.rs");
    t.compile_fail("tests/ui/receipt_*.rs");
}

#[test]
fn a_partial_receipt_cannot_stand_in_for_a_terminal_one() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/partial_receipt_*.rs");
}

/// A multishot arrival borrows a pool slot rather than owning storage, and
/// recycles it on drop. Both halves of that have to be enforced: it must
/// not outlive the pool it will recycle into, and two must not be live at
/// once, or which slot goes back when would follow drop order instead of
/// the caller's intent.
#[test]
fn a_multishot_arrival_cannot_escape_or_alias_its_pool() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/arrival_cannot_outlive_its_pool.rs");
    t.compile_fail("tests/ui/two_arrivals_cannot_be_held_at_once.rs");
}

/// An accepted connection is owned rather than borrowed, so the compiler
/// cannot tie it to a pool the way it does an arrival. What it can do is
/// refuse to let the result be thrown away unread, which is the failure
/// that would leak a live descriptor.
#[test]
fn an_accepted_connection_cannot_be_discarded_unread() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/an_accepted_connection_cannot_be_dropped_silently.rs");
}
