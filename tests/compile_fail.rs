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
