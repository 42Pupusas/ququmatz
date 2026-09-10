//! Compile-fail regression coverage for Q-01: every `Sqe` constructor that
//! stores a pointer derived from caller data must require an `unsafe` block
//! to call, because the borrow it takes does not extend to the returned
//! `Sqe` (see `src/op/mod.rs`'s module documentation for the full
//! rationale). If any of these ever compiles without `unsafe`, the safety
//! containment fixed for Q-01 has regressed.

#[test]
fn pointer_bearing_constructors_require_unsafe() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/*.rs");
}
