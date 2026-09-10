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

/// Vectored I/O hands the kernel two things to hold: the buffers, and the
/// `iovec` array naming them. Neither may be reachable while the request is
/// in flight, and neither may be reclaimed without a receipt — freeing the
/// array strands the kernel just as surely as freeing a buffer.
#[test]
fn vectored_storage_is_unreachable_until_redeemed() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/vectored_buffers_are_unreachable_in_flight.rs");
}

/// An open is bounded by a NUL rather than by a length, so the terminator
/// is the only thing standing between the kernel and a walk off the end of
/// the allocation. Two things follow: the path must be unreachable while
/// the request is in flight, like any other in-flight buffer, and an
/// `OwnedPath` must not hand out a mutable view of bytes whose NUL is the
/// proof it carries.
#[test]
fn an_in_flight_path_cannot_be_read_or_rewritten() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/an_in_flight_path_is_unreachable.rs");
}

/// A direct accept produces a table slot, not a connection this process
/// owns, and an exhausted table *ends* the request rather than refusing one
/// connection. Both facts have to be type errors rather than conventions:
/// there is no `Socket` to extract, the terminal outcome cannot be reduced
/// to a receipt without surrendering any folded slot, and an ignored
/// completion is diagnosable.
#[test]
fn a_direct_accept_yields_slots_and_cannot_silently_stop() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/a_direct_accept_slot_is_not_a_connection.rs");
}

/// A `statx` is the only owned request where the kernel *writes* a
/// fixed-size struct into caller storage, with no length anywhere in the
/// SQE to bound it. Both regions it touches — the path it scans and the
/// destination it fills — must therefore be unreachable while in flight,
/// and neither reclaimable without a receipt.
#[test]
fn an_in_flight_statx_touches_two_regions_and_exposes_neither() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/an_in_flight_statx_destination_is_unreachable.rs");
}

/// A direct open produces a third kind of resource: a slot in the ring's
/// file table, which is neither a borrowed pool buffer nor a descriptor
/// this process owns. The distinction has to be a type error rather than a
/// convention, because the three are released in three different ways —
/// recycled, closed, or handed back to the ring.
#[test]
fn a_table_slot_cannot_be_mistaken_for_a_descriptor() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/a_direct_slot_is_not_a_descriptor.rs");
}

/// A direct socket owns no memory at all, so unlike every other ticket
/// there is nothing for the compiler to protect from the kernel. What is
/// still at stake is the record of the slot: the ticket and the completion
/// are the only things that name it, and an explicit target closes
/// whatever file it replaces, so discarding either loses a live socket in
/// the ring's table.
#[test]
fn a_direct_socket_slot_cannot_be_silently_discarded() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/a_direct_socket_slot_must_be_recorded.rs");
}

/// A rename is the first owned request that publishes *two* path
/// addresses, so there are two regions the kernel scans and two that must
/// stay unreachable until a receipt proves it has stopped. Dropping either
/// ticket leaks rather than corrupting, which is the safe failure — but it
/// is silent, so it has to be diagnosed rather than merely permitted.
#[test]
fn in_flight_rename_paths_are_unreachable_and_not_silently_dropped() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/an_in_flight_rename_path_is_unreachable.rs");
    t.compile_fail("tests/ui/a_rename_ticket_must_be_kept.rs");
}

/// An `openat2` is the only owned request whose *parameters* live in
/// caller memory: the kernel reads an `open_how` to learn what to open, as
/// well as the path. So two regions must stay unreachable until a receipt
/// proves the kernel has stopped, and an abandoned ticket loses both plus
/// any descriptor the open produced — silent, and therefore diagnosed.
#[test]
fn an_in_flight_openat2_hides_both_regions_and_is_not_silently_dropped() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/an_in_flight_open_how_is_unreachable.rs");
    t.compile_fail("tests/ui/an_openat2_ticket_must_be_kept.rs");
}

/// A `sendmsg` is the first owned request where the addresses the kernel
/// dereferences are not in the SQE at all: they are *bytes inside a struct*
/// in caller memory, which the kernel reads to find the descriptor array
/// and the destination, then follows to reach the data. Three levels, three
/// regions, none of them reachable while in flight and none reclaimable
/// without a receipt — and an abandoned ticket loses all of it silently, so
/// it has to be diagnosed.
#[test]
fn an_in_flight_message_hides_every_region_it_chains_together() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/an_in_flight_message_header_is_unreachable.rs");
    t.compile_fail("tests/ui/a_sendmsg_ticket_must_be_kept.rs");
}

/// A `recvmsg` chains the same three regions as a `sendmsg` and adds a
/// direction: the kernel *writes* the header as well as reading it, so the
/// staging region is a destination and not merely a description. Reading
/// any of it in flight races a kernel write rather than observing a
/// finished one, and the peer address in particular is meaningless until
/// the length beside it has been written.
#[test]
fn an_in_flight_received_message_hides_what_the_kernel_is_writing() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/an_in_flight_received_message_is_unreachable.rs");
    t.compile_fail("tests/ui/a_recvmsg_ticket_must_be_kept.rs");
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
