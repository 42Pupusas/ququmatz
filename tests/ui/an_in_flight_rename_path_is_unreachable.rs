use ququmatz::owned::{MmapBuffer, OwnedPath, PendingRename};

// Type errors only. The `must_use` half of the guarantee lives in
// `a_rename_ticket_must_be_kept.rs`, because an `E0599` here aborts
// compilation before the lint pass ever runs — a fixture mixing the two
// would "pass" while never exercising the lint at all.

fn read_a_path_in_flight(ticket: PendingRename<MmapBuffer, MmapBuffer>) {
    // Both paths are behind the ticket while the kernel scans them. A
    // rename publishes two addresses, so exposing either would be a read
    // of storage the kernel is using.
    //
    // Probed as a field rather than as `from()`: the call form collides with
    // `From::from` and drags a `core` snippet into the expected stderr, which
    // only renders where the `rust-src` component is installed.
    let _ = ticket.from;
}

fn take_a_path_in_flight(ticket: PendingRename<MmapBuffer, MmapBuffer>) {
    // Reclaiming without a receipt would hand back storage whose address
    // the kernel still holds.
    let _ = ticket.into_paths();
}

fn rewrite_a_verified_path(path: OwnedPath<MmapBuffer>) {
    // The NUL is the only bound on the kernel's scan, so an `OwnedPath`
    // never hands out a mutable view: writing over the terminator would
    // invalidate the proof the type carries.
    path.as_mut_slice();
}

fn main() {}
