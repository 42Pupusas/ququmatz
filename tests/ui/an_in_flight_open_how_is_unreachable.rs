use ququmatz::owned::{MmapBuffer, PendingOpenat2};

// Type errors only. The `must_use` half of the guarantee lives in
// `an_openat2_ticket_must_be_kept.rs`, because an `E0599` here aborts
// compilation before the lint pass ever runs — a fixture mixing the two
// would "pass" while never exercising the lint at all.

fn read_the_open_how_in_flight(ticket: PendingOpenat2<MmapBuffer, MmapBuffer>) {
    // The kernel reads the `open_how` to learn what to open, so it is
    // behind the ticket for the same reason the path is. Exposing it
    // would be a read of storage the kernel is using.
    let _ = ticket.published_how();
}

fn take_both_storages_in_flight(ticket: PendingOpenat2<MmapBuffer, MmapBuffer>) {
    // Reclaiming without a receipt would hand back two storages whose
    // addresses the kernel still holds.
    let _ = ticket.into_parts();
}

fn main() {}
