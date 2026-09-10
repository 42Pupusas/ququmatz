use ququmatz::owned::{MmapBuffer, PendingTimeout};

// Type errors only. The `must_use` half of the guarantee lives in
// `a_timeout_ticket_must_be_kept.rs`, because an `E0599` here aborts
// compilation before the lint pass ever runs — a fixture mixing the two
// would "pass" while never exercising the lint at all.

fn read_the_duration_in_flight(ticket: PendingTimeout<MmapBuffer>) {
    // The kernel may be copying these bytes right now, so the published
    // duration is readable before submission and after redemption, never
    // in between.
    let _ = ticket.published();
}

fn take_the_storage_in_flight(ticket: PendingTimeout<MmapBuffer>) {
    // Reclaiming without a receipt hands back storage whose address the
    // kernel still holds.
    let _ = ticket.into_store();
}

fn main() {}
