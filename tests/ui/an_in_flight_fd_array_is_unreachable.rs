use ququmatz::owned::{MmapBuffer, PendingFilesUpdate};

// Type errors only. The `must_use` half of the guarantee lives in
// `a_files_update_ticket_must_be_kept.rs`, because an `E0599` here aborts
// compilation before the lint pass ever runs — a fixture mixing the two
// would "pass" while never exercising the lint at all.

fn read_the_array_in_flight(ticket: PendingFilesUpdate<MmapBuffer, 2>) {
    // The kernel may be walking these entries right now, so the published
    // array is readable before submission and after redemption, never in
    // between.
    let _ = ticket.published();
}

fn take_the_storage_in_flight(ticket: PendingFilesUpdate<MmapBuffer, 2>) {
    // Reclaiming without a receipt hands back storage whose address the
    // kernel still holds.
    let _ = ticket.into_store();
}

fn read_the_outcome_in_flight(ticket: PendingFilesUpdate<MmapBuffer, 2>) {
    // How much of the update took effect is not knowable until the CQE
    // that reports it has been reaped.
    let _ = ticket.update();
}

fn main() {}
