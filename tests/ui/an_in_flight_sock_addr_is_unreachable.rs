use ququmatz::owned::{MmapBuffer, PendingBind};

// Type errors only. The `must_use` half of the guarantee lives in
// `a_bind_ticket_must_be_kept.rs`, because an `E0599` here aborts
// compilation before the lint pass ever runs — a fixture mixing the two
// would "pass" while never exercising the lint at all.

fn read_the_address_in_flight(ticket: PendingBind<MmapBuffer>) {
    // The kernel may be reading these bytes right now: the copy happens
    // inside `io_uring_enter`, and under SQPOLL no call's return proves
    // it has happened yet.
    let _ = ticket.published();
}

fn take_the_storage_in_flight(ticket: PendingBind<MmapBuffer>) {
    // Reclaiming without a receipt hands back storage whose address the
    // kernel still holds.
    let _ = ticket.into_store();
}

fn read_the_outcome_in_flight(ticket: PendingBind<MmapBuffer>) {
    // Whether the socket is bound is not knowable until the CQE that
    // reports it has been reaped.
    let _ = ticket.outcome();
}

fn main() {}
