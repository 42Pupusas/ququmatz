use ququmatz::owned::{MmapBuffer, PendingConnect};

// Type errors only. The `must_use` half of the guarantee lives in
// `a_connect_ticket_must_be_kept.rs`, because an `E0599` here aborts
// compilation before the lint pass ever runs — a fixture mixing the two
// would "pass" while never exercising the lint at all.

fn read_the_address_in_flight(ticket: PendingConnect<MmapBuffer>) {
    // The kernel may be reading these bytes right now: the copy happens
    // inside `io_uring_enter`, and under SQPOLL no call's return proves
    // it has happened yet.
    let _ = ticket.published();
}

fn take_the_storage_in_flight(ticket: PendingConnect<MmapBuffer>) {
    // Reclaiming without a receipt hands back storage whose address the
    // kernel still holds.
    let _ = ticket.into_store();
}

fn read_the_outcome_in_flight(ticket: PendingConnect<MmapBuffer>) {
    // Whether the socket is connected is not knowable until the CQE that
    // reports it has been reaped: io_uring arms a poll and retries, so
    // the answer arrives only once the handshake has resolved.
    let _ = ticket.outcome();
}

fn main() {}
