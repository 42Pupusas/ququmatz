use ququmatz::owned::{MmapBuffer, PendingEpollCtl};

// Type errors only. The `must_use` half of the guarantee lives in
// `an_epoll_ticket_must_be_kept.rs`, because an `E0599` here aborts
// compilation before the lint pass ever runs — a fixture mixing the two
// would "pass" while never exercising the lint at all.

fn read_the_event_in_flight(ticket: PendingEpollCtl<MmapBuffer>) {
    // The kernel may be reading these bytes right now. That is true even
    // for a `Del`, which reads nothing: the SQE carries no way to say
    // "this address will not be dereferenced".
    let _ = ticket.published();
}

fn take_the_storage_in_flight(ticket: PendingEpollCtl<MmapBuffer>) {
    // Reclaiming without a receipt hands back storage whose address the
    // kernel still holds.
    let _ = ticket.into_store();
}

fn read_the_outcome_in_flight(ticket: PendingEpollCtl<MmapBuffer>) {
    // Whether the registration changed is not knowable until the CQE that
    // reports it has been reaped.
    let _ = ticket.outcome();
}

fn main() {}
