#![deny(unused_must_use)]

use ququmatz::owned::{DirectAccept, DirectIncoming, Event};

// Nothing here is a type error, so the file reaches the lint pass. That
// matters: an `E0599` earlier in the file would abort compilation before
// `unused_must_use` ever ran, and the fixture would "pass" without
// exercising the guarantee it claims.

fn ignore_a_completion(ticket: &mut DirectAccept, event: Event) {
    // An exhausted file table *ends* a direct accept rather than refusing a
    // single connection, so a dropped outcome is a listener that has
    // silently stopped accepting.
    ticket.record(event);
}

fn ignore_the_slot(incoming: DirectIncoming) {
    // A slot has no destructor that can release it — dropping one leaves
    // the connection installed until the ring dies.
    incoming.into_slot();
}

fn main() {}
