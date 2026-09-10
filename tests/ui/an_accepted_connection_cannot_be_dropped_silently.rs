// An accepted connection is owned, not borrowed, so no lifetime can force
// the caller to deal with it — dropping a `Socket` is legal and closes it.
// What the API can guarantee is that ignoring a completion is never silent.
// This denies the lint rather than relying on it being an error by default,
// which is exactly the strength of the claim: it is diagnosable, not
// prevented.
#![deny(unused_must_use)]

use ququmatz::owned::{Event, MultishotAccept};

fn ignore_the_result(ticket: &mut MultishotAccept, event: Event) {
    ticket.record(event);
}

fn main() {}
