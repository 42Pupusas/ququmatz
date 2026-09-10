use ququmatz::owned::{Event, MultishotRecv};
use ququmatz::BufferConsumer;

fn two_at_once(
    ticket: &MultishotRecv,
    first_event: Event,
    second_event: Event,
    pool: &mut BufferConsumer,
) {
    let first = ticket.record(first_event, pool);
    // The pool is still mutably borrowed by `first`. Taking a second
    // arrival now would put two live slot guards over one pool, so which
    // slot is recycled when would follow drop order rather than the
    // caller's intent.
    let second = ticket.record(second_event, pool);
    drop(first);
    drop(second);
}

fn main() {}
