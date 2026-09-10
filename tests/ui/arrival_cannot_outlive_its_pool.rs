use ququmatz::owned::{Arrival, Delivery, Event, MultishotRecv};
use ququmatz::BufferConsumer;

fn escape<'a>(
    ticket: &MultishotRecv,
    event: Event,
    pool: &mut BufferConsumer,
) -> Option<Arrival<'a>> {
    // An Arrival holds a pool slot the kernel is waiting to reuse, and
    // recycles it on drop. Letting one outlive the borrow of the pool would
    // leave it recycling into a pool that may already be gone, so the
    // borrow checker must refuse.
    match ticket.record(event, pool) {
        Ok(Delivery::Data(arrival)) => Some(arrival),
        _ => None,
    }
}

fn main() {}
