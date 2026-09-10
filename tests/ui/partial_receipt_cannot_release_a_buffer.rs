use ququmatz::owned::{MmapBuffer, PartialReceipt, PendingZc};

fn takes_ticket(ticket: PendingZc<MmapBuffer>, notice: PartialReceipt) {
    // A zero-copy send's result CQE says how much was accepted, not that the
    // NIC has stopped reading. Redeeming with it would free live pages, so
    // the type system must refuse: `redeem` takes a `Receipt` only.
    let _completed = ticket.redeem(notice);
}

fn main() {}
