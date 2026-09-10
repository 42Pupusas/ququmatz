use ququmatz::owned::{MmapBuffer, PendingSendmsg};

// Type errors only. The `must_use` half of the guarantee lives in
// `a_sendmsg_ticket_must_be_kept.rs`, because an `E0599` here aborts
// compilation before the lint pass ever runs — a fixture mixing the two
// would "pass" while never exercising the lint at all.

fn read_the_header_in_flight(ticket: PendingSendmsg<MmapBuffer, MmapBuffer, 2>) {
    // The header's bytes are the addresses the kernel is about to
    // dereference, so it stays behind the ticket for the same reason the
    // buffers do.
    let _ = ticket.published_header();
}

fn read_a_descriptor_in_flight(ticket: PendingSendmsg<MmapBuffer, MmapBuffer, 2>) {
    // The descriptor array is a second region the kernel reaches by
    // following the header, and is equally off-limits while in flight.
    let _ = ticket.published_descriptor(0);
}

fn borrow_the_buffers_in_flight(ticket: PendingSendmsg<MmapBuffer, MmapBuffer, 2>) {
    // The buffers are the third level, named by descriptors the kernel is
    // reading.
    let _ = ticket.buffers();
}

fn take_every_storage_in_flight(ticket: PendingSendmsg<MmapBuffer, MmapBuffer, 2>) {
    // Reclaiming without a receipt would hand back the staging region
    // whose address the kernel still holds, along with the buffers its
    // descriptors name.
    let _ = ticket.into_parts();
}

fn main() {}
