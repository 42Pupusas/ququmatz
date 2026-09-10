use ququmatz::owned::{MmapBuffer, PendingRecvmsg};

// Type errors only. The `must_use` half of the guarantee lives in
// `a_recvmsg_ticket_must_be_kept.rs`, because an `E0599` here aborts
// compilation before the lint pass ever runs — a fixture mixing the two
// would "pass" while never exercising the lint at all.

fn read_the_header_in_flight(ticket: PendingRecvmsg<MmapBuffer, MmapBuffer, 2>) {
    // Worse than the send side: the kernel is *writing* this header, so
    // reading it in flight races a write rather than merely observing one.
    let _ = ticket.published_header();
}

fn read_the_peer_in_flight(ticket: PendingRecvmsg<MmapBuffer, MmapBuffer, 2>) {
    // The address slot is the kernel's destination too, and the length
    // that says whether it holds a whole address is not written yet.
    let _ = ticket.peer();
}

fn borrow_the_buffers_in_flight(ticket: PendingRecvmsg<MmapBuffer, MmapBuffer, 2>) {
    // The payload buffers are where the kernel is scattering the message.
    let _ = ticket.buffers();
}

fn take_every_storage_in_flight(ticket: PendingRecvmsg<MmapBuffer, MmapBuffer, 2>) {
    // Reclaiming without a receipt hands back the staging region whose
    // address the kernel still holds, along with the buffers its
    // descriptors name.
    let _ = ticket.into_parts();
}

fn main() {}
