use ququmatz::owned::{MmapBuffer, PendingStatx};

fn peek(ticket: &PendingStatx<MmapBuffer, MmapBuffer>) {
    // The kernel writes a whole `Statx` through this pointer until the
    // completion arrives, so an in-flight ticket exposes no view of it.
    // Reading it early would race a write this process cannot observe.
    let _ = ticket.stat();
}

fn borrow_path(ticket: &PendingStatx<MmapBuffer, MmapBuffer>) {
    // The path is being scanned for its terminator at the same time, so it
    // is unreachable for the same reason.
    let _ = ticket.path();
}

fn extract(ticket: PendingStatx<MmapBuffer, MmapBuffer>) {
    // Neither storage comes back without a receipt: the destination write
    // is fixed-size and unbounded by anything in the SQE, so freeing it
    // early is a write into memory this process has handed away.
    let _ = ticket.into_parts();
}

fn main() {}
