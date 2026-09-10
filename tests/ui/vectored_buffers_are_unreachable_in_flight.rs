use ququmatz::owned::{MmapBuffer, PendingVectored};

fn peek(ticket: &PendingVectored<MmapBuffer, MmapBuffer, 2>) {
    // The kernel may be writing into every one of these buffers until the
    // terminal completion, so a `PendingVectored` deliberately exposes no
    // accessor for them. Reading one would race the kernel.
    let _ = ticket.buffers();
}

fn extract(ticket: PendingVectored<MmapBuffer, MmapBuffer, 2>) {
    // Nor can the storage be taken back without a receipt: that would free
    // memory the kernel still holds a pointer into, including the iovec
    // array it reads to find the buffers.
    let _ = ticket.into_parts();
}

fn main() {}
