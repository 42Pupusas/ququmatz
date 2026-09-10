use ququmatz::owned::{MmapBuffer, OwnedPath, PendingOpen};

fn peek(ticket: &PendingOpen<MmapBuffer>) {
    // The kernel is scanning these bytes for the terminator until the
    // completion arrives, so a `PendingOpen` exposes no accessor for them.
    let _ = ticket.path();
}

fn extract(ticket: PendingOpen<MmapBuffer>) {
    // Nor can the storage be taken back without a receipt: freeing it while
    // the kernel resolves the path is a use-after-free, and unlike a length
    // -bounded read there is nothing to stop the scan early.
    let _ = ticket.into_path();
}

fn rewrite(path: &mut OwnedPath<MmapBuffer>) {
    // An `OwnedPath` proved a NUL lies inside its storage. Handing out a
    // mutable view would let that byte be overwritten, so the proof would
    // no longer hold for the value that carries it.
    let _ = path.as_mut_slice();
}

fn main() {}
