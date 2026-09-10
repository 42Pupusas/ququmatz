use ququmatz::fs::File;
use ququmatz::net::Socket;
use ququmatz::owned::{DirectOpened, MmapBuffer, PendingDirectOpen};

fn as_a_file(opened: DirectOpened<MmapBuffer>) -> Option<File> {
    // A direct open installs into the ring's file table and never gives
    // this process a descriptor, so there is no `File` to be had. The two
    // results are different resources with different releases: `close(2)`
    // for a descriptor, asking the ring for a slot.
    opened.into_file()
}

fn as_a_socket(opened: DirectOpened<MmapBuffer>) -> Option<Socket> {
    // And a slot is certainly not a socket.
    opened.into_socket()
}

fn peek(ticket: &PendingDirectOpen<MmapBuffer>) {
    // The kernel is scanning these bytes for the terminator until the
    // completion arrives, exactly as for an ordinary open.
    let _ = ticket.path();
}

fn extract(ticket: PendingDirectOpen<MmapBuffer>) {
    // And the storage cannot be taken back without a receipt.
    let _ = ticket.into_path();
}

fn main() {}
