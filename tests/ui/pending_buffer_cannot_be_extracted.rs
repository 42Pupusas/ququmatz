use ququmatz::owned::{MmapBuffer, Prepared};
use ququmatz::{IoUring, types::RawFd};

fn main() {
    let ring = IoUring::new(4).expect("ring");
    let (mut sub, _comp) = ring.split_owned().ok().expect("split");
    let buf = MmapBuffer::with_capacity(32).expect("map");
    let ticket = sub
        .push(Prepared::write(RawFd::from_raw(1), buf, 0))
        .ok()
        .expect("push");

    // Reclaiming storage without a receipt must not be possible safely.
    let _buf = ticket.into_buffer();
}
