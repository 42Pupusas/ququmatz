use ququmatz::owned::{MmapBuffer, Prepared};
use ququmatz::{IoUring, types::RawFd};

fn main() {
    let ring = IoUring::new(8).expect("ring");
    let (mut sub, mut comp) = ring.split_owned().ok().expect("split");

    let first = sub
        .push(Prepared::write(
            RawFd::from_raw(1),
            MmapBuffer::with_capacity(8).expect("map"),
            0,
        ))
        .ok()
        .expect("push");
    let second = sub
        .push(Prepared::write(
            RawFd::from_raw(1),
            MmapBuffer::with_capacity(8).expect("map"),
            0,
        ))
        .ok()
        .expect("push");
    sub.submit().expect("submit");

    let receipt = comp.wait_one().expect("completion");
    let _a = first.redeem(receipt);
    // One receipt authorizes exactly one redemption.
    let _b = second.redeem(receipt);
}
