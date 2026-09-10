use ququmatz::{RawFd, Sqe};

fn main() {
    let addr = [0u8; 16];
    let _sqe = Sqe::connect(RawFd::from_raw(0), &addr);
}
