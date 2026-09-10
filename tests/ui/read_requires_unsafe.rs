use ququmatz::{RawFd, Sqe};

fn main() {
    let mut buf = [0u8; 8];
    let _sqe = Sqe::read(RawFd::from_raw(0), &mut buf, 0);
}
