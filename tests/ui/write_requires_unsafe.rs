use ququmatz::{RawFd, Sqe};

fn main() {
    let buf = [0u8; 8];
    let _sqe = Sqe::write(RawFd::from_raw(0), &buf, 0);
}
