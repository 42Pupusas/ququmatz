use ququmatz::{MsgFlags, RawFd, Sqe};

fn main() {
    let buf = [0u8; 8];
    let _sqe = Sqe::send(RawFd::from_raw(0), &buf, MsgFlags::default());
}
