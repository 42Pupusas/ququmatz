use ququmatz::{Sqe, TimeoutFlags, Timespec};

fn main() {
    let ts = Timespec::from_millis(50);
    let _sqe = Sqe::timeout(&ts, 0, TimeoutFlags::default());
}
