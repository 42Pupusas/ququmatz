use ququmatz::{DirFd, FileMode, OpenFlags, Sqe};

fn main() {
    let path = c"/tmp/example";
    let _sqe = Sqe::openat(DirFd::Cwd, path, OpenFlags::default(), FileMode::default());
}
