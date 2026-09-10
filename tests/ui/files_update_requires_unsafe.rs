use ququmatz::Sqe;

fn main() {
    let fds = [3i32, 4, -1];
    let _sqe = Sqe::files_update(&fds, 0);
}
