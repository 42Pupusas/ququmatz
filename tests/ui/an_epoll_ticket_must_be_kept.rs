#![deny(unused_must_use)]

use ququmatz::owned::{MmapBuffer, OwnedSubmitter, PreparedEpollCtl};

// Nothing here is a type error, so the file reaches the lint pass. That
// matters: an `E0599` earlier in the file would abort compilation before
// `unused_must_use` ever ran, and the fixture would "pass" without
// exercising the guarantee it claims.

fn discard_an_epoll_ticket(sub: &mut OwnedSubmitter, request: PreparedEpollCtl<MmapBuffer>) {
    // Dropping the ticket leaks the event storage rather than freeing it
    // underneath a kernel that may still be reading it. Neither descriptor
    // goes with it — `epoll_ctl` borrows both — but the outcome is lost,
    // and "already registered" is an ordinary result of racing another
    // thread rather than a bug. That is the safe failure, but it is
    // silent, so it must at least be diagnosed.
    sub.push_epoll_ctl(request);
}

fn main() {}
