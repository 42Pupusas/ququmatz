#![deny(unused_must_use)]

use ququmatz::owned::{MmapBuffer, OwnedSubmitter, PreparedTimeout};

// Nothing here is a type error, so the file reaches the lint pass. That
// matters: an `E0599` earlier in the file would abort compilation before
// `unused_must_use` ever ran, and the fixture would "pass" without
// exercising the guarantee it claims.

fn discard_a_timeout_ticket(sub: &mut OwnedSubmitter, request: PreparedTimeout<MmapBuffer>) {
    // Dropping the ticket leaks the timespec storage rather than freeing
    // it underneath a kernel that may not have copied the duration yet —
    // under SQPOLL the submitting thread never enters the kernel, so
    // nothing here can prove the copy has happened. That is the safe
    // failure, but it is silent, so it must at least be diagnosed.
    sub.push_timeout(request);
}

fn main() {}
