#![deny(unused_must_use)]

use ququmatz::owned::{MmapBuffer, OwnedSubmitter, PreparedConnect};

// Nothing here is a type error, so the file reaches the lint pass. That
// matters: an `E0599` earlier in the file would abort compilation before
// `unused_must_use` ever ran, and the fixture would "pass" without
// exercising the guarantee it claims.

fn discard_a_connect_ticket(sub: &mut OwnedSubmitter, request: PreparedConnect<MmapBuffer>) {
    // Dropping the ticket leaks the address storage rather than freeing
    // it underneath a kernel that may still be reading it. The socket
    // does not go with it — `connect` borrows the descriptor — but the
    // outcome is lost, and "connection refused" is an ordinary result of
    // nothing listening rather than a bug. That is the safe failure, but
    // it is silent, so it must at least be diagnosed.
    sub.push_connect(request);
}

fn main() {}
