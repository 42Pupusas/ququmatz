#![deny(unused_must_use)]

use ququmatz::owned::{MmapBuffer, OwnedSubmitter, PreparedOpenat2};

// Nothing here is a type error, so the file reaches the lint pass. That
// matters: an `E0599` earlier in the file would abort compilation before
// `unused_must_use` ever ran, and the fixture would "pass" without
// exercising the guarantee it claims.

fn discard_an_openat2_ticket(
    sub: &mut OwnedSubmitter,
    request: PreparedOpenat2<MmapBuffer, MmapBuffer>,
) {
    // Dropping the ticket leaks the path and the `open_how` rather than
    // freeing them underneath a kernel that may still be reading both,
    // and loses any descriptor the open produced. That is the safe
    // failure, but it is silent, so it must at least be diagnosed.
    sub.push_openat2(request);
}

fn main() {}
