#![deny(unused_must_use)]

use ququmatz::owned::{MmapBuffer, OwnedSubmitter, PreparedSendmsg};

// Nothing here is a type error, so the file reaches the lint pass. That
// matters: an `E0599` earlier in the file would abort compilation before
// `unused_must_use` ever ran, and the fixture would "pass" without
// exercising the guarantee it claims.

fn discard_a_sendmsg_ticket(
    sub: &mut OwnedSubmitter,
    request: PreparedSendmsg<MmapBuffer, MmapBuffer, 2>,
) {
    // Dropping the ticket leaks the staging region and every buffer rather
    // than freeing them underneath a kernel that may still be reading the
    // header, following it to the descriptors, and following those to the
    // data. That is the safe failure, but it is silent, so it must at
    // least be diagnosed.
    sub.push_sendmsg(request);
}

fn main() {}
