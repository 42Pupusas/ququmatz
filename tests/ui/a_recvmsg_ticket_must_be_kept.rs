#![deny(unused_must_use)]

use ququmatz::owned::{MmapBuffer, OwnedSubmitter, PreparedRecvmsg};

// Nothing here is a type error, so the file reaches the lint pass. That
// matters: an `E0599` earlier in the file would abort compilation before
// `unused_must_use` ever ran, and the fixture would "pass" without
// exercising the guarantee it claims.

fn discard_a_recvmsg_ticket(
    sub: &mut OwnedSubmitter,
    request: PreparedRecvmsg<MmapBuffer, MmapBuffer, 2>,
) {
    // Dropping the ticket leaks the staging region and every buffer rather
    // than freeing them underneath a kernel that may still be writing the
    // header, reading it to reach the descriptors, and filling the buffers
    // those name. That is the safe failure, but it is silent, so it must
    // at least be diagnosed.
    sub.push_recvmsg(request);
}

fn main() {}
