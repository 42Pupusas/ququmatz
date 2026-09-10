#![deny(unused_must_use)]

use ququmatz::owned::{DirectSocketCreated, OwnedSubmitter, PreparedDirectSocket};

// Nothing here is a type error, so the file reaches the lint pass. That
// matters: an `E0599` earlier in the file would abort compilation before
// `unused_must_use` ever ran, and the fixture would "pass" without
// exercising the guarantee it claims.

fn ignore_the_ticket(sub: &mut OwnedSubmitter, request: PreparedDirectSocket) {
    // The ticket owns no memory, so dropping it frees nothing — but it is
    // the only record of which slot the socket lands in, and an unnamed
    // slot stays occupied until the ring is torn down.
    sub.push_direct_socket(request);
}

fn ignore_the_slot(created: DirectSocketCreated) {
    // A slot has no destructor that can release it.
    created.into_slot();
}

fn main() {}
