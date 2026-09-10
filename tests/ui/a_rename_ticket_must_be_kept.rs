#![deny(unused_must_use)]

use ququmatz::owned::{MmapBuffer, OwnedSubmitter, PreparedPathOp, PreparedRename};

// Nothing here is a type error, so the file reaches the lint pass. That
// matters: an `E0599` earlier in the file would abort compilation before
// `unused_must_use` ever ran, and the fixture would "pass" without
// exercising the guarantee it claims.

fn discard_a_rename_ticket(
    sub: &mut OwnedSubmitter,
    request: PreparedRename<MmapBuffer, MmapBuffer>,
) {
    // Dropping the ticket leaks both path storages rather than freeing
    // them underneath a kernel that may still be scanning. That is the
    // safe failure, but it is silent, so it must at least be diagnosed.
    sub.push_rename(request);
}

fn discard_a_path_op_ticket(sub: &mut OwnedSubmitter, request: PreparedPathOp<MmapBuffer>) {
    sub.push_path_op(request);
}

fn main() {}
