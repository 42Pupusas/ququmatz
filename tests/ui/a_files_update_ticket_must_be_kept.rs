#![deny(unused_must_use)]

use ququmatz::owned::{MmapBuffer, OwnedSubmitter, PreparedFilesUpdate};

// Nothing here is a type error, so the file reaches the lint pass. That
// matters: an `E0599` earlier in the file would abort compilation before
// `unused_must_use` ever ran, and the fixture would "pass" without
// exercising the guarantee it claims.

fn discard_a_files_update_ticket(
    sub: &mut OwnedSubmitter,
    request: PreparedFilesUpdate<MmapBuffer, 2>,
) {
    // Dropping the ticket leaks the descriptor array rather than freeing
    // it underneath a kernel that may still be walking it. No descriptor
    // goes with it — the kernel duplicates what it installs — but the
    // outcome is lost too, and a `files_update` can report that only part
    // of the request took effect. That is the safe failure, but it is
    // silent, so it must at least be diagnosed.
    sub.push_files_update(request);
}

fn main() {}
