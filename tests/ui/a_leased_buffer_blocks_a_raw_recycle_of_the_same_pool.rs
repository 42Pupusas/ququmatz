//! Q-02/Q-05 residual: AUDIT.md once claimed nothing stopped calling
//! `pool.recycle(buf_id)` directly while a `CompletedBuffer` for that same
//! id was still alive elsewhere. That claim was wrong by the time it was
//! written -- `CompletedBuffer<'pool>` holds `&'pool mut ProvidedBufferRing`
//! for its whole life, so *no* other call into the pool, recycle included,
//! can happen while a lease is outstanding. This pins that down: calling
//! `recycle` on the same pool a live lease still exclusively borrows must
//! fail to compile, exactly like a second `claim` already does.

use ququmatz::ProvidedBufferRing;

fn recycle_while_leased(pool: &mut ProvidedBufferRing, buf_id: u16, len: u32) {
    let leased = pool.claim(buf_id, len);
    // The pool is still mutably borrowed by `leased`. This call must be
    // rejected the same way a second `claim` is.
    pool.recycle(buf_id);
    drop(leased);
}

fn main() {}
