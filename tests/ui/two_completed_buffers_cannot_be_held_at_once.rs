use ququmatz::ProvidedBufferRing;

fn two_at_once(pool: &mut ProvidedBufferRing, buf_id: u16, len: u32) {
    let first = pool.claim(buf_id, len);
    // The pool is still mutably borrowed by `first`. Claiming again now
    // would put two live slot guards over one pool, so which slot is
    // recycled when would follow drop order rather than the caller's
    // intent -- exactly the failure `CompletedBuffer` exists to rule out.
    let second = pool.claim(buf_id, len);
    drop(first);
    drop(second);
}

fn main() {}
