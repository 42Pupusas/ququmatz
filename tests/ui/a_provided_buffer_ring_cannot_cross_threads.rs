//! Q-05's related auto-trait defect: `ProvidedBufferRing`'s doc comment
//! claims it is `!Send`/`!Sync`, "like `IoUring`". Before the ring
//! retained a share of the parent `RingResources` (a raw pointer field),
//! every field on this struct was a plain integer, so the auto-trait
//! rules made it `Send`/`Sync` regardless of what the documentation
//! claimed -- nothing enforced the restriction the comment describes.
//! Now that it holds a raw pointer, `Send`/`Sync` are no longer
//! auto-derived, matching the doc. This pins that down: spawning a
//! thread with the pool moved in must fail to compile.

use ququmatz::IoUring;

fn main() {
    let mut ring = IoUring::new(8).expect("ring setup");
    let pool = ring
        .register_provided_buffers(0, 4, 64)
        .expect("register provided buffers");

    std::thread::spawn(move || {
        let _ = pool.bgid();
    })
    .join()
    .unwrap();
}
