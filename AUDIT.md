# ququmatz audit and remediation strategy

## Executive summary

**Recommendation: do not treat the current API as a sound safe-Rust abstraction. Prioritize a breaking safety release before further performance work or structural refactoring.**

The crate has useful domain-separated SQE builders, explicit kernel layouts, resource cleanup guards, and a substantial passing test suite. However, safe public methods permit callers to violate memory lifetimes and aliasing rules. Passing Clippy and integration tests does not establish soundness.

The most urgent defects are:

1. SQE constructors discard borrowed-data lifetimes while submission remains safe.
2. Provided-buffer methods manufacture caller-selected reference lifetimes and do not establish ownership of completed slots.
3. Synchronous `do_*` helpers accept any available completion as proof that their own operation has finished.
4. Public safe syscall wrappers expose arbitrary memory reads, writes, and unmapping.

Additional findings cover provided-buffer teardown, unsupported setup modes, short submissions, thread-affine ring modes, architecture-specific ABIs, error-path cleanup, test isolation, and maintainability.

## Scope, baseline, and confidence

- Repository: `/home/cuarentaydos/Code/tooling/ququmatz`
- Package: `ququmatz 0.15.1`, edition 2024.
- Audited revision: `b4e5280a65b486e6752488f8c5e1730381158e06` — “Add MSG_CMSG_CLOEXEC to MsgFlags; bump to 0.15.1”.
- Initial tracked working tree was clean.
- Toolchain reported by environment diagnostics: Cargo 1.97.1.
- Review concentrated on ring setup/ownership, SQ/CQ protocols, provided buffers, syscall boundaries, representative operation builders, public ABI types, tests, and package documentation. This is not a line-by-line certification of every opcode or architecture assembly backend.
- No implementation changes were made. Existing tests were executed; they perform filesystem and network operations. This report is the audit deliverable.
- Findings marked **confirmed** follow directly from source/API contracts, sometimes corroborated by Linux documentation. They are not claims that a malicious exploit was executed. Unsafe crash/use-after-free demonstrations were deliberately not run.
- Cross-architecture execution, Rust 1.85 compatibility, Miri, sanitizer runs, dependency vulnerability scanning, performance measurements, and kernel-version matrix testing were not performed.

Severity describes possible impact; priority describes remediation order. **Critical** means safe API misuse can violate Rust memory safety, not that remote exploitation has been demonstrated.

## Verification results

All Cargo commands below used `--manifest-path /home/cuarentaydos/Code/tooling/ququmatz/Cargo.toml`.

| Check | Default features | `--all-features` |
|---|---|---|
| `cargo build --workspace --all-targets` | Pass | Pass |
| `cargo test --workspace --all-targets` | 133 tests passed | 133 tests passed |
| `cargo test --workspace --doc` | 3 compile-only doctests passed | 3 compile-only doctests passed |
| `cargo clippy --workspace --all-targets -- -D warnings` | Pass | Pass |
| `cargo fmt --all -- --check` | Pass; feature-independent | Same source |

The only declared optional feature is `dhat-heap`; default and all-features therefore cover the declared feature combinations. All-targets test runs also exercised benchmark harness test mode and compiled example test targets; they did not measure benchmark performance or run the examples as applications.

Environment diagnostics initially attempted a workspace check from `/home/cuarentaydos`, not this crate, and reported no manifest. The explicit-manifest commands above supersede that diagnostic. An unrelated missing API key did not affect this audit.

The valid structural command was:

```text
cargo graph --report /home/cuarentaydos/Code/tooling/ququmatz
```

It reported **52 types, 8 levels, 89 dependency edges, 37 skip edges, 6 back-edges, and “NOT a DAG: 0 cycle(s)”**. The zero-cycle count does not negate the reported dropped back-edges. An earlier attempt with an unsupported `--manifest-path` argument produced an empty graph and was discarded; a mistyped path also failed and was corrected.

## Finding summary

| ID | Severity | Priority | Finding |
|---|---|---|---|
| Q-01 | Critical | P0 | Safe SQEs erase lifetimes and permit arbitrary raw submissions |
| Q-02 | Critical | P0 | Provided-buffer references can outlive memory or alias kernel writes |
| Q-03 | Critical | P0 | `run_one` does not wait for its own operation on all paths |
| Q-04 | Critical | P0 | Safe raw syscall interface permits memory corruption |
| Q-05 | High | P0 | Provided-buffer registration does not retain ring ownership |
| Q-06 | High | P1 | Setup accepts layouts that mapping/parser code does not support |
| Q-07 | High | P1 | Short submission results are counted as full submission |
| Q-08 | High | P1 | Split API ignores single-issuer/deferred-work thread restrictions |
| Q-09 | High | P1 | Architecture support exceeds ABI correctness and platform gating |
| Q-10 | Medium | P2 | Setup allocation failure leaks a separately mapped CQ |
| Q-11 | Medium | P1 | Integration test uses a predictable truncating `/tmp` path |
| Q-12 | Medium | P2 | Safety-critical responsibilities remain coupled and duplicated |
| Q-13 | Medium | P2 | Published compatibility and safety documentation is misleading |

## Detailed findings

### Q-01 — Safe SQEs erase lifetimes and permit arbitrary raw submissions

**Status: Phase 0 containment fixed.** Every `Sqe` constructor that stores a
pointer derived from caller data — whether it took a structured
reference/slice/`&CStr` or a raw pointer directly — is now `unsafe fn`,
including `Sqe::from_raw`. This closes the specific defect described below
(a safe constructor call compiling without any `unsafe` token at the actual
unsound boundary) but is containment, not the Phase 2 owned-request/lease
redesign the original remediation calls for: callers can still write
`unsafe { Sqe::read(...) }` around a dangling buffer and get past the
compiler, because the contract is still documented-and-trusted rather than
type-enforced. Eight `trybuild` compile-fail regression tests
(`tests/ui/*_requires_unsafe.rs`, driven by `tests/compile_fail.rs`) pin
that every previously-safe pointer-bearing constructor now fails to compile
without an `unsafe` block; they will catch a regression back to an
accidentally-safe signature but do not — and cannot — prove the unsafe
contracts callers write are actually upheld. The five `do_*` convenience
methods in `src/ring/ops.rs` build their now-unsafe SQEs internally inside
an `unsafe` block justified by `run_one`'s submit-and-wait-before-return
structure; that justification still carries Q-03's residual
completion-correlation caveat below. The full Phase 2 fix — owned in-flight
requests whose lifetime the type system ties to the operation's terminal
completion — remains open.

**Update — a safe alternative now exists (`src/owned/`).** Rather than only
restricting the borrowed-pointer API, the crate now offers a safe one
alongside it. `owned` replaces borrowing with ownership transfer: a buffer
moves into `Prepared`, then into a `Pending` ticket that owns the storage
and exposes no way to read, write, or extract it while the kernel may be
using it, and comes back only via `Completed`. Because the ticket owns
rather than borrows, it is `Send` when its buffer is, so submission and
completion run on independent OS threads with no scoped join and no
crate-owned slab — the application decides where tickets live. This is the
intended use of the crate expressed without `unsafe` at the call site; see
`examples/split_owned_threads.rs`.

Redemption is authenticated, which matters because `Completion` is a public
struct any safe code can build, so a raw `user_data` match proves nothing.
A `Receipt` is minted only by `OwnedCompleter::reap` from a CQE it actually
reaped, carries both request and ring identity, and is neither `Copy` nor
`Clone`. `Pending::redeem` rejects a receipt from another request or
another ring and hands both values back intact. `RequestId`s are monotonic
and never reused, so a stale receipt cannot authenticate a later request.
Multishot CQEs (`IORING_CQE_F_MORE`) are deliberately not turned into
receipts, since they are not terminal.

Abandonment degrades safely: dropping *or* `mem::forget`ing a `Pending`
leaks its buffer instead of freeing storage the kernel may still write to.
This is the property a forgettable borrow-guard cannot have, and it is why
this design is sound where `thread::scoped` was not. The cost is explicit —
without a registry the crate cannot reclaim abandoned requests, so an
optional reaper is possible future work.

Four further compile-fail tests (`tests/ui/pending_*.rs`,
`tests/ui/receipt_*.rs`) pin that an in-flight buffer is unreachable and
unextractable, that a `Receipt` cannot be constructed by safe code, and
that one receipt cannot be spent twice. 28 unit tests cover the lifecycle,
including cross-ring rejection, same-ring wrong-request rejection,
queue-full returning the buffer intact, kernel errors not stranding
storage, and a ticket redeemed on a second thread.

**Machine-checked under Miri.** The lifecycle is generic over the buffer,
so `src/owned/miri.rs` substitutes heap storage and a stand-in kernel that
touches the bytes only through the address published in the SQE — Miri
cannot run this crate's syscalls, which are inline `asm!`, so neither
`MmapBuffer` nor a real ring is reachable. Nine tests cover the kernel
writing into a live ticket's buffer, reading bytes staged before
submission, the ticket being moved between owners mid-flight, redemption
after a rejected receipt, out-of-order redemption of sixteen concurrent
tickets, and the abandonment paths. They pass under both Stacked Borrows
and Tree Borrows with leak checking on.

Miri paid for itself immediately by finding a real defect: `Prepared` and
`Pending` stored the buffer address as a `usize`, so the pointer the kernel
received had no provenance and every access through it was UB. Both now
hold a `*mut u8` derived from the buffer, with hand-written `Send` impls
bounded on `B: Send` replacing the auto-trait that the raw pointer
suppresses. The two tests that assert abandonment leaks free the storage
explicitly afterwards so leak checking stays enabled everywhere else.

Two limits on that evidence. `-Zmiri-strict-provenance` cannot pass here by
construction: io_uring's ABI stores the address as a `u64`, so recovering a
pointer from the SQE is an integer-to-pointer round trip inherent to the
interface. Tree Borrows likewise does not model such casts, which makes its
pass weaker evidence than the Stacked Borrows one. Both accept the crate
code itself — the remaining cast lives in the test's stand-in kernel, where
the real kernel would be.

**Zero-copy sends.** `send_zc` is now covered too, by `PreparedZc` /
`PendingZc` / `ZcCompleted` in `src/owned/zerocopy.rs`. It needed separate
types rather than a flag on `Prepared` because its buffer outlives its
first completion: an ordinary `write` copies into the kernel, so one CQE
means the bytes are free, while a zero-copy send maps the pages to the NIC
and the send CQE reports only how much was accepted. Releasing the buffer
there is a use-after-free that a plain `Pending` would perform happily.

The kernel signals which case applies rather than leaving it to be
inferred. A send CQE carrying `IORING_CQE_F_MORE` promises a later
notification; **without that flag no notification is ever posted** and the
send CQE is itself terminal, which is what happens when the kernel falls
back to copying. A design that waited unconditionally for a notification
would leak every such request forever. `OwnedCompleter::reap_event` reads
the flag and returns `Event::Partial` or `Event::Complete` accordingly, so
both paths terminate.

The separation is a type error, not a convention. The non-terminal CQE
becomes a `PartialReceipt`, which `record_sent` accepts — handing the
ticket back still holding its buffer — and which no releasing method will
take; only a `Receipt` from a terminal CQE can redeem.
`tests/ui/partial_receipt_*` pins both halves: `E0308` for the
substitution, `E0451` against forging one. Note that the pre-existing
`reap` skips `MORE` CQEs, which silently discards a zero-copy send's byte
count; rings that submit `push_zc` work must use `reap_event`, and its
documentation says so.

**`MORE` is not a zero-copy concept.** The first version of this classified
every `MORE` CQE as a zero-copy send result, in a type called
`SendReceipt` that carried only `ring`/`id`/`result`. Reading the multishot
path afterwards showed that to be wrong in a way the `send_zc` tests could
not expose: a multishot arrival also sets `MORE`, but carries a **pool
buffer id in the upper 16 bits of the CQE flags**, and a type with no
`flags` field drops it. That buffer is then never recycled, so the pool
drains and the multishot stalls on `ENOBUFS` — a leak rather than
corruption, but a real one. `reap` was worse: it skips `MORE` CQEs
entirely, taking every arrival and its buffer with them.

The flag answers "will more completions follow?", which is exactly "may
this CQE release anything?". What the CQE *carries* is an independent axis.
So the type is now `PartialReceipt` in `src/owned/event.rs`, it preserves
the kernel's flags, and it exposes `buffer_id()`. `src/owned/event_tests.rs`
pins the decoding, including id `0` (a real id, not an absent one) and
`u16::MAX` (survives the shift); those three tests were confirmed to fail
when `buffer_id` is stubbed to return `None`.

Five further Miri tests cover the NIC reading the buffer *after* the send
CQE was recorded, the no-notification path, abandonment while a send is in
flight, a mismatched send notice, and reclaiming an unpublished send. The
two kernel behaviours are pinned deterministically there because a live
ring cannot be made to choose one; the real-ring test in
`src/owned/tests.rs` drives an actual loopback socket and accepts either.
It was checked once with a temporary assertion that a notification really
did arrive, confirming the two-CQE path is genuinely exercised rather than
passing through the trivial branch, but does not assert it permanently.

**Multishot receive.** Covered by `PreparedMultishot` / `MultishotRecv` /
`Arrival` in `src/owned/multishot.rs`. This one does not fit the ticket
model at all, and forcing it to would have been the mistake. Every other
owned request holds a buffer for its whole life; a multishot owns nothing.
One SQE stays armed across many arrivals and the kernel picks a *pool*
buffer per arrival, so the resource is a borrow of a pool slot that must be
recycled exactly once — not an allocation. Never recycling drains the pool;
recycling twice hands the kernel a buffer that is already queued.

`Arrival` is therefore an RAII guard holding `&'pool mut BufferConsumer`,
and it recycles on drop, including on unwind. The exclusive borrow does
real work beyond the recycle: two arrivals cannot be live at once, so
recycling order follows the caller rather than drop order, and slot ids
cannot be confused. `tests/ui/arrival_cannot_outlive_its_pool.rs` (`E0621`)
and `two_arrivals_cannot_be_held_at_once.rs` (`E0499`) pin both. An earlier
draft of those fixtures passed for the wrong reason — they imported
`BufferConsumer` through the private `ring` module and failed with `E0603`,
which would have held even if `Arrival` were unsound. Fixed to import the
crate-root re-export, and the errors are now the intended ones.

The second hazard is that finishing is not failure. Per
`io_uring_prep_recv_multishot(3)`, a CQE **without** `MORE` means the
multishot is done and the application must submit a new request to keep
receiving. `ENOBUFS` from a drained pool is a common cause, so it can
happen at any time; treating it as ordinary end-of-stream leaves a socket
permanently deaf. `Delivery` reports it as `Done` and is deliberately
*not* `#[non_exhaustive]`, so callers cannot skip the case with a `_` arm,
and `Finished` cannot be re-armed — receiving again means a new request,
which is what the kernel requires.

The third hazard was found by reading `io_uring/net.c` rather than the man
page, and it invalidated the first version of this code. Terminal and
*empty* are also independent axes. `io_recv_finish()` computes the buffer
flags **before** deciding whether the request continues:

```c
cflags |= io_put_kbuf(req, sel->val, sel->buf_list);
if (... && io_req_post_cqe(req, sel->val, cflags | IORING_CQE_F_MORE))
        return true;                             /* stayed armed */
finish:
        io_req_set_res(req, sel->val, cflags);   /* terminal, same cflags */
```

When the extra CQE cannot be posted — a full completion queue — the buffer
id rides out on the *terminal* CQE instead. A `Done` that carried no
payload would leak a pool slot exactly when the pool is already under
pressure, which is the same defect as the `PartialReceipt` bug one commit
earlier, in the branch that looked too simple to check. `Finished` now
carries the final `Arrival`, and `into_receipt` was replaced by
`into_parts` returning both, because a method that quietly discarded
received bytes should not be the convenient one. `CqeFlags::buffer_id()`
owns the decode, since three copies of a bit-shift is how the two paths
drift apart.

Six real-kernel tests cover the module: three writes delivered from one
armed submission, a foreign completion rejected, a CQ-overflow flood, a
terminal CQE with no buffer, and two load-bearing ones. A **two-buffer
pool carrying six messages** can only pass if each arrival returned its
slot — verified by `mem::forget`ing the arrival, which ends the multishot
at round 2 with `ENOBUFS` (errno 105), and re-verified after the loop was
restructured for clippy, to confirm it had not gone slack. A **synthesised
terminal CQE carrying a buffer id** pins the fold, since CQ overflow cannot
be forced deterministically from userspace; it was verified by making
`Done` drop its payload again, which fails on the missing arrival.

**Vectored I/O.** Covered by `PreparedVectored` / `PendingVectored` /
`VectoredCompleted` in `src/owned/vectored.rs`. Every other request hands
the kernel one pointer to the data. A vectored one hands it a pointer to an
**array of `IoVec`**, which the kernel dereferences to reach the buffers —
so there are two regions it touches, and both must stay put for the whole
operation.

The buffers are the easy half: `StableBuffer` already promises the bytes
do not move when the owner does, so `[B; N]` sits inline in the ticket and
moving the ticket moves `N` owners rather than `N * len` bytes.

The array is the trap, and it decided the whole design. It cannot live
inline in the ticket, because a `Pending` is deliberately `Send` and is
*expected* to be handed to a completion thread — an inline array would
relocate the exact bytes the kernel is about to read, leaving it following
a pointer into a dead stack slot. Nothing in the type system would notice:
the request would still compile, still submit, and still read or write
whatever now occupies that address. Since that is precisely the guarantee
`StableBuffer` encodes, the array's storage is *required to implement it*
rather than getting a new trait, and the caller supplies it so one
allocation can serve many requests.

Size and alignment are checked before the array is written, not after: an
unaligned `IoVec` write is UB, so discovering the problem afterwards is too
late. Both checks hand back every owner untouched, so a rejected request
never costs a buffer. `PendingVectored` also carries the target fd and
offset purely so a queue-full retry comes back aimed where the caller
aimed it — an earlier draft reconstructed it with `fd: 0`, which would
have silently retargeted a retry at stdin.

**Miri found a real defect in the test fixtures here.** The `HeapBuffer`
stand-in allocates with `align 1`, which is right for data but wrong for
descriptors, and Miri rejected it where the system allocator had been
handing back aligned addresses and hiding the problem. The fix belonged in
the fixture rather than the check: `HeapBuffer::for_descriptors` now
allocates at `align_of::<IoVec>()`, matching the page-aligned `MmapBuffer`
real callers pass. Five Miri tests cover the module, walking the array the
way the kernel does — read the descriptor, then follow *its* pointer — so a
stale array is a hard error rather than a wrong byte. They pass under both
Stacked Borrows and Tree Borrows with the leak checker on.

Ordering is load-bearing and was verified by reversing the descriptor
write loop, which fails three tests with visibly transposed data. The
alignment check was verified by disabling it, which fails the misalignment
test. `tests/ui/vectored_buffers_are_unreachable_in_flight.rs` pins that
neither the buffers nor the array can be reached or reclaimed while the
request is in flight.

**Multishot accept.** Covered by `PreparedAccept` / `MultishotAccept` /
`Incoming` in `src/owned/accept.rs`. It shares the `MORE`/re-arm state
machine with recv, and the same terminal-CQE-carries-a-resource hazard, but
deliberately does *not* share `Arrival` — the ownership stories are
opposites. A recv arrival **borrows** a pool slot the kernel is waiting to
reuse, so it carries a lifetime and recycles on drop. An accepted
connection is **owned**: `io_accept()` has already called `fd_install`, so
the descriptor belongs to this process whether or not anyone reads the CQE,
and the only release is `close`. There is no pool to borrow from, so
`Incoming::Connection` carries a plain `Socket` with no lifetime at all.
Making one type serve both, with the slot as a generic parameter, would
have forced a fictional lifetime onto the accept side.

The terminal-CQE hazard is identical in shape and was fixed before it
could ship: `io_accept()` installs the fd, then only afterwards decides
whether to post an aux CQE, falling through to `io_req_set_res(req, ret,
cflags)` with `ret` still the descriptor. So `AcceptFinished` carries the
final `Socket`, and `into_parts` returns both halves rather than offering a
receipt-only accessor that would leak a live connection.

The peer address is deliberately not captured. `io_uring_prep_multishot_
accept(3)` warns that a single `addr` is reused for every connection, so a
fast second connection can overwrite the first before it is read; an API
that returned that racing value would be handing out data it cannot
vouch for.

Four real-kernel tests: three clients served from one armed submission with
distinct live descriptors (verified by swapping in a single-shot `accept`,
which ends the request after the first connection), a synthesised terminal
CQE carrying a real accepted fd (verified by making `Done` drop its
payload), a negative result yielding no socket in both the armed and
terminal cases, and a foreign completion rejected.

The compile-fail fixture here claims less than the arrival ones, on
purpose. Ownership means no lifetime, so the compiler cannot force a caller
to deal with a connection — dropping a `Socket` is legal and closes it.
What is pinned is that ignoring a completion is never silent, and the
fixture sets `#![deny(unused_must_use)]` itself rather than relying on the
lint being hard by default, because the guarantee really is "diagnosable",
not "prevented". An earlier draft asserted the stronger claim and passed
for the wrong reason — a type mismatch I had introduced in the fixture
itself, not the lint.

**`openat`.** Covered by `PreparedOpen` / `PendingOpen` / `Opened` in
`src/owned/open.rs`, with path storage in `src/owned/path.rs`. Two things
are new here, and each changed the design.

First, **the kernel reads without a length**. Every other operation is
bounded by the SQE's `len` field, so an over-long read is impossible by
construction. `openat` takes only an address and scans forward until it
finds a NUL, which makes the terminator the entire bound. An unterminated
path is therefore not a short read but a walk off the end of the
allocation, and the caller cannot detect it afterwards from the result. So
termination is checked once, up front, and `OwnedPath` exists to carry the
proof: a request cannot be built from raw bytes at all, only from a value
that has one. Interior NULs are rejected too, since the kernel stops at the
first — `"/etc\0passwd"` would silently open `/etc`.

That claim is machine-checked rather than asserted. The Miri stand-in
kernel resolves the path the way `openat` does, scanning with nothing but
the terminator to stop it, and the fixture fills its storage with `0xFF` so
the written NUL is the only zero in the allocation. Removing that write
makes Miri report **Undefined Behavior: dangling pointer** — the scan
leaves the allocation — which is precisely the failure `OwnedPath`
prevents. `OwnedPath` also exposes no mutable view of its bytes, because
overwriting the NUL would invalidate the proof the value carries.

Second, **the result is itself a resource**. Every earlier request handed
storage to the kernel and got the same storage back; an open also produces
a descriptor the kernel created. Two independent things are therefore
reclaimable from one CQE, and they fail differently: losing the storage
leaks memory, while losing the descriptor consumes a slot in a table
bounded by `RLIMIT_NOFILE`, which runs out first. `Opened::into_parts`
hands back both, and the descriptor arrives as an owning `File` — a new
type in `src/fs.rs` — so ignoring it closes rather than leaks.

`File` is deliberately not `Socket`. Both are owned descriptors, but a
`Socket` answers `bind`, `listen`, `shutdown` and `getsockname`, none of
which mean anything for a file. Returning one from an open would compile
and would be a lie.

Thirteen tests cover the module: three real-kernel (a working descriptor
that is then written through, a failed open reporting `ENOENT` with no
descriptor to leak, and a ticket redeemed on a second thread), six on the
path rules, one on queue-full handback, and five under Miri. Both path
checks were verified load-bearing by disabling them. The queue-full test
asserts every field survives the round trip, not just the storage, since a
retry that lost its flags would open the same path differently.
`tests/ui/an_in_flight_path_is_unreachable.rs` pins that the path is
unreachable in flight and that its bytes cannot be rewritten.

**Direct open.** Covered by `PreparedDirectOpen` / `PendingDirectOpen` /
`DirectOpened` in `src/owned/direct.rs`, with the slot vocabulary in
`src/owned/slot.rs`. This is the third ownership story: the result is
neither borrowed storage nor an owned descriptor, but an **index into one
ring's registered-file table**. `io_openat` with a `file_index` calls
`io_install_fixed_file`, which puts the file in the ring's table and never
calls `fd_install`, so no descriptor enters the process at all.

That changes what release means. A `DirectSlot` has no `Drop` and cannot
have one: freeing a slot means submitting to the ring, which the value does
not hold. Dropping one leaves the file installed until the slot is
overwritten or the ring is torn down. That is a milder leak than an
abandoned `File` and the difference is worth stating precisely — a leaked
descriptor lives as long as the *process*, a leaked slot dies with the
*ring*. `#[must_use]` says so at the call site, and a compile-fail fixture
pins that a slot cannot be converted into a `File` or a `Socket`.

The encoding is where a guess would have been wrong, so it came from
`io_uring/openclose.c` rather than memory. `sqe->file_index` is a three-way
overload: `0` means "not a direct operation", `IORING_FILE_INDEX_ALLOC`
(`u32::MAX`) means "kernel picks a slot", and anything else is
`slot + 1`. `SlotIndex` therefore refuses `u32::MAX` and `u32::MAX - 1`,
the two values whose successors are unrepresentable, so a nameable index
can never collide with the sentinel.

Resolving the index has a matching trap. `io_install_fixed_file` returns
`0` on success for an explicit slot, so believing the CQE result would
report every explicitly-placed file as landing in slot 0. Only
`SlotTarget::Auto` reads its index from the result; `Exact` keeps the index
the caller named.

The test for that was initially too weak to catch it. It asserted the
reported index matched the target, which holds even with the `+1` encoding
removed — it was checking my arithmetic against itself. The version that
fails on sabotage writes through the slot the caller was *told* about, and
gets `EBADF` when the file actually landed one slot lower.

Fourteen tests: four real-kernel (installation into an explicit slot then a
write through it, an out-of-range slot refused, a direct open without a
registered table failing rather than leaking a descriptor, and a foreign
receipt rejected), nine on the encoding and resolution rules, and four
under Miri including the abandonment path.

**`statx`.** Covered by `PreparedStatx` / `PendingStatx` / `StatxCompleted`
in `src/owned/statx.rs`. It is the only owned request where the kernel
*writes a typed structure* rather than moving bytes, and that changes both
ends of the operation.

Every other request is bounded by the SQE's length field, so a destination
that is too small yields a short transfer. `statx` has no length for its
destination anywhere in the SQE: `io_statx_prep` takes `addr2` and the
kernel writes a whole `struct statx` there, reporting only success or
`-errno`. An undersized destination is therefore a fixed-size write past
the end of the allocation that nothing in the result reveals, and a
misaligned one is UB for the same write. Both are checked before the
request can exist, and both hand every storage back, so a rejected request
costs nothing. The reserved mask bit (`STATX__RESERVED`, `0x8000_0000`) is
rejected up front too, since the kernel fails it with `EINVAL`.

What comes back is also different in kind. A read's byte count describes
bytes that are all meaningful; a `statx` result is *partially* valid, and
which fields the kernel filled is reported in-band by `stx_mask`. The man
page is explicit that this need not equal the requested mask — a filesystem
may decline a requested field and may volunteer an unrequested one — so
reading `stx_size` without consulting the mask reads whatever the kernel
left there, often a plausible dummy value rather than an obviously wrong
one. `Statx` therefore gained mask-gated accessors returning `Option`, and
`StatxCompleted::stat` returns `None` on failure rather than a zeroed
struct, because a failed `statx` does not write the destination at all.

All three guards were verified by disabling each in turn; each fails its
test. The alignment check was re-verified after being rewritten to satisfy
Clippy's `cast_ptr_alignment`, since the rewrite moved the test from a cast
to an address computation. Nine unit tests and five under Miri cover the
module, including both regions staying valid across a ticket move, the
abandonment path leaking *both*, and reclaim preserving flags and mask.
`tests/ui/an_in_flight_statx_destination_is_unreachable.rs` pins that
neither the path nor the destination is reachable in flight.

`AT_EMPTY_PATH` is deliberately not reachable: it requires an empty path,
which `OwnedPath` rejects by construction. That mode stays on the `unsafe`
`Sqe::statx_ptr`.

**Direct accept.** Covered by `PreparedDirectAccept` / `DirectAccept` /
`DirectIncoming` in `src/owned/direct_accept.rs`. An earlier draft of this
was discarded rather than committed because two real-kernel tests failed;
both failures turned out to be **the tests being wrong about the kernel**,
and the second one was wrong about the crate too.

The rewrite began by measuring instead of reasoning. A throwaway probe
against a two-slot table produced: first connection `res=0` with `MORE`
set, second `res=1` with `MORE` set, third `res=-23` with **`MORE` clear**,
and a fourth connection produced no completion at all — the probe hung,
which is itself the proof that the request had already ended.

That settles both defects. The old exhaustion test asserted `-ENFILE`
"stays armed"; the kernel gates its re-arm on `ret >= 0`, so any negative
result skips the extra CQE and falls through to `io_req_set_res`. A full
table does not refuse one connection, it retires the listener — and since a
registered table is far smaller than `RLIMIT_NOFILE`, that is the ordinary
case. An API that reported it as a survivable hiccup would leave callers
blocked forever on a dead request, so it is now a `Done`.

The watermark test was measuring the wrong thing, and the fix took two
attempts. It sampled the next free descriptor once before opening three
client sockets and again at the end, so the delta it saw was the *clients* —
process descriptors unrelated to the accept. Narrowing the bracket to span
only each completion made it pass, and it survived every sabotage, but it
failed as soon as the whole suite ran in parallel: the next-free descriptor
is **process-global**, so every other test thread creating and closing
files perturbed it, once making it move *down*. A test that reads a shared
resource cannot make a claim about one request no matter how tightly it is
bracketed.

The assertion is now local to the ring: a fresh sparse table allocates
densely from zero, so three connections yield exactly slots `0, 1, 2`.
Those cannot be process descriptors, since 0, 1 and 2 are already stdin,
stdout and stderr. Sabotaging the encoding produces `[4, 14, 16]` — plainly
descriptors — which is a sharper diagnostic than a watermark delta, and it
is deterministic under parallelism.

The slot encoding needed care in the opposite direction from direct open.
Submission-side, zero means "not a direct request", which is why
`SlotIndex` encodes `index + 1`. Completion-side under `Auto`, zero is a
real slot — measured as the *first* connection's result — so treating it as
absent would drop the first connection of every run. That is pinned by its
own test.

Four sabotages, each caught: dropping the folded slot on the terminal CQE,
writing `0` instead of `IORING_FILE_INDEX_ALLOC` into `splice_fd_in` (which
reproduces the original bug exactly — process descriptors come back and the
table never fills), and treating result `0` as no slot, which fails both
the real-kernel test and its dedicated unit test. The encoding sabotage was
re-run after the parallelism fix, since replacing an assertion invalidates
the evidence gathered with the old one. Six unit tests plus an SQE
encoding test that also pins the non-direct variant leaves `splice_fd_in`
clear. The compile-fail fixture had to be split: an `E0599` earlier in the
file aborted compilation before `unused_must_use` ran, so the lint
guarantee was never being exercised — the same trap as the accept fixture.

**Direct socket.** Covered by `PreparedDirectSocket` /
`PendingDirectSocket` / `DirectSocketCreated` in
`src/owned/direct_socket.rs`. It is the first owned request that owns *no*
memory — a socket is three integers — so there is no in-flight storage to
protect, no `ManuallyDrop`, and no reason to leak on drop. What still needs
keeping is the *record* of the slot, which is why the ticket and the
completion are both `must_use`.

Measured before designing, as with direct accept. Six facts came out of the
probe, three of them load-bearing. An explicit slot **replaces and closes**
whatever file occupies it, matching the man page's "the file will first be
removed from the table and closed", and it reports the same `0` as an
install into a free slot — so nothing in the completion reveals that a live
file was destroyed. Exhaustion gives `-ENFILE`, but unlike direct accept
this is a one-shot, so there is no armed request to retire. And an absent
table is reported *differently depending on the target*: `Auto` says
`-ENFILE` (a table that does not exist has no free entry), while an
explicit slot says `-ENXIO`.

Four sabotages. Two were caught immediately: dropping the `CLOEXEC` guard,
and ignoring the caller's target so every request became `Auto` — which
failed the replacement test (the eventfd survived) and the errno test
(`-23` where `-6` was expected).

The other two exposed weak tests rather than weak code, which is the point
of running them. Making an explicit target believe the CQE result instead
of its own index **passed**, because the test had seeded slot `0` — the one
index where `Auto.resolve(0)` and `Exact(0)` agree. Re-seeding at slot `2`
made the sabotage fail as it should. Then removing the `result < 0` guard
also passed: `SlotTarget::Exact::resolve` returns `Some` regardless of the
result, so that guard is the *only* thing stopping a failed explicit
request from naming a slot the kernel never filled. The ENXIO test checked
the errno but not the slot; it now checks both.

**Directory-entry operations.** Covered by `PreparedPathOp` /
`PendingPathOp` / `PathOpCompleted` in `src/owned/pathop.rs` for `unlinkat`
and `mkdirat`, and by `PreparedRename` / `PendingRename` /
`RenameCompleted` in `src/owned/rename.rs` for `renameat2`. They own path
storage the way an open does, but their completions carry no resource at
all — only `0` or `-errno` — so an abandoned ticket leaks exactly the
storage the caller supplied and nothing more. A rename is the first owned
request that publishes **two** path addresses, and both must stay live for
the kernel's two scans.

Measured before designing, and the measurements changed the API twice.
`AT_REMOVEDIR` reads like an optional flag but is determined by the target:
`EISDIR` without it on a directory, `ENOTDIR` with it on a file. So the two
working combinations are the only two reachable ones, as
`PathOpKind::Unlink` and `PathOpKind::Rmdir`. And a default `renameat`
**destroys an existing destination silently** — measured as `ov2` going
from `"old"` to `"new"` with result `0`, indistinguishable from a rename
onto a free name. `RenameMode` is therefore an enum with no default, and it
is an enum rather than flags because `NOREPLACE|EXCHANGE` together is
`-EINVAL`: the broken combination is not representable. `mkdirat`'s mode is
masked by the umask (`0777` asked, `0755` got), which the docs now say.

Four sabotages, and the fourth is the one worth recording. Swapping the
removal flags was caught by three tests; collapsing `NoReplace` to the
default and swapping the two directory descriptors were each caught. But
**letting `PendingPathOp::drop` actually free its in-flight path storage —
the core unsoundness this whole layer exists to prevent — passed all 150
tests.** Behavioural tests cannot see it: the kernel has usually finished
by then, so the freed read succeeds by luck. Both families had no Miri
coverage, unlike every other path-owning request. Eight Miri tests were
added, and the sabotage then failed with "dangling pointer". Freeing only
the rename's *destination* is caught specifically by `resolve_second_path`,
which is why the second scan exists rather than reusing the first.

Two weak tests were also found by sabotage rather than by review, both the
same degenerate-value mistake as the direct-socket slot `0`: the
cross-directory rename used the basename `"item"` on **both** sides, so an
implementation sending one path twice still passed. Distinct names now.

`openat2` was added next, and is the first owned request whose
*parameters* live in caller memory: the kernel reads a `struct open_how`
at a second published address to learn what to open. That is the vectored
descriptor-array hazard rather than an open's, so the storage is
caller-supplied and size- and alignment-checked, and it gets its own Miri
read (`read_open_how`) for the reason `resolve_second_path` exists —
freeing only the second region is invisible to a check that scans the
first. Six sabotages were run against it, all caught: freeing the
`open_how` on drop, sending a mode `openat2` rejects, dropping the
`resolve` restrictions, mis-sizing `how_size`, silently losing `EXCL` from
`CreateNew`, and pointing the SQE's `open_how` at the path storage.

Measurement drove the API here more than in any previous family, because
`openat2` validates what `openat` ignores: a mode without `CREAT` is
`EINVAL` rather than ignored, as are a mode above `0o7777`, an unknown
flag bit, an unknown `resolve` bit, and any `how_size` that is not the
kernel's own. None of those is reachable through the owned API —
`Openat2Mode` pairs the mode with the flag that gives it meaning,
`ResolveFlags` is a named-bit type, and `how_size` is written by the crate
rather than chosen.

`sendmsg` closes the nested-pointer case this finding's acceptance
criteria name explicitly. It is the first owned request where the
addresses the kernel dereferences are not SQE fields at all: the SQE names
a `struct msghdr`, and the kernel reads *that* to find the `iovec` array
and the destination address before following either to the data. Three
regions chained by pointers that live in caller memory. The header, the
descriptors, and the address are staged in one caller-supplied region
checked once for size and alignment; the payload buffers stay inline under
`StableBuffer`. Miri exercises the whole chain by reading the header and
following its own `msg_iov`, so a freed staging region is a dangling-
pointer error rather than a wrong byte.

`recvmsg` chains the same three regions the other direction, and the
difference is not symmetry: the kernel **writes** the header as well as
reading it, so the staging region is a destination too. That makes it the
first owned request whose most important result is not in the CQE.

Measured, not assumed. An 11-byte datagram delivered into a 2-byte buffer
completes with `2` — byte-for-byte what a 2-byte datagram that arrived
whole reports. The nine discarded bytes appear nowhere in the result; only
the written-back `MSG_TRUNC` distinguishes them, which is why `received`
returns the count and the flags together as one value rather than letting
a caller read the count alone. `MsgOutFlags` is a separate output-only
type for the same reason. The identical shape on a *stream* socket sets no
flag and loses nothing, so a short read there is not a loss.

The peer address is the other place the header outranks the result, and
the reported length cannot be used to read it. Three behaviours were
measured against a real kernel: a connected socket writes nothing and
reports `0` however much room was reserved; an IPv6 peer reports `28`
while writing only the 16 bytes it was given, leaving the rest of the slot
untouched; and an `AF_UNIX` peer with a short path reports a length
*between* the two — 11 for `/tmp/qq1` — filling part of the slot and no
more. Reading the whole slot in the last two cases mixes the kernel's
bytes with whatever preceded them. `PeerAddress` therefore yields an IPv4
address only when the reported length is exactly a whole `SockAddrIn` and
the family written is `AF_INET`, and names the other outcomes instead of
handing back a plausible-looking address. A *failed* receive writes
nothing back at all, so the staged values survive and must not be read as
an outcome.

A timeout adds no new pointer shape — one fixed-size `Timespec` — but it
is the first request whose *result* cannot be read the usual way. The
kernel reports `-ETIME` when the timer ran to completion, which is the
outcome the caller asked for, and `0` when it did not because enough other
completions arrived first. A `Result` would call the working case an error
and the pre-empted case a success, so `Expiry` names all four outcomes
instead; `Cancelled` is separated from `Failed` for the same reason, since
a removed timeout was removed on purpose.

Its storage rule was decided by measurement rather than by analogy. The
kernel copies the `Timespec` during `io_uring_enter` and never reads it
again: a timeout staged at 300ms, submitted, then overwritten with 9000ms
still fires at 300ms, and two timeouts sharing one slot in a single enter
both use the value present at enter rather than at push. That is an
argument for a borrow, and it fails on SQPOLL — `split_owned` accepts a
polling ring, where the submitting thread never enters the kernel and the
SQ thread consumed the entry tens of microseconds *after* `submit`
returned. No call's return proves the copy has happened, so the borrow has
nowhere safe to end and the storage is owned like everything else.

The last two requests were written off in an earlier revision of this
section as "fixed-size scalar or struct arguments, no new shape". Probing
them before wrapping them found a shape in each.

`files_update` is the only request whose result is a **count** rather than
a status, and the count can come back short. An array of
`[good, bad, good]` returns `1`: the first entry installed, the rest
abandoned. The number is positive, so the usual reading of a non-negative
result calls that a success while two of three slots still hold whatever
they held before. `Update` separates `All` from `Partial` so the case
cannot be missed; a bad descriptor in *first* position reports `-EBADF`
instead, so `Partial` always means at least one slot changed. It also does
not own the descriptors it installs — the kernel duplicates each one,
verified by reading through the caller's handle afterwards and by closing
it and still reaching the file through the table. That is what lets
`TableEntry::Install` take a plain `RawFd` rather than an owning handle; a
request that consumed descriptors would have to, or risk a double close.

`epoll_ctl` reads its `epoll_event` for an `Add` or a `Mod` and **not at
all** for a `Del` — a `Del` with a null pointer returns `0` against a real
kernel. `EpollChange` therefore carries the event in the two variants that
use it and omits it from the third, so a mask that would be silently
discarded cannot be written. The storage is still owned for a `Del`,
because nothing in the SQE distinguishes an address that will not be read
from one that has not been read yet.

## Measuring the coverage rather than asserting it

Every earlier revision of this section described the scope in prose, and
twice that prose was wrong. The coverage is now a measurement: a
throwaway probe using `IORING_REGISTER_PROBE` asked the running kernel
what it supports and cross-referenced the answer against this crate's
constructors.

On Linux 7.1.5 the kernel reports 65 supported opcodes. This crate builds
SQEs for 42 of them, and 20 of those have owned wrappers. The 23 with no
constructor at all are, with two exceptions, newer than the `Opcode`
enum, which stopped at `SEND_ZC = 47` and so could not name them: the
four xattr operations, `MSG_RING`, `SYMLINKAT`, `LINKAT`,
`SYNC_FILE_RANGE`, `SENDMSG_ZC`, `READ_MULTISHOT`, `WAITID`, the three
futex operations, `FIXED_FD_INSTALL`, `FTRUNCATE`, `RECV_ZC`,
`EPOLL_WAIT`, `READV_FIXED`, `WRITEV_FIXED`, `PIPE`, `NOP128`, and one
opcode newer than the published header this crate was checked against.

The census also corrected a claim made here one revision ago. `send` was
listed among the owned operations; it is not. Grepping the owned module
for `Sqe::` call sites — one per wrapper — shows no `send_ptr`, and
`recv` and `accept` are owned only in their multishot forms. The
pointer-bearing claim still holds, because a caller reaching for an owned
send has `sendmsg` and `send_zc`, but the count was 19 rather than 20
until `bind` made it 20.

Because this kind of drift is the recurring failure, [`IoUring::probe`]
is now part of the API rather than a throwaway. It is also what a caller
needs: opcode numbers here are compile-time constants, and a kernel older
than the build target rejects the unknown ones with `EINVAL` at
completion — indistinguishable from a malformed request. Asking first is
the only way to tell those apart.

## `bind` and `listen`

The census turned up one gap that was not about newness: this crate had
`socket`, `connect`, `accept`, and `shutdown`, but neither `bind` nor
`listen`. The server half of the socket lifecycle was missing, so no
server could be written without dropping to raw syscalls for two steps in
the middle.

They are asymmetric, and the asymmetry decides the API. `bind` reads a
socket address from caller memory; `listen` reads nothing at all — the
kernel takes the backlog from `len` and rejects a request carrying an
address. So `Sqe::listen` is a safe `fn` with no owned counterpart, and
`bind` gets the full owned treatment.

`bind` copies its address in *prep*, inside `io_uring_enter`: an address
overwritten with `0xFF` after `submit` returned still binds the port
originally staged, while overwriting it between `push` and `submit`
fails with `EAFNOSUPPORT`. That locates the read precisely, and it is the
same situation as the timeout's `Timespec` — including the same reason it
is not enough for a borrow. Under SQPOLL no call's return proves the copy
happened, so the storage is owned.

`PreparedBind` takes a typed `SockAddrIn` rather than raw bytes, which
makes one failure unrepresentable and matters more than it looks: the
kernel spends `EINVAL` on both a malformed address *and* a socket that is
already bound. With malformed addresses ruled out at construction,
`EINVAL` has exactly one reading left. `BindOutcome` then separates
`AlreadyBound` (`EINVAL`) from `AddressInUse` (`EADDRINUSE`) and
`PermissionDenied` (`EACCES`) — measured values, and worth keeping apart
because retrying a different port fixes the second and loops forever on
the first.

**Scope limits.** The owned layer now covers every `io_uring` operation
this crate exposes that takes a pointer into caller memory: read/write,
vectored I/O, zero-copy send, `sendmsg`, `recvmsg`, multishot recv and
accept, `openat`, `openat2`, direct open, direct accept, direct socket,
`statx`, `renameat`, `unlinkat`, `mkdirat`, `timeout`, `files_update`,
`epoll_ctl`, and `bind`. The `unsafe` `Sqe` surface remains for
lock-free users and for the pointer-free operations (`nop`, `cancel`,
`poll_add`, `timeout_remove`, `listen`), which own nothing and so have
nothing to model.

`connect` is the one pointer-bearing operation still reachable only
through the raw surface. It takes a caller `sockaddr` on exactly the
terms `bind` does, so the wrapper would be `PreparedBind` with a
different opcode and a different outcome enum; it is listed here as a
known gap rather than a decision.

Two things are deliberately still raw because they need more than a
request type. Multishot `recvmsg` prepends an `io_uring_recvmsg_out` to
each provided buffer, so the completion must parse a header out of pool
storage rather than out of a region the ticket owns. Linked timeouts must
be submitted *immediately after* the operation they cancel, and nothing in
a per-request `push` API expresses "these two SQEs are adjacent, in this
order, or neither goes" — each push can fail on its own and leave the link
half-formed. Both want a request *pair*, which is a different shape from
anything here.

Neither direct accept nor direct socket has Miri coverage: neither owns
userspace storage, so there is no pointer lifetime to model.

**Status (original): confirmed.**

**Evidence:** `src/op/mod.rs:21–69` defines `Sqe` without a lifetime, derives `Copy`/`Clone`, acknowledges that constructors only borrow during construction, and exposes safe `from_raw`. `src/op/file.rs:57–98` converts slices into pointers. `IoUring::push` and `Submitter::push` in `src/ring/mod.rs` accept those entries safely; subsequent publication/submission is also safe. Related pointer-bearing constructors exist in the network/control/buffer operation modules. `src/ring/register.rs::register_buffers` accepts `IoVec` descriptions without owning the backing storage.

**Failure scenario:** construct a read SQE from a local mutable buffer, let the buffer go out of scope, then safely push and submit the retained SQE. Alternatively, retain access to a live buffer while a kernel operation writes to it. `Sqe::from_raw` bypasses even constructor-time validation. Duplicating a read SQE also duplicates an untracked writable destination.

**Impact:** use-after-free, invalid aliasing, and concurrent access to memory, all reachable without a caller-written unsafe block. Kernel address validation cannot detect a valid address whose Rust ownership or lifetime is wrong.

**Remediation:** establish a single auditable unsafe boundary for raw queue insertion/publication and all externally supplied pointer-bearing operations. Preserve safe NOP/scalar helpers only where their invariants genuinely hold. For a safe asynchronous layer, introduce owned in-flight requests and operation-specific buffer ownership that persists through terminal completion, including multishot termination and zero-copy notifications. Do not rely solely on adding a lifetime to `Sqe`: moving an SQE into a queue must not end the enforced borrow. A droppable/forgettable token must not be the only thing keeping borrowed memory alive.

**Acceptance:** compile-fail cases reject dropping or reborrowing storage while a safe request is active; raw SQE submission requires explicit unsafe responsibility; cancellation and error paths retain storage until the kernel has stopped accessing it. Include nested `IoVec`/`MsgHdr`, path, timespec, fixed-buffer, multishot, and zero-copy cases.

### Q-02 — Provided-buffer references can outlive memory or alias kernel writes

**Status: confirmed.**

**Evidence:** `src/ring/pbuf.rs::buffer_pinned` and `buffer_mut_pinned` return `&'ring [u8]` / `&'ring mut [u8]` from a shorter `&'borrow self`, constrained only by `'ring: 'borrow`. This does not prove the allocation lasts for `'ring`. `buffer`, `buffer_mut`, and `recycle` validate ranges but maintain no per-slot completion/ownership state. Initial registration publishes every buffer to the kernel.

**Failure scenarios:** safe callers can request a `'static` slice, drop the pool, then use the slice. Repeated mutable pinned borrows can produce overlapping mutable references. Even removing pinned methods is insufficient: a caller can borrow a valid slot while it is still offered to, or in use by, the kernel. Repeated recycling can offer the same buffer more than once or overwrite unconsumed descriptors.

**Impact:** dangling references, overlapping mutable references, and Rust/kernel data races.

**Remediation:** remove the lifetime-extending safe methods immediately. Introduce a `CompletedBuffer` lease in its own module; obtain it only after validating a completion against the originating pool and an outstanding operation. Model each slot as offered, in-flight/completed, leased, or recyclable. Reject duplicate recycling and publication beyond available descriptor capacity. Lease references must borrow the lease, and storage must remain owned if a lease is forgotten. If these guarantees are intentionally caller-managed, the relevant methods must instead be unsafe with precise contracts.

**Acceptance:** compile-fail lifetime/alias tests; state-machine tests for fabricated completions, duplicate recycle, stale ids/generations, cross-pool completions, capacity wraparound, and access before completion. Miri should cover the userspace lease model without syscalls.

### Q-03 — `run_one` does not wait for its own operation on all paths

**Status: confirmed.**

**Evidence:** `src/ring/ops.rs:13–24`: push one SQE, `submit_and_wait(1)`, then return `complete().into_result()`. There is no request identity check or outstanding-request isolation. The `?` after submission also returns immediately on syscall error.

**Failure scenario:** leave a NOP completion in the CQ, then call `do_recv` on a connected socket with no data. The existing completion can satisfy the wait and be returned as the receive result, while the receive remains pending against the caller's buffer. A signal interrupt during a wait is another path that can end a borrow while submitted work is still active.

**Impact:** wrong results and premature release of borrowed buffers; therefore independently unsound even if raw constructors are made unsafe.

**Remediation:** temporarily remove safe exposure of these helpers, or implement a separate synchronous owner that cannot mix arbitrary outstanding work. Completion dispatch must correlate exact request identities and preserve unrelated completions. Every failure/cancellation path must establish terminal completion before releasing borrowed storage; requesting cancellation is not sufficient. Do not assume closing the ring synchronously ends all kernel work.

**Acceptance:** regression tests with a pre-existing CQE, pending unrelated operation, out-of-order completions, EINTR, short submission, queue-full errors, and cancellation races. Assert that no return path exposes the buffer while kernel access remains possible.

### Q-04 — Safe raw syscall interface permits memory corruption

**Status: confirmed.**

**Evidence:** `src/lib.rs` publicly exports `syscall`. `src/syscall/mod.rs` exposes safe pointer/length or integer-address wrappers including `read`, `recvfrom`, `getsockname`, `accept4`, `io_uring_setup`, `io_uring_register`, `mmap`, and `munmap`.

**Failure scenario:** safe code takes a pointer to a Rust value, passes it as a writable destination to a syscall, or unmaps a page containing a live allocation. A pointer being in the process address space does not imply exclusive access, sufficient size, or valid lifetime. `mmap` with replacement mappings also requires ownership constraints.

**Impact:** bypass of Rust memory safety independently of `IoUring`.

**Remediation:** make the raw syscall backend internal where possible. Put wrappers on an owning `Syscalls`/architecture backend type and mark operations unsafe when their preconditions cannot be checked. Supply safe slice/reference-based methods only where the syscall's full semantics are constrained. Audit generic interfaces such as `Socket::set_option<T>` for ABI validity, initialization/padding, and option-specific pointer semantics rather than assuming arbitrary `T` is a valid kernel payload.

**Acceptance:** external compile checks cannot perform raw reads/writes/unmapping without unsafe code; bounded safe wrappers preserve destination size and mutability. Review all exported syscall operations, not just those Clippy happens to flag.

### Q-05 — Provided-buffer registration does not retain ring ownership

**Status: confirmed ownership defect; in-flight teardown behavior needs targeted kernel testing.**

**Evidence:** `src/ring/pbuf.rs::ProvidedBufferRing` stores a numeric `fd`, not a retained `RingResources` owner or lifetime borrow. Registration methods return it independently of `IoUring`/`Submitter`. Its destructor unregisters by fd and group id, ignores the result, and unmaps both regions. Manual `unregister_provided_buffers` is available while a pool object remains alive.

**Failure scenarios:** drop the ring before its pool; reuse that fd for another ring with the same buffer-group id; drop the stale pool and unregister the new ring's group. Similarly, manually unregister a group, register a replacement, then drop the old pool. Dropping a pool with selected buffers still in use has no explicit quiescence protocol.

**Impact:** wrong-resource cleanup and unsafe storage teardown assumptions. Exact behavior for in-flight selected buffers must be verified against supported kernels rather than assumed from unregister success.

**Remediation:** registrations must retain shared ring resources and a unique registration identity. Remove or coordinate manual unregister with the owner. Add an explicit close/quiesce operation that reports failures and preserves memory until requests are terminal; design the destructor as a safe fallback, not as a substitute for a shutdown protocol.

**Acceptance:** ring-before-pool drop, either split-half drop order, fd reuse, group replacement, unregister failure, and active multishot teardown tests.

**Related auto-trait defect:** despite documentation claiming `!Send`/`!Sync`, `ProvidedBufferRing` contains only integer-like fields, and `BufferConsumer` wraps it. These fields do not enforce the claimed restrictions; the explicit `Send` impl does not make `BufferConsumer` `!Sync`. Decide the intended guarantees and enforce them with appropriate representation/marker state plus trait assertions.

### Q-06 — Setup accepts layouts that mapping/parser code does not support

**Status: confirmed.**

**Evidence:** `src/types/ring_ctrl.rs` exports `NO_SQARRAY` and `NO_MMAP`; `IoUringBuilder::setup_flags` accepts them. `src/ring/mod.rs::map_rings` assumes conventional mmaps and 64-byte SQEs/16-byte CQEs. `parse_sq` always writes an identity SQ array at `sq_off.array`.

For `NO_SQARRAY`, Linux documents that `sq_off.array` is zero. The unconditional identity-array writes therefore target the start of shared ring metadata rather than an SQ array. `NO_MMAP` requires caller-provided memory, which this builder does not supply. The bitflag `Not` implementation also allows callers to form unnamed flag bits; safety cannot depend on only named constants being constructible.

**Impact:** shared-ring corruption, malformed queue state, errors, or hangs for accepted configurations. Extended entry-size modes are also incompatible with the hard-coded strides if accepted by the kernel.

**Remediation:** validate setup flags against an explicit supported mask before setup. Reject `NO_MMAP`, alternate SQ/CQ layouts, and other unimplemented modes. Implement `NO_SQARRAY` only with a separate validated layout path that never writes an SQ array. Use checked mapping-size calculations.

**Acceptance:** mode-by-mode rejection/support tests, named and unnamed flag combinations, and layout tests that inspect offsets/strides before submission. No unsupported mode may reach pointer parsing.

### Q-07 — Short submission results are counted as full submission

**Status: confirmed against syscall contract; fault scenario not injected in this audit.**

**Evidence:** both ring owners' `submit`/`submit_and_wait` assign `sq_submitted = sq_tail_local` after a successful enter regardless of its returned count. Linux permits submitting fewer entries than requested. The unsplit high-CQ-occupancy branch discards the first enter's count and returns the second enter's result, whose submission count is normally zero.

**Impact:** remaining SQEs can be left unsubmitted; subsequent `submit()` may return zero despite pending work. The high-occupancy path reports an incorrect submitted count. Error-after-publication accounting also needs explicit reconciliation.

**Remediation:** introduce one `SubmissionQueue`/submission-progress implementation shared by split and unsplit owners. Advance normal-mode progress by the actual consumed count and preserve unsent work. Distinguish kernel SQPOLL consumption from syscall-driven consumption. Aggregate counts across multi-enter paths and define retry semantics around errors and published head/tail state.

**Acceptance:** deterministic backend tests for return counts 0, partial, and full; EINTR/resource errors; wraparound; high CQ occupancy; retries; and split/unsplit parity. Assert each request is consumed exactly once and returned counts match actual submission.

### Q-08 — Split API ignores thread-affine ring modes

**Status: confirmed against Linux setup/enter contracts.**

**Evidence:** `IoUringBuilder` exposes `single_issuer` and `defer_taskrun`; `split` always returns `Send` halves and does not retain setup flags to enforce mode constraints. `Completer::wait` issues GETEVENTS on whichever thread owns it. `defer_taskrun()` does not add the required SINGLE_ISSUER flag; the existing builder test manually adds it.

Linux enforces the designated issuer for SINGLE_ISSUER and the submitting/creating thread requirement for DEFER_TASKRUN completion processing, subject to documented mode exceptions such as SQPOLL.

**Impact:** configurations that appear supported fail with issuer errors or do not progress when moved to the advertised dedicated threads.

**Remediation:** retain validated setup mode and thread-affinity semantics. Make deferred task-run configuration imply its prerequisites or reject incomplete combinations. Reject incompatible splits or expose distinct local and transferable ring types. Do not try to solve runtime thread-affinity restrictions with an unconditional `Send` promise.

**Acceptance:** test creation, submission, and wait from same/different threads in ordinary, SQPOLL, SINGLE_ISSUER, and DEFER_TASKRUN modes. Document intentional restrictions and assert deterministic errors for unsupported transitions.

### Q-09 — Architecture support exceeds ABI correctness and platform gating

**Status: confirmed source-level ABI/gating problems; non-host execution not performed.**

**Evidence:** `src/lib.rs:1–7` gates on architecture but not `target_os = "linux"`. `src/types/net.rs::MsgHdr` hard-codes x86_64 padding; those padding fields shift members on 32-bit ARM. `src/types/epoll.rs` unconditionally uses the packed x86_64-style epoll layout rather than target-specific kernel layout. Layout tests in `src/tests/mod.rs` hard-code 64-bit sizes. `src/syscall/mod.rs::check` treats every negative `isize` as errno, although successful 32-bit mappings can have the high bit set. Pbuf size multiplication is unchecked on 32-bit targets.

**Impact:** wrong kernel arguments/layouts on advertised architectures, valid mmap addresses misclassified as errors, and potentially dangerous Linux syscall numbers used on another OS. Unsupported architectures currently compile an effectively empty crate rather than producing an explicit unsupported-target error.

**Remediation:** initially narrow supported targets to configurations actually validated. Add Linux OS gating and clear compile errors. Implement target-correct `MsgHdr`/epoll layouts, Linux's reserved negative errno-range decoding, and checked address/length arithmetic. Validate pbuf counts against the kernel's maximum (32768 entries), not just nonzero/power-of-two constraints. Only restore each target after dedicated ABI and runtime verification.

**Acceptance:** per-target size, alignment, and field-offset assertions; cross-compilation plus execution on x86_64, aarch64, riscv64, and ARM if retained; synthetic high-bit successful syscall-return tests; checked arithmetic boundary tests; non-Linux build rejection. Treat cross-compilation alone as insufficient ABI proof.

### Q-10 — Setup allocation failure leaks a separately mapped CQ

**Status: confirmed conditional error-path defect.**

**Evidence:** `src/ring/mod.rs::from_params` disarms `SetupGuard` before `RingResources::alloc`. If allocation fails, its manual cleanup unmaps SQEs and the SQ ring and closes the fd, but does not unmap `cq_ring_region` when SINGLE_MMAP is absent.

**Impact:** a CQ mapping leaks in that fallback layout under allocation failure. The path is less relevant to the README's modern kernel baseline, where SINGLE_MMAP is generally available, but the implemented fallback is still incorrect.

**Remediation:** transfer resources transactionally; keep cleanup ownership armed until the shared owner is successfully installed. Give mapped regions their own RAII owner in a dedicated module and eliminate duplicate manual unwind code.

**Acceptance:** inject failure at every allocation/map stage in single- and dual-mapping layouts; assert each successfully acquired fd/mapping is released exactly once.

### Q-11 — Integration test uses a predictable truncating `/tmp` path

**Status: confirmed.**

**Evidence:** `src/tests/mod.rs:2159–2187`, `openat2_basic`, opens `/tmp/ququmatz_openat2_test` with CREAT | TRUNC, no exclusive creation, and `resolve = 0`, then unlinks it.

**Impact:** concurrent test runs interfere; a pre-existing symlink can redirect truncation to another file writable by the test runner. Do not run this suite with elevated privileges. Other filesystem fixtures should be reviewed as well.

**Remediation:** use a Rust-owned private temporary directory with secure unique creation and restrictive permissions, then open relative to its directory fd. Prefer unnamed temporary files where path semantics are not under test. Ensure cleanup is ownership-based and cannot remove a pre-existing object.

**Acceptance:** concurrent-process test runs do not share paths; a deliberately pre-existing symlink outside the private fixture cannot be followed or modified; cleanup works after test failure.

### Q-12 — Safety-critical responsibilities remain coupled and duplicated

**Status: confirmed structural finding; graph output is a diagnostic, not proof of a runtime cycle.**

**Evidence:** `src/ring/mod.rs` is 1297 lines and combines shared resource ownership, mapped regions, partial setup, SQ/CQ parsing, submission, completion, splitting, and iterators. `src/ring/pbuf.rs` is 756 lines and combines allocation/registration, producer protocol, consumer wrappers, raw slicing, and tests. `src/tests/mod.rs` is 2590 lines. Split and unsplit submission logic is duplicated and already differs in CQ synchronization/backpressure handling. Free functions remain in syscall, ring mapping/parsing, and pbuf logic.

The graph's back-edges include IoUring→builder/iterator, Completer→iterator, ProvidedBufferRing→consumer, RecvmsgOut→parts, and Error→Completion. Factory/iterator relationships and documentation-derived references may explain some of these; do not introduce meaningless wrappers solely to make the report green.

**Remediation:** after safety containment, extract one cohesive owner at a time into its own file: `MappedRegion`, shared ring resources, `RingLayout`, `SubmissionQueue`, `CompletionQueue`, buffer registration, buffer leases, and completion dispatch. Put raw syscall operations on backend structs/trait impls. Split test fixtures and test domains into separate files. Keep `IoUring` as orchestration rather than a second implementation of each protocol. Preserve safety contracts in API documentation; avoid explanatory implementation prose where better names/types suffice.

**Acceptance:** after each extraction, build/test/Clippy in both feature modes, build the entire workspace, and rerun the graph report. Record which edges are genuine dependencies versus tool inference and avoid worsening the baseline without an explicit reason.

### Q-13 — Published compatibility and safety documentation is misleading

**Status: confirmed.**

**Evidence:** README claims Linux 5.6+ “for full feature set”, while pbuf rings require 5.19 and several operations/modes require 6.x. README usage specifies `ququmatz = "0.1"` for a 0.15.1 package; that requirement does not select 0.15.x. README lists only x86_64 while crate gating enables four architectures. Cargo.toml does not declare `rust-version` despite the Rust 1.85 claim. `dhat-heap` introduces a dependency tree beyond the default zero-dependency configuration. Safety and thread-trait claims in SQE, helper, and pool documentation conflict with the implementation (Q-01–Q-05).

**Remediation:** publish an operation/setup-feature kernel matrix, verified target matrix, explicit MSRV, corrected dependency snippet, and feature-qualified dependency/no_std claims. Explain that no_std does not make Linux syscalls usable on bare-metal targets. Remove “safe” guarantees until enforced by types and protocols. Separate compile-only examples from tested runtime behavior.

**Acceptance:** CI checks declared MSRV and supported kernels/targets; README snippets use the intended release series and are compiled; documentation agrees with trait assertions and safety tests.

## Additional investigations before a safety release

These are follow-up review items, not additional demonstrated runtime defects:

- Compare the SQPOLL tail-publication/NEED_WAKEUP sequence with liburing's store-to-load barrier protocol, especially on weakly ordered CPUs. Passing one host roundtrip does not establish absence of lost wakeups.
- Stress CQ overflow, delayed `sync_cq`, and split completion progress. The occupancy-based “backpressure safety” branch is not itself a proof against deadlock or dropped completions.
- Audit registered ring-fd lifecycle: `register_ring_fd` has no matching high-level unregister owner. Document task-local registration semantics and cleanup.
- Audit all operation encodings against current kernel/liburing definitions, including flag combinations, direct descriptors, multishot termination, and zero-copy notification lifetime. Layout tests can agree with an incorrect implementation if their expected values are copied from it.
- Add targeted coverage of `Socket::set_option<T>`, arbitrary address families versus IPv4-only address wrappers, close-on-exec defaults for accept, and application-visible descriptor ownership/reuse.
- Check arithmetic for user-constructible completion values: `Completion::into_result` negates any negative `i32`, including `i32::MIN`, which can panic with overflow checks. Either constrain the domain or define total conversion behavior.
- Run dependency advisory and license checks for default, profiling, and development dependency graphs. No advisory-clean claim is made here.

## Remediation sequence

### Phase 0 — Contain unsafe public contracts

**Owner:** crate maintainer plus an independent Rust unsafe-code reviewer.

1. Correct Q-11 test isolation before adding more runtime tests.
2. Restrict/remove safe raw syscall entry points (Q-04).
3. Restrict raw asynchronous submission and erase misleading safe-constructor guarantees (Q-01).
4. Remove lifetime-extending pool methods and require an unsafe contract until leases are implemented (Q-02).
5. Remove or restrict safe synchronous helpers until completion/error semantics are repaired (Q-03).
6. Prevent unowned registration teardown and stale group cleanup (Q-05).

**Exit:** no known safe API path can free/reborrow kernel-accessed memory or fabricate references beyond an owner's lifetime. Publish migration guidance and a breaking 0.x release plan; warn downstream consumers without claiming that documentation alone repairs soundness.

### Phase 1 — Repair kernel protocol correctness

**Owner:** ring/backend maintainer.

Address Q-06 through Q-10 one defect at a time. Introduce deterministic syscall-result/failure injection through a Rust backend trait to test partial submissions and teardown without relying on rare host-kernel behavior. Reject unsupported layouts and thread-affine transitions before any pointer parsing or publication.

**Exit:** tests cover all short/error/retry submission states, accepted setup modes, ring/pool teardown orderings, and allocation failures. Unsupported targets/modes fail explicitly.

### Phase 2 — Implement a sound safe layer

**Owner:** API/ownership maintainer, reviewed independently.

Implement owned in-flight requests, exact completion dispatch, completed-buffer leases, generation-aware registration ownership, and terminal-completion shutdown. Define separate lifetime rules for ordinary I/O, multishot operations, and zero-copy sends. Review behavior under `mem::forget`, panic, dropped request handles, cancellation failure, and lost CQEs; destructor execution must not be the sole safety assumption.

**Exit:** compile-fail tests reject invalid borrows; Miri validates pure userspace ownership/state models; kernel integration tests validate operation completion and teardown contracts on the supported kernel matrix.

### Phase 3 — Modularize and restore documented support

**Owner:** maintainability/release maintainer.

Perform the Q-12 extractions individually, not as a broad rewrite. Repair target-specific ABIs before advertising those targets. Update package metadata, README, capability documentation, and CI (Q-13). Keep optional profiling integration out of default runtime state; use feature-gated fields and thin enabled/no-op wrapper methods if runtime feature state is introduced.

**Exit:** workspace verification remains green after every extraction; graph warnings are reduced or explicitly justified; release documentation describes only verified configurations.

## Required regression and release checklist

- [ ] Compile-fail tests for all safe asynchronous borrowed inputs and pool leases.
- [ ] Raw pointer/address syscalls require unsafe responsibility or are private.
- [ ] Existing CQEs cannot satisfy another operation's synchronous completion.
- [ ] EINTR, short submits, cancellation, and teardown cannot prematurely release storage.
- [ ] Duplicate/stale/cross-pool recycling and completion claims are rejected.
- [ ] Pool and ring lifetimes survive either split-half drop order and fd/group reuse.
- [ ] Every accepted setup mode has matching mapping, stride, and thread semantics.
- [ ] Per-target ABI sizes, alignments, and offsets are verified against Linux definitions.
- [ ] High-bit syscall success and checked length/address arithmetic are tested.
- [ ] Allocation failures release all acquired resources exactly once.
- [ ] Tests use isolated filesystem fixtures and bounded waits.
- [ ] Default and dhat-heap: workspace build, full tests, doctests, strict Clippy.
- [ ] Release-mode tests, formatting, MSRV, kernel/target matrix, and pure-model Miri.
- [ ] `cargo graph --report` reviewed against the 37-skip/6-back-edge baseline.
- [ ] Dependency advisory/license checks and independent unsafe-code review completed.
- [ ] Migration guide distinguishes unsafe raw access from the sound safe API.

## References

- Linux `io_uring_setup(2)`: https://man7.org/linux/man-pages/man2/io_uring_setup.2.html — NO_SQARRAY offsets, NO_MMAP requirements, setup-mode prerequisites, thread restrictions, and asynchronous resource cleanup.
- Linux `io_uring_enter(2)`: https://man7.org/linux/man-pages/man2/io_uring_enter.2.html — consumed-entry return values, unordered completions, EINTR, deferred-task thread restrictions, and zero-copy notification semantics.
- Rust Reference, behavior considered undefined: https://doc.rust-lang.org/reference/behavior-considered-undefined.html — reference validity, aliasing, and data races (background reference; not fetched during this audit).

**Bottom line:** preserve the crate's lightweight syscall approach, but make memory ownership and terminal completion explicit. Fix the known soundness defects before optimizing or treating the passing suite as evidence of production-safe Rust APIs.
