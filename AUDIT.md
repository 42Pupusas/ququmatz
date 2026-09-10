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

**Scope limits.** This covers ordinary `read`/`write` only. Vectored I/O,
paths, `statx`, multishot, and zero-copy still go through the `unsafe`
constructors and need their own owned request types — `send_zc` in
particular must not release its buffer on the send CQE alone. The
`unsafe` `Sqe` surface remains for those and for lock-free users.

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
