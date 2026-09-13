# ququmatz

Zero-dependency `io_uring` bindings for Linux via raw syscalls — no libc required.

## Features

- `#![no_std]` — no heap allocator or `std` runtime required, but this is
  still Linux-only: it issues raw `io_uring` syscalls by number, which
  only Linux assigns, so it is not usable on bare-metal or non-Linux
  embedded targets
- Direct syscall interface — no libc, no C dependencies
- Type-safe SQE builder API for all common operations
- Supports: read/write, vectored I/O, fixed buffers, openat/close, fsync, poll, timeout, accept/connect/send/recv, statx, fallocate, rename, unlink, shutdown, linked chains, and more
- SQPOLL support
- File and buffer registration
- Zero dependencies in the default build; the optional `dhat-heap` feature
  (used by `examples/dhat_comparison.rs` to profile allocations) pulls in
  the `dhat` crate and is never enabled unless you ask for it

## Requirements

- Linux; `x86_64`, `aarch64`, `riscv64`, or `armv7` (other targets are
  rejected at compile time by the crate's own `compile_error!`, not
  silently miscompiled — see `src/lib.rs`)
- A kernel new enough for whichever operations you use. `IoUring::new`
  itself only needs `io_uring_setup` (Linux 5.1), but several features
  used through this crate need much newer kernels: provided-buffer rings
  need 5.19, zero-copy send needs 6.0, and a handful of narrower register
  ops go up to 6.14 — each such method's doc comment states its own
  minimum. There is no single "5.6+" floor that covers the whole API.
- Rust 1.88+ (needs const `cast_signed`/`cast_unsigned` and
  `is_multiple_of`, both newer than the edition's own 1.85 floor) on
  `x86_64`; the four extra targets above are
  compiled and their ABI layouts checked under `cross`/qemu in CI, but the
  `io_uring` runtime itself is only exercised on `x86_64` — qemu-user does
  not implement `io_uring_setup`, so no non-`x86_64` kernel runtime path
  has run yet on real hardware.

## Usage

```toml
[dependencies]
ququmatz = "0.15"
```

```rust
use ququmatz::{IoUring, Sqe};

let mut ring = IoUring::new(64).expect("io_uring setup failed");

// Submit a NOP to verify the ring works
ring.push(Sqe::nop().user_data(42)).expect("push");
ring.submit_and_wait(1).expect("submit");

let cqe = ring.complete().expect("completion");
assert_eq!(cqe.user_data, 42);
assert_eq!(cqe.result, 0);
```

## Benchmarks

See [`BENCHMARKS.md`](BENCHMARKS.md) for head-to-head numbers against the
[`io-uring`](https://crates.io/crates/io-uring) crate — the only other
actively maintained raw `io_uring` binding for Rust — plus an honest
account of what those numbers do and don't establish, and one unresolved
anomaly flagged for follow-up rather than dressed up as a result.

## License

MIT
