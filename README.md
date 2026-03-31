# ququmatz

Zero-dependency `io_uring` bindings for Linux via raw syscalls — no libc required.

## Features

- `#![no_std]` — suitable for embedded or minimal runtimes
- Direct syscall interface — no libc, no C dependencies
- Type-safe SQE builder API for all common operations
- Supports: read/write, vectored I/O, fixed buffers, openat/close, fsync, poll, timeout, accept/connect/send/recv, statx, fallocate, rename, unlink, shutdown, linked chains, and more
- SQPOLL support
- File and buffer registration

## Requirements

- Linux kernel 5.6+ (for full feature set)
- x86_64 architecture
- Rust 1.85+ (edition 2024)

## Usage

```toml
[dependencies]
ququmatz = "0.1"
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

## License

MIT
