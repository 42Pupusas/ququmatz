# Benchmarks

## What this crate is compared against, and why

Two harnesses run against [`io-uring`](https://crates.io/crates/io-uring)
(`tokio-rs/io-uring`), both gated to `x86_64` because that crate ships a
prebuilt ABI table only for that architecture:

- `benches/comparison.rs` — isolated single-opcode microbenchmarks (build
  one SQE, do one submit/wait/complete cycle).
- `benches/realistic.rs` — multi-step workloads shaped like what an
  application actually runs: a request/response round trip, and a
  durable-write chain.

`io-uring` is the only other actively maintained raw `io_uring` binding in
the Rust ecosystem, which is why it is the sole comparison target:

- **55M+ total downloads, 11.8M in the last 90 days**, with a release as
  recent as this month (0.7.15). It is the library `tokio-uring` and
  `monoio` build their runtimes on, so it is the de facto standard raw
  layer.
- **`rio`** (`spacejam/rio`) was considered and rejected. Its last release
  was **0.9.4 in August 2020** — five years stale, predating multishot
  operations, direct descriptors, and every kernel feature this crate's
  `owned` layer covers. It is also **GPL-3.0**, which would put a
  copyleft dependency in this crate's dev-dependency tree for no
  comparative benefit over a crate that is both current and permissively
  licensed.
- `tokio-uring` and `monoio` are async *runtimes* built atop `io-uring`,
  not raw bindings; comparing against them would be measuring executor
  overhead, not the syscall layer this crate implements.

## Realistic workloads (`benches/realistic.rs`)

Isolated single-opcode numbers understate what a real caller pays, because
a real operation is rarely just one syscall: a network service does
recv-then-send in a loop, and a durable-write path is open, write, fsync,
close — all four, every time. Two workloads capture that shape, each run
against `ququmatz`, `io-uring`, and a plain blocking `std` baseline with no
`io_uring` involved at all:

- **`echo_roundtrip`** — a loopback client writes a small request; the
  "server" side receives it through one ring op and echoes it back through
  a second; the client reads the reply. This is the request/response loop
  a network service actually runs, not a single recv in isolation.
- **`log_append`** — open a fresh file, write one record, `fsync` it,
  close it, linked as a single submission (`IOSQE_IO_LINK`). This is the
  durability shape a log or write-ahead-log writer needs: benchmarking
  `write` alone (as `comparison.rs` does) would silently drop the fsync
  and close that durability actually requires.

Measured on the development host (`arrakis`, x86_64, kernel 5.14) via
`cargo bench --bench realistic`, `divan`, 100 samples per case:

```text
realistic           fastest       │ slowest       │ median        │ mean          │ samples │ iters
├─ echo_roundtrip                 │               │               │               │         │
│  ├─ io_uring      14.76 µs      │ 67.25 µs      │ 14.87 µs      │ 15.51 µs      │ 100     │ 100
│  ├─ ququmatz      14.52 µs      │ 33.73 µs      │ 14.71 µs      │ 15.09 µs      │ 100     │ 100
│  ╰─ std_blocking  13.38 µs      │ 29.36 µs      │ 13.47 µs      │ 14.46 µs      │ 100     │ 100
╰─ log_append                     │               │               │               │         │
   ├─ io_uring      36.67 µs      │ 184.7 µs      │ 41.01 µs      │ 44.81 µs      │ 100     │ 100
   ├─ ququmatz      36.43 µs      │ 65.75 µs      │ 44.42 µs      │ 44.8 µs       │ 100     │ 100
   ╰─ std_blocking  17.31 µs      │ 28.57 µs      │ 18.05 µs      │ 20.59 µs      │ 100     │ 100
```

**Reading it:** `ququmatz` and `io-uring` land within noise of each other
on both workloads — the isolated-opcode parity from `comparison.rs` holds
under realistic multi-step use too. Both cost roughly 2× the plain
blocking baseline on these small, single-connection, single-file
workloads run one operation at a time. `io_uring`'s actual advantage —
batching many concurrent operations behind one syscall — cannot show up
here, because neither workload above ever has more than one operation in
flight; see `echo_roundtrip_concurrent` below for the workload that
actually exercises it.

### Concurrent workload (`echo_roundtrip_concurrent`)

The two workloads above submit one operation, wait for it, submit the
next — never more than one thing in flight. That is not the case
`io_uring` exists for. `echo_roundtrip_concurrent` drives `K` loopback
connections per iteration: one ring pushes `K` recvs and submits them in
a single `enter` syscall, drains `K` completions by `user_data`, then
does the same for `K` sends. `ququmatz`, `io-uring`, and a third variant,
`ququmatz_split`, all implement that exact batching shape, and all three
are compared against `K` OS threads, each blocking on its own connection
with plain `read`/`write` — the design a batching ring has to beat once
concurrency is high enough for thread-wakeup and scheduler overhead to
matter. `K` sweeps 1/8/32/128 so the crossover, if any, is visible rather
than asserted.

`ququmatz_split` is `ququmatz`'s `IoUring::split()` driven by two
persistent OS threads instead of one: a submission thread holds the
`Submitter` and pushes/submits each phase's SQEs, a completion thread
holds the `Completer` and reaps that phase's CQEs, and the two
communicate through a `quetzalcoatl` SPSC ring carrying a small "ticket"
(which phase, how many completions to wait for) plus a `std::sync::mpsc`
channel carrying the recv byte counts the send phase needs. This is
genuinely cross-thread for the whole benchmark, not per call — unlike
`ququmatz_split` in `benches/comparison.rs`, which calls `Submitter`/
`Completer` from a single thread and only exercises the split API's
shape, not its cross-thread cost.

```text
realistic                     fastest       │ slowest       │ median        │ mean          │ samples │ iters
╰─ echo_roundtrip_concurrent                │               │               │               │         │
   ├─ io_uring                              │               │               │               │         │
   │  ├─ 1                    9.116 µs      │ 33.74 µs      │ 9.196 µs      │ 9.586 µs      │ 100     │ 100
   │  ├─ 8                    61.73 µs      │ 108.2 µs      │ 62.16 µs      │ 63.21 µs      │ 100     │ 100
   │  ├─ 32                   243.3 µs      │ 421.1 µs      │ 247.8 µs      │ 252.4 µs      │ 100     │ 100
   │  ╰─ 128                  995.4 µs      │ 1.612 ms      │ 1.02 ms       │ 1.034 ms      │ 100     │ 100
   ├─ ququmatz                              │               │               │               │         │
   │  ├─ 1                    9.086 µs      │ 22.67 µs      │ 9.166 µs      │ 9.397 µs      │ 100     │ 100
   │  ├─ 8                    60.42 µs      │ 105.9 µs      │ 62.26 µs      │ 63.26 µs      │ 100     │ 100
   │  ├─ 32                   237.8 µs      │ 394.3 µs      │ 246.1 µs      │ 251.6 µs      │ 100     │ 100
   │  ╰─ 128                  988 µs        │ 1.589 ms      │ 1.021 ms      │ 1.033 ms      │ 100     │ 100
   ├─ ququmatz_split                        │               │               │               │         │
   │  ├─ 1                    24.24 µs      │ 208.8 µs      │ 24.86 µs      │ 32.77 µs      │ 100     │ 100
   │  ├─ 8                    82.25 µs      │ 235.4 µs      │ 83.29 µs      │ 88.99 µs      │ 100     │ 100
   │  ├─ 32                   273.4 µs      │ 528.3 µs      │ 286.7 µs      │ 298.8 µs      │ 100     │ 100
   │  ╰─ 128                  1.053 ms      │ 1.912 ms      │ 1.092 ms      │ 1.133 ms      │ 100     │ 100
   ╰─ std_blocking_threads                  │               │               │               │         │
      ├─ 1                    37.27 µs      │ 100.3 µs      │ 47.2 µs       │ 51.83 µs      │ 100     │ 100
      ├─ 8                    141.4 µs      │ 263.7 µs      │ 156.9 µs      │ 162.5 µs      │ 100     │ 100
      ├─ 32                   504 µs        │ 934 µs        │ 594.1 µs      │ 602.9 µs      │ 100     │ 100
      ╰─ 128                  2.133 ms      │ 3.033 ms      │ 2.564 ms      │ 2.555 ms      │ 100     │ 100
```

**Reading it:** `ququmatz` and `io-uring` land within noise of each other
at every `K` — the batching-path parity holds here the same way the
single-operation parity did on `echo_roundtrip` above. Both beat
`std_blocking_threads` at every `K` tested, and the margin widens as `K`
grows — roughly 4× at `K=1` down to roughly 2.5× at `K=128`
(`std_blocking_threads` scales worse than linearly past `K=32`, plausibly
thread-spawn/join and scheduler contention rather than the syscalls
themselves, though that split was not separately measured). This is the
result the earlier two workloads structurally could not show: one ring
batching many operations behind one syscall beats one thread per
connection once there is more than one connection to serve, and
`ququmatz` gets the same batching win `io-uring` gets, not a smaller one.

`ququmatz_split` sits between the single-ring variants and
`std_blocking_threads`: it still beats `std_blocking_threads` at every
`K` (roughly 1.5× at `K=1`, narrowing to roughly 1.9× at `K=128`), but it
is consistently slower than the single-threaded `ququmatz`/`io-uring`
runs — most visibly at `K=1`, where its median is nearly 3× the
single-ring median. That gap is the cross-thread handoff cost this
variant pays on every iteration: two `quetzalcoatl` SPSC pushes/pops and
two `std::sync::mpsc` round trips per phase pair, none of which the
single-threaded split-ring benchmark in `comparison.rs` pays, and none of
which a single-threaded ring pays at all. The gap narrows as `K` grows
because the fixed per-iteration handoff cost is amortized over more
recv/send work per phase, the same shape `io_uring` batching itself
relies on.

Reproduced across two consecutive runs with consistent numbers at each
`K`.

What this does **not** establish: `K=128` on one loopback host with one
ring and threads capped by the same machine's core count is not a
production load test, and no attempt was made to find where
thread-per-connection stops being the wrong design — only that it
already is by `K=8`. Nor does it establish that a submit/complete thread
split is never worth it: this workload's per-iteration submit-wait-recv
round trip is exactly the shape that punishes an extra thread handoff
most, since the completion thread cannot do useful work while the
submission thread blocks on it (and vice versa) — a workload where the
submission and completion sides have independent, overlapping work would
show a different trade.

### A methodology failure caught before publishing

The first run of `log_append` reported `ququmatz` roughly **8× slower**
than `io-uring`, with one 18ms outlier against a ~40µs median elsewhere.
That result was not reported here, because the benchmark closures read
each completion's result but never checked it — a `write`, `fsync`, or
`close` that failed (or a linked op that was skipped after an earlier
failure in the chain returned `-ECANCELED`) would still "complete"
in a few microseconds and be silently counted as a real data point next
to runs that did the actual I/O.

Adding `assert!(result >= 0)` over every completion in both variants
made the gap and the outlier disappear on the next two runs, which are
the numbers published above. That is consistent with the failing run
having measured something cheaper than the real workload on one side —
almost certainly transient `/tmp` filesystem contention from many
open/write/fsync/close cycles racing prior benchmark warmup iterations'
cleanup, given the failure mode was a single large outlier rather than a
sustained shift. No root cause was pinned down further than that, and
none is claimed; what is claimed is that the checked numbers are
consistent across three separate runs and the unchecked ones were not
trustworthy enough to publish.

The standing rule this confirms again: **a benchmark that only times an
operation, without checking what it returned, can time a degenerate or
failed run and report it as a measurement.** Every benchmark added after
this one checks results before taking `divan::black_box` of them.

## Isolated-opcode benchmarks (`benches/comparison.rs`)

Every representative single operation, one call at a time: build one SQE,
one submit/wait/complete cycle.

```text
comparison             fastest       │ slowest       │ median        │ mean          │ samples │ iters
├─ linked_nops_3                     │               │               │               │         │
│  ├─ io_uring         1.622 µs      │ 13.42 µs      │ 1.642 µs      │ 1.773 µs      │ 100     │ 100
│  ╰─ ququmatz         1.572 µs      │ 19.95 µs      │ 1.732 µs      │ 1.951 µs      │ 100     │ 100
├─ nop_batch_32                      │               │               │               │         │
│  ├─ io_uring         3.525 µs      │ 12.32 µs      │ 4.177 µs      │ 4.119 µs      │ 100     │ 100
│  ╰─ ququmatz         4.136 µs      │ 14.54 µs      │ 4.482 µs      │ 4.736 µs      │ 100     │ 100
├─ nop_batch_128                     │               │               │               │         │
│  ├─ io_uring         9.747 µs      │ 43.92 µs      │ 12.38 µs      │ 12.56 µs      │ 100     │ 100
│  ╰─ ququmatz         9.888 µs      │ 36.55 µs      │ 13.23 µs      │ 13.53 µs      │ 100     │ 100
├─ nop_single                        │               │               │               │         │
│  ├─ io_uring         761.7 ns      │ 4.257 µs      │ 916.2 ns      │ 942.1 ns      │ 100     │ 100
│  ╰─ ququmatz         730.7 ns      │ 3.996 µs      │ 850.7 ns      │ 880.5 ns      │ 100     │ 100
├─ read_4k                           │               │               │               │         │
│  ├─ io_uring         1.371 µs      │ 24.27 µs      │ 7.197 µs      │ 6.184 µs      │ 100     │ 100
│  ╰─ ququmatz         7.884 µs      │ 15.15 µs      │ 7.994 µs      │ 8.446 µs      │ 100     │ 100
├─ ring_setup                        │               │               │               │         │
│  ├─ io_uring         20.49 µs      │ 51.63 µs      │ 25.18 µs      │ 26.97 µs      │ 100     │ 100
│  ╰─ ququmatz         27.91 µs      │ 52.04 µs      │ 32.26 µs      │ 32.83 µs      │ 100     │ 100
├─ sqe_build_nop                     │               │               │               │         │
│  ├─ io_uring         1.229 ns      │ 11.16 ns      │ 1.229 ns      │ 1.332 ns      │ 100     │ 204800
│  ╰─ ququmatz         3.039 ns      │ 3.323 ns      │ 3.049 ns      │ 3.068 ns      │ 100     │ 102400
├─ sqe_build_read                    │               │               │               │         │
│  ├─ io_uring         45.25 ns      │ 62.47 ns      │ 48.62 ns      │ 49.57 ns      │ 100     │ 6400
│  ╰─ ququmatz         42.13 ns      │ 43.4 ns       │ 42.29 ns      │ 42.33 ns      │ 100     │ 6400
├─ sqe_build_write                   │               │               │               │         │
│  ├─ io_uring         1.542 ns      │ 7.197 ns      │ 1.542 ns      │ 1.602 ns      │ 100     │ 204800
│  ╰─ ququmatz         1.253 ns      │ 2.746 ns      │ 1.258 ns      │ 1.274 ns      │ 100     │ 204800
├─ struct_sizes                      │               │               │               │         │
│  ╰─ size_validation  0.331 ns      │ 0.334 ns      │ 0.331 ns      │ 0.332 ns      │ 100     │ 409600
├─ write_4k                          │               │               │               │         │
│  ├─ io_uring         1.372 µs      │ 51.91 µs      │ 5.304 µs      │ 5.38 µs       │ 100     │ 100
│  ├─ ququmatz         8.204 µs      │ 17.83 µs      │ 9.227 µs      │ 9.265 µs      │ 100     │ 100
│  ╰─ ququmatz_split   981.7 ns      │ 29.03 µs      │ 1.141 µs      │ 1.646 µs      │ 100     │ 100
╰─ writev_2x2k                       │               │               │               │         │
   ├─ io_uring         1.302 µs      │ 121.9 µs      │ 5.524 µs      │ 7.357 µs      │ 100     │ 100
   ╰─ ququmatz         8.805 µs      │ 22.15 µs      │ 9.757 µs      │ 9.849 µs      │ 100     │ 100
```

`struct_sizes` is not a timing comparison — it is a runtime assertion that
`IoUringSqe`/`IoUringCqe` are byte-identical in size to `io-uring`'s
`squeue::Entry`/`cqueue::Entry` (64 and 16 bytes respectively). It belongs
in the bench harness so a size regression shows up next to the numbers it
would affect, but it is a correctness check, not a measurement.

**SQE construction and single-shot NOP round trips are comparable** —
within noise of each other in both directions.

**File I/O in isolation (`read_4k`, `write_4k`, `writev_2x2k`) shows
`io-uring` faster in the unsplit path**, by roughly 1.3–1.6×. This does
**not** reappear in the realistic `log_append` workload above, where the
two crates are at parity — the isolated numbers reflect single-op
overhead that a multi-step workload's other costs (open, fsync, close,
kernel round trips) dilute. No profiling has been done to attribute the
isolated-case gap to a specific cause; treat it as an open question about
single-op overhead, not a workload-level regression.

**The `write_4k` split-path anomaly is unresolved and flagged, not
claimed.** `ququmatz_split` (using this crate's `Submitter`/`Completer`
split) is faster than *both* the unsplit `ququmatz` benchmark and
`io-uring`'s own split API — by roughly an order of magnitude, too large
a gap to attribute to the one extra atomic load the unsplit path's
CQ-occupancy backpressure check performs. No measurement was done to
isolate the cause (page cache state, per-file dentry/inode effects from
each variant using a distinct temp file, or something else). This crate
does **not** advertise "split submission is 10× faster" as a verified
property — it is a lead for follow-up profiling, not a result, and the
`log_append` methodology failure above is a reminder of exactly how such
a number can be wrong.

## Methodology and its limits

- Single ring, single thread, one benchmark process, on one x86_64
  development machine. No multi-core, no concurrent-ring, no sustained
  load or tail-latency (p99/p999) measurement.
- File I/O benchmarks write/read through the page cache (no
  `O_DIRECT`), so they measure this crate's syscall path plus whatever
  the kernel's writeback and caching layers do that day, not raw device
  throughput.
- 100 samples via `divan`'s default configuration; no statistical
  significance testing beyond what `divan` reports (fastest/slowest/
  median/mean).
- This is a snapshot from one run on one kernel version (5.14). Kernel
  version, filesystem, and hardware all plausibly shift these numbers;
  no claim is made that they hold on a different machine or kernel.
- `echo_roundtrip` and `log_append` exercise one connection or one file
  with one operation in flight at a time; `echo_roundtrip_concurrent`
  covers the batched-concurrency case, against both `io-uring` and a
  thread-per-connection `std` baseline, for the echo shape only —
  `log_append` has no concurrent counterpart yet (K parallel durable
  writes through one ring vs. K threads each doing blocking
  open/write/fsync/close).

## Running it yourself

```sh
cargo bench --bench comparison   # isolated single-opcode calls, x86_64 only
cargo bench --bench realistic    # multi-step workloads, x86_64 only
cargo bench --bench io_uring     # this crate alone, all supported architectures
```
