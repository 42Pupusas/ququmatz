//! Asking the kernel which operations it actually supports.
//!
//! The opcode numbers this crate names are compile-time constants, and a
//! kernel older than the one it was built against will reject some of
//! them. An unsupported opcode fails with `EINVAL` at completion time,
//! which is indistinguishable from a malformed request — so code that
//! wants to degrade gracefully has to ask in advance rather than try and
//! interpret the failure.
//!
//! [`Probe`] is that question. It is a snapshot, not a live view: the
//! kernel fills a fixed array once, and the answers do not change for the
//! lifetime of a running kernel.

use super::IoUring;
use crate::error::Error;
use crate::syscall;
use crate::types::{Opcode, RegisterOp};

/// The kernel's report for a single opcode.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct ProbeOp {
    op: u8,
    resv: u8,
    flags: u16,
    resv2: u32,
}

/// Fixed header the kernel writes ahead of the per-opcode entries.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct ProbeHeader {
    last_op: u8,
    ops_len: u8,
    resv: u16,
    resv2: [u32; 3],
}

/// How many opcode slots a probe asks the kernel to fill.
///
/// The kernel writes at most `last_op + 1` entries and reports how many
/// it wrote, so a fixed array larger than any current kernel's opcode
/// count needs no allocator and cannot truncate the answer.
const SLOTS: u32 = 256;

/// The same count as an array length.
const SLOT_COUNT: usize = SLOTS as usize;

/// What the kernel supports, as reported by `IORING_REGISTER_PROBE`.
///
/// Obtained from [`IoUring::probe`]. The answer is a property of the
/// running kernel, so one probe per process is enough.
///
/// ```no_run
/// # fn main() -> Result<(), ququmatz::Error> {
/// use ququmatz::types::Opcode;
///
/// let ring = ququmatz::IoUring::new(8)?;
/// let probe = ring.probe()?;
/// if probe.supports(Opcode::Bind) {
///     // use the ring for bind
/// }
/// # Ok(())
/// # }
/// ```
#[repr(C)]
pub struct Probe {
    header: ProbeHeader,
    ops: [ProbeOp; SLOT_COUNT],
}

impl Probe {
    /// `IO_URING_OP_SUPPORTED`: the kernel implements this opcode.
    const SUPPORTED: u16 = 1 << 0;

    /// Ask `ring`'s kernel what it supports.
    ///
    /// # Errors
    ///
    /// Returns an error if the kernel rejects the request, which is how a
    /// kernel too old to have `IORING_REGISTER_PROBE` itself (pre-5.6)
    /// reports that it cannot answer.
    pub(super) fn interrogate(ring: &IoUring) -> Result<Self, Error> {
        let mut probe = Self {
            header: ProbeHeader::default(),
            ops: [ProbeOp::default(); SLOT_COUNT],
        };
        syscall::io_uring_register(
            ring.fd,
            RegisterOp::RegisterProbe.into(),
            core::ptr::from_mut(&mut probe) as usize,
            SLOTS,
        )?;
        Ok(probe)
    }

    /// The highest opcode number this kernel knows about.
    ///
    /// Opcodes above this are newer than the running kernel. Note that an
    /// opcode at or below it is *known*, not necessarily *supported* —
    /// use [`supports`](Self::supports) for that.
    #[must_use]
    pub const fn last_op(&self) -> u8 {
        self.header.last_op
    }

    /// How many per-opcode entries the kernel filled in.
    #[must_use]
    pub const fn reported(&self) -> usize {
        self.header.ops_len as usize
    }

    /// Whether the kernel implements `op`.
    ///
    /// An opcode the kernel has never heard of and one it knows but does
    /// not implement both answer `false`, which is the distinction that
    /// matters to a caller deciding whether to submit.
    #[must_use]
    pub fn supports(&self, op: Opcode) -> bool {
        self.supports_raw(op.into())
    }

    /// Whether the kernel implements the opcode numbered `raw`.
    ///
    /// For opcodes newer than the [`Opcode`] enum, which cannot be named
    /// through it.
    #[must_use]
    pub fn supports_raw(&self, raw: u8) -> bool {
        self.ops[..self.reported()]
            .iter()
            .any(|entry| entry.op == raw && entry.flags & Self::SUPPORTED != 0)
    }
}

impl IoUring {
    /// Ask the kernel which operations it supports.
    ///
    /// Opcode numbers are compile-time constants in this crate, so a
    /// kernel older than the build target rejects some of them with
    /// `EINVAL` at completion — a failure indistinguishable from a
    /// malformed request. Probing first is how that ambiguity is avoided.
    ///
    /// # Errors
    ///
    /// Returns an error if the kernel rejects the request, which is also
    /// how a kernel predating `IORING_REGISTER_PROBE` (pre-5.6) answers.
    pub fn probe(&self) -> Result<Probe, Error> {
        Probe::interrogate(self)
    }
}

#[cfg(test)]
mod probe_tests {
    use super::*;
    use crate::IoUring;

    #[test]
    fn the_kernel_reports_the_opcodes_this_crate_was_built_against() {
        let ring = IoUring::new(4).expect("ring");
        let probe = ring.probe().expect("probe");

        // Every opcode in the enum predates this crate's minimum kernel,
        // so a running kernel that supports io_uring at all must have
        // them. A `false` here means the enum names an opcode number the
        // kernel does not implement, which is a bug in the table rather
        // than a fact about the kernel.
        for op in [
            Opcode::Nop,
            Opcode::Readv,
            Opcode::Writev,
            Opcode::Fsync,
            Opcode::Timeout,
            Opcode::Accept,
            Opcode::Connect,
            Opcode::Openat,
            Opcode::Close,
            Opcode::Statx,
            Opcode::Read,
            Opcode::Write,
            Opcode::Send,
            Opcode::Recv,
            Opcode::EpollCtl,
            Opcode::Renameat,
            Opcode::Unlinkat,
            Opcode::Mkdirat,
        ] {
            assert!(probe.supports(op), "kernel lacks {op:?}");
        }
    }

    #[test]
    fn an_opcode_past_the_kernels_range_is_not_reported_as_supported() {
        let ring = IoUring::new(4).expect("ring");
        let probe = ring.probe().expect("probe");

        // 255 is past IORING_OP_LAST on every kernel that exists, so a
        // `true` here would mean the scan is reading beyond what the
        // kernel filled rather than answering about the opcode.
        assert!(!probe.supports_raw(u8::MAX));
        assert!(probe.last_op() < u8::MAX);
    }

    #[test]
    fn the_scan_stops_at_what_the_kernel_filled_rather_than_the_array_end() {
        let mut probe = Probe {
            header: ProbeHeader::default(),
            ops: [ProbeOp::default(); SLOT_COUNT],
        };
        // One filled entry saying NOP is unsupported, and 255 zeroed
        // slots behind it. A scan running past `ops_len` reaches a slot
        // whose `op` field is a default `0` -- which *is* NOP's opcode.
        // Only the `flags` check would stand between that and a wrong
        // answer, so the bound is doing real work here rather than being
        // a tidy-looking optimisation.
        probe.header.last_op = 0;
        probe.header.ops_len = 1;
        probe.ops[0] = ProbeOp {
            op: Opcode::Nop.into(),
            resv: 0,
            flags: 0,
            resv2: 0,
        };
        assert!(!probe.supports(Opcode::Nop));

        // Now mark a slot the kernel never filled as supported. Reading
        // it at all is the bug; the value it holds is arbitrary.
        probe.ops[7] = ProbeOp {
            op: Opcode::Nop.into(),
            resv: 0,
            flags: Probe::SUPPORTED,
            resv2: 0,
        };
        assert!(
            !probe.supports(Opcode::Nop),
            "a slot past ops_len must not be consulted"
        );
    }

    #[test]
    fn the_report_covers_every_opcode_up_to_the_last_one() {
        let ring = IoUring::new(4).expect("ring");
        let probe = ring.probe().expect("probe");

        // The kernel fills one entry per opcode it knows, so a report
        // shorter than `last_op` would mean `supports` silently answers
        // `false` for opcodes that were never examined.
        assert!(
            probe.reported() > probe.last_op() as usize,
            "reported {} entries for last_op {}",
            probe.reported(),
            probe.last_op()
        );
    }

    #[test]
    fn bind_and_listen_are_supported_or_absent_together() {
        let ring = IoUring::new(4).expect("ring");
        let probe = ring.probe().expect("probe");

        // Both landed in 6.11. A kernel offering one without the other
        // would make the socket lifecycle half-usable, and the code that
        // picks a path based on one of them would be wrong about the
        // other.
        assert_eq!(
            probe.supports(Opcode::Bind),
            probe.supports(Opcode::Listen),
            "bind and listen arrived in the same kernel release"
        );
    }
}
