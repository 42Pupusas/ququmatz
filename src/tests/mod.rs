extern crate std;
use std::{vec, vec::Vec};

use super::*;
use crate::types::{
    AcceptFlags, EventFdFlags, FileMode, FsyncFlags, Futex2Flags, FutexWaitv, IdType, InotifyEvent,
    InotifyInitFlags, IoCqringOffsets, IoSqringOffsets, IoUringBuf, IoUringBufReg, IoUringCqe,
    IoUringParams, IoUringSqe, MsgFlags, MsgHdr, Opcode, OpenFlags, PbufRingFlags, PollMask,
    RecvmsgOut, SockAddrIn, SqeFlags, Statx, StatxFlags, StatxMask, StatxTimestamp, WaitOptions,
    WaitidSiginfo, WatchMask,
};
use core::mem;

/// A private, unpredictable path under the system temp directory for a
/// single test's exclusive use.
///
/// Mixes the process id, a monotonically increasing counter, and the
/// current time into the name so that concurrent test runs never collide
/// on the same path, and a pre-planted file or symlink at a *guessed*
/// path cannot be hit. Callers must still create the path with an
/// exclusive syscall flag (`O_EXCL` / `O_CREAT_NEW` / plain `mkdir`) —
/// this type only guarantees the *name* is unpredictable and unique, not
/// that the create step itself is safe against a pre-existing object.
/// Best-effort removes the path on drop, including across test panics.
#[cfg(not(miri))]
struct UniqueTestPath {
    path: std::string::String,
}

#[cfg(not(miri))]
impl UniqueTestPath {
    fn new(prefix: &str) -> Self {
        Self::new_in(
            std::env::temp_dir()
                .to_str()
                .expect("temp dir is valid UTF-8"),
            prefix,
        )
    }

    /// Like [`new`](Self::new), but rooted at `dir` instead of the system
    /// temp directory — needed for tests (like `O_DIRECT`) that require a
    /// real block-backed filesystem rather than whatever `temp_dir()`
    /// resolves to, which is tmpfs on most distros.
    fn new_in(dir: &str, prefix: &str) -> Self {
        static COUNTER: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
        let nonce = COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_nanos();
        let pid = std::process::id();
        Self {
            path: std::format!("{dir}/ququmatz_{prefix}_{pid}_{nonce}_{nanos}"),
        }
    }

    fn as_str(&self) -> &str {
        &self.path
    }

    fn as_cstring(&self) -> std::ffi::CString {
        std::ffi::CString::new(self.path.clone()).expect("generated path has no interior NUL")
    }
}

#[cfg(not(miri))]
impl Drop for UniqueTestPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

// ---------------------------------------------------------------
// Layout tests — verify our repr(C) structs match kernel sizes.
// These run under Miri.
// ---------------------------------------------------------------

#[test]
fn sqe_layout() {
    assert_eq!(mem::size_of::<IoUringSqe>(), 64);
    assert_eq!(mem::align_of::<IoUringSqe>(), 8);
}

#[test]
fn cqe_layout() {
    assert_eq!(mem::size_of::<IoUringCqe>(), 16);
    assert_eq!(mem::align_of::<IoUringCqe>(), 8);
}

#[test]
fn params_layout() {
    assert_eq!(mem::size_of::<IoUringParams>(), 120);
    assert_eq!(mem::align_of::<IoUringParams>(), 8);
}

#[test]
fn iovec_layout() {
    // struct iovec is a pointer plus a size_t, so it tracks the target's
    // pointer width rather than being 16 bytes everywhere.
    let ptr = mem::size_of::<*mut u8>();
    assert_eq!(mem::size_of::<IoVec>(), 2 * ptr);
    assert_eq!(mem::align_of::<IoVec>(), mem::align_of::<*mut u8>());
}

#[test]
fn msghdr_layout() {
    let expected_size = if mem::size_of::<usize>() == 8 { 56 } else { 28 };
    assert_eq!(mem::size_of::<MsgHdr>(), expected_size);
    assert_eq!(mem::align_of::<MsgHdr>(), mem::align_of::<*mut u8>());
}

#[test]
fn msghdr_field_offsets_follow_the_pointer_width() {
    let hdr = MsgHdr::default();
    let base = core::ptr::from_ref(&hdr) as usize;
    let ptr = mem::size_of::<*mut u8>();
    let offset_of = |addr: usize| addr - base;

    assert_eq!(offset_of(core::ptr::from_ref(&hdr.msg_name) as usize), 0);
    assert_eq!(
        offset_of(core::ptr::from_ref(&hdr.msg_namelen) as usize),
        ptr
    );
    assert_eq!(
        offset_of(core::ptr::from_ref(&hdr.msg_iov) as usize),
        2 * ptr,
        "msg_iov sits one pointer past the msg_namelen slot: on 64-bit that \
         means the ABI padding is present, on 32-bit that it is absent"
    );
    assert_eq!(
        offset_of(core::ptr::from_ref(&hdr.msg_iovlen) as usize),
        3 * ptr
    );
    assert_eq!(
        offset_of(core::ptr::from_ref(&hdr.msg_control) as usize),
        4 * ptr
    );
    assert_eq!(
        offset_of(core::ptr::from_ref(&hdr.msg_controllen) as usize),
        5 * ptr
    );
    assert_eq!(
        offset_of(core::ptr::from_ref(&hdr.msg_flags) as usize),
        6 * ptr
    );
}

#[test]
fn sockaddrin_layout() {
    assert_eq!(mem::size_of::<SockAddrIn>(), 16);
    assert_eq!(mem::align_of::<SockAddrIn>(), 4);
}

#[test]
fn recvmsg_out_layout() {
    // Mirrors the kernel `struct io_uring_recvmsg_out`: four packed u32s.
    assert_eq!(mem::size_of::<RecvmsgOut>(), 16);
    assert_eq!(mem::align_of::<RecvmsgOut>(), 4);
    assert_eq!(RecvmsgOut::SIZE, 16);
}

/// Builds a synthetic multishot-recvmsg buffer exactly as the kernel lays it
/// out: `[recvmsg_out header][name padded to name_reserved][control padded to
/// ctrl_reserved][payload]`. Header fields report the *would-have-been*
/// lengths, which may exceed the reserved widths.
///
/// The header is written native-endian because that is what the kernel does.
struct RecvmsgBufFixture<'a> {
    name_reserved: usize,
    ctrl_reserved: usize,
    hdr_namelen: u32,
    hdr_controllen: u32,
    name: &'a [u8],
    control: &'a [u8],
    payload: &'a [u8],
}

impl RecvmsgBufFixture<'_> {
    fn build(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.hdr_namelen.to_ne_bytes());
        buf.extend_from_slice(&self.hdr_controllen.to_ne_bytes());
        buf.extend_from_slice(&(self.payload.len() as u32).to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes());

        let mut name_region = vec![0u8; self.name_reserved];
        name_region[..self.name.len()].copy_from_slice(self.name);
        buf.extend_from_slice(&name_region);

        let mut ctrl_region = vec![0u8; self.ctrl_reserved];
        ctrl_region[..self.control.len()].copy_from_slice(self.control);
        buf.extend_from_slice(&ctrl_region);

        buf.extend_from_slice(self.payload);
        buf
    }
}

#[test]
fn recvmsg_out_parse_splits_name_control_payload() {
    const NAME_RES: usize = 16; // e.g. sizeof(sockaddr_in)
    const CTRL_RES: usize = 24;
    let name = [0x11u8; 16];
    let control = [0x22u8; 10];
    let payload = b"hello multishot recvmsg";

    let buf = RecvmsgBufFixture {
        name_reserved: NAME_RES,
        ctrl_reserved: CTRL_RES,
        hdr_namelen: name.len() as u32,
        hdr_controllen: control.len() as u32,
        name: &name,
        control: &control,
        payload,
    }
    .build();

    let parts = RecvmsgOut::parse(&buf, NAME_RES as u32, CTRL_RES as u32).expect("buffer is valid");

    assert_eq!(parts.header.namelen, name.len() as u32);
    assert_eq!(parts.header.controllen, control.len() as u32);
    assert_eq!(parts.header.payloadlen, payload.len() as u32);
    assert_eq!(parts.name, &name);
    assert_eq!(parts.control, &control[..]);
    assert_eq!(parts.payload, payload);
}

#[test]
fn recvmsg_out_parse_caps_truncated_name_at_reserved() {
    // Peer address larger than what we reserved: header reports the full
    // would-have-been namelen, but only `msg_namelen` bytes exist in the
    // buffer. We must cap the readable name at the reserved width.
    const NAME_RES: usize = 8; // smaller than the real address
    const CTRL_RES: usize = 0;
    let name_in_buf = [0xABu8; 8]; // only 8 bytes physically present
    let payload = b"payload";

    let buf = RecvmsgBufFixture {
        name_reserved: NAME_RES,
        ctrl_reserved: CTRL_RES,
        hdr_namelen: 128,
        hdr_controllen: 0,
        name: &name_in_buf,
        control: &[],
        payload,
    }
    .build();

    let parts = RecvmsgOut::parse(&buf, NAME_RES as u32, CTRL_RES as u32).expect("valid");
    // Header preserves the kernel-reported (truncated) length...
    assert_eq!(parts.header.namelen, 128);
    // ...but the readable slice is capped at the reserved width.
    assert_eq!(parts.name.len(), NAME_RES);
    assert_eq!(parts.name, &name_in_buf);
    assert!(parts.control.is_empty());
    assert_eq!(parts.payload, payload);
}

#[test]
fn recvmsg_out_parse_rejects_buffer_too_small() {
    // Buffer shorter than header + reserved name + reserved control => the
    // kernel truncated internally; parse must return None (like
    // io_uring_recvmsg_validate returning NULL).
    const NAME_RES: u32 = 16;
    const CTRL_RES: u32 = 16;
    // 16 (header) + 16 + 16 = 48 required; give it 40.
    let buf = vec![0u8; 40];
    assert!(RecvmsgOut::parse(&buf, NAME_RES, CTRL_RES).is_none());

    // Exactly the fixed size (no payload) is still valid: empty payload.
    let buf_exact = vec![0u8; 48];
    let parts = RecvmsgOut::parse(&buf_exact, NAME_RES, CTRL_RES).expect("exact fit is valid");
    assert!(parts.payload.is_empty());
}

#[test]
fn recvmsg_out_parse_zero_name_and_control() {
    // The common TCP case: no peer name, no control data. Payload starts
    // right after the 16-byte header.
    let payload = b"just bytes";
    let buf = RecvmsgBufFixture {
        name_reserved: 0,
        ctrl_reserved: 0,
        hdr_namelen: 0,
        hdr_controllen: 0,
        name: &[],
        control: &[],
        payload,
    }
    .build();
    let parts = RecvmsgOut::parse(&buf, 0, 0).expect("valid");
    assert!(parts.name.is_empty());
    assert!(parts.control.is_empty());
    assert_eq!(parts.payload, payload);
    assert_eq!(buf.len(), RecvmsgOut::SIZE + payload.len());
}

#[test]
fn timespec_layout() {
    assert_eq!(mem::size_of::<Timespec>(), 16);
    assert_eq!(mem::align_of::<Timespec>(), 8);
}

#[test]
fn io_sqring_offsets_layout() {
    assert_eq!(mem::size_of::<IoSqringOffsets>(), 40);
    assert_eq!(mem::align_of::<IoSqringOffsets>(), 8);
}

#[test]
fn io_cqring_offsets_layout() {
    assert_eq!(mem::size_of::<IoCqringOffsets>(), 40);
    assert_eq!(mem::align_of::<IoCqringOffsets>(), 8);
}

#[test]
fn io_uring_buf_layout() {
    assert_eq!(mem::size_of::<IoUringBuf>(), 16);
    assert_eq!(mem::align_of::<IoUringBuf>(), 8);
    assert_eq!(mem::offset_of!(IoUringBuf, addr), 0);
    assert_eq!(mem::offset_of!(IoUringBuf, len), 8);
    assert_eq!(mem::offset_of!(IoUringBuf, bid), 12);
    // resv aliases the ring's producer tail — it MUST be at offset 14.
    assert_eq!(mem::offset_of!(IoUringBuf, resv), 14);
}

#[test]
fn io_uring_buf_reg_layout() {
    assert_eq!(mem::size_of::<IoUringBufReg>(), 40);
    assert_eq!(mem::align_of::<IoUringBufReg>(), 8);
}

#[test]
fn pbuf_ring_flags_inc_matches_kernel_bit() {
    assert_eq!(PbufRingFlags::INC.bits(), 1 << 1);
}

#[test]
fn statx_timestamp_layout() {
    assert_eq!(mem::size_of::<StatxTimestamp>(), 16);
    assert_eq!(mem::align_of::<StatxTimestamp>(), 8);
}

// ---------------------------------------------------------------
// mem::zeroed validity — Miri will flag if zeroed is UB for these.
// ---------------------------------------------------------------

#[test]
fn zeroed_sqe_is_valid() {
    let sqe: IoUringSqe = unsafe { mem::zeroed() };
    assert_eq!(sqe.opcode, 0);
    assert_eq!(sqe.fd, 0);
    assert_eq!(sqe.user_data, 0);
    assert_eq!(sqe.len, 0);
}

#[test]
fn sqe_default_is_zeroed() {
    let sqe = IoUringSqe::default();
    let bytes: [u8; 64] = unsafe { mem::transmute(sqe) };
    assert!(bytes.iter().all(|&b| b == 0));
}

// ---------------------------------------------------------------
// SQE builder field placement — verify fields land at correct
// offsets within the struct. Miri validates pointer arithmetic.
// ---------------------------------------------------------------

#[test]
fn sqe_field_offsets() {
    assert_eq!(mem::offset_of!(IoUringSqe, opcode), 0);
    assert_eq!(mem::offset_of!(IoUringSqe, flags), 1);
    assert_eq!(mem::offset_of!(IoUringSqe, ioprio), 2);
    assert_eq!(mem::offset_of!(IoUringSqe, fd), 4);
    assert_eq!(mem::offset_of!(IoUringSqe, off), 8);
    assert_eq!(mem::offset_of!(IoUringSqe, addr), 16);
    assert_eq!(mem::offset_of!(IoUringSqe, len), 24);
    assert_eq!(mem::offset_of!(IoUringSqe, op_flags), 28);
    assert_eq!(mem::offset_of!(IoUringSqe, user_data), 32);
    assert_eq!(mem::offset_of!(IoUringSqe, buf_index), 40);
    assert_eq!(mem::offset_of!(IoUringSqe, personality), 42);
    assert_eq!(mem::offset_of!(IoUringSqe, splice_fd_in), 44);
    assert_eq!(mem::offset_of!(IoUringSqe, addr3), 48);
}

#[test]
fn sqe_builder_read_places_fields_correctly() {
    let mut buf = [0u8; 32];
    let sqe = unsafe { Sqe::read(RawFd::from_raw(42), &mut buf, 100) }.user_data(99);
    let inner = sqe.0;

    assert_eq!(Opcode::Read, inner.opcode);
    assert_eq!(inner.fd, 42);
    assert_eq!(inner.addr, buf.as_mut_ptr() as u64);
    assert_eq!(inner.len, 32);
    assert_eq!(inner.off, 100);
    assert_eq!(inner.user_data, 99);
}

#[test]
fn sqe_builder_write_places_fields_correctly() {
    let buf = [1u8; 16];
    let sqe = unsafe { Sqe::write(RawFd::from_raw(7), &buf, 0) }.user_data(55);
    let inner = sqe.0;

    assert_eq!(Opcode::Write, inner.opcode);
    assert_eq!(inner.fd, 7);
    assert_eq!(inner.addr, buf.as_ptr() as u64);
    assert_eq!(inner.len, 16);
    assert_eq!(inner.off, 0);
    assert_eq!(inner.user_data, 55);
}

#[test]
fn sqe_builder_readv_places_fields_correctly() {
    let mut buf = [0u8; 8];
    let vecs = [unsafe { IoVec::new(buf.as_mut_ptr(), buf.len()) }];
    let sqe = unsafe { Sqe::readv(RawFd::from_raw(3), &vecs, 50) }.user_data(10);
    let inner = sqe.0;

    assert_eq!(Opcode::Readv, inner.opcode);
    assert_eq!(inner.fd, 3);
    assert_eq!(inner.addr, vecs.as_ptr() as u64);
    assert_eq!(inner.len, 1);
    assert_eq!(inner.off, 50);
    assert_eq!(inner.user_data, 10);
}

#[test]
fn sqe_builder_readv_fixed_places_fields_correctly() {
    let mut buf = [0u8; 8];
    let vecs = [unsafe { IoVec::new(buf.as_mut_ptr(), buf.len()) }];
    let sqe =
        unsafe { Sqe::readv_fixed(RawFd::from_raw(3), vecs.as_ptr(), 1, 50, 7) }.user_data(10);
    let inner = sqe.0;

    assert_eq!(Opcode::ReadvFixed, inner.opcode);
    assert_eq!(inner.fd, 3);
    assert_eq!(inner.addr, vecs.as_ptr() as u64);
    assert_eq!(inner.len, 1);
    assert_eq!(inner.off, 50);
    assert_eq!(inner.buf_index, 7);
    assert_eq!(inner.user_data, 10);
}

#[test]
fn sqe_builder_writev_fixed_places_fields_correctly() {
    let buf = [1u8; 8];
    let vecs = [unsafe { IoVec::new(buf.as_ptr().cast_mut(), buf.len()) }];
    let sqe =
        unsafe { Sqe::writev_fixed(RawFd::from_raw(4), vecs.as_ptr(), 1, 20, 3) }.user_data(11);
    let inner = sqe.0;

    assert_eq!(Opcode::WritevFixed, inner.opcode);
    assert_eq!(inner.fd, 4);
    assert_eq!(inner.addr, vecs.as_ptr() as u64);
    assert_eq!(inner.len, 1);
    assert_eq!(inner.off, 20);
    assert_eq!(inner.buf_index, 3);
    assert_eq!(inner.user_data, 11);
}

#[test]
fn sqe_builder_openat_places_fields_correctly() {
    use crate::types::DirFd;
    let path = c"/tmp/test";
    let sqe = unsafe {
        Sqe::openat(
            DirFd::Cwd,
            path,
            OpenFlags::default(),
            FileMode::OWNER_READ
                | FileMode::OWNER_WRITE
                | FileMode::GROUP_READ
                | FileMode::OTHER_READ,
        )
    }
    .user_data(77);
    let inner = sqe.0;

    assert_eq!(Opcode::Openat, inner.opcode);
    assert_eq!(inner.fd, DirFd::Cwd.as_raw());
    assert_eq!(inner.addr, path.as_ptr() as u64);
    assert_eq!(inner.len, 0o644);
    assert_eq!(inner.op_flags, 0);
    assert_eq!(inner.user_data, 77);
}

#[test]
fn sqe_builder_close_places_fields_correctly() {
    let sqe = Sqe::close(RawFd::from_raw(5)).user_data(88);
    let inner = sqe.0;

    assert_eq!(Opcode::Close, inner.opcode);
    assert_eq!(inner.fd, 5);
    assert_eq!(inner.user_data, 88);
}

#[test]
fn sqe_builder_nop_places_fields_correctly() {
    let sqe = Sqe::nop().user_data(123).flags(SqeFlags::IO_LINK);
    let inner = sqe.0;

    assert_eq!(Opcode::Nop, inner.opcode);
    assert_eq!(inner.user_data, 123);
    assert_eq!(SqeFlags::IO_LINK, inner.flags);
}

// ---------------------------------------------------------------
// Simulated ring index math — exercises the same wrapping/masking
// logic as the real ring, but on heap memory so Miri can check it.
// ---------------------------------------------------------------

#[test]
fn ring_index_wrapping() {
    let mask: u32 = 3;
    let mut sqes = [IoUringSqe::default(); 4];
    let mut sq_array = [0u32; 4];

    for i in 0u32..4 {
        let idx = i & mask;
        sqes[idx as usize] = IoUringSqe {
            opcode: Opcode::Nop.into(),
            user_data: u64::from(i),
            ..IoUringSqe::default()
        };
        sq_array[idx as usize] = idx;
    }

    for i in 0u32..4 {
        let idx = i & mask;
        assert_eq!(sqes[idx as usize].user_data, u64::from(i));
        assert_eq!(sq_array[idx as usize], idx);
    }

    let wrap_idx = 4u32 & mask;
    assert_eq!(wrap_idx, 0);
    sqes[wrap_idx as usize].user_data = 999;
    assert_eq!(sqes[0].user_data, 999);
}

#[test]
fn cq_index_wrapping() {
    let mask: u32 = 3;
    let cqes = [
        IoUringCqe {
            user_data: 10,
            res: 0,
            flags: 0,
        },
        IoUringCqe {
            user_data: 11,
            res: 0,
            flags: 0,
        },
        IoUringCqe {
            user_data: 12,
            res: 0,
            flags: 0,
        },
        IoUringCqe {
            user_data: 13,
            res: 0,
            flags: 0,
        },
    ];

    for i in 0u32..4 {
        let idx = i & mask;
        assert_eq!(cqes[idx as usize].user_data, u64::from(10 + i));
    }

    assert_eq!(cqes[(4u32 & mask) as usize].user_data, 10);
}

// ---------------------------------------------------------------
// Kernel integration tests — skipped under Miri (they need syscalls).
// ---------------------------------------------------------------

#[test]
fn sqe_link_chain_flags() {
    let sqe = Sqe::nop().user_data(1).link();
    assert_eq!(SqeFlags::IO_LINK, sqe.0.flags);

    let sqe = Sqe::nop().user_data(2).hardlink();
    assert_eq!(SqeFlags::IO_HARDLINK, sqe.0.flags);

    let sqe = Sqe::nop().user_data(3).drain();
    assert_eq!(SqeFlags::IO_DRAIN, sqe.0.flags);

    // Combining flags
    let sqe = Sqe::nop().user_data(4).link().drain();
    assert_eq!((SqeFlags::IO_LINK | SqeFlags::IO_DRAIN).bits(), sqe.0.flags);
}

#[test]
fn sqe_builder_timeout_places_fields_correctly() {
    let ts = Timespec::new(1, 500_000_000);
    let sqe = unsafe { Sqe::timeout(&ts, 3, TimeoutFlags::default()) }.user_data(42);
    let inner = sqe.0;

    assert_eq!(Opcode::Timeout, inner.opcode);
    assert_eq!(inner.addr, (&raw const ts) as u64);
    assert_eq!(inner.off, 3); // count
    assert_eq!(inner.op_flags, 0);
    assert_eq!(inner.user_data, 42);
}

#[test]
fn sqe_builder_cancel_places_fields_correctly() {
    let sqe = Sqe::cancel(99).user_data(100);
    let inner = sqe.0;

    assert_eq!(Opcode::AsyncCancel, inner.opcode);
    assert_eq!(inner.addr, 99); // target user_data
    assert_eq!(inner.user_data, 100);
    assert_eq!(inner.op_flags, 0);
}

#[test]
fn sqe_builder_cancel_with_flags_sets_the_all_bit() {
    let sqe = Sqe::cancel_with_flags(99, crate::types::CancelFlags::ALL).user_data(100);
    let inner = sqe.0;

    assert_eq!(Opcode::AsyncCancel, inner.opcode);
    assert_eq!(inner.addr, 99);
    assert_eq!(inner.op_flags, crate::types::CancelFlags::ALL.bits());
}

#[test]
fn sqe_builder_cancel_fd_matches_by_descriptor() {
    use crate::types::{CancelFlags, RawFd};

    let sqe = Sqe::cancel_fd(RawFd::from_raw(7), CancelFlags::ALL).user_data(1);
    let inner = sqe.0;

    assert_eq!(Opcode::AsyncCancel, inner.opcode);
    assert_eq!(inner.fd, 7);
    assert_eq!(inner.op_flags, (CancelFlags::FD | CancelFlags::ALL).bits());
}

#[test]
fn sqe_builder_cancel_any_ignores_user_data() {
    use crate::types::CancelFlags;

    let sqe = Sqe::cancel_any(CancelFlags::ALL).user_data(1);
    let inner = sqe.0;

    assert_eq!(Opcode::AsyncCancel, inner.opcode);
    assert_eq!(inner.addr, 0);
    assert_eq!(inner.op_flags, (CancelFlags::ANY | CancelFlags::ALL).bits());
}

#[test]
fn sqe_builder_cancel_matching_opcode_stores_opcode_in_len() {
    use crate::types::CancelFlags;

    let sqe = Sqe::cancel_any(CancelFlags::empty()).cancel_matching_opcode(Opcode::Read);
    let inner = sqe.0;

    assert_eq!(inner.op_flags, (CancelFlags::ANY | CancelFlags::OP).bits());
    assert_eq!(inner.len, Opcode::Read as u32);
}

#[test]
fn sqe_builder_msg_ring_places_fields_correctly() {
    use crate::types::RawFd;

    let sqe = Sqe::msg_ring(RawFd::from_raw(9), 5, 42).user_data(100);
    let inner = sqe.0;

    assert_eq!(Opcode::MsgRing, inner.opcode);
    assert_eq!(inner.fd, 9);
    assert_eq!(inner.len, 5);
    assert_eq!(inner.off, 42);
    assert_eq!(inner.op_flags, 0);
}

#[test]
fn sqe_builder_msg_ring_cqe_flags_sets_flags_pass_and_carries_the_flags() {
    use crate::types::{MsgRingFlags, RawFd};

    let sqe = Sqe::msg_ring_cqe_flags(RawFd::from_raw(9), 5, 42, 0x7);
    let inner = sqe.0;

    assert_eq!(Opcode::MsgRing, inner.opcode);
    assert_eq!(inner.op_flags, MsgRingFlags::FLAGS_PASS.bits());
    assert_eq!(inner.splice_fd_in, 7);
}

#[test]
fn sqe_builder_msg_ring_fd_sets_the_send_fd_sentinel() {
    use crate::types::RawFd;

    let sqe = Sqe::msg_ring_fd(RawFd::from_raw(9), RawFd::from_raw(3), -1, 7);
    let inner = sqe.0;

    assert_eq!(Opcode::MsgRing, inner.opcode);
    assert_eq!(inner.addr, 1); // IORING_MSG_SEND_FD
    assert_eq!(inner.addr3, 3);
    assert_eq!(inner.off, 7);
    assert_eq!(inner.splice_fd_in, -1);
}

#[test]
fn cancel_outcome_classifies_raw_results() {
    use crate::types::CancelOutcome;

    assert_eq!(CancelOutcome::from_raw(0), CancelOutcome::Applied(0));
    assert_eq!(CancelOutcome::from_raw(3), CancelOutcome::Applied(3));
    assert_eq!(CancelOutcome::from_raw(-2), CancelOutcome::NotFound);
    assert_eq!(
        CancelOutcome::from_raw(-114),
        CancelOutcome::AlreadyCompleting
    );
    assert!(matches!(
        CancelOutcome::from_raw(-22),
        CancelOutcome::Failed(_)
    ));
    assert!(CancelOutcome::from_raw(1).is_applied());
    assert!(!CancelOutcome::from_raw(-2).is_applied());
}

#[test]
fn cancel_outcome_display_names_every_variant() {
    extern crate std;
    use std::{format, string::ToString};

    assert_eq!(CancelOutcome::Applied(0).to_string(), "cancelled");
    assert_eq!(
        CancelOutcome::Applied(3).to_string(),
        "cancelled 3 request(s)"
    );
    assert_eq!(
        CancelOutcome::NotFound.to_string(),
        "no matching request found"
    );
    assert_eq!(
        CancelOutcome::AlreadyCompleting.to_string(),
        "matching request was already completing"
    );
    assert_eq!(
        CancelOutcome::from_raw(-22).to_string(),
        format!("cancel failed: {}", crate::error::Errno::new(22))
    );
}

#[test]
fn sync_cancel_reg_layout_matches_the_kernel_struct() {
    use crate::types::RawSyncCancelReg;

    assert_eq!(mem::size_of::<RawSyncCancelReg>(), 64);
    assert_eq!(mem::align_of::<RawSyncCancelReg>(), 8);
}

#[cfg(not(miri))]
#[test]
fn a_real_sync_cancel_stops_a_pending_timeout_without_a_submit_round_trip() {
    use crate::types::{CancelFlags, SyncCancelReg};

    let mut ring = IoUring::new(8).expect("setup");

    // A timeout far longer than the test should take, so the sync cancel
    // is what ends it rather than expiry.
    let ts = Timespec::from_millis(60_000);
    let target_user_data = 99;
    ring.push(unsafe { Sqe::timeout(&ts, 0, TimeoutFlags::default()) }.user_data(target_user_data))
        .expect("push timeout");
    ring.submit().expect("submit timeout");

    let outcome = ring
        .sync_cancel(SyncCancelReg::user_data(
            target_user_data,
            CancelFlags::empty(),
        ))
        .expect("sync_cancel register call");
    assert!(
        outcome.is_applied(),
        "expected the timeout to be cancelled, got {outcome:?}"
    );

    // The cancelled timeout still posts its own CQE, reporting -ECANCELED.
    ring.submit_and_wait(1)
        .expect("wait for cancelled timeout's cqe");
    let cqe = ring.complete().expect("completion");
    assert_eq!(cqe.user_data, target_user_data);
    assert_eq!(cqe.result, -125); // -ECANCELED
}

#[cfg(not(miri))]
#[test]
fn a_real_sync_cancel_with_no_match_reports_not_found() {
    use crate::types::{CancelFlags, CancelOutcome, SyncCancelReg};

    let mut ring = IoUring::new(4).expect("setup");
    let outcome = ring
        .sync_cancel(SyncCancelReg::user_data(0xDEAD_BEEF, CancelFlags::empty()))
        .expect("sync_cancel register call");
    assert_eq!(outcome, CancelOutcome::NotFound);
}

#[test]
fn io_uring_file_index_range_layout_matches_the_kernel_struct() {
    use crate::types::IoUringFileIndexRange;

    assert_eq!(mem::size_of::<IoUringFileIndexRange>(), 16);
    assert_eq!(mem::align_of::<IoUringFileIndexRange>(), 8);
}

#[cfg(not(miri))]
#[test]
fn a_real_file_alloc_range_confines_auto_allocation_to_the_reserved_slice() {
    use crate::types::{AddressFamily, SocketFlags, SocketType};

    let mut ring = IoUring::new(8).expect("setup");
    // A sparse table with 8 slots, all empty.
    ring.register_files(&[-1; 8]).expect("register_files");
    // Confine auto-allocation to slots [4, 8): the low half stays free
    // for explicit assignment, the high half is where the kernel may pick.
    ring.register_file_alloc_range(4, 4)
        .expect("register_file_alloc_range");

    ring.push(Sqe::socket_direct(
        AddressFamily::Inet,
        SocketType::Stream,
        0,
        SocketFlags::empty(),
    ))
    .expect("push socket_direct");
    ring.submit_and_wait(1).expect("submit");
    let cqe = ring.complete().expect("completion");
    assert!(cqe.result >= 0, "socket_direct failed: {}", cqe.result);
    let slot = cqe.result as u32;
    assert!(
        (4..8).contains(&slot),
        "auto-allocated slot {slot} escaped the reserved range [4, 8)"
    );

    ring.unregister_files().expect("unregister_files");
}

#[test]
fn timespec_from_millis() {
    let ts = Timespec::from_millis(1500);
    assert_eq!(ts.tv_sec(), 1);
    assert_eq!(ts.tv_nsec(), 500_000_000);

    let ts = Timespec::from_millis(50);
    assert_eq!(ts.tv_sec(), 0);
    assert_eq!(ts.tv_nsec(), 50_000_000);
}

#[test]
fn sqe_builder_fsync_places_fields_correctly() {
    let sqe = Sqe::fsync(RawFd::from_raw(5), FsyncFlags::DATASYNC).user_data(10);
    let inner = sqe.0;

    assert_eq!(Opcode::Fsync, inner.opcode);
    assert_eq!(inner.fd, 5);
    assert_eq!(inner.op_flags, FsyncFlags::DATASYNC.bits());
    assert_eq!(inner.user_data, 10);
}

#[test]
fn sqe_builder_poll_add_places_fields_correctly() {
    let sqe = Sqe::poll_add(RawFd::from_raw(3), PollMask::IN | PollMask::RDHUP).user_data(20);
    let inner = sqe.0;

    assert_eq!(Opcode::PollAdd, inner.opcode);
    assert_eq!(inner.fd, 3);
    assert_eq!(inner.op_flags, (PollMask::IN | PollMask::RDHUP).bits());
    assert_eq!(inner.user_data, 20);
}

#[test]
fn statx_layout() {
    assert_eq!(core::mem::size_of::<Statx>(), 256);
    assert_eq!(mem::align_of::<Statx>(), 8);

    assert_eq!(mem::offset_of!(Statx, stx_mask), 0);
    assert_eq!(mem::offset_of!(Statx, stx_blksize), 4);
    assert_eq!(mem::offset_of!(Statx, stx_attributes), 8);
    assert_eq!(mem::offset_of!(Statx, stx_nlink), 16);
    assert_eq!(mem::offset_of!(Statx, stx_uid), 20);
    assert_eq!(mem::offset_of!(Statx, stx_gid), 24);
    assert_eq!(mem::offset_of!(Statx, stx_mode), 28);
    assert_eq!(mem::offset_of!(Statx, stx_ino), 32);
    assert_eq!(mem::offset_of!(Statx, stx_size), 40);
    assert_eq!(mem::offset_of!(Statx, stx_blocks), 48);
    assert_eq!(mem::offset_of!(Statx, stx_attributes_mask), 56);
    assert_eq!(mem::offset_of!(Statx, stx_atime), 64);
    assert_eq!(mem::offset_of!(Statx, stx_btime), 80);
    assert_eq!(mem::offset_of!(Statx, stx_ctime), 96);
    assert_eq!(mem::offset_of!(Statx, stx_mtime), 112);
    assert_eq!(mem::offset_of!(Statx, stx_rdev_major), 128);
    assert_eq!(mem::offset_of!(Statx, stx_rdev_minor), 132);
    assert_eq!(mem::offset_of!(Statx, stx_dev_major), 136);
    assert_eq!(mem::offset_of!(Statx, stx_dev_minor), 140);
    assert_eq!(mem::offset_of!(Statx, stx_mnt_id), 144);
    assert_eq!(mem::offset_of!(Statx, stx_dio_mem_align), 152);
    assert_eq!(mem::offset_of!(Statx, stx_dio_offset_align), 156);
}

#[test]
fn waitid_siginfo_layout() {
    assert_eq!(core::mem::size_of::<WaitidSiginfo>(), 128);

    assert_eq!(mem::offset_of!(WaitidSiginfo, si_signo), 0);
    assert_eq!(mem::offset_of!(WaitidSiginfo, si_errno), 4);
    assert_eq!(mem::offset_of!(WaitidSiginfo, si_code), 8);
    assert_eq!(mem::offset_of!(WaitidSiginfo, si_pid), 16);
    assert_eq!(mem::offset_of!(WaitidSiginfo, si_uid), 20);
    assert_eq!(mem::offset_of!(WaitidSiginfo, si_status), 24);
}

#[test]
fn sqe_builder_waitid_places_fields_correctly() {
    let mut info = WaitidSiginfo::default();
    let sqe = unsafe {
        Sqe::waitid(
            IdType::Pid,
            1234,
            core::ptr::from_mut(&mut info),
            WaitOptions::EXITED,
        )
    }
    .user_data(30);
    let inner = sqe.0;

    assert_eq!(Opcode::WaitId, inner.opcode);
    assert_eq!(inner.fd, 1234);
    assert_eq!(inner.len, IdType::Pid.as_raw());
    assert_eq!(inner.splice_fd_in, WaitOptions::EXITED.bits() as i32);
    assert_eq!(inner.off, core::ptr::from_mut(&mut info) as u64);
    assert_eq!(inner.user_data, 30);
}

#[test]
fn sqe_builder_futex_wait_places_fields_correctly() {
    let word: u32 = 0;
    let sqe = unsafe {
        Sqe::futex_wait(
            core::ptr::from_ref(&word),
            7,
            u64::from(u32::MAX),
            Futex2Flags::default_size(),
        )
    }
    .user_data(40);
    let inner = sqe.0;

    assert_eq!(Opcode::FutexWait, inner.opcode);
    assert_eq!(inner.addr, core::ptr::from_ref(&word) as u64);
    assert_eq!(inner.off, 7);
    assert_eq!(inner.addr3, u64::from(u32::MAX));
    assert_eq!(inner.fd, Futex2Flags::default_size().bits() as i32);
    assert_eq!(inner.user_data, 40);
}

#[test]
fn sqe_builder_futex_wake_places_fields_correctly() {
    let word: u32 = 0;
    let sqe = unsafe {
        Sqe::futex_wake(
            core::ptr::from_ref(&word),
            3,
            u64::from(u32::MAX),
            Futex2Flags::default_size(),
        )
    }
    .user_data(41);
    let inner = sqe.0;

    assert_eq!(Opcode::FutexWake, inner.opcode);
    assert_eq!(inner.addr, core::ptr::from_ref(&word) as u64);
    assert_eq!(inner.off, 3);
    assert_eq!(inner.addr3, u64::from(u32::MAX));
    assert_eq!(inner.fd, Futex2Flags::default_size().bits() as i32);
    assert_eq!(inner.user_data, 41);
}

#[test]
fn sqe_builder_futex_waitv_places_fields_correctly() {
    let word: u32 = 0;
    let waiters =
        [unsafe { FutexWaitv::new(core::ptr::from_ref(&word), 0, Futex2Flags::default_size()) }];
    let sqe = unsafe { Sqe::futex_waitv(&waiters) }.user_data(42);
    let inner = sqe.0;

    assert_eq!(Opcode::FutexWaitv, inner.opcode);
    assert_eq!(inner.addr, waiters.as_ptr() as u64);
    assert_eq!(inner.len, 1);
    assert_eq!(inner.user_data, 42);
}

#[cfg(not(miri))]
#[test]
fn fsync_on_tmpfile() {
    let mut ring = IoUring::new(4).expect("setup");
    let fd = open_tmpfile(&mut ring);

    // Write some data first
    let buf = b"fsync test";
    ring.push(unsafe { Sqe::write(RawFd::from_raw(fd as usize), buf, 0) }.user_data(1))
        .expect("push write");
    ring.submit_and_wait(1).expect("submit");
    ring.complete().expect("write cqe");

    // Fsync
    ring.push(Sqe::fsync(RawFd::from_raw(fd as usize), FsyncFlags::default()).user_data(2))
        .expect("push fsync");
    ring.submit_and_wait(1).expect("submit");

    let cqe = ring.complete().expect("fsync cqe");
    assert_eq!(cqe.user_data, 2);
    assert_eq!(cqe.result, 0);

    let _ = syscall::close(RawFd::from_raw(fd as usize));
}

#[cfg(not(miri))]
#[test]
fn a_real_sync_file_range_writes_out_the_bytes_it_names() {
    use crate::types::SyncFileRangeFlags;

    let mut ring = IoUring::new(4).expect("setup");
    let fd = open_tmpfile(&mut ring);

    let buf = b"sync_file_range test";
    ring.push(unsafe { Sqe::write(RawFd::from_raw(fd as usize), buf, 0) }.user_data(1))
        .expect("push write");
    ring.submit_and_wait(1).expect("submit");
    ring.complete().expect("write cqe");

    ring.push(
        Sqe::sync_file_range(
            RawFd::from_raw(fd as usize),
            0,
            buf.len() as u32,
            SyncFileRangeFlags::WAIT_BEFORE
                | SyncFileRangeFlags::WRITE
                | SyncFileRangeFlags::WAIT_AFTER,
        )
        .user_data(2),
    )
    .expect("push sync_file_range");
    ring.submit_and_wait(1).expect("submit");

    let cqe = ring.complete().expect("sync_file_range cqe");
    assert_eq!(cqe.user_data, 2);
    assert_eq!(cqe.result, 0);

    let _ = syscall::close(RawFd::from_raw(fd as usize));
}

#[test]
fn sqe_builder_sync_file_range_places_fields_correctly() {
    use crate::types::{Opcode, SyncFileRangeFlags};

    let sqe = Sqe::sync_file_range(RawFd::from_raw(11), 100, 200, SyncFileRangeFlags::WRITE);
    let inner = sqe.0;
    assert_eq!(Opcode::SyncFileRange, inner.opcode);
    assert_eq!(inner.fd, 11);
    assert_eq!(inner.off, 100);
    assert_eq!(inner.len, 200);
    assert_eq!(inner.op_flags, SyncFileRangeFlags::WRITE.bits());
}

#[test]
fn sqe_builder_fixed_fd_install_sets_fixed_file_and_places_fields_correctly() {
    use crate::types::{InstallFdFlags, Opcode, SqeFlags};

    let sqe = Sqe::fixed_fd_install(RawFd::from_raw(3), InstallFdFlags::NO_CLOEXEC);
    let inner = sqe.0;
    assert_eq!(Opcode::FixedFdInstall, inner.opcode);
    assert_eq!(inner.fd, 3);
    assert_eq!(
        inner.flags & SqeFlags::FIXED_FILE.bits(),
        SqeFlags::FIXED_FILE.bits(),
        "the slot is always read as a table index, never a raw fd"
    );
    assert_eq!(inner.op_flags, InstallFdFlags::NO_CLOEXEC.bits());
}

#[test]
fn sqe_builder_ftruncate_places_fields_correctly() {
    let sqe = Sqe::ftruncate(RawFd::from_raw(9), 4096);
    let inner = sqe.0;
    assert_eq!(Opcode::Ftruncate, inner.opcode);
    assert_eq!(inner.fd, 9);
    assert_eq!(inner.off, 4096);
    assert_eq!(inner.addr, 0);
    assert_eq!(inner.len, 0);
}

#[cfg(not(miri))]
#[test]
fn a_real_ftruncate_grows_and_shrinks_a_files_reported_size() {
    let mut ring = IoUring::new(4).expect("setup");
    let fd = open_tmpfile(&mut ring);
    let fd = RawFd::from_raw(fd as usize);

    ring.push(unsafe { Sqe::write(fd, b"hello", 0) }.user_data(1))
        .expect("push write");
    ring.submit_and_wait(1).expect("submit write");
    ring.complete().expect("write cqe");

    ring.push(Sqe::ftruncate(fd, 10).user_data(2))
        .expect("push grow");
    ring.submit_and_wait(1).expect("submit grow");
    let cqe = ring.complete().expect("grow cqe");
    assert_eq!(cqe.result, 0, "ftruncate grow failed");

    let mut stat = Statx::default();
    ring.push(
        unsafe {
            Sqe::statx(
                crate::types::DirFd::Fd(fd),
                c"",
                StatxFlags::EMPTY_PATH,
                StatxMask::SIZE,
                &mut stat,
            )
        }
        .user_data(3),
    )
    .expect("push statx");
    ring.submit_and_wait(1).expect("submit statx");
    ring.complete().expect("statx cqe");
    assert_eq!(stat.size(), Some(10), "grow must extend the reported size");

    ring.push(Sqe::ftruncate(fd, 2).user_data(4))
        .expect("push shrink");
    ring.submit_and_wait(1).expect("submit shrink");
    let cqe = ring.complete().expect("shrink cqe");
    assert_eq!(cqe.result, 0, "ftruncate shrink failed");

    let mut stat2 = Statx::default();
    ring.push(
        unsafe {
            Sqe::statx(
                crate::types::DirFd::Fd(fd),
                c"",
                StatxFlags::EMPTY_PATH,
                StatxMask::SIZE,
                &mut stat2,
            )
        }
        .user_data(5),
    )
    .expect("push statx");
    ring.submit_and_wait(1).expect("submit statx");
    ring.complete().expect("statx cqe");
    assert_eq!(stat2.size(), Some(2), "shrink must discard the tail");

    let _ = syscall::close(fd);
}

#[test]
fn sqe_builder_pipe_places_fields_correctly() {
    use crate::types::PipeFlags;

    let mut fds = [0i32; 2];
    let sqe = unsafe { Sqe::pipe(&mut fds, PipeFlags::NONBLOCK) };
    let inner = sqe.0;
    assert_eq!(Opcode::Pipe, inner.opcode);
    assert_eq!(inner.fd, 0);
    assert_eq!(inner.off, 0);
    assert_eq!(inner.addr, fds.as_ptr() as u64);
    assert_eq!(inner.op_flags, PipeFlags::NONBLOCK.bits());
}

#[cfg(not(miri))]
#[test]
fn a_real_pipe_creates_a_working_pair() {
    use crate::types::PipeFlags;

    let mut ring = IoUring::new(4).expect("setup");
    let mut fds = [0i32; 2];
    ring.push(unsafe { Sqe::pipe(&mut fds, PipeFlags::default()) }.user_data(1))
        .expect("push pipe");
    ring.submit_and_wait(1).expect("submit pipe");
    let cqe = ring.complete().expect("pipe cqe");
    assert_eq!(cqe.result, 0, "pipe creation failed");
    assert_ne!(fds[0], 0, "read end must be a real descriptor");
    assert_ne!(fds[1], 0, "write end must be a real descriptor");
    assert_ne!(fds[0], fds[1], "the two ends are distinct descriptors");

    let read_fd = RawFd::from_raw(fds[0] as usize);
    let write_fd = RawFd::from_raw(fds[1] as usize);

    ring.push(unsafe { Sqe::write(write_fd, b"hi", 0) }.user_data(2))
        .expect("push write");
    ring.submit_and_wait(1).expect("submit write");
    let cqe = ring.complete().expect("write cqe");
    assert_eq!(cqe.result, 2, "wrote 2 bytes into the pipe");

    let mut buf = [0u8; 2];
    ring.push(unsafe { Sqe::read(read_fd, &mut buf, 0) }.user_data(3))
        .expect("push read");
    ring.submit_and_wait(1).expect("submit read");
    let cqe = ring.complete().expect("read cqe");
    assert_eq!(cqe.result, 2, "read back 2 bytes from the pipe");
    assert_eq!(&buf, b"hi");

    let _ = syscall::close(read_fd);
    let _ = syscall::close(write_fd);
}

#[test]
fn sqe_builder_symlinkat_places_fields_correctly() {
    let sqe = unsafe { Sqe::symlinkat(c"target", crate::types::DirFd::Cwd, c"link") };
    let inner = sqe.0;
    assert_eq!(Opcode::Symlinkat, inner.opcode);
    assert_eq!(inner.fd, crate::types::AT_FDCWD);
    assert_eq!(inner.addr, c"target".as_ptr() as u64);
    assert_eq!(inner.off, c"link".as_ptr() as u64);
}

#[test]
fn sqe_builder_linkat_places_the_new_directory_in_len() {
    use crate::types::LinkFlags;

    let sqe = unsafe {
        Sqe::linkat(
            crate::types::DirFd::Cwd,
            c"old",
            crate::types::DirFd::Fd(RawFd::from_raw(7)),
            c"new",
            LinkFlags::SYMLINK_FOLLOW,
        )
    };
    let inner = sqe.0;
    assert_eq!(Opcode::Linkat, inner.opcode);
    assert_eq!(inner.fd, crate::types::AT_FDCWD);
    assert_eq!(inner.len, 7);
    assert_eq!(inner.addr, c"old".as_ptr() as u64);
    assert_eq!(inner.off, c"new".as_ptr() as u64);
    assert_eq!(inner.op_flags, LinkFlags::SYMLINK_FOLLOW.bits());
}

#[cfg(not(miri))]
#[test]
fn a_real_symlinkat_creates_a_link_pointing_at_the_literal_text() {
    let mut ring = IoUring::new(4).expect("setup");
    let path = std::format!("/tmp/ququmatz_symlinkat_{}", std::process::id());
    let cpath = std::ffi::CString::new(path.clone()).expect("cstring");
    let _ = std::fs::remove_file(&path);

    ring.push(
        unsafe { Sqe::symlinkat(c"/does/not/exist", crate::types::DirFd::Cwd, &cpath) }
            .user_data(1),
    )
    .expect("push symlinkat");
    ring.submit_and_wait(1).expect("submit");
    let cqe = ring.complete().expect("symlinkat cqe");
    assert_eq!(cqe.result, 0, "symlinkat failed: {}", cqe.result);

    let target = std::fs::read_link(&path).expect("read_link");
    assert_eq!(target.to_str().unwrap(), "/does/not/exist");
    let _ = std::fs::remove_file(&path);
}

#[cfg(not(miri))]
#[test]
fn a_real_linkat_shares_the_source_inode() {
    let mut ring = IoUring::new(4).expect("setup");
    let source = std::format!("/tmp/ququmatz_linkat_src_{}", std::process::id());
    let dest = std::format!("/tmp/ququmatz_linkat_dst_{}", std::process::id());
    std::fs::write(&source, b"shared").expect("seed");
    let _ = std::fs::remove_file(&dest);
    let csource = std::ffi::CString::new(source.clone()).expect("cstring");
    let cdest = std::ffi::CString::new(dest.clone()).expect("cstring");

    ring.push(
        unsafe {
            Sqe::linkat(
                crate::types::DirFd::Cwd,
                &csource,
                crate::types::DirFd::Cwd,
                &cdest,
                crate::types::LinkFlags::default(),
            )
        }
        .user_data(1),
    )
    .expect("push linkat");
    ring.submit_and_wait(1).expect("submit");
    let cqe = ring.complete().expect("linkat cqe");
    assert_eq!(cqe.result, 0, "linkat failed: {}", cqe.result);

    use std::os::unix::fs::MetadataExt;
    let a = std::fs::metadata(&source).expect("metadata");
    let b = std::fs::metadata(&dest).expect("metadata");
    assert_eq!(a.ino(), b.ino());

    let _ = std::fs::remove_file(&source);
    let _ = std::fs::remove_file(&dest);
}

#[test]
fn sqe_builder_setxattr_places_the_path_in_addr3() {
    use crate::types::XattrFlags;

    let value = b"payload";
    let sqe = unsafe { Sqe::setxattr(c"user.test", c"/tmp/x", value, XattrFlags::CREATE) };
    let inner = sqe.0;
    assert_eq!(Opcode::Setxattr, inner.opcode);
    assert_eq!(inner.addr, c"user.test".as_ptr() as u64);
    assert_eq!(inner.off, value.as_ptr() as u64);
    assert_eq!(inner.len, value.len() as u32);
    assert_eq!(inner.op_flags, XattrFlags::CREATE.bits());
    assert_eq!(inner.addr3, c"/tmp/x".as_ptr() as u64);
}

#[test]
fn sqe_builder_getxattr_places_the_path_in_addr3() {
    let mut dest = [0u8; 16];
    let sqe = unsafe { Sqe::getxattr(c"user.test", c"/tmp/x", &mut dest) };
    let inner = sqe.0;
    assert_eq!(Opcode::Getxattr, inner.opcode);
    assert_eq!(inner.addr, c"user.test".as_ptr() as u64);
    assert_eq!(inner.off, dest.as_ptr() as u64);
    assert_eq!(inner.len, dest.len() as u32);
    assert_eq!(inner.addr3, c"/tmp/x".as_ptr() as u64);
}

#[test]
fn sqe_builder_fsetxattr_and_fgetxattr_place_fields_correctly() {
    use crate::types::XattrFlags;

    let value = b"v";
    let set = unsafe { Sqe::fsetxattr(RawFd::from_raw(3), c"user.a", value, XattrFlags::REPLACE) };
    let inner = set.0;
    assert_eq!(Opcode::Fsetxattr, inner.opcode);
    assert_eq!(inner.fd, 3);
    assert_eq!(inner.addr, c"user.a".as_ptr() as u64);
    assert_eq!(inner.off, value.as_ptr() as u64);
    assert_eq!(inner.op_flags, XattrFlags::REPLACE.bits());

    let mut dest = [0u8; 8];
    let get = unsafe { Sqe::fgetxattr(RawFd::from_raw(3), c"user.a", &mut dest) };
    let inner = get.0;
    assert_eq!(Opcode::Fgetxattr, inner.opcode);
    assert_eq!(inner.fd, 3);
    assert_eq!(inner.addr, c"user.a".as_ptr() as u64);
    assert_eq!(inner.off, dest.as_ptr() as u64);
}

#[cfg(not(miri))]
#[test]
fn a_real_setxattr_getxattr_roundtrip_on_a_regular_file() {
    let mut ring = IoUring::new(4).expect("setup");
    let path = std::format!("/tmp/ququmatz_xattr_{}", std::process::id());
    std::fs::write(&path, b"body").expect("seed");
    let cpath = std::ffi::CString::new(path.clone()).expect("cstring");
    let name = c"user.ququmatz_test";

    let value = b"attribute-value";
    ring.push(
        unsafe { Sqe::setxattr(name, &cpath, value, crate::types::XattrFlags::default()) }
            .user_data(1),
    )
    .expect("push setxattr");
    ring.submit_and_wait(1).expect("submit");
    let cqe = ring.complete().expect("setxattr cqe");
    assert_eq!(cqe.result, 0, "setxattr failed: {}", cqe.result);

    let mut dest = [0u8; 64];
    ring.push(unsafe { Sqe::getxattr(name, &cpath, &mut dest) }.user_data(2))
        .expect("push getxattr");
    ring.submit_and_wait(1).expect("submit");
    let cqe = ring.complete().expect("getxattr cqe");
    assert!(cqe.result >= 0, "getxattr failed: {}", cqe.result);
    #[allow(clippy::cast_sign_loss)]
    let n = cqe.result as usize;
    assert_eq!(&dest[..n], value);

    let _ = std::fs::remove_file(&path);
}

#[cfg(not(miri))]
#[test]
fn statx_on_tmp() {
    let mut ring = IoUring::new(4).expect("setup");
    let mut buf = Statx::default();

    ring.push(
        unsafe {
            Sqe::statx(
                crate::types::DirFd::Cwd,
                c"/tmp",
                StatxFlags::default(),
                StatxMask::BASIC_STATS,
                &mut buf,
            )
        }
        .user_data(1),
    )
    .expect("push statx");
    ring.submit_and_wait(1).expect("submit");

    let cqe = ring.complete().expect("statx cqe");
    assert_eq!(cqe.user_data, 1);
    assert_eq!(cqe.result, 0);

    // /tmp should be a directory (mode & S_IFMT == S_IFDIR = 0o40000)
    assert_ne!(buf.stx_mode & 0o17_0000, 0);
    assert!(buf.stx_size > 0 || buf.stx_mode & 0o40000 != 0);
}

#[cfg(not(miri))]
#[test]
fn timeout_expiry() {
    let mut ring = IoUring::new(4).expect("setup");

    // 50ms timeout with count=0 (pure timer)
    let ts = Timespec::from_millis(50);
    ring.push(unsafe { Sqe::timeout(&ts, 0, TimeoutFlags::default()) }.user_data(1))
        .expect("push");
    ring.submit_and_wait(1).expect("submit");

    let cqe = ring.complete().expect("completion");
    assert_eq!(cqe.user_data, 1);
    // Timeout expiry returns -ETIME (62)
    assert_eq!(cqe.result, -62);
}

#[cfg(not(miri))]
#[test]
fn linked_nop_chain() {
    let mut ring = IoUring::new(8).expect("failed to create io_uring");

    // Submit 3 linked NOPs — they must complete in order
    ring.push(Sqe::nop().user_data(1).link()).expect("push 1");
    ring.push(Sqe::nop().user_data(2).link()).expect("push 2");
    ring.push(Sqe::nop().user_data(3)).expect("push 3");

    ring.submit_and_wait(3).expect("submit");

    // Linked ops complete in submission order
    let cqes: Vec<_> = ring.completions().collect();
    assert_eq!(cqes.len(), 3);
    for cqe in &cqes {
        assert_eq!(cqe.result, 0);
    }
    // All three user_data values present
    let mut seen = [false; 4];
    for cqe in &cqes {
        seen[cqe.user_data as usize] = true;
    }
    assert!(seen[1] && seen[2] && seen[3]);
}

#[cfg(not(miri))]
#[test]
fn nop_roundtrip() {
    let mut ring = IoUring::new(4).expect("failed to create io_uring");

    ring.push_nop(42).expect("failed to push NOP");
    ring.submit_and_wait(1).expect("failed to submit");

    let cqe = ring.complete().expect("expected a completion");
    assert_eq!(cqe.user_data, 42);
    assert_eq!(cqe.result, 0);

    assert!(ring.complete().is_none());
}

#[cfg(not(miri))]
#[test]
fn a_msg_ring_to_its_own_fd_posts_a_second_cqe() {
    use crate::types::RawFd;

    let mut ring = IoUring::new(4).expect("failed to create io_uring");
    let own_fd = RawFd::from_raw(ring.raw_fd().as_usize());

    let sqe = Sqe::msg_ring(own_fd, 7, 99).user_data(1);
    ring.push(sqe).expect("failed to push msg_ring");
    ring.submit_and_wait(2).expect("failed to submit");

    let mut saw_msg_ring_op = false;
    let mut saw_message = false;
    for _ in 0..2 {
        let cqe = ring.complete().expect("expected a completion");
        if cqe.user_data == 1 {
            assert_eq!(cqe.result, 0, "the msg_ring op itself should succeed");
            saw_msg_ring_op = true;
        } else if cqe.user_data == 99 {
            assert_eq!(cqe.result, 7);
            saw_message = true;
        }
    }
    assert!(
        saw_msg_ring_op,
        "the msg_ring request's own completion is missing"
    );
    assert!(saw_message, "the posted message never arrived");
}

#[cfg(not(miri))]
#[test]
fn multiple_nops() {
    let mut ring = IoUring::new(4).expect("failed to create io_uring");

    for i in 0..4 {
        ring.push_nop(i).expect("failed to push NOP");
    }
    ring.submit_and_wait(4).expect("failed to submit");

    let mut seen = [false; 4];
    for _ in 0..4 {
        let cqe = ring.complete().expect("expected a completion");
        assert_eq!(cqe.result, 0);
        seen[cqe.user_data as usize] = true;
    }
    assert!(seen.iter().all(|&s| s));
    assert!(ring.complete().is_none());
}

#[cfg(not(miri))]
#[test]
fn submit_return_value_tracks_actual_consumption_across_rounds() {
    // `submit`/`submit_and_wait` must advance their internal `sq_submitted`
    // bookkeeping by what `io_uring_enter` actually reports consuming, not
    // by the requested count — Linux permits a short submission. On the
    // common path (no rejected entries) the kernel consumes everything in
    // one call, so this cannot exercise a genuine partial-consumption
    // return from the kernel deterministically without a mockable syscall
    // backend (see AUDIT.md Q-07). What it does prove: many interleaved
    // push/submit rounds against a small ring never desynchronize the
    // `sq_submitted` cursor from reality — every push is submitted exactly
    // once, nothing is submitted twice, and nothing is silently dropped.
    // A regression that went back to unconditionally setting
    // `sq_submitted = sq_tail_local` would still pass this test on a
    // healthy kernel; it guards the accounting's steady-state correctness,
    // not the short-submission path itself.
    let mut ring = IoUring::new(4).expect("setup");
    let mut next_user_data = 0u64;
    let mut expected = std::collections::HashSet::new();

    for round in 0..50u64 {
        let batch = 1 + (round % 3);
        for _ in 0..batch {
            ring.push_nop(next_user_data).expect("push");
            expected.insert(next_user_data);
            next_user_data += 1;
        }
        let submitted = ring.submit_and_wait(batch as u32).expect("submit");
        assert_eq!(
            submitted, batch as u32,
            "round {round}: every pushed entry should be consumed in one \
             call on a healthy kernel with no queue pressure"
        );
        for _ in 0..batch {
            let cqe = ring.complete().expect("completion");
            assert!(
                expected.remove(&cqe.user_data),
                "round {round}: completion for user_data {} was unexpected or duplicated",
                cqe.user_data
            );
            assert_eq!(cqe.result, 0);
        }
    }

    assert!(
        expected.is_empty(),
        "leftover user_data values never completed: {expected:?}"
    );
    assert!(ring.complete().is_none());
}

#[cfg(not(miri))]
#[test]
fn completions_iterator() {
    let mut ring = IoUring::new(8).expect("failed to create io_uring");

    for i in 0..4 {
        ring.push_nop(i).expect("failed to push NOP");
    }
    ring.submit_and_wait(4).expect("failed to submit");

    let cqes: Vec<_> = ring.completions().collect();
    assert_eq!(cqes.len(), 4);
    for cqe in &cqes {
        assert_eq!(cqe.result, 0);
    }
}

#[cfg(not(miri))]
fn open_tmpfile(ring: &mut IoUring) -> i32 {
    ring.do_openat(
        crate::types::DirFd::Cwd,
        c"/tmp",
        OpenFlags::TMPFILE | OpenFlags::RDWR,
        FileMode::OWNER_READ | FileMode::OWNER_WRITE,
    )
    .expect("failed to open tmpfile") as i32
}

#[cfg(not(miri))]
#[test]
fn read_write_roundtrip() {
    let mut ring = IoUring::new(4).expect("failed to create io_uring");
    let fd = open_tmpfile(&mut ring);

    let write_buf = b"hello io_uring!";
    ring.push(unsafe { Sqe::write(RawFd::from_raw(fd as usize), write_buf, 0) }.user_data(1))
        .expect("failed to push write");
    ring.submit_and_wait(1).expect("failed to submit write");

    let cqe = ring.complete().expect("expected write completion");
    assert_eq!(cqe.user_data, 1);
    assert_eq!(cqe.result, write_buf.len() as i32);

    let mut read_buf = [0u8; 64];
    ring.push(unsafe { Sqe::read(RawFd::from_raw(fd as usize), &mut read_buf, 0) }.user_data(2))
        .expect("failed to push read");
    ring.submit_and_wait(1).expect("failed to submit read");

    let cqe = ring.complete().expect("expected read completion");
    assert_eq!(cqe.user_data, 2);
    assert_eq!(cqe.result, write_buf.len() as i32);
    assert_eq!(&read_buf[..write_buf.len()], write_buf);

    ring.push(Sqe::close(RawFd::from_raw(fd as usize)).user_data(3))
        .expect("failed to push close");
    ring.submit_and_wait(1).expect("failed to submit close");

    let cqe = ring.complete().expect("expected close completion");
    assert_eq!(cqe.user_data, 3);
    assert_eq!(cqe.result, 0);
}

#[cfg(not(miri))]
#[test]
fn a_stray_leftover_completion_is_not_mistaken_for_do_reads_own_result() {
    use crate::error::CompletionError;

    let mut ring = IoUring::new(4).expect("failed to create io_uring");
    let fd = open_tmpfile(&mut ring);
    let write_buf = b"stray completion probe";
    let n = ring
        .do_write(RawFd::from_raw(fd as usize), write_buf, 0)
        .expect("do_write");
    assert_eq!(n as usize, write_buf.len());

    // Leave a NOP completion sitting in the CQ, unconsumed, the way a
    // caller who forgot to drain something earlier would.
    ring.push_nop(0xdead_beef).expect("push stray nop");
    ring.submit_and_wait(1).expect("wait for stray nop");

    let mut read_buf = [0u8; 64];
    let err = ring
        .do_read(RawFd::from_raw(fd as usize), &mut read_buf, 0)
        .expect_err("do_read must not accept the stray nop's completion as its own");
    match err {
        Error::Completion(CompletionError::UnexpectedCompletion { found, .. }) => {
            assert_eq!(found, 0xdead_beef);
        }
        other => panic!("expected UnexpectedCompletion, got {other:?}"),
    }

    ring.do_close(RawFd::from_raw(fd as usize))
        .expect("do_close");
}

#[cfg(not(miri))]
#[test]
fn vectored_read_write() {
    let mut ring = IoUring::new(4).expect("failed to create io_uring");
    let fd = open_tmpfile(&mut ring);

    let mut buf_a = *b"hello ";
    let mut buf_b = *b"world!";
    let write_vecs = [
        unsafe { IoVec::new(buf_a.as_mut_ptr(), buf_a.len()) },
        unsafe { IoVec::new(buf_b.as_mut_ptr(), buf_b.len()) },
    ];
    ring.push(unsafe { Sqe::writev(RawFd::from_raw(fd as usize), &write_vecs, 0) }.user_data(1))
        .expect("failed to push writev");
    ring.submit_and_wait(1).expect("failed to submit writev");

    let cqe = ring.complete().expect("expected writev completion");
    assert_eq!(cqe.user_data, 1);
    assert_eq!(cqe.result as usize, buf_a.len() + buf_b.len());

    let mut read_buf = [0u8; 64];
    let read_vecs = [unsafe { IoVec::new(read_buf.as_mut_ptr(), read_buf.len()) }];
    ring.push(unsafe { Sqe::readv(RawFd::from_raw(fd as usize), &read_vecs, 0) }.user_data(2))
        .expect("failed to push readv");
    ring.submit_and_wait(1).expect("failed to submit readv");

    let cqe = ring.complete().expect("expected readv completion");
    assert_eq!(cqe.user_data, 2);
    let total = buf_a.len() + buf_b.len();
    assert_eq!(cqe.result as usize, total);
    assert_eq!(&read_buf[..total], b"hello world!");

    let _ = syscall::close(RawFd::from_raw(fd as usize));
}

#[cfg(not(miri))]
#[test]
fn builder_with_cq_entries() {
    let ring = IoUring::builder(4).cq_entries(16).build().expect("setup");
    // Just verify it was created successfully
    drop(ring);
}

#[cfg(not(miri))]
#[test]
fn builder_with_clamp() {
    // Requesting absurdly large ring with clamp should succeed
    let ring = IoUring::builder(1 << 20).clamp().build().expect("setup");
    drop(ring);
}

#[cfg(not(miri))]
#[test]
fn feature_detection() {
    let ring = IoUring::new(4).expect("setup");
    let features = ring.features();
    // Any modern kernel (5.4+) should have SINGLE_MMAP
    assert!(
        features.contains(Features::SINGLE_MMAP),
        "expected SINGLE_MMAP feature"
    );
}

#[cfg(not(miri))]
#[test]
fn registered_buffers_read_write() {
    let mut ring = IoUring::new(4).expect("setup");
    let fd = open_tmpfile(&mut ring);

    // Create and register a buffer
    let mut buf = vec![0u8; 4096];
    let iov = [unsafe { IoVec::new(buf.as_mut_ptr(), buf.len()) }];
    ring.register_buffers(&iov).expect("register_buffers");

    // Write via fixed buffer
    let msg = b"fixed buffer write!";
    buf[..msg.len()].copy_from_slice(msg);
    ring.push(
        unsafe {
            Sqe::write_fixed(
                RawFd::from_raw(fd as usize),
                buf.as_ptr(),
                msg.len() as u32,
                0,
                0,
            )
        }
        .user_data(1),
    )
    .expect("push write_fixed");
    ring.submit_and_wait(1).expect("submit");
    let cqe = ring.complete().expect("write cqe");
    assert_eq!(cqe.user_data, 1);
    assert_eq!(cqe.result, msg.len() as i32);

    // Read back via fixed buffer
    buf.fill(0);
    ring.push(
        unsafe {
            Sqe::read_fixed(
                RawFd::from_raw(fd as usize),
                buf.as_mut_ptr(),
                msg.len() as u32,
                0,
                0,
            )
        }
        .user_data(2),
    )
    .expect("push read_fixed");
    ring.submit_and_wait(1).expect("submit");
    let cqe = ring.complete().expect("read cqe");
    assert_eq!(cqe.user_data, 2);
    assert_eq!(cqe.result, msg.len() as i32);
    assert_eq!(&buf[..msg.len()], msg);

    ring.unregister_buffers().expect("unregister");
    let _ = syscall::close(RawFd::from_raw(fd as usize));
}

#[cfg(not(miri))]
#[test]
fn a_real_readv_fixed_writev_fixed_gathers_and_scatters_within_a_registered_buffer() {
    let mut ring = IoUring::new(4).expect("setup");
    let fd = open_tmpfile(&mut ring);

    let mut buf = vec![0u8; 4096];
    let iov = [unsafe { IoVec::new(buf.as_mut_ptr(), buf.len()) }];
    ring.register_buffers(&iov).expect("register_buffers");

    let first = b"hello, ";
    let second = b"fixed vector!";
    buf[0..first.len()].copy_from_slice(first);
    buf[64..64 + second.len()].copy_from_slice(second);

    let vecs = [
        unsafe { IoVec::new(buf.as_mut_ptr(), first.len()) },
        unsafe { IoVec::new(buf.as_mut_ptr().add(64), second.len()) },
    ];
    ring.push(
        unsafe { Sqe::writev_fixed(RawFd::from_raw(fd as usize), vecs.as_ptr(), 2, 0, 0) }
            .user_data(1),
    )
    .expect("push writev_fixed");
    ring.submit_and_wait(1).expect("submit");
    let cqe = ring.complete().expect("writev cqe");
    assert_eq!(cqe.user_data, 1);
    assert_eq!(cqe.result, (first.len() + second.len()) as i32);

    let mut dest = vec![0u8; 4096];
    let dest_iov = [unsafe { IoVec::new(dest.as_mut_ptr(), dest.len()) }];
    ring.unregister_buffers().expect("unregister source");
    ring.register_buffers(&dest_iov)
        .expect("register destination buffer");

    let read_vecs = [
        unsafe { IoVec::new(dest.as_mut_ptr(), first.len()) },
        unsafe { IoVec::new(dest.as_mut_ptr().add(64), second.len()) },
    ];
    ring.push(
        unsafe { Sqe::readv_fixed(RawFd::from_raw(fd as usize), read_vecs.as_ptr(), 2, 0, 0) }
            .user_data(2),
    )
    .expect("push readv_fixed");
    ring.submit_and_wait(1).expect("submit");
    let cqe = ring.complete().expect("readv cqe");
    assert_eq!(cqe.user_data, 2);
    assert_eq!(cqe.result, (first.len() + second.len()) as i32);
    assert_eq!(&dest[0..first.len()], first);
    assert_eq!(&dest[64..64 + second.len()], second);

    ring.unregister_buffers().expect("unregister destination");
    let _ = syscall::close(RawFd::from_raw(fd as usize));
}

#[cfg(not(miri))]
#[test]
fn registered_files() {
    let mut ring = IoUring::new(4).expect("setup");
    let fd = open_tmpfile(&mut ring);

    ring.register_files(&[fd]).expect("register_files");
    ring.unregister_files().expect("unregister_files");

    let _ = syscall::close(RawFd::from_raw(fd as usize));
}

#[cfg(not(miri))]
#[test]
fn a_real_tagged_file_table_posts_a_death_cqe_once_unregistered() {
    let mut ring = IoUring::new(4).expect("setup");
    let fd = open_tmpfile(&mut ring);

    const DEATH_TAG: u64 = 0xdead_beef;
    ring.register_files_tagged(&[fd], &[DEATH_TAG])
        .expect("register_files_tagged");

    ring.unregister_files().expect("unregister_files");

    ring.push(Sqe::nop().user_data(1)).expect("push nop");
    ring.submit_and_wait(2).expect("submit");

    let mut saw_death_tag = false;
    let mut saw_nop = false;
    for _ in 0..2 {
        let cqe = ring.complete().expect("cqe");
        if cqe.user_data == DEATH_TAG {
            saw_death_tag = true;
            assert_eq!(cqe.result, 0);
        } else if cqe.user_data == 1 {
            saw_nop = true;
        }
    }
    assert!(
        saw_death_tag,
        "expected a CQE carrying the file's death tag"
    );
    assert!(saw_nop, "expected the ordinary nop's own completion too");

    let _ = syscall::close(RawFd::from_raw(fd as usize));
}

#[cfg(not(miri))]
#[test]
fn a_real_tagged_file_update_posts_a_death_cqe_for_the_slot_it_replaces() {
    let mut ring = IoUring::new(4).expect("setup");
    let fd_a = open_tmpfile(&mut ring);
    let fd_b = open_tmpfile(&mut ring);

    const REPLACED_TAG: u64 = 0xfeed_face;
    ring.register_files_tagged(&[fd_a], &[0])
        .expect("register_files_tagged");

    ring.update_registered_files_tagged(&[fd_b], &[REPLACED_TAG], 0)
        .expect("update_registered_files_tagged");
    ring.update_registered_files_tagged(&[-1], &[0], 0)
        .expect("clear the slot to release fd_b");

    ring.push(Sqe::nop().user_data(1)).expect("push nop");
    ring.submit_and_wait(2).expect("submit");

    let mut saw_death_tag = false;
    for _ in 0..2 {
        let cqe = ring.complete().expect("cqe");
        if cqe.user_data == REPLACED_TAG {
            saw_death_tag = true;
        }
    }
    assert!(
        saw_death_tag,
        "expected a CQE carrying the replaced slot's death tag"
    );

    ring.unregister_files().expect("unregister_files");
    let _ = syscall::close(RawFd::from_raw(fd_a as usize));
    let _ = syscall::close(RawFd::from_raw(fd_b as usize));
}

#[cfg(not(miri))]
#[test]
fn a_real_tagged_buffer_table_posts_a_death_cqe_once_unregistered() {
    let mut ring = IoUring::new(4).expect("setup");
    let mut buf = vec![0u8; 64];
    let iov = [unsafe { IoVec::new(buf.as_mut_ptr(), buf.len()) }];

    const DEATH_TAG: u64 = 0xc0ffee;
    ring.register_buffers_tagged(&iov, &[DEATH_TAG])
        .expect("register_buffers_tagged");

    ring.unregister_buffers().expect("unregister_buffers");

    ring.push(Sqe::nop().user_data(1)).expect("push nop");
    ring.submit_and_wait(2).expect("submit");

    let mut saw_death_tag = false;
    for _ in 0..2 {
        let cqe = ring.complete().expect("cqe");
        if cqe.user_data == DEATH_TAG {
            saw_death_tag = true;
            assert_eq!(cqe.result, 0);
        }
    }
    assert!(
        saw_death_tag,
        "expected a CQE carrying the buffer's death tag"
    );
}

#[cfg(not(miri))]
#[test]
fn a_real_clone_buffers_gives_the_destination_ring_a_usable_copy() {
    let mut src = IoUring::new(4).expect("setup src");
    let mut dst = IoUring::new(4).expect("setup dst");

    let mut buf = vec![0xABu8; 64];
    let iov = [unsafe { IoVec::new(buf.as_mut_ptr(), buf.len()) }];
    src.register_buffers(&iov).expect("register_buffers");

    match dst.clone_registered_buffers(src.raw_fd()) {
        Ok(()) => {}
        Err(_) => {
            // Kernel < 6.12 or clone otherwise refused; nothing more to verify.
            return;
        }
    }

    let fd = open_tmpfile(&mut dst);
    // The clone shares the same underlying pages as `buf`, so its
    // virtual address is still valid for a fixed write through the
    // destination ring's copy of the buffer table.
    let sqe = unsafe {
        Sqe::write_fixed(
            RawFd::from_raw(fd as usize),
            buf.as_ptr(),
            buf.len() as u32,
            0,
            0,
        )
        .user_data(1)
    };
    dst.push(sqe).expect("push write_fixed");
    dst.submit_and_wait(1).expect("submit");
    let cqe = dst.complete().expect("cqe");
    assert_eq!(cqe.result, 64, "clone should leave a usable fixed buffer");

    let _ = syscall::close(RawFd::from_raw(fd as usize));
}

#[cfg(not(miri))]
#[test]
fn socket_with_typed_flags_creates_nonblocking_fd() {
    use crate::Socket;
    use crate::types::{AddressFamily, SocketFlags, SocketType};

    let sock = Socket::with_typed_flags(
        AddressFamily::Inet,
        SocketType::Stream,
        0,
        SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
    )
    .expect("socket");
    // fd() returns RawFd(usize); a successful socket() guarantees it's valid
    let _ = sock.fd();
    // No syscall to inspect flags here — we trust the kernel applied them
    // because socket(2) returned success with that argument layout. The
    // round-trip test (`tcp_send_recv_roundtrip`) exercises NONBLOCK end
    // to end via the io_uring accept path.
}

#[cfg(not(miri))]
fn setup_tcp_listener() -> (i32, u16) {
    let rawfd = syscall::socket(types::AF_INET, types::SOCK_STREAM | types::SOCK_NONBLOCK, 0)
        .expect("socket");
    let fd = rawfd.as_i32();

    let one: i32 = 1;
    // SOL_SOCKET=1, SO_REUSEADDR=2 — kernel constants, inlined here
    // because they're only needed by this test.
    // Safety: `one` is a live local `i32`, matching `SO_REUSEADDR`'s ABI.
    unsafe {
        syscall::setsockopt(
            rawfd,
            1,
            2,
            (&raw const one).cast(),
            core::mem::size_of::<i32>() as u32,
        )
    }
    .expect("setsockopt");

    let addr = SockAddrIn {
        sin_family: types::AF_INET as u16,
        sin_port: 0u16.to_be(), // let the kernel pick an ephemeral port
        sin_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        sin_zero: [0; 8],
    };
    // Safety: `addr` is a live local `SockAddrIn`, exactly the size passed.
    unsafe {
        syscall::bind(
            rawfd,
            (&raw const addr).cast(),
            core::mem::size_of::<SockAddrIn>() as u32,
        )
    }
    .expect("bind");
    syscall::listen(rawfd, 1).expect("listen");

    // Retrieve the actual port assigned by the kernel
    let mut bound_addr = SockAddrIn::default();
    let mut addrlen = core::mem::size_of::<SockAddrIn>() as u32;
    // Safety: `bound_addr`/`addrlen` are live locals, `addrlen` initialized
    // to `bound_addr`'s size.
    unsafe { syscall::getsockname(rawfd, (&raw mut bound_addr).cast(), &raw mut addrlen) }
        .expect("getsockname");

    (fd, u16::from_be(bound_addr.sin_port))
}

/// Drive an accept+connect handshake on `ring` and return the accepted server
/// fd. `listener`/`client` are raw fds; `port` is the listener's bound port.
#[cfg(not(miri))]
fn tcp_handshake(ring: &mut IoUring, listener: i32, client: i32, port: u16) -> i32 {
    ring.push(Sqe::accept(RawFd::from_raw(listener as usize), AcceptFlags::default()).user_data(1))
        .expect("push accept");
    let connect_addr = SockAddrIn {
        sin_family: types::AF_INET as u16,
        sin_port: port.to_be(),
        sin_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        sin_zero: [0; 8],
    };
    let addr_bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(
            (&raw const connect_addr).cast(),
            core::mem::size_of::<SockAddrIn>(),
        )
    };
    ring.push(unsafe { Sqe::connect(RawFd::from_raw(client as usize), addr_bytes) }.user_data(2))
        .expect("push connect");
    ring.submit_and_wait(2).expect("submit handshake");

    let mut server_fd = -1i32;
    for _ in 0..2 {
        let cqe = ring.complete().expect("handshake cqe");
        if cqe.user_data == 1 {
            assert!(cqe.result >= 0, "accept failed: {}", cqe.result);
            server_fd = cqe.result;
        } else {
            assert!(
                cqe.result == 0 || cqe.result == -115,
                "connect failed: {}",
                cqe.result
            );
        }
    }
    assert!(server_fd >= 0, "never got accept completion");
    server_fd
}

#[cfg(not(miri))]
#[test]
fn tcp_send_recv_roundtrip() {
    let mut ring = IoUring::new(8).expect("setup");
    let (listener, port) = setup_tcp_listener();

    let client = syscall::socket(types::AF_INET, types::SOCK_STREAM | types::SOCK_NONBLOCK, 0)
        .expect("client socket")
        .as_i32();

    // Accept + connect in parallel
    ring.push(Sqe::accept(RawFd::from_raw(listener as usize), AcceptFlags::default()).user_data(1))
        .expect("push accept");

    let connect_addr = SockAddrIn {
        sin_family: types::AF_INET as u16,
        sin_port: port.to_be(),
        sin_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        sin_zero: [0; 8],
    };
    let addr_bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(
            (&raw const connect_addr).cast(),
            core::mem::size_of::<SockAddrIn>(),
        )
    };
    ring.push(unsafe { Sqe::connect(RawFd::from_raw(client as usize), addr_bytes) }.user_data(2))
        .expect("push connect");

    ring.submit_and_wait(2).expect("submit");

    let mut server_fd = -1i32;
    for _ in 0..2 {
        let cqe = ring.complete().expect("cqe");
        if cqe.user_data == 1 {
            assert!(cqe.result >= 0, "accept failed: {}", cqe.result);
            server_fd = cqe.result;
        } else {
            assert!(
                cqe.result == 0 || cqe.result == -115,
                "connect failed: {}",
                cqe.result
            );
        }
    }
    assert!(server_fd >= 0, "never got accept completion");

    // Send from client, recv on server
    let msg = b"hello from io_uring!";
    ring.push(
        unsafe { Sqe::send(RawFd::from_raw(client as usize), msg, MsgFlags::default()) }
            .user_data(3),
    )
    .expect("push send");
    ring.submit_and_wait(1).expect("submit send");
    let cqe = ring.complete().expect("send cqe");
    assert_eq!(cqe.user_data, 3);
    assert_eq!(cqe.result, msg.len() as i32);

    let mut recv_buf = [0u8; 64];
    ring.push(
        unsafe {
            Sqe::recv(
                RawFd::from_raw(server_fd as usize),
                &mut recv_buf,
                MsgFlags::default(),
            )
        }
        .user_data(4),
    )
    .expect("push recv");
    ring.submit_and_wait(1).expect("submit recv");
    let cqe = ring.complete().expect("recv cqe");
    assert_eq!(cqe.user_data, 4);
    assert_eq!(cqe.result, msg.len() as i32);
    assert_eq!(&recv_buf[..msg.len()], msg);

    let _ = syscall::close(RawFd::from_raw(server_fd as usize));
    let _ = syscall::close(RawFd::from_raw(client as usize));
    let _ = syscall::close(RawFd::from_raw(listener as usize));
}

#[cfg(not(miri))]
#[test]
fn provided_buffer_ring_buffer_mut_allows_inplace_edit() {
    // Round-trips real kernel-delivered bytes through `buffer_mut`.
    // Proves the mutable path works end-to-end and that edits to
    // the returned `&mut [u8]` actually land in the backing region
    // (the shared `buffer()` read afterwards sees them).
    let mut ring = IoUring::new(8).expect("setup");
    let (listener, port) = setup_tcp_listener();

    let client = syscall::socket(types::AF_INET, types::SOCK_STREAM | types::SOCK_NONBLOCK, 0)
        .expect("client socket")
        .as_i32();

    let mut pbuf = ring
        .register_provided_buffers(2, 4, 64)
        .expect("register_provided_buffers");

    ring.push(Sqe::accept(RawFd::from_raw(listener as usize), AcceptFlags::default()).user_data(1))
        .expect("push accept");
    let connect_addr = SockAddrIn {
        sin_family: types::AF_INET as u16,
        sin_port: port.to_be(),
        sin_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        sin_zero: [0; 8],
    };
    let addr_bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(
            (&raw const connect_addr).cast(),
            core::mem::size_of::<SockAddrIn>(),
        )
    };
    ring.push(unsafe { Sqe::connect(RawFd::from_raw(client as usize), addr_bytes) }.user_data(2))
        .expect("push connect");
    ring.submit_and_wait(2).expect("submit");

    let mut server_fd = -1i32;
    for _ in 0..2 {
        let cqe = ring.complete().expect("cqe");
        if cqe.user_data == 1 {
            server_fd = cqe.result;
        }
    }
    assert!(server_fd >= 0);

    let msg = b"mutate me";
    ring.push(
        unsafe { Sqe::send(RawFd::from_raw(client as usize), msg, MsgFlags::default()) }
            .user_data(3),
    )
    .expect("push send");
    let recv_sqe = unsafe {
        Sqe::recv_ptr(
            RawFd::from_raw(server_fd as usize),
            core::ptr::null_mut(),
            0,
            MsgFlags::default(),
        )
    }
    .buffer_select(2)
    .user_data(4);
    ring.push(recv_sqe).expect("push recv");
    ring.submit_and_wait(2).expect("submit send+recv");

    let mut buf_id = u16::MAX;
    let mut len = 0u32;
    for _ in 0..2 {
        let cqe = ring.complete().expect("cqe");
        if cqe.user_data == 4 {
            assert!(cqe.result >= 0, "recv failed: {}", cqe.result);
            buf_id = cqe.buffer_id().expect("buffer_id present");
            #[allow(clippy::cast_sign_loss)]
            {
                len = cqe.result as u32;
            }
        }
    }
    assert_ne!(buf_id, u16::MAX);

    // Mutate in place: uppercase the payload via `buffer_mut`.
    {
        let payload = pbuf.buffer_mut(buf_id, len).expect("buffer_mut");
        assert_eq!(payload, msg);
        payload.make_ascii_uppercase();
    }

    // The shared view of the same slot should now reflect the edit.
    let after = pbuf.buffer(buf_id, len).expect("buffer");
    assert_eq!(after, b"MUTATE ME");

    // Out-of-range ids / overlong lens return None, not a panic.
    assert!(pbuf.buffer_mut(999, 1).is_none());
    assert!(pbuf.buffer_mut(0, pbuf.buf_size() + 1).is_none());

    pbuf.recycle_and_commit(buf_id);
    let _ = syscall::close(RawFd::from_raw(server_fd as usize));
    let _ = syscall::close(RawFd::from_raw(client as usize));
    let _ = syscall::close(RawFd::from_raw(listener as usize));
}

#[cfg(not(miri))]
#[test]
fn provided_buffer_ring_register_only() {
    let mut ring = IoUring::new(4).expect("setup");
    let pbuf = ring
        .register_provided_buffers(7, 4, 64)
        .expect("register_provided_buffers");
    assert_eq!(pbuf.bgid(), 7);
    assert_eq!(pbuf.entries(), 4);
    assert_eq!(pbuf.buf_size(), 64);
    // Drop unregisters and frees.
    drop(pbuf);

    // Re-registering the same bgid should now succeed.
    let _pbuf2 = ring
        .register_provided_buffers(7, 4, 64)
        .expect("re-register");
}

#[cfg(not(miri))]
#[test]
fn provided_buffer_ring_outlives_the_ring_that_registered_it() {
    // Q-05: `ProvidedBufferRing` used to carry a bare copied `fd: RawFd`
    // with no tie to the parent ring's actual lifetime. Dropping the
    // parent `IoUring` closed that fd underneath the pool; the kernel is
    // then free to hand the same fd number to the next thing this
    // process opens, and the pool's own registration/unmap calls would
    // silently target whatever now holds that number instead of failing
    // loudly. Retaining a `RingResources` share defers the fd close
    // until the pool itself is dropped, so a pool must go on working
    // (here: `status()`, which issues `io_uring_register` against the
    // pool's own fd) for as long as it is alive, even after its parent
    // `IoUring` is gone and something else has taken over lower fd
    // numbers.
    let mut ring = IoUring::new(4).expect("setup");
    let pbuf = ring
        .register_provided_buffers(3, 4, 64)
        .expect("register_provided_buffers");

    drop(ring);

    // Open several fresh descriptors: if the parent's fd had actually
    // been closed here, one of these opens would likely reclaim that
    // exact number, and the assertions below would then be silently
    // exercising someone else's descriptor instead of catching the bug.
    let mut decoys = vec![];
    for _ in 0..8 {
        decoys.push(syscall::eventfd2(0, 0).expect("decoy eventfd"));
    }

    // The pool's own fd must still be live: `status()` round-trips an
    // `io_uring_register` call against it.
    let head = pbuf
        .status()
        .expect("status survives the parent ring's drop");
    assert_eq!(head, 0, "a freshly registered pool has consumed nothing");

    for fd in decoys {
        let _ = syscall::close(fd);
    }
    drop(pbuf);
}

#[cfg(not(miri))]
#[test]
fn provided_buffer_ring_rejects_count_above_kernel_max() {
    use crate::error::{Error, InvalidArgKind, SetupError};

    // IORING_REGISTER_PBUF_RING caps ring_entries at 32768 (2^15). A
    // caller-supplied count above that must be rejected before any mmap or
    // registration syscall runs, not surfaced as an opaque kernel EINVAL.
    let mut ring = IoUring::new(4).expect("setup");
    let Err(err) = ring.register_provided_buffers(1, 1 << 16, 64) else {
        panic!("count above 32768 must be rejected")
    };
    assert_eq!(
        err,
        Error::Setup(SetupError::InvalidArg(InvalidArgKind::BufferCountTooLarge))
    );
}

#[cfg(not(miri))]
#[test]
fn provided_buffer_ring_recv() {
    let mut ring = IoUring::new(8).expect("setup");
    let (listener, port) = setup_tcp_listener();

    let client = syscall::socket(types::AF_INET, types::SOCK_STREAM | types::SOCK_NONBLOCK, 0)
        .expect("client socket")
        .as_i32();

    // Register a 4-entry provided-buffer ring of 64-byte buffers
    // under group id 1. Dropping `pbuf` at end of scope
    // unregisters and frees.
    let mut pbuf = ring
        .register_provided_buffers(1, 4, 64)
        .expect("register_provided_buffers");

    // Accept + connect
    ring.push(Sqe::accept(RawFd::from_raw(listener as usize), AcceptFlags::default()).user_data(1))
        .expect("push accept");
    let connect_addr = SockAddrIn {
        sin_family: types::AF_INET as u16,
        sin_port: port.to_be(),
        sin_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        sin_zero: [0; 8],
    };
    let addr_bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(
            (&raw const connect_addr).cast(),
            core::mem::size_of::<SockAddrIn>(),
        )
    };
    ring.push(unsafe { Sqe::connect(RawFd::from_raw(client as usize), addr_bytes) }.user_data(2))
        .expect("push connect");
    ring.submit_and_wait(2).expect("submit");

    let mut server_fd = -1i32;
    for _ in 0..2 {
        let cqe = ring.complete().expect("cqe");
        if cqe.user_data == 1 {
            assert!(cqe.result >= 0, "accept failed: {}", cqe.result);
            server_fd = cqe.result;
        } else {
            assert!(
                cqe.result == 0 || cqe.result == -115,
                "connect failed: {}",
                cqe.result
            );
        }
    }
    assert!(server_fd >= 0);

    // Send from client; recv on server using buffer select (len=0
    // tells the kernel to use the selected buffer's length).
    let msg = b"provided buffers!";
    ring.push(
        unsafe { Sqe::send(RawFd::from_raw(client as usize), msg, MsgFlags::default()) }
            .user_data(3),
    )
    .expect("push send");
    let recv_sqe = unsafe {
        Sqe::recv_ptr(
            RawFd::from_raw(server_fd as usize),
            core::ptr::null_mut(),
            0,
            MsgFlags::default(),
        )
    }
    .buffer_select(1)
    .user_data(4);
    ring.push(recv_sqe).expect("push recv");

    ring.submit_and_wait(2).expect("submit send+recv");

    let mut got_send = false;
    let mut got_recv = false;
    for _ in 0..2 {
        let cqe = ring.complete().expect("cqe");
        if cqe.user_data == 3 {
            assert_eq!(cqe.result, msg.len() as i32);
            got_send = true;
        } else {
            assert_eq!(cqe.user_data, 4);
            assert!(cqe.result >= 0, "recv failed: {}", cqe.result);
            let buf_id = cqe.buffer_id().expect("buffer_id present");
            #[allow(clippy::cast_sign_loss)]
            let payload = pbuf
                .buffer(buf_id, cqe.result as u32)
                .expect("buffer slice");
            assert_eq!(payload, msg);
            // Return the buffer to the pool.
            pbuf.recycle_and_commit(buf_id);
            got_recv = true;
        }
    }
    assert!(got_send && got_recv);

    let _ = syscall::close(RawFd::from_raw(server_fd as usize));
    let _ = syscall::close(RawFd::from_raw(client as usize));
    let _ = syscall::close(RawFd::from_raw(listener as usize));
}

#[cfg(not(miri))]
#[test]
fn a_real_incremental_buffer_ring_consumes_one_buffer_across_two_recvs() {
    // A single 16-byte buffer, registered for incremental consumption
    // (IOU_PBUF_RING_INC). Two separate 8-byte sends are received by two
    // separate recv requests against the *same* bgid; the kernel should
    // hand back the same buffer id both times, advancing into it rather
    // than treating each recv as claiming a fresh buffer.
    use crate::types::CqeFlags;

    let mut ring = IoUring::new(8).expect("setup");
    let (listener, port) = setup_tcp_listener();
    let client = syscall::socket(types::AF_INET, types::SOCK_STREAM | types::SOCK_NONBLOCK, 0)
        .expect("client socket")
        .as_i32();

    let Ok(mut pbuf) = ring.register_incremental_buffers(9, 1, 16) else {
        // Kernel predates IOU_PBUF_RING_INC (6.12+); nothing to test.
        let _ = syscall::close(RawFd::from_raw(client as usize));
        let _ = syscall::close(RawFd::from_raw(listener as usize));
        return;
    };

    let server_fd = tcp_handshake(&mut ring, listener, client, port);

    let first = b"AAAAAAAA";
    let second = b"BBBBBBBB";

    ring.push(
        unsafe { Sqe::send(RawFd::from_raw(client as usize), first, MsgFlags::default()) }
            .user_data(10),
    )
    .expect("push send 1");
    ring.submit_and_wait(1).expect("submit send 1");
    let cqe = ring.complete().expect("send 1 cqe");
    assert_eq!(cqe.result, first.len() as i32);

    let recv1 = unsafe {
        Sqe::recv_ptr(
            RawFd::from_raw(server_fd as usize),
            core::ptr::null_mut(),
            0,
            MsgFlags::default(),
        )
    }
    .buffer_select(9)
    .user_data(11);
    ring.push(recv1).expect("push recv 1");
    ring.submit_and_wait(1).expect("submit recv 1");
    let cqe1 = ring.complete().expect("recv 1 cqe");
    assert_eq!(cqe1.result, first.len() as i32, "recv 1: {}", cqe1.result);
    let buf_id_1 = cqe1.buffer_id().expect("buffer_id on recv 1");
    assert!(
        cqe1.flags.contains(CqeFlags::BUF_MORE),
        "first partial recv must keep the buffer under kernel ownership"
    );

    ring.push(
        unsafe {
            Sqe::send(
                RawFd::from_raw(client as usize),
                second,
                MsgFlags::default(),
            )
        }
        .user_data(12),
    )
    .expect("push send 2");
    ring.submit_and_wait(1).expect("submit send 2");
    let cqe = ring.complete().expect("send 2 cqe");
    assert_eq!(cqe.result, second.len() as i32);

    let recv2 = unsafe {
        Sqe::recv_ptr(
            RawFd::from_raw(server_fd as usize),
            core::ptr::null_mut(),
            0,
            MsgFlags::default(),
        )
    }
    .buffer_select(9)
    .user_data(13);
    ring.push(recv2).expect("push recv 2");
    ring.submit_and_wait(1).expect("submit recv 2");
    let cqe2 = ring.complete().expect("recv 2 cqe");
    assert_eq!(cqe2.result, second.len() as i32, "recv 2: {}", cqe2.result);
    let buf_id_2 = cqe2.buffer_id().expect("buffer_id on recv 2");
    assert_eq!(
        buf_id_1, buf_id_2,
        "incremental consumption must hand back the same buffer id"
    );
    assert!(
        !cqe2.flags.contains(CqeFlags::BUF_MORE),
        "the buffer is now fully drained and should return to the pool"
    );

    // Both partial writes land in the same physically contiguous 16-byte
    // slot — the kernel advances the buffer's tracked address between
    // completions, not the underlying memory.
    let whole = pbuf.buffer(buf_id_2, 16).expect("full 16-byte buffer");
    assert_eq!(&whole[..8], first);
    assert_eq!(&whole[8..], second);

    pbuf.recycle_and_commit(buf_id_2);

    let _ = syscall::close(RawFd::from_raw(server_fd as usize));
    let _ = syscall::close(RawFd::from_raw(client as usize));
    let _ = syscall::close(RawFd::from_raw(listener as usize));
}

#[cfg(not(miri))]
#[test]
fn rw_attr_pi_layout_matches_the_kernel_struct() {
    use crate::types::RwAttrPi;

    assert_eq!(mem::size_of::<RwAttrPi>(), 32);
    assert_eq!(mem::align_of::<RwAttrPi>(), 8);
    assert_eq!(mem::offset_of!(RwAttrPi, flags), 0);
    assert_eq!(mem::offset_of!(RwAttrPi, app_tag), 2);
    assert_eq!(mem::offset_of!(RwAttrPi, len), 4);
    assert_eq!(mem::offset_of!(RwAttrPi, addr), 8);
    assert_eq!(mem::offset_of!(RwAttrPi, seed), 16);
    assert_eq!(mem::offset_of!(RwAttrPi, rsvd), 24);
}

#[cfg(not(miri))]
#[test]
fn sqe_builder_with_pi_attr_places_attr_ptr_and_mask_over_addr3_and_pad2() {
    use crate::types::{RwAttrFlags, RwAttrPi};

    let mut buf = [0u8; 16];
    let attr = RwAttrPi::default();
    let sqe = unsafe { Sqe::read(RawFd::from_raw(9), &mut buf, 0) };
    let sqe = unsafe { sqe.with_pi_attr(&raw const attr) };
    let inner = sqe.0;

    assert_eq!(inner.addr3, &raw const attr as u64);
    assert_eq!(inner.attr_ptr(), &raw const attr as u64);
    assert_eq!(inner.pad2[0], RwAttrFlags::PI.bits());
    assert_eq!(inner.attr_type_mask(), RwAttrFlags::PI.bits());
}

#[cfg(not(miri))]
#[test]
fn a_real_pi_attributed_read_reaches_the_kernels_metadata_check() {
    use crate::types::RwAttrPi;

    let mut ring = IoUring::new(4).expect("failed to create io_uring");
    let fd = open_tmpfile(&mut ring);

    let mut read_buf = [0u8; 16];
    let mut meta_buf = [0u8; 8];
    let attr = RwAttrPi {
        flags: 0,
        app_tag: 0,
        len: meta_buf.len() as u32,
        addr: meta_buf.as_mut_ptr() as u64,
        seed: 0,
        rsvd: 0,
    };

    let sqe = unsafe { Sqe::read(RawFd::from_raw(fd as usize), &mut read_buf, 0) };
    let sqe = unsafe { sqe.with_pi_attr(&raw const attr) }.user_data(1);
    ring.push(sqe).expect("failed to push PI-attributed read");
    ring.submit_and_wait(1).expect("failed to submit");

    let cqe = ring.complete().expect("expected a completion");
    assert_eq!(cqe.user_data, 1);
    // A tmpfile has no FMODE_HAS_METADATA — the kernel rejects the
    // request with -EINVAL once it reaches io_rw_init_file's metadata
    // check, confirming attr_ptr/attr_type_mask were read and parsed
    // (an unparsed/garbage attribute would fail earlier, at the
    // attr_type_mask != IORING_RW_ATTR_FLAG_PI check in __io_prep_rw,
    // or crash on a bad attr_ptr instead of failing this specific,
    // late-stage check).
    assert_eq!(cqe.result, -Errno::EINVAL.0);

    ring.push(Sqe::close(RawFd::from_raw(fd as usize)).user_data(2))
        .expect("failed to push close");
    ring.submit_and_wait(1).expect("failed to submit close");
    let cqe = ring.complete().expect("expected close completion");
    assert_eq!(cqe.result, 0);
}

#[cfg(not(miri))]
#[test]
fn io_uring_buf_status_layout_matches_the_kernel_struct() {
    use crate::types::IoUringBufStatus;

    assert_eq!(mem::size_of::<IoUringBufStatus>(), 40);
    assert_eq!(mem::align_of::<IoUringBufStatus>(), 4);
}

#[cfg(not(miri))]
#[test]
fn a_real_pbuf_status_reports_the_head_the_kernel_advances() {
    let mut ring = IoUring::new(8).expect("setup");
    let mut pbuf = ring
        .register_provided_buffers(7, 4, 64)
        .expect("register_provided_buffers");

    // Freshly registered and fully stocked: nothing has been consumed yet.
    assert_eq!(pbuf.status().expect("status"), 0);

    // A TCP handshake, then a send/recv over it, drives exactly one buffer
    // through the pool.
    let (listener, port) = setup_tcp_listener();
    let client = syscall::socket(types::AF_INET, types::SOCK_STREAM | types::SOCK_NONBLOCK, 0)
        .expect("client socket")
        .as_i32();
    let server_fd = tcp_handshake(&mut ring, listener, client, port);

    let msg = b"pbuf status";
    ring.push(
        unsafe { Sqe::send(RawFd::from_raw(client as usize), msg, MsgFlags::default()) }
            .user_data(2),
    )
    .expect("push send");

    let recv_sqe = unsafe {
        Sqe::recv_ptr(
            RawFd::from_raw(server_fd as usize),
            core::ptr::null_mut(),
            0,
            MsgFlags::default(),
        )
    }
    .buffer_select(7)
    .user_data(3);
    ring.push(recv_sqe).expect("push recv");
    ring.submit_and_wait(2).expect("submit send+recv");

    let mut recv_result = None;
    for _ in 0..2 {
        let cqe = ring.complete().expect("cqe");
        if cqe.user_data == 3 {
            recv_result = Some(cqe);
        }
    }
    let recv_cqe = recv_result.expect("recv completion");
    assert!(recv_cqe.result >= 0, "recv failed: {}", recv_cqe.result);
    let buf_id = recv_cqe.buffer_id().expect("buffer_id present");

    // Consumed but not yet recycled: the kernel's head has advanced past
    // the buffer it handed out.
    assert_eq!(pbuf.status().expect("status"), 1);

    pbuf.recycle_and_commit(buf_id);
    // Recycling publishes a fresh buffer at the tail; it does not move the
    // kernel's consumer head backwards.
    assert_eq!(pbuf.status().expect("status"), 1);

    let _ = syscall::close(RawFd::from_raw(server_fd as usize));
    let _ = syscall::close(RawFd::from_raw(client as usize));
    let _ = syscall::close(RawFd::from_raw(listener as usize));
}

/// Two-thread mirror of [`provided_buffer_ring_recv`]: register the pool from
/// the `Submitter` after `split()`, hand its `BufferConsumer` to a separate
/// completion thread, and recv several messages so the kernel recycles buffer
/// ids fed back across the thread boundary.
///
/// Exercises the split-concurrency path: `Submitter::register_provided_buffers`,
/// `ProvidedBufferRing::split`, and `BufferConsumer` (read + recycle) on a
/// thread distinct from the one that submits.
#[cfg(not(miri))]
#[test]
fn provided_buffer_ring_recv_split_threads() {
    extern crate std;
    use std::sync::mpsc;
    use std::thread;

    const BGID: u16 = 3;
    const POOL_ENTRIES: u32 = 4;
    const BUF_SIZE: u32 = 64;
    const MESSAGES: usize = 8; // > pool size, so ids must recycle
    const RECV_UD: u64 = 100;

    let mut ring = IoUring::new(8).expect("setup");
    let (listener, port) = setup_tcp_listener();

    let client = syscall::socket(types::AF_INET, types::SOCK_STREAM | types::SOCK_NONBLOCK, 0)
        .expect("client socket")
        .as_i32();

    // --- Connection handshake on the un-split ring (setup is serial) ---------
    let server_fd = tcp_handshake(&mut ring, listener, client, port);

    // --- Split, then register the pool through the Submitter -----------------
    let (mut submitter, mut completer) = ring.split().unwrap_or_else(|(_, e)| panic!("split: {e}"));
    let pool = submitter
        .register_provided_buffers(BGID, POOL_ENTRIES, BUF_SIZE)
        .expect("register provided buffers via Submitter");
    assert_eq!(pool.bgid(), BGID);
    let mut consumer = pool.split(); // Send → moves to the completion thread

    // --- Completion thread: read each recv'd buffer, verify, recycle ---------
    let (got_tx, got_rx) = mpsc::channel::<(usize, std::vec::Vec<u8>)>();
    let complete = thread::spawn(move || {
        let mut received = 0usize;
        while received < MESSAGES {
            completer.wait(1).expect("wait");
            for cqe in completer.completions() {
                if cqe.user_data != RECV_UD {
                    continue;
                }
                assert!(!cqe.is_err(), "recv failed: errno {}", -cqe.result);
                let buf_id = cqe.buffer_id().expect("buffer_id present");
                #[allow(clippy::cast_sign_loss)]
                let len = cqe.result as u32;
                let payload = consumer.buffer(buf_id, len).expect("buffer slice");
                got_tx
                    .send((received, payload.to_vec()))
                    .expect("main alive");
                consumer.recycle_and_commit(buf_id);
                received += 1;
            }
        }
        completer
    });

    // --- Submit thread: one single-shot recv per message ---------------------
    // Single-shot (not multishot) keeps the test deterministic: each recv
    // consumes exactly one pool buffer, and we only arm the next after the
    // previous completion has recycled, so the 4-buffer pool serves all 8.
    let (send_next_tx, send_next_rx) = mpsc::channel::<()>();
    let submit = thread::spawn(move || {
        for _ in 0..MESSAGES {
            // Wait until the driver has written a message to recv.
            send_next_rx.recv().expect("driver alive");
            let recv_sqe = unsafe {
                Sqe::recv_ptr(
                    RawFd::from_raw(server_fd as usize),
                    core::ptr::null_mut(),
                    0,
                    MsgFlags::default(),
                )
            }
            .buffer_select(BGID)
            .user_data(RECV_UD);
            submitter.push(recv_sqe).expect("push recv");
            submitter.submit().expect("submit recv");
        }
        submitter
    });

    // --- Driver: write one message, let the recv fire, collect, repeat -------
    for i in 0..MESSAGES {
        let msg = std::format!("msg-{i:02}");
        send_next_tx.send(()).expect("submit thread alive");
        // Small settle so the recv SQE is armed before/around the write; the
        // recv is robust to ordering either way (data is buffered in the socket).
        // Safety: `msg` is a live `String`, readable for its full length.
        let n =
            unsafe { syscall::write(RawFd::from_raw(client as usize), msg.as_ptr(), msg.len()) }
                .expect("write");
        assert_eq!(n, msg.len());

        let (idx, payload) = got_rx
            .recv_timeout(core::time::Duration::from_secs(5))
            .expect("completion within timeout");
        assert_eq!(idx, i, "completions arrive in order");
        assert_eq!(payload, msg.as_bytes(), "payload mismatch at message {i}");
    }

    let _submitter = submit.join().expect("submit thread");
    let _completer = complete.join().expect("complete thread");

    let _ = syscall::close(RawFd::from_raw(server_fd as usize));
    let _ = syscall::close(RawFd::from_raw(client as usize));
    let _ = syscall::close(RawFd::from_raw(listener as usize));
}

// ---------------------------------------------------------------
// Inotify layout tests — run under Miri.
// ---------------------------------------------------------------

#[test]
fn inotify_event_layout() {
    assert_eq!(mem::size_of::<InotifyEvent>(), 16);
    assert_eq!(mem::align_of::<InotifyEvent>(), 4);
}

#[test]
fn inotify_event_field_offsets() {
    assert_eq!(mem::offset_of!(InotifyEvent, wd), 0);
    assert_eq!(mem::offset_of!(InotifyEvent, mask), 4);
    assert_eq!(mem::offset_of!(InotifyEvent, cookie), 8);
    assert_eq!(mem::offset_of!(InotifyEvent, len), 12);
}

#[test]
fn watch_mask_bitflags() {
    let mask = WatchMask::MODIFY | WatchMask::CREATE | WatchMask::DELETE;
    assert!(mask.contains(WatchMask::MODIFY));
    assert!(mask.contains(WatchMask::CREATE));
    assert!(mask.contains(WatchMask::DELETE));
    assert!(!mask.contains(WatchMask::ACCESS));
}

#[test]
fn watch_mask_close_shorthand() {
    let close = WatchMask::CLOSE;
    assert!(close.contains(WatchMask::CLOSE_WRITE));
    assert!(close.contains(WatchMask::CLOSE_NOWRITE));
}

#[test]
fn watch_mask_move_shorthand() {
    let mv = WatchMask::MOVE;
    assert!(mv.contains(WatchMask::MOVED_FROM));
    assert!(mv.contains(WatchMask::MOVED_TO));
}

#[test]
fn inotify_init_flag_bits() {
    assert_eq!(InotifyInitFlags::NONBLOCK.bits(), 0o4000);
    assert_eq!(InotifyInitFlags::CLOEXEC.bits(), 0o2_000_000);
}

// ---------------------------------------------------------------
// Inotify kernel integration tests — skipped under Miri.
// ---------------------------------------------------------------

#[cfg(not(miri))]
#[test]
fn inotify_new_returns_valid_fd() {
    let ino = Inotify::new().expect("inotify_init1");
    // fd() returns RawFd; successful inotify_init1 guarantees it's valid
    let _ = ino.fd();
}

#[cfg(not(miri))]
#[test]
fn inotify_into_fd_prevents_double_close() {
    let ino = Inotify::new().expect("inotify_init1");
    let fd = ino.into_fd();
    // fd is RawFd(usize); successful inotify_init1 guarantees it's valid
    syscall::close(fd).expect("close");
}

#[cfg(not(miri))]
#[test]
fn inotify_add_and_remove_watch() {
    let ino = Inotify::new().expect("inotify_init1");
    let wd = ino
        .add_watch(c"/tmp", WatchMask::CREATE | WatchMask::DELETE)
        .expect("add_watch");
    assert!(wd >= 0);
    ino.remove_watch(wd).expect("remove_watch");
}

#[cfg(not(miri))]
#[test]
fn inotify_remove_bad_wd_returns_error() {
    use crate::error::Errno;
    let ino = Inotify::new().expect("inotify_init1");
    let err = ino.remove_watch(9999).unwrap_err();
    assert_eq!(err, Error::Syscall(Errno::EINVAL));
}

#[cfg(not(miri))]
#[test]
fn inotify_add_watch_bad_path_returns_error() {
    use crate::error::Errno;
    let ino = Inotify::new().expect("inotify_init1");
    let err = ino
        .add_watch(c"/nonexistent_path_ququmatz_test", WatchMask::MODIFY)
        .unwrap_err();
    assert_eq!(err, Error::Syscall(Errno::ENOENT));
}

#[cfg(not(miri))]
#[test]
fn inotify_read_via_io_uring() {
    use std::fs;

    let ino = Inotify::new().expect("inotify_init1");

    // Create a private, unpredictably-named temp directory to watch. Plain
    // `create_dir` (not `create_dir_all`) is exclusive at the leaf: if
    // anything (including a symlink) already occupies that name, mkdir(2)
    // fails with EEXIST instead of following it.
    let target = UniqueTestPath::new("inotify_test");
    let dir = target.as_str();
    fs::create_dir(dir).expect("mkdir");

    let watch_cstring = target.as_cstring();
    let wd = ino
        .add_watch(&watch_cstring, WatchMask::CREATE)
        .expect("add_watch");

    // Create a file inside the watched dir to trigger an event
    let file_path = std::format!("{dir}/testfile");
    fs::write(&file_path, b"hello").expect("write file");

    // Read the event via io_uring
    let mut ring = IoUring::new(4).expect("setup");
    let mut buf = [0u8; 256];
    let n = ring.do_read(ino.fd(), &mut buf, 0).expect("do_read");
    assert!(n > 0, "expected data, got {n}");

    // Parse the event header
    let event: InotifyEvent =
        unsafe { core::ptr::read_unaligned(buf.as_ptr().cast::<InotifyEvent>()) };
    assert_eq!(event.wd, wd);
    assert_ne!(event.mask & WatchMask::CREATE.bits(), 0);

    // Check the name if present
    if event.len > 0 {
        let name_start = mem::size_of::<InotifyEvent>();
        let name_bytes = &buf[name_start..name_start + event.len as usize];
        let name = core::str::from_utf8(
            &name_bytes[..name_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(name_bytes.len())],
        )
        .expect("valid utf8");
        assert_eq!(name, "testfile");
    }

    ino.remove_watch(wd).expect("remove_watch");

    // `file_path` and the directory itself are removed by `target`'s Drop,
    // which runs even if an assertion above panics.
}

// ---------------------------------------------------------------
// EventFd tests
// ---------------------------------------------------------------

#[test]
fn eventfd_flags_values() {
    assert_eq!(EventFdFlags::NONBLOCK.bits(), 0o4000);
    assert_eq!(EventFdFlags::CLOEXEC.bits(), 0o2_000_000);
    assert_eq!(EventFdFlags::SEMAPHORE.bits(), 1);
}

#[test]
fn eventfd_flags_combine() {
    let flags = EventFdFlags::NONBLOCK | EventFdFlags::CLOEXEC;
    assert!(flags.contains(EventFdFlags::NONBLOCK));
    assert!(flags.contains(EventFdFlags::CLOEXEC));
    assert!(!flags.contains(EventFdFlags::SEMAPHORE));
}

#[cfg(not(miri))]
#[test]
fn eventfd_new_returns_valid_fd() {
    let efd = EventFd::new(0).expect("eventfd2");
    // fd() returns RawFd; successful eventfd2 guarantees it's valid
    let _ = efd.fd();
}

#[cfg(not(miri))]
#[test]
fn eventfd_into_fd_prevents_double_close() {
    let efd = EventFd::new(0).expect("eventfd2");
    let fd = efd.into_fd();
    // fd is RawFd; successful eventfd2 guarantees it's valid
    syscall::close(fd).expect("close");
}

#[cfg(not(miri))]
#[test]
fn eventfd_with_flags() {
    let efd =
        EventFd::with_flags(0, EventFdFlags::NONBLOCK | EventFdFlags::CLOEXEC).expect("eventfd2");
    let _ = efd.fd();
}

#[cfg(not(miri))]
#[test]
fn eventfd_write_and_read() {
    let efd = EventFd::new(0).expect("eventfd2");
    efd.write(42).expect("write");
    let val = efd.read().expect("read");
    assert_eq!(val, 42);
}

#[cfg(not(miri))]
#[test]
fn eventfd_write_accumulates() {
    let efd = EventFd::new(0).expect("eventfd2");
    efd.write(10).expect("write 1");
    efd.write(20).expect("write 2");
    let val = efd.read().expect("read");
    assert_eq!(val, 30);
}

#[cfg(not(miri))]
#[test]
fn eventfd_read_resets_counter() {
    use crate::error::Errno;
    let efd = EventFd::new(0).expect("eventfd2");
    efd.write(5).expect("write");
    let _ = efd.read().expect("read");
    // Counter is now 0 — reading again should return EAGAIN
    let err = efd.read().unwrap_err();
    assert_eq!(err, Error::Syscall(Errno::EAGAIN));
}

#[cfg(not(miri))]
#[test]
fn eventfd_initial_value() {
    let efd = EventFd::new(99).expect("eventfd2");
    let val = efd.read().expect("read");
    assert_eq!(val, 99);
}

#[cfg(not(miri))]
#[test]
fn eventfd_explicit_close() {
    let efd = EventFd::new(0).expect("eventfd2");
    efd.close().expect("close");
}

#[cfg(not(miri))]
#[test]
fn eventfd_semaphore_mode() {
    let efd =
        EventFd::with_flags(0, EventFdFlags::NONBLOCK | EventFdFlags::SEMAPHORE).expect("eventfd2");
    efd.write(3).expect("write");
    // In semaphore mode, each read returns 1 and decrements by 1
    assert_eq!(efd.read().expect("read 1"), 1);
    assert_eq!(efd.read().expect("read 2"), 1);
    assert_eq!(efd.read().expect("read 3"), 1);
    // Counter exhausted
    let err = efd.read().unwrap_err();
    assert_eq!(err, Error::Syscall(crate::error::Errno::EAGAIN));
}

#[cfg(not(miri))]
#[test]
fn eventfd_read_via_io_uring() {
    let efd = EventFd::new(0).expect("eventfd2");
    efd.write(7).expect("write");

    let mut ring = IoUring::new(4).expect("setup");
    let mut buf = [0u8; 8];
    let n = ring.do_read(efd.fd(), &mut buf, 0).expect("do_read");
    assert_eq!(n, 8);
    assert_eq!(u64::from_ne_bytes(buf), 7);
}

#[cfg(not(miri))]
#[test]
fn eventfd_write_via_io_uring() {
    let efd = EventFd::new(0).expect("eventfd2");

    let mut ring = IoUring::new(4).expect("setup");
    let val: u64 = 42;
    let buf = val.to_ne_bytes();
    let n = ring.do_write(efd.fd(), &buf, 0).expect("do_write");
    assert_eq!(n, 8);

    // Verify the counter was updated
    let counter = efd.read().expect("read");
    assert_eq!(counter, 42);
}

// ---------------------------------------------------------------
// Layout tests for new structs — run under Miri.
// ---------------------------------------------------------------

#[test]
fn open_how_layout() {
    use crate::types::OpenHow;
    assert_eq!(mem::size_of::<OpenHow>(), 24);
    assert_eq!(mem::align_of::<OpenHow>(), 8);
    assert_eq!(mem::offset_of!(OpenHow, flags), 0);
    assert_eq!(mem::offset_of!(OpenHow, mode), 8);
    assert_eq!(mem::offset_of!(OpenHow, resolve), 16);
}

#[test]
fn epoll_event_layout() {
    use crate::types::EpollEvent;
    assert_eq!(mem::offset_of!(EpollEvent, events), 0);

    #[cfg(target_arch = "x86_64")]
    {
        assert_eq!(mem::size_of::<EpollEvent>(), 12);
        assert_eq!(mem::align_of::<EpollEvent>(), 1);
        assert_eq!(mem::offset_of!(EpollEvent, data), 4);
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        assert_eq!(mem::size_of::<EpollEvent>(), 16);
        assert_eq!(mem::align_of::<EpollEvent>(), 8);
        assert_eq!(mem::offset_of!(EpollEvent, data), 8);
    }
}

#[test]
fn io_uring_files_update_layout() {
    use crate::types::IoUringFilesUpdate;
    assert_eq!(mem::size_of::<IoUringFilesUpdate>(), 16);
    assert_eq!(mem::align_of::<IoUringFilesUpdate>(), 8);
    assert_eq!(mem::offset_of!(IoUringFilesUpdate, offset), 0);
    assert_eq!(mem::offset_of!(IoUringFilesUpdate, resv), 4);
    assert_eq!(mem::offset_of!(IoUringFilesUpdate, fds), 8);
}

#[test]
fn io_uring_rsrc_register_layout_matches_the_kernel_struct() {
    use crate::types::IoUringRsrcRegister;
    assert_eq!(mem::size_of::<IoUringRsrcRegister>(), 32);
    assert_eq!(mem::align_of::<IoUringRsrcRegister>(), 8);
    assert_eq!(mem::offset_of!(IoUringRsrcRegister, nr), 0);
    assert_eq!(mem::offset_of!(IoUringRsrcRegister, flags), 4);
    assert_eq!(mem::offset_of!(IoUringRsrcRegister, resv2), 8);
    assert_eq!(mem::offset_of!(IoUringRsrcRegister, data), 16);
    assert_eq!(mem::offset_of!(IoUringRsrcRegister, tags), 24);
}

#[test]
fn io_uring_rsrc_update2_layout_matches_the_kernel_struct() {
    use crate::types::IoUringRsrcUpdate2;
    assert_eq!(mem::size_of::<IoUringRsrcUpdate2>(), 32);
    assert_eq!(mem::align_of::<IoUringRsrcUpdate2>(), 8);
    assert_eq!(mem::offset_of!(IoUringRsrcUpdate2, offset), 0);
    assert_eq!(mem::offset_of!(IoUringRsrcUpdate2, resv), 4);
    assert_eq!(mem::offset_of!(IoUringRsrcUpdate2, data), 8);
    assert_eq!(mem::offset_of!(IoUringRsrcUpdate2, tags), 16);
    assert_eq!(mem::offset_of!(IoUringRsrcUpdate2, nr), 24);
    assert_eq!(mem::offset_of!(IoUringRsrcUpdate2, resv2), 28);
}

#[test]
fn io_uring_clone_buffers_layout_matches_the_kernel_struct() {
    use crate::types::IoUringCloneBuffers;
    assert_eq!(mem::size_of::<IoUringCloneBuffers>(), 32);
    assert_eq!(mem::align_of::<IoUringCloneBuffers>(), 4);
    assert_eq!(mem::offset_of!(IoUringCloneBuffers, src_fd), 0);
    assert_eq!(mem::offset_of!(IoUringCloneBuffers, flags), 4);
    assert_eq!(mem::offset_of!(IoUringCloneBuffers, src_off), 8);
    assert_eq!(mem::offset_of!(IoUringCloneBuffers, dst_off), 12);
    assert_eq!(mem::offset_of!(IoUringCloneBuffers, nr), 16);
    assert_eq!(mem::offset_of!(IoUringCloneBuffers, pad), 20);
}

// ---------------------------------------------------------------
// SQE builder field-placement tests for new ops — run under Miri.
// ---------------------------------------------------------------

#[test]
fn sqe_builder_splice_places_fields_correctly() {
    use crate::types::{Opcode, SpliceFlags};
    let sqe = Sqe::splice(
        RawFd::from_raw(7),
        100,
        RawFd::from_raw(3),
        200,
        4096,
        SpliceFlags::MORE,
    )
    .user_data(55);
    let inner = sqe.0;
    assert_eq!(Opcode::Splice, inner.opcode);
    assert_eq!(inner.fd, 7); // fd_out
    assert_eq!(inner.off, 100); // off_out
    assert_eq!(inner.splice_fd_in, 3); // fd_in
    assert_eq!(inner.addr, 200); // off_in
    assert_eq!(inner.len, 4096);
    assert_eq!(inner.op_flags, SpliceFlags::MORE.bits());
    assert_eq!(inner.user_data, 55);
}

#[test]
fn sqe_builder_tee_places_fields_correctly() {
    use crate::types::{Opcode, SpliceFlags};
    let sqe = Sqe::tee(
        RawFd::from_raw(5),
        RawFd::from_raw(3),
        8192,
        SpliceFlags::NONBLOCK,
    )
    .user_data(77);
    let inner = sqe.0;
    assert_eq!(Opcode::Tee, inner.opcode);
    assert_eq!(inner.fd, 5); // fd_out
    assert_eq!(inner.splice_fd_in, 3); // fd_in
    assert_eq!(inner.len, 8192);
    assert_eq!(inner.op_flags, SpliceFlags::NONBLOCK.bits());
    assert_eq!(inner.user_data, 77);
}

#[test]
fn sqe_builder_epoll_ctl_places_fields_correctly() {
    use crate::types::{EpollEvent, EpollEvents, EpollOp, Opcode};
    let event = EpollEvent {
        events: EpollEvents::IN.bits(),
        data: 42,
    };
    let sqe =
        unsafe { Sqe::epoll_ctl(RawFd::from_raw(9), EpollOp::Add, RawFd::from_raw(4), &event) }
            .user_data(88);
    let inner = sqe.0;
    assert_eq!(Opcode::EpollCtl, inner.opcode);
    assert_eq!(inner.fd, 9); // epfd
    assert_eq!(inner.off, 4); // target fd
    assert_eq!(inner.addr, (&raw const event) as u64);
    assert_eq!(inner.len, EpollOp::Add as u32);
    assert_eq!(inner.user_data, 88);
}

#[test]
fn sqe_builder_epoll_wait_places_fields_correctly() {
    use crate::types::EpollEvent;
    let mut events = [EpollEvent::default(); 4];
    let addr = events.as_mut_ptr() as u64;
    let sqe = unsafe { Sqe::epoll_wait(RawFd::from_raw(9), &mut events) }.user_data(88);
    let inner = sqe.0;
    assert_eq!(Opcode::EpollWait, inner.opcode);
    assert_eq!(inner.fd, 9);
    assert_eq!(inner.addr, addr);
    assert_eq!(inner.len, 4);
    assert_eq!(inner.user_data, 88);
}

#[test]
fn sqe_builder_fadvise_places_fields_correctly() {
    use crate::types::{FadviseAdvice, Opcode};
    let sqe = Sqe::fadvise(RawFd::from_raw(3), 0, 4096, FadviseAdvice::Sequential).user_data(11);
    let inner = sqe.0;
    assert_eq!(Opcode::Fadvise, inner.opcode);
    assert_eq!(inner.fd, 3);
    assert_eq!(inner.off, 0);
    assert_eq!(inner.len, 4096);
    assert_eq!(inner.op_flags, FadviseAdvice::Sequential as u32);
    assert_eq!(inner.user_data, 11);
}

#[test]
fn sqe_builder_openat2_places_fields_correctly() {
    use crate::types::{Opcode, OpenHow};
    let how = OpenHow {
        flags: 2,
        mode: 0o644,
        resolve: 0,
    };
    let path = c"/tmp/x";
    let sqe = unsafe { Sqe::openat2(types::AT_FDCWD, path, &how) }.user_data(99);
    let inner = sqe.0;
    assert_eq!(Opcode::Openat2, inner.opcode);
    assert_eq!(inner.fd, types::AT_FDCWD);
    assert_eq!(inner.addr, path.as_ptr() as u64);
    assert_eq!(inner.off, (&raw const how) as u64);
    assert_eq!(inner.len as usize, mem::size_of::<OpenHow>());
    assert_eq!(inner.user_data, 99);
}

#[test]
fn sqe_builder_send_zc_places_fields_correctly() {
    use crate::types::{MsgFlags, Opcode};
    let buf = b"zero copy!";
    let sqe = unsafe { Sqe::send_zc(RawFd::from_raw(5), buf, MsgFlags::NOSIGNAL) }.user_data(66);
    let inner = sqe.0;
    assert_eq!(Opcode::SendZc, inner.opcode);
    assert_eq!(inner.fd, 5);
    assert_eq!(inner.addr, buf.as_ptr() as u64);
    assert_eq!(inner.len, buf.len() as u32);
    assert_eq!(inner.op_flags, MsgFlags::NOSIGNAL.bits());
    assert_eq!(inner.user_data, 66);
}

#[test]
fn sqe_builder_sendmsg_zc_places_fields_correctly() {
    use crate::types::{MsgFlags, MsgHdr, Opcode};
    let hdr = MsgHdr::default();
    let sqe =
        unsafe { Sqe::sendmsg_zc(RawFd::from_raw(7), &hdr, MsgFlags::NOSIGNAL) }.user_data(67);
    let inner = sqe.0;
    assert_eq!(Opcode::SendmsgZc, inner.opcode);
    assert_eq!(inner.fd, 7);
    assert_eq!(inner.addr, (&raw const hdr) as u64);
    assert_eq!(inner.len, 1);
    assert_eq!(inner.op_flags, MsgFlags::NOSIGNAL.bits());
    assert_eq!(inner.user_data, 67);
}

#[test]
fn sqe_builder_files_update_places_fields_correctly() {
    use crate::types::Opcode;
    let fds = [3i32, 4, -1];
    let sqe = unsafe { Sqe::files_update(&fds, 2) }.user_data(44);
    let inner = sqe.0;
    assert_eq!(Opcode::FilesUpdate, inner.opcode);
    assert_eq!(inner.addr, fds.as_ptr() as u64);
    assert_eq!(inner.len, 3);
    assert_eq!(inner.off, 2);
    assert_eq!(inner.user_data, 44);
}

#[test]
fn sqe_builder_provide_buffers_places_fields_correctly() {
    use crate::types::Opcode;
    let mut buf = [0u8; 256];
    let sqe = unsafe { Sqe::provide_buffers(buf.as_mut_ptr(), 64, 4, 1, 0) }.user_data(33);
    let inner = sqe.0;
    assert_eq!(Opcode::ProvideBuffers, inner.opcode);
    assert_eq!(inner.fd, 4); // count as i32
    assert_eq!(inner.addr, buf.as_ptr() as u64);
    assert_eq!(inner.len, 64); // buf_size
    assert_eq!(inner.off, 0); // buf_id (starting bid)
    assert_eq!(inner.buf_index, 1); // bgid
    assert_eq!(inner.user_data, 33);
}

#[test]
fn sqe_builder_remove_buffers_places_fields_correctly() {
    use crate::types::Opcode;
    let sqe = Sqe::remove_buffers(3, 1).user_data(22);
    let inner = sqe.0;
    assert_eq!(Opcode::RemoveBuffers, inner.opcode);
    assert_eq!(inner.fd, 3); // count
    assert_eq!(inner.buf_index, 1); // bgid
    assert_eq!(inner.user_data, 22);
}

#[test]
fn sqe_modifier_cqe_skip_success() {
    use crate::types::SqeFlags;
    let sqe = Sqe::nop().cqe_skip_success();
    assert_eq!(
        sqe.0.flags & SqeFlags::CQE_SKIP_SUCCESS.bits(),
        SqeFlags::CQE_SKIP_SUCCESS.bits()
    );
}

#[test]
fn sqe_builder_accept_multishot_places_fields_correctly() {
    use crate::types::{AcceptFlags, IORING_ACCEPT_MULTISHOT, Opcode};
    let sqe = Sqe::accept_multishot(RawFd::from_raw(7), AcceptFlags::NONBLOCK).user_data(5);
    let inner = sqe.0;
    assert_eq!(Opcode::Accept, inner.opcode);
    assert_eq!(inner.fd, 7);
    assert_eq!(inner.ioprio, IORING_ACCEPT_MULTISHOT);
    assert_eq!(inner.op_flags, AcceptFlags::NONBLOCK.bits());
}

#[test]
fn sqe_builder_with_accept_sets_dontwait_and_poll_first_bits() {
    use crate::types::{
        AcceptFlags, AcceptModifier, IORING_ACCEPT_DONTWAIT, IORING_ACCEPT_POLL_FIRST, Opcode,
    };
    let sqe = Sqe::accept(RawFd::from_raw(4), AcceptFlags::default())
        .with_accept(AcceptModifier::DontWait)
        .with_accept(AcceptModifier::PollFirst)
        .user_data(9);
    let inner = sqe.0;
    assert_eq!(Opcode::Accept, inner.opcode);
    assert_eq!(inner.fd, 4);
    assert_eq!(
        inner.ioprio & IORING_ACCEPT_DONTWAIT,
        IORING_ACCEPT_DONTWAIT
    );
    assert_eq!(
        inner.ioprio & IORING_ACCEPT_POLL_FIRST,
        IORING_ACCEPT_POLL_FIRST
    );
}

#[test]
fn sqe_builder_accept_multishot_direct_sets_file_index_alloc() {
    use crate::types::{AcceptFlags, IORING_ACCEPT_MULTISHOT, Opcode};
    let sqe = Sqe::accept_multishot_direct(RawFd::from_raw(7), AcceptFlags::default()).user_data(5);
    let inner = sqe.0;
    assert_eq!(Opcode::Accept, inner.opcode);
    assert_eq!(inner.fd, 7);
    assert_eq!(inner.ioprio, IORING_ACCEPT_MULTISHOT);
    // IORING_FILE_INDEX_ALLOC: the kernel reads `file_index` (aliasing
    // `splice_fd_in`) as ~0u32 and allocates a slot per connection. Zero
    // here means "not a direct request", which turns this back into an
    // ordinary accept that installs process descriptors.
    assert_eq!(inner.splice_fd_in, -1);

    // The non-direct variant must leave it clear.
    let plain = Sqe::accept_multishot(RawFd::from_raw(7), AcceptFlags::default());
    assert_eq!(plain.0.splice_fd_in, 0);
}

#[test]
fn sqe_builder_recv_multishot_places_fields_correctly() {
    use crate::types::{IORING_RECV_MULTISHOT, MsgFlags, Opcode};
    let sqe = Sqe::recv_multishot(RawFd::from_raw(4), MsgFlags::default()).user_data(6);
    let inner = sqe.0;
    assert_eq!(Opcode::Recv, inner.opcode);
    assert_eq!(inner.fd, 4);
    // Multishot bit must be in `ioprio`, NOT `op_flags`. Putting it in
    // `op_flags` would alias `MSG_PEEK` (0x2) on recv and silently turn
    // every multishot recv into a peek that doesn't consume data.
    assert_eq!(inner.ioprio & IORING_RECV_MULTISHOT, IORING_RECV_MULTISHOT);
    assert_eq!(inner.op_flags, MsgFlags::default().bits());
}

#[test]
fn sqe_builder_read_multishot_places_fields_correctly() {
    use crate::types::Opcode;
    let sqe = Sqe::read_multishot(RawFd::from_raw(5), 0, 9).user_data(3);
    let inner = sqe.0;
    assert_eq!(Opcode::ReadMultishot, inner.opcode);
    assert_eq!(inner.fd, 5);
    assert_eq!(inner.off, 0);
    // `read_multishot` must select a buffer itself, unlike `recv_multishot`
    // which puts the multishot bit in `ioprio` — this is a distinct
    // opcode, so there is no bit to set, only `IOSQE_BUFFER_SELECT` and
    // the group id.
    assert_eq!(
        inner.flags & SqeFlags::BUFFER_SELECT.bits(),
        SqeFlags::BUFFER_SELECT.bits()
    );
    assert_eq!(inner.buf_index, 9);
    assert_eq!(
        inner.len, 0,
        "nbytes must be zero: the pool buffer's size governs the transfer"
    );
}

#[test]
fn sqe_builder_with_poll_first_sets_ioprio_bit() {
    use crate::types::{IORING_RECVSEND_POLL_FIRST, MsgFlags, Opcode, SendRecvFlag};
    let buf = [0u8; 4];
    let sqe = unsafe { Sqe::send(RawFd::from_raw(9), &buf, MsgFlags::default()) }
        .with(SendRecvFlag::PollFirst);
    let inner = sqe.0;
    assert_eq!(Opcode::Send, inner.opcode);
    assert_eq!(inner.fd, 9);
    assert_eq!(
        inner.ioprio & IORING_RECVSEND_POLL_FIRST,
        IORING_RECVSEND_POLL_FIRST
    );
}

#[test]
fn sqe_builder_with_fixed_buf_sets_ioprio_and_index() {
    use crate::types::{IORING_RECVSEND_FIXED_BUF, MsgFlags, SendRecvFlag};
    let buf = [0u8; 4];
    let sqe = unsafe { Sqe::send(RawFd::from_raw(3), &buf, MsgFlags::default()) }
        .with(SendRecvFlag::FixedBuf(7));
    let inner = sqe.0;
    assert_eq!(
        inner.ioprio & IORING_RECVSEND_FIXED_BUF,
        IORING_RECVSEND_FIXED_BUF
    );
    assert_eq!(inner.buf_index, 7);
}

#[test]
fn sqe_builder_with_report_usage_sets_ioprio_bit() {
    use crate::types::{IORING_SEND_ZC_REPORT_USAGE, MsgFlags, Opcode, SendRecvFlag};
    let buf = [0u8; 4];
    let sqe = unsafe { Sqe::send_zc(RawFd::from_raw(2), &buf, MsgFlags::default()) }
        .with(SendRecvFlag::ReportUsage);
    let inner = sqe.0;
    assert_eq!(Opcode::SendZc, inner.opcode);
    assert_eq!(
        inner.ioprio & IORING_SEND_ZC_REPORT_USAGE,
        IORING_SEND_ZC_REPORT_USAGE
    );
}

#[test]
fn sqe_builder_with_bundle_sets_ioprio_bit() {
    use crate::types::{IORING_RECVSEND_BUNDLE, MsgFlags, Opcode, SendRecvFlag};
    let sqe =
        Sqe::recv_multishot(RawFd::from_raw(4), MsgFlags::default()).with(SendRecvFlag::Bundle);
    let inner = sqe.0;
    assert_eq!(Opcode::Recv, inner.opcode);
    assert_eq!(
        inner.ioprio & IORING_RECVSEND_BUNDLE,
        IORING_RECVSEND_BUNDLE
    );
}

#[test]
fn sqe_builder_with_vectorized_sets_ioprio_bit() {
    use crate::types::{IORING_SEND_VECTORIZED, MsgFlags, Opcode, SendRecvFlag};
    let buf = [0u8; 4];
    let sqe = unsafe { Sqe::send_zc(RawFd::from_raw(6), &buf, MsgFlags::default()) }
        .with(SendRecvFlag::Vectorized);
    let inner = sqe.0;
    assert_eq!(Opcode::SendZc, inner.opcode);
    assert_eq!(
        inner.ioprio & IORING_SEND_VECTORIZED,
        IORING_SEND_VECTORIZED
    );
}

#[test]
fn sqe_builder_with_chains_multiple_flags() {
    use crate::types::{
        IORING_RECVSEND_FIXED_BUF, IORING_RECVSEND_POLL_FIRST, MsgFlags, SendRecvFlag,
    };
    let buf = [0u8; 4];
    let sqe = unsafe { Sqe::send(RawFd::from_raw(5), &buf, MsgFlags::default()) }
        .with(SendRecvFlag::PollFirst)
        .with(SendRecvFlag::FixedBuf(3));
    let inner = sqe.0;
    let expected = IORING_RECVSEND_POLL_FIRST | IORING_RECVSEND_FIXED_BUF;
    assert_eq!(inner.ioprio & expected, expected);
    assert_eq!(inner.buf_index, 3);
}

#[test]
fn sqe_builder_personality_sets_field() {
    use crate::types::MsgFlags;
    let buf = [0u8; 4];
    let sqe = unsafe { Sqe::send(RawFd::from_raw(1), &buf, MsgFlags::default()) }.personality(42);
    assert_eq!(sqe.0.personality, 42);
}

#[test]
fn sqe_builder_recvmsg_multishot_places_fields_correctly() {
    use crate::types::{IORING_RECV_MULTISHOT, MsgFlags, MsgHdr, Opcode};
    let mut msg = MsgHdr::default();
    let sqe = unsafe {
        Sqe::recvmsg_multishot(
            RawFd::from_raw(11),
            core::ptr::from_mut(&mut msg),
            MsgFlags::default(),
        )
    };
    let inner = sqe.0;
    assert_eq!(Opcode::RecvMsg, inner.opcode);
    assert_eq!(inner.fd, 11);
    assert_eq!(inner.len, 1);
    // Multishot bit must be in `ioprio`, NOT `op_flags`. Same MSG_PEEK
    // alias hazard as `recv_multishot`.
    assert_eq!(inner.ioprio & IORING_RECV_MULTISHOT, IORING_RECV_MULTISHOT);
    assert_eq!(inner.op_flags, MsgFlags::default().bits());
}

#[test]
fn sqe_builder_socket_places_fields_correctly() {
    use crate::types::{AddressFamily, Opcode, SocketFlags, SocketType};
    let sqe = Sqe::socket(
        AddressFamily::Inet,
        SocketType::Stream,
        0,
        SocketFlags::NONBLOCK,
    );
    let inner = sqe.0;
    assert_eq!(Opcode::Socket, inner.opcode);
    assert_eq!(inner.fd, AddressFamily::Inet.as_raw());
    // The flags ride in the type field, as socket(2) expects.
    assert_eq!(
        inner.off,
        u64::from(SocketType::Stream.as_raw() as u32 | SocketFlags::NONBLOCK.bits())
    );
    // rw_flags must be zero or the kernel rejects the request outright.
    assert_eq!(inner.op_flags, 0);
    // Plain socket op does NOT set splice_fd_in.
    assert_eq!(inner.splice_fd_in, 0);
}

#[test]
fn sqe_builder_socket_direct_sets_file_index_alloc() {
    use crate::types::{AddressFamily, Opcode, SocketFlags, SocketType};
    let sqe = Sqe::socket_direct(
        AddressFamily::Inet,
        SocketType::Stream,
        0,
        SocketFlags::NONBLOCK,
    );
    let inner = sqe.0;
    assert_eq!(Opcode::Socket, inner.opcode);
    assert_eq!(inner.fd, AddressFamily::Inet.as_raw());
    assert_eq!(
        inner.off,
        u64::from(SocketType::Stream.as_raw() as u32 | SocketFlags::NONBLOCK.bits())
    );
    assert_eq!(inner.op_flags, 0);
    // IORING_FILE_INDEX_ALLOC: kernel reads splice_fd_in as ~0u32.
    assert_eq!(inner.splice_fd_in, -1);
}

#[test]
fn sqe_builder_bind_places_the_length_in_addr2() {
    use crate::types::Opcode;
    let addr = [0u8; 16];
    let sqe = unsafe { Sqe::bind(RawFd::from_raw(7), &addr) };
    let inner = sqe.0;
    assert_eq!(Opcode::Bind, inner.opcode);
    assert_eq!(inner.fd, 7);
    assert_eq!(inner.addr, addr.as_ptr() as u64);
    // The kernel reads the length from addr2 (aliased by `off`), and
    // rejects the request outright if any of these carry a value.
    assert_eq!(inner.off, 16);
    assert_eq!(inner.len, 0);
    assert_eq!(inner.op_flags, 0);
    assert_eq!(inner.buf_index, 0);
    assert_eq!(inner.splice_fd_in, 0);
}

#[test]
fn sqe_builder_listen_carries_only_a_backlog() {
    use crate::types::Opcode;
    let sqe = Sqe::listen(RawFd::from_raw(7), 128);
    let inner = sqe.0;
    assert_eq!(Opcode::Listen, inner.opcode);
    assert_eq!(inner.fd, 7);
    assert_eq!(inner.len, 128);
    // `listen` reads no caller memory; a stray addr is an EINVAL.
    assert_eq!(inner.addr, 0);
    assert_eq!(inner.off, 0);
    assert_eq!(inner.op_flags, 0);
    assert_eq!(inner.buf_index, 0);
    assert_eq!(inner.splice_fd_in, 0);
}

#[cfg(not(miri))]
#[test]
fn a_bound_listener_accepts_a_real_connection() {
    use crate::types::{AddressFamily, SocketFlags, SocketType};
    // Asserting the CQE is 0 proves only that the kernel accepted the
    // encoding. A bind to the wrong address, or a listen the kernel
    // ignored, would report 0 just the same. The effect worth checking is
    // that the socket is reachable at the port we asked for, so this
    // reads the bound address back and connects to it.
    let mut ring = crate::IoUring::new(8).expect("ring");
    let listener = crate::net::Socket::with_typed_flags(
        AddressFamily::Inet,
        SocketType::Stream,
        0,
        SocketFlags::default(),
    )
    .expect("socket");

    let addr = SockAddrIn {
        sin_family: types::AF_INET as u16,
        sin_port: 0,
        sin_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        sin_zero: [0; 8],
    }
    .to_bytes();

    ring.push(unsafe { Sqe::bind(listener.fd(), &addr) }.user_data(1))
        .expect("push bind");
    ring.submit_and_wait(1).expect("submit");
    assert_eq!(ring.complete().expect("cqe").result, 0, "bind");

    ring.push(Sqe::listen(listener.fd(), 8).user_data(2))
        .expect("push listen");
    ring.submit_and_wait(1).expect("submit");
    assert_eq!(ring.complete().expect("cqe").result, 0, "listen");

    let port = u16::from_be(listener.local_addr().expect("getsockname").sin_port);
    assert_ne!(port, 0, "bind must have assigned an ephemeral port");

    let client = syscall::socket(types::AF_INET, types::SOCK_STREAM | types::SOCK_NONBLOCK, 0)
        .expect("client socket")
        .as_i32();
    let server = tcp_handshake(&mut ring, listener.fd().as_i32(), client, port);

    let _ = syscall::close(RawFd::from_raw(server as usize));
    let _ = syscall::close(RawFd::from_raw(client as usize));
}

#[cfg(not(miri))]
#[test]
fn an_accept_with_dontwait_reports_eagain_rather_than_waiting() {
    use crate::types::AcceptModifier;
    // With no connection pending, DontWait must complete at once with
    // -EAGAIN instead of arming poll or handing the request to io-wq to
    // block until a peer connects — exactly the non-blocking accept4(2)
    // contract, driven through the ring instead of a blocking syscall.
    let mut ring = crate::IoUring::new(8).expect("ring");
    let (listener, _port) = setup_tcp_listener();

    ring.push(
        Sqe::accept(RawFd::from_raw(listener as usize), AcceptFlags::default())
            .with_accept(AcceptModifier::DontWait)
            .user_data(1),
    )
    .expect("push accept");
    ring.submit_and_wait(1).expect("submit");
    let result = ring.complete().expect("cqe").result;
    assert_eq!(result, -11, "expected -EAGAIN, got {result}");

    let _ = syscall::close(RawFd::from_raw(listener as usize));
}

#[cfg(not(miri))]
#[test]
fn an_accept_with_poll_first_still_accepts_a_real_connection() {
    use crate::types::AcceptModifier;
    // PollFirst only changes how the kernel waits (poll registration up
    // front instead of a blocking io-wq worker); it must not change the
    // outcome — a real pending connection is still accepted normally.
    let mut ring = crate::IoUring::new(8).expect("ring");
    let (listener, port) = setup_tcp_listener();

    let client = syscall::socket(types::AF_INET, types::SOCK_STREAM | types::SOCK_NONBLOCK, 0)
        .expect("client socket")
        .as_i32();

    ring.push(
        Sqe::accept(RawFd::from_raw(listener as usize), AcceptFlags::default())
            .with_accept(AcceptModifier::PollFirst)
            .user_data(1),
    )
    .expect("push accept");

    let connect_addr = SockAddrIn {
        sin_family: types::AF_INET as u16,
        sin_port: port.to_be(),
        sin_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        sin_zero: [0; 8],
    };
    let addr_bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(
            (&raw const connect_addr).cast(),
            core::mem::size_of::<SockAddrIn>(),
        )
    };
    ring.push(unsafe { Sqe::connect(RawFd::from_raw(client as usize), addr_bytes) }.user_data(2))
        .expect("push connect");
    ring.submit_and_wait(2).expect("submit handshake");

    let mut server_fd = -1i32;
    for _ in 0..2 {
        let cqe = ring.complete().expect("handshake cqe");
        if cqe.user_data == 1 {
            assert!(cqe.result >= 0, "accept failed: {}", cqe.result);
            server_fd = cqe.result;
        } else {
            assert!(
                cqe.result == 0 || cqe.result == -115,
                "connect failed: {}",
                cqe.result
            );
        }
    }
    assert!(server_fd >= 0, "never got accept completion");

    let _ = syscall::close(RawFd::from_raw(server_fd as usize));
    let _ = syscall::close(RawFd::from_raw(client as usize));
    let _ = syscall::close(RawFd::from_raw(listener as usize));
}

#[cfg(not(miri))]
#[test]
fn a_listen_backlog_the_kernel_clamps_is_not_an_error() {
    use crate::types::{AddressFamily, SocketFlags, SocketType};
    // Both ends of the range are silently clamped rather than rejected,
    // so neither needs guarding at construction.
    let mut ring = crate::IoUring::new(8).expect("ring");
    for backlog in [0, u32::MAX] {
        let sock = crate::net::Socket::with_typed_flags(
            AddressFamily::Inet,
            SocketType::Stream,
            0,
            SocketFlags::default(),
        )
        .expect("socket");
        ring.push(Sqe::listen(sock.fd(), backlog).user_data(1))
            .expect("push");
        ring.submit_and_wait(1).expect("submit");
        let res = ring.complete().expect("cqe").result;
        assert_eq!(res, 0, "listen({backlog}) should be clamped, not rejected");
    }
}

#[cfg(not(miri))]
#[test]
fn a_second_bind_and_a_taken_port_report_different_errors() {
    use crate::types::{AddressFamily, SocketFlags, SocketType};
    // Rebinding a socket that is already bound is EINVAL; binding a port
    // another socket holds is EADDRINUSE. Collapsing the two would tell a
    // caller to retry a different port when the real fault is their own
    // duplicate bind.
    let mut ring = crate::IoUring::new(8).expect("ring");
    let make = || {
        crate::net::Socket::with_typed_flags(
            AddressFamily::Inet,
            SocketType::Stream,
            0,
            SocketFlags::default(),
        )
        .expect("socket")
    };
    let bind = |ring: &mut crate::IoUring, fd, bytes: &[u8; 16]| {
        ring.push(unsafe { Sqe::bind(fd, bytes) }.user_data(1))
            .expect("push");
        ring.submit_and_wait(1).expect("submit");
        ring.complete().expect("cqe").result
    };

    let first = make();
    let addr = SockAddrIn {
        sin_family: types::AF_INET as u16,
        sin_port: 0,
        sin_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        sin_zero: [0; 8],
    }
    .to_bytes();
    assert_eq!(bind(&mut ring, first.fd(), &addr), 0);

    assert_eq!(
        bind(&mut ring, first.fd(), &addr),
        -22,
        "rebinding a bound socket is EINVAL"
    );

    let taken = SockAddrIn {
        sin_family: types::AF_INET as u16,
        sin_port: first.local_addr().expect("getsockname").sin_port,
        sin_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        sin_zero: [0; 8],
    }
    .to_bytes();
    let second = make();
    assert_eq!(
        bind(&mut ring, second.fd(), &taken),
        -98,
        "a port another socket holds is EADDRINUSE"
    );
}

#[cfg(not(miri))]
#[test]
fn a_malformed_bind_address_is_refused_by_the_kernel() {
    use crate::types::{AddressFamily, SocketFlags, SocketType};
    let mut ring = crate::IoUring::new(8).expect("ring");
    let sock = crate::net::Socket::with_typed_flags(
        AddressFamily::Inet,
        SocketType::Stream,
        0,
        SocketFlags::default(),
    )
    .expect("socket");
    let addr = [0u8; 16];

    ring.push(unsafe { Sqe::bind_ptr(sock.fd(), addr.as_ptr(), 0) }.user_data(1))
        .expect("push");
    ring.submit_and_wait(1).expect("submit");
    assert_eq!(
        ring.complete().expect("cqe").result,
        -22,
        "a zero-length address is EINVAL"
    );

    ring.push(unsafe { Sqe::bind_ptr(sock.fd(), core::ptr::null(), 16) }.user_data(2))
        .expect("push");
    ring.submit_and_wait(1).expect("submit");
    assert_eq!(
        ring.complete().expect("cqe").result,
        -14,
        "a null address is EFAULT"
    );
}

#[cfg(not(miri))]
#[test]
fn a_socket_sqe_with_flags_is_accepted_by_the_kernel() {
    use crate::types::{AddressFamily, SocketFlags, SocketType};
    // The field-placement tests above cannot catch a wrong field: they
    // assert the encoding the builder produces, whatever it is. An earlier
    // version put these flags in rw_flags, which the kernel requires to be
    // zero, so every socket op with a non-default flag failed with EINVAL
    // while both unit tests passed. Only submitting it says otherwise.
    let mut ring = crate::IoUring::new(4).expect("ring");
    for flags in [
        SocketFlags::default(),
        SocketFlags::NONBLOCK,
        SocketFlags::CLOEXEC,
        SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
    ] {
        ring.push(Sqe::socket(AddressFamily::Inet, SocketType::Stream, 0, flags).user_data(1))
            .expect("push");
        ring.submit_and_wait(1).expect("submit");
        let res = ring.complete().expect("cqe").result;
        assert!(res >= 0, "socket with flags {flags:?} failed: {res}");
        let _ = syscall::close(RawFd::from_raw(res as usize));
    }
}

#[cfg(not(miri))]
#[test]
fn sqe_builder_uring_cmd_sock_inq_places_cmd_op_and_fd() {
    let sqe = Sqe::uring_cmd_sock_inq(RawFd::from_raw(11)).user_data(1);
    let inner = sqe.0;

    assert_eq!(Opcode::UringCmd, inner.opcode);
    assert_eq!(inner.fd, 11);
    assert_eq!(
        inner.cmd_op(),
        u32::from(crate::types::SocketUringCmdOp::SiocInq)
    );
}

#[cfg(not(miri))]
#[test]
fn a_real_siocinq_via_uring_cmd_reports_bytes_a_send_queued() {
    let mut ring = IoUring::new(8).expect("setup");
    let (listener, port) = setup_tcp_listener();
    let client = syscall::socket(types::AF_INET, types::SOCK_STREAM | types::SOCK_NONBLOCK, 0)
        .expect("client socket")
        .as_i32();
    let server_fd = tcp_handshake(&mut ring, listener, client, port);

    let payload = b"hello";
    ring.push(unsafe { Sqe::write(RawFd::from_raw(client as usize), payload, 0) }.user_data(1))
        .expect("push write");
    ring.submit_and_wait(1).expect("submit write");
    let cqe = ring.complete().expect("write cqe");
    assert_eq!(cqe.result, payload.len() as i32);

    ring.push(Sqe::uring_cmd_sock_inq(RawFd::from_raw(server_fd as usize)).user_data(2))
        .expect("push siocinq");
    ring.submit_and_wait(1).expect("submit siocinq");
    let cqe = ring.complete().expect("siocinq cqe");

    if cqe.result != -95 {
        assert_eq!(
            cqe.result,
            payload.len() as i32,
            "SIOCINQ should report the bytes the client just sent"
        );
    }

    let _ = syscall::close(RawFd::from_raw(server_fd as usize));
    let _ = syscall::close(RawFd::from_raw(client as usize));
    let _ = syscall::close(RawFd::from_raw(listener as usize));
}

#[cfg(not(miri))]
#[test]
fn sqe_builder_uring_cmd_sock_getsockopt_places_level_optname_optval_and_len() {
    let mut optval = [0u8; 4];
    let sqe = unsafe { Sqe::uring_cmd_sock_getsockopt(RawFd::from_raw(3), 1, 2, &mut optval) };
    let inner = sqe.0;

    assert_eq!(Opcode::UringCmd, inner.opcode);
    assert_eq!(
        inner.cmd_op(),
        u32::from(crate::types::SocketUringCmdOp::GetSockOpt)
    );
    assert_eq!(inner.sock_level(), 1);
    assert_eq!(inner.sock_optname(), 2);
    assert_eq!(inner.sock_optval(), optval.as_ptr() as u64);
    assert_eq!(inner.optlen(), 4);
}

#[cfg(not(miri))]
#[test]
fn a_real_getsockopt_via_uring_cmd_reports_the_same_option_as_the_ordinary_syscall() {
    // SOL_SOCKET=1, SO_TYPE=3 — kernel constants, inlined because they're
    // only needed by this test.
    let rawfd = syscall::socket(types::AF_INET, types::SOCK_STREAM, 0).expect("socket");

    let mut ring = IoUring::new(4).expect("ring");
    let mut optval = [0u8; 4];
    ring.push(unsafe { Sqe::uring_cmd_sock_getsockopt(rawfd, 1, 3, &mut optval) }.user_data(1))
        .expect("push");
    ring.submit_and_wait(1).expect("submit");
    let cqe = ring.complete().expect("cqe");

    match cqe.result {
        // Older kernels (pre-6.3) reject IORING_OP_URING_CMD on a socket fd
        // outright; treat that as a valid environment to tolerate rather
        // than a failure to chase.
        -95 => {}
        result => {
            assert_eq!(result, 4, "expected the 4-byte SO_TYPE option length back");
            let reported = i32::from_ne_bytes(optval);
            assert_eq!(
                reported,
                types::SOCK_STREAM,
                "SO_TYPE should read back SOCK_STREAM"
            );
        }
    }

    let _ = syscall::close(rawfd);
}

#[cfg(not(miri))]
#[test]
fn a_real_setsockopt_via_uring_cmd_changes_a_real_socket_option() {
    // SOL_SOCKET=1, SO_REUSEADDR=2, SO_TYPE=3.
    let rawfd = syscall::socket(types::AF_INET, types::SOCK_STREAM, 0).expect("socket");

    let mut ring = IoUring::new(4).expect("ring");
    let one: i32 = 1;
    let optval = one.to_ne_bytes();
    ring.push(unsafe { Sqe::uring_cmd_sock_setsockopt(rawfd, 1, 2, &optval) }.user_data(1))
        .expect("push");
    ring.submit_and_wait(1).expect("submit");
    let cqe = ring.complete().expect("cqe");

    if cqe.result != -95 {
        assert_eq!(cqe.result, 0, "setsockopt via uring_cmd should succeed");

        // Confirm through the ordinary syscall that the option actually changed.
        let mut readback: i32 = 0;
        let mut len = core::mem::size_of::<i32>() as u32;
        // Safety: `readback`/`len` are live locals, `len` initialized to
        // `readback`'s size.
        unsafe { syscall::getsockopt(rawfd, 1, 2, (&raw mut readback).cast(), &raw mut len) }
            .expect("getsockopt readback");
        assert_eq!(readback, 1, "SO_REUSEADDR should now be set");
    }

    let _ = syscall::close(rawfd);
}

#[cfg(not(miri))]
#[test]
fn a_real_getsockname_via_uring_cmd_reports_the_bound_address() {
    let (listener, port) = setup_tcp_listener();

    let mut ring = IoUring::new(4).expect("ring");
    let mut addr = SockAddrIn::default();
    let mut addr_len = core::mem::size_of::<SockAddrIn>() as i32;
    ring.push(
        unsafe {
            Sqe::uring_cmd_sock_getsockname(
                RawFd::from_raw(listener as usize),
                (&raw mut addr).cast(),
                &raw mut addr_len,
            )
        }
        .user_data(1),
    )
    .expect("push");
    ring.submit_and_wait(1).expect("submit");
    let cqe = ring.complete().expect("cqe");

    if cqe.result != -95 {
        assert_eq!(cqe.result, 0, "getsockname via uring_cmd should succeed");
        assert_eq!(u16::from_be(addr.sin_port), port);
    }

    let _ = syscall::close(RawFd::from_raw(listener as usize));
}

#[cfg(not(miri))]
#[test]
fn a_nonblocking_socket_sqe_really_creates_a_nonblocking_socket() {
    use crate::types::{AddressFamily, SocketFlags, SocketType};
    // Acceptance is not application: a flag the kernel ignored would still
    // give a successful CQE. A non-blocking listener with no pending
    // connection must fail accept4 with EAGAIN rather than block, which is
    // observable without a second thread.
    let mut ring = crate::IoUring::new(4).expect("ring");
    ring.push(
        Sqe::socket(
            AddressFamily::Inet,
            SocketType::Stream,
            0,
            SocketFlags::NONBLOCK,
        )
        .user_data(1),
    )
    .expect("push");
    ring.submit_and_wait(1).expect("submit");
    let res = ring.complete().expect("cqe").result;
    assert!(res >= 0, "socket failed: {res}");
    let fd = RawFd::from_raw(res as usize);

    let addr = SockAddrIn {
        sin_family: types::AF_INET as u16,
        sin_port: 0,
        sin_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        sin_zero: [0; 8],
    };
    // Safety: `addr` is a live local `SockAddrIn`, exactly the size passed.
    unsafe {
        syscall::bind(
            fd,
            (&raw const addr).cast(),
            core::mem::size_of::<SockAddrIn>() as u32,
        )
    }
    .expect("bind");
    syscall::listen(fd, 1).expect("listen");

    let mut peer = SockAddrIn::default();
    let mut len = core::mem::size_of::<SockAddrIn>() as u32;
    // Safety: `peer`/`len` are live locals, `len` initialized to `peer`'s
    // size.
    let outcome = unsafe { syscall::accept4(fd, (&raw mut peer).cast(), &raw mut len, 0) };
    let err = outcome.expect_err("a non-blocking accept4 must not succeed here");
    assert_eq!(err.raw(), 11, "EAGAIN proves the flag was applied");

    let _ = syscall::close(fd);
}

#[test]
fn open_flags_new_bits() {
    use crate::types::OpenFlags;
    // verify none of the new bits overlap each other or existing ones
    let flags = OpenFlags::EXCL
        | OpenFlags::APPEND
        | OpenFlags::NONBLOCK
        | OpenFlags::NOFOLLOW
        | OpenFlags::CLOEXEC
        | OpenFlags::DIRECTORY
        | OpenFlags::PATH;
    // All set bits should be distinct — OR then AND to verify no aliasing
    assert!(flags.bits() != 0);
    // EXCL and CREAT are separate
    assert_ne!(OpenFlags::EXCL.bits(), OpenFlags::CREAT.bits());
    // CLOEXEC value matches O_CLOEXEC on Linux
    assert_eq!(OpenFlags::CLOEXEC.bits(), 0o2_000_000);
}

#[test]
fn setup_flags_new_bits() {
    use crate::types::SetupFlags;
    assert_eq!(SetupFlags::IOPOLL.bits(), 1 << 0);
    assert_eq!(SetupFlags::COOP_TASKRUN.bits(), 1 << 8);
    assert_eq!(SetupFlags::DEFER_TASKRUN.bits(), 1 << 13);
    assert_eq!(SetupFlags::NO_MMAP.bits(), 1 << 14);
    assert_eq!(SetupFlags::NO_SQARRAY.bits(), 1 << 16);
}

#[test]
fn enter_flags_new_bits() {
    use crate::types::EnterFlags;
    assert_eq!(EnterFlags::EXT_ARG.bits(), 1 << 3);
    assert_eq!(EnterFlags::REGISTERED_RING.bits(), 1 << 4);
}

#[test]
fn msg_flags_bits() {
    use crate::types::MsgFlags;
    assert_eq!(MsgFlags::DONTWAIT.bits(), 0x40);
    assert_eq!(MsgFlags::WAITALL.bits(), 0x100);
    assert_eq!(MsgFlags::NOSIGNAL.bits(), 0x4000);
    assert_eq!(MsgFlags::CMSG_CLOEXEC.bits(), 1 << 30);
}

#[test]
fn msg_flags_combine_without_overlap() {
    use crate::types::MsgFlags;
    let combined = MsgFlags::CMSG_CLOEXEC | MsgFlags::DONTWAIT;
    assert_eq!(combined.bits(), 0x4000_0040);
}

#[test]
fn splice_flags_fd_in_fixed() {
    use crate::types::SpliceFlags;
    // High bit of u32
    assert_eq!(SpliceFlags::FD_IN_FIXED.bits(), 1 << 31);
}

#[test]
fn features_new_bits() {
    use crate::types::Features;
    assert_eq!(Features::RSRC_TAGS.bits(), 1 << 10);
    assert_eq!(Features::CQE_SKIP.bits(), 1 << 11);
    assert_eq!(Features::LINKED_FILE.bits(), 1 << 12);
    assert_eq!(Features::REG_REG_RING.bits(), 1 << 13);
    assert_eq!(Features::RECVSEND_BUNDLE.bits(), 1 << 14);
    assert_eq!(Features::MIN_TIMEOUT.bits(), 1 << 15);
}

// ---------------------------------------------------------------
// Kernel integration tests for new ops — skipped under Miri.
// ---------------------------------------------------------------

#[cfg(not(miri))]
#[test]
fn builder_coop_taskrun() {
    let ring = IoUring::builder(4).coop_taskrun().build().expect("setup");
    drop(ring);
}

#[cfg(not(miri))]
#[test]
fn builder_iopoll_sets_the_flag_and_the_kernel_accepts_it() {
    let ring = IoUring::builder(4).iopoll().build().expect("iopoll setup");
    assert!(
        ring.setup_flags()
            .contains(crate::types::SetupFlags::IOPOLL)
    );
    drop(ring);
}

#[cfg(not(miri))]
#[test]
fn builder_defer_taskrun() {
    // DEFER_TASKRUN requires SINGLE_ISSUER on some kernels
    let ring = IoUring::builder(4)
        .defer_taskrun()
        .single_issuer()
        .build()
        .expect("setup");
    drop(ring);
}

#[cfg(not(miri))]
#[test]
fn a_real_iopoll_ring_writes_and_reads_back_through_o_direct() {
    use crate::MmapBuffer;
    use std::os::unix::fs::OpenOptionsExt;

    // IORING_SETUP_IOPOLL only works on files opened O_DIRECT, backed by a
    // block device that supports polling. `std::env::temp_dir()` is tmpfs
    // on most distros, which rejects O_DIRECT outright — anchor the path
    // under the crate's own directory, which this repo checks out onto a
    // real (btrfs) filesystem, instead.
    let dir = env!("CARGO_MANIFEST_DIR");
    let path = UniqueTestPath::new_in(dir, "iopoll");

    // Most non-polled request types — `openat` included — are rejected on an
    // IOPOLL ring (see io_uring_setup(2)): only the small set of opcodes
    // that can actually be polled for completion is allowed. Open the file
    // through a plain syscall and reserve the ring for the pollable
    // read/write this test exercises.
    let file = std::fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .custom_flags(OpenFlags::DIRECT.bits() as i32)
        .open(path.as_str())
        .expect("open with O_DIRECT");
    let fd = {
        use std::os::fd::AsRawFd;
        file.as_raw_fd()
    };

    let mut ring = IoUring::builder(4).iopoll().build().expect("iopoll setup");

    // O_DIRECT imposes alignment restrictions on the buffer address and
    // length that an ordinary heap `Vec` does not satisfy on every
    // filesystem; `MmapBuffer` is page-aligned by construction.
    let mut buf = MmapBuffer::with_capacity(4096).expect("mmap buffer");
    buf.as_mut_slice()[..5].copy_from_slice(b"iouri");

    ring.push(unsafe { Sqe::write(RawFd::from_raw(fd as usize), buf.as_slice(), 0) }.user_data(1))
        .expect("push write");
    ring.submit_and_wait(1).expect("submit write");
    let cqe = ring.complete().expect("write cqe");
    assert_eq!(cqe.user_data, 1);

    // Polling is a property of the block device and driver, not just the
    // kernel API: `-EOPNOTSUPP` here means this machine's storage queue
    // has `/sys/block/*/queue/io_poll` disabled (common under
    // virtualized/sandboxed block devices), not that this crate's IOPOLL
    // plumbing is wrong. Accept either a full pollable round trip or that
    // specific, well-understood rejection, and only fail on anything else.
    if cqe.result == -libc_eopnotsupp() {
        drop(file);
        return;
    }
    assert_eq!(cqe.result, 4096);

    let mut read_buf = MmapBuffer::with_capacity(4096).expect("mmap buffer");
    ring.push(
        unsafe { Sqe::read(RawFd::from_raw(fd as usize), read_buf.as_mut_slice(), 0) }.user_data(2),
    )
    .expect("push read");
    ring.submit_and_wait(1).expect("submit read");
    let cqe = ring.complete().expect("read cqe");
    assert_eq!(cqe.user_data, 2);
    assert_eq!(cqe.result, 4096);
    assert_eq!(&read_buf.as_slice()[..5], b"iouri");

    drop(file);
}

#[cfg(not(miri))]
const fn libc_eopnotsupp() -> i32 {
    95
}

#[cfg(not(miri))]
#[test]
fn a_real_no_mmap_ring_completes_a_nop_with_caller_supplied_memory() {
    // NO_MMAP means the kernel pins pages this crate itself allocated and
    // described in params.sq_off.user_addr/cq_off.user_addr, rather than
    // allocating its own -- confirmed against io_uring/io_uring.c's
    // io_allocate_scq_urings and io_uring/memmap.c's io_region_pin_pages.
    // A round-tripped NOP here exercises that the sizing this crate
    // predicts for that memory (ring::no_mmap::NoMmapRegions) is large
    // enough for the kernel to actually lay the rings out in, and that
    // the parsing code reads the right offsets back out of memory this
    // crate owns instead of memory `mmap(2)` produced.
    let mut ring = IoUring::builder(4)
        .no_mmap()
        .build()
        .expect("NO_MMAP ring should be accepted by this kernel (6.5+)");
    assert!(
        ring.setup_flags()
            .contains(crate::types::SetupFlags::NO_MMAP)
    );

    ring.push_nop(7).expect("push nop");
    ring.submit_and_wait(1).expect("submit");
    let cqe = ring.complete().expect("expected a completion");
    assert_eq!(cqe.user_data, 7);
}

#[cfg(not(miri))]
#[test]
fn a_real_no_mmap_ring_rejects_a_plain_mmap_on_its_fd() {
    // The man page and io_uring/memmap.c's io_region_validate_mmap (which
    // rejects any region flagged IO_REGION_F_USER_PROVIDED) both document
    // that a NO_MMAP ring's fd cannot be mmap'd through the usual path --
    // confirming this crate is right not to attempt one internally, and
    // that a caller reaching for the fd directly gets the same rejection
    // the kernel documents rather than a silent, differently-sized map.
    use crate::types::{MapFlags, Prot, RingOffset};

    let ring = IoUring::builder(4)
        .no_mmap()
        .build()
        .expect("NO_MMAP setup");
    // The exact errno the kernel settles on here has drifted across
    // versions (EINVAL from `io_region_validate_mmap`'s explicit check,
    // ENOMEM from a later `vm_insert_pages` failure on some paths) --
    // what this crate's own correctness rests on is that the mmap fails
    // at all, not which errno names the rejection.
    // Safety: this call is expected to fail; the kernel rejects it before
    // any mapping is established, so there is nothing here to clobber.
    let _ = unsafe {
        crate::syscall::mmap(
            0,
            4096,
            Prot::READ | Prot::WRITE,
            MapFlags::SHARED,
            ring.raw_fd().as_usize(),
            RingOffset::SqRing.into(),
        )
    }
    .expect_err("a NO_MMAP ring's fd must refuse a plain mmap");
}

#[cfg(not(miri))]
#[test]
fn a_real_no_mmap_ring_survives_a_larger_queue_depth() {
    // Exercise the sizing prediction (ring::no_mmap::predict_entries /
    // ring_region_size / sqes_region_size) against a queue depth well
    // past the smallest power of two, so a formula that only happened to
    // work for `entries == 4` would be caught here.
    let mut ring = IoUring::builder(257)
        .no_mmap()
        .build()
        .expect("NO_MMAP setup at a larger depth");

    for i in 0..8u64 {
        ring.push_nop(i).expect("push nop");
    }
    ring.submit_and_wait(8).expect("submit");
    let mut seen = 0u64;
    while let Some(cqe) = ring.complete() {
        seen += 1;
        assert!(cqe.user_data < 8);
    }
    assert_eq!(seen, 8);
}

#[cfg(not(miri))]
#[test]
fn a_real_no_sqarray_ring_completes_a_nop_without_an_indirection_array() {
    // NO_SQARRAY zeroes sq_off.array and removes the SQ indirection array
    // entirely; the kernel indexes SQEs directly by the masked SQ head
    // instead. push() already writes each SQE to that exact slot (tail &
    // mask, which becomes the kernel's next head), so this exercises that
    // no array needs to exist for a submission to land in the right place
    // -- confirming both the sizing fix (no oversized/undersized SQ mmap)
    // and the parse fix (no identity array written into memory that
    // doesn't back one).
    let mut ring = IoUring::builder(4)
        .no_sqarray()
        .build()
        .expect("NO_SQARRAY ring should be accepted by this kernel");

    ring.push_nop(42).expect("push nop");
    ring.submit_and_wait(1).expect("submit");
    let cqe = ring.complete().expect("expected a completion");
    assert_eq!(cqe.user_data, 42);
    assert_eq!(cqe.result, 0);
}

#[cfg(not(miri))]
#[test]
fn a_real_no_sqarray_ring_carries_several_submissions_in_order() {
    // A single SQE landing correctly could be a coincidence of head == 0.
    // Push several NOPs with distinct user_data and confirm every one
    // completes -- if the sizing were wrong this would either fail to
    // build, fault, or silently drop entries past whatever the
    // (incorrectly computed) region actually held.
    let mut ring = IoUring::builder(8)
        .no_sqarray()
        .build()
        .expect("NO_SQARRAY ring should be accepted by this kernel");

    for i in 0..5u64 {
        ring.push_nop(100 + i).expect("push nop");
    }
    ring.submit_and_wait(5).expect("submit");

    let mut seen = [false; 5];
    for _ in 0..5 {
        let cqe = ring.complete().expect("expected a completion");
        assert_eq!(cqe.result, 0);
        let idx = (cqe.user_data - 100) as usize;
        assert!(
            !seen[idx],
            "duplicate completion for user_data {}",
            cqe.user_data
        );
        seen[idx] = true;
    }
    assert!(seen.iter().all(|&s| s), "not every pushed nop completed");
}

#[cfg(not(miri))]
#[test]
fn builder_rejects_unnamed_setup_flag_bits() {
    use crate::error::{Error, InvalidArgKind, SetupError};
    use crate::types::SetupFlags;

    // Safety must not depend on callers only ever constructing named
    // constants: SetupFlags's Not/BitOr impls let a caller form bits with
    // no associated constant at all (e.g. a future kernel flag this crate
    // has not learned about yet). Those must be rejected too.
    const UNNAMED_BIT: u32 = 1 << 30;
    assert_eq!(
        UNNAMED_BIT & SetupFlags::SQPOLL.bits(),
        0,
        "test bit must not collide with a real named flag"
    );

    let flags = SetupFlags::from_raw_for_test(UNNAMED_BIT);
    let Err(err) = IoUring::builder(4).setup_flags(flags).build() else {
        panic!("unnamed setup-flag bits must be rejected before the kernel is asked")
    };
    assert_eq!(
        err,
        Error::Setup(SetupError::InvalidArg(
            InvalidArgKind::UnsupportedSetupFlags(UNNAMED_BIT)
        ))
    );
}

#[cfg(not(miri))]
#[test]
fn builder_accepts_combined_supported_flags() {
    // Sanity check that the supported-mask gate does not reject legitimate
    // combinations of implemented flags.
    let ring = IoUring::builder(4)
        .clamp()
        .coop_taskrun()
        .build()
        .expect("supported flag combination must build");
    drop(ring);
}

#[cfg(not(miri))]
#[test]
fn split_rejects_defer_taskrun() {
    use crate::error::{Error, InvalidArgKind, SetupError};
    use crate::types::SetupFlags;

    // DEFER_TASKRUN requires every io_uring_enter(GETEVENTS) call to run on
    // the thread that created (or enabled) the ring. A Completer moved to
    // another thread would violate that on its very first `wait` or
    // `submit_and_wait`, so split() must refuse rather than hand out a
    // Send type that cannot honor its own thread-safety claim.
    let ring = IoUring::builder(4)
        .defer_taskrun()
        .single_issuer()
        .build()
        .expect("setup");
    assert!(
        !ring.can_split(),
        "can_split must agree with split's own check"
    );

    let setup_flags = SetupFlags::DEFER_TASKRUN.bits()
        | SetupFlags::COOP_TASKRUN.bits()
        | SetupFlags::SINGLE_ISSUER.bits();
    let Err((ring, err)) = ring.split() else {
        panic!("DEFER_TASKRUN ring must not split")
    };
    assert_eq!(
        err,
        Error::Setup(SetupError::InvalidArg(InvalidArgKind::IncompatibleSplit(
            setup_flags
        )))
    );
    // The ring must come back usable, not consumed by the failed split.
    drop(ring);
}

#[cfg(not(miri))]
#[test]
fn split_rejects_single_issuer_without_sqpoll() {
    use crate::error::{Error, InvalidArgKind, SetupError};
    use crate::types::SetupFlags;

    // SINGLE_ISSUER without SQPOLL restricts *submission* to one userspace
    // thread; the kernel fails a competing submitter with -EEXIST. A
    // Submitter moved to a second thread would hit that on its first push
    // or submit.
    let ring = IoUring::builder(4).single_issuer().build().expect("setup");
    assert!(!ring.can_split());

    let Err((ring, err)) = ring.split() else {
        panic!("SINGLE_ISSUER without SQPOLL must not split")
    };
    assert_eq!(
        err,
        Error::Setup(SetupError::InvalidArg(InvalidArgKind::IncompatibleSplit(
            SetupFlags::SINGLE_ISSUER.bits()
        )))
    );
    drop(ring);
}

#[cfg(not(miri))]
#[test]
fn split_allows_single_issuer_with_sqpoll() {
    // With SQPOLL, the kernel's own polling thread is the sole submitter
    // regardless of which userspace thread calls io_uring_enter, so
    // SINGLE_ISSUER's restriction is satisfied structurally. This
    // combination must remain splittable.
    let ring = IoUring::builder(4)
        .sqpoll(50)
        .single_issuer()
        .build()
        .expect("setup");
    assert!(ring.can_split());

    let (sub, comp) = ring.split().unwrap_or_else(|(_, e)| panic!("split: {e}"));
    drop((sub, comp));
}

#[cfg(not(miri))]
#[test]
fn split_allows_default_flags() {
    // No thread-affinity flags at all: must split, as before this change.
    let ring = IoUring::new(4).expect("setup");
    assert!(ring.can_split());
    let (sub, comp) = ring.split().unwrap_or_else(|(_, e)| panic!("split: {e}"));
    drop((sub, comp));
}

#[cfg(not(miri))]
#[test]
fn splice_pipe_roundtrip() {
    use crate::types::SpliceFlags;
    let mut pipe_fds = [0i32; 2];
    // Safety: `pipe_fds` is a live local `[i32; 2]`, writable for two `i32`s.
    unsafe { crate::syscall::pipe2(pipe_fds.as_mut_ptr(), 0) }.expect("pipe2");
    let [read_end, write_end] = pipe_fds;

    let mut ring = IoUring::new(8).expect("setup");
    let msg = b"splice test data";

    // Write to the pipe's write end directly
    ring.push(unsafe { Sqe::write(RawFd::from_raw(write_end as usize), msg, 0) }.user_data(1))
        .expect("push write");
    ring.submit_and_wait(1).expect("submit write");
    let cqe = ring.complete().expect("write cqe");
    assert_eq!(cqe.result, msg.len() as i32);

    // Splice from the read end of the pipe into a tmpfile
    let fd = open_tmpfile(&mut ring);
    ring.push(
        Sqe::splice(
            RawFd::from_raw(fd as usize),
            u64::MAX,
            RawFd::from_raw(read_end as usize),
            u64::MAX,
            msg.len() as u32,
            SpliceFlags::default(),
        )
        .user_data(2),
    )
    .expect("push splice");
    ring.submit_and_wait(1).expect("submit splice");
    let cqe = ring.complete().expect("splice cqe");
    assert_eq!(cqe.result, msg.len() as i32, "splice byte count");

    // Verify the data landed in the file
    let mut read_buf = [0u8; 64];
    ring.push(unsafe { Sqe::read(RawFd::from_raw(fd as usize), &mut read_buf, 0) }.user_data(3))
        .expect("push read");
    ring.submit_and_wait(1).expect("submit read");
    let cqe = ring.complete().expect("read cqe");
    assert_eq!(cqe.result, msg.len() as i32);
    assert_eq!(&read_buf[..msg.len()], msg);

    let _ = syscall::close(RawFd::from_raw(read_end as usize));
    let _ = syscall::close(RawFd::from_raw(write_end as usize));
    let _ = syscall::close(RawFd::from_raw(fd as usize));
}

#[cfg(not(miri))]
#[test]
fn a_real_read_multishot_delivers_two_writes_from_one_armed_request() {
    use crate::types::CqeFlags;

    let mut pipe_fds = [0i32; 2];
    // Safety: `pipe_fds` is a live local `[i32; 2]`, writable for two `i32`s.
    unsafe { crate::syscall::pipe2(pipe_fds.as_mut_ptr(), 0) }.expect("pipe2");
    let [read_end, write_end] = pipe_fds;

    let mut ring = IoUring::new(8).expect("setup");
    let mut pbuf = ring
        .register_provided_buffers(21, 4, 64)
        .expect("register_provided_buffers");

    ring.push(Sqe::read_multishot(RawFd::from_raw(read_end as usize), 0, 21).user_data(1))
        .expect("push read_multishot");
    ring.submit().expect("submit");

    let first = b"first write";
    ring.push(unsafe { Sqe::write(RawFd::from_raw(write_end as usize), first, 0) }.user_data(2))
        .expect("push write 1");
    ring.submit_and_wait(1).expect("submit write 1");

    let mut arrivals: Vec<Vec<u8>> = Vec::new();
    let mut saw_more = false;
    loop {
        let Some(cqe) = ring.complete() else {
            break;
        };
        if cqe.user_data == 2 {
            assert_eq!(cqe.result, first.len() as i32);
            continue;
        }
        assert_eq!(cqe.user_data, 1);
        assert!(cqe.flags.contains(CqeFlags::MORE), "must stay armed");
        saw_more = true;
        let buf_id = cqe.buffer_id().expect("buffer_id present");
        #[allow(clippy::cast_sign_loss)]
        let payload = pbuf
            .buffer(buf_id, cqe.result as u32)
            .expect("buffer slice");
        arrivals.push(payload.to_vec());
        pbuf.recycle_and_commit(buf_id);
    }
    assert!(
        saw_more,
        "the read must have delivered at least one arrival"
    );

    let second = b"second write";
    ring.push(unsafe { Sqe::write(RawFd::from_raw(write_end as usize), second, 0) }.user_data(3))
        .expect("push write 2");
    ring.submit_and_wait(1).expect("submit write 2");

    loop {
        let Some(cqe) = ring.complete() else {
            break;
        };
        if cqe.user_data == 3 {
            assert_eq!(cqe.result, second.len() as i32);
            continue;
        }
        assert_eq!(cqe.user_data, 1);
        let buf_id = cqe.buffer_id().expect("buffer_id present");
        #[allow(clippy::cast_sign_loss)]
        let payload = pbuf
            .buffer(buf_id, cqe.result as u32)
            .expect("buffer slice");
        arrivals.push(payload.to_vec());
        pbuf.recycle_and_commit(buf_id);
    }

    let joined: Vec<u8> = arrivals.concat();
    let expected: Vec<u8> = first.iter().chain(second.iter()).copied().collect();
    assert_eq!(
        joined, expected,
        "one armed multishot read delivered both writes in order"
    );

    let _ = syscall::close(RawFd::from_raw(read_end as usize));
    let _ = syscall::close(RawFd::from_raw(write_end as usize));
}

#[cfg(not(miri))]
unsafe extern "C" {
    #[link_name = "epoll_create1"]
    fn epoll_create1(flags: i32) -> i32;
}

#[cfg(not(miri))]
#[test]
fn a_real_epoll_wait_reports_a_pipe_becoming_readable() {
    use crate::types::{EpollEvent, EpollEvents, EpollOp};

    let mut pipe_fds = [0i32; 2];
    // Safety: `pipe_fds` is a live local `[i32; 2]`, writable for two `i32`s.
    unsafe { crate::syscall::pipe2(pipe_fds.as_mut_ptr(), 0) }.expect("pipe2");
    let [read_end, write_end] = pipe_fds;

    // SAFETY: a plain syscall with no pointer arguments.
    let epfd = unsafe { epoll_create1(0) };
    assert!(epfd >= 0, "epoll_create1 failed");

    let mut ring = IoUring::new(8).expect("setup");

    let watch = EpollEvent {
        events: EpollEvents::IN.bits(),
        data: 0xC0FF_EE,
    };
    ring.push(
        unsafe {
            Sqe::epoll_ctl(
                RawFd::from_raw(epfd as usize),
                EpollOp::Add,
                RawFd::from_raw(read_end as usize),
                &watch,
            )
        }
        .user_data(1),
    )
    .expect("push epoll_ctl add");
    ring.submit_and_wait(1).expect("submit add");
    let add_cqe = ring.complete().expect("add cqe");
    assert_eq!(add_cqe.result, 0, "epoll_ctl add must succeed");

    // Nothing readable yet: this wait is issued before the write and stays
    // outstanding until the pipe becomes readable.
    let mut wait_events = [EpollEvent::default(); 1];
    ring.push(
        unsafe { Sqe::epoll_wait(RawFd::from_raw(epfd as usize), &mut wait_events) }.user_data(2),
    )
    .expect("push epoll_wait");
    ring.submit().expect("submit wait");

    // The pipe becomes readable while the wait is outstanding.
    let msg = b"epoll wait test";
    ring.push(unsafe { Sqe::write(RawFd::from_raw(write_end as usize), msg, 0) }.user_data(3))
        .expect("push write");
    ring.submit_and_wait(2).expect("submit write");

    let mut wait_result: Option<i32> = None;
    let mut write_result: Option<i32> = None;
    while wait_result.is_none() || write_result.is_none() {
        let cqe = ring.complete().expect("cqe");
        match cqe.user_data {
            2 => wait_result = Some(cqe.result),
            3 => write_result = Some(cqe.result),
            other => panic!("unexpected user_data {other}"),
        }
    }
    assert_eq!(write_result.expect("write completion"), msg.len() as i32);
    let n = wait_result.expect("wait completion");
    assert_eq!(n, 1, "exactly one fd became readable");
    let reported = wait_events[0];
    let (events, data) = (reported.events, reported.data);
    assert_eq!(data, 0xC0FF_EE);
    assert_ne!(events & EpollEvents::IN.bits(), 0);

    let _ = syscall::close(RawFd::from_raw(read_end as usize));
    let _ = syscall::close(RawFd::from_raw(write_end as usize));
    let _ = syscall::close(RawFd::from_raw(epfd as usize));
}

#[cfg(not(miri))]
#[test]
fn fadvise_roundtrip() {
    use crate::types::FadviseAdvice;
    let mut ring = IoUring::new(4).expect("setup");
    let fd = open_tmpfile(&mut ring);

    let buf = b"fadvise data";
    ring.push(unsafe { Sqe::write(RawFd::from_raw(fd as usize), buf, 0) }.user_data(1))
        .expect("push");
    ring.submit_and_wait(1).expect("submit");
    ring.complete().expect("write cqe");

    ring.push(
        Sqe::fadvise(
            RawFd::from_raw(fd as usize),
            0,
            buf.len() as u32,
            FadviseAdvice::Sequential,
        )
        .user_data(2),
    )
    .expect("push fadvise");
    ring.submit_and_wait(1).expect("submit fadvise");
    let cqe = ring.complete().expect("fadvise cqe");
    assert_eq!(cqe.user_data, 2);
    assert_eq!(cqe.result, 0, "fadvise failed: {}", cqe.result);

    let _ = syscall::close(RawFd::from_raw(fd as usize));
}

#[cfg(not(miri))]
#[test]
fn openat2_basic() {
    use crate::types::{OpenFlags, OpenHow};
    let mut ring = IoUring::new(4).expect("setup");

    let target = UniqueTestPath::new("openat2_test");
    let path = target.as_cstring();

    let how = OpenHow {
        flags: u64::from(OpenFlags::RDWR.bits() | OpenFlags::CREAT.bits() | OpenFlags::EXCL.bits()),
        mode: 0o600,
        resolve: 0,
    };
    ring.push(unsafe { Sqe::openat2(types::AT_FDCWD, &path, &how) }.user_data(1))
        .expect("push openat2");
    ring.submit_and_wait(1).expect("submit");
    let cqe = ring.complete().expect("openat2 cqe");
    assert_eq!(cqe.user_data, 1);
    assert!(cqe.result >= 0, "openat2 failed: {}", cqe.result);

    let _ = syscall::close(RawFd::from_raw(cqe.result as usize));
    // cleanup
    ring.push(unsafe { Sqe::unlinkat(crate::types::DirFd::Cwd, &path, UnlinkFlags::default()) })
        .expect("push unlinkat");
    ring.submit_and_wait(1).expect("submit unlinkat");
    let _ = ring.complete();
}

#[cfg(not(miri))]
#[test]
fn send_zc_roundtrip() {
    use crate::types::{CqeFlags, MsgFlags};
    let mut ring = IoUring::new(8).expect("setup");
    let (listener, port) = setup_tcp_listener();

    let client = syscall::socket(types::AF_INET, types::SOCK_STREAM | types::SOCK_NONBLOCK, 0)
        .expect("client socket")
        .as_i32();

    ring.push(Sqe::accept(RawFd::from_raw(listener as usize), AcceptFlags::default()).user_data(1))
        .expect("push accept");
    let connect_addr = SockAddrIn {
        sin_family: types::AF_INET as u16,
        sin_port: port.to_be(),
        sin_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        sin_zero: [0; 8],
    };
    let addr_bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(
            (&raw const connect_addr).cast(),
            mem::size_of::<SockAddrIn>(),
        )
    };
    ring.push(unsafe { Sqe::connect(RawFd::from_raw(client as usize), addr_bytes) }.user_data(2))
        .expect("push connect");
    ring.submit_and_wait(2).expect("submit accept+connect");

    let mut server_fd = -1i32;
    for _ in 0..2 {
        let cqe = ring.complete().expect("cqe");
        if cqe.user_data == 1 {
            assert!(cqe.result >= 0);
            server_fd = cqe.result;
        }
    }
    assert!(server_fd >= 0);

    // send_zc: kernel generates a send CQE (user_data=3) + a NOTIF CQE (user_data=3,
    // CqeFlags::NOTIF). The NOTIF may arrive in any order relative to other ops.
    let msg = b"zero copy send";
    let mut recv_buf = [0u8; 64];
    ring.push(
        unsafe { Sqe::send_zc(RawFd::from_raw(client as usize), msg, MsgFlags::NOSIGNAL) }
            .user_data(3),
    )
    .expect("push send_zc");
    ring.push(
        unsafe {
            Sqe::recv(
                RawFd::from_raw(server_fd as usize),
                &mut recv_buf,
                MsgFlags::default(),
            )
        }
        .user_data(4),
    )
    .expect("push recv");
    ring.submit_and_wait(2).expect("submit send_zc+recv");

    // Collect all three CQEs: send_zc result, recv result, and NOTIF.
    let mut got_send = false;
    let mut got_recv = false;
    let mut got_notif = false;
    // send_zc produces 2 CQEs (result + NOTIF); recv produces 1 → 3 total.
    for _ in 0..3 {
        if let Some(cqe) = ring.complete() {
            if cqe.user_data == 3 && cqe.flags.contains(CqeFlags::NOTIF) {
                got_notif = true;
            } else if cqe.user_data == 3 {
                assert_eq!(cqe.result, msg.len() as i32, "send_zc byte count");
                got_send = true;
            } else if cqe.user_data == 4 {
                assert_eq!(cqe.result, msg.len() as i32, "recv byte count");
                assert_eq!(&recv_buf[..msg.len()], msg);
                got_recv = true;
            }
        } else {
            // NOTIF may arrive slightly after; give it one more wait
            ring.submit_and_wait(1).ok();
        }
    }
    assert!(got_send, "missing send_zc completion");
    assert!(got_recv, "missing recv completion");
    assert!(got_notif, "missing NOTIF completion");

    let _ = syscall::close(RawFd::from_raw(server_fd as usize));
    let _ = syscall::close(RawFd::from_raw(client as usize));
    let _ = syscall::close(RawFd::from_raw(listener as usize));
}

#[cfg(not(miri))]
#[test]
fn register_eventfd_wakes_on_completion() {
    let efd = EventFd::new(0).expect("eventfd");

    let mut ring = IoUring::new(4).expect("setup");
    ring.register_eventfd(efd.fd()).expect("register_eventfd");

    // Push a NOP — on completion the kernel should signal the eventfd
    ring.push(Sqe::nop().user_data(1)).expect("push");
    ring.submit().expect("submit");

    // Blocking read on the eventfd; should unblock once the NOP completes
    let count = efd.read().expect("eventfd read");
    assert!(count >= 1, "expected ≥1 signal, got {count}");

    ring.unregister_eventfd().expect("unregister_eventfd");
}

#[cfg(not(miri))]
#[test]
fn register_eventfd_async_only_on_async() {
    // With async-only mode, inline completions (NOPs) must NOT signal the eventfd.
    // We verify no hang: if the eventfd were incorrectly signalled this would
    // just pass, so the meaningful check is that we can call the API successfully.
    let efd = EventFd::with_flags(0, EventFdFlags::NONBLOCK).expect("eventfd");

    let mut ring = IoUring::new(4).expect("setup");
    ring.register_eventfd_async(efd.fd())
        .expect("register_eventfd_async");
    ring.push(Sqe::nop().user_data(1)).expect("push");
    ring.submit_and_wait(1).expect("submit");
    ring.complete().expect("nop cqe");

    // NOP completes inline — eventfd should NOT have been signalled.
    let result = efd.read();
    assert!(
        result.is_err(),
        "expected no signal for inline NOP, got Ok({result:?})"
    );

    ring.unregister_eventfd().expect("unregister_eventfd");
}

#[cfg(not(miri))]
#[test]
fn cqe_skip_success_no_cqe_on_success() {
    let mut ring = IoUring::new(4).expect("setup");

    // NOP with CQE_SKIP_SUCCESS set — no CQE should appear on success.
    ring.push(Sqe::nop().user_data(42).cqe_skip_success())
        .expect("push");
    ring.submit().expect("submit");
    // Give the kernel a moment to process it (submit_and_wait(0) just polls).
    ring.submit_and_wait(0).ok();
    assert!(
        ring.complete().is_none(),
        "expected no CQE with CQE_SKIP_SUCCESS"
    );
}

#[cfg(not(miri))]
#[test]
fn accept_with_addr_roundtrip() {
    let mut ring = IoUring::new(8).expect("setup");
    let (listener, port) = setup_tcp_listener();

    let client = syscall::socket(types::AF_INET, types::SOCK_STREAM | types::SOCK_NONBLOCK, 0)
        .expect("client socket")
        .as_i32();

    let mut peer_addr = SockAddrIn::default();
    let mut peer_addrlen = mem::size_of::<SockAddrIn>() as u32;

    ring.push(
        unsafe {
            Sqe::accept_with_addr(
                RawFd::from_raw(listener as usize),
                &mut peer_addr,
                &mut peer_addrlen,
                AcceptFlags::default(),
            )
        }
        .user_data(1),
    )
    .expect("push accept_with_addr");

    let connect_addr = SockAddrIn {
        sin_family: types::AF_INET as u16,
        sin_port: port.to_be(),
        sin_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        sin_zero: [0; 8],
    };
    let addr_bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(
            (&raw const connect_addr).cast(),
            mem::size_of::<SockAddrIn>(),
        )
    };
    ring.push(unsafe { Sqe::connect(RawFd::from_raw(client as usize), addr_bytes) }.user_data(2))
        .expect("push connect");

    ring.submit_and_wait(2).expect("submit");

    let mut server_fd = -1i32;
    for _ in 0..2 {
        let cqe = ring.complete().expect("cqe");
        if cqe.user_data == 1 {
            assert!(cqe.result >= 0, "accept failed: {}", cqe.result);
            server_fd = cqe.result;
        }
    }
    assert!(server_fd >= 0);
    // The peer address should be the loopback IPv4 address
    assert_eq!(peer_addr.sin_family, types::AF_INET as u16);
    assert_eq!(peer_addr.sin_addr, u32::from_ne_bytes([127, 0, 0, 1]));
    assert_eq!(peer_addrlen, mem::size_of::<SockAddrIn>() as u32);

    let _ = syscall::close(RawFd::from_raw(server_fd as usize));
    let _ = syscall::close(RawFd::from_raw(client as usize));
    let _ = syscall::close(RawFd::from_raw(listener as usize));
}

#[cfg(not(miri))]
#[test]
fn update_registered_files_replaces_slot() {
    let mut ring = IoUring::new(4).expect("setup");
    let fd = open_tmpfile(&mut ring);

    // Register a table with one slot, then replace it via files_update
    ring.register_files(&[fd]).expect("register_files");

    let fd2 = open_tmpfile(&mut ring);
    ring.update_registered_files(&[fd2], 0)
        .expect("update_registered_files");

    // Slot 0 now points to fd2; use a regular write through the fixed slot.
    let msg = b"via updated fixed fd";
    ring.push(
        unsafe { Sqe::write(RawFd::from_raw(0), msg, 0) }
            .fixed_file()
            .user_data(1),
    )
    .expect("push write");
    ring.submit_and_wait(1).expect("submit");
    let cqe = ring.complete().expect("cqe");
    assert_eq!(cqe.result, msg.len() as i32);

    ring.unregister_files().expect("unregister");
    let _ = syscall::close(RawFd::from_raw(fd as usize));
    let _ = syscall::close(RawFd::from_raw(fd2 as usize));
}

// ---------------------------------------------------------------
// Error `Display` impls — pure formatting, run under Miri.
// ---------------------------------------------------------------

#[test]
fn submit_error_display() {
    extern crate std;
    use std::string::ToString;

    assert_eq!(
        SubmitError::QueueFull.to_string(),
        "submission queue is full"
    );
    assert_eq!(
        SubmitError::Syscall(Errno::EAGAIN).to_string(),
        "submit syscall failed: os error 11"
    );
}

#[test]
fn completion_error_display() {
    extern crate std;
    use std::string::ToString;

    assert_eq!(
        CompletionError::NoCompletion.to_string(),
        "no completion available"
    );
    assert_eq!(
        CompletionError::Failed(Errno::EINVAL).to_string(),
        "operation failed: os error 22"
    );
}

#[test]
fn setup_error_display() {
    extern crate std;
    use std::string::ToString;

    assert_eq!(
        SetupError::InvalidArg(InvalidArgKind::BufferCountZero).to_string(),
        "invalid argument: buffer count must be non-zero"
    );
    assert_eq!(
        SetupError::Syscall(Errno::EINVAL).to_string(),
        "setup syscall failed: os error 22"
    );
}

#[test]
fn error_display_delegates_to_inner() {
    extern crate std;
    use std::string::ToString;

    // Each wrapping variant must format exactly like the value it wraps.
    assert_eq!(
        Error::Submit(SubmitError::QueueFull).to_string(),
        SubmitError::QueueFull.to_string()
    );
    assert_eq!(
        Error::Completion(CompletionError::NoCompletion).to_string(),
        CompletionError::NoCompletion.to_string()
    );
    assert_eq!(
        Error::Setup(SetupError::Syscall(Errno::EINVAL)).to_string(),
        SetupError::Syscall(Errno::EINVAL).to_string()
    );
    // The leaf `Syscall` arm has its own message.
    assert_eq!(
        Error::Syscall(Errno::ENOENT).to_string(),
        "syscall failed: os error 2"
    );
}

// ---------------------------------------------------------------
// SQPOLL submit path — needs a real kernel, skipped under Miri.
// ---------------------------------------------------------------

#[cfg(not(miri))]
#[test]
fn a_real_ring_fd_registration_can_be_undone() {
    let mut ring = IoUring::new(4).expect("setup");
    let offset = ring.register_ring_fd().expect("register_ring_fd");
    ring.unregister_ring_fd(offset).expect("unregister_ring_fd");
}

#[cfg(not(miri))]
#[test]
fn a_real_iowq_affinity_registration_can_be_set_and_undone() {
    let mut ring = IoUring::new(4).expect("setup");
    // CPU 0 is present on every Linux system this crate targets, online
    // or not — the kernel accepts naming an offline CPU in the mask, it
    // just never schedules a worker there, so this does not need to probe
    // `/sys` for which CPUs actually exist to be a valid affinity mask.
    let mask: [u8; 1] = [0b0000_0001];
    ring.register_iowq_affinity(&mask)
        .expect("register_iowq_affinity");
    ring.unregister_iowq_affinity()
        .expect("unregister_iowq_affinity");
}

#[cfg(not(miri))]
#[test]
fn a_real_napi_registration_reports_dynamic_tracking_and_can_be_undone() {
    use crate::types::NapiTrackingStrategy;

    let mut ring = IoUring::new(4).expect("setup");
    match ring.register_napi(1000, false, NapiTrackingStrategy::Dynamic) {
        Ok(before) => {
            // Freshly created ring: no NAPI tracking was configured yet.
            assert_eq!(before.busy_poll_timeout_usec, 0);
            let after = ring.unregister_napi().expect("unregister_napi");
            // Reports what was in effect just before unregistering, i.e.
            // what register_napi just set.
            assert_eq!(after.busy_poll_timeout_usec, 1000);
        }
        // Kernels built without CONFIG_NET_RX_BUSY_POLL reject this
        // opcode outright; that is a valid environment for this crate to
        // run in, not a bug to chase.
        Err(_) => {}
    }
}

#[cfg(not(miri))]
#[test]
fn enabling_a_ring_that_was_never_disabled_is_rejected() {
    let mut ring = IoUring::new(4).expect("setup");
    ring.enable_rings()
        .expect_err("EBADFD: ring was not created with SetupFlags::R_DISABLED");
}

#[cfg(not(miri))]
#[test]
fn a_real_r_disabled_ring_rejects_enter_until_enable_rings_is_called() {
    use crate::types::SetupFlags;

    let mut ring = IoUring::builder(4).r_disabled().build().expect("setup");
    assert!(ring.setup_flags().contains(SetupFlags::R_DISABLED));

    ring.push_nop(1).expect("push");
    ring.submit().expect_err("EBADFD: ring is still disabled");

    ring.enable_rings().expect("enable_rings");

    // The NOP pushed before enabling is still queued — flush_sq_tail was
    // called by the rejected submit(), so this round trips it the same
    // way any other submit would.
    ring.submit_and_wait(1)
        .expect("submit_and_wait after enable");
    let cqe = ring.complete().expect("nop completion");
    assert_eq!(cqe.user_data, 1);
    assert_eq!(cqe.result, 0);
}

#[cfg(not(miri))]
#[test]
fn a_real_submit_all_ring_still_submits_a_batch_with_no_failures() {
    use crate::types::SetupFlags;

    let mut ring = IoUring::builder(4).submit_all().build().expect("setup");
    assert!(ring.setup_flags().contains(SetupFlags::SUBMIT_ALL));

    ring.push_nop(1).expect("push");
    ring.push_nop(2).expect("push");
    let submitted = ring.submit_and_wait(2).expect("submit_and_wait");
    assert_eq!(submitted, 2);

    let mut seen: Vec<u64> = ring.completions().map(|c| c.user_data).collect();
    seen.sort_unstable();
    assert_eq!(seen, vec![1, 2]);
}

#[cfg(not(miri))]
#[test]
fn a_real_taskrun_flag_ring_completes_a_nop_under_defer_taskrun() {
    use crate::types::SetupFlags;

    // TASKRUN_FLAG is rejected unless combined with COOP_TASKRUN or
    // DEFER_TASKRUN; defer_taskrun() sets COOP_TASKRUN for us. Some
    // kernels also require SINGLE_ISSUER alongside DEFER_TASKRUN.
    let mut ring = IoUring::builder(4)
        .defer_taskrun()
        .single_issuer()
        .taskrun_flag()
        .build()
        .expect("setup");
    assert!(ring.setup_flags().contains(SetupFlags::TASKRUN_FLAG));

    ring.push_nop(1).expect("push");
    ring.submit_and_wait(1).expect("submit_and_wait");
    let cqe = ring.complete().expect("nop completion");
    assert_eq!(cqe.user_data, 1);
    assert_eq!(cqe.result, 0);
}

#[cfg(not(miri))]
#[test]
fn submit_sqpoll_roundtrip() {
    // 100ms idle so the poll thread reliably parks between submissions,
    // forcing `submit_sqpoll` through its SQ_WAKEUP branch on the 2nd push.
    let mut ring = IoUring::builder(4).sqpoll(100).build().expect("setup");

    ring.push_nop(1).expect("push");
    ring.submit_sqpoll().expect("submit_sqpoll");
    // Spin until the poll thread reaps our NOP into the CQ.
    let cqe = loop {
        if let Some(cqe) = ring.complete() {
            break cqe;
        }
        core::hint::spin_loop();
    };
    assert_eq!(cqe.user_data, 1);
    assert_eq!(cqe.result, 0);

    // Let the kernel poll thread go idle, then submit again so the
    // need-wakeup path actually fires.
    for _ in 0..1_000_000 {
        core::hint::spin_loop();
    }
    ring.push_nop(2).expect("push");
    ring.submit_sqpoll().expect("submit_sqpoll wakeup");
    let cqe = loop {
        if let Some(cqe) = ring.complete() {
            break cqe;
        }
        core::hint::spin_loop();
    };
    assert_eq!(cqe.user_data, 2);
}

#[cfg(not(miri))]
#[test]
fn submit_sqpoll_split_roundtrip() {
    // Same SQPOLL path, but through the split Submitter/Completer halves so
    // `Submitter::submit_sqpoll` is exercised (not just `IoUring::`).
    let ring = IoUring::builder(4).sqpoll(100).build().expect("setup");
    let (mut sub, mut comp) = ring.split().unwrap_or_else(|(_, e)| panic!("split: {e}"));

    sub.push_nop(7).expect("push");
    sub.submit_sqpoll().expect("submit_sqpoll");
    let cqe = loop {
        if let Some(cqe) = comp.complete() {
            break cqe;
        }
        core::hint::spin_loop();
    };
    assert_eq!(cqe.user_data, 7);
    assert_eq!(cqe.result, 0);

    // Park the poll thread, then submit again to hit the wakeup branch.
    for _ in 0..1_000_000 {
        core::hint::spin_loop();
    }
    sub.push_nop(8).expect("push");
    sub.submit_sqpoll().expect("submit_sqpoll wakeup");
    let cqe = loop {
        if let Some(cqe) = comp.complete() {
            break cqe;
        }
        core::hint::spin_loop();
    };
    assert_eq!(cqe.user_data, 8);
}

#[cfg(not(miri))]
#[test]
fn split_submit_return_value_tracks_actual_consumption_across_rounds() {
    // Split-ring counterpart of
    // `submit_return_value_tracks_actual_consumption_across_rounds`: the
    // `Submitter`/`Completer` halves run a separate copy of the same
    // sq_submitted-tracking logic, so a fix applied only to the unsplit
    // `IoUring` path would leave this one unrepaired. Same scope note
    // applies — see AUDIT.md Q-07 — this proves round-trip accounting
    // integrity, not a genuine kernel short-submission.
    let ring = IoUring::new(4).expect("setup");
    let (mut sub, mut comp) = ring.split().unwrap_or_else(|(_, e)| panic!("split: {e}"));
    let mut next_user_data = 0u64;
    let mut expected = std::collections::HashSet::new();

    for round in 0..50u64 {
        let batch = 1 + (round % 3);
        for _ in 0..batch {
            sub.push_nop(next_user_data).expect("push");
            expected.insert(next_user_data);
            next_user_data += 1;
        }
        let submitted = sub.submit_and_wait(batch as u32).expect("submit");
        assert_eq!(
            submitted, batch as u32,
            "round {round}: every pushed entry should be consumed in one \
             call on a healthy kernel with no queue pressure"
        );
        for _ in 0..batch {
            let cqe = comp.complete().expect("completion");
            assert!(
                expected.remove(&cqe.user_data),
                "round {round}: completion for user_data {} was unexpected or duplicated",
                cqe.user_data
            );
            assert_eq!(cqe.result, 0);
        }
        // Unlike the unsplit `IoUring::submit_and_wait`, `Submitter` has no
        // access to the CQ head and so cannot auto-flush it. Publish the
        // drained head back to the kernel so the CQ ring has free slots for
        // the next round — without this, the CQ ring fills after a few
        // rounds and the kernel queues further completions internally
        // instead of posting them where `complete()` can see them.
        comp.sync_cq();
    }

    assert!(
        expected.is_empty(),
        "leftover user_data values never completed: {expected:?}"
    );
    assert!(comp.complete().is_none());
}
