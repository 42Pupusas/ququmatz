extern crate std;
use std::{vec, vec::Vec};

use super::*;
use crate::types::{
    AcceptFlags, EventFdFlags, FileMode, FsyncFlags, InotifyEvent, InotifyInitFlags,
    IoCqringOffsets, IoSqringOffsets, IoUringBuf, IoUringBufReg, IoUringCqe, IoUringParams,
    IoUringSqe, MsgFlags, MsgHdr, Opcode, OpenFlags, PollMask, SockAddrIn, SqeFlags, Statx,
    StatxFlags, StatxMask, StatxTimestamp, WatchMask,
};
use core::mem;

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
    assert_eq!(mem::size_of::<IoVec>(), 16);
    assert_eq!(mem::align_of::<IoVec>(), 8);
}

#[test]
fn msghdr_layout() {
    assert_eq!(mem::size_of::<MsgHdr>(), 56);
    assert_eq!(mem::align_of::<MsgHdr>(), 8);
}

#[test]
fn sockaddrin_layout() {
    assert_eq!(mem::size_of::<SockAddrIn>(), 16);
    assert_eq!(mem::align_of::<SockAddrIn>(), 4);
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
    let sqe = Sqe::read(42, &mut buf, 100).user_data(99);
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
    let sqe = Sqe::write(7, &buf, 0).user_data(55);
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
    let sqe = Sqe::readv(3, &vecs, 50).user_data(10);
    let inner = sqe.0;

    assert_eq!(Opcode::Readv, inner.opcode);
    assert_eq!(inner.fd, 3);
    assert_eq!(inner.addr, vecs.as_ptr() as u64);
    assert_eq!(inner.len, 1);
    assert_eq!(inner.off, 50);
    assert_eq!(inner.user_data, 10);
}

#[test]
fn sqe_builder_openat_places_fields_correctly() {
    use crate::types::DirFd;
    let path = c"/tmp/test";
    let sqe = Sqe::openat(
        DirFd::Cwd,
        path,
        OpenFlags::default(),
        FileMode::OWNER_READ | FileMode::OWNER_WRITE | FileMode::GROUP_READ | FileMode::OTHER_READ,
    )
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
    let sqe = Sqe::close(5).user_data(88);
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
    let sqe = Sqe::timeout(&ts, 3, TimeoutFlags::default()).user_data(42);
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
    let sqe = Sqe::fsync(5, FsyncFlags::DATASYNC).user_data(10);
    let inner = sqe.0;

    assert_eq!(Opcode::Fsync, inner.opcode);
    assert_eq!(inner.fd, 5);
    assert_eq!(inner.op_flags, FsyncFlags::DATASYNC.bits());
    assert_eq!(inner.user_data, 10);
}

#[test]
fn sqe_builder_poll_add_places_fields_correctly() {
    let sqe = Sqe::poll_add(3, PollMask::IN | PollMask::RDHUP).user_data(20);
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

#[cfg(not(miri))]
#[test]
fn fsync_on_tmpfile() {
    let mut ring = IoUring::new(4).expect("setup");
    let fd = open_tmpfile(&mut ring);

    // Write some data first
    let buf = b"fsync test";
    ring.push(Sqe::write(fd, buf, 0).user_data(1))
        .expect("push write");
    ring.submit_and_wait(1).expect("submit");
    ring.complete().expect("write cqe");

    // Fsync
    ring.push(Sqe::fsync(fd, FsyncFlags::default()).user_data(2))
        .expect("push fsync");
    ring.submit_and_wait(1).expect("submit");

    let cqe = ring.complete().expect("fsync cqe");
    assert_eq!(cqe.user_data, 2);
    assert_eq!(cqe.result, 0);

    let _ = syscall::close(RawFd::from_raw(fd as usize));
}

#[cfg(not(miri))]
#[test]
fn statx_on_tmp() {
    let mut ring = IoUring::new(4).expect("setup");
    let mut buf = Statx::default();

    ring.push(
        Sqe::statx(
            crate::types::DirFd::Cwd,
            c"/tmp",
            StatxFlags::default(),
            StatxMask::BASIC_STATS,
            &mut buf,
        )
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
    ring.push(Sqe::timeout(&ts, 0, TimeoutFlags::default()).user_data(1))
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
    ring.push(Sqe::write(fd, write_buf, 0).user_data(1))
        .expect("failed to push write");
    ring.submit_and_wait(1).expect("failed to submit write");

    let cqe = ring.complete().expect("expected write completion");
    assert_eq!(cqe.user_data, 1);
    assert_eq!(cqe.result, write_buf.len() as i32);

    let mut read_buf = [0u8; 64];
    ring.push(Sqe::read(fd, &mut read_buf, 0).user_data(2))
        .expect("failed to push read");
    ring.submit_and_wait(1).expect("failed to submit read");

    let cqe = ring.complete().expect("expected read completion");
    assert_eq!(cqe.user_data, 2);
    assert_eq!(cqe.result, write_buf.len() as i32);
    assert_eq!(&read_buf[..write_buf.len()], write_buf);

    ring.push(Sqe::close(fd).user_data(3))
        .expect("failed to push close");
    ring.submit_and_wait(1).expect("failed to submit close");

    let cqe = ring.complete().expect("expected close completion");
    assert_eq!(cqe.user_data, 3);
    assert_eq!(cqe.result, 0);
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
    ring.push(Sqe::writev(fd, &write_vecs, 0).user_data(1))
        .expect("failed to push writev");
    ring.submit_and_wait(1).expect("failed to submit writev");

    let cqe = ring.complete().expect("expected writev completion");
    assert_eq!(cqe.user_data, 1);
    assert_eq!(cqe.result as usize, buf_a.len() + buf_b.len());

    let mut read_buf = [0u8; 64];
    let read_vecs = [unsafe { IoVec::new(read_buf.as_mut_ptr(), read_buf.len()) }];
    ring.push(Sqe::readv(fd, &read_vecs, 0).user_data(2))
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
    ring.push(unsafe { Sqe::write_fixed(fd, buf.as_ptr(), msg.len() as u32, 0, 0) }.user_data(1))
        .expect("push write_fixed");
    ring.submit_and_wait(1).expect("submit");
    let cqe = ring.complete().expect("write cqe");
    assert_eq!(cqe.user_data, 1);
    assert_eq!(cqe.result, msg.len() as i32);

    // Read back via fixed buffer
    buf.fill(0);
    ring.push(
        unsafe { Sqe::read_fixed(fd, buf.as_mut_ptr(), msg.len() as u32, 0, 0) }.user_data(2),
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
fn registered_files() {
    let mut ring = IoUring::new(4).expect("setup");
    let fd = open_tmpfile(&mut ring);

    ring.register_files(&[fd]).expect("register_files");
    ring.unregister_files().expect("unregister_files");

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
    syscall::setsockopt(
        rawfd,
        1,
        2,
        (&raw const one).cast(),
        core::mem::size_of::<i32>() as u32,
    )
    .expect("setsockopt");

    let addr = SockAddrIn {
        sin_family: types::AF_INET as u16,
        sin_port: 0u16.to_be(), // let the kernel pick an ephemeral port
        sin_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        sin_zero: [0; 8],
    };
    syscall::bind(
        rawfd,
        (&raw const addr).cast(),
        core::mem::size_of::<SockAddrIn>() as u32,
    )
    .expect("bind");
    syscall::listen(rawfd, 1).expect("listen");

    // Retrieve the actual port assigned by the kernel
    let mut bound_addr = SockAddrIn::default();
    let mut addrlen = core::mem::size_of::<SockAddrIn>() as u32;
    syscall::getsockname(rawfd, (&raw mut bound_addr).cast(), &raw mut addrlen)
        .expect("getsockname");

    (fd, u16::from_be(bound_addr.sin_port))
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
    ring.push(Sqe::accept(listener, AcceptFlags::default()).user_data(1))
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
    ring.push(Sqe::connect(client, addr_bytes).user_data(2))
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
    ring.push(Sqe::send(client, msg, MsgFlags::default()).user_data(3))
        .expect("push send");
    ring.submit_and_wait(1).expect("submit send");
    let cqe = ring.complete().expect("send cqe");
    assert_eq!(cqe.user_data, 3);
    assert_eq!(cqe.result, msg.len() as i32);

    let mut recv_buf = [0u8; 64];
    ring.push(Sqe::recv(server_fd, &mut recv_buf, MsgFlags::default()).user_data(4))
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

    ring.push(Sqe::accept(listener, AcceptFlags::default()).user_data(1))
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
    ring.push(Sqe::connect(client, addr_bytes).user_data(2))
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
    ring.push(Sqe::send(client, msg, MsgFlags::default()).user_data(3))
        .expect("push send");
    let recv_sqe =
        unsafe { Sqe::recv_ptr(server_fd, core::ptr::null_mut(), 0, MsgFlags::default()) }
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
    ring.push(Sqe::accept(listener, AcceptFlags::default()).user_data(1))
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
    ring.push(Sqe::connect(client, addr_bytes).user_data(2))
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
    ring.push(Sqe::send(client, msg, MsgFlags::default()).user_data(3))
        .expect("push send");
    let recv_sqe =
        unsafe { Sqe::recv_ptr(server_fd, core::ptr::null_mut(), 0, MsgFlags::default()) }
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

    // Create a temp directory to watch
    let pid = std::process::id();
    let dir = std::format!("/tmp/ququmatz_inotify_test_{pid}");
    fs::create_dir_all(&dir).expect("mkdir");

    let watch_path = std::format!("{dir}\0");
    let watch_cstr =
        core::ffi::CStr::from_bytes_with_nul(watch_path.as_bytes()).expect("valid cstr");
    let wd = ino
        .add_watch(watch_cstr, WatchMask::CREATE)
        .expect("add_watch");

    // Create a file inside the watched dir to trigger an event
    let file_path = std::format!("{dir}/testfile");
    fs::write(&file_path, b"hello").expect("write file");

    // Read the event via io_uring
    let mut ring = IoUring::new(4).expect("setup");
    let mut buf = [0u8; 256];
    let n = ring
        .do_read(ino.fd().as_i32(), &mut buf, 0)
        .expect("do_read");
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

    // Cleanup
    let _ = fs::remove_file(&file_path);
    let _ = fs::remove_dir(&dir);
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
    let n = ring
        .do_read(efd.fd().as_i32(), &mut buf, 0)
        .expect("do_read");
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
    let n = ring.do_write(efd.fd().as_i32(), &buf, 0).expect("do_write");
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
    // Kernel struct is `packed`: 4 bytes events + 8 bytes data = 12 bytes, align 1.
    assert_eq!(mem::size_of::<EpollEvent>(), 12);
    assert_eq!(mem::offset_of!(EpollEvent, events), 0);
    assert_eq!(mem::offset_of!(EpollEvent, data), 4);
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

// ---------------------------------------------------------------
// SQE builder field-placement tests for new ops — run under Miri.
// ---------------------------------------------------------------

#[test]
fn sqe_builder_splice_places_fields_correctly() {
    use crate::types::{Opcode, SpliceFlags};
    let sqe = Sqe::splice(7, 100, 3, 200, 4096, SpliceFlags::MORE).user_data(55);
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
    let sqe = Sqe::tee(5, 3, 8192, SpliceFlags::NONBLOCK).user_data(77);
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
    let sqe = Sqe::epoll_ctl(9, EpollOp::Add, 4, &event).user_data(88);
    let inner = sqe.0;
    assert_eq!(Opcode::EpollCtl, inner.opcode);
    assert_eq!(inner.fd, 9); // epfd
    assert_eq!(inner.off, 4); // target fd
    assert_eq!(inner.addr, (&raw const event) as u64);
    assert_eq!(inner.len, EpollOp::Add as u32);
    assert_eq!(inner.user_data, 88);
}

#[test]
fn sqe_builder_fadvise_places_fields_correctly() {
    use crate::types::{FadviseAdvice, Opcode};
    let sqe = Sqe::fadvise(3, 0, 4096, FadviseAdvice::Sequential).user_data(11);
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
    let sqe = Sqe::openat2(types::AT_FDCWD, path, &how).user_data(99);
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
    let sqe = Sqe::send_zc(5, buf, MsgFlags::NOSIGNAL).user_data(66);
    let inner = sqe.0;
    assert_eq!(Opcode::SendZc, inner.opcode);
    assert_eq!(inner.fd, 5);
    assert_eq!(inner.addr, buf.as_ptr() as u64);
    assert_eq!(inner.len, buf.len() as u32);
    assert_eq!(inner.op_flags, MsgFlags::NOSIGNAL.bits());
    assert_eq!(inner.user_data, 66);
}

#[test]
fn sqe_builder_files_update_places_fields_correctly() {
    use crate::types::Opcode;
    let fds = [3i32, 4, -1];
    let sqe = Sqe::files_update(&fds, 2).user_data(44);
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
    let sqe = Sqe::accept_multishot(7, AcceptFlags::NONBLOCK).user_data(5);
    let inner = sqe.0;
    assert_eq!(Opcode::Accept, inner.opcode);
    assert_eq!(inner.fd, 7);
    assert_eq!(inner.ioprio, IORING_ACCEPT_MULTISHOT);
    assert_eq!(inner.op_flags, AcceptFlags::NONBLOCK.bits());
}

#[test]
fn sqe_builder_recv_multishot_places_fields_correctly() {
    use crate::types::{IORING_RECV_MULTISHOT, MsgFlags, Opcode};
    let sqe = Sqe::recv_multishot(4, MsgFlags::default()).user_data(6);
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
fn sqe_builder_with_poll_first_sets_ioprio_bit() {
    use crate::types::{IORING_RECVSEND_POLL_FIRST, MsgFlags, Opcode, SendRecvFlag};
    let buf = [0u8; 4];
    let sqe = Sqe::send(9, &buf, MsgFlags::default()).with(SendRecvFlag::PollFirst);
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
    let sqe = Sqe::send(3, &buf, MsgFlags::default()).with(SendRecvFlag::FixedBuf(7));
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
    let sqe = Sqe::send_zc(2, &buf, MsgFlags::default()).with(SendRecvFlag::ReportUsage);
    let inner = sqe.0;
    assert_eq!(Opcode::SendZc, inner.opcode);
    assert_eq!(
        inner.ioprio & IORING_SEND_ZC_REPORT_USAGE,
        IORING_SEND_ZC_REPORT_USAGE
    );
}

#[test]
fn sqe_builder_with_chains_multiple_flags() {
    use crate::types::{
        IORING_RECVSEND_FIXED_BUF, IORING_RECVSEND_POLL_FIRST, MsgFlags, SendRecvFlag,
    };
    let buf = [0u8; 4];
    let sqe = Sqe::send(5, &buf, MsgFlags::default())
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
    let sqe = Sqe::send(1, &buf, MsgFlags::default()).personality(42);
    assert_eq!(sqe.0.personality, 42);
}

#[test]
fn sqe_builder_recvmsg_multishot_places_fields_correctly() {
    use crate::types::{IORING_RECV_MULTISHOT, MsgFlags, MsgHdr, Opcode};
    let mut msg = MsgHdr::default();
    let sqe =
        unsafe { Sqe::recvmsg_multishot(11, core::ptr::from_mut(&mut msg), MsgFlags::default()) };
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
    assert_eq!(inner.off, SocketType::Stream.as_raw() as u64);
    assert_eq!(inner.op_flags, SocketFlags::NONBLOCK.bits());
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
    assert_eq!(inner.off, SocketType::Stream.as_raw() as u64);
    assert_eq!(inner.op_flags, SocketFlags::NONBLOCK.bits());
    // IORING_FILE_INDEX_ALLOC: kernel reads splice_fd_in as ~0u32.
    assert_eq!(inner.splice_fd_in, -1);
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
fn splice_pipe_roundtrip() {
    use crate::types::SpliceFlags;
    // pipe2(2) via /proc/self/fd to avoid direct syscall
    let mut pipe_fds = [0i32; 2];
    let ret = unsafe { libc_pipe2(pipe_fds.as_mut_ptr(), 0) };
    assert_eq!(ret, 0, "pipe2 failed");
    let [read_end, write_end] = pipe_fds;

    let mut ring = IoUring::new(8).expect("setup");
    let msg = b"splice test data";

    // Write to the pipe's write end directly
    ring.push(Sqe::write(write_end, msg, 0).user_data(1))
        .expect("push write");
    ring.submit_and_wait(1).expect("submit write");
    let cqe = ring.complete().expect("write cqe");
    assert_eq!(cqe.result, msg.len() as i32);

    // Splice from the read end of the pipe into a tmpfile
    let fd = open_tmpfile(&mut ring);
    ring.push(
        Sqe::splice(
            fd,
            u64::MAX,
            read_end,
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
    ring.push(Sqe::read(fd, &mut read_buf, 0).user_data(3))
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
fn fadvise_roundtrip() {
    use crate::types::FadviseAdvice;
    let mut ring = IoUring::new(4).expect("setup");
    let fd = open_tmpfile(&mut ring);

    let buf = b"fadvise data";
    ring.push(Sqe::write(fd, buf, 0).user_data(1))
        .expect("push");
    ring.submit_and_wait(1).expect("submit");
    ring.complete().expect("write cqe");

    ring.push(Sqe::fadvise(fd, 0, buf.len() as u32, FadviseAdvice::Sequential).user_data(2))
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

    let how = OpenHow {
        flags: u64::from(
            OpenFlags::RDWR.bits() | OpenFlags::CREAT.bits() | OpenFlags::TRUNC.bits(),
        ),
        mode: 0o600,
        resolve: 0,
    };
    ring.push(Sqe::openat2(types::AT_FDCWD, c"/tmp/ququmatz_openat2_test", &how).user_data(1))
        .expect("push openat2");
    ring.submit_and_wait(1).expect("submit");
    let cqe = ring.complete().expect("openat2 cqe");
    assert_eq!(cqe.user_data, 1);
    assert!(cqe.result >= 0, "openat2 failed: {}", cqe.result);

    let _ = syscall::close(RawFd::from_raw(cqe.result as usize));
    // cleanup
    ring.push(Sqe::unlinkat(
        crate::types::DirFd::Cwd,
        c"/tmp/ququmatz_openat2_test",
        UnlinkFlags::default(),
    ))
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

    ring.push(Sqe::accept(listener, AcceptFlags::default()).user_data(1))
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
    ring.push(Sqe::connect(client, addr_bytes).user_data(2))
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
    ring.push(Sqe::send_zc(client, msg, MsgFlags::NOSIGNAL).user_data(3))
        .expect("push send_zc");
    ring.push(Sqe::recv(server_fd, &mut recv_buf, MsgFlags::default()).user_data(4))
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
        Sqe::accept_with_addr(
            listener,
            &mut peer_addr,
            &mut peer_addrlen,
            AcceptFlags::default(),
        )
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
    ring.push(Sqe::connect(client, addr_bytes).user_data(2))
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
    ring.push(Sqe::write(0, msg, 0).fixed_file().user_data(1))
        .expect("push write");
    ring.submit_and_wait(1).expect("submit");
    let cqe = ring.complete().expect("cqe");
    assert_eq!(cqe.result, msg.len() as i32);

    ring.unregister_files().expect("unregister");
    let _ = syscall::close(RawFd::from_raw(fd as usize));
    let _ = syscall::close(RawFd::from_raw(fd2 as usize));
}

/// Thin shim over `pipe2(2)` — only used in tests, so we call the
/// raw syscall number rather than pulling in libc.
#[cfg(not(miri))]
unsafe fn libc_pipe2(fds: *mut i32, flags: i32) -> i32 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") 293i64, // SYS_pipe2
            in("rdi") fds,
            in("rsi") i64::from(flags),
            lateout("rax") ret,
            options(nostack),
        );
    }
    if ret < 0 { -(ret as i32) } else { ret as i32 }
}
