#![no_std]
#![cfg(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64",
    target_arch = "arm"
))]

mod error;
pub mod eventfd;
pub mod inotify;
pub mod net;
pub mod op;
pub(crate) mod syscall;
pub mod types;

mod ring;

pub use error::Error;
pub use eventfd::EventFd;
pub use inotify::Inotify;
pub use net::Socket;
pub use op::Sqe;
pub use ring::{
    Completer, Completion, Completions, IoUring, IoUringBuilder, ProvidedBufferRing,
    SplitCompletions, Submitter,
};
pub use types::{
    CqeFlags, EventFdFlags, Features, InotifyEvent, IoUringBuf, IoUringBufReg, IoVec, RawFd,
    SetupFlags, SocketFlags, SqeFlags, TimeoutFlags, Timespec, WatchMask,
};

#[cfg(test)]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
mod tests {
    extern crate std;
    use std::{vec, vec::Vec};

    use super::*;
    use crate::types::{
        AcceptFlags, EventFdFlags, FileMode, FsyncFlags, IN_CLOEXEC, IN_NONBLOCK, InotifyEvent,
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
        let path = c"/tmp/test";
        let sqe = Sqe::openat(
            types::AT_FDCWD,
            path,
            OpenFlags::default(),
            FileMode::OWNER_READ
                | FileMode::OWNER_WRITE
                | FileMode::GROUP_READ
                | FileMode::OTHER_READ,
        )
        .user_data(77);
        let inner = sqe.0;

        assert_eq!(Opcode::Openat, inner.opcode);
        assert_eq!(inner.fd, types::AT_FDCWD);
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

        let _ = syscall::close(fd as usize);
    }

    #[cfg(not(miri))]
    #[test]
    fn statx_on_tmp() {
        let mut ring = IoUring::new(4).expect("setup");
        let mut buf = Statx::default();

        ring.push(
            Sqe::statx(
                types::AT_FDCWD,
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
            types::AT_FDCWD,
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

        let _ = syscall::close(fd as usize);
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
            unsafe { Sqe::write_fixed(fd, buf.as_ptr(), msg.len() as u32, 0, 0) }.user_data(1),
        )
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
        let _ = syscall::close(fd as usize);
    }

    #[cfg(not(miri))]
    #[test]
    fn registered_files() {
        let mut ring = IoUring::new(4).expect("setup");
        let fd = open_tmpfile(&mut ring);

        ring.register_files(&[fd]).expect("register_files");
        ring.unregister_files().expect("unregister_files");

        let _ = syscall::close(fd as usize);
    }

    #[cfg(not(miri))]
    fn setup_tcp_listener() -> (i32, u16) {
        let fd = syscall::socket(types::AF_INET, types::SOCK_STREAM | types::SOCK_NONBLOCK, 0)
            .expect("socket") as i32;

        let one: i32 = 1;
        syscall::setsockopt(
            fd as usize,
            types::SOL_SOCKET,
            types::SO_REUSEADDR,
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
            fd as usize,
            (&raw const addr).cast(),
            core::mem::size_of::<SockAddrIn>() as u32,
        )
        .expect("bind");
        syscall::listen(fd as usize, 1).expect("listen");

        // Retrieve the actual port assigned by the kernel
        let mut bound_addr = SockAddrIn::default();
        let mut addrlen = core::mem::size_of::<SockAddrIn>() as u32;
        syscall::getsockname(fd as usize, (&raw mut bound_addr).cast(), &raw mut addrlen)
            .expect("getsockname");

        (fd, u16::from_be(bound_addr.sin_port))
    }

    #[cfg(not(miri))]
    #[test]
    fn tcp_send_recv_roundtrip() {
        let mut ring = IoUring::new(8).expect("setup");
        let (listener, port) = setup_tcp_listener();

        let client = syscall::socket(types::AF_INET, types::SOCK_STREAM | types::SOCK_NONBLOCK, 0)
            .expect("client socket") as i32;

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

        let _ = syscall::close(server_fd as usize);
        let _ = syscall::close(client as usize);
        let _ = syscall::close(listener as usize);
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
            .expect("client socket") as i32;

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
        let _ = syscall::close(server_fd as usize);
        let _ = syscall::close(client as usize);
        let _ = syscall::close(listener as usize);
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
            .expect("client socket") as i32;

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

        let _ = syscall::close(server_fd as usize);
        let _ = syscall::close(client as usize);
        let _ = syscall::close(listener as usize);
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
    fn in_nonblock_value() {
        assert_eq!(IN_NONBLOCK, 0o4000);
    }

    #[test]
    fn in_cloexec_value() {
        assert_eq!(IN_CLOEXEC, 0o2_000_000);
    }

    // ---------------------------------------------------------------
    // Inotify kernel integration tests — skipped under Miri.
    // ---------------------------------------------------------------

    #[cfg(not(miri))]
    #[test]
    fn inotify_new_returns_valid_fd() {
        let ino = Inotify::new().expect("inotify_init1");
        assert!(ino.fd() >= 0);
    }

    #[cfg(not(miri))]
    #[test]
    fn inotify_into_fd_prevents_double_close() {
        let ino = Inotify::new().expect("inotify_init1");
        let fd = ino.into_fd();
        assert!(fd >= 0);
        // Manually close — should succeed exactly once.
        syscall::close(fd as usize).expect("close");
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
        let ino = Inotify::new().expect("inotify_init1");
        let err = ino.remove_watch(9999).unwrap_err();
        assert_eq!(err, Error::EINVAL);
    }

    #[cfg(not(miri))]
    #[test]
    fn inotify_add_watch_bad_path_returns_error() {
        let ino = Inotify::new().expect("inotify_init1");
        let err = ino
            .add_watch(c"/nonexistent_path_ququmatz_test", WatchMask::MODIFY)
            .unwrap_err();
        assert_eq!(err, Error::ENOENT);
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
        assert!(efd.fd() >= 0);
    }

    #[cfg(not(miri))]
    #[test]
    fn eventfd_into_fd_prevents_double_close() {
        let efd = EventFd::new(0).expect("eventfd2");
        let fd = efd.into_fd();
        assert!(fd >= 0);
        syscall::close(fd as usize).expect("close");
    }

    #[cfg(not(miri))]
    #[test]
    fn eventfd_with_flags() {
        let efd = EventFd::with_flags(0, EventFdFlags::NONBLOCK | EventFdFlags::CLOEXEC)
            .expect("eventfd2");
        assert!(efd.fd() >= 0);
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
        let efd = EventFd::new(0).expect("eventfd2");
        efd.write(5).expect("write");
        let _ = efd.read().expect("read");
        // Counter is now 0 — reading again should return EAGAIN
        let err = efd.read().unwrap_err();
        assert_eq!(err, Error::EAGAIN);
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
        let efd = EventFd::with_flags(0, EventFdFlags::NONBLOCK | EventFdFlags::SEMAPHORE)
            .expect("eventfd2");
        efd.write(3).expect("write");
        // In semaphore mode, each read returns 1 and decrements by 1
        assert_eq!(efd.read().expect("read 1"), 1);
        assert_eq!(efd.read().expect("read 2"), 1);
        assert_eq!(efd.read().expect("read 3"), 1);
        // Counter exhausted
        let err = efd.read().unwrap_err();
        assert_eq!(err, Error::EAGAIN);
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
}
