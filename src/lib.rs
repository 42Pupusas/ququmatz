#![no_std]
#![cfg(target_arch = "x86_64")]

mod error;
pub mod op;
pub(crate) mod syscall;
pub mod types;

mod ring;

pub use error::Error;
pub use op::Sqe;
pub use ring::{Completion, Completions, IoUring, IoUringBuilder};
pub use types::{
    CqeFlags, Features, IoVec, RawFd, SetupFlags, SqeFlags, TimeoutFlags, Timespec,
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
        AcceptFlags, FileMode, FsyncFlags, IoUringCqe, IoUringParams, IoUringSqe, MsgFlags, Opcode,
        OpenFlags, PollMask, SockAddrIn, SqeFlags, Statx, StatxFlags, StatxMask,
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
        let sqe = unsafe { Sqe::read(42, buf.as_mut_ptr(), 32, 100) }.user_data(99);
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
        let sqe = unsafe { Sqe::write(7, buf.as_ptr(), 16, 0) }.user_data(55);
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
        let vecs = [IoVec {
            base: buf.as_mut_ptr(),
            len: buf.len(),
        }];
        let sqe = unsafe { Sqe::readv(3, vecs.as_ptr(), 1, 50) }.user_data(10);
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
        let sqe = unsafe {
            Sqe::openat(
                types::AT_FDCWD,
                path.as_ptr().cast(),
                OpenFlags::RDONLY,
                FileMode::OWNER_READ | FileMode::OWNER_WRITE | FileMode::GROUP_READ | FileMode::OTHER_READ,
            )
        }
        .user_data(77);
        let inner = sqe.0;

        assert_eq!(Opcode::Openat, inner.opcode);
        assert_eq!(inner.fd, types::AT_FDCWD);
        assert_eq!(inner.addr, path.as_ptr() as u64);
        assert_eq!(inner.len, 0o644);
        assert_eq!(inner.op_flags, OpenFlags::RDONLY.bits());
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
        let sqe = unsafe { Sqe::timeout(&raw const ts, 3, TimeoutFlags::default()) }.user_data(42);
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
        assert_eq!(ts.tv_sec, 1);
        assert_eq!(ts.tv_nsec, 500_000_000);

        let ts = Timespec::from_millis(50);
        assert_eq!(ts.tv_sec, 0);
        assert_eq!(ts.tv_nsec, 50_000_000);
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
    }

    #[cfg(not(miri))]
    #[test]
    fn fsync_on_tmpfile() {
        let mut ring = IoUring::new(4).expect("setup");
        let fd = open_tmpfile();

        // Write some data first
        let buf = b"fsync test";
        ring.push(unsafe { Sqe::write(fd, buf.as_ptr(), buf.len() as u32, 0) }.user_data(1))
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
            unsafe {
                Sqe::statx(
                    types::AT_FDCWD,
                    c"/tmp".as_ptr().cast(),
                    StatxFlags::default(),
                    StatxMask::BASIC_STATS,
                    &raw mut buf,
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
        ring.push(unsafe { Sqe::timeout(&raw const ts, 0, TimeoutFlags::default()) }.user_data(1))
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
    fn open_tmpfile() -> i32 {
        syscall::openat(
            types::AT_FDCWD,
            c"/tmp".as_ptr().cast(),
            OpenFlags::TMPFILE | OpenFlags::RDWR,
            FileMode::OWNER_READ | FileMode::OWNER_WRITE,
        )
        .expect("failed to open tmpfile") as i32
    }

    #[cfg(not(miri))]
    #[test]
    fn read_write_roundtrip() {
        let mut ring = IoUring::new(4).expect("failed to create io_uring");
        let fd = open_tmpfile();

        let write_buf = b"hello io_uring!";
        ring.push(
            unsafe { Sqe::write(fd, write_buf.as_ptr(), write_buf.len() as u32, 0) }.user_data(1),
        )
        .expect("failed to push write");
        ring.submit_and_wait(1).expect("failed to submit write");

        let cqe = ring.complete().expect("expected write completion");
        assert_eq!(cqe.user_data, 1);
        assert_eq!(cqe.result, write_buf.len() as i32);

        let mut read_buf = [0u8; 64];
        ring.push(
            unsafe { Sqe::read(fd, read_buf.as_mut_ptr(), read_buf.len() as u32, 0) }.user_data(2),
        )
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
        let fd = open_tmpfile();

        let mut buf_a = *b"hello ";
        let mut buf_b = *b"world!";
        let write_vecs = [
            IoVec {
                base: buf_a.as_mut_ptr(),
                len: buf_a.len(),
            },
            IoVec {
                base: buf_b.as_mut_ptr(),
                len: buf_b.len(),
            },
        ];
        ring.push(unsafe { Sqe::writev(fd, write_vecs.as_ptr(), 2, 0) }.user_data(1))
            .expect("failed to push writev");
        ring.submit_and_wait(1).expect("failed to submit writev");

        let cqe = ring.complete().expect("expected writev completion");
        assert_eq!(cqe.user_data, 1);
        assert_eq!(cqe.result as usize, buf_a.len() + buf_b.len());

        let mut read_buf = [0u8; 64];
        let read_vecs = [IoVec {
            base: read_buf.as_mut_ptr(),
            len: read_buf.len(),
        }];
        ring.push(unsafe { Sqe::readv(fd, read_vecs.as_ptr(), 1, 0) }.user_data(2))
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
        let fd = open_tmpfile();

        // Create and register a buffer
        let mut buf = vec![0u8; 4096];
        let iov = [IoVec {
            base: buf.as_mut_ptr(),
            len: buf.len(),
        }];
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
        let fd = open_tmpfile();

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
        ring.push(
            unsafe {
                Sqe::accept(
                    listener,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    AcceptFlags::NONE,
                )
            }
            .user_data(1),
        )
        .expect("push accept");

        let connect_addr = SockAddrIn {
            sin_family: types::AF_INET as u16,
            sin_port: port.to_be(),
            sin_addr: u32::from_ne_bytes([127, 0, 0, 1]),
            sin_zero: [0; 8],
        };
        ring.push(
            unsafe {
                Sqe::connect(
                    client,
                    (&raw const connect_addr).cast(),
                    core::mem::size_of::<SockAddrIn>() as u32,
                )
            }
            .user_data(2),
        )
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
            unsafe { Sqe::send(client, msg.as_ptr(), msg.len() as u32, MsgFlags::NONE) }
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
                    server_fd,
                    recv_buf.as_mut_ptr(),
                    recv_buf.len() as u32,
                    MsgFlags::NONE,
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

        let _ = syscall::close(server_fd as usize);
        let _ = syscall::close(client as usize);
        let _ = syscall::close(listener as usize);
    }
}
