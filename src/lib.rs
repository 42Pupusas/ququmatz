mod error;
pub mod op;
pub(crate) mod syscall;
pub mod types;

mod ring;

pub use error::Error;
pub use op::Sqe;
pub use ring::{Completion, Completions, IoUring};
pub use types::IoVec;

#[cfg(test)]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
mod tests {
    use super::*;
    use crate::types::{IoUringCqe, IoUringParams, IoUringSqe};
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
        // Verify field offsets match the kernel's io_uring_sqe layout.
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
        let sqe = Sqe::read(42, buf.as_mut_ptr(), 32, 100).user_data(99);
        let inner = sqe.0;

        assert_eq!(inner.opcode, types::IORING_OP_READ);
        assert_eq!(inner.fd, 42);
        assert_eq!(inner.addr, buf.as_mut_ptr() as u64);
        assert_eq!(inner.len, 32);
        assert_eq!(inner.off, 100);
        assert_eq!(inner.user_data, 99);
    }

    #[test]
    fn sqe_builder_write_places_fields_correctly() {
        let buf = [1u8; 16];
        let sqe = Sqe::write(7, buf.as_ptr(), 16, 0).user_data(55);
        let inner = sqe.0;

        assert_eq!(inner.opcode, types::IORING_OP_WRITE);
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
        let sqe = Sqe::readv(3, vecs.as_ptr(), 1, 50).user_data(10);
        let inner = sqe.0;

        assert_eq!(inner.opcode, types::IORING_OP_READV);
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
            path.as_ptr().cast(),
            types::O_RDONLY,
            0o644,
        )
        .user_data(77);
        let inner = sqe.0;

        assert_eq!(inner.opcode, types::IORING_OP_OPENAT);
        assert_eq!(inner.fd, types::AT_FDCWD);
        assert_eq!(inner.addr, path.as_ptr() as u64);
        assert_eq!(inner.len, 0o644);
        assert_eq!(inner.op_flags, types::O_RDONLY as u32);
        assert_eq!(inner.user_data, 77);
    }

    #[test]
    fn sqe_builder_close_places_fields_correctly() {
        let sqe = Sqe::close(5).user_data(88);
        let inner = sqe.0;

        assert_eq!(inner.opcode, types::IORING_OP_CLOSE);
        assert_eq!(inner.fd, 5);
        assert_eq!(inner.user_data, 88);
    }

    #[test]
    fn sqe_builder_nop_places_fields_correctly() {
        let sqe = Sqe::nop().user_data(123).flags(0x04);
        let inner = sqe.0;

        assert_eq!(inner.opcode, types::IORING_OP_NOP);
        assert_eq!(inner.user_data, 123);
        assert_eq!(inner.flags, 0x04);
    }

    // ---------------------------------------------------------------
    // Simulated ring index math — exercises the same wrapping/masking
    // logic as the real ring, but on heap memory so Miri can check it.
    // ---------------------------------------------------------------

    #[test]
    fn ring_index_wrapping() {
        // Simulate a 4-entry ring (mask = 3)
        let mask: u32 = 3;
        let mut sqes = [IoUringSqe::default(); 4];
        let mut sq_array = [0u32; 4];

        // Fill all 4 slots, wrapping the tail
        for i in 0u32..4 {
            let idx = i & mask;
            sqes[idx as usize] = IoUringSqe {
                opcode: types::IORING_OP_NOP,
                user_data: u64::from(i),
                ..IoUringSqe::default()
            };
            sq_array[idx as usize] = idx;
        }

        // Verify each slot
        for i in 0u32..4 {
            let idx = i & mask;
            assert_eq!(sqes[idx as usize].user_data, u64::from(i));
            assert_eq!(sq_array[idx as usize], idx);
        }

        // Wrap around: slot 4 maps to index 0
        let wrap_idx = 4u32 & mask;
        assert_eq!(wrap_idx, 0);
        sqes[wrap_idx as usize].user_data = 999;
        assert_eq!(sqes[0].user_data, 999);
    }

    #[test]
    fn cq_index_wrapping() {
        // Simulate a 4-entry CQ ring
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

        // Read in order with wrapping
        for i in 0u32..4 {
            let idx = i & mask;
            assert_eq!(cqes[idx as usize].user_data, u64::from(10 + i));
        }

        // Wrap: index 4 maps back to 0
        assert_eq!(cqes[(4u32 & mask) as usize].user_data, 10);
    }

    // ---------------------------------------------------------------
    // Kernel integration tests — skipped under Miri (they need syscalls).
    // ---------------------------------------------------------------

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
            types::O_TMPFILE | types::O_RDWR,
            types::S_IRUSR | types::S_IWUSR,
        )
        .expect("failed to open tmpfile") as i32
    }

    #[cfg(not(miri))]
    #[test]
    fn read_write_roundtrip() {
        let mut ring = IoUring::new(4).expect("failed to create io_uring");
        let fd = open_tmpfile();

        // Write data
        let write_buf = b"hello io_uring!";
        ring.push(Sqe::write(fd, write_buf.as_ptr(), write_buf.len() as u32, 0).user_data(1))
            .expect("failed to push write");
        ring.submit_and_wait(1).expect("failed to submit write");

        let cqe = ring.complete().expect("expected write completion");
        assert_eq!(cqe.user_data, 1);
        assert_eq!(cqe.result, write_buf.len() as i32);

        // Read it back
        let mut read_buf = [0u8; 64];
        ring.push(Sqe::read(fd, read_buf.as_mut_ptr(), read_buf.len() as u32, 0).user_data(2))
            .expect("failed to push read");
        ring.submit_and_wait(1).expect("failed to submit read");

        let cqe = ring.complete().expect("expected read completion");
        assert_eq!(cqe.user_data, 2);
        assert_eq!(cqe.result, write_buf.len() as i32);
        assert_eq!(&read_buf[..write_buf.len()], write_buf);

        // Close via io_uring
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

        // Vectored write: two buffers
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
        ring.push(Sqe::writev(fd, write_vecs.as_ptr(), 2, 0).user_data(1))
            .expect("failed to push writev");
        ring.submit_and_wait(1).expect("failed to submit writev");

        let cqe = ring.complete().expect("expected writev completion");
        assert_eq!(cqe.user_data, 1);
        assert_eq!(cqe.result as usize, buf_a.len() + buf_b.len());

        // Vectored read into a single buffer
        let mut read_buf = [0u8; 64];
        let read_vecs = [IoVec {
            base: read_buf.as_mut_ptr(),
            len: read_buf.len(),
        }];
        ring.push(Sqe::readv(fd, read_vecs.as_ptr(), 1, 0).user_data(2))
            .expect("failed to push readv");
        ring.submit_and_wait(1).expect("failed to submit readv");

        let cqe = ring.complete().expect("expected readv completion");
        assert_eq!(cqe.user_data, 2);
        let total = buf_a.len() + buf_b.len();
        assert_eq!(cqe.result as usize, total);
        assert_eq!(&read_buf[..total], b"hello world!");

        let _ = syscall::close(fd as usize);
    }
}
