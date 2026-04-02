use core::arch::asm;

pub const SYS_CLOSE: usize = 57;
pub const SYS_MMAP: usize = 222;
pub const SYS_MUNMAP: usize = 215;
pub const SYS_SOCKET: usize = 198;
pub const SYS_CONNECT: usize = 203;
pub const SYS_ACCEPT4: usize = 242;
pub const SYS_SENDTO: usize = 206;
pub const SYS_RECVFROM: usize = 207;
pub const SYS_SHUTDOWN: usize = 210;
pub const SYS_BIND: usize = 200;
pub const SYS_LISTEN: usize = 201;
pub const SYS_GETSOCKNAME: usize = 204;
pub const SYS_SETSOCKOPT: usize = 208;
pub const SYS_OPENAT: usize = 56;
pub const SYS_IO_URING_SETUP: usize = 425;
pub const SYS_IO_URING_ENTER: usize = 426;
pub const SYS_IO_URING_REGISTER: usize = 427;

#[inline]
pub unsafe fn syscall1(nr: usize, a1: usize) -> isize {
    let ret: isize;
    unsafe {
        asm!(
            "svc #0",
            inlateout("x0") a1 as isize => ret,
            in("x8") nr,
            options(nostack),
        );
    }
    ret
}

#[inline]
pub unsafe fn syscall2(nr: usize, a1: usize, a2: usize) -> isize {
    let ret: isize;
    unsafe {
        asm!(
            "svc #0",
            inlateout("x0") a1 as isize => ret,
            in("x1") a2,
            in("x8") nr,
            options(nostack),
        );
    }
    ret
}

#[inline]
pub unsafe fn syscall3(nr: usize, a1: usize, a2: usize, a3: usize) -> isize {
    let ret: isize;
    unsafe {
        asm!(
            "svc #0",
            inlateout("x0") a1 as isize => ret,
            in("x1") a2,
            in("x2") a3,
            in("x8") nr,
            options(nostack),
        );
    }
    ret
}

#[inline]
pub unsafe fn syscall4(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> isize {
    let ret: isize;
    unsafe {
        asm!(
            "svc #0",
            inlateout("x0") a1 as isize => ret,
            in("x1") a2,
            in("x2") a3,
            in("x3") a4,
            in("x8") nr,
            options(nostack),
        );
    }
    ret
}

#[inline]
pub unsafe fn syscall5(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> isize {
    let ret: isize;
    unsafe {
        asm!(
            "svc #0",
            inlateout("x0") a1 as isize => ret,
            in("x1") a2,
            in("x2") a3,
            in("x3") a4,
            in("x4") a5,
            in("x8") nr,
            options(nostack),
        );
    }
    ret
}

#[inline]
pub unsafe fn syscall6(
    nr: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
) -> isize {
    let ret: isize;
    unsafe {
        asm!(
            "svc #0",
            inlateout("x0") a1 as isize => ret,
            in("x1") a2,
            in("x2") a3,
            in("x3") a4,
            in("x4") a5,
            in("x5") a6,
            in("x8") nr,
            options(nostack),
        );
    }
    ret
}
