use core::arch::asm;

pub const SYS_READ: usize = 3;
pub const SYS_WRITE: usize = 4;
pub const SYS_CLOSE: usize = 6;
pub const SYS_MMAP2: usize = 192;
pub const SYS_MUNMAP: usize = 91;
pub const SYS_SOCKET: usize = 281;
pub const SYS_CONNECT: usize = 283;
pub const SYS_ACCEPT4: usize = 366;
pub const SYS_SENDTO: usize = 290;
pub const SYS_RECVFROM: usize = 292;
pub const SYS_SHUTDOWN: usize = 293;
pub const SYS_BIND: usize = 282;
pub const SYS_LISTEN: usize = 284;
pub const SYS_GETSOCKNAME: usize = 286;
pub const SYS_SETSOCKOPT: usize = 294;
pub const SYS_PIPE2: usize = 359;
pub const SYS_EVENTFD2: usize = 356;
pub const SYS_INOTIFY_INIT1: usize = 360;
pub const SYS_INOTIFY_ADD_WATCH: usize = 317;
pub const SYS_INOTIFY_RM_WATCH: usize = 318;
pub const SYS_IO_URING_SETUP: usize = 425;
pub const SYS_IO_URING_ENTER: usize = 426;
pub const SYS_IO_URING_REGISTER: usize = 427;

#[inline]
pub unsafe fn syscall1(nr: usize, a1: usize) -> isize {
    let ret: isize;
    unsafe {
        asm!(
            "svc #0",
            inlateout("r0") a1 as isize => ret,
            in("r7") nr,
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
            inlateout("r0") a1 as isize => ret,
            in("r1") a2,
            in("r7") nr,
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
            inlateout("r0") a1 as isize => ret,
            in("r1") a2,
            in("r2") a3,
            in("r7") nr,
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
            inlateout("r0") a1 as isize => ret,
            in("r1") a2,
            in("r2") a3,
            in("r3") a4,
            in("r7") nr,
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
            inlateout("r0") a1 as isize => ret,
            in("r1") a2,
            in("r2") a3,
            in("r3") a4,
            in("r4") a5,
            in("r7") nr,
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
            inlateout("r0") a1 as isize => ret,
            in("r1") a2,
            in("r2") a3,
            in("r3") a4,
            in("r4") a5,
            in("r5") a6,
            in("r7") nr,
            options(nostack),
        );
    }
    ret
}
