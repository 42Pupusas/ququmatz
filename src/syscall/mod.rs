#![allow(
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::missing_errors_doc
)]

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
use x86_64 as arch;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
use aarch64 as arch;

#[cfg(target_arch = "riscv64")]
mod riscv64;
#[cfg(target_arch = "riscv64")]
use riscv64 as arch;

#[cfg(target_arch = "arm")]
mod arm;
#[cfg(target_arch = "arm")]
use arm as arch;

use crate::error::Errno;
use crate::types::RawFd;
#[allow(clippy::wildcard_imports)]
use arch::*;

const fn check(ret: isize) -> Result<usize, Errno> {
    if ret < 0 {
        Err(Errno((-ret) as i32))
    } else {
        Ok(ret as usize)
    }
}

pub fn io_uring_setup(
    entries: u32,
    params: *mut crate::types::IoUringParams,
) -> Result<RawFd, Errno> {
    check(unsafe { syscall2(SYS_IO_URING_SETUP, entries as usize, params as usize) })
        .map(RawFd::from_raw)
}

pub fn io_uring_enter(
    fd: RawFd,
    to_submit: u32,
    min_complete: u32,
    flags: crate::types::EnterFlags,
) -> Result<usize, Errno> {
    check(unsafe {
        syscall6(
            SYS_IO_URING_ENTER,
            fd.as_usize(),
            to_submit as usize,
            min_complete as usize,
            flags.bits() as usize,
            0, // sig
            0, // sigsz
        )
    })
}

pub fn mmap(
    addr: usize,
    len: usize,
    prot: crate::types::Prot,
    flags: crate::types::MapFlags,
    fd: usize,
    offset: u64,
) -> Result<usize, Errno> {
    // ARM 32-bit uses mmap2 which takes a page-granularity offset (offset / 4096)
    #[cfg(target_arch = "arm")]
    let nr = SYS_MMAP2;
    #[cfg(not(target_arch = "arm"))]
    let nr = SYS_MMAP;

    #[cfg(target_arch = "arm")]
    let off = (offset as usize) >> 12;
    #[cfg(not(target_arch = "arm"))]
    let off = offset as usize;

    check(unsafe {
        syscall6(
            nr,
            addr,
            len,
            prot.bits() as usize,
            flags.bits() as usize,
            fd,
            off,
        )
    })
}

pub fn munmap(addr: usize, len: usize) -> Result<(), Errno> {
    check(unsafe { syscall2(SYS_MUNMAP, addr, len) })?;
    Ok(())
}

pub fn socket(domain: i32, sock_type: i32, protocol: i32) -> Result<RawFd, Errno> {
    check(unsafe {
        syscall3(
            SYS_SOCKET,
            domain as usize,
            sock_type as usize,
            protocol as usize,
        )
    })
    .map(RawFd::from_raw)
}

pub fn connect(fd: RawFd, addr: *const u8, addrlen: u32) -> Result<(), Errno> {
    check(unsafe { syscall3(SYS_CONNECT, fd.as_usize(), addr as usize, addrlen as usize) })?;
    Ok(())
}

pub fn accept4(fd: RawFd, addr: *mut u8, addrlen: *mut u32, flags: i32) -> Result<RawFd, Errno> {
    check(unsafe {
        syscall4(
            SYS_ACCEPT4,
            fd.as_usize(),
            addr as usize,
            addrlen as usize,
            flags as usize,
        )
    })
    .map(RawFd::from_raw)
}

pub fn bind(fd: RawFd, addr: *const u8, addrlen: u32) -> Result<(), Errno> {
    check(unsafe { syscall3(SYS_BIND, fd.as_usize(), addr as usize, addrlen as usize) })?;
    Ok(())
}

pub fn listen(fd: RawFd, backlog: i32) -> Result<(), Errno> {
    check(unsafe { syscall2(SYS_LISTEN, fd.as_usize(), backlog as usize) })?;
    Ok(())
}

pub fn getsockname(fd: RawFd, addr: *mut u8, addrlen: *mut u32) -> Result<(), Errno> {
    check(unsafe {
        syscall3(
            SYS_GETSOCKNAME,
            fd.as_usize(),
            addr as usize,
            addrlen as usize,
        )
    })?;
    Ok(())
}

pub fn setsockopt(
    fd: RawFd,
    level: i32,
    optname: i32,
    optval: *const u8,
    optlen: u32,
) -> Result<(), Errno> {
    check(unsafe {
        syscall5(
            SYS_SETSOCKOPT,
            fd.as_usize(),
            level as usize,
            optname as usize,
            optval as usize,
            optlen as usize,
        )
    })?;
    Ok(())
}

pub fn io_uring_register(fd: RawFd, opcode: u32, arg: usize, nr_args: u32) -> Result<usize, Errno> {
    check(unsafe {
        syscall4(
            SYS_IO_URING_REGISTER,
            fd.as_usize(),
            opcode as usize,
            arg,
            nr_args as usize,
        )
    })
}

pub fn sendto(fd: RawFd, buf: *const u8, len: usize, flags: u32) -> Result<usize, Errno> {
    check(unsafe {
        syscall6(
            SYS_SENDTO,
            fd.as_usize(),
            buf as usize,
            len,
            flags as usize,
            0,
            0,
        )
    })
}

pub fn recvfrom(fd: RawFd, buf: *mut u8, len: usize, flags: u32) -> Result<usize, Errno> {
    check(unsafe {
        syscall6(
            SYS_RECVFROM,
            fd.as_usize(),
            buf as usize,
            len,
            flags as usize,
            0,
            0,
        )
    })
}

pub fn shutdown(fd: RawFd, how: u32) -> Result<(), Errno> {
    check(unsafe { syscall2(SYS_SHUTDOWN, fd.as_usize(), how as usize) })?;
    Ok(())
}

pub fn read(fd: RawFd, buf: *mut u8, len: usize) -> Result<usize, Errno> {
    check(unsafe { syscall3(SYS_READ, fd.as_usize(), buf as usize, len) })
}

pub fn write(fd: RawFd, buf: *const u8, len: usize) -> Result<usize, Errno> {
    check(unsafe { syscall3(SYS_WRITE, fd.as_usize(), buf as usize, len) })
}

pub fn close(fd: RawFd) -> Result<(), Errno> {
    check(unsafe { syscall1(SYS_CLOSE, fd.as_usize()) })?;
    Ok(())
}

pub fn eventfd2(initval: u32, flags: i32) -> Result<RawFd, Errno> {
    check(unsafe { syscall2(SYS_EVENTFD2, initval as usize, flags as usize) }).map(RawFd::from_raw)
}

pub fn inotify_init1(flags: i32) -> Result<RawFd, Errno> {
    check(unsafe { syscall1(SYS_INOTIFY_INIT1, flags as usize) }).map(RawFd::from_raw)
}

pub fn inotify_add_watch(fd: RawFd, path: *const u8, mask: u32) -> Result<usize, Errno> {
    check(unsafe {
        syscall3(
            SYS_INOTIFY_ADD_WATCH,
            fd.as_usize(),
            path as usize,
            mask as usize,
        )
    })
}

pub fn inotify_rm_watch(fd: RawFd, wd: i32) -> Result<(), Errno> {
    check(unsafe { syscall2(SYS_INOTIFY_RM_WATCH, fd.as_usize(), wd as usize) })?;
    Ok(())
}
