#![allow(
    dead_code,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::missing_errors_doc
)]

use crate::error::Error;
use core::arch::asm;

const SYS_CLOSE: usize = 3;
const SYS_MMAP: usize = 9;
const SYS_MUNMAP: usize = 11;
const SYS_OPENAT: usize = 257;
const SYS_IO_URING_SETUP: usize = 425;
const SYS_IO_URING_ENTER: usize = 426;

#[inline]
unsafe fn syscall1(nr: usize, a1: usize) -> isize {
    let ret: isize;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") nr as isize => ret,
            in("rdi") a1,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline]
unsafe fn syscall2(nr: usize, a1: usize, a2: usize) -> isize {
    let ret: isize;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") nr as isize => ret,
            in("rdi") a1,
            in("rsi") a2,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

#[inline]
unsafe fn syscall6(
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
            "syscall",
            inlateout("rax") nr as isize => ret,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            in("r8") a5,
            in("r9") a6,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

const fn check(ret: isize) -> Result<usize, Error> {
    if ret < 0 {
        Err(Error((-ret) as i32))
    } else {
        Ok(ret as usize)
    }
}

pub fn io_uring_setup(
    entries: u32,
    params: *mut crate::types::IoUringParams,
) -> Result<usize, Error> {
    check(unsafe { syscall2(SYS_IO_URING_SETUP, entries as usize, params as usize) })
}

pub fn io_uring_enter(
    fd: usize,
    to_submit: u32,
    min_complete: u32,
    flags: u32,
) -> Result<usize, Error> {
    check(unsafe {
        syscall6(
            SYS_IO_URING_ENTER,
            fd,
            to_submit as usize,
            min_complete as usize,
            flags as usize,
            0, // sig
            0, // sigsz
        )
    })
}

pub fn mmap(
    addr: usize,
    len: usize,
    prot: i32,
    flags: i32,
    fd: usize,
    offset: u64,
) -> Result<usize, Error> {
    check(unsafe {
        syscall6(
            SYS_MMAP,
            addr,
            len,
            prot as usize,
            flags as usize,
            fd,
            offset as usize,
        )
    })
}

pub fn munmap(addr: usize, len: usize) -> Result<(), Error> {
    check(unsafe { syscall2(SYS_MUNMAP, addr, len) })?;
    Ok(())
}

pub fn openat(dfd: i32, path: *const u8, flags: i32, mode: u32) -> Result<usize, Error> {
    check(unsafe {
        syscall6(
            SYS_OPENAT,
            dfd as usize,
            path as usize,
            flags as usize,
            mode as usize,
            0,
            0,
        )
    })
}

pub fn close(fd: usize) -> Result<(), Error> {
    check(unsafe { syscall1(SYS_CLOSE, fd) })?;
    Ok(())
}
