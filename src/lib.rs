#![no_std]

#[cfg(not(target_os = "linux"))]
compile_error!(
    "ququmatz issues raw syscalls by number and only Linux assigns those numbers. \
     Other systems reuse them for unrelated calls: on FreeBSD amd64, which shares \
     this target_arch, number 1 is _exit and 3 is read, so a write would terminate \
     the process. Build for a *-linux-* target."
);

#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "aarch64",
    target_arch = "riscv64",
    target_arch = "arm"
)))]
compile_error!(
    "ququmatz has no syscall table for this architecture. Linux numbers its \
     syscalls per-architecture, so one must be written and verified rather than \
     inherited. Supported: x86_64, aarch64, riscv64, arm."
);

mod error;
pub mod eventfd;
pub mod fs;
pub mod inotify;
pub mod net;
pub mod op;
pub mod owned;
pub mod syscall;
pub mod types;

mod ring;

pub use error::{CompletionError, Errno, Error, InvalidArgKind, SetupError, SubmitError};
pub use eventfd::EventFd;
pub use inotify::Inotify;
pub use net::Socket;
pub use op::Sqe;
pub use owned::{MmapBuffer, OwnedCompleter, OwnedSubmitter, Pending, Prepared};
pub use ring::{
    BufferConsumer, Completer, Completion, Completions, IoUring, IoUringBuilder, Probe,
    ProvidedBufferRing, SplitCompletions, Submitter,
};
pub use types::{
    AcceptFlags, AddressFamily, CqeFlags, DirFd, EnterFlags, EpollEvent, EpollEvents, EpollOp,
    EventFdFlags, FadviseAdvice, FallocateMode, Features, FileMode, FsyncFlags, InotifyEvent,
    InotifyInitFlags, IoUringBuf, IoUringBufReg, IoUringCqe, IoUringFilesUpdate, IoUringParams,
    IoUringRsrcUpdate, IoUringSqe, IoVec, MadviseAdvice, MsgFlags, OpenFlags, OpenHow, PollMask,
    RawFd, RecvmsgOut, RecvmsgParts, RenameFlags, SendRecvFlag, SetupFlags, ShutdownHow,
    SocketFlags, SocketType, SpliceFlags, SqeFlags, StatxFlags, StatxMask, TimeoutFlags, Timespec,
    UnlinkFlags, WatchMask,
};

#[cfg(test)]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
mod tests;
