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

pub use error::{CompletionError, Errno, Error, InvalidArgKind, SetupError, SubmitError};
pub use eventfd::EventFd;
pub use inotify::Inotify;
pub use net::Socket;
pub use op::Sqe;
pub use ring::{
    BufferConsumer, Completer, Completion, Completions, IoUring, IoUringBuilder,
    ProvidedBufferRing, SplitCompletions, Submitter,
};
pub use types::{
    AcceptFlags, AddressFamily, CqeFlags, DirFd, EnterFlags, EpollEvent, EpollEvents, EpollOp,
    EventFdFlags, FadviseAdvice, FallocateMode, Features, FileMode, FsyncFlags, InotifyEvent,
    InotifyInitFlags, IoUringBuf, IoUringBufReg, IoUringFilesUpdate, IoUringRsrcUpdate, IoVec,
    MadviseAdvice, MsgFlags, OpenFlags, OpenHow, PollMask, RawFd, RecvmsgOut, RecvmsgParts,
    RenameFlags, SendRecvFlag, SetupFlags, ShutdownHow, SocketFlags, SocketType, SpliceFlags,
    SqeFlags, StatxFlags, StatxMask, TimeoutFlags, Timespec, UnlinkFlags, WatchMask,
};

#[cfg(test)]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]
mod tests;
