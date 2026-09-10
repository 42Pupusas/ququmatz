//! Kernel-domain types: opcodes, flags, layout structs, and constants.
//!
//! Submodules group items by their kernel concern (filesystem, networking,
//! buffer registration, etc.). Everything is re-exported at the module root
//! for callers.

// ---------------------------------------------------------------------------
// Bitflag newtype macro — eliminates per-type boilerplate.
// Visible to all submodules automatically as a macro defined in the parent.
// ---------------------------------------------------------------------------

macro_rules! bitflags {
    (
        $(#[$meta:meta])*
        $vis:vis struct $Name:ident($inner:ty);
        $(
            $(#[$cmeta:meta])*
            const $FLAG:ident = $value:expr;
        )*
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
        $vis struct $Name($inner);

        impl $Name {
            $(
                $(#[$cmeta])*
                pub const $FLAG: Self = Self($value);
            )*

            /// Returns the raw underlying value.
            #[must_use]
            pub const fn bits(self) -> $inner {
                self.0
            }

            /// Check whether all bits in `flag` are set.
            #[must_use]
            pub const fn contains(self, flag: Self) -> bool {
                (self.0 & flag.0) == flag.0
            }

            /// Combine two sets in a `const` context, where `|` cannot go.
            #[must_use]
            pub const fn union_const(self, other: Self) -> Self {
                Self(self.0 | other.0)
            }

            /// The empty set, in a `const` context where `default` cannot go.
            #[must_use]
            pub const fn empty() -> Self {
                Self(0)
            }
        }

        impl PartialEq<$inner> for $Name {
            fn eq(&self, other: &$inner) -> bool {
                self.0 == *other
            }
        }

        impl core::ops::BitOr for $Name {
            type Output = Self;
            fn bitor(self, rhs: Self) -> Self {
                Self(self.0 | rhs.0)
            }
        }

        impl core::ops::BitOrAssign for $Name {
            fn bitor_assign(&mut self, rhs: Self) {
                self.0 |= rhs.0;
            }
        }

        impl core::ops::BitAnd for $Name {
            type Output = Self;
            fn bitand(self, rhs: Self) -> Self {
                Self(self.0 & rhs.0)
            }
        }

        impl core::ops::BitAndAssign for $Name {
            fn bitand_assign(&mut self, rhs: Self) {
                self.0 &= rhs.0;
            }
        }

        impl core::ops::Not for $Name {
            type Output = Self;
            fn not(self) -> Self {
                Self(!self.0)
            }
        }
    };
}

mod buffers;
mod epoll;
mod eventfd;
mod fs;
mod inotify;
mod mmap;
mod net;
mod opcodes;
mod poll;
mod ring_ctrl;
mod sendrecv;
mod splice;
mod sqe_cqe;
mod timeout;

pub use buffers::{
    IoCqringOffsets, IoSqringOffsets, IoUringBuf, IoUringBufReg, IoUringFilesUpdate,
    IoUringRsrcUpdate, IoVec, RawFd,
};
pub use epoll::{EpollEvent, EpollEvents, EpollOp};
pub use eventfd::EventFdFlags;
#[cfg(test)]
pub(crate) use fs::AT_FDCWD;
pub use fs::{
    DirFd, FadviseAdvice, FallocateMode, FileMode, FsyncFlags, MadviseAdvice, OpenFlags, OpenHow,
    RenameFlags, ResolveFlags, Statx, StatxFlags, StatxMask, StatxTimestamp, UnlinkFlags, resolve,
};
pub use inotify::{InotifyEvent, InotifyInitFlags, WatchMask};
pub use mmap::{MapFlags, Prot};
#[cfg(test)]
pub(crate) use net::{AF_INET, SOCK_NONBLOCK, SOCK_STREAM};
pub use net::{
    AcceptFlags, AddressFamily, MsgFlags, MsgHdr, RecvmsgOut, RecvmsgParts, ShutdownHow,
    SockAddrIn, SocketFlags, SocketType,
};
pub use opcodes::{Opcode, RegisterOp, RingOffset};
pub use poll::PollMask;
pub use ring_ctrl::{EnterFlags, Features, SetupFlags, SqeFlags};
pub use sendrecv::SendRecvFlag;
pub(crate) use sendrecv::{
    IORING_ACCEPT_MULTISHOT, IORING_RECV_MULTISHOT, IORING_RECVSEND_FIXED_BUF,
    IORING_RECVSEND_POLL_FIRST, IORING_SEND_ZC_REPORT_USAGE,
};
pub use splice::SpliceFlags;
pub use sqe_cqe::{CqeFlags, IoUringCqe, IoUringParams, IoUringSqe};
pub use timeout::{TimeoutFlags, Timespec};
