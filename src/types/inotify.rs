//! Inotify watch mask, event header, and init flags.

use super::bitflags;

bitflags! {
    /// Event mask for inotify watches.
    pub struct WatchMask(u32);
    /// File was accessed.
    const ACCESS = 0x0000_0001;
    /// File was modified.
    const MODIFY = 0x0000_0002;
    /// Metadata changed.
    const ATTRIB = 0x0000_0004;
    /// Writable file was closed.
    const CLOSE_WRITE = 0x0000_0008;
    /// Non-writable file was closed.
    const CLOSE_NOWRITE = 0x0000_0010;
    /// File was opened.
    const OPEN = 0x0000_0020;
    /// File was moved from watched directory.
    const MOVED_FROM = 0x0000_0040;
    /// File was moved to watched directory.
    const MOVED_TO = 0x0000_0080;
    /// File was created in watched directory.
    const CREATE = 0x0000_0100;
    /// File was deleted from watched directory.
    const DELETE = 0x0000_0200;
    /// Watched file/directory was deleted.
    const DELETE_SELF = 0x0000_0400;
    /// Watched file/directory was moved.
    const MOVE_SELF = 0x0000_0800;
    /// Shorthand for `CLOSE_WRITE | CLOSE_NOWRITE`.
    const CLOSE = 0x0000_0018;
    /// Shorthand for `MOVED_FROM | MOVED_TO`.
    const MOVE = 0x0000_00C0;
    /// All events.
    const ALL_EVENTS = 0x0000_0FFF;
}

/// Fixed-size header of a kernel `inotify_event`.
///
/// The kernel appends a variable-length null-terminated name after this
/// header when the event is for a file inside a watched directory.
/// The `len` field gives the total size of that name (including padding
/// and the null terminator). When `len` is 0 the event targets the
/// watched inode itself and there is no trailing name.
///
/// To parse events from a read buffer, advance by
/// `size_of::<InotifyEvent>() + event.len as usize` for each event.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct InotifyEvent {
    /// Watch descriptor that matched.
    pub wd: i32,
    /// Bitmask of events (same bits as [`WatchMask`], plus kernel-set flags).
    pub mask: u32,
    /// Cookie for pairing `MOVED_FROM`/`MOVED_TO` events.
    pub cookie: u32,
    /// Length of the optional name following this struct.
    pub len: u32,
}

bitflags! {
    /// Flags for [`Inotify::with_flags`](crate::Inotify::with_flags).
    pub struct InotifyInitFlags(i32);
    /// Set the inotify fd to non-blocking mode.
    const NONBLOCK = 0o4000;
    /// Set close-on-exec on the inotify fd.
    const CLOEXEC = 0o2_000_000;
}
