//! `mmap` protection and mapping flags.

bitflags! {
    /// Memory protection flags for `mmap`.
    pub struct Prot(u32);
    const READ = 0x1;
    const WRITE = 0x2;
}

bitflags! {
    /// Mapping flags for `mmap`.
    pub struct MapFlags(u32);
    const SHARED = 0x01;
    const PRIVATE = 0x02;
    const ANONYMOUS = 0x20;
    const POPULATE = 0x0000_8000;
}
