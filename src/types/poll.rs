//! Poll event mask.

bitflags! {
    /// Event mask for poll operations (matches Linux poll event bits).
    pub struct PollMask(u32);
    const IN = 0x0001;
    const OUT = 0x0004;
    const ERR = 0x0008;
    const HUP = 0x0010;
    const RDHUP = 0x2000;
}
