//! Tests for CQE classification.
//!
//! These construct `PartialReceipt`/`Receipt` directly rather than driving a
//! ring, because the point under test is the mapping from CQE flags to what
//! the completion authorizes — the kernel's own behaviour is pinned by the
//! real-ring tests in `tests.rs`.

extern crate std;

use super::event::{Event, PartialReceipt};
use super::identity::{RequestId, RingId};
use super::request::Receipt;
use crate::types::CqeFlags;

/// The flags a multishot arrival carries: non-terminal, with a chosen
/// buffer id packed into the upper 16 bits.
fn arrival_flags(buf_id: u16) -> CqeFlags {
    CqeFlags::from_raw(CqeFlags::MORE.bits() | CqeFlags::BUFFER.bits() | (u32::from(buf_id) << 16))
}

#[test]
fn a_non_terminal_arrival_keeps_the_buffer_id_it_must_recycle() {
    // Regression: `PartialReceipt` originally carried no flags, so a
    // multishot arrival's buffer id was silently dropped. That buffer would
    // then never be recycled, draining the pool until the multishot stalled
    // on ENOBUFS.
    let partial = PartialReceipt {
        ring: RingId::next(),
        id: RequestId::from_raw(7),
        result: 128,
        flags: arrival_flags(9),
    };
    assert_eq!(partial.buffer_id(), Some(9));
    assert_eq!(partial.raw_result(), 128);
}

#[test]
fn buffer_id_zero_is_a_real_id_not_an_absent_one() {
    let partial = PartialReceipt {
        ring: RingId::next(),
        id: RequestId::from_raw(1),
        result: 0,
        flags: arrival_flags(0),
    };
    assert_eq!(partial.buffer_id(), Some(0));
}

#[test]
fn the_highest_buffer_id_survives_the_shift() {
    let partial = PartialReceipt {
        ring: RingId::next(),
        id: RequestId::from_raw(1),
        result: 0,
        flags: arrival_flags(u16::MAX),
    };
    assert_eq!(partial.buffer_id(), Some(u16::MAX));
}

#[test]
fn a_completion_without_the_buffer_flag_reports_no_id() {
    // A zero-copy send's result CQE is non-terminal but selects no buffer,
    // so upper bits that happen to be set must not be read as an id.
    let partial = PartialReceipt {
        ring: RingId::next(),
        id: RequestId::from_raw(2),
        result: 64,
        flags: CqeFlags::MORE,
    };
    assert!(partial.buffer_id().is_none());
}

#[test]
fn only_a_terminal_event_yields_a_receipt() {
    let ring = RingId::next();
    let partial = Event::Partial(PartialReceipt {
        ring,
        id: RequestId::from_raw(3),
        result: 1,
        flags: CqeFlags::MORE,
    });
    assert!(!partial.is_terminal());
    assert!(partial.into_receipt().is_none());

    let complete = Event::Complete(Receipt {
        ring,
        id: RequestId::from_raw(3),
        result: 1,
        flags: CqeFlags::from_raw(0),
    });
    assert!(complete.is_terminal());
    assert!(complete.into_receipt().is_some());
}

#[test]
fn identity_is_reachable_without_deciding_which_kind_it_is() {
    let ring = RingId::next();
    let id = RequestId::from_raw(11);
    let partial = Event::Partial(PartialReceipt {
        ring,
        id,
        result: 5,
        flags: arrival_flags(2),
    });
    assert_eq!(partial.id(), id);
    assert_eq!(partial.ring(), ring);
    assert_eq!(partial.raw_result(), 5);
    assert!(partial.flags().contains(CqeFlags::BUFFER));
}
