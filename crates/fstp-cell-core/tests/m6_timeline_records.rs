//! The timeline ledger records of M6 design section 3.1 (lane L6-REC):
//! the event id, the idempotency key and the fold rules behind I-25,
//! I-26 and R-NT-01.
//!
//! Written before the fold. A refusal test is red while the fold accepts
//! every timeline record.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::BTreeSet;

use fstp_cell_core::timeline::{
    CHANNEL_EMAIL, FiredMessage, Recipient, TimelineRecord, event_id, immediate_source,
    message_idem,
};
use fstp_cell_core::{
    CellRecord, CellState, FoldError, apply, decode_cell_record, encode_cell_record,
};
use fstp_domain::id::AccountId;
use fstp_ledger::{MemStore, RecordStore, Seq};
use fstp_prop::{Gen, prop_assert, prop_assert_eq};

/// A time inside the bound, in UTC microseconds (2026-11-06).
const AT: i64 = 1_794_000_000_000_000;

struct Ledger {
    state: CellState,
    store: MemStore<CellRecord>,
    n: u8,
}

impl Ledger {
    fn new() -> Ledger {
        Ledger {
            state: CellState::genesis(),
            store: MemStore::new(),
            n: 0,
        }
    }

    /// Folds `records` as one entry under a fresh command id. On a
    /// refusal the ledger and the state stay as they were.
    fn fold(&mut self, records: Vec<TimelineRecord>) -> Result<(), FoldError> {
        self.n += 1;
        let mut store = self.store.clone();
        let head = store.head();
        let batch: Vec<CellRecord> = records.into_iter().map(CellRecord::Timeline).collect();
        store.append(head, AT, [self.n; 16], batch).unwrap();
        let mut entries = Vec::new();
        store
            .read(Seq::from_raw(head.raw() + 1), usize::MAX, &mut entries)
            .unwrap();
        let mut next = self.state.clone();
        for e in &entries {
            apply(&mut next, e)?;
        }
        self.state = next;
        self.store = store;
        Ok(())
    }
}

fn scheduled(kind: u16, source: &[u8], version: u64) -> TimelineRecord {
    TimelineRecord::EventScheduled {
        event: event_id(kind, 0, source, version),
        kind,
        lead: 0,
        source: source.to_vec(),
        source_version: version,
        due: AT,
        offset_minutes: 60,
    }
}

fn template(template: u16, version: u16, digest: u8) -> TimelineRecord {
    TimelineRecord::TemplateVersionRecorded {
        template,
        version,
        locale: "en".to_owned(),
        digest: [digest; 32],
    }
}

fn message(event: &[u8; 32], account: u128, outbox: u8) -> FiredMessage {
    FiredMessage {
        outbox: [outbox; 16],
        idem: message_idem(
            event,
            Recipient::Account(AccountId::from_raw(account)),
            CHANNEL_EMAIL,
        ),
        template: 1,
        version: 1,
    }
}

fn fired(event: [u8; 32], messages: Vec<FiredMessage>) -> TimelineRecord {
    TimelineRecord::EventFired { event, messages }
}

/// I-26, M6 design section 3.1: the idempotency key is a function of the
/// event, the recipient and the channel only. Two different triples never
/// share a key, and one triple always gives the same key.
#[test]
fn i26_idem_is_one_key_per_event_recipient_and_channel() {
    fstp_prop::check(
        "i26_idem_is_one_key_per_event_recipient_and_channel",
        |g: &mut Gen| {
            let triple = |g: &mut Gen| {
                let mut event = [0u8; 32];
                event[0] = g.u8_in(0..=3);
                let recipient = if g.bool() {
                    Recipient::Account(AccountId::from_raw(u128::from(g.u8_in(0..=3))))
                } else {
                    let mut d = [0u8; 32];
                    d[31] = g.u8_in(0..=3);
                    Recipient::Address(d)
                };
                (event, recipient, g.u8_in(1..=2))
            };
            let a = triple(g);
            let b = triple(g);
            let ka = message_idem(&a.0, a.1, a.2);
            let kb = message_idem(&b.0, b.1, b.2);
            prop_assert_eq!(ka == kb, a == b, "{a:?} {b:?}");
            prop_assert_eq!(ka, message_idem(&a.0, a.1, a.2));
            Ok(())
        },
    );
}

/// I-26, M6 design section 3.1: an account recipient and an address
/// recipient never share a key, even when their bytes coincide.
#[test]
fn i26_idem_separates_account_and_address_recipients() {
    let event = [7u8; 32];
    let mut digest = [0u8; 32];
    digest[16..].copy_from_slice(&5u128.to_be_bytes());
    assert_ne!(
        message_idem(
            &event,
            Recipient::Account(AccountId::from_raw(5)),
            CHANNEL_EMAIL
        ),
        message_idem(&event, Recipient::Address(digest), CHANNEL_EMAIL)
    );
}

/// R-NT-01, M6 design section 3.1: the event id names its kind, lead,
/// source and source version. An amended source version is a new event.
#[test]
fn r_nt_01_event_id_changes_with_every_input() {
    let base = event_id(3, -14, b"src", 1);
    let all: BTreeSet<[u8; 32]> = [
        base,
        event_id(4, -14, b"src", 1),
        event_id(3, -3, b"src", 1),
        event_id(3, -14, b"srd", 1),
        event_id(3, -14, b"src", 2),
        event_id(3, -14, b"sr", 1),
    ]
    .into_iter()
    .collect();
    assert_eq!(all.len(), 6, "R-NT-01: an event id collides");
    assert_eq!(base, event_id(3, -14, b"src", 1));
    assert_eq!(immediate_source(9, 2).len(), 12);
    assert_ne!(immediate_source(9, 2), immediate_source(9, 3));
}

/// I-26, M6 design section 3.1: the fold refuses a second `EventFired` for
/// one event.
#[test]
fn i26_fold_refuses_a_second_event_fired() {
    let mut l = Ledger::new();
    let s = scheduled(1, b"a", 1);
    let TimelineRecord::EventScheduled { event, .. } = s.clone() else {
        unreachable!()
    };
    l.fold(vec![template(1, 1, 9), s]).unwrap();
    l.fold(vec![fired(event, vec![message(&event, 1, 1)])])
        .unwrap();
    assert!(
        l.fold(vec![fired(event, vec![message(&event, 2, 2)])])
            .is_err(),
        "I-26: a second EventFired folded"
    );
    assert!(
        l.fold(vec![fired(event, Vec::new())]).is_err(),
        "I-26: a second EventFired without messages folded"
    );
}

/// I-26: one idempotency key is listed by at most one fired message, in
/// one record or across records.
#[test]
fn i26_fold_refuses_a_fired_idem_twice() {
    let mut l = Ledger::new();
    let a = scheduled(1, b"a", 1);
    let b = scheduled(1, b"b", 1);
    let (
        TimelineRecord::EventScheduled { event: ea, .. },
        TimelineRecord::EventScheduled { event: eb, .. },
    ) = (a.clone(), b.clone())
    else {
        unreachable!()
    };
    l.fold(vec![template(1, 1, 9), a, b]).unwrap();
    let twice = vec![message(&ea, 1, 1), message(&ea, 1, 2)];
    assert!(
        l.fold(vec![fired(ea, twice)]).is_err(),
        "I-26: one record listed one idem twice"
    );
    l.fold(vec![fired(ea, vec![message(&ea, 1, 1)])]).unwrap();
    let mut stolen = message(&ea, 1, 3);
    stolen.outbox = [3; 16];
    assert!(
        l.fold(vec![fired(eb, vec![stolen])]).is_err(),
        "I-26: a fired idem was listed again by another event"
    );
    assert!(
        l.fold(vec![fired(eb, vec![message(&eb, 2, 1)])]).is_err(),
        "an outbox id was listed twice"
    );
    l.fold(vec![fired(eb, vec![message(&eb, 2, 4)])]).unwrap();
}

/// I-25, M6 design section 3.1: every fired message names a template
/// version recorded before it.
#[test]
fn i25_fold_refuses_a_message_without_its_template_version() {
    let mut l = Ledger::new();
    let s = scheduled(1, b"a", 1);
    let TimelineRecord::EventScheduled { event, .. } = s.clone() else {
        unreachable!()
    };
    l.fold(vec![s]).unwrap();
    assert!(
        l.fold(vec![fired(event, vec![message(&event, 1, 1)])])
            .is_err(),
        "I-25: a message without a recorded template version folded"
    );
    l.fold(vec![template(1, 1, 9)]).unwrap();
    l.fold(vec![fired(event, vec![message(&event, 1, 1)])])
        .unwrap();
    assert_eq!(l.state.timeline().template(1, 1), Some(&[9u8; 32]));
}

/// I-25: a template version is recorded once and never changes.
#[test]
fn i25_template_version_never_changes() {
    let mut l = Ledger::new();
    l.fold(vec![template(1, 1, 9)]).unwrap();
    assert!(
        l.fold(vec![template(1, 1, 8)]).is_err(),
        "I-25: a version changed"
    );
    assert!(
        l.fold(vec![template(1, 1, 9)]).is_err(),
        "I-25: recorded twice"
    );
    l.fold(vec![template(1, 2, 8), template(2, 1, 8)]).unwrap();
}

/// R-NT-01 AC, M6 design section 3.1: a cancelled event stays in the
/// state, never fires, and is not cancelled twice. Only a scheduled event
/// fires or is cancelled.
#[test]
fn r_nt_01_cancelled_event_never_fires() {
    let mut l = Ledger::new();
    let old = scheduled(5, b"m", 1);
    let new = scheduled(5, b"m", 2);
    let (
        TimelineRecord::EventScheduled { event: eo, .. },
        TimelineRecord::EventScheduled { event: en, .. },
    ) = (old.clone(), new.clone())
    else {
        unreachable!()
    };
    l.fold(vec![template(1, 1, 9), old]).unwrap();
    assert!(
        l.fold(vec![TimelineRecord::EventCancelled {
            event: en,
            superseded_by: None
        }])
        .is_err(),
        "an unscheduled event was cancelled"
    );
    l.fold(vec![
        new,
        TimelineRecord::EventCancelled {
            event: eo,
            superseded_by: Some(en),
        },
    ])
    .unwrap();
    assert!(
        l.state.timeline().is_cancelled(&eo),
        "R-NT-01: cancelled, never deleted"
    );
    assert!(
        l.fold(vec![fired(eo, vec![message(&eo, 1, 1)])]).is_err(),
        "R-NT-01: a cancelled event fired"
    );
    assert!(
        l.fold(vec![TimelineRecord::EventCancelled {
            event: eo,
            superseded_by: None
        }])
        .is_err(),
        "an event was cancelled twice"
    );
    let ghost = [0xEE; 32];
    assert!(
        l.fold(vec![fired(ghost, Vec::new())]).is_err(),
        "an unscheduled event fired"
    );
    l.fold(vec![fired(en, vec![message(&en, 1, 1)])]).unwrap();
    assert!(
        l.fold(vec![TimelineRecord::EventCancelled {
            event: en,
            superseded_by: None
        }])
        .is_err(),
        "a fired event was cancelled"
    );
}

/// M6 design section 3.1: an `EventScheduled` whose id is not the digest
/// of its own fields is refused, and an event is scheduled once.
#[test]
fn r_nt_01_fold_checks_the_event_id_and_schedules_once() {
    let mut l = Ledger::new();
    let mut s = scheduled(1, b"a", 1);
    if let TimelineRecord::EventScheduled { event, .. } = &mut s {
        event[0] ^= 1;
    }
    assert!(l.fold(vec![s]).is_err(), "a forged event id folded");
    l.fold(vec![scheduled(1, b"a", 1)]).unwrap();
    assert!(
        l.fold(vec![scheduled(1, b"a", 1)]).is_err(),
        "an event was scheduled twice"
    );
}

fn any_record(g: &mut Gen) -> TimelineRecord {
    let id32 = |g: &mut Gen| {
        let mut out = [0u8; 32];
        for b in &mut out {
            *b = g.u8();
        }
        out
    };
    match g.u8_in(0..=3) {
        0 => TimelineRecord::TemplateVersionRecorded {
            template: g.u16(),
            version: g.u16(),
            locale: if g.bool() {
                "en".to_owned()
            } else {
                "pt-BR".to_owned()
            },
            digest: id32(g),
        },
        1 => {
            let kind = g.u16();
            let lead = g.i64();
            let source = g.bytes(0..=64);
            let source_version = g.u64();
            TimelineRecord::EventScheduled {
                event: event_id(kind, lead, &source, source_version),
                kind,
                lead,
                source,
                source_version,
                due: g.i64(),
                offset_minutes: g.i16_in(-1080..=1080),
            }
        }
        2 => TimelineRecord::EventCancelled {
            event: id32(g),
            superseded_by: g.option(id32),
        },
        _ => TimelineRecord::EventFired {
            event: id32(g),
            messages: g.vec(0..=3, |g| FiredMessage {
                outbox: {
                    let mut o = [0u8; 16];
                    for b in &mut o {
                        *b = g.u8();
                    }
                    o
                },
                idem: id32(g),
                template: g.u16(),
                version: g.u16(),
            }),
        },
    }
}

/// I-23, ADR-007, M6 design section 3.1: every timeline record round
/// trips through the cell envelope under the member `timeline`, in one
/// spelling.
#[test]
fn i23_timeline_records_round_trip_in_the_cell_envelope() {
    fstp_prop::check(
        "i23_timeline_records_round_trip_in_the_cell_envelope",
        |g: &mut Gen| {
            let r = CellRecord::Timeline(any_record(g));
            let bytes = encode_cell_record(&r);
            prop_assert!(bytes.starts_with(b"{\"timeline\":"), "member");
            prop_assert_eq!(decode_cell_record(&bytes), Ok(r));
            Ok(())
        },
    );
}
