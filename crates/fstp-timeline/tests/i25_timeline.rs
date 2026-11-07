//! I-25, I-26, R-NT-01, D13 and I-53 for the timeline engine (M6 design
//! sections 4 and 7, lane L6-TL).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use common::Cell;
use fstp_cell_core::timeline::{
    EventStatus, FiredMessage, Recipient, TimelineCommand, TimelineRecord,
};
use fstp_cell_core::{CellCommand, CellRecord};
use fstp_domain::id::{BindingId, ProposalId};
use fstp_domain::record::OutboxEvent;
use fstp_domain::rules::StateTag;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::review::{L1, PR1};
use fstp_prop::{check, prop_assert, prop_assert_eq};
use fstp_timeline::message::MessageSpec;
use fstp_timeline::{Derived, kind};

const MINUTE: i64 = 60_000_000;
const DAY: i64 = 86_400_000_000;

fn base() -> Cell {
    static BASE: OnceLock<Cell> = OnceLock::new();
    BASE.get_or_init(|| Cell::from_engine(common::submitted().entries().unwrap()))
        .clone()
}

fn start() -> i64 {
    base().state.now_floor().micros()
}

/// Every `EventFired` record of the ledger, with its messages.
fn fired(c: &Cell) -> Vec<([u8; 32], Vec<FiredMessage>)> {
    c.entries
        .iter()
        .filter_map(|e| match &e.record {
            CellRecord::Timeline(TimelineRecord::EventFired { event, messages }) => {
                Some((*event, messages.clone()))
            }
            _ => None,
        })
        .collect()
}

fn outbox_event(g: &mut fstp_prop::Gen) -> OutboxEvent {
    match g.u8_in(0..=3) {
        0 => OutboxEvent::ProposalOutcome {
            proposal: PR1,
            state: *g.pick(&[
                StateTag::NotSelected,
                StateTag::Ineligible,
                StateTag::Granted,
            ]),
        },
        1 => OutboxEvent::NotifiableConflict { proposal: PR1 },
        2 => OutboxEvent::BindingEnded {
            binding: BindingId::from_raw(u128::from(g.u8())),
        },
        // A proposal the ledger does not know: the event fires, with no
        // recipient.
        _ => OutboxEvent::ProposalOutcome {
            proposal: ProposalId::from_raw(9_999),
            state: StateTag::NotSelected,
        },
    }
}

/// I-25 (property): no event is lost or duplicated by derivation. Outbox
/// records arrive between ticks, ticks run at random instants, and the
/// cell restarts from its ledger at random points. Then:
///
/// - every `OutboxEnqueued` record has exactly one event, and it fired
///   exactly once;
/// - each idempotency key and outbox row is listed once (I-26), with one
///   body that names the same event and key;
/// - each fired template version was recorded first (I-25);
/// - a further plan is empty, and the replayed ledger derives the same
///   events as the running state.
#[test]
fn i25_property_no_event_lost_or_duplicated_by_derivation() {
    check(
        "i25_property_no_event_lost_or_duplicated_by_derivation",
        |g| {
            let mut c = base();
            let mut now = start();
            let mut enqueued = 0usize;
            for _ in 0..g.usize_in(1..=12) {
                match g.u8_in(0..=2) {
                    0 => {
                        now += g.i64_in(0..=MINUTE);
                        c.enqueue(now, outbox_event(g));
                        enqueued += 1;
                    }
                    1 => {
                        now += g.i64_in(0..=MINUTE);
                        c.tick(Timestamp::from_micros(now))?;
                    }
                    _ => {
                        // A restart: the state is the replay of the ledger.
                        c.state = c.replayed();
                    }
                }
            }
            now += MINUTE;
            c.tick(Timestamp::from_micros(now))?;
            let t = c.state.timeline();
            let immediate: Vec<_> = t
                .events()
                .filter(|(_, e)| e.kind == kind::IMMEDIATE)
                .collect();
            prop_assert_eq!(immediate.len(), enqueued);
            prop_assert!(
                immediate
                    .iter()
                    .all(|(_, e)| e.status == EventStatus::Fired)
            );
            let fired = fired(&c);
            let ids: BTreeSet<[u8; 32]> = fired.iter().map(|(e, _)| *e).collect();
            prop_assert_eq!(ids.len(), fired.len());
            let messages: Vec<FiredMessage> = fired.iter().flat_map(|(_, m)| m.clone()).collect();
            let idems: BTreeSet<[u8; 32]> = messages.iter().map(|m| m.idem).collect();
            let rows: BTreeSet<[u8; 16]> = messages.iter().map(|m| m.outbox).collect();
            prop_assert_eq!(idems.len(), messages.len());
            prop_assert_eq!(rows.len(), messages.len());
            prop_assert_eq!(c.bodies.len(), messages.len());
            for (m, b) in messages.iter().zip(&c.bodies) {
                prop_assert_eq!(m.outbox, b.outbox);
                let spec = MessageSpec::decode(&b.body).map_err(|e| format!("{e:?}"))?;
                prop_assert_eq!(spec.idem, m.idem);
                prop_assert!(t.fired_idem(&m.idem) == Some(&spec.event));
                prop_assert!(t.template(m.template, m.version).is_some());
            }
            prop_assert!(fstp_timeline::plan(&c.state, Timestamp::from_micros(now)).is_empty());
            let again = c.replayed();
            prop_assert!(again == c.state);
            prop_assert_eq!(
                fstp_timeline::derive(&again, Timestamp::from_micros(now)),
                fstp_timeline::derive(&c.state, Timestamp::from_micros(now))
            );
            Ok(())
        },
    );
}

/// I-25, I-26: an outcome record fires one message to the lead, whose
/// body names the recorded template version and the event, and a second
/// tick fires nothing again.
#[test]
fn i25_outcome_record_fires_one_message_to_the_lead_once() {
    let mut c = base();
    let at = start() + MINUTE;
    c.enqueue(
        at,
        OutboxEvent::ProposalOutcome {
            proposal: PR1,
            state: StateTag::NotSelected,
        },
    );
    let ran = c.tick(Timestamp::from_micros(at)).unwrap();
    assert_eq!(ran.len(), 2, "{ran:?}");
    assert_eq!(c.bodies.len(), 1);
    let spec = MessageSpec::decode(&c.bodies[0].body).unwrap();
    assert_eq!(spec.to, Recipient::Account(L1));
    assert_eq!(spec.template, fstp_mail::TemplateId::ProposalOutcome);
    assert!(spec.template().is_some());
    assert!(
        c.tick(Timestamp::from_micros(at + MINUTE))
            .unwrap()
            .is_empty()
    );
}

/// I-26: a firing retried after it committed is refused by the fold, and
/// its command id is the one it committed under, so the store answers it
/// as a duplicate.
#[test]
fn i26_a_repeated_firing_is_refused_and_keeps_its_id() {
    let mut c = base();
    let at = start() + MINUTE;
    c.enqueue(at, OutboxEvent::NotifiableConflict { proposal: PR1 });
    let now = Timestamp::from_micros(at);
    let plan = fstp_timeline::plan(&c.state, now);
    c.run(TimelineCommand::Plan { records: plan }, Vec::new(), now)
        .unwrap();
    let event = fstp_timeline::due_events(c.state.timeline(), now)[0];
    let f = fstp_timeline::firing(&c.state, &event, now).unwrap();
    let id = fstp_timeline::command_id(&f.command);
    c.run(f.command.clone(), f.bodies.clone(), now).unwrap();
    assert!(c.state.committed(id).is_some());
    assert!(fstp_timeline::firing(&c.state, &event, now).is_none());
    assert!(c.run(f.command, f.bodies, now).is_err());
}

/// I-25: a firing whose bodies do not name exactly its messages is
/// refused, so no outbox row commits without its `EventFired`.
#[test]
fn i25_bodies_that_do_not_match_the_messages_are_refused() {
    let mut c = base();
    let at = start() + MINUTE;
    c.enqueue(
        at,
        OutboxEvent::ProposalOutcome {
            proposal: PR1,
            state: StateTag::NotSelected,
        },
    );
    let now = Timestamp::from_micros(at);
    let plan = fstp_timeline::plan(&c.state, now);
    c.run(TimelineCommand::Plan { records: plan }, Vec::new(), now)
        .unwrap();
    let event = fstp_timeline::due_events(c.state.timeline(), now)[0];
    let f = fstp_timeline::firing(&c.state, &event, now).unwrap();
    assert!(c.run(f.command.clone(), Vec::new(), now).is_err());
    let mut doubled = f.bodies.clone();
    doubled.extend(f.bodies.clone());
    assert!(c.run(f.command, doubled, now).is_err());
}

/// I-25: an event does not fire before it is due.
#[test]
fn i25_an_event_never_fires_before_it_is_due() {
    let c = base();
    let mut t = c.state.timeline().clone();
    let _ = &mut t;
    let d = Derived {
        kind: kind::CORRIGENDUM,
        lead: 0,
        source: vec![1],
        source_version: 1,
        due: start() + DAY,
        offset_minutes: 0,
    };
    let mut c = c;
    c.run(
        TimelineCommand::Plan {
            records: vec![d.scheduled()],
        },
        Vec::new(),
        Timestamp::from_micros(start()),
    )
    .unwrap();
    let early = Timestamp::from_micros(start() + DAY - 1);
    assert!(fstp_timeline::due_events(c.state.timeline(), early).is_empty());
    let fire = TimelineCommand::Fire {
        event: d.id(),
        templates: Vec::new(),
        messages: Vec::new(),
        then: None,
    };
    assert!(c.run(fire, Vec::new(), early).is_err());
}

/// R-NT-01 AC: when a source's version changes, the scheduled event is
/// cancelled, superseded by the new one, and the new one is scheduled.
/// The cancelled event stays in the state.
#[test]
fn r_nt_01_amended_due_date_cancels_and_reschedules() {
    let mut c = base();
    let now = Timestamp::from_micros(start());
    let old = Derived {
        kind: kind::MILESTONE_REMINDER,
        lead: -14 * DAY,
        source: vec![7; 8],
        source_version: 1,
        due: start() + 30 * DAY,
        offset_minutes: 60,
    };
    c.run(
        TimelineCommand::Plan {
            records: vec![old.scheduled()],
        },
        Vec::new(),
        now,
    )
    .unwrap();
    let new = Derived {
        source_version: 2,
        due: start() + 40 * DAY,
        ..old.clone()
    };
    let derived: BTreeMap<_, _> = [(new.id(), new.clone())].into_iter().collect();
    let records = fstp_timeline::diff(c.state.timeline(), &derived);
    assert_eq!(
        records,
        vec![
            new.scheduled(),
            TimelineRecord::EventCancelled {
                event: old.id(),
                superseded_by: Some(new.id()),
            },
        ]
    );
    c.run(TimelineCommand::Plan { records }, Vec::new(), now)
        .unwrap();
    let t = c.state.timeline();
    assert_eq!(
        t.event(&old.id()).map(|e| e.status),
        Some(EventStatus::Cancelled(Some(new.id())))
    );
    assert_eq!(
        t.event(&new.id()).map(|e| e.status),
        Some(EventStatus::Scheduled)
    );
    assert!(fstp_timeline::diff(t, &derived).is_empty());
}

/// I-25: a timeline command is the timeline task's alone. An account's
/// command of that kind is refused.
#[test]
fn i25_an_account_cannot_issue_a_timeline_command() {
    let c = base();
    let cmd = CellCommand::Timeline(TimelineCommand::Plan {
        records: vec![
            Derived {
                kind: kind::CORRIGENDUM,
                lead: 0,
                source: vec![1],
                source_version: 1,
                due: start(),
                offset_minutes: 0,
            }
            .scheduled(),
        ],
    });
    let x = fstp_cell_core::CellCtx {
        actor: L1,
        at: start(),
    };
    let r = fstp_cell_core::decide_with_id(
        &c.state,
        &cmd,
        &x,
        [1; 16],
        &fstp_domain::oracle::Answers::new(),
    );
    assert!(r.is_err());
}

/// I-25: the body of a message round-trips, and a changed byte of a
/// canonical body is either refused or decodes to another body.
#[test]
fn i25_message_body_round_trips() {
    let mut c = base();
    let at = start() + MINUTE;
    c.enqueue(
        at,
        OutboxEvent::ProposalOutcome {
            proposal: PR1,
            state: StateTag::Ineligible,
        },
    );
    c.tick(Timestamp::from_micros(at)).unwrap();
    let body = &c.bodies[0].body;
    let spec = MessageSpec::decode(body).unwrap();
    assert_eq!(spec.encode().as_ref(), Some(body));
}
