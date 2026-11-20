//! J2, I-25, I-26 (ADR-026 record of lane L5): the invitation of a person
//! to a programme role by address is one timeline event of kind
//! `ROLE_INVITATION`, which the accounts port schedules and fires itself.
//! The timeline's own plan never cancels it, and its own firing never
//! builds its entry, since only the port holds the link token. The fire
//! entry records the pinned template version first and lists exactly one
//! message with its row, and a second firing of the event is refused.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]

mod common;

use common::Cell;
use fstp_cell_core::timeline::{EventStatus, TimelineCommand, TimelineRecord};
use fstp_domain::id::ProgrammeId;
use fstp_domain::time::Timestamp;
use fstp_timeline::{kind, role_invitation_event, role_invitation_firing, role_invitation_message};

const DAY: i64 = 86_400_000_000;
const PROGRAMME: ProgrammeId = ProgrammeId::from_raw(0x5101);

fn cell() -> Cell {
    Cell::from_engine(common::submitted().entries().unwrap())
}

fn now(c: &Cell, plus: i64) -> Timestamp {
    let last = c.entries.last().map_or(0, |e| e.at);
    Timestamp::from_micros(last + plus)
}

/// I-25: a scheduled invitation event survives every later plan, so the
/// timeline never cancels it before the port fires it, and the timeline's
/// own firing skips it.
#[test]
fn i25_role_invitation_event_is_never_planned_away() {
    let mut c = cell();
    let at = now(&c, 1);
    let d = role_invitation_event(PROGRAMME, 77, at);
    c.run(
        TimelineCommand::Plan {
            records: vec![d.scheduled()],
        },
        Vec::new(),
        at,
    )
    .unwrap();
    for step in 1..4 {
        let later = Timestamp::from_micros(at.micros() + step * DAY);
        let plan = fstp_timeline::plan(&c.state, later);
        assert!(
            !plan.iter().any(|r| matches!(
                r,
                TimelineRecord::EventCancelled { event, .. } if *event == d.id()
            )),
            "I-25: the plan cancels the invitation event: {plan:?}"
        );
        assert!(
            fstp_timeline::firing(&c.state, &d.id(), later).is_none(),
            "only the accounts port fires an invitation"
        );
        c.tick(later).unwrap();
    }
    let e = c.state.timeline().event(&d.id()).unwrap();
    assert_eq!(e.kind, kind::ROLE_INVITATION);
    assert_eq!(e.status, EventStatus::Scheduled);
}

/// I-25, I-26: the port's firing records the template version once,
/// lists one message whose row carries the body, and fires the event once.
/// One event, one address and email give one key and one row.
#[test]
fn i26_role_invitation_fires_one_message_once() {
    let mut c = cell();
    let at = now(&c, 1);
    let d = role_invitation_event(PROGRAMME, 78, at);
    c.run(
        TimelineCommand::Plan {
            records: vec![d.scheduled()],
        },
        Vec::new(),
        at,
    )
    .unwrap();
    let address = fstp_crypto::sha256(b"synthetic-invitee-1@e2e.invalid");
    let m = role_invitation_message(&d.id(), address).unwrap();
    let again = role_invitation_message(&d.id(), address).unwrap();
    assert_eq!(
        (m.outbox, m.idem),
        (again.outbox, again.idem),
        "I-26: one key"
    );
    let f = role_invitation_firing(&c.state, &d.id(), &m, b"composed".to_vec(), at).unwrap();
    let TimelineCommand::Fire {
        templates,
        messages,
        then,
        ..
    } = &f.command
    else {
        panic!("not a firing: {:?}", f.command);
    };
    assert_eq!(templates.len(), 1, "I-25: the version is recorded first");
    assert_eq!(messages.len(), 1);
    assert!(then.is_none());
    assert_eq!(f.bodies.len(), 1);
    assert_eq!(f.bodies[0].outbox, m.outbox);
    c.run(f.command.clone(), f.bodies.clone(), at).unwrap();
    let e = c.state.timeline().event(&d.id()).unwrap();
    assert_eq!(e.status, EventStatus::Fired);
    assert_eq!(c.state.timeline().fired_idem(&m.idem), Some(&d.id()));
    // I-26: the event fired, so no second firing is built, and a replayed
    // one is refused by the decider.
    assert!(role_invitation_firing(&c.state, &d.id(), &m, b"again".to_vec(), at).is_none());
    assert!(c.run(f.command, f.bodies, at).is_err(), "I-26: fired twice");
}

/// R-NT-01 (M6 design section 6, ADR-026 record of lane L5): an
/// invitation event belongs to its programme only, and every immediate
/// event of the scenario resolves to the programme of its proposal, so
/// the programme timeline read lists each event under one programme.
#[test]
fn r_nt_01_events_resolve_to_their_programme() {
    let mut c = cell();
    let at = now(&c, 1);
    c.enqueue(
        at.micros(),
        fstp_domain::record::OutboxEvent::NotifiableConflict {
            proposal: fstp_domain_testkit::r#gen::review::PR1,
        },
    );
    let d = role_invitation_event(PROGRAMME, 79, at);
    c.run(
        TimelineCommand::Plan {
            records: vec![d.scheduled()],
        },
        Vec::new(),
        at,
    )
    .unwrap();
    c.tick(at).unwrap();
    let t = c.state.timeline();
    let e = t.event(&d.id()).unwrap();
    assert_eq!(fstp_timeline::event_programme(&c.state, e), Some(PROGRAMME));
    let mut immediate = 0;
    for (_, e) in t.events().filter(|(_, e)| e.kind == kind::IMMEDIATE) {
        immediate += 1;
        let p = fstp_timeline::event_programme(&c.state, e);
        assert!(
            p.is_some_and(|p| p != PROGRAMME),
            "an immediate event without its programme: {e:?}"
        );
    }
    assert!(immediate > 0, "the scenario enqueued nothing");
}
