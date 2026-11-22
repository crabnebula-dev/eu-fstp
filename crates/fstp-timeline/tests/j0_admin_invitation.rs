//! J0, SoD-07, I-25, I-26 (ADR-026 record of lane L18): the invitation of
//! a second tenant admin by address is one timeline event of kind
//! `ADMIN_INVITATION`, which the accounts port schedules and fires itself,
//! as it does for `ROLE_INVITATION`. It belongs to no programme. The fire
//! entry records the `admin-invitation` template version first and lists
//! exactly one message.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]

mod common;

use common::Cell;
use fstp_cell_core::timeline::{EventStatus, TimelineCommand, TimelineRecord};
use fstp_domain::time::Timestamp;
use fstp_timeline::{
    admin_invitation_event, admin_invitation_message, kind, role_invitation_firing,
};

const DAY: i64 = 86_400_000_000;

fn cell() -> Cell {
    Cell::from_engine(common::submitted().entries().unwrap())
}

fn now(c: &Cell, plus: i64) -> Timestamp {
    let last = c.entries.last().map_or(0, |e| e.at);
    Timestamp::from_micros(last + plus)
}

/// J0, I-25, I-26: the plan never cancels an admin invitation event and
/// the timeline's own firing skips it. The port's firing records the
/// `admin-invitation` version, lists one message, and fires once. The
/// event names no programme, and the delivery log names its template.
#[test]
fn j0_admin_invitation_event_is_fired_by_the_port_only() {
    let mut c = cell();
    let at = now(&c, 1);
    let d = admin_invitation_event(0x1a2b, at);
    assert_eq!(d.kind, kind::ADMIN_INVITATION);
    c.run(
        TimelineCommand::Plan {
            records: vec![d.scheduled()],
        },
        Vec::new(),
        at,
    )
    .unwrap();
    for step in 1..3 {
        let later = Timestamp::from_micros(at.micros() + step * DAY / 24);
        let plan = fstp_timeline::plan(&c.state, later);
        assert!(
            !plan.iter().any(|r| matches!(
                r,
                TimelineRecord::EventCancelled { event, .. } if *event == d.id()
            )),
            "I-25: the plan cancels the admin invitation event: {plan:?}"
        );
        assert!(
            fstp_timeline::firing(&c.state, &d.id(), later).is_none(),
            "only the accounts port fires an admin invitation"
        );
    }
    let address = fstp_crypto::sha256(b"synthetic-admin-2@e2e.invalid");
    let m = admin_invitation_message(&d.id(), address).unwrap();
    assert_eq!(m.template.id(), fstp_mail::TemplateId::AdminInvitation);
    let f = role_invitation_firing(&c.state, &d.id(), &m, b"composed".to_vec(), at).unwrap();
    let TimelineCommand::Fire {
        templates,
        messages,
        ..
    } = &f.command
    else {
        panic!("not a firing: {:?}", f.command);
    };
    assert_eq!(templates.len(), 1, "I-25: the version is recorded first");
    assert_eq!(messages.len(), 1);
    c.run(f.command.clone(), f.bodies.clone(), at).unwrap();
    let e = c.state.timeline().event(&d.id()).unwrap();
    assert_eq!(e.status, EventStatus::Fired);
    assert_eq!(fstp_timeline::event_programme(&c.state, e), None);
    assert_eq!(
        fstp_timeline::event_template(&c.state, &d.id()),
        Some(fstp_mail::TemplateId::AdminInvitation)
    );
    assert!(c.run(f.command, f.bodies, at).is_err(), "I-26: fired twice");
}
