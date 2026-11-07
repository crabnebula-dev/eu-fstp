//! D13 and I-53 sources of the timeline engine (M6 design section 4): the
//! sweep kinds fire with their System command in one entry, and a
//! tightening yields its corrigendum event.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use common::Cell;
use fstp_cell_core::CellRecord;
use fstp_cell_core::timeline::{EventStatus, TimelineRecord};
use fstp_domain::assignment::AssignmentKind;
use fstp_domain::command::{Actor, DeclarationSubject};
use fstp_domain::record::Record;
use fstp_domain::scoring::{ScoreKey, Stage};
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::policy::{DRAFTER_1, P1, PM_A, PM_B, PM_C, PolicyWorld, eur};
use fstp_domain_testkit::r#gen::review::{COORDINATOR, PR1, R1, R2, declare, plan_of};
use fstp_domain_testkit::r#gen::roster::call;
use fstp_domain_testkit::mc::life_model::{
    T_EVAL, admit, assign_declared, assignment_of, close, knock_out, score,
};
use fstp_timeline::kind;

const DAY: i64 = 86_400_000_000;

/// D13, R-EV-07, M6 design section 4: when the P-07 window elapses, the
/// timeline schedules a `STAGE2_EXPIRY` event and fires it in one entry
/// with the `ExpireStage2` records. The next tick issues nothing, and the
/// event is not derived again.
#[test]
fn d13_sweep_kind_fires_with_its_system_command_in_one_entry() {
    let mut scn = common::submitted();
    for r in [R1, R2] {
        for s in assign_declared(r, PR1, call(1), AssignmentKind::Reviewer) {
            common::step(&mut scn, T_EVAL, &s);
        }
    }
    let coordinator = declare(COORDINATOR, DeclarationSubject::Proposal(PR1), false, false);
    common::step(&mut scn, T_EVAL, &coordinator);
    common::step(&mut scn, T_EVAL, &knock_out(PR1, true));
    common::step(&mut scn, T_EVAL, &admit(PR1));
    for r in [R1, R2] {
        let key = ScoreKey {
            assignment: assignment_of(r, PR1, call(1), AssignmentKind::Reviewer),
            stage: Stage::One,
            plan: plan_of(PR1),
        };
        common::step(&mut scn, T_EVAL, &score(r, key, &[2, 2]));
    }
    common::step(&mut scn, T_EVAL, &close(Actor::Account(COORDINATOR), PR1));
    let mut c = Cell::from_engine(scn.entries().unwrap());
    let t1 = Timestamp::from_micros(T_EVAL.micros() + 29 * DAY);
    let ran = c.tick(t1).unwrap();
    let fire = ran
        .iter()
        .find(|r| {
            r.batch
                .iter()
                .any(|x| matches!(x, CellRecord::Timeline(TimelineRecord::EventFired { .. })))
        })
        .unwrap_or_else(|| panic!("nothing fired: {ran:?}"));
    let transitioned = fire.batch.iter().any(|x| {
        matches!(
            x,
            CellRecord::Engine(fstp_engine::Record::Core(Record::Transitioned(_)))
        )
    });
    assert!(transitioned, "{:?}", fire.batch);
    let expiry: Vec<_> = c
        .state
        .timeline()
        .events()
        .filter(|(_, e)| e.kind == kind::STAGE2_EXPIRY)
        .collect();
    assert_eq!(expiry.len(), 1);
    assert_eq!(expiry[0].1.status, EventStatus::Fired);
    assert!(
        fstp_engine::sweep::due(c.state.engine(), t1)
            .unwrap()
            .is_empty()
    );
    let next = Timestamp::from_micros(t1.micros() + DAY);
    let again = c.tick(next).unwrap();
    assert!(
        again.iter().all(|r| !r.batch.iter().any(|x| matches!(
            x,
            CellRecord::Timeline(TimelineRecord::EventScheduled { kind: k, .. }) if *k == kind::STAGE2_EXPIRY
        ))),
        "{again:?}"
    );
}

/// I-53: a live edit that lowers P-05 of a published call yields
/// corrigendum 1, which the timeline schedules and fires once. With no
/// proposal in the call, it has no recipient.
#[test]
fn i53_a_tightening_yields_one_corrigendum_event() {
    let mut w = PolicyWorld::new(false).unwrap_or_else(|e| panic!("{e}"));
    assert!(w.draft(DRAFTER_1, 1, P1).unwrap().is_ok());
    assert!(w.approve(PM_B, 1).is_ok());
    assert!(w.publish(PM_A, 1).unwrap().is_ok());
    let lowered = eur(1_000_000).unwrap();
    assert!(w.edit(PM_C, P1, |v| v.live.p05 = lowered).unwrap().is_ok());
    let mut c = Cell::from_engine(w.setup.scenario.entries().unwrap());
    let now = Timestamp::from_micros(c.state.now_floor().micros() + 1);
    c.tick(now).unwrap();
    let corrigenda: Vec<_> = c
        .state
        .timeline()
        .events()
        .filter(|(_, e)| e.kind == kind::CORRIGENDUM)
        .collect();
    assert_eq!(corrigenda.len(), 1, "{corrigenda:?}");
    assert_eq!(corrigenda[0].1.source_version, 1);
    assert_eq!(corrigenda[0].1.status, EventStatus::Fired);
    assert!(
        c.tick(Timestamp::from_micros(now.micros() + DAY))
            .unwrap()
            .is_empty()
    );
}
