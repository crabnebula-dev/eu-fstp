//! R-LA-03: a named human records every decision, and computed outcomes cannot be chosen (NOTE 3, NOTE 13, design 3.5).
//!
//! - `CloseStage1` is recorded by the FSTP coordinator. The System and
//!   other accounts are refused. The record names the coordinator and the
//!   outcome is the computed one.
//! - `DeclineAfterConcern` is recorded by the programme manager (O-49).
//! - The cut-off's outcome per proposal follows from the order and the
//!   rank position, and its transitions carry the decision.
//! - No outcome can be chosen: the commands that compute an outcome have
//!   no outcome field, and the command decoder refuses one.
//! - `stage1_ready` offers the close to the coordinator, and `due` never
//!   returns it, because a System actor cannot record it.
//!
//! The stories run production commands from genesis and compare every
//! step with the lifecycle reference in both directions.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::assignment::AssignmentKind;
use fstp_domain::command::{Actor, Command, CommandKind, SystemCause};
use fstp_domain::decision::Vote;
use fstp_domain::record::{Record, Transitioned};
use fstp_domain::rules::{Row, StateTag};
use fstp_domain::scoring::Stage;
use fstp_domain_testkit::r#gen::review::{COORDINATOR, IRC, L1, L2, PR1, PR2, R1, R2, R3};
use fstp_domain_testkit::r#gen::roster::{Backend, STAFF_PM, call};
use fstp_domain_testkit::mc::life_model::{
    IRC2, Story, assign_declared, ballots, close, cut_off, cut_off_decision, decline, irc_review,
    life_judges, story_setup,
};
use fstp_json::{ToJson, Value};

fn one(backend: Backend) -> Story {
    let setup = story_setup(vec![(L1, PR1, false), (L2, PR2, false)], life_judges());
    let mut s = Story::new(&setup, backend, |_| {}).unwrap_or_else(|e| panic!("{e}"));
    s.submit(L2, PR2).unwrap_or_else(|e| panic!("{e}"));
    s
}

fn transitions(records: &[Record]) -> Vec<Transitioned> {
    records
        .iter()
        .filter_map(|r| match r {
            Record::Transitioned(t) => Some(*t),
            _ => None,
        })
        .collect()
}

fn r_la_03_stage1_close_is_recorded_by_the_coordinator_on(b: Backend) {
    let mut s = one(b);
    s.to_stage1(L1, PR1, &[R1, R2])
        .unwrap_or_else(|e| panic!("{e}"));
    s.score_stage1(PR1, &[R1, R2], &[vec![2, 1], vec![2, 1]])
        .unwrap_or_else(|e| panic!("{e}"));
    for actor in [Actor::System(SystemCause::Timeline), Actor::Account(R1)] {
        let got = s
            .attempt(&close(actor, PR1))
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(
            got.is_none(),
            "R-LA-03, NOTE 13: {actor:?} may not record the stage 1 close"
        );
    }
    let records = s
        .run(&close(Actor::Account(COORDINATOR), PR1))
        .unwrap_or_else(|e| panic!("{e}"));
    let closed = records.iter().find_map(|r| match r {
        Record::Stage1Closed(c) => Some(c.clone()),
        _ => None,
    });
    let closed = closed.unwrap_or_else(|| panic!("R-LA-03: no Stage1Closed in {records:?}"));
    assert_eq!(
        closed.recorder(),
        COORDINATOR,
        "R-LA-03: the recorder is named"
    );
    assert!(closed.passed(), "I-08: 75.00 is strictly above 50.00");
    assert_eq!(
        transitions(&records),
        vec![Transitioned {
            proposal: PR1,
            from: StateTag::Stage1,
            to: StateTag::Stage2,
            row: Row::Stage1ToStage2,
            actor: Actor::Account(COORDINATOR),
            decision: None,
        }],
        "R-AU-01: the transition names its row and the recording coordinator"
    );
}

fn r_la_03_decline_is_recorded_by_the_programme_manager_on(b: Backend) {
    let mut s = one(b);
    s.ranked(L1, PR1, &[R1, R2], &[vec![2, 2], vec![2, 2]])
        .unwrap_or_else(|e| panic!("{e}"));
    s.run(&cut_off(
        R1,
        cut_off_decision(1),
        call(1),
        vec![PR1],
        1,
        false,
        ballots(&[R1, R2, R3], Vote::For),
    ))
    .unwrap_or_else(|e| panic!("{e}"));
    for i in [IRC, IRC2] {
        for st in assign_declared(i, PR1, call(1), AssignmentKind::Irc) {
            s.run(&st).unwrap_or_else(|e| panic!("{e}"));
        }
    }
    let concern = s
        .world
        .assignment(IRC, PR1, Stage::Two, AssignmentKind::Irc)
        .unwrap();
    s.run(&irc_review(IRC, concern, false))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(s.state(PR1), Some(StateTag::IrcReview));
    for actor in [Actor::System(SystemCause::Timeline), Actor::Account(R1)] {
        let got = s
            .attempt(&decline(actor, PR1))
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(
            got.is_none(),
            "NOTE 13, O-49: {actor:?} may not record IRC_REVIEW to DECLINED"
        );
    }
    let records = s
        .run(&decline(Actor::Account(STAFF_PM), PR1))
        .unwrap_or_else(|e| panic!("{e}"));
    let t = transitions(&records);
    assert_eq!(t.len(), 1, "one transition: {records:?}");
    assert_eq!(
        t.first().map(|x| (x.to, x.actor)),
        Some((StateTag::Declined, Actor::Account(STAFF_PM)))
    );
}

fn r_la_03_cut_off_outcomes_follow_the_order_on(b: Backend) {
    let mut s = one(b);
    s.ranked(L1, PR1, &[R1, R2], &[vec![2, 2], vec![2, 2]])
        .unwrap_or_else(|e| panic!("{e}"));
    s.ranked(L2, PR2, &[R1, R2], &[vec![2, 1], vec![2, 1]])
        .unwrap_or_else(|e| panic!("{e}"));
    let records = s
        .run(&cut_off(
            R2,
            cut_off_decision(7),
            call(1),
            vec![PR1, PR2],
            1,
            false,
            ballots(&[R1, R2, R3], Vote::For),
        ))
        .unwrap_or_else(|e| panic!("{e}"));
    let mut t = transitions(&records);
    t.sort_by_key(|x| x.proposal);
    let expect = |p, to, row| Transitioned {
        proposal: p,
        from: StateTag::Ranked,
        to,
        row,
        actor: Actor::Account(R2),
        decision: Some(cut_off_decision(7)),
    };
    assert_eq!(
        t,
        vec![
            expect(PR1, StateTag::IrcReview, Row::RankedToIrcReview),
            expect(PR2, StateTag::NotSelected, Row::RankedToNotSelected),
        ],
        "NOTE 6, R-AU-01: PR1 within the cut-off and PR2 below it, with the decision"
    );
}

/// R-LA-03, NOTE 3, NOTE 13: the FSTP coordinator records the stage 1
/// close, the System and other accounts cannot, and the outcome is computed.
#[test]
fn r_la_03_stage1_close_is_recorded_by_the_coordinator() {
    r_la_03_stage1_close_is_recorded_by_the_coordinator_on(Backend::Production);
}

/// R-LA-03, NOTE 13, O-49: the programme manager records IRC_REVIEW to DECLINED.
#[test]
fn r_la_03_decline_is_recorded_by_the_programme_manager() {
    r_la_03_decline_is_recorded_by_the_programme_manager_on(Backend::Production);
}

/// R-LA-03, NOTE 6: the cut-off outcomes follow from the order and the rank position.
#[test]
fn r_la_03_cut_off_outcomes_follow_the_order() {
    r_la_03_cut_off_outcomes_follow_the_order_on(Backend::Production);
}

/// R-LA-03: the stories above pass on the references alone.
#[test]
fn r_la_03_stories_pass_on_the_reference() {
    r_la_03_stage1_close_is_recorded_by_the_coordinator_on(Backend::Reference);
    r_la_03_decline_is_recorded_by_the_programme_manager_on(Backend::Reference);
    r_la_03_cut_off_outcomes_follow_the_order_on(Backend::Reference);
}

/// R-LA-03, design 3.5: a chosen outcome is rejected. The commands whose
/// outcome is computed decode without an outcome member, and the decoder
/// refuses one that names a target state.
#[test]
fn r_la_03_a_chosen_outcome_is_rejected() {
    for cmd in [
        Command::CloseStage1 { proposal: PR1 },
        Command::RankAfterStage2 { proposal: PR1 },
        Command::ExpireStage2 { proposal: PR1 },
        Command::DeclineAfterConcern { proposal: PR1 },
    ] {
        let v = cmd.to_json();
        assert_eq!(
            fstp_domain::codec::command_from_json(&v).ok(),
            Some(cmd.clone()),
            "{:?} round-trips",
            cmd.kind()
        );
        let mut chosen = v.clone();
        let Value::Object(o) = &mut chosen else {
            panic!("a command encodes as an object");
        };
        o.insert("outcome", Value::String("STAGE2".to_owned()));
        assert!(
            fstp_domain::codec::command_from_json(&chosen).is_err(),
            "R-LA-03: {:?} with a chosen outcome must be refused",
            cmd.kind()
        );
    }
}

/// R-LA-03, NOTE 3: `stage1_ready` offers a closable stage 1 to the
/// coordinator, and `due` never returns `CloseStage1`.
#[test]
fn r_la_03_stage1_close_is_offered_to_the_coordinator_not_the_system() {
    let mut s = one(Backend::Production);
    s.to_stage1(L1, PR1, &[R1, R2])
        .unwrap_or_else(|e| panic!("{e}"));
    let now = s.world.now();
    let state = &s.world.rev.sod.state;
    assert!(
        !fstp_domain::stage1_ready(state, now).contains(&PR1),
        "NOTE 3: stage 1 cannot close before the reviewers score"
    );
    s.score_stage1(PR1, &[R1, R2], &[vec![2, 1], vec![0, 0]])
        .unwrap_or_else(|e| panic!("{e}"));
    let state = &s.world.rev.sod.state;
    assert!(
        fstp_domain::stage1_ready(state, now).contains(&PR1),
        "NOTE 3: every active reviewer scored and P-03 valid scores exist"
    );
    assert!(
        fstp_domain::due(state, now)
            .iter()
            .all(|c| c.kind() != CommandKind::CloseStage1),
        "R-LA-03: the System never records the stage 1 close"
    );
}
