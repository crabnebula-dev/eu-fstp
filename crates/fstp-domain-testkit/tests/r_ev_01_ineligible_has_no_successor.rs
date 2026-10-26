//! R-EV-01: a proposal failing a knock-out criterion receives no further review (design 6.4).
//!
//! The model check runs M-LIFECYCLE from DRAFT, built from genesis. Its
//! transition property says that INELIGIBLE is never left and gets no
//! further assignment or score. The stories check the knock-out record:
//! the FSTP coordinator declares on the proposal first (I-03), every P-09
//! criterion has exactly one outcome, and a failed one needs a reason.
//! Every step is compared with the lifecycle reference in both directions.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::assignment::AssignmentKind;
use fstp_domain::command::{Command, DeclarationSubject, KnockOutResult};
use fstp_domain::id::KnockOutCriterionId;
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::policy::text;
use fstp_domain_testkit::r#gen::review::{COORDINATOR, L1, PR1, R1, R2, R3, declare, withdraw};
use fstp_domain_testkit::r#gen::roster::{Backend, call};
use fstp_domain_testkit::harness::mc::check_exhaustive;
use fstp_domain_testkit::mc::life_model::{
    LifeModel, Story, T_EVAL, admit, assign_declared, by, knock_out, knock_out_decision,
    life_judges, story_setup,
};
use fstp_domain_testkit::mc::lifecycle_model::{
    M_LIFECYCLE_STATES, lifecycle_config, r_ev_01_properties,
};

fn model(backend: Backend) {
    let model = LifeModel::new(lifecycle_config(), backend)
        .unwrap_or_else(|e| panic!("M-LIFECYCLE start from genesis: {e}"));
    if let Err(e) = check_exhaustive(
        &model,
        &r_ev_01_properties::<LifeModel>(),
        M_LIFECYCLE_STATES,
    ) {
        panic!("{e}");
    }
}

fn submitted(backend: Backend) -> Story {
    let setup = story_setup(vec![(L1, PR1, false)], life_judges());
    let mut s = Story::new(&setup, backend, |_| {}).unwrap_or_else(|e| panic!("{e}"));
    s.submit(L1, PR1).unwrap_or_else(|e| panic!("{e}"));
    s.at(T_EVAL);
    for r in [R1, R2] {
        for st in assign_declared(r, PR1, call(1), AssignmentKind::Reviewer) {
            s.run(&st).unwrap_or_else(|e| panic!("{e}"));
        }
    }
    s
}

fn outcomes(ids: &[u128], failed: Option<u128>) -> Vec<KnockOutResult> {
    ids.iter()
        .map(|c| KnockOutResult {
            criterion: KnockOutCriterionId::from_raw(*c),
            passed: Some(*c) != failed,
        })
        .collect()
}

fn ko(
    ids: &[u128],
    failed: Option<u128>,
    reason: bool,
) -> fstp_domain_testkit::r#gen::roster::Step {
    by(
        COORDINATOR,
        Command::RecordKnockOut {
            decision: knock_out_decision(PR1),
            proposal: PR1,
            outcomes: outcomes(ids, failed),
            reason: reason.then(|| text(81_500)),
        },
    )
}

fn r_ev_01_knock_out_record_rules_on(b: Backend) {
    let mut s = submitted(b);
    let early = s
        .attempt(&knock_out(PR1, true))
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        early.is_none(),
        "I-03, Conflict declarations: the coordinator declares on the proposal before the knock-out"
    );
    s.run(&declare(
        COORDINATOR,
        DeclarationSubject::Proposal(PR1),
        false,
        false,
    ))
    .unwrap_or_else(|e| panic!("{e}"));
    for (step, why) in [
        (ko(&[1, 2], None, false), "a P-09 criterion has no outcome"),
        (
            ko(&[1, 2, 2, 3], None, false),
            "a P-09 criterion has two outcomes",
        ),
        (
            ko(&[1, 2, 3, 4], None, false),
            "an outcome names no P-09 criterion",
        ),
        (
            ko(&[1, 2, 3], Some(2), false),
            "a failed criterion needs a reason",
        ),
    ] {
        let got = s.attempt(&step).unwrap_or_else(|e| panic!("{e}"));
        assert!(
            got.is_none(),
            "R-EV-01: {why}, the knock-out must be refused"
        );
    }
    s.run(&ko(&[1, 2, 3], Some(2), true))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(s.state(PR1), Some(StateTag::Ineligible));
}

fn r_ev_01_ineligible_gets_no_further_review_on(b: Backend) {
    let mut s = submitted(b);
    s.run(&declare(
        COORDINATOR,
        DeclarationSubject::Proposal(PR1),
        false,
        false,
    ))
    .unwrap_or_else(|e| panic!("{e}"));
    s.run(&knock_out(PR1, false))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(s.state(PR1), Some(StateTag::Ineligible));
    let mut later = vec![admit(PR1), withdraw(L1, PR1)];
    later.extend(assign_declared(R3, PR1, call(1), AssignmentKind::Reviewer));
    for step in later {
        let got = s.attempt(&step).unwrap_or_else(|e| panic!("{e}"));
        assert!(
            got.is_none(),
            "R-EV-01, NOTE 10: {:?} on an INELIGIBLE proposal must be refused",
            step.cmd.kind()
        );
    }
}

/// R-EV-01, NOTE 10: on M-LIFECYCLE, INELIGIBLE has no successor and gets
/// no further assignment or score.
#[test]
fn r_ev_01_ineligible_has_no_successor() {
    model(Backend::Production);
}

/// R-EV-01: the model passes on the references alone.
#[test]
fn r_ev_01_ineligible_has_no_successor_reference() {
    model(Backend::Reference);
}

/// R-EV-01, I-03: the knock-out record names every P-09 criterion once, a
/// failure needs a reason, and the coordinator declares first.
#[test]
fn r_ev_01_knock_out_record_rules() {
    r_ev_01_knock_out_record_rules_on(Backend::Production);
}

/// R-EV-01: after a failed knock-out, admission, assignment and withdrawal are refused.
#[test]
fn r_ev_01_ineligible_gets_no_further_review() {
    r_ev_01_ineligible_gets_no_further_review_on(Backend::Production);
}

/// R-EV-01: the stories pass on the references alone.
#[test]
fn r_ev_01_stories_pass_on_the_reference() {
    r_ev_01_knock_out_record_rules_on(Backend::Reference);
    r_ev_01_ineligible_gets_no_further_review_on(Backend::Reference);
}
