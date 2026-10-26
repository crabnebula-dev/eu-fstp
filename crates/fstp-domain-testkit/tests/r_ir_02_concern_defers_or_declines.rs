//! R-IR-02: an IRC concern is sent to the applicant, and the proposal is deferred or declined per the state machine (NOTE 7, NOTE 13).
//!
//! The model check runs M-LIFECYCLE from DRAFT, built from genesis. Its
//! transition property says that every concern is enqueued for the
//! applicant through the outbox. It defers the proposal exactly when a
//! later call of the programme is published. Otherwise the proposal stays
//! in IRC_REVIEW until the programme manager records the decline. Witnesses
//! reach both outcomes. The stories check the same rows one by one.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::assignment::AssignmentKind;
use fstp_domain::command::Actor;
use fstp_domain::decision::Vote;
use fstp_domain::proposal::ReentryStage;
use fstp_domain::record::{OutboxEvent, Record};
use fstp_domain::rules::StateTag;
use fstp_domain::scoring::Stage;
use fstp_domain_testkit::r#gen::policy::text;
use fstp_domain_testkit::r#gen::review::{IRC, L1, PR1, R1, R2, R3};
use fstp_domain_testkit::r#gen::roster::{Backend, STAFF_PM, call, publish};
use fstp_domain_testkit::harness::mc::check_exhaustive;
use fstp_domain_testkit::mc::life_model::{
    IRC2, LifeModel, Story, assign_declared, ballots, cut_off, cut_off_decision, decline,
    irc_review, life_judges, reenter, story_setup,
};
use fstp_domain_testkit::mc::lifecycle_model::{
    M_LIFECYCLE_STATES, lifecycle_config, r_ir_02_properties,
};

fn model(backend: Backend) {
    let model = LifeModel::new(lifecycle_config(), backend)
        .unwrap_or_else(|e| panic!("M-LIFECYCLE start from genesis: {e}"));
    if let Err(e) = check_exhaustive(
        &model,
        &r_ir_02_properties::<LifeModel>(),
        M_LIFECYCLE_STATES,
    ) {
        panic!("{e}");
    }
}

/// PR1 in IRC_REVIEW in call 1 with IRC and IRC2 assigned and declared.
pub fn in_irc_review(backend: Backend) -> Story {
    let setup = story_setup(vec![(L1, PR1, false)], life_judges());
    let mut s = Story::new(&setup, backend, |_| {}).unwrap_or_else(|e| panic!("{e}"));
    s.ranked(L1, PR1, &[R1, R2], &[vec![2, 2], vec![2, 2]])
        .unwrap_or_else(|e| panic!("PR1 to RANKED: {e}"));
    s.run(&cut_off(
        R1,
        cut_off_decision(1),
        call(1),
        vec![PR1],
        1,
        false,
        ballots(&[R1, R2, R3], Vote::For),
    ))
    .unwrap_or_else(|e| panic!("PR1 to IRC_REVIEW: {e}"));
    for i in [IRC, IRC2] {
        for st in assign_declared(i, PR1, call(1), AssignmentKind::Irc) {
            s.run(&st).unwrap_or_else(|e| panic!("{e}"));
        }
    }
    s
}

fn concern_sent(records: &[Record]) -> bool {
    records.iter().any(|r| {
        matches!(
            r,
            Record::OutboxEnqueued(OutboxEvent::IrcConcern { proposal, concern })
                if *proposal == PR1 && *concern == text(86_000)
        )
    })
}

fn r_ir_02_concern_without_future_call_declines_on(b: Backend) {
    let mut s = in_irc_review(b);
    let a = s
        .world
        .assignment(IRC, PR1, Stage::Two, AssignmentKind::Irc)
        .unwrap();
    let records = s
        .run(&irc_review(IRC, a, false))
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        concern_sent(&records),
        "R-IR-02: the concern goes to the applicant: {records:?}"
    );
    assert_eq!(
        s.state(PR1),
        Some(StateTag::IrcReview),
        "NOTE 7: with no later call the proposal awaits the decline"
    );
    let a2 = s
        .world
        .assignment(IRC2, PR1, Stage::Two, AssignmentKind::Irc)
        .unwrap();
    let after = s
        .attempt(&irc_review(IRC2, a2, true))
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        after.is_none(),
        "R-IR-01: no validation counts once a concern is raised"
    );
    s.run(&decline(Actor::Account(STAFF_PM), PR1))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(s.state(PR1), Some(StateTag::Declined));
}

fn r_ir_02_concern_with_future_call_defers_on(b: Backend) {
    let mut s = in_irc_review(b);
    s.run(&publish(call(2))).unwrap_or_else(|e| panic!("{e}"));
    let a = s
        .world
        .assignment(IRC, PR1, Stage::Two, AssignmentKind::Irc)
        .unwrap();
    let records = s
        .run(&irc_review(IRC, a, false))
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        concern_sent(&records),
        "R-IR-02: the concern goes to the applicant: {records:?}"
    );
    assert!(
        records.iter().any(|r| matches!(
            r,
            Record::DeferralRecorded { proposal, from_call, left: ReentryStage::IrcReview }
                if *proposal == PR1 && *from_call == call(1)
        )),
        "NOTE 7: a later call exists, so the concern defers PR1 from IRC_REVIEW"
    );
    assert_eq!(s.state(PR1), Some(StateTag::Deferred));
    let refused = s
        .attempt(&decline(Actor::Account(STAFF_PM), PR1))
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(refused.is_none(), "a deferred proposal is not declined");
    s.run(&reenter(PR1, call(2)))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        s.state(PR1),
        Some(StateTag::IrcReview),
        "NOTE 8: re-entry at the stage it left"
    );
}

/// R-IR-02, NOTE 7: on M-LIFECYCLE every concern is sent, and defers or awaits the decline.
#[test]
fn r_ir_02_concern_defers_or_declines() {
    model(Backend::Production);
}

/// R-IR-02: the model passes on the references alone.
#[test]
fn r_ir_02_concern_defers_or_declines_reference() {
    model(Backend::Reference);
}

/// R-IR-02, NOTE 7, NOTE 13: a concern without a later call leaves the
/// proposal in IRC_REVIEW, and the programme manager declines it.
#[test]
fn r_ir_02_concern_without_future_call_declines() {
    r_ir_02_concern_without_future_call_declines_on(Backend::Production);
}

/// R-IR-02, NOTE 7, NOTE 8: a concern with a later call defers the
/// proposal, which re-enters at IRC_REVIEW.
#[test]
fn r_ir_02_concern_with_future_call_defers() {
    r_ir_02_concern_with_future_call_defers_on(Backend::Production);
}

/// R-IR-02: the stories pass on the references alone.
#[test]
fn r_ir_02_stories_pass_on_the_reference() {
    r_ir_02_concern_without_future_call_declines_on(Backend::Reference);
    r_ir_02_concern_with_future_call_defers_on(Backend::Reference);
}
