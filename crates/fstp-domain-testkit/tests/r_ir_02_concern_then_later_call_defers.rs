//! R-IR-02, NOTE 7: a concern raised while no later call exists defers the proposal once a later call of the programme is published.
//!
//! The story runs production commands from genesis and compares every step
//! with the lifecycle reference in both directions. IRC raises a concern
//! on PR1 while call 1 is the programme's only published call, so PR1
//! waits in IRC_REVIEW for the programme manager's decline. Call 2 is then
//! published. The decline guard "no future call" no longer holds, and the
//! deferral guard "concern raised; future call exists" does.
//!
//! - The programme manager's `DeclineAfterConcern` is refused (NOTE 7).
//! - `due` lists the System's `DeclineAfterConcern`, which records the
//!   deferral with the stage left and takes PR1 to DEFERRED. It carries no
//!   decision, since its outcome is computed (NOTE 13).
//! - PR1 then re-enters IRC_REVIEW in call 2 (NOTE 8).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::assignment::AssignmentKind;
use fstp_domain::command::{Actor, Command, SystemCause};
use fstp_domain::decision::Vote;
use fstp_domain::proposal::ReentryStage;
use fstp_domain::record::Record;
use fstp_domain::rules::{Row, StateTag};
use fstp_domain::scoring::Stage;
use fstp_domain_testkit::r#gen::review::{IRC, L1, PR1, R1, R2, R3};
use fstp_domain_testkit::r#gen::roster::{Backend, STAFF_PM, call, publish};
use fstp_domain_testkit::mc::life_model::{
    IRC2, Story, assign_declared, ballots, cut_off, cut_off_decision, decline, irc_review,
    life_judges, reenter, story_setup,
};

fn r_ir_02_concern_then_later_call_defers_on(b: Backend) {
    let setup = story_setup(vec![(L1, PR1, false)], life_judges());
    let mut s = Story::new(&setup, b, |_| {}).unwrap_or_else(|e| panic!("{e}"));
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
    let a = s
        .world
        .assignment(IRC, PR1, Stage::Two, AssignmentKind::Irc)
        .unwrap();
    s.run(&irc_review(IRC, a, false))
        .unwrap_or_else(|e| panic!("IRC raises a concern: {e}"));
    assert_eq!(s.state(PR1), Some(StateTag::IrcReview));
    s.run(&publish(call(2))).unwrap_or_else(|e| panic!("{e}"));
    let by_pm = s
        .attempt(&decline(Actor::Account(STAFF_PM), PR1))
        .unwrap_or_else(|e| panic!("{e}"));
    assert!(
        by_pm.is_none(),
        "NOTE 7: the decline needs no future call, and call 2 is published"
    );
    if b == Backend::Production {
        let due = fstp_domain::due(&s.world.rev.sod.state, s.world.now());
        assert!(
            due.contains(&Command::DeclineAfterConcern { proposal: PR1 }),
            "NOTE 7: due lists the System's deferral after the concern: {due:?}"
        );
    }
    let records = s
        .run(&decline(Actor::System(SystemCause::Timeline), PR1))
        .unwrap_or_else(|e| panic!("NOTE 7: the System defers PR1: {e}"));
    assert!(
        records.contains(&Record::DeferralRecorded {
            proposal: PR1,
            from_call: call(1),
            left: ReentryStage::IrcReview,
        }),
        "NOTE 8: the deferral records the call and the stage left: {records:?}"
    );
    assert!(
        records.iter().any(|r| matches!(r, Record::Transitioned(t)
            if t.row == Row::IrcReviewToDeferred && t.decision.is_none())),
        "NOTE 7, NOTE 13: IRC_REVIEW to DEFERRED with no decision: {records:?}"
    );
    assert_eq!(s.state(PR1), Some(StateTag::Deferred));
    s.run(&reenter(PR1, call(2)))
        .unwrap_or_else(|e| panic!("NOTE 8: re-entry into call 2: {e}"));
    assert_eq!(s.state(PR1), Some(StateTag::IrcReview));
}

/// R-IR-02, NOTE 7, NOTE 13: a concern raised before a later call is
/// published defers the proposal by the System once the call is published.
#[test]
fn r_ir_02_concern_then_later_call_defers() {
    r_ir_02_concern_then_later_call_defers_on(Backend::Production);
}

/// R-IR-02: the story above passes on the references alone.
#[test]
fn r_ir_02_concern_then_later_call_defers_reference() {
    r_ir_02_concern_then_later_call_defers_on(Backend::Reference);
}
