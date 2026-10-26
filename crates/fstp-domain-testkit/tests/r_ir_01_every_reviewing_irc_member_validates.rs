//! R-IR-01: at least P-15 IRC members review each nominated proposal, and IRC_REVIEW to NEGOTIATION needs every reviewing member's validation.
//!
//! The stories run production commands from genesis with P-15 = 2. Every
//! step is compared with the lifecycle reference in both directions.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::assignment::AssignmentKind;
use fstp_domain::decision::Vote;
use fstp_domain::rules::StateTag;
use fstp_domain::scoring::Stage;
use fstp_domain_testkit::r#gen::review::{IRC, L1, PR1, R1, R2, R3};
use fstp_domain_testkit::r#gen::roster::{Backend, call};
use fstp_domain_testkit::mc::life_model::{
    IRC2, Story, assign_declared, ballots, cut_off, cut_off_decision, irc_review, life_judges,
    story_setup,
};

fn nominated(backend: Backend) -> Story {
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
    s
}

fn validate(s: &mut Story, i: fstp_domain::id::AccountId) {
    let a = s
        .world
        .assignment(i, PR1, Stage::Two, AssignmentKind::Irc)
        .unwrap();
    s.run(&irc_review(i, a, true))
        .unwrap_or_else(|e| panic!("{e}"));
}

fn assign(s: &mut Story, i: fstp_domain::id::AccountId) {
    for st in assign_declared(i, PR1, call(1), AssignmentKind::Irc) {
        s.run(&st).unwrap_or_else(|e| panic!("{e}"));
    }
}

fn r_ir_01_p15_members_must_all_validate_on(b: Backend) {
    let mut s = nominated(b);
    assign(&mut s, IRC);
    validate(&mut s, IRC);
    assert_eq!(
        s.state(PR1),
        Some(StateTag::IrcReview),
        "R-IR-01: one validation is fewer than P-15"
    );
    assign(&mut s, IRC2);
    validate(&mut s, IRC2);
    assert_eq!(
        s.state(PR1),
        Some(StateTag::Negotiation),
        "R-IR-01: every one of P-15 reviewing members validated"
    );
}

/// R-IR-01: NEGOTIATION needs at least P-15 IRC assignments, every one validated.
#[test]
fn r_ir_01_p15_members_must_all_validate() {
    r_ir_01_p15_members_must_all_validate_on(Backend::Production);
}

/// R-IR-01: the story passes on the references alone.
#[test]
fn r_ir_01_story_passes_on_the_reference() {
    r_ir_01_p15_members_must_all_validate_on(Backend::Reference);
}
