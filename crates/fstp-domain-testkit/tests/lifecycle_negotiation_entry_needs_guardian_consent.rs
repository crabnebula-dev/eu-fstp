//! I-18 and R-NG-02: a minor's proposal enters NEGOTIATION only with a verified guardian consent (NOTE 9).
//!
//! The stories run production commands from genesis. PR1 is flagged as a
//! minor's proposal and needs no guardian record to be submitted (R-SB-02).
//! After the cut-off, IRC and IRC2 validate it. Without a consent record in
//! the vault the last validation may be refused or recorded, but the
//! proposal must not enter NEGOTIATION. With the record it does.

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

fn validated(backend: Backend, consent: bool) -> Story {
    let setup = story_setup(vec![(L1, PR1, true)], life_judges());
    let mut s = Story::new(&setup, backend, |t| {
        if consent {
            t.consent(PR1);
        }
    })
    .unwrap_or_else(|e| panic!("{e}"));
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
    for i in [IRC, IRC2] {
        let a = s
            .world
            .assignment(i, PR1, Stage::Two, AssignmentKind::Irc)
            .unwrap();
        s.attempt(&irc_review(i, a, true))
            .unwrap_or_else(|e| panic!("{e}"));
    }
    s
}

fn without_consent_on(b: Backend) {
    let s = validated(b, false);
    assert_eq!(
        s.state(PR1),
        Some(StateTag::IrcReview),
        "I-18, R-NG-02: no guardian consent, so PR1 must not enter NEGOTIATION"
    );
}

fn with_consent_on(b: Backend) {
    let s = validated(b, true);
    assert_eq!(
        s.state(PR1),
        Some(StateTag::Negotiation),
        "I-18, R-NG-02: with a verified guardian consent PR1 enters NEGOTIATION"
    );
}

/// I-18, R-NG-02, NOTE 9: without a verified guardian consent a minor's
/// proposal stays out of NEGOTIATION.
#[test]
fn i18_rng02_minor_without_consent_does_not_enter_negotiation() {
    without_consent_on(Backend::Production);
}

/// I-18, R-NG-02: with a verified guardian consent a minor's proposal enters NEGOTIATION.
#[test]
fn i18_rng02_minor_with_consent_enters_negotiation() {
    with_consent_on(Backend::Production);
}

/// I-18: the stories pass on the references alone.
#[test]
fn i18_rng02_stories_pass_on_the_reference() {
    without_consent_on(Backend::Reference);
    with_consent_on(Backend::Reference);
}
