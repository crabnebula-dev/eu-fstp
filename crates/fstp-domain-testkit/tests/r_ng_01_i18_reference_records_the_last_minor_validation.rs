//! R-NG-01 (guardian note) and I-18: the lifecycle reference requires the
//! last validation of a minor-flagged proposal to be recorded.
//!
//! Consent collection opens once every reviewing IRC member has validated
//! a minor-flagged proposal (`SPEC/01-requirements/functional.md` R-NG-01,
//! guardian note). The proposal stays in IRC_REVIEW until the consent
//! record is effective (`02-domain/state-machine.md` NOTE 14). A refusal
//! of the last validation would leave it unrecorded, so collection would
//! never open. The reference must therefore demand the record, with no
//! transition, and not merely allow it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::assignment::AssignmentKind;
use fstp_domain::decision::Vote;
use fstp_domain::id::{AccountId, AssignmentId};
use fstp_domain::rules::StateTag;
use fstp_domain::scoring::Stage;
use fstp_domain_testkit::r#gen::review::{IRC, L1, PR1, R1, R2, R3};
use fstp_domain_testkit::r#gen::roster::{Backend, call};
use fstp_domain_testkit::mc::life_model::{
    IRC2, Story, assign_declared, ballots, cut_off, cut_off_decision, irc_review, life_judges,
    story_setup,
};
use fstp_domain_testkit::reference::lifecycle::LifeVerdict;
use fstp_domain_testkit::vault::GroundTruth;

fn irc_assignment(s: &Story, member: AccountId) -> AssignmentId {
    s.world
        .assignment(member, PR1, Stage::Two, AssignmentKind::Irc)
        .unwrap_or_else(|| panic!("no IRC assignment of {member:?}"))
}

/// The reference verdict on IRC2's validation of PR1, after IRC validated
/// it. L1 has no attestation and PR1 has no consent, so PR1 is
/// minor-flagged at the gate.
fn last_minor_validation(b: Backend) -> LifeVerdict {
    let setup = story_setup(vec![(L1, PR1, true)], life_judges());
    let mut s = Story::new(&setup, b, |t: &mut GroundTruth| {
        t.withdraw_attestation(L1);
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
    let a = irc_assignment(&s, IRC);
    s.run(&irc_review(IRC, a, true))
        .unwrap_or_else(|e| panic!("IRC validates: {e}"));
    assert_eq!(s.state(PR1), Some(StateTag::IrcReview), "one validation");
    let a2 = irc_assignment(&s, IRC2);
    s.world.life_verdict(&irc_review(IRC2, a2, true))
}

/// R-NG-01 (guardian note), I-18, NOTE 14: the reference demands that the
/// last validation of a minor-flagged proposal without consent is recorded
/// with no transition. It never allows a refusal.
#[test]
fn r_ng_01_i18_reference_demands_the_last_minor_validation() {
    match last_minor_validation(Backend::Reference) {
        LifeVerdict::Accept(e) => assert!(
            e.transitions.is_empty(),
            "I-18: PR1 must stay in IRC_REVIEW, the reference expects {:?}",
            e.transitions
        ),
        other => panic!(
            "R-NG-01: the reference must demand the last validation, since a \
             refusal never opens consent collection. It says {other:?}"
        ),
    }
}
