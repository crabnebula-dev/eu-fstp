//! Review reproducer for lane dom: the SoD reference's minor flag on the reference backend.
//!
//! `SPEC/01-requirements/functional.md` R-ID-04 (Derivation note) and
//! `02-domain/state-machine.md` NOTE 14: a proposal is minor-flagged
//! unless the vault reports an effective verified over-18 attestation of
//! its lead at the deadline. The SoD reference (`reference/sod.rs`)
//! refuses `AddGuardian` on a proposal that is not minor-flagged, as
//! production does. It derives the flag only from a `VaultOutcome` of
//! `IsVerifiedAdultAtDeadline` folded before the gate's transition.
//! The reference backend writes no `VaultOutcome` records, so on that
//! backend the SoD view never clears the flag.
//!
//! Story: PR1 of L1, with the actor's field set and no attestation. IRC
//! and IRC2 validate, so PR1 stays in IRC_REVIEW. The vault then records
//! an effective attestation that shows L1 18 or older before the
//! deadline. IRC repeats the validation, and the gate admits PR1 on the
//! attestation. Production then refuses `AddGuardian`. The reference
//! backend must refuse it too.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::assignment::AssignmentKind;
use fstp_domain::decision::Vote;
use fstp_domain::id::{AccountId, AssignmentId, BindingId};
use fstp_domain::rules::StateTag;
use fstp_domain::scoring::Stage;
use fstp_domain_testkit::r#gen::review::{IRC, L1, PR1, R1, R2, R3, tag};
use fstp_domain_testkit::r#gen::roster::{Backend, LEAD_ADULT_FROM, add_member, call};
use fstp_domain_testkit::mc::life_model::{
    IRC2, Story, assign_declared, ballots, cut_off, cut_off_decision, irc_review, life_judges,
    story_setup,
};
use fstp_domain_testkit::vault::GroundTruth;

/// A verified guardian account outside the setup.
const GUARDIAN: AccountId = AccountId::from_raw(9_911);

fn irc_assignment(s: &Story, member: AccountId) -> AssignmentId {
    s.world
        .assignment(member, PR1, Stage::Two, AssignmentKind::Irc)
        .unwrap_or_else(|| panic!("no IRC assignment of {member:?}"))
}

/// Whether `AddGuardian` on PR1 is accepted after the gate admitted PR1
/// on the lead's late attestation, on `b`.
fn add_guardian_after_adult_gate(b: Backend) -> bool {
    let setup = story_setup(vec![(L1, PR1, true)], life_judges());
    let mut s = Story::new(&setup, b, |t: &mut GroundTruth| {
        t.withdraw_attestation(L1);
        t.set_identity(GUARDIAN, tag(GUARDIAN));
        t.verify(GUARDIAN);
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
        let a = irc_assignment(&s, i);
        s.attempt(&irc_review(i, a, true))
            .unwrap_or_else(|e| panic!("{e}"));
    }
    assert_eq!(s.state(PR1), Some(StateTag::IrcReview), "minor-flagged");
    s.vault(|t| t.attest_adult(L1, LEAD_ADULT_FROM))
        .unwrap_or_else(|e| panic!("{e}"));
    let a = irc_assignment(&s, IRC);
    s.run(&irc_review(IRC, a, true))
        .unwrap_or_else(|e| panic!("R-IR-01: the repeat records the entry: {e}"));
    assert_eq!(
        s.state(PR1),
        Some(StateTag::Negotiation),
        "admitted as adult"
    );
    let step = add_member(L1, PR1, GUARDIAN, BindingId::from_raw(9_913), true);
    s.attempt(&step).unwrap_or_else(|e| panic!("{e}")).is_some()
}

/// R-ID-04, NOTE 14: once the gate found the attestation, PR1 is not
/// minor-flagged, so the SoD reference refuses `AddGuardian` on the
/// reference backend, as production does.
#[test]
fn review_r_id_04_reference_backend_clears_the_flag_at_an_adult_gate() {
    assert!(
        !add_guardian_after_adult_gate(Backend::Production),
        "control: production refuses AddGuardian after an adult gate"
    );
    assert!(
        !add_guardian_after_adult_gate(Backend::Reference),
        "R-ID-04: the reference backend accepts AddGuardian on PR1, which \
         its gate admitted on the lead's attestation. The SoD view reads \
         the flag only from VaultOutcome records, and the reference \
         backend writes none, so the flag is never cleared"
    );
}
