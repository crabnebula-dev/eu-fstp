//! I-06 and SoD-09 at GRANTED: an applicant whose verification reveals a Drafting account of the same identity never reaches GRANTED (NOTE 9, Identity discovery).
//!
//! Lead c carries the identity of the staff call drafter, but is not
//! verified, so the draft passes SoD-09 and I-06. The proposal reaches
//! NEGOTIATION from genesis by production commands and R1 determines
//! 4.00. Then the vault verifies c in NEGOTIATION. The reaction in the same
//! step voids c's Applicant binding under I-06, and the call drafter's
//! Drafting binding stays (O-53). The grant facts never make the proposal
//! GRANTED, and the programme manager records NEGOTIATION to DECLINED for
//! SoD-09 or the I-06 void. A lead that is never verified is declined for
//! identity verification. The deferred half of I-06 is that GRANTED keeps
//! I-06 and SoD-09.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::Actor;
use fstp_domain::decision::NegotiationFailure;
use fstp_domain::record::Record;
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::money::{
    LC, MoneySetup, MoneyStory, PC, accept_grant, approve_grant, contract_effective,
    decline_negotiation,
};
use fstp_domain_testkit::r#gen::roster::{Backend, STAFF_PM};
use fstp_domain_testkit::vault::IdentityTag;

fn setup() -> MoneySetup {
    let mut s = MoneySetup::sybil([400, 400, 400]);
    s.drafts.retain(|d| d.proposal == PC);
    s.unverified = vec![LC];
    // The staff call drafter's identity, from `add_staff`.
    s.identities = vec![(LC, IdentityTag::new(904))];
    s
}

fn declined_reason(recs: &[Record]) -> Option<NegotiationFailure> {
    recs.iter().find_map(|r| match r {
        Record::NegotiationDeclined { reason, .. } => Some(*reason),
        _ => None,
    })
}

fn sybil_revealed(b: Backend) {
    let mut s = MoneyStory::new(&setup(), b).unwrap_or_else(|e| panic!("setup: {e}"));
    s.determine(PC, 1, &[])
        .unwrap_or_else(|e| panic!("R1 determines 4.00: {e}"));
    let reaction = s
        .world
        .vault(|t| t.verify(LC))
        .unwrap_or_else(|e| panic!("the vault reaction: {e}"));
    assert!(
        reaction
            .iter()
            .any(|r| matches!(r, Record::BindingVoided(v) if v.rule == fstp_domain::refusal::RuleRef::I06)),
        "Identity discovery: the reaction voids c's Applicant binding under I-06: {reaction:?}"
    );
    s.refused(&accept_grant(LC, PC))
        .unwrap_or_else(|e| panic!("enforcement point 2: a voided lead cannot accept: {e}"));
    let _ = s
        .attempt(&approve_grant(STAFF_PM, PC))
        .unwrap_or_else(|e| panic!("{e}"));
    let _ = s
        .attempt(&contract_effective(PC))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_ne!(s.state(PC), Some(StateTag::Granted), "I-06: never GRANTED");
    let recs = s
        .run(&decline_negotiation(Actor::Account(STAFF_PM), PC))
        .unwrap_or_else(|e| panic!("NOTE 9: the programme manager records DECLINED: {e}"));
    let reason = declined_reason(&recs);
    assert!(
        matches!(
            reason,
            Some(NegotiationFailure::ReceivingVoidedUnderI06 | NegotiationFailure::Sod09Refused)
        ),
        "NOTE 9: the reason is SoD-09 or the I-06 void, got {reason:?}"
    );
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

fn never_verified(b: Backend) {
    let mut s = MoneyStory::new(&setup(), b).unwrap_or_else(|e| panic!("setup: {e}"));
    s.determine(PC, 1, &[])
        .unwrap_or_else(|e| panic!("R1 determines 4.00: {e}"));
    s.run(&accept_grant(LC, PC))
        .unwrap_or_else(|e| panic!("c accepts: {e}"));
    s.run(&approve_grant(STAFF_PM, PC))
        .unwrap_or_else(|e| panic!("the programme manager approves: {e}"));
    let _ = s
        .attempt(&contract_effective(PC))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_ne!(
        s.state(PC),
        Some(StateTag::Granted),
        "row NEGOTIATION to GRANTED: identity verified is a guard"
    );
    let recs = s
        .run(&decline_negotiation(Actor::Account(STAFF_PM), PC))
        .unwrap_or_else(|e| panic!("NOTE 9: the programme manager records DECLINED: {e}"));
    assert_eq!(
        declined_reason(&recs),
        Some(NegotiationFailure::IdentityNotVerified),
        "NOTE 9: identity verification fails"
    );
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// I-06, SoD-09, NOTE 9: a Sybil of a Drafting account revealed in
/// NEGOTIATION is never granted and is declined.
#[test]
fn i06_granted_sybil_of_staff_is_never_granted() {
    sybil_revealed(Backend::Production);
}

/// SoD-09, NOTE 9: an unverified lead is never granted and is declined
/// for identity verification.
#[test]
fn i06_granted_unverified_lead_is_never_granted() {
    never_verified(Backend::Production);
}

/// I-06: the stories pass on the references alone.
#[test]
fn i06_granted_stories_pass_on_the_reference() {
    sybil_revealed(Backend::Reference);
    never_verified(Backend::Reference);
}
