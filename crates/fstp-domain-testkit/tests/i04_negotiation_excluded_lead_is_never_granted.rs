//! I-04 at negotiation: an excluded applicant revealed in NEGOTIATION never reaches GRANTED (NOTE 9, Identity discovery, Q5 A).
//!
//! Lead c reaches NEGOTIATION from genesis by production commands, and R1
//! determines 4.00. Then the vault reports that c's identity is in the
//! excluded class K1 of P-13. The reaction in the same step voids c's
//! Applicant binding under I-04 (`roles-and-sod.md` Identity discovery),
//! so the lead can no longer accept, and the grant facts never make the
//! proposal GRANTED. The programme manager records NEGOTIATION to
//! DECLINED with that reason, which releases the reservation. The deferred
//! half of I-04 is that GRANTED keeps I-04 for every Receiving account.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::Actor;
use fstp_domain::decision::NegotiationFailure;
use fstp_domain::record::Record;
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::money::{
    LC, MoneySetup, MoneyStory, PC, accept_grant, approve_grant, contract_effective,
    decline_negotiation,
};
use fstp_domain_testkit::r#gen::review::tag;
use fstp_domain_testkit::r#gen::roster::{Backend, K1, STAFF_PM};

fn setup() -> MoneySetup {
    let mut s = MoneySetup::sybil([400, 400, 400]);
    s.drafts.retain(|d| d.proposal == PC);
    s
}

fn excluded(b: Backend, before_facts: bool) {
    let mut s = MoneyStory::new(&setup(), b).unwrap_or_else(|e| panic!("setup: {e}"));
    s.determine(PC, 1, &[])
        .unwrap_or_else(|e| panic!("R1 determines 4.00: {e}"));
    if !before_facts {
        s.run(&accept_grant(LC, PC))
            .unwrap_or_else(|e| panic!("c accepts: {e}"));
        s.run(&approve_grant(STAFF_PM, PC))
            .unwrap_or_else(|e| panic!("the programme manager approves: {e}"));
    }
    let reaction = s
        .world
        .vault(|t| t.exclude(tag(LC), K1))
        .unwrap_or_else(|e| panic!("the vault reaction: {e}"));
    assert!(
        reaction
            .iter()
            .any(|r| matches!(r, Record::BindingVoided(v) if v.rule == fstp_domain::refusal::RuleRef::I04)),
        "Identity discovery: the reaction voids c's Applicant binding under I-04: {reaction:?}"
    );
    if before_facts {
        s.refused(&accept_grant(LC, PC))
            .unwrap_or_else(|e| panic!("enforcement point 2: a voided lead cannot accept: {e}"));
    } else {
        let _ = s
            .attempt(&contract_effective(PC))
            .unwrap_or_else(|e| panic!("the contract fact after the exclusion: {e}"));
    }
    assert_ne!(
        s.state(PC),
        Some(StateTag::Granted),
        "I-04: an excluded applicant never reaches GRANTED"
    );
    let recs = s
        .run(&decline_negotiation(Actor::Account(STAFF_PM), PC))
        .unwrap_or_else(|e| panic!("NOTE 9: the programme manager records DECLINED: {e}"));
    assert!(
        recs.iter().any(|r| matches!(
            r,
            Record::NegotiationDeclined {
                reason: NegotiationFailure::ReceivingVoidedUnderI04,
                ..
            }
        )),
        "NOTE 9: the reason is the I-04 void: {recs:?}"
    );
    assert_eq!(s.state(PC), Some(StateTag::Declined));
    assert_eq!(
        s.world.money.counted(PC),
        0,
        "the decline releases the reservation"
    );
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// I-04, NOTE 9: an exclusion revealed before the grant facts blocks the
/// lead's acceptance and ends in DECLINED.
#[test]
fn i04_negotiation_excluded_lead_cannot_accept_and_is_declined() {
    excluded(Backend::Production, true);
}

/// I-04, NOTE 9: an exclusion revealed between the facts keeps the
/// contract fact from granting, and ends in DECLINED.
#[test]
fn i04_negotiation_exclusion_between_facts_blocks_the_grant() {
    excluded(Backend::Production, false);
}

/// I-04: the stories pass on the references alone.
#[test]
fn i04_negotiation_stories_pass_on_the_reference() {
    excluded(Backend::Reference, true);
    excluded(Backend::Reference, false);
}
