//! R-NG-02, I-18, NOTE 9: guardian consent is checked again before GRANTED.
//!
//! Lead c is flagged as a minor and the vault holds a verified guardian
//! consent, so the proposal enters NEGOTIATION from genesis by production
//! commands. With the consent, the grant facts make it GRANTED. When the
//! vault withdraws the consent in NEGOTIATION, the facts never make it
//! GRANTED, and the programme manager records DECLINED for the missing
//! consent.

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

fn setup() -> MoneySetup {
    let mut s = MoneySetup::sybil([400, 400, 400]);
    s.drafts.retain(|d| d.proposal == PC);
    if let Some(d) = s.drafts.first_mut() {
        d.minor = true;
    }
    s.consents = vec![PC];
    s
}

fn with_consent(b: Backend) {
    let mut s = MoneyStory::new(&setup(), b).unwrap_or_else(|e| panic!("setup: {e}"));
    s.grant(PC)
        .unwrap_or_else(|e| panic!("I-18: with the consent c is granted: {e}"));
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

fn withdrawn(b: Backend) {
    let mut s = MoneyStory::new(&setup(), b).unwrap_or_else(|e| panic!("setup: {e}"));
    s.determine(PC, 1, &[])
        .unwrap_or_else(|e| panic!("R1 determines 4.00: {e}"));
    s.world
        .vault(|t| t.withdraw_consent(PC))
        .unwrap_or_else(|e| panic!("the vault reaction: {e}"));
    let _ = s
        .attempt(&accept_grant(LC, PC))
        .unwrap_or_else(|e| panic!("{e}"));
    let _ = s
        .attempt(&approve_grant(STAFF_PM, PC))
        .unwrap_or_else(|e| panic!("{e}"));
    let _ = s
        .attempt(&contract_effective(PC))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_ne!(
        s.state(PC),
        Some(StateTag::Granted),
        "I-18, NOTE 9: consent is checked again before GRANTED"
    );
    let recs = s
        .run(&decline_negotiation(Actor::Account(STAFF_PM), PC))
        .unwrap_or_else(|e| panic!("NOTE 9: the programme manager records DECLINED: {e}"));
    assert!(
        recs.iter().any(|r| matches!(
            r,
            Record::NegotiationDeclined {
                reason: NegotiationFailure::GuardianConsentMissing,
                ..
            }
        )),
        "NOTE 9: the reason is the missing consent: {recs:?}"
    );
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// R-NG-02, I-18: a minor with a verified guardian consent is granted.
#[test]
fn r_ng_02_minor_with_consent_is_granted() {
    with_consent(Backend::Production);
}

/// R-NG-02, I-18, NOTE 9: a consent withdrawn in NEGOTIATION blocks GRANTED.
#[test]
fn r_ng_02_withdrawn_consent_blocks_the_grant() {
    withdrawn(Backend::Production);
}

/// R-NG-02: the stories pass on the references alone.
#[test]
fn r_ng_02_stories_pass_on_the_reference() {
    with_consent(Backend::Reference);
    withdrawn(Backend::Reference);
}
