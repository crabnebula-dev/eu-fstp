//! R-ID-04, I-18, NOTE 9: the flag the NEGOTIATION gate derived governs the guard into GRANTED.
//!
//! `SPEC/02-domain/state-machine.md` NOTE 14 derives the minor flag from
//! the vault at the IRC_REVIEW to NEGOTIATION gate, never from the actor.
//! NOTE 9 checks guardian consent again before GRANTED for a minor-flagged
//! proposal (I-18: no minor-flagged proposal reaches GRANTED without
//! consent). Whether the guard into GRANTED derives the flag again is not
//! decided (ADR-008, "Second derivation", interim). So these stories keep
//! the attestation unchanged after the gate, and hold under either answer.
//!
//! - Lead c sends the `minor` field set, but the vault holds an effective
//!   verified over-18 attestation and no consent. The proposal is not
//!   minor-flagged, so the grant facts make it GRANTED.
//! - Lead c sends the field clear, but the vault holds no attestation and a
//!   verified consent. The proposal enters NEGOTIATION minor-flagged. When
//!   the vault withdraws the consent, the facts never make it GRANTED, and
//!   the programme manager records DECLINED for the missing consent.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::Actor;
use fstp_domain::decision::NegotiationFailure;
use fstp_domain::record::Record;
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::money::{
    LC, MoneySetup, MoneyStory, PC, accept_grant, approve_grant, contract_effective,
    decline_negotiation,
};
use fstp_domain_testkit::r#gen::roster::{Backend, LEAD_ADULT_FROM, STAFF_PM};

/// The setup of PC alone, with the actor's `CreateDraft` field `field`.
fn setup(field: bool) -> MoneySetup {
    let mut s = MoneySetup::sybil([400, 400, 400]);
    s.drafts.retain(|d| d.proposal == PC);
    if let Some(d) = s.drafts.first_mut() {
        d.minor = field;
    }
    s
}

fn adult_granted_on(b: Backend) {
    let mut s = MoneyStory::with(&setup(true), b, |t| {
        t.withdraw_attestation(LC);
        t.attest_adult(LC, LEAD_ADULT_FROM);
    })
    .unwrap_or_else(|e| {
        panic!("R-ID-04, NOTE 14: the adult lead's proposal must reach NEGOTIATION: {e}")
    });
    assert!(!s.world.truth().has_consent(PC), "no consent in this story");
    s.grant(PC).unwrap_or_else(|e| {
        panic!("R-ID-04: PC is not minor-flagged, so it is granted without consent: {e}")
    });
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

fn consent_checked_again_on(b: Backend) {
    let mut s = MoneyStory::with(&setup(false), b, |t| {
        t.withdraw_attestation(LC);
        t.consent(PC);
    })
    .unwrap_or_else(|e| {
        panic!("I-18, NOTE 14: the consent admits the minor-flagged proposal: {e}")
    });
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
        "I-18, NOTE 9: PC is minor-flagged from the gate, whatever the actor's \
         field said, so the consent is checked again before GRANTED"
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

/// R-ID-04, NOTE 14: a proposal admitted on the lead's attestation is not
/// minor-flagged, so it is granted without consent, whatever the actor's
/// field said.
#[test]
fn r_id_04_adult_admitted_proposal_is_granted_without_consent() {
    adult_granted_on(Backend::Production);
}

/// R-ID-04: the adult grant story on the references alone.
#[test]
fn r_id_04_adult_admitted_proposal_is_granted_without_consent_reference() {
    adult_granted_on(Backend::Reference);
}

/// I-18, NOTE 9, R-ID-04: a proposal admitted on its guardian consent stays
/// minor-flagged, so a consent withdrawn in NEGOTIATION blocks GRANTED,
/// whatever the actor's field said.
#[test]
fn i18_consent_admitted_proposal_needs_the_consent_again_before_grant() {
    consent_checked_again_on(Backend::Production);
}

/// I-18: the withdrawn consent story on the references alone.
#[test]
fn i18_consent_admitted_proposal_needs_the_consent_again_before_grant_reference() {
    consent_checked_again_on(Backend::Reference);
}
