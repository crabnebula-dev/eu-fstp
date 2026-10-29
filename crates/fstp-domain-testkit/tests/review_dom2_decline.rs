//! Review of lane dom2: `DeclineNegotiation` still reads the minor flag of
//! the negotiation gate, while the guard into GRANTED derives it again
//! (state-machine NOTE 14, decided 2026-10-29; NOTE 9; I-18).
//!
//! NOTE 9: NEGOTIATION to DECLINED ends a negotiation that cannot reach
//! GRANTED, and one of its grounds is a missing guardian consent (I-18).
//! After the second derivation, the decline and the GRANTED guard disagree
//! about whether consent is missing.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::Actor;
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::minor::{ask_production, money_setup};
use fstp_domain_testkit::r#gen::money::{
    LC, MoneyStory, PC, accept_grant, approve_grant, contract_effective, decline_negotiation,
};
use fstp_domain_testkit::r#gen::roster::{Backend, LEAD_ADULT_FROM, STAFF_PM};

/// PC in NEGOTIATION from genesis on production, admitted on `adult` (the
/// lead's attestation) or else on a guardian consent, with its amount
/// determined, accepted and approved.
fn negotiating(adult: bool) -> MoneyStory {
    let mut s = MoneyStory::with(&money_setup(true), Backend::Production, |t| {
        t.withdraw_attestation(LC);
        if adult {
            t.attest_adult(LC, LEAD_ADULT_FROM);
        } else {
            t.consent(PC);
        }
    })
    .unwrap_or_else(|e| panic!("PC enters NEGOTIATION: {e}"));
    assert_eq!(s.state(PC), Some(StateTag::Negotiation));
    s.determine(PC, 1, &[])
        .unwrap_or_else(|e| panic!("R1 determines: {e}"));
    s.run(&accept_grant(LC, PC))
        .unwrap_or_else(|e| panic!("accept: {e}"));
    s.run(&approve_grant(STAFF_PM, PC))
        .unwrap_or_else(|e| panic!("approve: {e}"));
    s
}

/// Whether production decides `step` without a refusal, with the answers
/// the synthetic vault gives.
fn production_accepts(s: &MoneyStory, step: &fstp_domain_testkit::r#gen::roster::Step) -> bool {
    let state = &s.world.life.rev.sod.state;
    let Ok((ctx, answers)) = ask_production(&s.world, step) else {
        return false;
    };
    fstp_domain::decide(state, &step.cmd, &ctx, &answers).is_ok()
}

/// NOTE 9, NOTE 14 (decided 2026-10-29): PC was admitted on its consent.
/// In NEGOTIATION the consent is withdrawn and the lead is attested 18 or
/// older at the deadline. The GRANTED guard derives the flag again and
/// admits PC, so the negotiation can reach GRANTED. Production still
/// declines it for a missing guardian consent, read from the gate's flag.
#[test]
fn review_dom2_decline_refused_when_second_derivation_admits() {
    let mut s = negotiating(false);
    s.world
        .vault(|t| {
            t.withdraw_consent(PC);
            t.attest_adult(LC, LEAD_ADULT_FROM);
        })
        .unwrap_or_else(|e| panic!("vault reaction: {e}"));
    assert!(
        production_accepts(&s, &contract_effective(PC)),
        "precondition: the completing fact would take PC into GRANTED"
    );
    let decline = decline_negotiation(Actor::Account(STAFF_PM), PC);
    assert!(
        !production_accepts(&s, &decline),
        "NOTE 9, NOTE 14: PC can reach GRANTED on the lead's attestation, \
         yet DeclineNegotiation declines it for a missing guardian consent \
         taken from the negotiation gate's flag"
    );
}

/// NOTE 9, NOTE 14, I-18: PC was admitted on the lead's attestation. In
/// NEGOTIATION the attestation is withdrawn and there is no consent. The
/// GRANTED guard refuses under I-18, so consent is missing, but the
/// decline finds no ground and is refused. `AddGuardian` is refused too,
/// since the gate's flag is clear, so PC can neither reach GRANTED nor be
/// declined.
#[test]
fn review_dom2_decline_records_consent_missing_after_second_derivation() {
    let mut s = negotiating(true);
    s.world
        .vault(|t| t.withdraw_attestation(LC))
        .unwrap_or_else(|e| panic!("vault reaction: {e}"));
    assert!(
        !production_accepts(&s, &contract_effective(PC)),
        "precondition: I-18 refuses the completing fact"
    );
    let decline = decline_negotiation(Actor::Account(STAFF_PM), PC);
    assert!(
        production_accepts(&s, &decline),
        "NOTE 9, I-18: the GRANTED guard finds PC minor-flagged with no \
         consent, so DeclineNegotiation must be able to record \
         GuardianConsentMissing, and production refuses it"
    );
}
