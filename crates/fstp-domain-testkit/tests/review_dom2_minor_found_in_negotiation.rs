//! Review reproducers for lane dom2: a lead found under 18 by the second derivation (state-machine NOTE 14, decided 2026-10-29).
//!
//! ADR-008 "Second derivation": a verification in NEGOTIATION that shows
//! the lead under 18 at the deadline "then needs a verified guardian
//! consent before GRANTED". NOTE 9: NEGOTIATION to DECLINED ends a
//! negotiation that cannot reach GRANTED, and one of its grounds is that
//! guardian consent (I-18) is missing. These stories lose the lead's
//! attestation in NEGOTIATION, after a gate that found the lead adult.
//! They run production only.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::Actor;
use fstp_domain::id::{AccountId, BindingId};
use fstp_domain::record::Record;
use fstp_domain::refusal::RuleRef;
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::minor::{ask_production, money_setup};
use fstp_domain_testkit::r#gen::money::{
    LC, MoneyStory, PC, accept_grant, approve_grant, contract_effective, decline_negotiation,
};
use fstp_domain_testkit::r#gen::roster::{Backend, LEAD_ADULT_FROM, STAFF_PM, add_member};

/// A guardian account outside the setup, verified in the vault.
const GUARDIAN: AccountId = AccountId::from_raw(9_951);

/// PC enters NEGOTIATION on LC's attestation, its amount is determined,
/// then the vault withdraws the attestation (for example after a manual
/// check found LC under 18). The lead accepts and the programme manager
/// approves. No guardian consent exists.
fn minor_found_in_negotiation() -> MoneyStory {
    let mut s = MoneyStory::with(&money_setup(false), Backend::Production, |t| {
        t.withdraw_attestation(LC);
        t.attest_adult(LC, LEAD_ADULT_FROM);
        t.verify(GUARDIAN);
    })
    .unwrap_or_else(|e| panic!("NOTE 14: the attested PC enters NEGOTIATION: {e}"));
    assert_eq!(s.state(PC), Some(StateTag::Negotiation), "setup");
    s.determine(PC, 1, &[])
        .unwrap_or_else(|e| panic!("R1 determines 4.00: {e}"));
    s.run(&accept_grant(LC, PC))
        .unwrap_or_else(|e| panic!("the lead accepts: {e}"));
    s.run(&approve_grant(STAFF_PM, PC))
        .unwrap_or_else(|e| panic!("the programme manager approves: {e}"));
    s.world
        .vault(|t| t.withdraw_attestation(LC))
        .unwrap_or_else(|e| panic!("the vault reaction: {e}"));
    s
}

/// NOTE 9, NOTE 14, I-18: once the guard into GRANTED refuses PC under
/// I-18, the programme manager's `DeclineNegotiation` must find the
/// missing guardian consent. Production still reads the flag of the
/// negotiation gate, finds no failure and refuses the decline.
#[test]
fn review_decline_finds_consent_missing_after_second_derivation() {
    let s = minor_found_in_negotiation();
    let state = &s.world.life.rev.sod.state;
    let fact = contract_effective(PC);
    let (ctx, answers) = ask_production(&s.world, &fact).unwrap_or_else(|r| panic!("{r}"));
    let r = fstp_domain::decide(state, &fact.cmd, &ctx, &answers)
        .expect_err("control: I-18 refuses the completing fact");
    assert_eq!(r.rule, RuleRef::I18, "control: the I-18 refusal");

    let step = decline_negotiation(Actor::Account(STAFF_PM), PC);
    let (ctx, answers) = ask_production(&s.world, &step).unwrap_or_else(|r| panic!("{r}"));
    let out = fstp_domain::decide(state, &step.cmd, &ctx, &answers);
    let declined = out.as_ref().is_ok_and(|rs| {
        rs.iter()
            .any(|r| matches!(r, Record::NegotiationDeclined { .. }))
    });
    assert!(
        declined,
        "NOTE 9, NOTE 14: PC cannot reach GRANTED because guardian consent \
         (I-18) is missing, so NEGOTIATION to DECLINED must apply, but \
         production gives {out:?}"
    );
}

/// ADR-008 "Second derivation", R-NG-01: a lead found under 18 in
/// NEGOTIATION needs a verified guardian consent before GRANTED, so the
/// lead must be able to bind the guardian whose consent that needs.
/// Production refuses `AddGuardian`, since the flag it reads is still the
/// negotiation gate's.
#[test]
fn review_add_guardian_open_when_minor_found_in_negotiation() {
    let s = minor_found_in_negotiation();
    let state = &s.world.life.rev.sod.state;
    let step = add_member(LC, PC, GUARDIAN, BindingId::from_raw(9_952), true);
    let (ctx, answers) = ask_production(&s.world, &step).unwrap_or_else(|r| {
        panic!(
            "ADR-008 Second derivation: the lead of a proposal minor-flagged \
             at the guard into GRANTED must be able to bind a guardian, but \
             AddGuardian is refused: {r}"
        )
    });
    let out = fstp_domain::decide(state, &step.cmd, &ctx, &answers);
    assert!(
        out.is_ok(),
        "ADR-008 Second derivation: AddGuardian must be accepted, got {out:?}"
    );
}
