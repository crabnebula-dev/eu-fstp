//! Row NEGOTIATION to GRANTED: the grant is computed when the last of the lead's acceptance, the programme manager's approval and the contract EFFECTIVE fact arrives (design 3.2, contracts.md States).
//!
//! Lead c reaches NEGOTIATION from genesis by production commands and R1
//! determines 4.00. Each of the three facts can come last, and the one
//! that completes the set takes the proposal to GRANTED in its own batch,
//! with `GrantDecided` for the determined amount and the agreed plan. The
//! acceptance is the lead's alone, the approval the programme manager's
//! alone, and the EFFECTIVE fact comes only from the System.
//!
//! When a guard of the row fails only for now, here because the vault has
//! not verified the lead yet, the completing fact is refused. The
//! programme manager cannot decline either, since a verification may
//! still come. Once the vault verifies the lead, the same fact is sent
//! again and grants. The contract seam of design 2.11,
//! `grant_preconditions` with `check_grant_preconditions`, gives M5 the
//! same answer before the contract is sent or countersigned.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::Answers;
use fstp_domain::command::Actor;
use fstp_domain::grant::{check_grant_preconditions, grant_preconditions};
use fstp_domain::record::Record;
use fstp_domain::refusal::{RefusalReason, RuleRef};
use fstp_domain::rules::{Row, StateTag};
use fstp_domain_testkit::r#gen::money::{
    LC, MoneySetup, MoneyStory, PC, accept_grant, approve_grant, contract_effective,
    decline_negotiation,
};
use fstp_domain_testkit::r#gen::review::{R1, plan_of};
use fstp_domain_testkit::r#gen::roster::{Backend, STAFF_PM, Step};

fn setup() -> MoneySetup {
    let mut s = MoneySetup::sybil([400, 400, 400]);
    s.drafts.retain(|d| d.proposal == PC);
    s
}

fn facts() -> [Step; 3] {
    [
        accept_grant(LC, PC),
        approve_grant(STAFF_PM, PC),
        contract_effective(PC),
    ]
}

fn last(b: Backend, which: usize) {
    let mut s = MoneyStory::new(&setup(), b).unwrap_or_else(|e| panic!("setup: {e}"));
    s.determine(PC, 1, &[])
        .unwrap_or_else(|e| panic!("R1 determines 4.00: {e}"));
    let all = facts();
    for (i, f) in all.iter().enumerate() {
        if i != which {
            s.run(f).unwrap_or_else(|e| panic!("fact {i}: {e}"));
            assert_eq!(
                s.state(PC),
                Some(StateTag::Negotiation),
                "two facts do not grant"
            );
        }
    }
    let recs = s
        .run(all.get(which).unwrap())
        .unwrap_or_else(|e| panic!("the completing fact {which}: {e}"));
    assert_eq!(s.state(PC), Some(StateTag::Granted));
    let grant = recs.iter().find_map(|r| match r {
        Record::GrantDecided(g) => Some(g.clone()),
        _ => None,
    });
    let g = grant.unwrap_or_else(|| panic!("I-13: the batch records GrantDecided: {recs:?}"));
    assert_eq!(g.granted().amount().minor(), 400);
    assert_eq!(g.agreed_plan(), plan_of(PC));
    assert!(recs.iter().any(|r| matches!(
        r,
        Record::Transitioned(t) if t.row == Row::NegotiationToGranted
    )));
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

fn actors(b: Backend) {
    let mut s = MoneyStory::new(&setup(), b).unwrap_or_else(|e| panic!("setup: {e}"));
    s.determine(PC, 1, &[])
        .unwrap_or_else(|e| panic!("R1 determines 4.00: {e}"));
    let mut by_pm = accept_grant(LC, PC);
    by_pm.actor = Actor::Account(STAFF_PM);
    s.refused(&by_pm)
        .unwrap_or_else(|e| panic!("AcceptGrant is the lead's: {e}"));
    let mut by_lead = approve_grant(STAFF_PM, PC);
    by_lead.actor = Actor::Account(LC);
    s.refused(&by_lead)
        .unwrap_or_else(|e| panic!("ApproveGrant is the programme manager's: {e}"));
    let mut by_r1 = contract_effective(PC);
    by_r1.actor = Actor::Account(R1);
    s.refused(&by_r1)
        .unwrap_or_else(|e| panic!("the contract fact comes from the System: {e}"));
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

fn retried(b: Backend, which: usize) {
    let mut setup = setup();
    setup.unverified = vec![LC];
    let mut s = MoneyStory::new(&setup, b).unwrap_or_else(|e| panic!("setup: {e}"));
    s.determine(PC, 1, &[])
        .unwrap_or_else(|e| panic!("R1 determines 4.00: {e}"));
    let all = facts();
    for (i, f) in all.iter().enumerate() {
        if i != which {
            s.run(f).unwrap_or_else(|e| panic!("fact {i}: {e}"));
        }
    }
    let completing = all.get(which).unwrap();
    s.refused(completing).unwrap_or_else(|e| {
        panic!("SoD-09: the completing fact {which} is refused while c is unverified: {e}")
    });
    assert_eq!(s.state(PC), Some(StateTag::Negotiation));
    s.world
        .vault(|t| t.verify(LC))
        .unwrap_or_else(|e| panic!("the vault verifies c: {e}"));
    s.refused(&decline_negotiation(Actor::Account(STAFF_PM), PC))
        .unwrap_or_else(|e| panic!("NOTE 9: no failure holds once c is verified: {e}"));
    s.run(completing)
        .unwrap_or_else(|e| panic!("the completing fact {which} is sent again: {e}"));
    assert_eq!(
        s.state(PC),
        Some(StateTag::Granted),
        "NOTE 9: the negotiation keeps an exit once the failure clears"
    );
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// Production's answer to the contract seam for `PC` now.
fn preconditions(s: &MoneyStory) -> Result<(), fstp_domain::refusal::Refusal> {
    let state = &s.world.life.rev.sod.state;
    let mut answers = Answers::new();
    for q in grant_preconditions(state, PC)? {
        let a = s.world.life.rev.answer(&q);
        answers.insert(q, a);
    }
    check_grant_preconditions(state, PC, &answers)
}

/// Row NEGOTIATION to GRANTED, SoD-09, NOTE 9: a completing fact refused
/// while the lead is unverified is sent again once the vault verifies the
/// lead, and grants.
#[test]
fn r_ng_grant_completing_fact_is_retried_after_verification() {
    for which in 0..3 {
        retried(Backend::Production, which);
    }
}

/// Row NEGOTIATION to GRANTED, R-NG-03, SoD-09, design 2.11 contract seam:
/// the preconditions refuse before an amount is reserved and while the lead
/// is unverified, and hold once it is verified, so the countersigned
/// contract grants.
#[test]
fn r_ng_grant_preconditions_seam_matches_the_completing_fact() {
    let mut setup = setup();
    setup.unverified = vec![LC];
    let mut s =
        MoneyStory::new(&setup, Backend::Production).unwrap_or_else(|e| panic!("setup: {e}"));
    let early = preconditions(&s).unwrap_err();
    assert_eq!(
        (early.rule, early.reason),
        (RuleRef::Rng03, RefusalReason::GuardFailed),
        "R-NG-03: no amount is reserved yet"
    );
    s.determine(PC, 1, &[])
        .unwrap_or_else(|e| panic!("R1 determines 4.00: {e}"));
    let unverified = preconditions(&s).unwrap_err();
    assert_eq!(
        unverified.rule,
        RuleRef::Sod09,
        "SoD-09: the lead is not verified"
    );
    s.run(&accept_grant(LC, PC))
        .unwrap_or_else(|e| panic!("c accepts: {e}"));
    s.run(&approve_grant(STAFF_PM, PC))
        .unwrap_or_else(|e| panic!("the programme manager approves: {e}"));
    s.refused(&contract_effective(PC))
        .unwrap_or_else(|e| panic!("the seam and the completing fact agree: {e}"));
    s.world
        .vault(|t| t.verify(LC))
        .unwrap_or_else(|e| panic!("the vault verifies c: {e}"));
    preconditions(&s).unwrap_or_else(|r| panic!("every precondition holds now: {r}"));
    s.run(&contract_effective(PC))
        .unwrap_or_else(|e| panic!("the countersigned contract grants: {e}"));
    assert_eq!(s.state(PC), Some(StateTag::Granted));
    let after = preconditions(&s).unwrap_err();
    assert_eq!(
        after.reason,
        RefusalReason::WrongState,
        "the seam applies in NEGOTIATION only"
    );
}

/// Row NEGOTIATION to GRANTED, I-13: the acceptance completes the set.
#[test]
fn r_ng_grant_completes_on_the_acceptance() {
    last(Backend::Production, 0);
}

/// Row NEGOTIATION to GRANTED, I-13: the approval completes the set.
#[test]
fn r_ng_grant_completes_on_the_approval() {
    last(Backend::Production, 1);
}

/// Row NEGOTIATION to GRANTED, I-13: the contract EFFECTIVE fact completes the set.
#[test]
fn r_ng_grant_completes_on_the_contract_fact() {
    last(Backend::Production, 2);
}

/// Row NEGOTIATION to GRANTED, I-84: each fact has its own actor.
#[test]
fn r_ng_grant_facts_have_their_actors() {
    actors(Backend::Production);
}

/// Row NEGOTIATION to GRANTED, I-13, SoD-09, NOTE 9: the stories pass on the
/// references alone.
#[test]
fn r_ng_grant_stories_pass_on_the_reference() {
    for which in 0..3 {
        last(Backend::Reference, which);
        retried(Backend::Reference, which);
    }
    actors(Backend::Reference);
}
