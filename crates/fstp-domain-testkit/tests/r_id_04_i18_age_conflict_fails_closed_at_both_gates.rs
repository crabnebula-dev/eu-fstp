//! R-ID-04, I-18: an age conflict fails closed at both minor flag gates until a manual identity check (state-machine NOTE 14, decided 2026-10-29).
//!
//! `SPEC/02-domain/state-machine.md` NOTE 14: "When the vault holds a
//! verified adult attestation and a verification showing the lead under 18
//! at that deadline, a manual identity check resolves the conflict before
//! either gate admits the proposal." ADR-008 "Minor flag details",
//! Override: neither wins, and until the check resolves it
//! `IsVerifiedAdultAtDeadline` does not answer, so the gate fails closed
//! (`03-architecture/overview.md` NOTE 2) and the proposal stays where it
//! is. The domain sees the conflict only as the vault not answering.
//!
//! The synthetic vault twin models the conflict: an effective attestation
//! that shows the lead 18 or older at the deadline, and an effective
//! verification that shows the lead under 18 there, give no answer to the
//! over-18 query. A manual check that finds the lead adult sets the
//! verification aside. One that finds the lead a minor withdraws the
//! attestation. The stories run production commands from genesis and
//! compare every step with the references in both directions.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::assignment::AssignmentKind;
use fstp_domain::decision::Vote;
use fstp_domain::id::{AccountId, AssignmentId};
use fstp_domain::oracle::{Query, QueryKind};
use fstp_domain::refusal::{RefusalReason, RuleRef};
use fstp_domain::rules::StateTag;
use fstp_domain::scoring::Stage;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::minor::{ask_production, money_setup};
use fstp_domain_testkit::r#gen::money::{
    LC, MoneyStory, PC, accept_grant, approve_grant, contract_effective,
};
use fstp_domain_testkit::r#gen::review::{IRC, L1, PR1, R1, R2, R3};
use fstp_domain_testkit::r#gen::roster::{
    Backend, CALL_DEADLINE, LEAD_ADULT_AFTER_DEADLINE, LEAD_ADULT_FROM, STAFF_PM, call,
};
use fstp_domain_testkit::mc::life_model::{
    IRC2, Story, assign_declared, ballots, cut_off, cut_off_decision, irc_review, life_judges,
    story_setup,
};
use fstp_domain_testkit::vault::{AgeCheck, GroundTruth, SyntheticVault};
use fstp_engine::IdentityOracle;

// ---------------------------------------------------------------------------
// The twin
// ---------------------------------------------------------------------------

/// A synthetic account for the twin tests.
const A: AccountId = AccountId::from_raw(9_931);

fn at(micros: i64) -> Timestamp {
    Timestamp::from_micros(micros)
}

fn adult_query(deadline: Timestamp) -> Query {
    Query::IsVerifiedAdultAtDeadline {
        account: A,
        deadline,
    }
}

/// A attested 18 or older from 10, and verified under 18 until 20.
fn conflicted() -> GroundTruth {
    let mut t = GroundTruth::new();
    t.verify(A);
    t.attest_adult(A, at(10));
    t.verify_under_18(A, at(20));
    t
}

/// NOTE 14, ADR-008 Override (decided 2026-10-29): while an attestation and
/// an under-18 verification conflict at a deadline, the twin answers the
/// over-18 query neither yes nor no. The vault fails the query, and every
/// other query is still answered.
#[test]
fn r_id_04_twin_gives_no_adult_answer_during_an_age_conflict() {
    let t = conflicted();
    assert!(t.age_conflict_at(A, at(15)), "conflict at 15");
    assert_eq!(t.adult_answer(A, at(15)), None, "NOTE 14: no answer at 15");
    assert!(!t.answers(&adult_query(at(15))), "NOTE 14: no answer at 15");
    assert!(t.try_answer(&adult_query(at(15))).is_none(), "no answer");
    let vault = SyntheticVault::new(t.clone());
    assert!(
        vault.ask(&adult_query(at(15))).is_err(),
        "overview NOTE 2: the vault fails the over-18 query during the conflict"
    );
    assert!(
        vault
            .ask(&Query::IsVerified { account: A })
            .is_ok_and(|a| a.holds),
        "the conflict leaves every other query answered"
    );
    assert_eq!(
        t.adult_answer(A, at(20)),
        Some(true),
        "from 20 the verification shows A 18 or older too, so no conflict"
    );
    assert_eq!(
        t.adult_answer(A, at(5)),
        Some(false),
        "before 10 the attestation does not show A 18 or older, so no conflict"
    );
}

/// NOTE 14, G9: a manual identity check resolves the conflict. One that
/// finds the account adult lets the attestation count. One that finds it a
/// minor withdraws the attestation. Each is a vault change of the account.
#[test]
fn r_id_04_twin_manual_check_resolves_the_age_conflict() {
    let mut adult = conflicted();
    let before = adult.epoch();
    adult.resolve_age_conflict(A, AgeCheck::Adult);
    assert_eq!(adult.adult_answer(A, at(15)), Some(true), "adult check");
    assert!(
        adult.changed_since(before).contains(&A),
        "the check lists A in ChangedSince"
    );
    let mut minor = conflicted();
    minor.resolve_age_conflict(A, AgeCheck::Minor);
    assert_eq!(minor.adult_answer(A, at(15)), Some(false), "minor check");
    assert!(
        SyntheticVault::new(minor)
            .ask(&adult_query(at(15)))
            .is_ok_and(|a| !a.holds),
        "after the check the vault answers no"
    );
}

// ---------------------------------------------------------------------------
// The negotiation gate
// ---------------------------------------------------------------------------

/// L1 attested 18 or older before the deadline, and verified under 18 until
/// after it, so the two conflict at the deadline of call 1.
fn conflict(t: &mut GroundTruth) {
    t.withdraw_attestation(L1);
    t.attest_adult(L1, LEAD_ADULT_FROM);
    t.verify_under_18(L1, LEAD_ADULT_AFTER_DEADLINE);
}

/// PR1 in IRC_REVIEW with IRC and IRC2 assigned, from genesis, under the
/// conflict. IRC has validated, so IRC2's validation would complete the
/// review.
fn before_the_last_validation(b: Backend) -> Story {
    let setup = story_setup(vec![(L1, PR1, false)], life_judges());
    let mut s = Story::new(&setup, b, conflict).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        s.world.rev.sod.truth.age_conflict_at(L1, CALL_DEADLINE),
        "the setup holds the conflict"
    );
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
    s
}

fn irc_assignment(s: &Story, member: AccountId) -> AssignmentId {
    s.world
        .assignment(member, PR1, Stage::Two, AssignmentKind::Irc)
        .unwrap_or_else(|| panic!("no IRC assignment of {member:?}"))
}

/// IRC2's validation, which completes the review. `true` when accepted.
fn last_validation(s: &mut Story, context: &str) -> bool {
    let a = irc_assignment(s, IRC2);
    s.attempt(&irc_review(IRC2, a, true))
        .unwrap_or_else(|e| panic!("{context}: {e}"))
        .is_some()
}

fn gate_conflict_then_adult_check_on(b: Backend) {
    let mut s = before_the_last_validation(b);
    assert!(
        !last_validation(&mut s, "NOTE 14: the conflict waits for a manual check"),
        "NOTE 14, overview NOTE 2: the vault gives no answer about L1's \
         attestation, so the last validation must be refused"
    );
    assert_eq!(s.state(PR1), Some(StateTag::IrcReview), "PR1 stays");
    s.vault(|t| t.resolve_age_conflict(L1, AgeCheck::Adult))
        .unwrap_or_else(|e| panic!("the vault reaction: {e}"));
    assert!(
        last_validation(&mut s, "G9: the manual check found L1 adult"),
        "the validation is sent again once the check resolved the conflict"
    );
    assert_eq!(
        s.state(PR1),
        Some(StateTag::Negotiation),
        "R-ID-04, NOTE 14: the check found L1 adult, so PR1 enters \
         NEGOTIATION without a consent"
    );
}

/// R-ID-04, NOTE 14 (decided 2026-10-29), overview NOTE 2: an age conflict
/// at the deadline refuses the validation that would complete the review.
/// A manual check that finds the lead adult then admits the proposal.
#[test]
fn r_id_04_age_conflict_fails_closed_at_the_negotiation_gate() {
    gate_conflict_then_adult_check_on(Backend::Production);
}

/// R-ID-04, NOTE 14: the gate conflict story on the references alone.
#[test]
fn r_id_04_age_conflict_fails_closed_at_the_negotiation_gate_reference() {
    gate_conflict_then_adult_check_on(Backend::Reference);
}

fn gate_conflict_with_consent_on(b: Backend) {
    let mut s = before_the_last_validation(b);
    s.vault(|t| t.consent(PR1))
        .unwrap_or_else(|e| panic!("the vault reaction: {e}"));
    assert!(
        !last_validation(&mut s, "NOTE 14: a consent does not resolve the conflict"),
        "NOTE 14, overview NOTE 2: a verified guardian consent does not \
         excuse the missing attestation answer, so the validation must be \
         refused"
    );
    assert_eq!(s.state(PR1), Some(StateTag::IrcReview), "PR1 stays");
    s.vault(|t| t.resolve_age_conflict(L1, AgeCheck::Minor))
        .unwrap_or_else(|e| panic!("the vault reaction: {e}"));
    assert!(
        last_validation(&mut s, "G9: the manual check found L1 a minor"),
        "the validation is sent again once the check resolved the conflict"
    );
    assert_eq!(
        s.state(PR1),
        Some(StateTag::Negotiation),
        "I-18, NOTE 14: the check found L1 a minor, and PR1 has a verified \
         guardian consent, so it enters NEGOTIATION"
    );
}

/// I-18, R-ID-04, NOTE 14 (decided 2026-10-29): a guardian consent does not
/// get a proposal past an unresolved age conflict at the negotiation gate.
/// Once a manual check finds the lead a minor, the consent admits it.
#[test]
fn i18_r_id_04_consent_does_not_pass_an_age_conflict_at_the_negotiation_gate() {
    gate_conflict_with_consent_on(Backend::Production);
}

/// I-18, R-ID-04: the gate conflict and consent story on the references alone.
#[test]
fn i18_r_id_04_consent_does_not_pass_an_age_conflict_at_the_negotiation_gate_reference() {
    gate_conflict_with_consent_on(Backend::Reference);
}

/// Overview NOTE 2: production refuses the last validation under the
/// conflict because an answer is missing, not on any other guard.
#[test]
fn r_id_04_negotiation_gate_refuses_an_age_conflict_as_a_missing_answer() {
    let s = before_the_last_validation(Backend::Production);
    let a = irc_assignment(&s, IRC2);
    let refused = s
        .world
        .rev
        .production_outcome(&irc_review(IRC2, a, true))
        .unwrap_or_else(|| panic!("production keeps a projection"));
    let r = refused.expect_err("overview NOTE 2: the last validation must be refused");
    assert_eq!(
        (r.rule, r.reason),
        (RuleRef::FactsIncomplete, RefusalReason::AnswerMissing),
        "NOTE 14: the conflict reaches the domain only as a missing answer"
    );
}

// ---------------------------------------------------------------------------
// The guard into GRANTED
// ---------------------------------------------------------------------------

/// PC in NEGOTIATION on LC's attestation, its amount determined, then the
/// vault verifies LC under 18 until after the deadline, so the two
/// conflict. The lead accepts and the programme manager approves.
fn granted_conflict(b: Backend) -> MoneyStory {
    let mut s = MoneyStory::with(&money_setup(false), b, |t| {
        t.withdraw_attestation(LC);
        t.attest_adult(LC, LEAD_ADULT_FROM);
    })
    .unwrap_or_else(|e| panic!("NOTE 14: the attested PC enters NEGOTIATION: {e}"));
    s.determine(PC, 1, &[])
        .unwrap_or_else(|e| panic!("R1 determines 4.00: {e}"));
    s.world
        .vault(|t| t.verify_under_18(LC, LEAD_ADULT_AFTER_DEADLINE))
        .unwrap_or_else(|e| panic!("the vault reaction: {e}"));
    assert!(
        s.world.truth().age_conflict_at(LC, CALL_DEADLINE),
        "the vault holds the conflict"
    );
    s.run(&accept_grant(LC, PC))
        .unwrap_or_else(|e| panic!("the lead accepts: {e}"));
    s.run(&approve_grant(STAFF_PM, PC))
        .unwrap_or_else(|e| panic!("the programme manager approves: {e}"));
    s
}

/// Sends the completing contract fact. `true` when it is accepted.
fn contract(s: &mut MoneyStory, context: &str) -> bool {
    s.attempt(&contract_effective(PC))
        .unwrap_or_else(|e| panic!("{context}: {e}"))
        .is_some()
}

fn grant_conflict_then_adult_check_on(b: Backend) {
    let mut s = granted_conflict(b);
    assert!(
        !contract(&mut s, "NOTE 14: the conflict waits for a manual check"),
        "NOTE 14 (decided 2026-10-29), overview NOTE 2: the guard into \
         GRANTED derives the flag again, and the vault gives no answer, so \
         the completing fact must be refused"
    );
    s.world
        .vault(|t| t.consent(PC))
        .unwrap_or_else(|e| panic!("the vault reaction: {e}"));
    assert!(
        !contract(&mut s, "NOTE 14: a consent does not resolve the conflict"),
        "overview NOTE 2: a consent does not excuse the missing attestation \
         answer at the guard into GRANTED"
    );
    assert_eq!(s.state(PC), Some(StateTag::Negotiation), "PC stays");
    s.world
        .vault(|t| t.resolve_age_conflict(LC, AgeCheck::Adult))
        .unwrap_or_else(|e| panic!("the vault reaction: {e}"));
    assert!(
        contract(&mut s, "G9: the manual check found LC adult"),
        "the fact is sent again once the check resolved the conflict"
    );
    assert_eq!(s.state(PC), Some(StateTag::Granted), "granted");
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// I-18, R-ID-04, NOTE 14 (decided 2026-10-29): an under-18 verification in
/// NEGOTIATION that conflicts with the attestation fails the guard into
/// GRANTED closed, a consent included, until a manual check resolves it.
#[test]
fn i18_r_id_04_age_conflict_fails_closed_at_the_guard_into_granted() {
    grant_conflict_then_adult_check_on(Backend::Production);
}

/// I-18, R-ID-04: the GRANTED conflict story on the references alone.
#[test]
fn i18_r_id_04_age_conflict_fails_closed_at_the_guard_into_granted_reference() {
    grant_conflict_then_adult_check_on(Backend::Reference);
}

fn grant_minor_check_on(b: Backend) {
    let mut s = granted_conflict(b);
    s.world
        .vault(|t| t.resolve_age_conflict(LC, AgeCheck::Minor))
        .unwrap_or_else(|e| panic!("the vault reaction: {e}"));
    assert!(
        !contract(&mut s, "ADR-008 Second derivation: LC is a minor now"),
        "I-18, NOTE 14: the check found LC a minor at the deadline, so PC \
         is minor-flagged at the guard into GRANTED and needs a consent"
    );
    s.world
        .vault(|t| t.consent(PC))
        .unwrap_or_else(|e| panic!("the vault reaction: {e}"));
    assert!(
        contract(&mut s, "I-18: the consent is recorded"),
        "the fact is sent again once the consent is effective"
    );
    assert_eq!(s.state(PC), Some(StateTag::Granted), "consent admits");
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// I-18, R-ID-04, ADR-008 Second derivation (decided 2026-10-29): a
/// verification in NEGOTIATION that shows the lead under 18 at the
/// deadline, confirmed by the manual check, needs a verified guardian
/// consent before GRANTED.
#[test]
fn i18_r_id_04_minor_found_in_negotiation_needs_consent_before_grant() {
    grant_minor_check_on(Backend::Production);
}

/// I-18, R-ID-04: the minor-check story on the references alone.
#[test]
fn i18_r_id_04_minor_found_in_negotiation_needs_consent_before_grant_reference() {
    grant_minor_check_on(Backend::Reference);
}

/// Overview NOTE 2, NOTE 14: under the conflict, production leaves the
/// over-18 question of the completing fact unanswered and refuses it as a
/// missing answer.
#[test]
fn r_id_04_guard_into_granted_refuses_an_age_conflict_as_a_missing_answer() {
    let s = granted_conflict(Backend::Production);
    let step = contract_effective(PC);
    let state = &s.world.life.rev.sod.state;
    let qs = fstp_domain::queries(state, &step.cmd, &s.world.life.rev.sod.ctx(&step))
        .unwrap_or_else(|r| panic!("refused before asking: {r}"));
    assert!(
        qs.iter()
            .any(|q| q.kind() == QueryKind::IsVerifiedAdultAtDeadline),
        "NOTE 14 (decided 2026-10-29): the guard into GRANTED must ask the \
         attestation again, and it asks {qs:?}"
    );
    let (ctx, answers) =
        ask_production(&s.world, &step).unwrap_or_else(|r| panic!("refused before asking: {r}"));
    let r = fstp_domain::decide(state, &step.cmd, &ctx, &answers)
        .expect_err("overview NOTE 2: the completing fact must be refused");
    assert_eq!(
        (r.rule, r.reason),
        (RuleRef::FactsIncomplete, RefusalReason::AnswerMissing),
        "NOTE 14: the conflict reaches the domain only as a missing answer"
    );
}
