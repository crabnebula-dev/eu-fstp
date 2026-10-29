//! R-ID-04, I-18: the guard into GRANTED derives the minor flag again (state-machine NOTE 14, decided 2026-10-29).
//!
//! `SPEC/02-domain/state-machine.md` NOTE 14: "the guard into GRANTED
//! derives the flag again in the same way, so a proposal that is
//! minor-flagged there needs a verified guardian consent before GRANTED".
//! ADR-008 "Minor flag details", Second derivation: the guard asks
//! `IsVerifiedAdultAtDeadline` again. The flag kept from the negotiation
//! gate no longer decides alone. The guard asks one-bit vault queries and
//! fails closed when the vault cannot answer (`03-architecture/overview.md`
//! NOTE 2). The deadline is that of the call in which the proposal passed
//! IRC review, the same call as at the negotiation gate.
//!
//! The stories run production commands from genesis. PC of lead LC enters
//! NEGOTIATION on an effective verified over-18 attestation and no
//! guardian consent. R1 determines its amount. Every step is compared with
//! the references in both directions, so a production guard that keeps
//! the gate's flag fails with an over-permission before any state check.
//! The direct tests run production `queries` and `decide` with the
//! answers the synthetic vault gives.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::Answers;
use fstp_domain::assignment::AssignmentKind;
use fstp_domain::grant::grant_preconditions;
use fstp_domain::oracle::{Query, QueryKind};
use fstp_domain::record::Record;
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::minor::{
    LATER_DEADLINE, ask_production, money_setup, reentered_money_world,
};
use fstp_domain_testkit::r#gen::money::{
    LC, MoneyStory, PC, accept_grant, approve_grant, contract_effective,
};
use fstp_domain_testkit::r#gen::review::{R1, R2};
use fstp_domain_testkit::r#gen::roster::{
    Backend, CALL_DEADLINE, LEAD_ADULT_AFTER_DEADLINE, LEAD_ADULT_FROM, STAFF_PM, Step, call,
};
use fstp_domain_testkit::mc::life_model::assign_declared;
use fstp_domain_testkit::vault::GroundTruth;

/// The vault facts at the negotiation gate.
#[derive(Clone, Copy, Debug)]
enum AtGate {
    /// An effective attestation shows LC 18 or older before the deadline,
    /// and PC has no guardian consent.
    Adult,
    /// LC has no attestation, and PC has a verified guardian consent.
    Consent,
}

impl AtGate {
    fn set(self, t: &mut GroundTruth) {
        t.withdraw_attestation(LC);
        match self {
            AtGate::Adult => t.attest_adult(LC, LEAD_ADULT_FROM),
            AtGate::Consent => t.consent(PC),
        }
    }
}

/// PC in NEGOTIATION from genesis under `gate`, with its amount determined.
/// The actor's `CreateDraft` field is set, which no guard may read.
fn determined(b: Backend, gate: AtGate) -> MoneyStory {
    let mut s = MoneyStory::with(&money_setup(true), b, |t| gate.set(t))
        .unwrap_or_else(|e| panic!("NOTE 14: {gate:?} admits PC to NEGOTIATION: {e}"));
    assert_eq!(s.state(PC), Some(StateTag::Negotiation), "{gate:?}");
    s.determine(PC, 1, &[])
        .unwrap_or_else(|e| panic!("R1 determines 4.00: {e}"));
    s
}

/// The acceptance and the approval, both of which complete no grant.
fn accept_and_approve(s: &mut MoneyStory) {
    s.run(&accept_grant(LC, PC))
        .unwrap_or_else(|e| panic!("the lead accepts: {e}"));
    s.run(&approve_grant(STAFF_PM, PC))
        .unwrap_or_else(|e| panic!("the programme manager approves: {e}"));
}

/// Sends the completing contract fact. `true` when it is accepted.
fn contract(s: &mut MoneyStory, context: &str) -> bool {
    s.attempt(&contract_effective(PC))
        .unwrap_or_else(|e| panic!("{context}: {e}"))
        .is_some()
}

fn attestation_withdrawn_on(b: Backend) {
    let mut s = determined(b, AtGate::Adult);
    s.world
        .vault(|t| t.withdraw_attestation(LC))
        .unwrap_or_else(|e| panic!("the vault reaction: {e}"));
    accept_and_approve(&mut s);
    let granted = contract(
        &mut s,
        "NOTE 14 (decided 2026-10-29): the guard into GRANTED derives the \
         flag again. LC has no attestation now and PC has no consent, so PC \
         is minor-flagged there and the completing fact must be refused",
    );
    assert!(!granted, "I-18: PC was granted without a consent");
    assert_eq!(s.state(PC), Some(StateTag::Negotiation), "PC stays");
    s.world
        .vault(|t| t.consent(PC))
        .unwrap_or_else(|e| panic!("the vault reaction: {e}"));
    let granted = contract(
        &mut s,
        "I-18: the consent is recorded, so the fact is sent again",
    );
    assert!(granted, "I-18, NOTE 14: with the consent, PC is granted");
    assert_eq!(s.state(PC), Some(StateTag::Granted), "consent admits");
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// I-18, R-ID-04, NOTE 14 (decided 2026-10-29): an attestation withdrawn in
/// NEGOTIATION leaves the proposal minor-flagged at the guard into GRANTED,
/// so it needs a verified guardian consent before GRANTED.
#[test]
fn i18_r_id_04_attestation_lost_in_negotiation_needs_consent_before_grant() {
    attestation_withdrawn_on(Backend::Production);
}

/// I-18, R-ID-04: the lost attestation story on the references alone.
#[test]
fn i18_r_id_04_attestation_lost_in_negotiation_needs_consent_before_grant_reference() {
    attestation_withdrawn_on(Backend::Reference);
}

fn attested_in_negotiation_on(b: Backend) {
    let mut s = determined(b, AtGate::Consent);
    s.world
        .vault(|t| {
            t.withdraw_consent(PC);
            t.attest_adult(LC, LEAD_ADULT_FROM);
        })
        .unwrap_or_else(|e| panic!("the vault reaction: {e}"));
    accept_and_approve(&mut s);
    let granted = contract(
        &mut s,
        "NOTE 14 (decided 2026-10-29): the guard derives the flag again. \
         LC now has an effective over-18 attestation at the deadline, so \
         PC is not minor-flagged there and needs no consent",
    );
    assert!(granted, "R-ID-04: PC is granted on the attestation");
    assert_eq!(s.state(PC), Some(StateTag::Granted), "attestation admits");
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// R-ID-04, NOTE 14 (decided 2026-10-29): the flag from the negotiation gate
/// does not decide alone. A proposal admitted on its consent whose lead is
/// attested in NEGOTIATION is granted without the consent.
#[test]
fn r_id_04_attestation_recorded_in_negotiation_clears_the_flag_at_grant() {
    attested_in_negotiation_on(Backend::Production);
}

/// R-ID-04: the attested-in-negotiation story on the references alone.
#[test]
fn r_id_04_attestation_recorded_in_negotiation_clears_the_flag_at_grant_reference() {
    attested_in_negotiation_on(Backend::Reference);
}

/// The production questions and answers of the completing contract fact,
/// after the acceptance and the approval.
fn completing(gate: AtGate) -> (MoneyStory, Step) {
    let mut s = determined(Backend::Production, gate);
    accept_and_approve(&mut s);
    (s, contract_effective(PC))
}

/// The over-18 query of LC at the deadline of call 1.
fn adult_query() -> Query {
    Query::IsVerifiedAdultAtDeadline {
        account: LC,
        deadline: CALL_DEADLINE,
    }
}

/// R-ID-04, NOTE 14, overview NOTE 7 (decided 2026-10-29): the completing
/// grant fact asks the vault about the lead's attestation at the deadline
/// of the call of IRC review, and about the guardian consent, whatever the
/// negotiation gate found.
#[test]
fn r_id_04_granted_guard_asks_the_attestation_and_the_consent_again() {
    for gate in [AtGate::Adult, AtGate::Consent] {
        let (s, step) = completing(gate);
        let (_, answers) = ask_production(&s.world, &step)
            .unwrap_or_else(|r| panic!("{gate:?}: refused before asking: {r}"));
        let asked: Vec<&Query> = answers.iter().map(|(q, _)| q).collect();
        assert!(
            asked.contains(&&adult_query()),
            "NOTE 14 (decided 2026-10-29), {gate:?}: the guard into GRANTED \
             must ask {:?}, and it asks {asked:?}",
            adult_query()
        );
        assert!(
            asked.contains(&&Query::HasGuardianConsent { proposal: PC }),
            "NOTE 14, I-18, {gate:?}: the guard into GRANTED must ask the \
             consent again, and it asks {asked:?}"
        );
    }
}

/// R-ID-04, NOTE 14, design 2.11 contract seam: the questions of the grant
/// preconditions, which M5 asks before a contract goes to SENT, hold the
/// attestation and the consent too.
#[test]
fn r_id_04_grant_preconditions_ask_the_attestation_and_the_consent_again() {
    let s = determined(Backend::Production, AtGate::Adult);
    let qs = grant_preconditions(&s.world.life.rev.sod.state, PC)
        .unwrap_or_else(|r| panic!("PC is in NEGOTIATION with a reservation: {r}"));
    assert!(
        qs.contains(&adult_query()) && qs.contains(&Query::HasGuardianConsent { proposal: PC }),
        "NOTE 14 (decided 2026-10-29): the grant preconditions must ask {:?} \
         and the consent, and they ask {qs:?}",
        adult_query()
    );
}

/// I-23, overview NOTE 5, NOTE 14: the batch that takes PC into GRANTED
/// records both answers of the second derivation as `VaultOutcome`
/// records.
#[test]
fn r_id_04_granted_batch_records_the_attestation_and_the_consent() {
    let (mut s, step) = completing(AtGate::Adult);
    let recs = s
        .run(&step)
        .unwrap_or_else(|e| panic!("the attested PC is granted: {e}"));
    assert_eq!(s.state(PC), Some(StateTag::Granted), "granted");
    let outcome = |kind: QueryKind, bit: bool| {
        recs.iter().any(|r| {
            matches!(r, Record::VaultOutcome { kind: k, holds, .. } if *k == kind && *holds == bit)
        })
    };
    assert!(
        outcome(QueryKind::IsVerifiedAdultAtDeadline, true),
        "overview NOTE 5, NOTE 14: the GRANTED batch must record the \
         attestation answer (yes): {recs:?}"
    );
    assert!(
        outcome(QueryKind::HasGuardianConsent, false),
        "overview NOTE 5, NOTE 14: the GRANTED batch must record the \
         consent answer (no): {recs:?}"
    );
}

/// Refuses the completing fact when the vault leaves `dropped` unanswered,
/// under facts that would admit PC on the other question.
fn fails_closed_without(gate: AtGate, dropped: QueryKind) {
    let (s, step) = completing(gate);
    let state = &s.world.life.rev.sod.state;
    let (ctx, all) = ask_production(&s.world, &step)
        .unwrap_or_else(|r| panic!("{gate:?}: refused before asking: {r}"));
    let full = fstp_domain::decide(state, &step.cmd, &ctx, &all);
    assert!(
        full.is_ok(),
        "{gate:?}: with every answer PC is granted: {full:?}"
    );
    let mut partial = Answers::new();
    for (q, a) in all.iter() {
        if q.kind() != dropped {
            partial.insert(q.clone(), a.clone());
        }
    }
    assert_eq!(
        partial.len().saturating_add(1),
        all.len(),
        "{gate:?}: NOTE 14 (decided 2026-10-29): the guard into GRANTED \
         asks {dropped:?} exactly once"
    );
    let decided = fstp_domain::decide(state, &step.cmd, &ctx, &partial);
    assert!(
        decided.is_err(),
        "overview NOTE 2: {gate:?}, the vault did not answer {dropped:?}, \
         and PC was granted: {decided:?}"
    );
}

/// NOTE 14, overview NOTE 2: a verified guardian consent does not excuse a
/// missing answer about the lead's attestation at the guard into GRANTED.
#[test]
fn r_id_04_granted_guard_fails_closed_without_the_attestation_answer() {
    fails_closed_without(AtGate::Consent, QueryKind::IsVerifiedAdultAtDeadline);
}

/// NOTE 14, overview NOTE 2, I-18: an effective over-18 attestation does not
/// excuse a missing answer about the guardian consent at the guard into
/// GRANTED.
#[test]
fn i18_r_id_04_granted_guard_fails_closed_without_the_consent_answer() {
    fails_closed_without(AtGate::Adult, QueryKind::HasGuardianConsent);
}

// ---------------------------------------------------------------------------
// A re-entered proposal (NOTE 8)
// ---------------------------------------------------------------------------

/// PC re-entered into call 2 and validated there, with LC shown 18 or older
/// only after the deadline of call 1 but before that of call 2, and no
/// consent. Its amount is then determined.
fn reentered_determined(b: Backend) -> MoneyStory {
    let w = reentered_money_world(b, |t| {
        t.withdraw_attestation(LC);
        t.attest_adult(LC, LEAD_ADULT_AFTER_DEADLINE);
    })
    .unwrap_or_else(|e| panic!("NOTE 8, NOTE 14: PC re-enters call 2: {e}"));
    let mut s = MoneyStory { world: w };
    assert_eq!(
        s.state(PC),
        Some(StateTag::Negotiation),
        "NOTE 14 (decided 2026-10-29): LC is 18 or older at the deadline of \
         call 2, in which PC passes IRC review, so PC enters NEGOTIATION"
    );
    // NOTE 8: assignments are made afresh in the new call, so the
    // determining reviewers are assigned in call 2 (R-NG-03, I-34).
    for r in [R1, R2] {
        for st in assign_declared(r, PC, call(2), AssignmentKind::Reviewer) {
            s.run(&st)
                .unwrap_or_else(|e| panic!("{r:?} is assigned in call 2: {e}"));
        }
    }
    s.determine(PC, 1, &[])
        .unwrap_or_else(|e| panic!("R1 determines 4.00: {e}"));
    s
}

fn reentered_granted_on(b: Backend) {
    let mut s = reentered_determined(b);
    accept_and_approve(&mut s);
    let granted = contract(
        &mut s,
        "NOTE 14 (decided 2026-10-29): at GRANTED the deadline is that of \
         call 2 again, so the attested LC needs no consent",
    );
    assert!(
        granted,
        "R-ID-04: the re-entered PC is granted on the attestation"
    );
    assert_eq!(s.state(PC), Some(StateTag::Granted), "granted");
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// R-ID-04, NOTE 14, ADR-008 "Which deadline" (decided 2026-10-29): the
/// guard into GRANTED of a re-entered proposal asks about the deadline of
/// the later call, the same call as at the negotiation gate, so a lead
/// adult only at that deadline is granted without a consent.
#[test]
fn r_id_04_reentered_proposal_is_granted_at_the_later_call_deadline() {
    reentered_granted_on(Backend::Production);
}

/// R-ID-04, NOTE 14: the re-entered grant story on the references alone.
#[test]
fn r_id_04_reentered_proposal_is_granted_at_the_later_call_deadline_reference() {
    reentered_granted_on(Backend::Reference);
}

/// R-ID-04, overview NOTE 7, NOTE 14 (decided 2026-10-29): for a re-entered
/// proposal, the guard into GRANTED asks about the deadline of call 2 only,
/// and never about that of call 1, where the proposal was submitted.
#[test]
fn r_id_04_reentered_granted_guard_asks_about_the_later_call_deadline() {
    let mut s = reentered_determined(Backend::Production);
    accept_and_approve(&mut s);
    let (_, answers) = ask_production(&s.world, &contract_effective(PC))
        .unwrap_or_else(|r| panic!("refused before asking: {r}"));
    let asked: Vec<&Query> = answers
        .iter()
        .map(|(q, _)| q)
        .filter(|q| q.kind() == QueryKind::IsVerifiedAdultAtDeadline)
        .collect();
    let want = Query::IsVerifiedAdultAtDeadline {
        account: LC,
        deadline: LATER_DEADLINE,
    };
    assert_eq!(
        asked,
        vec![&want],
        "NOTE 14 (decided 2026-10-29): the guard into GRANTED asks about the \
         deadline of call 2 only"
    );
}
