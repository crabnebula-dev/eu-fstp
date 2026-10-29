//! I-18, R-ID-04: the second derivation reaches every NEGOTIATION command that reads the minor flag (state-machine NOTE 14, decided 2026-10-29).
//!
//! `SPEC/02-domain/state-machine.md` NOTE 14: "the guard into GRANTED
//! derives the flag again in the same way". NOTE 9: NEGOTIATION to DECLINED
//! ends a negotiation that cannot reach GRANTED, and a missing guardian
//! consent (I-18) is one of its grounds. ADR-008 "Second derivation": a
//! verification in NEGOTIATION that shows the lead under 18 "then needs a
//! verified guardian consent before GRANTED". `03-architecture/overview.md`
//! NOTE 2: a guard fails closed when the vault cannot answer.
//!
//! So `DeclineNegotiation` finds consent missing exactly when the guard
//! into GRANTED would, and the lead can bind a guardian in NEGOTIATION once
//! the vault no longer shows the lead 18 or older. The decisions carry the
//! rules version of the 2026-10-29 readings (design 5.1), and the fold
//! keeps the gate's flag for a grant decided under the M2 readings.
//!
//! These are the regression tests of lane dom2 fix round 1. The stories run
//! from genesis and compare every step with the references in both
//! directions. The direct tests run production `queries` and `decide` with
//! the answers the synthetic vault gives.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::Actor;
use fstp_domain::decision::NegotiationFailure;
use fstp_domain::id::{AccountId, BindingId, CommandId};
use fstp_domain::oracle::QueryKind;
use fstp_domain::record::{Record, RulesVersion};
use fstp_domain::refusal::{Refusal, RefusalReason, RuleRef};
use fstp_domain::rules::{Row, StateTag};
use fstp_domain::{Answers, State};
use fstp_domain_testkit::r#gen::minor::{ask_production, money_setup};
use fstp_domain_testkit::r#gen::money::{
    LC, MoneyStory, PC, accept_grant, approve_grant, contract_effective, decline_negotiation,
};
use fstp_domain_testkit::r#gen::roster::{
    Backend, CALL_DEADLINE, LEAD_ADULT_AFTER_DEADLINE, LEAD_ADULT_FROM, STAFF_PM, Step, add_member,
};
use fstp_domain_testkit::reference::money::forge_grant;
use fstp_domain_testkit::vault::GroundTruth;
use fstp_ledger::Seq;

/// A guardian account outside the setup, verified in the vault.
const GUARDIAN: AccountId = AccountId::from_raw(9_961);

/// The command id of the direct runs.
const DIRECT: CommandId = CommandId::from_bytes(*b"test:dom2:fix:r1");

/// The vault facts at the negotiation gate.
#[derive(Clone, Copy, Debug)]
enum AtGate {
    /// An effective attestation shows LC 18 or older at the deadline, and
    /// PC has no guardian consent.
    Adult,
    /// LC has no attestation, and PC has a verified guardian consent.
    Consent,
}

impl AtGate {
    fn set(self, t: &mut GroundTruth) {
        t.withdraw_attestation(LC);
        t.verify(GUARDIAN);
        match self {
            AtGate::Adult => t.attest_adult(LC, LEAD_ADULT_FROM),
            AtGate::Consent => t.consent(PC),
        }
    }
}

/// PC in NEGOTIATION under `gate`, its amount determined, accepted and
/// approved, then the vault changed by `change`.
fn negotiating(b: Backend, gate: AtGate, change: impl FnOnce(&mut GroundTruth)) -> MoneyStory {
    let mut s = MoneyStory::with(&money_setup(true), b, |t| gate.set(t))
        .unwrap_or_else(|e| panic!("NOTE 14: {gate:?} admits PC to NEGOTIATION: {e}"));
    assert_eq!(s.state(PC), Some(StateTag::Negotiation), "{gate:?}");
    s.determine(PC, 1, &[])
        .unwrap_or_else(|e| panic!("R1 determines 4.00: {e}"));
    s.run(&accept_grant(LC, PC))
        .unwrap_or_else(|e| panic!("the lead accepts: {e}"));
    s.run(&approve_grant(STAFF_PM, PC))
        .unwrap_or_else(|e| panic!("the programme manager approves: {e}"));
    s.world
        .vault(change)
        .unwrap_or_else(|e| panic!("the vault reaction: {e}"));
    s
}

/// The programme manager's decline of PC.
fn decline() -> Step {
    decline_negotiation(Actor::Account(STAFF_PM), PC)
}

/// LC's `AddGuardian` of GUARDIAN on PC.
fn add_guardian(binding: u128) -> Step {
    add_member(LC, PC, GUARDIAN, BindingId::from_raw(binding), true)
}

/// Production's batch for `step` on `state`, with the answers the vault
/// `truth` gives. A query the vault leaves unanswered stays out.
fn decide_on(state: &State, s: &MoneyStory, step: &Step) -> Result<Vec<Record>, Refusal> {
    let ctx = step.ctx(s.world.now(), DIRECT);
    let mut answers = Answers::new();
    for q in fstp_domain::queries(state, &step.cmd, &ctx)? {
        if let Some(a) = s.world.truth().try_answer(&q) {
            answers.insert(q, a);
        }
    }
    fstp_domain::decide(state, &step.cmd, &ctx, &answers)
}

/// Production's batch for `step` on the story's state.
fn decide_now(s: &MoneyStory, step: &Step) -> Result<Vec<Record>, Refusal> {
    let (ctx, answers) = ask_production(&s.world, step)?;
    fstp_domain::decide(&s.world.life.rev.sod.state, &step.cmd, &ctx, &answers)
}

// ---------------------------------------------------------------------------
// DeclineNegotiation (NOTE 9)
// ---------------------------------------------------------------------------

fn decline_after_lost_attestation_on(b: Backend) {
    let mut s = negotiating(b, AtGate::Adult, |t| t.withdraw_attestation(LC));
    assert!(
        s.attempt(&contract_effective(PC))
            .unwrap_or_else(|e| panic!("{e}"))
            .is_none(),
        "I-18, NOTE 14: the guard into GRANTED finds PC minor-flagged with no consent"
    );
    let recs = s.run(&decline()).unwrap_or_else(|e| {
        panic!(
            "NOTE 9, NOTE 14: PC cannot reach GRANTED without a consent, so the \
             programme manager can decline it: {e}"
        )
    });
    assert!(
        recs.iter().any(|r| matches!(
            r,
            Record::NegotiationDeclined {
                reason: NegotiationFailure::GuardianConsentMissing,
                ..
            }
        )),
        "NOTE 9: the reason is the missing guardian consent: {recs:?}"
    );
    assert_eq!(s.state(PC), Some(StateTag::Declined), "declined");
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// I-18, NOTE 9, NOTE 14 (decided 2026-10-29): a proposal admitted on the
/// lead's attestation, whose attestation is withdrawn in NEGOTIATION with
/// no consent, is declined for the missing guardian consent.
#[test]
fn i18_r_id_04_decline_finds_consent_missing_after_the_attestation_is_lost() {
    decline_after_lost_attestation_on(Backend::Production);
}

/// I-18, NOTE 9: the lost-attestation decline on the references alone.
#[test]
fn i18_r_id_04_decline_finds_consent_missing_after_the_attestation_is_lost_reference() {
    decline_after_lost_attestation_on(Backend::Reference);
}

fn no_decline_after_attestation_on(b: Backend) {
    let mut s = negotiating(b, AtGate::Consent, |t| {
        t.withdraw_consent(PC);
        t.attest_adult(LC, LEAD_ADULT_FROM);
    });
    s.refused(&decline()).unwrap_or_else(|e| {
        panic!(
            "NOTE 9, NOTE 14: PC can reach GRANTED on the attestation recorded \
             in NEGOTIATION, so no listed failure holds: {e}"
        )
    });
    assert!(
        s.attempt(&contract_effective(PC))
            .unwrap_or_else(|e| panic!("{e}"))
            .is_some(),
        "R-ID-04, NOTE 14: the completing fact takes PC into GRANTED"
    );
    assert_eq!(s.state(PC), Some(StateTag::Granted), "granted");
}

/// R-ID-04, NOTE 9, NOTE 14 (decided 2026-10-29): a proposal admitted on
/// its consent, whose consent is withdrawn and whose lead is attested in
/// NEGOTIATION, can reach GRANTED, so the decline finds no missing consent.
#[test]
fn r_id_04_decline_refused_when_an_attestation_in_negotiation_admits() {
    no_decline_after_attestation_on(Backend::Production);
}

/// R-ID-04, NOTE 9: the attested-in-negotiation decline on the references.
#[test]
fn r_id_04_decline_refused_when_an_attestation_in_negotiation_admits_reference() {
    no_decline_after_attestation_on(Backend::Reference);
}

/// NOTE 9, NOTE 14, overview NOTE 2: the decline asks the attestation and
/// the consent as the guard into GRANTED does, and an age conflict that
/// waits for its manual check refuses it as a missing answer.
#[test]
fn r_id_04_decline_fails_closed_on_an_age_conflict() {
    let s = negotiating(Backend::Production, AtGate::Adult, |t| {
        t.verify_under_18(LC, LEAD_ADULT_AFTER_DEADLINE);
    });
    assert!(
        s.world.truth().age_conflict_at(LC, CALL_DEADLINE),
        "the vault holds the conflict"
    );
    let ctx = s.world.life.rev.sod.ctx(&decline());
    let qs = fstp_domain::queries(&s.world.life.rev.sod.state, &decline().cmd, &ctx)
        .unwrap_or_else(|r| panic!("refused before asking: {r}"));
    for kind in [
        QueryKind::IsVerifiedAdultAtDeadline,
        QueryKind::HasGuardianConsent,
    ] {
        assert!(
            qs.iter().any(|q| q.kind() == kind),
            "NOTE 14: the decline must ask {kind:?}, and it asks {qs:?}"
        );
    }
    let r = decide_now(&s, &decline()).expect_err("overview NOTE 2: the decline is refused");
    assert_eq!(
        (r.rule, r.reason),
        (RuleRef::FactsIncomplete, RefusalReason::AnswerMissing),
        "NOTE 14: the conflict reaches the domain only as a missing answer"
    );
}

// ---------------------------------------------------------------------------
// AddGuardian in NEGOTIATION (R-NG-01, ADR-008 "Second derivation")
// ---------------------------------------------------------------------------

fn guardian_after_lost_attestation_on(b: Backend) {
    let mut s = negotiating(b, AtGate::Adult, |t| t.withdraw_attestation(LC));
    s.run(&add_guardian(9_962)).unwrap_or_else(|e| {
        panic!(
            "ADR-008 Second derivation: LC is no longer shown 18 or older, so \
             PC needs a consent before GRANTED and LC may bind its guardian: {e}"
        )
    });
    s.world
        .vault(|t| t.consent(PC))
        .unwrap_or_else(|e| panic!("the vault reaction: {e}"));
    assert!(
        s.attempt(&contract_effective(PC))
            .unwrap_or_else(|e| panic!("{e}"))
            .is_some(),
        "I-18: with the consent, PC is granted"
    );
    assert_eq!(s.state(PC), Some(StateTag::Granted), "consent admits");
    s.invariants().unwrap_or_else(|e| panic!("{e}"));
}

/// R-NG-01, I-18, ADR-008 "Second derivation" (decided 2026-10-29): after
/// the attestation is lost in NEGOTIATION, the lead binds a guardian, whose
/// consent then admits PC to GRANTED.
#[test]
fn r_ng_01_i18_guardian_bound_in_negotiation_after_the_attestation_is_lost() {
    guardian_after_lost_attestation_on(Backend::Production);
}

/// R-NG-01, I-18: the guardian-in-negotiation story on the references.
#[test]
fn r_ng_01_i18_guardian_bound_in_negotiation_after_the_attestation_is_lost_reference() {
    guardian_after_lost_attestation_on(Backend::Reference);
}

fn no_guardian_for_an_adult_on(b: Backend) {
    let mut s = negotiating(b, AtGate::Adult, |_| {});
    s.refused(&add_guardian(9_963)).unwrap_or_else(|e| {
        panic!("R-ID-04: the vault still shows LC 18 or older, so no guardian: {e}")
    });
}

/// R-ID-04, R-NG-01: in NEGOTIATION a lead the vault still shows 18 or
/// older binds no guardian.
#[test]
fn r_id_04_no_guardian_in_negotiation_while_the_lead_is_shown_adult() {
    no_guardian_for_an_adult_on(Backend::Production);
}

/// R-ID-04, R-NG-01: the adult lead's guardian refusal on the references.
#[test]
fn r_id_04_no_guardian_in_negotiation_while_the_lead_is_shown_adult_reference() {
    no_guardian_for_an_adult_on(Backend::Reference);
}

/// R-NG-01, overview NOTE 2: `AddGuardian` in NEGOTIATION asks the
/// attestation again, and an age conflict that waits for its manual check
/// refuses it as a missing answer.
#[test]
fn r_ng_01_guardian_in_negotiation_fails_closed_on_an_age_conflict() {
    let s = negotiating(Backend::Production, AtGate::Adult, |t| {
        t.verify_under_18(LC, LEAD_ADULT_AFTER_DEADLINE);
    });
    let step = add_guardian(9_964);
    let ctx = s.world.life.rev.sod.ctx(&step);
    let qs = fstp_domain::queries(&s.world.life.rev.sod.state, &step.cmd, &ctx)
        .unwrap_or_else(|r| panic!("refused before asking: {r}"));
    assert!(
        qs.iter()
            .any(|q| q.kind() == QueryKind::IsVerifiedAdultAtDeadline),
        "ADR-008: AddGuardian in NEGOTIATION must ask the attestation, and it asks {qs:?}"
    );
    let r = decide_now(&s, &step).expect_err("overview NOTE 2: AddGuardian is refused");
    assert_eq!(
        (r.rule, r.reason),
        (RuleRef::FactsIncomplete, RefusalReason::AnswerMissing),
        "NOTE 14: the conflict reaches the domain only as a missing answer"
    );
}

// ---------------------------------------------------------------------------
// The GRANTED batch, its rules version and the fold (design 5.1)
// ---------------------------------------------------------------------------

/// The production GRANTED batch of PC, admitted at the gate under `gate`
/// and attested in NEGOTIATION, and the story before it.
fn granted_batch(gate: AtGate) -> (MoneyStory, Vec<Record>) {
    let s = negotiating(Backend::Production, gate, |t| {
        t.attest_adult(LC, LEAD_ADULT_FROM);
    });
    let recs = decide_now(&s, &contract_effective(PC))
        .unwrap_or_else(|r| panic!("R-ID-04: PC is granted on the attestation: {r}"));
    (s, recs)
}

/// I-23, NOTE 14: the GRANTED batch places the `IsVerifiedAdultAtDeadline`
/// outcome before the transition, so the fold derives the flag from it. It
/// stamps the grant with the rules version of the 2026-10-29 readings.
#[test]
fn r_id_04_granted_batch_places_the_attestation_outcome_before_the_transition() {
    let (_, recs) = granted_batch(AtGate::Consent);
    let outcome = recs.iter().position(|r| {
        matches!(
            r,
            Record::VaultOutcome {
                kind: QueryKind::IsVerifiedAdultAtDeadline,
                ..
            }
        )
    });
    let transition = recs
        .iter()
        .position(|r| matches!(r, Record::Transitioned(t) if t.row == Row::NegotiationToGranted));
    assert!(
        matches!((outcome, transition), (Some(o), Some(t)) if o < t),
        "NOTE 14: the attestation outcome must precede the GRANTED transition: {recs:?}"
    );
    let rules: Vec<RulesVersion> = recs
        .iter()
        .filter_map(|r| match r {
            Record::GrantDecided(g) => Some(g.rules()),
            _ => None,
        })
        .collect();
    assert_eq!(
        rules,
        vec![RulesVersion::MINOR_FLAG_2026_10_29],
        "design 5.1: the grant carries the version of the readings that produced it"
    );
}

/// NOTE 9, design 5.1: the decline carries the version of the 2026-10-29
/// readings, under which it derives the flag again.
#[test]
fn r_id_04_decline_carries_the_2026_10_29_rules_version() {
    let s = negotiating(Backend::Production, AtGate::Adult, |t| {
        t.withdraw_attestation(LC);
    });
    let recs = decide_now(&s, &decline()).unwrap_or_else(|r| panic!("NOTE 9: declined: {r}"));
    assert!(
        recs.iter().any(|r| matches!(
            r,
            Record::NegotiationDeclined { rules, .. }
                if *rules == RulesVersion::MINOR_FLAG_2026_10_29
        )),
        "design 5.1: {recs:?}"
    );
}

/// The state after folding `recs` onto the story's state.
fn folded(s: &MoneyStory, recs: &[Record]) -> State {
    let mut state = s.world.life.rev.sod.state.clone();
    for r in recs {
        fstp_domain::apply(&mut state, Seq::from_raw(1), s.world.now(), r)
            .unwrap_or_else(|e| panic!("the fold refuses {r:?}: {e}"));
    }
    state
}

/// Whether production admits a guardian on PC in `state`, which reads the
/// minor flag after GRANTED.
fn guardian_admitted(state: &State, s: &MoneyStory, binding: u128) -> bool {
    decide_on(state, s, &add_guardian(binding)).is_ok()
}

/// R-ID-04, NOTE 14: after GRANTED the flag is the one the guard into
/// GRANTED derived. PC was admitted at the gate on its consent, so the gate
/// flagged it. The guard found LC attested, so the flag is now clear and
/// no guardian is admitted.
#[test]
fn r_id_04_flag_after_grant_is_the_second_derivation() {
    let (s, recs) = granted_batch(AtGate::Consent);
    let state = folded(&s, &recs);
    assert!(
        !guardian_admitted(&state, &s, 9_965),
        "NOTE 14 (decided 2026-10-29): the guard into GRANTED found LC 18 or \
         older, so PC is not minor-flagged after GRANTED"
    );
}

/// I-18, R-ID-04, NOTE 14: the same story without the attestation. The
/// guard into GRANTED admits PC on its consent, so PC stays minor-flagged
/// after GRANTED.
#[test]
fn i18_r_id_04_flag_after_grant_stays_set_for_a_consent() {
    let s = negotiating(Backend::Production, AtGate::Consent, |_| {});
    let recs = decide_now(&s, &contract_effective(PC))
        .unwrap_or_else(|r| panic!("I-18: PC is granted on its consent: {r}"));
    let state = folded(&s, &recs);
    assert!(
        guardian_admitted(&state, &s, 9_966),
        "NOTE 14: the guard into GRANTED found PC minor-flagged"
    );
}

/// Design 5.1 ("Structural replay"): a GRANTED batch written under the M2
/// readings recorded its vault outcomes after the transition and no
/// second derivation. The fold keeps the gate's flag for it, so a ledger
/// written before 2026-10-29 keeps its meaning on replay. Here the gate
/// found LC 18 or older, so PC stays clear and admits no guardian. A fold
/// that derived the flag again would find no attestation bit before the
/// transition and set the flag.
#[test]
fn r_id_04_m2_grant_batch_keeps_the_gate_flag_on_replay() {
    let (s, recs) = granted_batch(AtGate::Adult);
    let mut old: Vec<Record> = Vec::new();
    let mut outcomes: Vec<Record> = Vec::new();
    for r in &recs {
        match r {
            Record::VaultOutcome { .. } => outcomes.push(r.clone()),
            Record::GrantDecided(g) => old.push(
                forge_grant(
                    g.proposal(),
                    g.granted().amount().minor(),
                    g.agreed_plan(),
                    g.acceptance(),
                    g.approval(),
                    g.contract(),
                    g.epoch().raw(),
                    RulesVersion::M2,
                )
                .unwrap_or_else(|e| panic!("the M2 grant: {e}")),
            ),
            _ => old.push(r.clone()),
        }
    }
    old.extend(outcomes);
    let state = folded(&s, &old);
    assert!(
        !guardian_admitted(&state, &s, 9_967),
        "design 5.1: under the M2 readings the flag from the gate holds \
         after GRANTED, and the gate found LC 18 or older"
    );
    let state = folded(&s, &recs);
    assert!(
        !guardian_admitted(&state, &s, 9_968),
        "control: the 2026-10-29 batch derives the same clear flag"
    );
}
