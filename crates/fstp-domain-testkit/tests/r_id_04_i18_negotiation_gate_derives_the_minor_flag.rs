//! R-ID-04, I-18, R-NG-02: the IRC_REVIEW to NEGOTIATION gate derives the minor flag from the vault.
//!
//! `SPEC/02-domain/state-machine.md` NOTE 14 (decided 2026-10-28): the flag
//! never comes from the actor. The gate admits a proposal only when its
//! lead has an effective verified over-18 attestation at the deadline, or
//! the proposal has a verified guardian consent record. Every other
//! proposal is minor-flagged and stays in IRC_REVIEW until its consent is
//! effective (R-NG-01). The guard asks one-bit vault queries and fails
//! closed when the vault cannot answer (`03-architecture/overview.md`
//! NOTE 2). `01-requirements/functional.md` R-ID-04: no field of an
//! applicant's request sets or clears the flag.
//!
//! The stories run production commands from genesis. PR1 of lead L1 is
//! ranked within the cut-off, and IRC and IRC2 validate it. The actor's
//! `CreateDraft` field and the vault facts are set apart: the setup
//! attests a lead whose field is clear, and each story changes the truth
//! before genesis. Every step is compared with the references in both
//! directions, so a production gate that reads the actor's field fails
//! with a disagreement before the state is checked.
//!
//! The deadline is that of the call in which PR1 passes IRC review. For a
//! re-entered proposal that is the later call (NOTE 8). Daniel decided
//! this on 2026-10-29 (NOTE 14, ADR-008 "Which deadline"), replacing the
//! interim reading of the submission call. The re-entry stories below
//! were rewritten for it. The guard into GRANTED derives the flag again
//! (decided the same day), and
//! `r_id_04_i18_granted_guard_derives_the_flag_again.rs` tests it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::assignment::AssignmentKind;
use fstp_domain::command::{Actor, Command, SystemCause};
use fstp_domain::decision::Vote;
use fstp_domain::oracle::{Answers, Query, QueryKind};
use fstp_domain::rules::StateTag;
use fstp_domain::scoring::Stage;
use fstp_domain_testkit::r#gen::policy::{eur, text};
use fstp_domain_testkit::r#gen::review::{IRC, L1, PR1, R1, R2, R3};
use fstp_domain_testkit::r#gen::roster::{
    Backend, CALL_DEADLINE, CALL_OPENS, Facts, Flags, LEAD_ADULT_AFTER_DEADLINE, LEAD_ADULT_FROM,
    STAFF_DRAFTER, STAFF_PM, Step, call, publish,
};
use fstp_domain_testkit::mc::life_model::{
    IRC2, Story, assign_declared, assignment_of, ballots, cut_off, cut_off_decision, decline,
    irc_review, life_judges, reenter, story_setup,
};
use fstp_domain_testkit::vault::GroundTruth;

/// The vault facts of a story about L1 and PR1.
#[derive(Clone, Copy, Debug)]
enum Vault {
    /// An effective attestation shows L1 18 or older before the deadline.
    Adult,
    /// An effective attestation shows L1 18 or older only after the deadline.
    AdultAfterDeadline,
    /// A provisional attestation shows L1 18 or older before the deadline.
    AdultProvisional,
    /// A verified guardian consent for PR1, and no attestation.
    Consent,
    /// Neither an attestation nor a consent.
    Neither,
}

impl Vault {
    /// Sets the facts on the setup's truth, whatever the setup gave L1.
    fn set(self, t: &mut GroundTruth) {
        t.withdraw_attestation(L1);
        match self {
            Vault::Adult => t.attest_adult(L1, LEAD_ADULT_FROM),
            Vault::AdultAfterDeadline => t.attest_adult(L1, LEAD_ADULT_AFTER_DEADLINE),
            Vault::AdultProvisional => t.attest_adult_provisional(L1, LEAD_ADULT_FROM),
            Vault::Consent => t.consent(PR1),
            Vault::Neither => {}
        }
    }

    /// Whether NOTE 14 admits PR1 to NEGOTIATION under these facts.
    fn admits(self) -> bool {
        matches!(self, Vault::Adult | Vault::Consent)
    }
}

/// PR1 in IRC_REVIEW with IRC and IRC2 assigned, from genesis. `field` is
/// the `minor` field the lead sends with `CreateDraft`.
fn in_irc_review(backend: Backend, field: bool, vault: Vault) -> Story {
    let setup = story_setup(vec![(L1, PR1, field)], life_judges());
    let mut s = Story::new(&setup, backend, |t| vault.set(t)).unwrap_or_else(|e| panic!("{e}"));
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
    s
}

/// The IRC assignment of `member` to PR1.
fn irc_assignment(s: &Story, member: fstp_domain::id::AccountId) -> fstp_domain::id::AssignmentId {
    s.world
        .assignment(member, PR1, Stage::Two, AssignmentKind::Irc)
        .unwrap_or_else(|| panic!("no IRC assignment of {member:?}"))
}

/// The story after IRC and IRC2 both validated PR1. For a minor-flagged
/// proposal the last validation is recorded without the transition
/// (I-18, R-NG-01 guardian note).
fn validated(backend: Backend, field: bool, vault: Vault) -> Story {
    let mut s = in_irc_review(backend, field, vault);
    for i in [IRC, IRC2] {
        let a = irc_assignment(&s, i);
        s.attempt(&irc_review(i, a, true))
            .unwrap_or_else(|e| panic!("field {field}, {vault:?}: {e}"));
    }
    s
}

fn adult_enters_on(b: Backend) {
    let s = validated(b, true, Vault::Adult);
    assert_eq!(
        s.state(PR1),
        Some(StateTag::Negotiation),
        "R-ID-04, NOTE 14: L1 has an effective verified over-18 attestation at the \
         deadline, so PR1 enters NEGOTIATION without a guardian consent, \
         although the actor's field says minor"
    );
}

fn neither_stays_on(b: Backend) {
    let s = validated(b, false, Vault::Neither);
    assert_eq!(
        s.state(PR1),
        Some(StateTag::IrcReview),
        "R-ID-04, I-18, NOTE 14: no attestation and no consent, so PR1 is \
         minor-flagged and stays in IRC_REVIEW, although the actor's field says adult"
    );
}

fn late_attestation_stays_on(b: Backend) {
    let s = validated(b, false, Vault::AdultAfterDeadline);
    assert_eq!(
        s.state(PR1),
        Some(StateTag::IrcReview),
        "R-ID-04: L1 is shown 18 or older only after the call deadline, so PR1 \
         stays minor-flagged in IRC_REVIEW"
    );
}

fn provisional_attestation_stays_on(b: Backend) {
    let s = validated(b, true, Vault::AdultProvisional);
    assert_eq!(
        s.state(PR1),
        Some(StateTag::IrcReview),
        "R-ID-04, overview NOTE 4 and NOTE 7: a provisional attestation is not \
         effective, so PR1 stays minor-flagged in IRC_REVIEW"
    );
}

fn consent_enters_on(b: Backend) {
    let s = validated(b, false, Vault::Consent);
    assert_eq!(
        s.state(PR1),
        Some(StateTag::Negotiation),
        "I-18, R-NG-02, NOTE 14: PR1 is minor-flagged and has a verified guardian \
         consent, so it enters NEGOTIATION"
    );
}

fn field_has_no_effect_on(b: Backend) {
    let facts = [
        Vault::Adult,
        Vault::AdultAfterDeadline,
        Vault::AdultProvisional,
        Vault::Consent,
        Vault::Neither,
    ];
    for vault in facts {
        for field in [false, true] {
            let s = validated(b, field, vault);
            let want = if vault.admits() {
                StateTag::Negotiation
            } else {
                StateTag::IrcReview
            };
            assert_eq!(
                s.state(PR1),
                Some(want),
                "R-ID-04: with the actor's field {field} and the vault {vault:?}, \
                 the gate outcome must follow the vault alone"
            );
        }
    }
}

fn consent_after_validation_enters_on(b: Backend) {
    let mut s = validated(b, false, Vault::Neither);
    assert_eq!(s.state(PR1), Some(StateTag::IrcReview), "minor-flagged");
    s.vault(|t| t.consent(PR1))
        .unwrap_or_else(|e| panic!("the vault reaction: {e}"));
    let a = irc_assignment(&s, IRC2);
    s.run(&irc_review(IRC2, a, true))
        .unwrap_or_else(|e| panic!("R-IR-01: the repeat records the entry: {e}"));
    assert_eq!(
        s.state(PR1),
        Some(StateTag::Negotiation),
        "R-NG-01, NOTE 14: PR1 stays in IRC_REVIEW until its consent is \
         effective, then a validated member records the entry"
    );
}

/// R-ID-04, NOTE 14: a proposal whose lead has an effective verified over-18
/// attestation at the deadline, and no guardian consent, enters NEGOTIATION.
#[test]
fn r_id_04_adult_attested_lead_enters_negotiation_without_consent() {
    adult_enters_on(Backend::Production);
}

/// R-ID-04, NOTE 14: the adult story on the references alone.
#[test]
fn r_id_04_adult_attested_lead_enters_negotiation_without_consent_reference() {
    adult_enters_on(Backend::Reference);
}

/// R-ID-04, I-18, NOTE 14: a proposal with neither an attestation nor a
/// consent is minor-flagged and stays in IRC_REVIEW.
#[test]
fn r_id_04_i18_lead_with_neither_stays_in_irc_review() {
    neither_stays_on(Backend::Production);
}

/// R-ID-04, I-18: the story of neither fact on the references alone.
#[test]
fn r_id_04_i18_lead_with_neither_stays_in_irc_review_reference() {
    neither_stays_on(Backend::Reference);
}

/// R-ID-04: an attestation that shows the lead 18 or older only after the
/// call deadline leaves the proposal minor-flagged.
#[test]
fn r_id_04_lead_adult_only_after_the_deadline_stays_in_irc_review() {
    late_attestation_stays_on(Backend::Production);
}

/// R-ID-04: the late attestation story on the references alone.
#[test]
fn r_id_04_lead_adult_only_after_the_deadline_stays_in_irc_review_reference() {
    late_attestation_stays_on(Backend::Reference);
}

/// R-ID-04, overview NOTE 4 and NOTE 7: a provisional attestation is not
/// effective and leaves the proposal minor-flagged.
#[test]
fn r_id_04_provisional_attestation_stays_in_irc_review() {
    provisional_attestation_stays_on(Backend::Production);
}

/// R-ID-04: the provisional attestation story on the references alone.
#[test]
fn r_id_04_provisional_attestation_stays_in_irc_review_reference() {
    provisional_attestation_stays_on(Backend::Reference);
}

/// I-18, R-NG-02, NOTE 14: a minor-flagged proposal with a verified
/// guardian consent enters NEGOTIATION, whatever the actor's field said.
#[test]
fn i18_r_ng_02_consent_admits_a_minor_flagged_proposal() {
    consent_enters_on(Backend::Production);
}

/// I-18, R-NG-02: the consent story on the references alone.
#[test]
fn i18_r_ng_02_consent_admits_a_minor_flagged_proposal_reference() {
    consent_enters_on(Backend::Reference);
}

/// R-ID-04: no value of the actor's `CreateDraft` field sets or clears the
/// flag. For each vault fact, both values give the gate outcome NOTE 14
/// derives from the vault alone.
#[test]
fn r_id_04_actor_field_neither_sets_nor_clears_the_flag() {
    field_has_no_effect_on(Backend::Production);
}

/// R-ID-04: the actor field table on the references alone.
#[test]
fn r_id_04_actor_field_neither_sets_nor_clears_the_flag_reference() {
    field_has_no_effect_on(Backend::Reference);
}

/// R-NG-01, NOTE 14, R-IR-01: a minor-flagged proposal waits in IRC_REVIEW
/// until its consent is effective, then a validated member records the entry.
#[test]
fn r_ng_01_minor_flagged_proposal_waits_for_its_consent() {
    consent_after_validation_enters_on(Backend::Production);
}

/// R-NG-01: the waiting story on the references alone.
#[test]
fn r_ng_01_minor_flagged_proposal_waits_for_its_consent_reference() {
    consent_after_validation_enters_on(Backend::Reference);
}

/// The production question set and answers of the last validation, by
/// IRC2, once IRC has validated.
fn last_validation(vault: Vault) -> (Story, fstp_domain_testkit::r#gen::roster::Step) {
    let mut s = in_irc_review(Backend::Production, false, vault);
    let a = irc_assignment(&s, IRC);
    s.run(&irc_review(IRC, a, true))
        .unwrap_or_else(|e| panic!("IRC validates: {e}"));
    let a2 = irc_assignment(&s, IRC2);
    (s, irc_review(IRC2, a2, true))
}

/// Whether `q` is one of the gate's questions: the attestation or the consent.
fn gate_question(q: &Query) -> bool {
    matches!(
        q.kind(),
        QueryKind::IsVerifiedAdultAtDeadline | QueryKind::HasGuardianConsent
    )
}

/// R-ID-04, NOTE 14, overview NOTE 7: the gate asks the vault whether the
/// lead has an effective verified over-18 attestation at the deadline of
/// the call in which the proposal passes IRC review, so the flag is derived
/// only from vault answers. Without a re-entry that is the call the
/// proposal was submitted to (ADR-008 "Which deadline", decided
/// 2026-10-29).
#[test]
fn r_id_04_gate_asks_the_vault_about_the_lead_at_the_deadline() {
    let (s, step) = last_validation(Vault::Adult);
    let sod = &s.world.rev.sod;
    let ctx = sod.ctx(&step);
    let qs = fstp_domain::queries(&sod.state, &step.cmd, &ctx)
        .unwrap_or_else(|r| panic!("the last validation is refused before asking: {r}"));
    let want = Query::IsVerifiedAdultAtDeadline {
        account: L1,
        deadline: CALL_DEADLINE,
    };
    assert!(
        qs.contains(&want),
        "R-ID-04: the validation that completes the review must ask {want:?}, \
         and it asks {qs:?}"
    );
}

/// NOTE 14, overview NOTE 2: when the vault cannot answer the gate's
/// questions, the validation that would complete the review is refused
/// and records nothing, even though the facts would admit the proposal.
#[test]
fn r_id_04_gate_fails_closed_when_the_vault_cannot_answer() {
    for vault in [Vault::Adult, Vault::Consent] {
        let (s, step) = last_validation(vault);
        let sod = &s.world.rev.sod;
        let (ctx, all) = sod
            .ask(&step, Facts::Effective)
            .unwrap_or_else(|r| panic!("{vault:?}: refused before asking: {r}"));
        let full = fstp_domain::decide(&sod.state, &step.cmd, &ctx, &all);
        assert!(
            full.is_ok(),
            "{vault:?}: with every answer the validation is recorded: {full:?}"
        );
        let mut partial = Answers::new();
        for (q, a) in all.iter() {
            if !gate_question(q) {
                partial.insert(q.clone(), a.clone());
            }
        }
        assert!(
            partial.len() < all.len(),
            "{vault:?}: R-ID-04: the gate asked the vault no attestation or consent question"
        );
        let decided = fstp_domain::decide(&sod.state, &step.cmd, &ctx, &partial);
        assert!(
            decided.is_err(),
            "overview NOTE 2: {vault:?}, the vault did not answer the gate, \
             and the validation was recorded: {decided:?}"
        );
    }
}

/// Refuses the last validation when the vault leaves `dropped` unanswered,
/// under facts that would admit PR1 on the other gate question.
fn fails_closed_without(vault: Vault, dropped: QueryKind) {
    let (s, step) = last_validation(vault);
    let sod = &s.world.rev.sod;
    let (ctx, all) = sod
        .ask(&step, Facts::Effective)
        .unwrap_or_else(|r| panic!("{vault:?}: refused before asking: {r}"));
    let full = fstp_domain::decide(&sod.state, &step.cmd, &ctx, &all);
    assert!(
        full.is_ok(),
        "{vault:?}: with every answer the validation is recorded: {full:?}"
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
        "{vault:?}: R-ID-04, NOTE 14: the gate asks {dropped:?} exactly once"
    );
    let decided = fstp_domain::decide(&sod.state, &step.cmd, &ctx, &partial);
    assert!(
        decided.is_err(),
        "overview NOTE 2: {vault:?}, the vault did not answer {dropped:?}, \
         and the validation was recorded: {decided:?}"
    );
}

/// NOTE 14, overview NOTE 2: a verified guardian consent does not excuse a
/// missing answer about the lead's attestation. The validation that would
/// complete the review is refused.
#[test]
fn r_id_04_gate_fails_closed_without_the_attestation_answer() {
    fails_closed_without(Vault::Consent, QueryKind::IsVerifiedAdultAtDeadline);
}

/// NOTE 14, overview NOTE 2, I-18: an effective over-18 attestation does not
/// excuse a missing answer about the guardian consent. The validation that
/// would complete the review is refused.
#[test]
fn i18_r_id_04_gate_fails_closed_without_the_consent_answer() {
    fails_closed_without(Vault::Adult, QueryKind::HasGuardianConsent);
}

/// The deadline of call 2 in the deferral stories: later than that of
/// call 1, the call PR1 was submitted to.
const LATER_DEADLINE: fstp_domain::time::Timestamp =
    fstp_domain::time::Timestamp::from_micros(5_000_000_000_000);

/// PR1 deferred from IRC_REVIEW of call 1 by a concern, then re-entered
/// into IRC_REVIEW of call 2, whose deadline is [`LATER_DEADLINE`]. L1 is
/// shown 18 or older from `adult_from`. IRC and IRC2 are assigned in call
/// 2. The gate asks about the deadline of call 2, the call in which PR1
/// passes IRC review (NOTE 14, ADR-008 "Which deadline", decided
/// 2026-10-29).
fn reentered(backend: Backend, adult_from: fstp_domain::time::Timestamp) -> Story {
    let setup = story_setup(vec![(L1, PR1, false)], life_judges());
    let mut s = Story::new(&setup, backend, |t| {
        t.withdraw_attestation(L1);
        t.attest_adult(L1, adult_from);
    })
    .unwrap_or_else(|e| panic!("{e}"));
    let zone = fstp_domain::time::ZoneName::new("Europe/Brussels").unwrap();
    s.run(&Step::by(
        STAFF_DRAFTER,
        Flags::NONE,
        Command::EditCall {
            call: call(2),
            opens: CALL_OPENS,
            deadline: LATER_DEADLINE,
            deadline_zone: zone,
            budget: eur(100_000_000).unwrap(),
            text: text(10_002),
        },
    ))
    .unwrap_or_else(|e| panic!("call 2 gets a later deadline: {e}"));
    s.run(&Step::by(
        STAFF_PM,
        Flags::NONE,
        Command::ApproveCallPublication {
            call: call(2),
            decision: fstp_domain::id::DecisionId::from_raw(9_702),
        },
    ))
    .unwrap_or_else(|e| panic!("the edited call 2 is approved again: {e}"));
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
    s.run(&irc_review(IRC, a, false))
        .unwrap_or_else(|e| panic!("IRC raises a concern: {e}"));
    s.run(&publish(call(2))).unwrap_or_else(|e| panic!("{e}"));
    s.run(&decline(Actor::System(SystemCause::Timeline), PR1))
        .unwrap_or_else(|e| panic!("NOTE 7: the System defers PR1: {e}"));
    assert_eq!(s.state(PR1), Some(StateTag::Deferred), "PR1 deferred");
    s.run(&reenter(PR1, call(2)))
        .unwrap_or_else(|e| panic!("NOTE 8: re-entry into call 2: {e}"));
    assert_eq!(s.state(PR1), Some(StateTag::IrcReview), "PR1 re-entered");
    for i in [IRC, IRC2] {
        for st in assign_declared(i, PR1, call(2), AssignmentKind::Irc) {
            s.run(&st).unwrap_or_else(|e| panic!("{e}"));
        }
    }
    s
}

/// The current IRC assignment of `member` to PR1 in call 2.
fn irc_assignment_in_call_2(member: fstp_domain::id::AccountId) -> fstp_domain::id::AssignmentId {
    assignment_of(member, PR1, call(2), AssignmentKind::Irc)
}

/// The re-entry story after IRC and IRC2 validated PR1 in call 2. For a
/// minor-flagged proposal the last validation is recorded without the
/// transition (I-18, R-NG-01 guardian note).
fn reentered_validated(b: Backend, adult_from: fstp_domain::time::Timestamp) -> Story {
    let mut s = reentered(b, adult_from);
    let a = irc_assignment_in_call_2(IRC);
    s.run(&irc_review(IRC, a, true))
        .unwrap_or_else(|e| panic!("IRC validates in call 2: {e}"));
    let a2 = irc_assignment_in_call_2(IRC2);
    s.attempt(&irc_review(IRC2, a2, true))
        .unwrap_or_else(|e| panic!("IRC2 validates in call 2: {e}"));
    s
}

fn reentered_adult_enters_on(b: Backend) {
    let s = reentered_validated(b, LEAD_ADULT_FROM);
    assert_eq!(
        s.state(PR1),
        Some(StateTag::Negotiation),
        "control, R-ID-04, NOTE 14: L1 is 18 or older at the deadline of call 1, \
         so the re-entered PR1 enters NEGOTIATION"
    );
}

/// Rewritten on 2026-10-29 for state-machine NOTE 14 ("Which deadline"
/// decided): it encoded the overturned interim reading, under which L1
/// stayed minor-flagged at the deadline of call 1.
fn reentered_later_deadline_enters_on(b: Backend) {
    let s = reentered_validated(b, LEAD_ADULT_AFTER_DEADLINE);
    assert_eq!(
        s.state(PR1),
        Some(StateTag::Negotiation),
        "R-ID-04, NOTE 14, ADR-008 (\"Which deadline\", decided 2026-10-29): \
         L1 is 18 or older at the deadline of call 2, in which the re-entered \
         PR1 passes IRC review, though not at that of call 1, so PR1 is not \
         minor-flagged and enters NEGOTIATION without a consent"
    );
}

/// R-ID-04, NOTE 14, ADR-008 ("Which deadline", decided 2026-10-29): after a
/// deferral and re-entry into a call with a later deadline (NOTE 8), the
/// gate derives the flag at the deadline of the later call, in which the
/// proposal passes IRC review.
///
/// Rewritten for NOTE 14 from
/// `r_id_04_reentered_proposal_is_flagged_at_the_submission_deadline`,
/// which encoded the overturned submission-call reading.
#[test]
fn r_id_04_reentered_proposal_is_derived_at_the_later_call_deadline() {
    reentered_later_deadline_enters_on(Backend::Production);
}

/// R-ID-04, NOTE 14: the re-entry story on the references alone.
///
/// Rewritten for NOTE 14 from
/// `r_id_04_reentered_proposal_is_flagged_at_the_submission_deadline_reference`.
#[test]
fn r_id_04_reentered_proposal_is_derived_at_the_later_call_deadline_reference() {
    reentered_later_deadline_enters_on(Backend::Reference);
}

fn reentered_minor_at_both_deadlines_stays_on(b: Backend) {
    let s = reentered_validated(
        b,
        fstp_domain_testkit::r#gen::minor::LEAD_ADULT_AFTER_LATER_DEADLINE,
    );
    assert_eq!(
        s.state(PR1),
        Some(StateTag::IrcReview),
        "R-ID-04, I-18, NOTE 14: L1 is 18 or older only after the deadline of \
         call 2, so the re-entered PR1 stays minor-flagged in IRC_REVIEW"
    );
}

/// R-ID-04, I-18, NOTE 14 (decided 2026-10-29): a lead shown 18 or older
/// only after the deadline of the later call leaves the re-entered
/// proposal minor-flagged.
#[test]
fn r_id_04_reentered_proposal_of_a_lead_adult_only_after_the_later_deadline_stays() {
    reentered_minor_at_both_deadlines_stays_on(Backend::Production);
}

/// R-ID-04, I-18: the story of a lead adult after both deadlines on the
/// references alone.
#[test]
fn r_id_04_reentered_proposal_of_a_lead_adult_only_after_the_later_deadline_stays_reference() {
    reentered_minor_at_both_deadlines_stays_on(Backend::Reference);
}

/// R-ID-04, overview NOTE 7, NOTE 14, ADR-008 ("Which deadline", decided
/// 2026-10-29): the last validation after a re-entry asks the vault about
/// the lead at the deadline of call 2, in which the proposal passes IRC
/// review, and never at that of call 1.
///
/// Rewritten for NOTE 14 from
/// `r_id_04_reentered_gate_asks_about_the_submission_deadline`, which
/// encoded the overturned submission-call reading.
#[test]
fn r_id_04_reentered_gate_asks_about_the_later_call_deadline() {
    let mut s = reentered(Backend::Production, LEAD_ADULT_AFTER_DEADLINE);
    let a = irc_assignment_in_call_2(IRC);
    s.run(&irc_review(IRC, a, true))
        .unwrap_or_else(|e| panic!("IRC validates in call 2: {e}"));
    let a2 = irc_assignment_in_call_2(IRC2);
    let step = irc_review(IRC2, a2, true);
    let sod = &s.world.rev.sod;
    let ctx = sod.ctx(&step);
    let qs = fstp_domain::queries(&sod.state, &step.cmd, &ctx)
        .unwrap_or_else(|r| panic!("the last validation is refused before asking: {r}"));
    let asked: Vec<&Query> = qs
        .iter()
        .filter(|q| q.kind() == QueryKind::IsVerifiedAdultAtDeadline)
        .collect();
    let want = Query::IsVerifiedAdultAtDeadline {
        account: L1,
        deadline: LATER_DEADLINE,
    };
    assert_eq!(
        asked,
        vec![&want],
        "NOTE 14 (decided 2026-10-29): the gate asks about the deadline of \
         call 2 only, and it asks {qs:?}"
    );
}

/// R-ID-04, NOTE 14: control for the re-entry stories. A lead 18 or older
/// at the deadline of the submission call takes the re-entered proposal
/// into NEGOTIATION, so the re-entered gate can admit.
#[test]
fn r_id_04_reentered_proposal_of_an_attested_lead_enters_negotiation() {
    reentered_adult_enters_on(Backend::Production);
}

/// R-ID-04: the re-entry control on the references alone.
#[test]
fn r_id_04_reentered_proposal_of_an_attested_lead_enters_negotiation_reference() {
    reentered_adult_enters_on(Backend::Reference);
}

/// Whether production says guardian consent collection is open for PR1.
fn collection_open(s: &Story) -> bool {
    fstp_domain::decision::awaiting_guardian_consent(&s.world.rev.sod.state, PR1)
}

/// R-NG-01 (guardian exception), design 6.6 step 3: collection opens once
/// every reviewing IRC member has validated a minor-flagged proposal, and
/// closes when the consent takes it into NEGOTIATION. The cell reads this
/// to issue the guardian's write ticket.
#[test]
fn r_ng_01_consent_collection_opens_after_the_last_validation() {
    let mut s = in_irc_review(Backend::Production, false, Vault::Neither);
    assert!(!collection_open(&s), "R-NG-01: no IRC member has validated");
    let a = irc_assignment(&s, IRC);
    s.run(&irc_review(IRC, a, true))
        .unwrap_or_else(|e| panic!("IRC validates: {e}"));
    assert!(!collection_open(&s), "R-NG-01: IRC2 has not validated");
    let a2 = irc_assignment(&s, IRC2);
    s.attempt(&irc_review(IRC2, a2, true))
        .unwrap_or_else(|e| panic!("IRC2 validates: {e}"));
    assert_eq!(s.state(PR1), Some(StateTag::IrcReview), "minor-flagged");
    assert!(
        collection_open(&s),
        "R-NG-01: every IRC member validated the minor-flagged PR1, so \
         consent collection is open"
    );
    s.vault(|t| t.consent(PR1))
        .unwrap_or_else(|e| panic!("the vault reaction: {e}"));
    s.run(&irc_review(IRC2, a2, true))
        .unwrap_or_else(|e| panic!("R-IR-01: the repeat records the entry: {e}"));
    assert_eq!(s.state(PR1), Some(StateTag::Negotiation), "consent admits");
    assert!(
        !collection_open(&s),
        "R-NG-01: PR1 left IRC_REVIEW, so collection is closed"
    );
}

/// R-NG-01, R-ID-04, NOTE 14: a proposal whose gate found an effective
/// over-18 attestation enters NEGOTIATION, and no consent collection opens.
#[test]
fn r_ng_01_no_consent_collection_for_an_attested_lead() {
    let s = validated(Backend::Production, true, Vault::Adult);
    assert_eq!(s.state(PR1), Some(StateTag::Negotiation), "attested");
    assert!(
        !collection_open(&s),
        "R-NG-01: the attested PR1 is not minor-flagged, so no collection opens"
    );
}
