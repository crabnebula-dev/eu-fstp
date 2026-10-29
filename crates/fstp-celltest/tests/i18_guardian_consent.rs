//! I-18: a proposal flagged as from a minor cannot enter negotiation
//! without a verified guardian consent record (design sections 6.6, 6.9
//! and 14.4, state-machine NOTE 14, Q13 A).
//!
//! Lane W1c wrote these tests before the production code. Each compares
//! production with `fstp_celltest::reference::vault`. They are red until
//! `fstp-vault-core` (lane W2d), `fstp-cell-core` (lane W2c) and the cell
//! routes and runtime (lane W3a) land. The reference and teeth tests are
//! green now.
//!
//! Claims built on seeding say so (design section 6.9): the vault-core
//! machine seeds its facts through `fstp_celltest::vault_seed`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::BTreeSet;

use fstp_cell_core::release::{ReleaseCommand, ReleaseRecord};
use fstp_cell_core::{CellCommand, CellCtx, CellRecord, CellRefusal};
use fstp_celltest::mc::auth_model::ProdCell;
use fstp_celltest::mc::driver_model::paths;
use fstp_celltest::mc::vcp_model::{
    AskReply, Production, Reference, VOp, VcpVault, reference_vault,
};
use fstp_celltest::reference::vault::{
    self as rv, CellEvent, GuardianRecipient, Person, RefWrite, WriteKind, guardian_ticket_allowed,
    guardian_ticket_order,
};
use fstp_celltest::vault_seed::{SeedLog, SeedSource, seed_fact};
use fstp_celltest::world::{DbMode, VaultLayout, World, WorldSpec};
use fstp_domain::command::Actor;
use fstp_domain::id::{AccountId, ProposalId};
use fstp_domain::oracle::{Answer, Answers, Query};
use fstp_domain::rules::StateTag;

use fstp_domain_testkit::r#gen::review::{L1, PR1, STRANGER};
use fstp_domain_testkit::r#gen::roster::CALL_DEADLINE;
use fstp_domain_testkit::harness::teeth::expect_prop_failure;
use fstp_domain_testkit::vault::PLACEHOLDER_DIGEST;
use fstp_prop::{Gen, prop_assert, prop_assert_eq};

// ---------------------------------------------------------------------------
// The "Minor applicant" vault: lead L, proposal P, guardians G1 and G2.

const LEAD: AccountId = AccountId::from_raw(301);
const G1: AccountId = AccountId::from_raw(401);
const G2: AccountId = AccountId::from_raw(402);
const P: ProposalId = ProposalId::from_raw(1);
const NOW: i64 = 1_000_000;

fn gate_queries() -> Vec<Query> {
    vec![
        Query::IsVerifiedAdultAtDeadline {
            account: LEAD,
            deadline: CALL_DEADLINE,
        },
        Query::HasGuardianConsent { proposal: P },
    ]
}

/// One vault operation of the "Minor applicant" machine: a consent by
/// either guardian, verified or not, a withdrawal, a guardian
/// verification, an acknowledgement of the provisional epoch, or an
/// acknowledgement of another epoch.
fn minor_op(g: &mut Gen, history: &[VOp]) -> VOp {
    let v = reference_vault(history);
    match g.u8_in(0..=5) {
        0 => VOp::Write(RefWrite::GuardianConsent {
            proposal: P,
            guardian: *g.pick(&[G1, G2]),
        }),
        1 => VOp::Write(RefWrite::ConsentWithdrawn { proposal: P }),
        2 => {
            let guardian = *g.pick(&[G1, G2]);
            VOp::Write(RefWrite::VerificationRecorded {
                account: guardian,
                person: Person(u64::try_from(guardian.raw()).unwrap()),
            })
        }
        3 | 4 => VOp::Ack {
            epoch: v.current(),
            seq: u64::try_from(history.len()).unwrap() + 1,
        },
        _ => VOp::Ack {
            epoch: v.current() + g.u64_in(1..=2),
            seq: 1,
        },
    }
}

/// A vault's answer to `HasGuardianConsent` for P after a history, or
/// `None` when it refused to answer.
type ConsentAnswer = dyn Fn(&[VOp]) -> Option<bool>;

/// The reference vault's answer.
fn reference_answer(history: &[VOp]) -> Option<bool> {
    match Reference
        .ask(history, None, &[Query::HasGuardianConsent { proposal: P }])
        .unwrap()
    {
        AskReply::Answered(a) => a.first().map(|x| x.holds),
        _ => None,
    }
}

/// The I-18 claim over a vault's answer after `history`: a yes from
/// `HasGuardianConsent` means the log holds an effective consent for P and
/// an effective verification of its guardian, both before the newest
/// withdrawal of P's consent, if any.
fn consent_claim(history: &[VOp], answer: &ConsentAnswer) -> Result<(), String> {
    if answer(history) != Some(true) {
        return Ok(());
    }
    let v = reference_vault(history);
    let mut guardian: Option<AccountId> = None;
    let mut verified: BTreeSet<AccountId> = BTreeSet::new();
    for e in v.log() {
        match &e.write {
            RefWrite::GuardianConsent { guardian: g, .. } => guardian = Some(*g),
            RefWrite::ConsentWithdrawn { .. } => guardian = None,
            RefWrite::VerificationRecorded { account, .. } => {
                verified.insert(*account);
            }
            _ => {}
        }
    }
    match guardian {
        Some(g) if verified.contains(&g) => Ok(()),
        _ => Err(format!(
            "I-18: the vault counts a consent whose guardian verification is not effective: {:?}",
            v.log()
        )),
    }
}

/// The reference's own I-18 claim after `history`.
fn reference_claim(history: &[VOp]) -> Result<(), String> {
    consent_claim(history, &reference_answer)
}

// ---------------------------------------------------------------------------
// The vault core.

/// I-18 (design section 14.4): `fstp_vault_core` answers
/// `HasGuardianConsent` as the reference does after every operation, so a
/// consent counts only once it and its guardian's verification are
/// effective (NOTE 4).
#[test]
fn i18_consent_counts_only_after_guardian_verification_is_effective() {
    fstp_prop::check(
        "i18_consent_counts_only_after_guardian_verification_is_effective",
        |g: &mut Gen| {
            let mut history = Vec::new();
            for _ in 0..g.usize_in(1..=10) {
                let op = minor_op(g, &history);
                history.push(op);
                let q = [Query::HasGuardianConsent { proposal: P }];
                let want = Reference.ask(&history, None, &q).unwrap();
                let got = Production
                    .ask(&history, None, &q)
                    .map_err(|e| format!("{} is NotImplemented", e.operation))?;
                prop_assert_eq!(got, want, "after {history:?}");
            }
            Ok(())
        },
    );
}

/// I-18: the reference counts a consent only when the consent and the
/// guardian's verification are both effective.
#[test]
fn i18_reference_consent_counts_only_after_guardian_verification_is_effective() {
    fstp_prop::check(
        "i18_reference_consent_counts_only_after_guardian_verification_is_effective",
        |g: &mut Gen| {
            let mut history = Vec::new();
            for _ in 0..g.usize_in(1..=12) {
                let op = minor_op(g, &history);
                history.push(op);
                reference_claim(&history)?;
            }
            Ok(())
        },
    );
}

/// The seeded defect of the teeth test: a vault whose `HasGuardianConsent`
/// answers yes for the newest effective consent of P, whether or not its
/// guardian is verified. It also ignores the pending rule of NOTE 4.
fn ignores_guardian_verification(history: &[VOp]) -> Option<bool> {
    let v = reference_vault(history);
    let newest = v.log().iter().rev().find_map(|e| match &e.write {
        RefWrite::GuardianConsent { .. } => Some(true),
        RefWrite::ConsentWithdrawn { .. } => Some(false),
        _ => None,
    });
    Some(newest.unwrap_or(false))
}

/// I-18 teeth: the claim check of
/// `i18_reference_consent_counts_only_after_guardian_verification_is_effective`
/// catches a vault that counts a consent whose guardian is unverified.
#[test]
fn i18_teeth_consent_by_unverified_guardian_is_caught() {
    let outcome = fstp_prop::run(
        "i18_teeth_consent_by_unverified_guardian_is_caught",
        fstp_prop::Config::default(),
        |g: &mut Gen| {
            let mut history = Vec::new();
            for _ in 0..g.usize_in(1..=12) {
                let op = minor_op(g, &history);
                history.push(op);
                consent_claim(&history, &ignores_guardian_verification)?;
            }
            Ok(())
        },
    );
    if let Err(e) = expect_prop_failure(&outcome, "I-18") {
        panic!("{e}");
    }
}

/// I-18, design sections 6.6 and 6.9, "Minor applicant": a machine over
/// `fstp_vault_core` with facts seeded through `vault_seed`. Consents are
/// recorded, withdrawn, or recorded by an unverified guardian. The NOTE 14
/// gate admits P only on a vault yes, and every yes the production vault
/// gives agrees with the reference.
///
/// Gap: the machine over `CellEngine` with PostgreSQL waits for lane W3a,
/// which has no `CellEngine` yet. This test drives the pure vault core.
#[test]
fn i18_minor_flag_blocks_negotiation_without_verified_consent() {
    fstp_prop::check(
        "i18_minor_flag_blocks_negotiation_without_verified_consent",
        |g: &mut Gen| {
            let mut state = fstp_vault_core::VaultState::default();
            let mut log = SeedLog::default();
            let mut history: Vec<VOp> = Vec::new();
            for _ in 0..g.usize_in(1..=10) {
                let op = minor_op(g, &history);
                match &op {
                    VOp::Write(w) => {
                        let source = match w {
                            RefWrite::VerificationRecorded { .. } => {
                                SeedSource::SyntheticVerification
                            }
                            _ => SeedSource::SyntheticConsent,
                        };
                        seed_fact(&mut state, &mut log, source, rv::wire::fact_write(w), NOW)
                            .map_err(|e| format!("seed: {e}"))?;
                    }
                    VOp::Ack { epoch, seq } => {
                        if let Err(fstp_vault_core::CoreError::NotImplemented(op)) =
                            fstp_vault_core::ack(&mut state, *epoch, *seq)
                        {
                            return Err(format!("{op} is NotImplemented"));
                        }
                    }
                }
                history.push(op);
                let wq: Vec<_> = gate_queries().iter().map(rv::wire::query).collect();
                let admitted = match fstp_vault_core::ask(&state, &wq) {
                    Ok(a) => a.iter().any(|x| x.holds),
                    Err(fstp_vault_core::CoreError::NotImplemented(op)) => {
                        return Err(format!("{op} is NotImplemented"));
                    }
                    Err(fstp_vault_core::CoreError::Refused(_)) => false,
                };
                let reference = reference_vault(&history);
                let lawful = reference.facts().consent_counts(P)
                    || reference.facts().adult_at(LEAD, CALL_DEADLINE);
                prop_assert!(
                    !admitted || lawful,
                    "I-18: the gate admitted minor-flagged P without an effective verified consent after {history:?}"
                );
            }
            prop_assert_eq!(
                log.writes.len(),
                history
                    .iter()
                    .filter(|o| matches!(o, VOp::Write(_)))
                    .count()
            );
            Ok(())
        },
    );
}

// ---------------------------------------------------------------------------
// The cell: the guardian ticket order of design section 6.6 step 3.

/// The production cell with PR1 in IRC_REVIEW, minor-flagged, with
/// `validations` of its two IRC validations recorded.
fn minor_cell(validations: usize) -> Result<ProdCell, String> {
    let path = paths::to(StateTag::Negotiation)?;
    let keep = path.len() - 2 + validations;
    let mut cell = ProdCell::genesis(paths::truth(false)).map_err(|e| e.to_string())?;
    for p in &path[..keep] {
        cell.exec_step(&p.step, p.at).map_err(|e| e.to_string())?;
    }
    Ok(cell)
}

/// The guardian consent write ticket command.
///
/// Gap: `ReleaseCommand::IssueWriteTicket` carries only the kind. Design
/// section 6.5 says a ticket names the account and the proposal, so W2c
/// must add them. Until then the test names PR1 only through the cell
/// state, which holds one proposal.
fn guardian_ticket() -> CellCommand {
    CellCommand::Release(ReleaseCommand::IssueWriteTicket {
        kind: WriteKind::GuardianConsent.code(),
    })
}

/// The accounts that ask for the guardian consent ticket: PR1's guardian,
/// added by `AddGuardian` on every path, its lead, and an account with no
/// binding on PR1.
const TICKET_ACTORS: [AccountId; 3] = [paths::GUARDIAN, L1, STRANGER];

/// What one guardian ticket command did, for [`ticket_property`].
#[derive(Clone, Debug)]
struct TicketRun {
    /// `fstp_domain::decision::awaiting_guardian_consent` for PR1.
    awaiting: bool,
    /// The attestation answer, if the cell asked.
    asked_adult: Option<bool>,
    /// The `SameIdentityAsAny` answer for the actor and the lead, if the
    /// cell asked.
    same_identity_as_lead: Option<bool>,
    /// Whether a ticket was issued.
    issued: bool,
    /// The cell trace.
    trace: Vec<CellEvent>,
}

/// One guardian ticket command: `validations` IRC validations recorded,
/// `actor` asking, and the vault answering `adult` to the attestation.
type TicketCell = dyn Fn(usize, AccountId, bool) -> Result<TicketRun, String>;

/// The production cell's run of the guardian ticket command.
fn production_ticket(
    validations: usize,
    actor: AccountId,
    adult: bool,
) -> Result<TicketRun, String> {
    let cell = minor_cell(validations).map_err(|e| format!("{e} (NotImplemented)"))?;
    let awaiting =
        fstp_domain::decision::awaiting_guardian_consent(&cell.state().engine().core, PR1);
    let x = CellCtx {
        actor,
        at: paths::to(StateTag::Negotiation)?
            .last()
            .unwrap()
            .at
            .micros(),
    };
    let cmd = guardian_ticket();
    let mut run = TicketRun {
        awaiting,
        asked_adult: None,
        same_identity_as_lead: None,
        issued: false,
        trace: Vec::new(),
    };
    let queries = match fstp_cell_core::queries(cell.state(), &cmd, &x) {
        Ok(q) => q,
        Err(CellRefusal::NotImplemented(op)) => {
            return Err(format!("{op} is NotImplemented"));
        }
        Err(CellRefusal::Domain(_)) => {
            run.trace.push(CellEvent::CommandEnd);
            return Ok(run);
        }
    };
    let mut answers = Answers::new();
    for q in &queries {
        let holds = match q {
            Query::IsVerifiedAdultAtDeadline { .. } => {
                run.asked_adult = Some(adult);
                adult
            }
            _ => paths::truth(false).answer(q).holds,
        };
        if let Query::SameIdentityAsAny { subject, others } = q
            && *subject == actor
            && others.contains(&L1)
        {
            run.same_identity_as_lead = Some(holds);
        }
        run.trace.push(CellEvent::Asked {
            query: q.clone(),
            holds,
        });
        answers.insert(
            q.clone(),
            Answer {
                holds,
                accounts: None,
                epoch: paths::truth(false).epoch(),
                digest: PLACEHOLDER_DIGEST,
            },
        );
    }
    run.issued = match fstp_cell_core::decide(cell.state(), &cmd, &x, &answers) {
        Ok(batch) => batch
            .iter()
            .any(|r| matches!(r, CellRecord::Release(ReleaseRecord::TicketIssued { .. }))),
        Err(CellRefusal::NotImplemented(op)) => {
            return Err(format!("{op} is NotImplemented"));
        }
        Err(CellRefusal::Domain(_)) => false,
    };
    if run.issued {
        run.trace.push(CellEvent::WriteTicketIssued {
            kind: WriteKind::GuardianConsent,
            proposal: PR1,
            lead: L1,
            deadline: CALL_DEADLINE,
        });
    }
    run.trace.push(CellEvent::CommandEnd);
    Ok(run)
}

/// The guardian ticket property over `cell`: the order of
/// `guardian_ticket_order`, and a ticket exactly when
/// `guardian_ticket_allowed` admits it for the asking account.
fn ticket_property(g: &mut Gen, cell: &TicketCell) -> Result<(), String> {
    let validations = g.usize_in(1..=2);
    let adult = g.bool();
    let actor = *g.pick(&TICKET_ACTORS);
    let run = cell(validations, actor, adult)?;
    guardian_ticket_order(&run.trace)?;
    let recipient = GuardianRecipient {
        guardian_binding: actor == paths::GUARDIAN,
        is_lead: actor == L1,
        same_identity_as_lead: run.same_identity_as_lead,
    };
    prop_assert_eq!(
        run.issued,
        guardian_ticket_allowed(run.awaiting, run.asked_adult, recipient),
        "I-18: validations {validations}, actor {actor:?}, adult {adult}, run {run:?}"
    );
    Ok(())
}

/// I-18, design section 6.6 step 3, ADR-009 "Write kinds" and the seam
/// row "The minor-flag gate of NOTE 14": the cell asks
/// `IsVerifiedAdultAtDeadline` for the lead at the call deadline before it
/// issues the guardian's write ticket. It issues the ticket only when
/// consent collection is open, the vault answered no, and the asking
/// account is PR1's guardian, added by `AddGuardian`, not its lead.
/// Checked as a cell trace against `reference::vault::guardian_ticket_order`
/// and `guardian_ticket_allowed`.
///
/// Gap: `ReleaseCommand::IssueWriteTicket` names no recipient, so the
/// recipient is the actor.
#[test]
fn i18_cell_asks_adult_attestation_before_guardian_ticket() {
    fstp_prop::check(
        "i18_cell_asks_adult_attestation_before_guardian_ticket",
        |g: &mut Gen| ticket_property(g, &production_ticket),
    );
}

/// I-18 teeth: a cell that gives the consent ticket to any asking account,
/// the lead included, once the vault said the lead is not an adult, fails
/// the guardian ticket property.
#[test]
fn i18_teeth_guardian_ticket_to_a_non_guardian_is_caught() {
    let mutant =
        |_validations: usize, _actor: AccountId, adult: bool| -> Result<TicketRun, String> {
            let mut trace = vec![CellEvent::Asked {
                query: Query::IsVerifiedAdultAtDeadline {
                    account: L1,
                    deadline: CALL_DEADLINE,
                },
                holds: adult,
            }];
            if !adult {
                trace.push(CellEvent::WriteTicketIssued {
                    kind: WriteKind::GuardianConsent,
                    proposal: PR1,
                    lead: L1,
                    deadline: CALL_DEADLINE,
                });
            }
            trace.push(CellEvent::CommandEnd);
            Ok(TicketRun {
                awaiting: true,
                asked_adult: Some(adult),
                same_identity_as_lead: None,
                issued: !adult,
                trace,
            })
        };
    let outcome = fstp_prop::run(
        "i18_teeth_guardian_ticket_to_a_non_guardian_is_caught",
        fstp_prop::Config::default(),
        |g: &mut Gen| ticket_property(g, &mutant),
    );
    if let Err(e) = expect_prop_failure(&outcome, "I-18") {
        panic!("{e}");
    }
}

/// I-18, ADR-009 "Write kinds": the reference gives the consent ticket to
/// PR1's guardian only. It refuses the lead, an unbound account, and a
/// guardian the vault ties to the lead's identity.
#[test]
fn i18_reference_guardian_ticket_goes_to_the_guardian_only() {
    let guardian = GuardianRecipient {
        guardian_binding: true,
        is_lead: false,
        same_identity_as_lead: None,
    };
    assert!(guardian_ticket_allowed(true, Some(false), guardian));
    for (why, r) in [
        (
            "the lead",
            GuardianRecipient {
                guardian_binding: false,
                is_lead: true,
                same_identity_as_lead: None,
            },
        ),
        (
            "an unbound account",
            GuardianRecipient {
                guardian_binding: false,
                ..guardian
            },
        ),
        (
            "a guardian with the lead's identity",
            GuardianRecipient {
                same_identity_as_lead: Some(true),
                ..guardian
            },
        ),
    ] {
        assert!(
            !guardian_ticket_allowed(true, Some(false), r),
            "I-18: the reference gave {why} the consent ticket"
        );
    }
    assert!(!guardian_ticket_allowed(true, None, guardian));
    assert!(!guardian_ticket_allowed(true, Some(true), guardian));
    assert!(!guardian_ticket_allowed(false, Some(false), guardian));
}

/// I-18: the reference order check catches a trace that issues the
/// guardian ticket without the attestation query.
#[test]
fn i18_teeth_guardian_ticket_without_adult_query_is_caught() {
    let trace = [
        CellEvent::Asked {
            query: Query::HasGuardianConsent { proposal: PR1 },
            holds: false,
        },
        CellEvent::WriteTicketIssued {
            kind: WriteKind::GuardianConsent,
            proposal: PR1,
            lead: L1,
            deadline: CALL_DEADLINE,
        },
        CellEvent::CommandEnd,
    ];
    let e = guardian_ticket_order(&trace).expect_err("the order check must refuse");
    assert!(e.starts_with("I-18:"), "{e}");
}

/// I-18, R-NG-01: the reference order check catches a vault outcome
/// record shown to a Judging actor.
#[test]
fn i18_teeth_vault_outcome_shown_to_judging_is_caught() {
    let trace = [CellEvent::Shown {
        judging: true,
        vault_outcomes: 2,
    }];
    let e = guardian_ticket_order(&trace).expect_err("the order check must refuse");
    assert!(e.starts_with("I-18:"), "{e}");
}

/// What the production cell serves the IRC member who recorded the last
/// validation of PR1, as the cell records that member reads.
///
/// Gap: no production read path exists yet. `fstp_cell_core` has no read
/// action, and the `fstp-cell` routes are W0 stubs. Lane W3a closes this
/// gap with the cell routes and their projections (design sections 5.4
/// and 5.5). It then replaces this body with a read through the route the
/// IRC actor is served, and the test below runs unchanged.
fn served_to_irc_actor(_cell: &ProdCell, _actor: AccountId) -> Result<Vec<CellRecord>, String> {
    Err(
        "the IRC actor's read path (fstp-cell routes and projections, lane W3a) is not built (NotImplemented)"
            .to_owned(),
    )
}

/// The `VaultOutcome` records among `records`.
fn vault_outcomes(records: &[CellRecord]) -> usize {
    records
        .iter()
        .filter(|r| {
            matches!(
                r,
                CellRecord::Engine(fstp_engine::Record::Core(
                    fstp_domain::Record::VaultOutcome { .. }
                ))
            )
        })
        .count()
}

/// I-18, R-NG-01, overview NOTE 7 and the seam row "The minor-flag gate
/// of NOTE 14": the production cell runs the last IRC validation of a
/// minor-flagged PR1. The M2 domain puts `VaultOutcome` records for the
/// attestation and the consent in that batch. The cell never shows them
/// to the IRC member, a Judging actor. Checked as a `Shown` event of the
/// cell trace against `reference::vault::guardian_ticket_order`.
///
/// Gap: red until lane W2c lands `fstp_cell_core` and lane W3a lands the
/// read path of [`served_to_irc_actor`].
#[test]
fn i18_r_ng_01_irc_actor_is_never_shown_the_vault_outcomes() {
    let path = paths::to(StateTag::Negotiation).unwrap();
    let last = path.last().unwrap();
    let Actor::Account(irc) = last.step.actor else {
        panic!("the last IRC validation is a system step: {:?}", last.step);
    };
    let mut cell = minor_cell(1).unwrap_or_else(|e| panic!("{e} (NotImplemented)"));
    let batch = cell
        .exec_step(&last.step, last.at)
        .unwrap_or_else(|e| panic!("the last IRC validation: {e} (NotImplemented)"));
    assert!(
        vault_outcomes(&batch) > 0,
        "I-18: the last IRC validation recorded no VaultOutcome, so the check below is empty: {batch:?}"
    );
    let served = served_to_irc_actor(&cell, irc).unwrap_or_else(|e| panic!("{e}"));
    let trace = [
        CellEvent::Shown {
            judging: true,
            vault_outcomes: vault_outcomes(&served),
        },
        CellEvent::CommandEnd,
    ];
    if let Err(e) = guardian_ticket_order(&trace) {
        panic!("{e}");
    }
}

/// I-18: the attestation queries the paths depend on. A lead attested
/// before the deadline reaches NEGOTIATION through the M2 domain, and a
/// minor-flagged one stays in IRC_REVIEW with both validations recorded.
#[test]
fn i18_paths_reach_negotiation_only_with_an_attestation() {
    let path = paths::to(StateTag::Negotiation).unwrap();
    assert_eq!(
        paths::check_with_domain(&path, paths::truth(true)).unwrap(),
        Some(StateTag::Negotiation)
    );
    assert_eq!(
        paths::check_with_domain(&path, paths::truth(false)).unwrap(),
        Some(StateTag::IrcReview)
    );
}

// ---------------------------------------------------------------------------
// The routes and the full cycle.

/// I-18, R-ID-04, NOTE 14: no route takes the minor flag from a request.
/// A command body with a `minor` member, in any position and of any JSON
/// type, is refused as malformed, not as a stub. The same body without
/// the member decodes, to the same command id, so the refusal is the
/// member's and not a refusal of an incomplete body.
///
/// Reading: Q13 A derives the flag from the vault, so the interim of
/// design section 6.6 step 1 (every draft built with `minor = true`) no
/// longer applies. The refusal of the member stays, so a client cannot
/// believe it set the flag.
///
/// Gap: `fstp_cell::http::CommandRequest` holds the command id and the
/// step-up id only, so the control body is `{command_id}`. Once lane W3a
/// puts the command (a `CreateDraft`) in the body and gives
/// `fstp_cell::CellError` a malformed refusal, this test builds a valid
/// `CreateDraft` body and matches that refusal.
#[test]
fn i18_route_never_takes_minor_flag_from_the_request() {
    fstp_prop::check(
        "i18_route_never_takes_minor_flag_from_the_request",
        |g: &mut Gen| {
            let value = *g.pick(&["true", "false", "0", "1", "null", "\"yes\"", "{}", "[]"]);
            let before = g.bool();
            let raw = g.bytes(16..=16);
            let id = hex16(&raw);
            let control = format!("{{\"command_id\":\"{id}\"}}");
            match fstp_cell::http::decode_command_request(control.as_bytes()) {
                Ok(r) => prop_assert_eq!(
                    r.command_id.as_slice(),
                    raw.as_slice(),
                    "the control body {control} decoded to another command id"
                ),
                Err(fstp_cell::CellError::NotImplemented(op)) => {
                    return Err(format!("{op} is NotImplemented"));
                }
                #[allow(unreachable_patterns, reason = "fstp-cell gains variants in lane W3a")]
                Err(e) => return Err(format!("the control body {control} was refused: {e}")),
            }
            let body = if before {
                format!("{{\"minor\":{value},\"command_id\":\"{id}\"}}")
            } else {
                format!("{{\"command_id\":\"{id}\",\"minor\":{value}}}")
            };
            match fstp_cell::http::decode_command_request(body.as_bytes()) {
                Ok(r) => Err(format!(
                    "I-18: a body with a minor member decoded: {r:?} from {body}"
                )),
                Err(fstp_cell::CellError::NotImplemented(op)) => {
                    Err(format!("{op} is NotImplemented"))
                }
                #[allow(unreachable_patterns, reason = "fstp-cell gains variants in lane W3a")]
                Err(_) => Ok(()),
            }
        },
    );
}

fn hex16(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn one_cell_world() -> World {
    World::start(WorldSpec {
        cells: 1,
        mode: DbMode::Shared,
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted: false,
        process_mode: false,
    })
    .unwrap_or_else(|e| panic!("the one-cell world did not start: {e}"))
}

/// I-18, `test-plan.md`: no minor-flagged proposal reaches GRANTED
/// without consent, over random full cycles through HTTP. Guardian
/// consents are seeded through the section 6.9 seeder (`fstp-vault-seeded`).
///
/// The cycle with a verified consent completes. The cycle with an
/// unverified guardian's consent must not: a completed report would mean
/// the minor-flagged proposal reached GRANTED.
///
/// Gap: `CellHandle` has no HTTP client, `CycleScript` names steps by text
/// only, and `CycleReport` cannot tell a guard refusal from a missing part
/// (lanes W1a and W3a). The step names follow
/// `SPEC/07-test-plan/synthetic-corpus.md`, variant "Minor applicant".
#[test]
fn i18_no_minor_flagged_proposal_reaches_granted_without_consent() {
    let world = one_cell_world();
    for consent in [true, false] {
        let script = fstp_celltest::world::CycleScript {
            steps: vec![
                "minor-applicant:draft".to_owned(),
                "minor-applicant:submit".to_owned(),
                "minor-applicant:evaluate".to_owned(),
                "minor-applicant:irc-validate".to_owned(),
                if consent {
                    "minor-applicant:seed-verified-guardian-consent".to_owned()
                } else {
                    "minor-applicant:seed-unverified-guardian-consent".to_owned()
                },
                "minor-applicant:negotiate-and-grant".to_owned(),
            ],
        };
        let report = world.run_cycle(0, &script);
        match (consent, report.result) {
            (true, Ok(())) | (false, Err(_)) => {}
            (true, Err(e)) => panic!("the cycle with a verified consent did not run: {e}"),
            (false, Ok(())) => {
                panic!("I-18: a minor-flagged proposal reached GRANTED without a verified consent")
            }
        }
    }
}
