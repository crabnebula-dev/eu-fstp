//! Calibration consent (R-LA-09, R-LA-10, I-37; M10 to M12 design
//! section 3.1, lane L12-I37).
//!
//! - `RequestCalibrationConsent`, by the programme manager. It is refused
//!   unless P-42 is on in the programme's live policy and the proposal's
//!   outcome notice record is committed. The request records that notice's
//!   sequence number, and the fold refuses a request whose number is not
//!   strictly below its own (the stricter reading of "outcome notice": the
//!   committed notice record counts, not an earlier state change).
//! - `GiveCalibrationConsent`, by the proposal's lead, after a request.
//! - `RevokeCalibrationConsent`, by the lead, on a standing consent. A
//!   revocation is final for the proposal: it is not requested or given
//!   again (interim reading, pending Daniel).
//! - [`admits`] and [`calibration_set`] are the membership check of a
//!   calibration run. Only a recorded, unrevoked consent admits a
//!   proposal, and each member carries its consent record's sequence
//!   number for the run's manifest.
//!
//! The lead is checked by account, not by an active Applicant binding,
//! because a terminal state may have ended the binding before the notice
//! (interim reading, pending Daniel).
//!
//! The outcome notice record is `OutboxEnqueued(ProposalOutcome)`. No core
//! command writes it yet. M6 dispatch adds it, and once M6 dispatches email
//! the request also waits for the dispatch record. Use beyond the tenant
//! (R-LA-11) is not built.
//!
//! TODO(legal): the consent wording and the legal basis for pseudonymised
//! use. Commands and records carry the wording only as a [`crate::id::TextRef`].

use std::collections::BTreeMap;

use fstp_ledger::Seq;

use crate::command::{Command, Ctx};
use crate::engine::{FoldError, PolicyScope};
use crate::id::{AccountId, CallId, ProgrammeId, ProposalId};
use crate::oracle::{Answers, Query};
use crate::record::{OutboxEvent, Record};
use crate::refusal::{Refusal, RefusalReason, RuleRef};
use crate::roles::Role;
use crate::rules::ParamId;
use crate::state::State;
use crate::time::Timestamp;

/// The consent facts of one proposal.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
struct Consent {
    /// The sequence number of the first outcome notice record.
    notice: Option<Seq>,
    /// The sequence number of the request.
    requested: Option<Seq>,
    /// The sequence number of the consent record.
    given: Option<Seq>,
    /// Whether the consent was revoked.
    revoked: bool,
}

/// The calibration consent part of the projection.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ConsentState {
    proposals: BTreeMap<ProposalId, Consent>,
}

impl ConsentState {
    /// No consent facts.
    pub(crate) fn genesis() -> ConsentState {
        ConsentState {
            proposals: BTreeMap::new(),
        }
    }

    fn get(&self, proposal: ProposalId) -> Consent {
        self.proposals.get(&proposal).copied().unwrap_or_default()
    }
}

/// The sequence number of the consent record that admits `proposal` to a
/// calibration run: a recorded consent with no revocation (I-37).
pub fn consent_of(state: &State, proposal: ProposalId) -> Option<Seq> {
    let c = state.calibration.get(proposal);
    if c.revoked { None } else { c.given }
}

/// Whether a calibration run may include `proposal` (I-37, R-LA-10).
pub fn admits(state: &State, proposal: ProposalId) -> bool {
    consent_of(state, proposal).is_some()
}

/// Every proposal a calibration run built now may include, each with the
/// sequence number of its consent record (I-37, R-LA-10).
pub fn calibration_set(state: &State) -> BTreeMap<ProposalId, Seq> {
    state
        .calibration
        .proposals
        .keys()
        .filter_map(|p| consent_of(state, *p).map(|s| (*p, s)))
        .collect()
}

/// The sequence number of `proposal`'s committed outcome notice record.
pub fn outcome_notice(state: &State, proposal: ProposalId) -> Option<Seq> {
    state.calibration.get(proposal).notice
}

const fn i37() -> Refusal {
    Refusal::new(RuleRef::I37, RefusalReason::WrongState)
}

const fn unknown() -> Refusal {
    Refusal::new(RuleRef::Input, RefusalReason::UnknownEntity)
}

const fn not_mine() -> Refusal {
    Refusal::new(RuleRef::Row, RefusalReason::WrongState)
}

/// The call that governs `proposal`.
fn call_of(state: &State, proposal: ProposalId) -> Result<CallId, Refusal> {
    crate::proposal::draft::proposal_call(state, proposal).ok_or_else(unknown)
}

/// The programme of `proposal`.
fn programme_of(state: &State, proposal: ProposalId) -> Result<ProgrammeId, Refusal> {
    let call = call_of(state, proposal)?;
    crate::programme::call(state, call)
        .map(|c| c.programme())
        .ok_or_else(unknown)
}

/// Whether the live P-42 of `programme` is on (`true`).
fn p42_on(state: &State, programme: ProgrammeId) -> bool {
    crate::policy::live_values(state, programme)
        .and_then(|v| v.opaque.get(&ParamId::P42))
        .is_some_and(|v| v.as_str() == "true")
}

/// Refuses unless the actor is the lead account of `proposal`.
fn require_lead(state: &State, proposal: ProposalId, ctx: &Ctx) -> Result<AccountId, Refusal> {
    let actor = crate::policy::actor_account(ctx)?;
    let d = crate::proposal::draft::draft(state, proposal).ok_or_else(unknown)?;
    if d.lead != actor {
        return Err(Refusal::new(RuleRef::Actor, RefusalReason::BindingInactive));
    }
    Ok(actor)
}

/// The proposal a calibration command acts on.
fn proposal_of(cmd: &Command) -> Option<ProposalId> {
    match cmd {
        Command::RequestCalibrationConsent { proposal }
        | Command::GiveCalibrationConsent { proposal, .. }
        | Command::RevokeCalibrationConsent { proposal } => Some(*proposal),
        _ => None,
    }
}

/// A consent command asks the vault nothing.
pub(crate) fn queries(_state: &State, _cmd: &Command, _ctx: &Ctx) -> Result<Vec<Query>, Refusal> {
    Ok(Vec::new())
}

/// Decides a consent command.
pub(crate) fn decide(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
    _answers: &Answers,
) -> Result<Vec<Record>, Refusal> {
    match cmd {
        Command::RequestCalibrationConsent { proposal } => {
            let by = crate::policy::actor_account(ctx)?;
            let programme = programme_of(state, *proposal)?;
            crate::policy::require_holder(
                state,
                by,
                programme,
                &[Role::ProgrammeManager],
                ctx.now,
            )?;
            if !p42_on(state, programme) {
                return Err(Refusal::new(
                    RuleRef::Param(ParamId::P42),
                    RefusalReason::GuardFailed,
                ));
            }
            let c = state.calibration.get(*proposal);
            let notice = c.notice.ok_or_else(i37)?;
            if c.requested.is_some() || c.revoked {
                return Err(i37());
            }
            Ok(vec![Record::CalibrationConsentRequested {
                proposal: *proposal,
                notice,
                by,
            }])
        }
        Command::GiveCalibrationConsent { proposal, wording } => {
            let by = require_lead(state, *proposal, ctx)?;
            let c = state.calibration.get(*proposal);
            if c.requested.is_none() || c.given.is_some() || c.revoked {
                return Err(i37());
            }
            Ok(vec![Record::CalibrationConsentGiven {
                proposal: *proposal,
                wording: *wording,
                by,
            }])
        }
        Command::RevokeCalibrationConsent { proposal } => {
            let by = require_lead(state, *proposal, ctx)?;
            let c = state.calibration.get(*proposal);
            if c.given.is_none() || c.revoked {
                return Err(i37());
            }
            Ok(vec![Record::CalibrationConsentRevoked {
                proposal: *proposal,
                by,
            }])
        }
        _ => Err(not_mine()),
    }
}

/// Folds a consent record at `seq`. It refuses a request that does not
/// name the proposal's committed notice at a strictly lower sequence
/// number, a consent without a request and a revocation without a consent.
pub(crate) fn apply(
    state: &mut State,
    seq: Seq,
    _at: Timestamp,
    record: &Record,
) -> Result<(), FoldError> {
    let proposal = match record {
        Record::CalibrationConsentRequested { proposal, .. }
        | Record::CalibrationConsentGiven { proposal, .. }
        | Record::CalibrationConsentRevoked { proposal, .. } => *proposal,
        _ => return Err(FoldError::Inconsistent),
    };
    if crate::proposal::draft::draft(state, proposal).is_none() {
        return Err(FoldError::UnknownEntity);
    }
    let mut c = state.calibration.get(proposal);
    match record {
        Record::CalibrationConsentRequested { notice, .. } => {
            if c.notice != Some(*notice) || *notice >= seq || c.requested.is_some() || c.revoked {
                return Err(FoldError::Inconsistent);
            }
            c.requested = Some(seq);
        }
        Record::CalibrationConsentGiven { .. } => {
            if c.requested.is_none() || c.given.is_some() || c.revoked {
                return Err(FoldError::Inconsistent);
            }
            c.given = Some(seq);
        }
        _ => {
            if c.given.is_none() || c.revoked {
                return Err(FoldError::Inconsistent);
            }
            c.revoked = true;
        }
    }
    state.calibration.proposals.insert(proposal, c);
    Ok(())
}

/// Notes the first outcome notice record of a proposal at `seq`. Every
/// other record leaves the consent part unchanged.
pub(crate) fn on_outbox(state: &mut State, seq: Seq, record: &Record) {
    if let Record::OutboxEnqueued(OutboxEvent::ProposalOutcome { proposal, .. }) = record {
        let c = state.calibration.proposals.entry(*proposal).or_default();
        if c.notice.is_none() {
            c.notice = Some(seq);
        }
    }
}

/// The calibration lane contributes no vault question to other lanes' commands.
pub(crate) fn contribute_queries(
    _state: &State,
    _cmd: &Command,
    _ctx: &Ctx,
) -> Result<Vec<Query>, Refusal> {
    Ok(Vec::new())
}

/// The calibration lane adds no record to other lanes' batches.
pub(crate) fn contribute(
    _state: &State,
    _cmd: &Command,
    _ctx: &Ctx,
    _answers: &Answers,
    _batch: &[Record],
) -> Result<Vec<Record>, Refusal> {
    Ok(Vec::new())
}

/// The frozen policy of the proposal's call governs a consent command
/// through MCP (R-MC-05).
pub(crate) fn governing_policy(state: &State, cmd: &Command) -> Result<PolicyScope, Refusal> {
    let proposal = proposal_of(cmd).ok_or_else(not_mine)?;
    Ok(PolicyScope::Call(call_of(state, proposal)?))
}
