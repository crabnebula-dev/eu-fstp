//! Draft creation and the people of a proposal: `CreateDraft`, `AddTeamMember` and `AddGuardian`.
//!
//! Written by lane L-SOD in step W3b. Lane L-LIFE extends the proposal
//! lifecycle around it.
//!
//! - `CreateDraft` needs a published call that is open now. It records
//!   `ProposalCreated` with the lead and the actor's `minor` field. No
//!   guard reads that field (R-ID-04). Lane L-SOD's contribution adds the
//!   lead's Applicant binding.
//! - `AddTeamMember` and `AddGuardian` need the lead as actor, with an
//!   active Applicant binding on the proposal (enforcement point 2). An
//!   account is bound at most once per proposal, voided bindings included.
//!   A guardian is added only to a minor-flagged proposal. These
//!   commands record nothing themselves. Lane L-SOD's contribution adds the
//!   Receiving binding, after SoD-01, SoD-03, SoD-05, SoD-06 and I-06.
//! - [`Drafts`] keeps the created proposals: their call, lead, the
//!   actor's `minor` field and the minor flag derived at the NEGOTIATION gate.
//! - The minor flag never comes from the actor (R-ID-04, state-machine
//!   NOTE 14). Every proposal is minor-flagged until the IRC_REVIEW to
//!   NEGOTIATION gate derives the flag from the vault. The gate records
//!   the `IsVerifiedAdultAtDeadline` outcome in its batch, right before
//!   the transition. The fold keeps that bit and gives it to the
//!   transition, so a replay derives the same flag from the ledger alone.
//!   Whether the flag is derived again before GRANTED is not decided
//!   (ADR-008, "Second derivation", interim), so the flag holds from the
//!   gate on.
//! - The `AddGuardian` guard reads the derived flag, never the actor's
//!   field. Before the gate every proposal is minor-flagged, so any lead
//!   can bind the guardian whose consent the gate may need (R-NG-01, design
//!   6.6 step 3). After a gate that found the attestation it is refused.

use std::collections::BTreeMap;

use crate::command::{Command, Ctx};
use crate::engine::{FoldError, PolicyScope};
use crate::id::{AccountId, CallId, ProposalId};
use crate::oracle::{Answers, Query, QueryKind};
use crate::record::{Record, Transitioned};
use crate::refusal::{Refusal, RefusalReason, RuleRef};
use crate::roles::Role;
use crate::rules::Row;
use crate::state::{State, UsedId};

/// One created proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Draft {
    /// Its call.
    pub(crate) call: CallId,
    /// Its lead.
    pub(crate) lead: AccountId,
    /// The `minor` field the actor sent with `CreateDraft`. No guard reads
    /// it. The minor flag is [`minor_flagged`].
    pub(crate) minor: bool,
    /// Whether the last IRC_REVIEW to NEGOTIATION gate found an effective
    /// verified over-18 attestation of the lead at the deadline (R-ID-04,
    /// state-machine NOTE 14). `false` until a gate derives it.
    pub(crate) adult_at_gate: bool,
}

/// The created proposals.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Drafts {
    proposals: BTreeMap<ProposalId, Draft>,
    /// The answer bit of the last `IsVerifiedAdultAtDeadline` outcome
    /// folded, until the next transition takes it.
    pending_adult: Option<bool>,
}

impl Drafts {
    /// No proposal yet.
    pub(crate) const fn genesis() -> Drafts {
        Drafts {
            proposals: BTreeMap::new(),
            pending_adult: None,
        }
    }

    /// The created proposal `proposal`. Lane L-LIFE reads it through the
    /// quorum's view of the store (`crate::scoring::ScoreFacts`).
    pub(crate) fn get(&self, proposal: ProposalId) -> Option<&Draft> {
        self.proposals.get(&proposal)
    }
}

/// The created proposal `proposal`.
pub(crate) fn draft(state: &State, proposal: ProposalId) -> Option<&Draft> {
    state.proposals.drafts.proposals.get(&proposal)
}

/// Whether `proposal` is minor-flagged (R-ID-04, state-machine NOTE 14).
///
/// The flag is derived at the IRC_REVIEW to NEGOTIATION gate from the
/// vault, and never from the actor. Before the gate, and for an unknown
/// proposal, it is set, so every reader fails closed.
pub(crate) fn minor_flagged(state: &State, proposal: ProposalId) -> bool {
    !draft(state, proposal).is_some_and(|d| d.adult_at_gate)
}

/// Keeps the bit of an `IsVerifiedAdultAtDeadline` outcome for the
/// transition that follows it in the gate's batch. Other records are
/// ignored.
pub(crate) fn on_vault_outcome(state: &mut State, record: &Record) {
    if let Record::VaultOutcome {
        kind: QueryKind::IsVerifiedAdultAtDeadline,
        holds,
        ..
    } = record
    {
        state.proposals.drafts.pending_adult = Some(*holds);
    }
}

/// Derives the minor flag at the IRC_REVIEW to NEGOTIATION transition from
/// the kept outcome bit (state-machine NOTE 14). With no kept bit the flag
/// is set. Every transition drops the kept bit, so it never reaches a later
/// gate.
pub(crate) fn on_transition(state: &mut State, t: &Transitioned) {
    let adult = state.proposals.drafts.pending_adult.take();
    if t.row == Row::IrcReviewToNegotiation
        && let Some(d) = state.proposals.drafts.proposals.get_mut(&t.proposal)
    {
        d.adult_at_gate = adult == Some(true);
    }
}

/// The call of the created proposal `proposal`.
pub(crate) fn proposal_call(state: &State, proposal: ProposalId) -> Option<CallId> {
    draft(state, proposal).map(|d| d.call)
}

/// The refusal of an unknown entity.
const fn unknown() -> Refusal {
    Refusal::new(RuleRef::Input, RefusalReason::UnknownEntity)
}

/// The refusal of a shell-supplied id that is already taken.
const fn reused() -> Refusal {
    Refusal::new(RuleRef::Ledger, RefusalReason::IdReused)
}

/// Checks one of the three commands and returns the records it owns.
fn check(state: &State, cmd: &Command, ctx: &Ctx) -> Result<Vec<Record>, Refusal> {
    let actor = crate::policy::actor_account(ctx)?;
    match cmd {
        Command::CreateDraft {
            proposal,
            call,
            binding,
            minor,
        } => {
            if state.used_ids.contains(UsedId::Proposal(*proposal))
                || draft(state, *proposal).is_some()
                || state.used_ids.contains(UsedId::Binding(*binding))
            {
                return Err(reused());
            }
            if crate::programme::call(state, *call).is_none() {
                return Err(unknown());
            }
            if !crate::programme::is_open_at(state, *call, ctx.now) {
                return Err(Refusal::new(RuleRef::Input, RefusalReason::WrongState));
            }
            Ok(vec![Record::ProposalCreated {
                proposal: *proposal,
                call: *call,
                lead: actor,
                minor: *minor,
            }])
        }
        Command::AddTeamMember {
            proposal,
            account,
            binding,
        }
        | Command::AddGuardian {
            proposal,
            account,
            binding,
        } => {
            let d = draft(state, *proposal).ok_or_else(unknown)?;
            let lead_active = state
                .roster
                .active_receiving(actor, Role::Applicant, *proposal, ctx.now)
                .is_some();
            if d.lead != actor || !lead_active {
                return Err(Refusal::new(RuleRef::Actor, RefusalReason::BindingInactive));
            }
            if state.used_ids.contains(UsedId::Binding(*binding)) {
                return Err(reused());
            }
            if matches!(cmd, Command::AddGuardian { .. }) && !minor_flagged(state, *proposal) {
                return Err(Refusal::new(RuleRef::Input, RefusalReason::InvalidValue));
            }
            if state.roster.bound_to(*account, *proposal) {
                return Err(Refusal::new(RuleRef::Input, RefusalReason::InvalidValue));
            }
            Ok(Vec::new())
        }
        _ => Err(Refusal::new(RuleRef::Input, RefusalReason::WrongState)),
    }
}

/// The vault questions of the three commands. They ask none themselves.
/// The binding's questions are lane L-SOD's contribution.
pub(crate) fn queries(state: &State, cmd: &Command, ctx: &Ctx) -> Result<Vec<Query>, Refusal> {
    check(state, cmd, ctx)?;
    Ok(Vec::new())
}

/// The records of the three commands that this module owns.
pub(crate) fn decide(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
    answers: &Answers,
) -> Result<Vec<Record>, Refusal> {
    let _ = answers;
    check(state, cmd, ctx)
}

/// Folds `ProposalCreated`.
pub(crate) fn apply(state: &mut State, record: &Record) -> Result<(), FoldError> {
    let Record::ProposalCreated {
        proposal,
        call,
        lead,
        minor,
    } = record
    else {
        return Err(FoldError::Inconsistent);
    };
    if draft(state, *proposal).is_some() || state.used_ids.contains(UsedId::Proposal(*proposal)) {
        return Err(FoldError::DuplicateId);
    }
    if crate::programme::call(state, *call).is_none() {
        return Err(FoldError::UnknownEntity);
    }
    state.used_ids.insert(UsedId::Proposal(*proposal));
    state.proposals.drafts.proposals.insert(
        *proposal,
        Draft {
            call: *call,
            lead: *lead,
            minor: *minor,
            adult_at_gate: false,
        },
    );
    Ok(())
}

/// The policy whose P-77 governs `AddTeamMember` and `AddGuardian` through
/// MCP: the frozen policy of the proposal's call (R-MC-05). `CreateDraft`
/// prepares a draft and is not a binding action.
pub(crate) fn governing_policy(state: &State, cmd: &Command) -> Result<PolicyScope, Refusal> {
    match cmd {
        Command::AddTeamMember { proposal, .. } | Command::AddGuardian { proposal, .. } => {
            proposal_call(state, *proposal)
                .map(PolicyScope::Call)
                .ok_or_else(unknown)
        }
        Command::CreateDraft { call, .. } => Ok(PolicyScope::Call(*call)),
        _ => Err(Refusal::new(RuleRef::Input, RefusalReason::WrongState)),
    }
}
