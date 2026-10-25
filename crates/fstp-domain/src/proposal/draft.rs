//! Draft creation and the people of a proposal: `CreateDraft`, `AddTeamMember` and `AddGuardian`.
//!
//! Written by lane L-SOD in step W3b. Lane L-LIFE extends the proposal
//! lifecycle around it.
//!
//! - `CreateDraft` needs a published call that is open now. It records
//!   `ProposalCreated` with the lead and the supplied minor flag (R-ID-04
//!   seam). Lane L-SOD's contribution adds the lead's Applicant binding.
//! - `AddTeamMember` and `AddGuardian` need the lead as actor, with an
//!   active Applicant binding on the proposal (enforcement point 2). An
//!   account is bound at most once per proposal, voided bindings included.
//!   A guardian is added only to a proposal flagged as a minor's. These
//!   commands record nothing themselves. Lane L-SOD's contribution adds the
//!   Receiving binding, after SoD-01, SoD-03, SoD-05, SoD-06 and I-06.
//! - [`Drafts`] keeps the created proposals: their call, lead and minor flag.

use std::collections::BTreeMap;

use crate::command::{Command, Ctx};
use crate::engine::{FoldError, PolicyScope};
use crate::id::{AccountId, CallId, ProposalId};
use crate::oracle::{Answers, Query};
use crate::record::Record;
use crate::refusal::{Refusal, RefusalReason, RuleRef};
use crate::roles::Role;
use crate::state::{State, UsedId};

/// One created proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Draft {
    /// Its call.
    pub(crate) call: CallId,
    /// Its lead.
    pub(crate) lead: AccountId,
    /// Whether the lead is flagged as a minor.
    pub(crate) minor: bool,
}

/// The created proposals.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Drafts {
    proposals: BTreeMap<ProposalId, Draft>,
}

impl Drafts {
    /// No proposal yet.
    pub(crate) const fn genesis() -> Drafts {
        Drafts {
            proposals: BTreeMap::new(),
        }
    }
}

/// The created proposal `proposal`.
pub(crate) fn draft(state: &State, proposal: ProposalId) -> Option<&Draft> {
    state.proposals.drafts.proposals.get(&proposal)
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
            if matches!(cmd, Command::AddGuardian { .. }) && !d.minor {
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
