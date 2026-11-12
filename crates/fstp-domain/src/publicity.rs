//! Grantee choices for the public pages (R-PB-02, R-PB-03, I-41, I-42,
//! I-43; M9 design sections 2.1 and 2.2, lane P1).
//!
//! - `SetPublicChoice`, by the grantee lead. It records a
//!   `PublicChoiceSet` for one phase: the level, the approved title,
//!   public summary and grantee name, and for the finished phase the
//!   accepted deliverables the grantee includes.
//! - `WithdrawPublicChoice`, by the lead. It records a
//!   `PublicChoiceWithdrawn`, after which the phase has no choice and the
//!   grant is hidden in that phase (I-43).
//!
//! Guards, in this order:
//!
//! - The actor is the proposal's lead, through an active Applicant
//!   binding, or through the Applicant binding that a terminal state
//!   ended normally. COMPLETED ends the Receiving bindings, and the
//!   finished choice is made there (interim, pending Daniel).
//! - I-41: a funded choice needs GRANTED, IN_EXECUTION or COMPLETED. A
//!   finished choice needs COMPLETED. A withdrawal needs a current choice
//!   of that phase, so no choice op succeeds on a proposal that never
//!   reached GRANTED.
//! - I-42, decision D4: a minor-flagged proposal takes only `Hidden`.
//!   The flag fails closed, as the public filter reads it.
//! - Deliverables go with the finished phase only. Each must be an
//!   accepted deliverable of this grant.
//!
//! A level above the programme maximum (P-50 or P-51) is stored as
//! chosen. The public filter applies the lower of the two at read time,
//! so a lower maximum narrows the pages at once (I-43).
//!
//! The texts are `TextRef`s only. The API core stores each one as a
//! public text owned by the proposal when the op arrives, and accepts no
//! client text reference, so a choice never names proposal content
//! (R-PB-03). This crate holds no text class and cannot check it.

use std::collections::{BTreeMap, BTreeSet};

use fstp_ledger::Seq;

use crate::command::{Command, Ctx};
use crate::engine::{FoldError, PolicyScope};
use crate::id::{AccountId, CallId, DeliverableId, ProposalId, TextRef};
use crate::oracle::{Answers, Query};
use crate::record::Record;
use crate::refusal::{Refusal, RefusalReason, RuleRef};
use crate::roles::{BindingStatus, Role};
use crate::rules::StateTag;
use crate::state::State;
use crate::time::Timestamp;

/// The phase of a grant that a choice governs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PublicPhase {
    /// GRANTED and IN_EXECUTION, under P-50.
    Funded,
    /// COMPLETED, under P-51.
    Finished,
}

impl PublicPhase {
    /// Both phases.
    pub const ALL: [PublicPhase; 2] = [PublicPhase::Funded, PublicPhase::Finished];
}

/// A visibility level (`public-transparency.md`). The order is the order
/// of the levels table, so `min` gives the lower level.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PublicLevel {
    /// Nothing about the grant.
    Hidden,
    /// Project title, public summary, call and status.
    Project,
    /// Adds the grantee name.
    ProjectAndGrantee,
    /// Adds the granted amount.
    Full,
}

impl PublicLevel {
    /// Every level, lowest first.
    pub const ALL: [PublicLevel; 4] = [
        PublicLevel::Hidden,
        PublicLevel::Project,
        PublicLevel::ProjectAndGrantee,
        PublicLevel::Full,
    ];
}

/// The current choice of one phase of one grant.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PublicChoice {
    /// The chosen level.
    pub level: PublicLevel,
    /// The approved project title, a public text.
    pub title: TextRef,
    /// The approved public summary, a public text.
    pub summary: TextRef,
    /// The approved grantee name, a public text.
    pub grantee: TextRef,
    /// The accepted deliverables the grantee includes, finished phase only.
    pub deliverables: BTreeSet<DeliverableId>,
    /// The sequence number of the `PublicChoiceSet` record.
    pub seq: Seq,
}

/// The publicity part of the projection: the current choice per grant
/// and phase.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PublicityState {
    choices: BTreeMap<(ProposalId, PublicPhase), PublicChoice>,
}

impl PublicityState {
    /// No choice.
    pub(crate) fn genesis() -> PublicityState {
        PublicityState {
            choices: BTreeMap::new(),
        }
    }

    /// The current choice of `proposal` for `phase`.
    pub fn choice(&self, proposal: ProposalId, phase: PublicPhase) -> Option<&PublicChoice> {
        self.choices.get(&(proposal, phase))
    }

    /// Every current choice, in proposal and phase order.
    pub fn iter(&self) -> impl Iterator<Item = (ProposalId, PublicPhase, &PublicChoice)> {
        self.choices.iter().map(|((p, ph), c)| (*p, *ph, c))
    }
}

/// The states in which a choice of `phase` may be set (I-41).
pub const fn settable_in(phase: PublicPhase) -> &'static [StateTag] {
    match phase {
        PublicPhase::Funded => &[
            StateTag::Granted,
            StateTag::InExecution,
            StateTag::Completed,
        ],
        PublicPhase::Finished => &[StateTag::Completed],
    }
}

/// The programme of `proposal`, whose P-50 and P-51 cap its choices.
pub fn programme_of(state: &State, proposal: ProposalId) -> Option<crate::id::ProgrammeId> {
    let call = crate::proposal::draft::proposal_call(state, proposal)?;
    crate::programme::call(state, call).map(|c| c.programme())
}

/// Whether `account` may make the choices of `proposal`: its lead, with
/// an active Applicant binding, or with the Applicant binding that a
/// terminal state ended normally (module documentation).
pub fn is_choice_maker(
    state: &State,
    account: AccountId,
    proposal: ProposalId,
    now: Timestamp,
) -> bool {
    let Some(d) = crate::proposal::draft::draft(state, proposal) else {
        return false;
    };
    if d.lead != account {
        return false;
    }
    if state
        .roster
        .active_receiving(account, Role::Applicant, proposal, now)
        .is_some()
    {
        return true;
    }
    let terminal = crate::view::proposal_state(state, proposal).is_some_and(StateTag::is_terminal);
    terminal
        && state.roster.ended().any(|(_, e)| {
            let b = &e.binding;
            b.account == account
                && b.role == Role::Applicant
                && b.proposal() == Some(proposal)
                && matches!(b.status, BindingStatus::Active)
        })
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

/// Refuses unless the actor may make the choices of `proposal`.
fn require_choice_maker(
    state: &State,
    proposal: ProposalId,
    ctx: &Ctx,
) -> Result<AccountId, Refusal> {
    let actor = crate::policy::actor_account(ctx)?;
    crate::proposal::draft::draft(state, proposal).ok_or_else(unknown)?;
    if !is_choice_maker(state, actor, proposal, ctx.now) {
        return Err(Refusal::new(RuleRef::Actor, RefusalReason::BindingInactive));
    }
    Ok(actor)
}

/// The proposal a publicity command acts on.
fn proposal_of(cmd: &Command) -> Option<ProposalId> {
    match cmd {
        Command::SetPublicChoice { proposal, .. }
        | Command::WithdrawPublicChoice { proposal, .. } => Some(*proposal),
        _ => None,
    }
}

/// A publicity command asks the vault nothing.
pub(crate) fn queries(_state: &State, _cmd: &Command, _ctx: &Ctx) -> Result<Vec<Query>, Refusal> {
    Ok(Vec::new())
}

/// Decides a publicity command (module documentation).
pub(crate) fn decide(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
    _answers: &Answers,
) -> Result<Vec<Record>, Refusal> {
    match cmd {
        Command::SetPublicChoice {
            proposal,
            phase,
            level,
            title,
            summary,
            grantee,
            deliverables,
        } => {
            let by = require_choice_maker(state, *proposal, ctx)?;
            let now = crate::view::proposal_state(state, *proposal).ok_or_else(unknown)?;
            if !settable_in(*phase).contains(&now) {
                return Err(Refusal::new(RuleRef::I41, RefusalReason::WrongState));
            }
            if *level != PublicLevel::Hidden
                && crate::view::proposal_minor_flagged(state, *proposal)
            {
                return Err(Refusal::new(RuleRef::I42, RefusalReason::GuardFailed));
            }
            if *phase == PublicPhase::Funded && !deliverables.is_empty() {
                return Err(Refusal::new(RuleRef::Input, RefusalReason::GuardFailed));
            }
            for d in deliverables {
                if state.money().accepted_deliverable(*proposal, *d).is_none() {
                    return Err(unknown());
                }
            }
            Ok(vec![Record::PublicChoiceSet {
                proposal: *proposal,
                phase: *phase,
                level: *level,
                title: *title,
                summary: *summary,
                grantee: *grantee,
                deliverables: deliverables.clone(),
                by,
            }])
        }
        Command::WithdrawPublicChoice { proposal, phase } => {
            let by = require_choice_maker(state, *proposal, ctx)?;
            if state.publicity.choice(*proposal, *phase).is_none() {
                return Err(Refusal::new(RuleRef::I41, RefusalReason::WrongState));
            }
            Ok(vec![Record::PublicChoiceWithdrawn {
                proposal: *proposal,
                phase: *phase,
                by,
            }])
        }
        _ => Err(not_mine()),
    }
}

/// Folds a publicity record at `seq`. It refuses a choice for an unknown
/// proposal, finished-phase deliverables on a funded choice, and a
/// withdrawal without a current choice.
pub(crate) fn apply(
    state: &mut State,
    seq: Seq,
    _at: Timestamp,
    record: &Record,
) -> Result<(), FoldError> {
    match record {
        Record::PublicChoiceSet {
            proposal,
            phase,
            level,
            title,
            summary,
            grantee,
            deliverables,
            ..
        } => {
            if crate::proposal::draft::draft(state, *proposal).is_none() {
                return Err(FoldError::UnknownEntity);
            }
            if *phase == PublicPhase::Funded && !deliverables.is_empty() {
                return Err(FoldError::Inconsistent);
            }
            state.publicity.choices.insert(
                (*proposal, *phase),
                PublicChoice {
                    level: *level,
                    title: *title,
                    summary: *summary,
                    grantee: *grantee,
                    deliverables: deliverables.clone(),
                    seq,
                },
            );
            Ok(())
        }
        Record::PublicChoiceWithdrawn {
            proposal, phase, ..
        } => {
            if state
                .publicity
                .choices
                .remove(&(*proposal, *phase))
                .is_none()
            {
                return Err(FoldError::Inconsistent);
            }
            Ok(())
        }
        _ => Err(FoldError::Inconsistent),
    }
}

/// The publicity lane contributes no vault question to other lanes' commands.
pub(crate) fn contribute_queries(
    _state: &State,
    _cmd: &Command,
    _ctx: &Ctx,
) -> Result<Vec<Query>, Refusal> {
    Ok(Vec::new())
}

/// The publicity lane adds no record to other lanes' batches.
pub(crate) fn contribute(
    _state: &State,
    _cmd: &Command,
    _ctx: &Ctx,
    _answers: &Answers,
    _batch: &[Record],
) -> Result<Vec<Record>, Refusal> {
    Ok(Vec::new())
}

/// The frozen policy of the proposal's call governs a publicity command
/// through MCP (R-MC-05).
pub(crate) fn governing_policy(state: &State, cmd: &Command) -> Result<PolicyScope, Refusal> {
    let proposal = proposal_of(cmd).ok_or_else(not_mine)?;
    Ok(PolicyScope::Call(call_of(state, proposal)?))
}
