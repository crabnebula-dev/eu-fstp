//! Team invitations (F-079, ADR-038; I-17, TH-07, TH-08, R-AN-01).
//!
//! A person joins the team of a proposal, or becomes its guardian, only by
//! accepting an invitation. The rule is Daniel's decision of 2026-11-23.
//!
//! - `InviteToTeam`, by the proposal's lead with an active Applicant
//!   binding, records `TeamInvited`. It names the invited address as a
//!   sealed text and no account. It binds nobody and asks the vault
//!   nothing about the invitee. A guardian invitation follows the guard of
//!   `AddGuardian`: a minor-flagged proposal, or NEGOTIATION once the
//!   vault no longer shows the lead 18 or older. That question is about
//!   the lead (ADR-008, "Second derivation").
//! - `WithdrawTeamInvitation`, by the lead, closes an open invitation.
//! - `AcceptTeamInvitation`, by any account, accepts an open invitation
//!   before it expires. The shell attests that the account's login email
//!   is the invited address. The inviting lead must still hold the active
//!   Applicant binding. The batch closes the invitation as joined, and
//!   lane L-SOD's contribution adds the Receiving binding after SoD-01,
//!   SoD-03, SoD-05, SoD-06, I-06 and I-36, as for `AddTeamMember`. So the
//!   vault is asked about the account only once it has accepted. A
//!   refusal records nothing, and the invitation stays open.
//! - `DeclineTeamInvitation`, by any account, closes an open invitation
//!   before it expires. The shell attests the address as for acceptance.
//! - Bounds: at most [`MAX_OPEN_PER_PROPOSAL`] open invitations per
//!   proposal and [`MAX_OPEN_PER_LEAD`] open invitations by one lead. An
//!   invitation is open until it closes or [`INVITATION_TTL_MICROS`] pass.
//!
//! Every refusal of the lead's two commands reads facts of the lead, the
//! proposal and the invitations only. None reads the invitee, whom the
//! domain does not know until acceptance.

use std::collections::BTreeMap;

use crate::command::{Command, Ctx};
use crate::engine::{FoldError, PolicyScope};
use crate::id::{AccountId, ProposalId, TeamInvitationId, TextRef};
use crate::oracle::{Answers, Query};
use crate::record::Record;
use crate::refusal::{Refusal, RefusalReason, RuleRef};
use crate::roles::Role;
use crate::state::State;
use crate::time::Timestamp;

/// How long an invitation stays open: 14 days, in microseconds (ADR-038,
/// lane reading for Daniel to confirm).
pub const INVITATION_TTL_MICROS: i64 = 14 * 86_400_000_000;

/// The most open invitations of one proposal (ADR-038).
pub const MAX_OPEN_PER_PROPOSAL: usize = 10;

/// The most open invitations by one lead, across proposals (ADR-038).
pub const MAX_OPEN_PER_LEAD: usize = 20;

/// One invitation, as the ledger recorded it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TeamInvitation {
    /// The proposal.
    pub proposal: ProposalId,
    /// The invited address, a sealed confidential text of the proposal.
    pub contact: TextRef,
    /// Whether the invitation is for the guardian.
    pub guardian: bool,
    /// The lead who invited.
    pub by: AccountId,
    /// When it expires.
    pub expires: Timestamp,
    /// `None` while not closed, then whether the invitee joined.
    pub closed: Option<bool>,
}

impl TeamInvitation {
    /// Whether it is open at `now`: not closed and not expired.
    pub fn open_at(&self, now: Timestamp) -> bool {
        self.closed.is_none() && now < self.expires
    }

    /// The role the acceptance binds.
    pub const fn role(&self) -> Role {
        if self.guardian {
            Role::Guardian
        } else {
            Role::ApplicantTeamMember
        }
    }
}

/// The invitations of every proposal, closed ones included, so an id is
/// never reused.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Invitations {
    by_id: BTreeMap<TeamInvitationId, TeamInvitation>,
}

impl Invitations {
    /// No invitation.
    pub(crate) const fn genesis() -> Invitations {
        Invitations {
            by_id: BTreeMap::new(),
        }
    }
}

/// The invitation `id`, open or not.
pub fn team_invitation(state: &State, id: TeamInvitationId) -> Option<&TeamInvitation> {
    state.proposals.team.by_id.get(&id)
}

/// Every invitation, open or not, by id.
pub fn team_invitations(
    state: &State,
) -> impl Iterator<Item = (TeamInvitationId, &TeamInvitation)> {
    state.proposals.team.by_id.iter().map(|(k, v)| (*k, v))
}

/// Whether `lead` may open one more invitation on `proposal` at `now`
/// under the bounds (ADR-038). The API asks before it stores the address,
/// so a bounded request stores no text. `InviteToTeam` checks it again.
pub fn invitation_allowed(
    state: &State,
    proposal: ProposalId,
    lead: AccountId,
    now: Timestamp,
) -> bool {
    let open = state
        .proposals
        .team
        .by_id
        .values()
        .filter(|i| i.open_at(now));
    let (mut on_proposal, mut by_lead) = (0usize, 0usize);
    for i in open {
        if i.proposal == proposal {
            on_proposal = on_proposal.saturating_add(1);
        }
        if i.by == lead {
            by_lead = by_lead.saturating_add(1);
        }
    }
    on_proposal < MAX_OPEN_PER_PROPOSAL && by_lead < MAX_OPEN_PER_LEAD
}

/// Whether `cmd` is decided here.
pub(crate) const fn is_team_command(cmd: &Command) -> bool {
    matches!(
        cmd,
        Command::InviteToTeam { .. }
            | Command::WithdrawTeamInvitation { .. }
            | Command::AcceptTeamInvitation { .. }
            | Command::DeclineTeamInvitation { .. }
    )
}

/// Whether `record` is folded here.
pub(crate) const fn is_team_record(record: &Record) -> bool {
    matches!(
        record,
        Record::TeamInvited { .. } | Record::TeamInvitationClosed { .. }
    )
}

const fn unknown() -> Refusal {
    Refusal::new(RuleRef::Input, RefusalReason::UnknownEntity)
}

const fn not_open() -> Refusal {
    Refusal::new(RuleRef::Input, RefusalReason::WrongState)
}

const fn not_lead() -> Refusal {
    Refusal::new(RuleRef::Actor, RefusalReason::BindingInactive)
}

/// Whether `account` is the lead of `proposal` with an active Applicant
/// binding at `now`.
fn active_lead(state: &State, proposal: ProposalId, account: AccountId, now: Timestamp) -> bool {
    super::draft::draft(state, proposal).is_some_and(|d| d.lead == account)
        && state
            .roster
            .active_receiving(account, Role::Applicant, proposal, now)
            .is_some()
}

/// The open invitation `id` of `proposal` at `now`.
fn open_invitation(
    state: &State,
    proposal: ProposalId,
    id: TeamInvitationId,
    now: Timestamp,
) -> Result<&TeamInvitation, Refusal> {
    let i = team_invitation(state, id).ok_or_else(unknown)?;
    if i.proposal != proposal {
        return Err(unknown());
    }
    if !i.open_at(now) {
        return Err(not_open());
    }
    Ok(i)
}

/// Checks a command and returns the records it owns before any answer,
/// with the vault question it asks, if any.
fn check(state: &State, cmd: &Command, ctx: &Ctx) -> Result<(Vec<Record>, Option<Query>), Refusal> {
    let actor = crate::policy::actor_account(ctx)?;
    match cmd {
        Command::InviteToTeam {
            proposal,
            invitation,
            contact,
            guardian,
        } => {
            super::draft::draft(state, *proposal).ok_or_else(unknown)?;
            if !active_lead(state, *proposal, actor, ctx.now) {
                return Err(not_lead());
            }
            if team_invitation(state, *invitation).is_some() {
                return Err(Refusal::new(RuleRef::Ledger, RefusalReason::IdReused));
            }
            if !invitation_allowed(state, *proposal, actor, ctx.now) {
                return Err(Refusal::new(RuleRef::Input, RefusalReason::GuardFailed));
            }
            // The guardian guard of `AddGuardian`. Its one question is
            // about the lead (ADR-008, "Second derivation").
            let question = if *guardian {
                super::draft::guardian_question(state, *proposal)?
            } else {
                None
            };
            let expires =
                Timestamp::from_micros(ctx.now.micros().saturating_add(INVITATION_TTL_MICROS));
            Ok((
                vec![Record::TeamInvited {
                    proposal: *proposal,
                    invitation: *invitation,
                    contact: *contact,
                    guardian: *guardian,
                    by: actor,
                    expires,
                }],
                question,
            ))
        }
        Command::WithdrawTeamInvitation {
            proposal,
            invitation,
        } => {
            let d = super::draft::draft(state, *proposal).ok_or_else(unknown)?;
            if d.lead != actor {
                return Err(not_lead());
            }
            let i = team_invitation(state, *invitation).ok_or_else(unknown)?;
            if i.proposal != *proposal {
                return Err(unknown());
            }
            if i.closed.is_some() {
                return Err(not_open());
            }
            Ok((closed(*proposal, *invitation, false), None))
        }
        Command::DeclineTeamInvitation {
            proposal,
            invitation,
        } => {
            open_invitation(state, *proposal, *invitation, ctx.now)?;
            Ok((closed(*proposal, *invitation, false), None))
        }
        Command::AcceptTeamInvitation {
            proposal,
            invitation,
            binding,
        } => {
            let i = open_invitation(state, *proposal, *invitation, ctx.now)?;
            // The lead's invitation stands only while that account still
            // leads the proposal with an active binding.
            if !active_lead(state, *proposal, i.by, ctx.now) {
                return Err(not_open());
            }
            if state
                .used_ids
                .contains(crate::state::UsedId::Binding(*binding))
            {
                return Err(Refusal::new(RuleRef::Ledger, RefusalReason::IdReused));
            }
            let question = if i.guardian {
                super::draft::guardian_question(state, *proposal)?
            } else {
                None
            };
            if state.roster.bound_to(actor, *proposal) {
                return Err(Refusal::new(RuleRef::Input, RefusalReason::InvalidValue));
            }
            Ok((closed(*proposal, *invitation, true), question))
        }
        _ => Err(not_open()),
    }
}

fn closed(proposal: ProposalId, invitation: TeamInvitationId, joined: bool) -> Vec<Record> {
    vec![Record::TeamInvitationClosed {
        proposal,
        invitation,
        joined,
    }]
}

/// The vault questions of the four commands: only a guardian invitation or
/// acceptance in NEGOTIATION asks one, about the lead.
pub(crate) fn queries(state: &State, cmd: &Command, ctx: &Ctx) -> Result<Vec<Query>, Refusal> {
    let (_, q) = check(state, cmd, ctx)?;
    Ok(q.into_iter().collect())
}

/// The records of the four commands that this module owns.
pub(crate) fn decide(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
    answers: &Answers,
) -> Result<Vec<Record>, Refusal> {
    let (records, question) = check(state, cmd, ctx)?;
    let mut out = Vec::new();
    if let Some(q) = question {
        // ADR-008 "Second derivation", as for `AddGuardian`: a guardian is
        // admitted only on a no. A yes leaves the lead shown 18 or older.
        if crate::grant::record_answer(&mut out, &q, answers)? {
            return Err(Refusal::new(RuleRef::Input, RefusalReason::InvalidValue));
        }
    }
    out.extend(records);
    Ok(out)
}

/// Folds `TeamInvited` and `TeamInvitationClosed`.
pub(crate) fn apply(state: &mut State, record: &Record) -> Result<(), FoldError> {
    match record {
        Record::TeamInvited {
            proposal,
            invitation,
            contact,
            guardian,
            by,
            expires,
        } => {
            if super::draft::draft(state, *proposal).is_none() {
                return Err(FoldError::UnknownEntity);
            }
            if state.proposals.team.by_id.contains_key(invitation) {
                return Err(FoldError::DuplicateId);
            }
            state.proposals.team.by_id.insert(
                *invitation,
                TeamInvitation {
                    proposal: *proposal,
                    contact: *contact,
                    guardian: *guardian,
                    by: *by,
                    expires: *expires,
                    closed: None,
                },
            );
            Ok(())
        }
        Record::TeamInvitationClosed {
            proposal,
            invitation,
            joined,
        } => {
            let i = state
                .proposals
                .team
                .by_id
                .get_mut(invitation)
                .ok_or(FoldError::UnknownEntity)?;
            if i.proposal != *proposal || i.closed.is_some() {
                return Err(FoldError::Inconsistent);
            }
            i.closed = Some(*joined);
            Ok(())
        }
        _ => Err(FoldError::Inconsistent),
    }
}

/// The policy whose P-77 governs these commands through MCP: the frozen
/// policy of the proposal's call (R-MC-05). No operation offers them
/// through MCP.
pub(crate) fn governing_policy(state: &State, cmd: &Command) -> Result<PolicyScope, Refusal> {
    let proposal = match cmd {
        Command::InviteToTeam { proposal, .. }
        | Command::WithdrawTeamInvitation { proposal, .. }
        | Command::AcceptTeamInvitation { proposal, .. }
        | Command::DeclineTeamInvitation { proposal, .. } => *proposal,
        _ => return Err(not_open()),
    };
    super::draft::proposal_call(state, proposal)
        .map(PolicyScope::Call)
        .ok_or_else(unknown)
}

/// The invitation an `AcceptTeamInvitation` accepts, for lane L-SOD's
/// binding and lane L-REV's rechecks.
pub(crate) fn accepted(state: &State, cmd: &Command) -> Option<TeamInvitation> {
    match cmd {
        Command::AcceptTeamInvitation { invitation, .. } => {
            team_invitation(state, *invitation).copied()
        }
        _ => None,
    }
}
