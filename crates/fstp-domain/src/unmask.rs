//! The FSTP coordinator unmasks a party of their own programme (I-17 as
//! amended 2026-11-15, ADR-023).
//!
//! - `UnmaskParty`, by an account with an active FSTP coordinator
//!   binding of the named programme. It records one `PartyUnmasked`.
//! - The subject is a role binding of the programme, held or ended, or a
//!   reviewer or IRC assignment of a proposal of the programme. The
//!   assignment is the anonymous handle of P-11.
//! - The party kind is derived here from the binding's role or the
//!   assignment's kind, never taken from the request.
//! - No proposal state is required: the coordinator unmasks at any stage.
//!
//! The record names the subject by its id only. It holds no identity
//! attribute, so the ledger never learns who the party is. The vault
//! shows the identity on its own origin, after the cell recorded the
//! unmask (ADR-023 readings 6 to 8). The purpose is a `TextRef` only.

use fstp_ledger::Seq;

use crate::command::{Command, Ctx};
use crate::engine::{FoldError, PolicyScope};
use crate::id::{AccountId, AssignmentId, BindingId, ProgrammeId, TextRef};
use crate::oracle::{Answers, Query};
use crate::record::Record;
use crate::refusal::{Refusal, RefusalReason, RuleRef};
use crate::roles::{Group, Role};
use crate::state::State;
use crate::time::Timestamp;

/// Who an unmask names, by an id the coordinator's pages show.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UnmaskSubject {
    /// A role binding of the programme, held or ended.
    Binding(BindingId),
    /// A reviewer or IRC assignment: the person behind one handle.
    Assignment(AssignmentId),
}

/// The kind of party an unmask names (ADR-023 reading 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PartyKind {
    /// The lead of a proposal.
    Applicant,
    /// An applicant team member.
    TeamMember,
    /// The guardian of a minor applicant (I-18).
    Guardian,
    /// A committee member, a committee chair or an assigned reviewer.
    Reviewer,
    /// An IRC member.
    Irc,
    /// A Drafting or Operations role, or another coordinator, of the
    /// programme.
    Staff,
}

impl PartyKind {
    /// Every kind.
    pub const ALL: [PartyKind; 6] = [
        PartyKind::Applicant,
        PartyKind::TeamMember,
        PartyKind::Guardian,
        PartyKind::Reviewer,
        PartyKind::Irc,
        PartyKind::Staff,
    ];

    /// The wire name of the API and the pages.
    pub const fn wire(self) -> &'static str {
        match self {
            PartyKind::Applicant => "applicant",
            PartyKind::TeamMember => "team_member",
            PartyKind::Guardian => "guardian",
            PartyKind::Reviewer => "reviewer",
            PartyKind::Irc => "irc",
            PartyKind::Staff => "staff",
        }
    }

    /// The party kind of a programme binding of `role`, or `None` for a
    /// role the core never binds to a programme.
    pub const fn of_role(role: Role) -> Option<PartyKind> {
        Some(match role {
            Role::Applicant => PartyKind::Applicant,
            Role::ApplicantTeamMember => PartyKind::TeamMember,
            Role::Guardian => PartyKind::Guardian,
            Role::CommitteeMember | Role::CommitteeChair => PartyKind::Reviewer,
            Role::IrcMember => PartyKind::Irc,
            Role::ProgrammeManager
            | Role::CallDrafter
            | Role::FstpCoordinator
            | Role::FinanceApprover
            | Role::PaymentReleaser
            | Role::ContractSignatory
            | Role::Auditor => PartyKind::Staff,
            Role::TenantAdmin | Role::FinancialSignatory | Role::LegalSignatory => return None,
        })
    }
}

/// One folded `PartyUnmasked`, as the audit read lists it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Unmask {
    /// The programme.
    pub programme: ProgrammeId,
    /// The derived party kind.
    pub party: PartyKind,
    /// The subject, by id.
    pub subject: UnmaskSubject,
    /// The purpose, a confidential text of the programme.
    pub purpose: TextRef,
    /// The coordinator.
    pub by: AccountId,
    /// The ledger position.
    pub seq: Seq,
    /// The instant of the entry.
    pub at: Timestamp,
}

/// The unmask part of the projection: every unmask, in ledger order.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct UnmaskState {
    records: Vec<Unmask>,
}

impl UnmaskState {
    /// No unmask.
    pub(crate) const fn genesis() -> UnmaskState {
        UnmaskState {
            records: Vec::new(),
        }
    }

    /// Every unmask, oldest first.
    pub fn records(&self) -> &[Unmask] {
        &self.records
    }

    /// The unmasks of `programme`, oldest first.
    pub fn of(&self, programme: ProgrammeId) -> impl Iterator<Item = &Unmask> {
        self.records
            .iter()
            .filter(move |u| u.programme == programme)
    }
}

/// The party kind and the account behind `subject`, when the subject is
/// of `programme`. `None` for an unknown subject, one of another
/// programme, or a tenant-wide role.
pub fn party_of(
    state: &State,
    programme: ProgrammeId,
    subject: UnmaskSubject,
) -> Option<(PartyKind, AccountId)> {
    match subject {
        UnmaskSubject::Binding(id) => {
            let b = state.roster.held_or_ended(id)?;
            if b.programme != programme {
                return None;
            }
            PartyKind::of_role(b.role).map(|k| (k, b.account))
        }
        UnmaskSubject::Assignment(id) => {
            let a = state.review().get(id)?;
            let of =
                crate::programme::call(state, a.call).map(crate::programme::CallView::programme);
            if of != Some(programme) {
                return None;
            }
            let kind = match a.kind.role() {
                Role::IrcMember => PartyKind::Irc,
                _ => PartyKind::Reviewer,
            };
            Some((kind, a.reviewer))
        }
    }
}

/// Whether `account` may unmask the parties of `programme` at `now`: it
/// holds an active FSTP coordinator binding there (ADR-023 reading 1).
pub fn is_unmasker(
    state: &State,
    account: AccountId,
    programme: ProgrammeId,
    now: Timestamp,
) -> bool {
    state.roster.bindings().any(|(_, b)| {
        b.account == account
            && b.programme == programme
            && b.role == Role::FstpCoordinator
            && b.group() == Group::Judging
            && b.active_at(now)
            && b.scheduled_end.is_none_or(|e| now < e)
    })
}

const fn unknown() -> Refusal {
    Refusal::new(RuleRef::Input, RefusalReason::UnknownEntity)
}

const fn not_mine() -> Refusal {
    Refusal::new(RuleRef::Row, RefusalReason::WrongState)
}

/// An unmask asks the vault nothing. The vault shows the identity later,
/// on its own origin.
pub(crate) fn queries(_state: &State, _cmd: &Command, _ctx: &Ctx) -> Result<Vec<Query>, Refusal> {
    Ok(Vec::new())
}

/// Decides `UnmaskParty` (module documentation).
pub(crate) fn decide(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
    _answers: &Answers,
) -> Result<Vec<Record>, Refusal> {
    let Command::UnmaskParty {
        programme,
        subject,
        purpose,
    } = cmd
    else {
        return Err(not_mine());
    };
    let by = crate::policy::actor_account(ctx)?;
    state.policy.programme(*programme).ok_or_else(unknown)?;
    if !is_unmasker(state, by, *programme, ctx.now) {
        return Err(Refusal::new(RuleRef::Actor, RefusalReason::BindingInactive));
    }
    let (party, _) = party_of(state, *programme, *subject).ok_or_else(unknown)?;
    Ok(vec![Record::PartyUnmasked {
        programme: *programme,
        party,
        subject: *subject,
        purpose: *purpose,
        by,
    }])
}

/// Folds a `PartyUnmasked` at `seq`. It refuses an unknown programme.
pub(crate) fn apply(
    state: &mut State,
    seq: Seq,
    at: Timestamp,
    record: &Record,
) -> Result<(), FoldError> {
    match record {
        Record::PartyUnmasked {
            programme,
            party,
            subject,
            purpose,
            by,
        } => {
            if state.policy.programme(*programme).is_none() {
                return Err(FoldError::UnknownEntity);
            }
            state.unmasks.records.push(Unmask {
                programme: *programme,
                party: *party,
                subject: *subject,
                purpose: *purpose,
                by: *by,
                seq,
                at,
            });
            Ok(())
        }
        _ => Err(FoldError::Inconsistent),
    }
}

/// The unmask lane contributes no vault question to other lanes' commands.
pub(crate) fn contribute_queries(
    _state: &State,
    _cmd: &Command,
    _ctx: &Ctx,
) -> Result<Vec<Query>, Refusal> {
    Ok(Vec::new())
}

/// The unmask lane adds no record to other lanes' batches.
pub(crate) fn contribute(
    _state: &State,
    _cmd: &Command,
    _ctx: &Ctx,
    _answers: &Answers,
    _batch: &[Record],
) -> Result<Vec<Record>, Refusal> {
    Ok(Vec::new())
}

/// The head policy of the programme governs an unmask through MCP. The
/// unmask has no tool, so MCP refuses it before this is asked (I-86).
pub(crate) fn governing_policy(_state: &State, cmd: &Command) -> Result<PolicyScope, Refusal> {
    match cmd {
        Command::UnmaskParty { programme, .. } => Ok(PolicyScope::Programme(*programme)),
        _ => Err(not_mine()),
    }
}
