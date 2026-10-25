//! Roles, bindings over time and separation of duties (design section 2.6, I-01, I-02, I-04, I-06).
//!
//! Owned by lane L-SOD (docs/handoff/m2-design.md section 10). Step W1c
//! declared only the vocabulary the interface names: [`Group`], [`Role`],
//! [`BindingScope`] and the empty [`RosterState`]. Lane L-SOD completes the
//! roster, the cooling-off windows and the account-level rules.

use crate::id::{AccountId, BindingId, CallId, ProgrammeId, ProposalId};
use crate::time::Timestamp;

/// The four role groups of `SPEC/02-domain/roles-and-sod.md`.
///
/// Declared by W1c for the interface. Lane L-SOD completes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Group {
    /// Programme manager and call drafter.
    Drafting,
    /// FSTP coordinator, committee member and chair, IRC member.
    Judging,
    /// Applicant, applicant team member and guardian.
    Receiving,
    /// Tenant admin, finance approver, payment releaser, contract signatory and auditor.
    Operations,
}

/// A role a binding can hold, as in the roles table of `SPEC/02-domain/roles-and-sod.md`.
///
/// The assigned reviewer is an assignment over a committee member binding,
/// not a role of its own (design section 2.6).
///
/// Declared by W1c for the interface. Lane L-SOD completes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    /// Programme manager (Drafting).
    ProgrammeManager,
    /// Call drafter (Drafting).
    CallDrafter,
    /// FSTP coordinator (Judging).
    FstpCoordinator,
    /// Committee member (Judging).
    CommitteeMember,
    /// Committee chair (Judging).
    CommitteeChair,
    /// IRC member (Judging).
    IrcMember,
    /// Applicant, the lead of a proposal (Receiving).
    Applicant,
    /// Applicant team member (Receiving).
    ApplicantTeamMember,
    /// Guardian of a minor applicant (Receiving).
    Guardian,
    /// Tenant admin (Operations).
    TenantAdmin,
    /// Finance approver (Operations).
    FinanceApprover,
    /// Payment releaser (Operations).
    PaymentReleaser,
    /// Contract signatory with signing authority (Operations, decided 2026-10-25).
    ContractSignatory,
    /// Auditor (Operations).
    Auditor,
}

impl Role {
    /// Every role, in the order of the roles table.
    pub const ALL: [Role; 14] = [
        Role::ProgrammeManager,
        Role::CallDrafter,
        Role::FstpCoordinator,
        Role::CommitteeMember,
        Role::CommitteeChair,
        Role::IrcMember,
        Role::Applicant,
        Role::ApplicantTeamMember,
        Role::Guardian,
        Role::TenantAdmin,
        Role::FinanceApprover,
        Role::PaymentReleaser,
        Role::ContractSignatory,
        Role::Auditor,
    ];

    /// The group of the role.
    pub const fn group(self) -> Group {
        match self {
            Role::ProgrammeManager | Role::CallDrafter => Group::Drafting,
            Role::FstpCoordinator
            | Role::CommitteeMember
            | Role::CommitteeChair
            | Role::IrcMember => Group::Judging,
            Role::Applicant | Role::ApplicantTeamMember | Role::Guardian => Group::Receiving,
            Role::TenantAdmin
            | Role::FinanceApprover
            | Role::PaymentReleaser
            | Role::ContractSignatory
            | Role::Auditor => Group::Operations,
        }
    }

    /// The role's name as the roles table spells it.
    pub const fn spec_name(self) -> &'static str {
        match self {
            Role::ProgrammeManager => "Programme manager",
            Role::CallDrafter => "Call drafter",
            Role::FstpCoordinator => "FSTP coordinator",
            Role::CommitteeMember => "Committee member",
            Role::CommitteeChair => "Committee chair",
            Role::IrcMember => "IRC member",
            Role::Applicant => "Applicant",
            Role::ApplicantTeamMember => "Applicant team member",
            Role::Guardian => "Guardian",
            Role::TenantAdmin => "Tenant admin",
            Role::FinanceApprover => "Finance approver",
            Role::PaymentReleaser => "Payment releaser",
            Role::ContractSignatory => "Contract signatory",
            Role::Auditor => "Auditor",
        }
    }
}

/// What a binding is scoped to. Receiving bindings are scoped to one
/// proposal and its call; every other binding to the programme.
///
/// Declared by W1c for the interface. Lane L-SOD completes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BindingScope {
    /// The whole programme: Drafting, Judging and Operations roles.
    Programme,
    /// One proposal and its call: Receiving roles (`SPEC/02-domain/roles-and-sod.md` Receiving bindings).
    Proposal {
        /// The proposal.
        proposal: ProposalId,
        /// The call the proposal belongs to.
        call: CallId,
    },
}

/// The P-12 value, counted in calls (P-12 NOTE 4). Zero is allowed.
///
/// Declared by W1c for the interface. Lane L-SOD completes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CoolingOff(pub u8);

/// Roster part of the projection: bindings and cooling-off bars.
///
/// Declared empty by W1c so that `State` can hold it. Lane L-SOD fills it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RosterState {
    _pending: (),
}

impl RosterState {
    /// The roster before any record.
    pub(crate) const fn genesis() -> RosterState {
        RosterState { _pending: () }
    }

    /// The binding of `role` that `account` holds in `programme` and that is
    /// active at `now`: started, not ended, not suspended and not voided (design section 3.6).
    /// Other lanes read the roster only through queries like this one.
    ///
    /// Declared by W1c as a stub that finds no binding. Lane L-SOD completes it.
    #[allow(dead_code, reason = "lanes L-POL, L-REV, L-LIFE and L-MONEY call it")]
    pub(crate) fn active_binding(
        &self,
        account: AccountId,
        role: Role,
        programme: ProgrammeId,
        now: Timestamp,
    ) -> Option<BindingId> {
        let _ = (account, role, programme, now);
        None
    }
}

// ---------------------------------------------------------------------------
// Engine entry points of this lane, called by `crate::engine`.
// ---------------------------------------------------------------------------

/// The vault questions of the role and vault change commands.
///
/// Declared by W1c as a stub. Lane L-SOD completes it.
pub(crate) fn queries(
    state: &crate::state::State,
    cmd: &crate::command::Command,
    ctx: &crate::command::Ctx,
) -> Result<Vec<crate::oracle::Query>, crate::refusal::Refusal> {
    let _ = (state, cmd, ctx);
    Err(crate::refusal::Refusal::not_implemented())
}

/// The records of the role and vault change commands.
///
/// Declared by W1c as a stub. Lane L-SOD completes it.
pub(crate) fn decide(
    state: &crate::state::State,
    cmd: &crate::command::Command,
    ctx: &crate::command::Ctx,
    answers: &crate::oracle::Answers,
) -> Result<Vec<crate::record::Record>, crate::refusal::Refusal> {
    let _ = (state, cmd, ctx, answers);
    Err(crate::refusal::Refusal::not_implemented())
}

/// Folds a role and vault change record.
///
/// Declared by W1c as a stub. Lane L-SOD completes it.
pub(crate) fn apply(
    state: &mut crate::state::State,
    seq: fstp_ledger::Seq,
    at: crate::time::Timestamp,
    record: &crate::record::Record,
) -> Result<(), crate::engine::FoldError> {
    let _ = (state, seq, at, record);
    Err(crate::engine::FoldError::NotImplemented)
}

/// The vault questions this lane needs for its contribution to the batch of
/// a command that another lane owns. It reads only the state and the command.
///
/// Declared by W1c as a stub that asks nothing. Lane L-SOD completes it.
pub(crate) fn contribute_queries(
    state: &crate::state::State,
    cmd: &crate::command::Command,
    ctx: &crate::command::Ctx,
) -> Result<Vec<crate::oracle::Query>, crate::refusal::Refusal> {
    let _ = (state, cmd, ctx);
    Ok(Vec::new())
}

/// The records this lane adds to the batch of a command that another lane
/// owns, given the records so far (`crate::engine` module docs).
/// Examples: ending a proposal's Receiving bindings when the batch takes
/// it to a terminal state (Q11 A), and voiding or suspending bindings after
/// a P-13 edit (enforcement point 3).
///
/// Declared by W1c as a stub that adds nothing. Lane L-SOD completes it.
pub(crate) fn contribute(
    state: &crate::state::State,
    cmd: &crate::command::Command,
    ctx: &crate::command::Ctx,
    answers: &crate::oracle::Answers,
    batch: &[crate::record::Record],
) -> Result<Vec<crate::record::Record>, crate::refusal::Refusal> {
    let _ = (state, cmd, ctx, answers, batch);
    Ok(Vec::new())
}

/// The policy whose P-77 governs a binding action of this lane through MCP
/// (R-MC-05, `crate::engine::PolicyScope`).
///
/// Declared by W1c as a stub. Lane L-SOD completes it.
pub(crate) fn governing_policy(
    state: &crate::state::State,
    cmd: &crate::command::Command,
) -> Result<crate::engine::PolicyScope, crate::refusal::Refusal> {
    let _ = (state, cmd);
    Err(crate::refusal::Refusal::not_implemented())
}
