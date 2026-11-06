//! Reads and their rules (M4 design section 3.6, D11, R-AC-01, I-21).
//!
//! [`READ_RULES`] gives each read one rule and the proposal states where
//! it is open. A state a row leaves out is a judged refusal, so no read is
//! unjudged in any of the 16 states. Reads whose target is not a proposal
//! list every state, since the proposal state does not bear on them.
//!
//! [`authorize_read`] judges one read: the rule first, then the state.
//! A caller outside the rule is refused with R-AC-01. A caller who must
//! declare before reading, or who has a conflict, is refused with R-CF-02
//! or I-03. A caller with no account is refused as an actor, unless the
//! read is public.
//!
//! A public read of a call opens only once the call is published, since
//! the call text is confidential until then (R-AC-01, R-GA-01). A target
//! that does not exist refuses with the rule's own refusal, as a target
//! outside the caller's relations does. Only a caller whom the rule admits
//! whatever the target gets an input refusal, so no read reveals which
//! ids exist.
//!
//! The content read runs the domain `ReadContent` command in dispatch as
//! well, which logs it (R-AU-01) and checks the vault (I-03). This module
//! judges the caller from the projection alone, and it also asks the
//! domain's [`fstp_domain::visibility::can_read_content`], so it never
//! admits a content read the domain refuses.
//!
//! Interim readings, pending Daniel (design section 15.0):
//!
//! - The pre-declaration view opens to each person who must declare
//!   before a content read, in the states where that read can follow
//!   (Q9). The spec states no state list, so this one is strict.
//! - Content reads in RANKED, DEFERRED and the terminal states admit the
//!   applicant team only (Q39).
//! - Through MCP, a content reader outside the team is refused unless P-75
//!   is on (change D6). It reads the typed frozen P-75 of the call, as the
//!   domain's own MCP check does.
//! - The proposal's call is the call of its latest Receiving binding,
//!   since the domain has no public accessor for the current call yet.
//!
//! Interim readings of lane m4reg, for the reads the M4 demo pages call.
//! The design names none of them, so each name follows its page:
//!
//! - `ListTenantAdmins` is a tenant admin read, as the settings are.
//!   `ListSignatories` and `GetActivation` are too (lane m4/roles).
//! - `GetMyVerification` is the caller's own object.
//! - `ListProgrammes` and `ListTemplates` open to a tenant admin and to a
//!   programme manager of any programme. A cell serves one tenant, so
//!   every programme of the state is the tenant's.
//! - `GetInvitation` admits anyone who holds the link, since the invitee
//!   reads it before enrolling. Its read model must resolve the link's
//!   token, never a guessable id (SoD-09).
//! - `ListProposalAssignments` is the FSTP coordinator's, from SUBMITTED
//!   on and outside INELIGIBLE (see `ASSIGNABLE` for the open seam).
//!
//! Interim reading of the home page, pending Daniel (design section 15.0,
//! 2026-10-31): `ListMyRoles` (`me.roles`) is the caller's own object. It
//! lists the caller's own active bindings and nothing about any other
//! account (I-86).
//!
//! Lane j2 (`SPEC/12-journey-ui.md` section 10, ADR-015): `GetJourney`
//! and `GetDiary` admit the proposal's team and every holder of a role of
//! the section 7.2 matrix in its programme. The rule only opens the read.
//! The dispatch then applies the visibility function to each entry, and a
//! staff reader of a draft is refused, since drafts are the team's alone
//! (I-21). Interim, pending Daniel: call drafters, tenant admins and the
//! financial and legal signatories read no diary. Section 7.2 names no
//! signatory, and both bind tenant-wide (roles-and-sod.md NOTE 5).
//!
//! Daniel, 2026-11-06: the Receiving bindings still end at a terminal
//! state, but the former lead and team members keep a read-only view of
//! `GetJourney`, `GetDiary`, `GetRouteMap`, `GetOwnProposal`,
//! `GetOwnStage2Thread` and `GetContent` of that proposal
//! (`ReadRule::FormerTeam`). No command reads this rule.

use fstp_domain::Via;
use fstp_domain::assignment::{Assignment, AssignmentKind, AssignmentStatus};
use fstp_domain::id::{AccountId, AssignmentId, CallId, ProgrammeId, ProposalId};
use fstp_domain::policy::{AgentContentAccess, ReadAccess};
use fstp_domain::roles::{BindingScope, BindingStatus, Group, Role};
use fstp_domain::time::Timestamp;
use fstp_domain::{State, StateTag};
use fstp_engine::EngineState;

use crate::principal::Principal;

/// A read (design section 3.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(
    missing_docs,
    reason = "each variant is named after the read it serves"
)]
pub enum ReadKind {
    ListOpenCalls,
    GetPublicCall,
    GetGuide,
    ListOwnProposals,
    GetOwnProposal,
    GetOwnWorkspace,
    GetOwnStage2Thread,
    GetOwnNotices,
    GetNegotiationLanding,
    ListMyAssignments,
    GetDeclarationView,
    GetContent,
    GetScoreSheet,
    GetStage2Thread,
    GetFindings,
    GetRankingView,
    GetCutOffRound,
    ListMyIrcCases,
    GetIrcCase,
    GetIntakeQueue,
    GetCallBoard,
    GetDraft,
    GetReport,
    GetPreview,
    GetImpact,
    ListImportProposals,
    ListInvitations,
    ListBindings,
    GetAuditLog,
    GetVaultOutcomes,
    ListMyAgents,
    ListMyAgentActivity,
    ListMyPendingActions,
    ListMySessions,
    ListNotifiableConflicts,
    ListApprovals,
    GetTenantSettings,
    GetOnboarding,
    // Lane m4reg: the reads the M4 demo pages call (module documentation).
    ListTenantAdmins,
    // Lane m4/roles: the signatory holders (NOTE 5) and the activation of
    // the organisation (SoD-18), tenant admin reads as the admin list is.
    ListSignatories,
    GetActivation,
    GetMyVerification,
    ListProgrammes,
    ListTemplates,
    GetInvitation,
    ListProposalAssignments,
    // The interim home page of design section 15.0 (2026-10-31): the
    // caller's own active roles (module documentation).
    ListMyRoles,
    // Lane j2: a proposal's route position and its diary
    // (`SPEC/12-journey-ui.md` section 10, module documentation).
    GetJourney,
    GetDiary,
    // Lane j4 (ADR-015 amendment of 2026-11-06): the server's checked
    // map tree of one proposal, for its team (section 8.1, O-58).
    GetRouteMap,
}

impl ReadKind {
    /// Every read, in declaration order.
    pub const ALL: [ReadKind; 50] = [
        ReadKind::ListOpenCalls,
        ReadKind::GetPublicCall,
        ReadKind::GetGuide,
        ReadKind::ListOwnProposals,
        ReadKind::GetOwnProposal,
        ReadKind::GetOwnWorkspace,
        ReadKind::GetOwnStage2Thread,
        ReadKind::GetOwnNotices,
        ReadKind::GetNegotiationLanding,
        ReadKind::ListMyAssignments,
        ReadKind::GetDeclarationView,
        ReadKind::GetContent,
        ReadKind::GetScoreSheet,
        ReadKind::GetStage2Thread,
        ReadKind::GetFindings,
        ReadKind::GetRankingView,
        ReadKind::GetCutOffRound,
        ReadKind::ListMyIrcCases,
        ReadKind::GetIrcCase,
        ReadKind::GetIntakeQueue,
        ReadKind::GetCallBoard,
        ReadKind::GetDraft,
        ReadKind::GetReport,
        ReadKind::GetPreview,
        ReadKind::GetImpact,
        ReadKind::ListImportProposals,
        ReadKind::ListInvitations,
        ReadKind::ListBindings,
        ReadKind::GetAuditLog,
        ReadKind::GetVaultOutcomes,
        ReadKind::ListMyAgents,
        ReadKind::ListMyAgentActivity,
        ReadKind::ListMyPendingActions,
        ReadKind::ListMySessions,
        ReadKind::ListNotifiableConflicts,
        ReadKind::ListApprovals,
        ReadKind::GetTenantSettings,
        ReadKind::GetOnboarding,
        ReadKind::ListTenantAdmins,
        ReadKind::ListSignatories,
        ReadKind::GetActivation,
        ReadKind::GetMyVerification,
        ReadKind::ListProgrammes,
        ReadKind::ListTemplates,
        ReadKind::GetInvitation,
        ReadKind::ListProposalAssignments,
        ReadKind::ListMyRoles,
        ReadKind::GetJourney,
        ReadKind::GetDiary,
        ReadKind::GetRouteMap,
    ];
}

/// Who a read admits (design section 3.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReadRule {
    /// Anyone, with or without an account. On a call target, only once
    /// the call is published (R-AC-01, R-GA-01).
    Public,
    /// The applicant team of the proposal: lead, team members and guardian,
    /// through an active Receiving binding.
    Team,
    /// A former lead or team member of the proposal, in a terminal state:
    /// their Receiving binding was active when the domain ended it there
    /// (`roles-and-sod.md` Receiving bindings). A read-only view of their
    /// own proposal and of the outcome, as `proposal.list_own` gives it,
    /// which revives no binding (Daniel, 2026-11-06, O-59).
    FormerTeam,
    /// The lead of the proposal.
    Lead,
    /// The assignee of the target assignment, declared free of conflict,
    /// over an active binding of the assignment's role.
    AssignedReviewer,
    /// The assignee of the target assignment, declared or not.
    Assignee,
    /// A reader that P-10 and the proposal state admit (R-AC-01, P-10
    /// NOTE 1, I-03, O-43, Q39), and through MCP only under P-75 (D6).
    ContentReader,
    /// Each person who must declare before reading the proposal, in the
    /// states where that read can follow (R-CF-02, Q9).
    Declarant,
    /// The declared assigned reviewer while P-10 lets reviewers read
    /// content, since findings quote it.
    FindingsReader,
    /// A holder of the role in the target's programme.
    Holder(Role),
    /// A holder of the role in any programme of the tenant, through an
    /// active programme binding outside the Receiving group. The creator
    /// start lists need no target programme (R-PG-02).
    HolderAnywhere(Role),
    /// Anyone who holds an invitation link, with or without an account.
    /// The invitee reads the landing before enrolling. The read model
    /// serves only the invitation that the link's token names, so the
    /// token is the capability (SoD-09).
    InvitationLink,
    /// The IRC assignee of the target IRC assignment, declared free of
    /// conflict.
    IrcAssignee,
    /// A programme manager of the target programme.
    DraftManager,
    /// An auditor of the target programme.
    Auditor,
    /// A tenant admin.
    TenantAdmin,
    /// The caller's own objects only.
    Own,
    /// Any one of these rules.
    AnyOf(&'static [ReadRule]),
}

const OPEN_ALWAYS: &[StateTag] = &StateTag::ALL;
/// The team, or in a terminal state its former lead and members (Daniel,
/// 2026-11-06).
const TEAM_OR_FORMER: ReadRule = ReadRule::AnyOf(&[ReadRule::Team, ReadRule::FormerTeam]);
const COMMITTEE: ReadRule = ReadRule::AnyOf(&[
    ReadRule::Holder(Role::CommitteeMember),
    ReadRule::Holder(Role::CommitteeChair),
]);
const DRAFT_READER: ReadRule = ReadRule::AnyOf(&[ReadRule::DraftManager, ReadRule::TenantAdmin]);
/// The creator start lists: a tenant admin, or a programme manager of any
/// programme of the tenant (R-PG-02, J1).
const CREATOR_START: ReadRule = ReadRule::AnyOf(&[
    ReadRule::HolderAnywhere(Role::ProgrammeManager),
    ReadRule::TenantAdmin,
]);
/// The readers of a proposal's route position and diary
/// (`SPEC/12-journey-ui.md` section 10): its team, or a holder of a role
/// of section 7.2 in the proposal's programme. Call drafters, tenant
/// admins and the financial and legal signatories read no diary (module
/// documentation).
const JOURNEY_READER: ReadRule = ReadRule::AnyOf(&[
    ReadRule::Team,
    ReadRule::FormerTeam,
    ReadRule::Holder(Role::FstpCoordinator),
    ReadRule::Holder(Role::ProgrammeManager),
    ReadRule::Holder(Role::CommitteeMember),
    ReadRule::Holder(Role::CommitteeChair),
    ReadRule::Holder(Role::IrcMember),
    ReadRule::Holder(Role::FinanceApprover),
    ReadRule::Holder(Role::PaymentReleaser),
    ReadRule::Holder(Role::ContractSignatory),
    ReadRule::Auditor,
]);
/// The states where the coordinator reads one proposal's assignments:
/// every state from SUBMITTED on, except INELIGIBLE. A draft is the
/// team's alone (I-21).
///
/// Interim reading, pending the lead or Daniel: R-EV-01 gives a
/// knocked-out proposal no further review, so INELIGIBLE is closed. The
/// domain opens reviewer assignment in SUBMITTED, before the knock-out,
/// and no `ReleaseCause` covers a failed knock-out. Such assignments
/// therefore stay in INELIGIBLE, and this read does not show them.
const ASSIGNABLE: &[StateTag] = &[
    StateTag::Submitted,
    StateTag::Stage1,
    StateTag::NotSelected,
    StateTag::Stage2,
    StateTag::Ranked,
    StateTag::IrcReview,
    StateTag::Deferred,
    StateTag::Declined,
    StateTag::Negotiation,
    StateTag::Withdrawn,
    StateTag::Granted,
    StateTag::InExecution,
    StateTag::Completed,
    StateTag::Terminated,
];

/// For each read, its rule and the proposal states where it is open (D11).
pub const READ_RULES: &[(ReadKind, ReadRule, &[StateTag])] = &[
    (ReadKind::ListOpenCalls, ReadRule::Public, OPEN_ALWAYS),
    (ReadKind::GetPublicCall, ReadRule::Public, OPEN_ALWAYS),
    (ReadKind::GetGuide, ReadRule::Public, OPEN_ALWAYS),
    (ReadKind::ListOwnProposals, ReadRule::Own, OPEN_ALWAYS),
    (ReadKind::GetOwnProposal, TEAM_OR_FORMER, OPEN_ALWAYS),
    (ReadKind::GetOwnWorkspace, ReadRule::Team, OPEN_ALWAYS),
    (ReadKind::GetOwnStage2Thread, TEAM_OR_FORMER, OPEN_ALWAYS),
    (ReadKind::GetOwnNotices, ReadRule::Own, OPEN_ALWAYS),
    (
        ReadKind::GetNegotiationLanding,
        ReadRule::Team,
        &[StateTag::Negotiation],
    ),
    (ReadKind::ListMyAssignments, ReadRule::Own, OPEN_ALWAYS),
    (
        ReadKind::GetDeclarationView,
        ReadRule::Declarant,
        &[
            StateTag::Submitted,
            StateTag::Stage1,
            StateTag::Stage2,
            StateTag::IrcReview,
            StateTag::Negotiation,
        ],
    ),
    (
        ReadKind::GetContent,
        ReadRule::AnyOf(&[
            ReadRule::Team,
            ReadRule::FormerTeam,
            ReadRule::ContentReader,
        ]),
        OPEN_ALWAYS,
    ),
    (
        ReadKind::GetScoreSheet,
        ReadRule::AssignedReviewer,
        &[StateTag::Stage1, StateTag::Stage2],
    ),
    (
        ReadKind::GetStage2Thread,
        ReadRule::AssignedReviewer,
        &[StateTag::Stage2],
    ),
    (
        ReadKind::GetFindings,
        ReadRule::FindingsReader,
        &[StateTag::Stage1, StateTag::Stage2],
    ),
    (ReadKind::GetRankingView, COMMITTEE, OPEN_ALWAYS),
    (ReadKind::GetCutOffRound, COMMITTEE, OPEN_ALWAYS),
    (ReadKind::ListMyIrcCases, ReadRule::Own, OPEN_ALWAYS),
    (
        ReadKind::GetIrcCase,
        ReadRule::IrcAssignee,
        &[StateTag::IrcReview],
    ),
    (
        ReadKind::GetIntakeQueue,
        ReadRule::Holder(Role::FstpCoordinator),
        OPEN_ALWAYS,
    ),
    (
        ReadKind::GetCallBoard,
        ReadRule::AnyOf(&[
            ReadRule::Holder(Role::ProgrammeManager),
            ReadRule::Holder(Role::CallDrafter),
            ReadRule::Holder(Role::FstpCoordinator),
        ]),
        OPEN_ALWAYS,
    ),
    (ReadKind::GetDraft, DRAFT_READER, OPEN_ALWAYS),
    (ReadKind::GetReport, DRAFT_READER, OPEN_ALWAYS),
    (ReadKind::GetPreview, DRAFT_READER, OPEN_ALWAYS),
    (ReadKind::GetImpact, DRAFT_READER, OPEN_ALWAYS),
    (ReadKind::ListImportProposals, DRAFT_READER, OPEN_ALWAYS),
    (ReadKind::ListInvitations, DRAFT_READER, OPEN_ALWAYS),
    (ReadKind::ListBindings, ReadRule::TenantAdmin, OPEN_ALWAYS),
    (ReadKind::GetAuditLog, ReadRule::Auditor, OPEN_ALWAYS),
    (ReadKind::GetVaultOutcomes, ReadRule::Auditor, OPEN_ALWAYS),
    (ReadKind::ListMyAgents, ReadRule::Own, OPEN_ALWAYS),
    (ReadKind::ListMyAgentActivity, ReadRule::Own, OPEN_ALWAYS),
    (ReadKind::ListMyPendingActions, ReadRule::Own, OPEN_ALWAYS),
    (ReadKind::ListMySessions, ReadRule::Own, OPEN_ALWAYS),
    (
        ReadKind::ListNotifiableConflicts,
        ReadRule::Holder(Role::FstpCoordinator),
        OPEN_ALWAYS,
    ),
    (ReadKind::ListApprovals, ReadRule::TenantAdmin, OPEN_ALWAYS),
    (
        ReadKind::GetTenantSettings,
        ReadRule::TenantAdmin,
        OPEN_ALWAYS,
    ),
    (ReadKind::GetOnboarding, ReadRule::TenantAdmin, OPEN_ALWAYS),
    (
        ReadKind::ListTenantAdmins,
        ReadRule::TenantAdmin,
        OPEN_ALWAYS,
    ),
    (
        ReadKind::ListSignatories,
        ReadRule::TenantAdmin,
        OPEN_ALWAYS,
    ),
    (ReadKind::GetActivation, ReadRule::TenantAdmin, OPEN_ALWAYS),
    (ReadKind::GetMyVerification, ReadRule::Own, OPEN_ALWAYS),
    (ReadKind::ListProgrammes, CREATOR_START, OPEN_ALWAYS),
    (ReadKind::ListTemplates, CREATOR_START, OPEN_ALWAYS),
    (
        ReadKind::GetInvitation,
        ReadRule::InvitationLink,
        OPEN_ALWAYS,
    ),
    (
        ReadKind::ListProposalAssignments,
        ReadRule::Holder(Role::FstpCoordinator),
        ASSIGNABLE,
    ),
    // I-86: the caller's own roles only.
    (ReadKind::ListMyRoles, ReadRule::Own, OPEN_ALWAYS),
    // Lane j2, section 10: the Receiving binding or permitted staff. The
    // dispatch applies the visibility function per entry (I-93).
    (ReadKind::GetJourney, JOURNEY_READER, OPEN_ALWAYS),
    (ReadKind::GetDiary, JOURNEY_READER, OPEN_ALWAYS),
    // Lane j4, section 8.1, O-58: the map is the team's alone. Judging
    // roles keep the strip of `proposal.journey` (section 8.3). Daniel,
    // 2026-11-06: the former team keeps a read-only view of all three.
    (
        ReadKind::GetRouteMap,
        ReadRule::AnyOf(&[ReadRule::Team, ReadRule::FormerTeam]),
        OPEN_ALWAYS,
    ),
];

/// The row of `READ_RULES` for `kind`.
pub fn read_rule(kind: ReadKind) -> Option<(ReadRule, &'static [StateTag])> {
    READ_RULES
        .iter()
        .find(|(k, _, _)| *k == kind)
        .map(|(_, r, s)| (*r, *s))
}

/// What a read is about. `fstp-api-core` resolves every id in the request
/// to one of these before the read is judged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReadTarget {
    /// The caller's own objects or the tenant.
    None,
    /// A programme.
    Programme(ProgrammeId),
    /// A call. A cut-off round is judged through its call until change D5
    /// adds its own id.
    Call(CallId),
    /// A proposal.
    Proposal(ProposalId),
    /// A reviewer or IRC assignment.
    Assignment(AssignmentId),
}

/// One read to judge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ReadOp {
    /// The read.
    pub kind: ReadKind,
    /// What it reads.
    pub target: ReadTarget,
}

/// The rule text a refused read names. It never names an account
/// (R-CF-03).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DenyRule {
    /// The caller has no account, so no actor rule admits it.
    Actor,
    /// R-AC-01: the read is not open to the caller here.
    Rac01,
    /// I-21: drafts are the team's alone.
    I21,
    /// R-CF-02: the caller must declare first.
    Rcf02,
    /// I-03: the caller has a conflict on the proposal.
    I03,
    /// P-75: a reviewer's agent may not read full content.
    P75,
    /// The target does not exist.
    Input,
}

impl DenyRule {
    /// The rule as `ApiError` carries it, such as `"R-AC-01"`.
    pub const fn spec_id(self) -> &'static str {
        match self {
            DenyRule::Actor => "actor",
            DenyRule::Rac01 => "R-AC-01",
            DenyRule::I21 => "I-21",
            DenyRule::Rcf02 => "R-CF-02",
            DenyRule::I03 => "I-03",
            DenyRule::P75 => "P-75",
            DenyRule::Input => "Input",
        }
    }

    /// The order in which one refusal of an `AnyOf` rule wins over
    /// another: a conflict outranks a missing declaration, which outranks
    /// P-75 and plain visibility.
    const fn rank(self) -> u8 {
        match self {
            DenyRule::Input => 6,
            DenyRule::I03 => 5,
            DenyRule::Rcf02 => 4,
            DenyRule::P75 => 3,
            DenyRule::I21 => 2,
            DenyRule::Rac01 => 1,
            DenyRule::Actor => 0,
        }
    }
}

/// A refused read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Denied {
    rule: DenyRule,
}

impl Denied {
    const fn new(rule: DenyRule) -> Denied {
        Denied { rule }
    }

    /// The rule that refused.
    pub const fn rule(&self) -> DenyRule {
        self.rule
    }
}

impl std::fmt::Display for Denied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "read refused ({})", self.rule.spec_id())
    }
}

impl std::error::Error for Denied {}

/// A cleared read. Only [`authorize_read`] builds one, so a read model
/// that takes it cannot be served without the judgement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ReadClearance {
    op: ReadOp,
    account: Option<AccountId>,
    rule: ReadRule,
}

impl ReadClearance {
    /// The read it clears.
    pub const fn op(&self) -> ReadOp {
        self.op
    }

    /// The reader's account, if any.
    pub const fn account(&self) -> Option<AccountId> {
        self.account
    }

    /// The rule that admitted the read. It is never `AnyOf`.
    pub const fn rule(&self) -> ReadRule {
        self.rule
    }
}

/// What the projection says about a read's target.
struct Context<'a> {
    programme: Option<ProgrammeId>,
    call: Option<CallId>,
    proposal: Option<ProposalId>,
    assignment: Option<&'a Assignment>,
    state: Option<StateTag>,
    /// The target is withheld from the public: a call not yet published,
    /// or a target that does not exist.
    unpublished: bool,
}

impl Context<'_> {
    /// The context of a target that does not exist. No relation holds in
    /// it, and the public sees nothing of it.
    const fn unknown() -> Context<'static> {
        Context {
            programme: None,
            call: None,
            proposal: None,
            assignment: None,
            state: None,
            unpublished: true,
        }
    }
}

/// Judges one read (design section 3.6): its rule, then the proposal
/// states where it is open. Total and pure.
///
/// A target that does not exist is judged against a context in which no
/// relation holds. A caller that context refuses gets the rule's own
/// refusal, the same as for an existing target outside the caller's
/// relations. Only a caller the rule admits whatever the target gets
/// [`DenyRule::Input`] (R-AC-01).
pub fn authorize_read(
    op: &ReadOp,
    p: &Principal,
    state: &EngineState,
    now: Timestamp,
) -> Result<ReadClearance, Denied> {
    let Some((rule, open)) = read_rule(op.kind) else {
        return Err(Denied::new(DenyRule::Rac01));
    };
    let account = p.account();
    if account.is_none() && !admits_anyone(rule) {
        return Err(Denied::new(DenyRule::Actor));
    }
    // Drafts are the team's alone (I-21), so a workspace refusal names it.
    let closed = |d: Denied| match (op.kind, d.rule) {
        (ReadKind::GetOwnWorkspace, DenyRule::Rac01) => Denied::new(DenyRule::I21),
        _ => d,
    };
    let ctx = match context(&state.core, op.target) {
        Ok(ctx) => ctx,
        Err(unknown) => {
            judge(rule, p, &state.core, &Context::unknown(), now).map_err(closed)?;
            return Err(unknown);
        }
    };
    let matched = judge(rule, p, &state.core, &ctx, now).map_err(closed)?;
    if let Some(s) = ctx.state
        && !open.contains(&s)
    {
        return Err(closed(Denied::new(DenyRule::Rac01)));
    }
    Ok(ReadClearance {
        op: *op,
        account,
        rule: matched,
    })
}

fn admits_anyone(rule: ReadRule) -> bool {
    match rule {
        ReadRule::Public | ReadRule::InvitationLink => true,
        ReadRule::AnyOf(rules) => rules.iter().any(|r| admits_anyone(*r)),
        _ => false,
    }
}

/// Resolves the target in the projection. An unknown target refuses with
/// [`DenyRule::Input`], which [`authorize_read`] passes on only to a
/// caller the rule admits whatever the target.
fn context(state: &State, target: ReadTarget) -> Result<Context<'_>, Denied> {
    let unknown = Denied::new(DenyRule::Input);
    let mut ctx = Context {
        programme: None,
        call: None,
        proposal: None,
        assignment: None,
        state: None,
        unpublished: false,
    };
    match target {
        ReadTarget::None => {}
        ReadTarget::Programme(p) => ctx.programme = Some(p),
        ReadTarget::Call(c) => {
            let call = state.calls().get(c).ok_or(unknown)?;
            ctx.call = Some(c);
            ctx.programme = Some(call.programme());
            ctx.unpublished = call.frozen().is_none();
        }
        ReadTarget::Proposal(x) => {
            ctx.state = Some(fstp_domain::view::proposal_state(state, x).ok_or(unknown)?);
            ctx.proposal = Some(x);
            if let Some((programme, call)) = proposal_home(state, x) {
                ctx.programme = Some(programme);
                ctx.call = Some(call);
            }
        }
        ReadTarget::Assignment(a) => {
            let assignment = state.review().get(a).ok_or(unknown)?;
            let x = assignment.proposal;
            ctx.state = Some(fstp_domain::view::proposal_state(state, x).ok_or(unknown)?);
            ctx.proposal = Some(x);
            ctx.call = Some(assignment.call);
            ctx.programme = state.calls().get(assignment.call).map(|c| c.programme());
            ctx.assignment = Some(assignment);
        }
    }
    Ok(ctx)
}

/// The programme and call of `proposal`: those of its Receiving binding
/// with the latest call, held, voided or ended. Every proposal has one,
/// since creating a draft binds its lead.
fn proposal_home(state: &State, proposal: ProposalId) -> Option<(ProgrammeId, CallId)> {
    let roster = state.roster();
    roster
        .bindings()
        .map(|(_, b)| *b)
        .chain(roster.ended().map(|(_, e)| e.binding))
        .filter_map(|b| match b.scope {
            BindingScope::Proposal { proposal: x, call } if x == proposal => {
                Some((b.opened, b.start, b.programme, call))
            }
            _ => None,
        })
        .max()
        .map(|(_, _, programme, call)| (programme, call))
}

/// Judges one rule. An `AnyOf` admits through its first admitting rule
/// and otherwise refuses with its strongest refusal.
fn judge(
    rule: ReadRule,
    p: &Principal,
    state: &State,
    ctx: &Context<'_>,
    now: Timestamp,
) -> Result<ReadRule, Denied> {
    let deny = |r: DenyRule| Err(Denied::new(r));
    let open = |ok: bool| {
        if ok {
            Ok(rule)
        } else {
            Err(Denied::new(DenyRule::Rac01))
        }
    };
    // A call is public only once it is published (R-AC-01, R-GA-01).
    let Some(account) = p.account() else {
        return match rule {
            ReadRule::Public => open(!ctx.unpublished),
            ReadRule::InvitationLink => Ok(rule),
            ReadRule::AnyOf(rules) => any_of(rules, p, state, ctx, now),
            _ => deny(DenyRule::Actor),
        };
    };
    match rule {
        ReadRule::Public => open(!ctx.unpublished),
        ReadRule::Own | ReadRule::InvitationLink => Ok(rule),
        ReadRule::HolderAnywhere(role) => open(holds_anywhere(state, account, role, now)),
        ReadRule::TenantAdmin => open(p.tenant_admin()),
        ReadRule::Team => match ctx.proposal {
            Some(x) => open(team(state, account, x, now)),
            None => deny(DenyRule::Rac01),
        },
        ReadRule::FormerTeam => match (ctx.proposal, ctx.state) {
            (Some(x), Some(s)) if s.is_terminal() => open(former_team(state, account, x)),
            _ => deny(DenyRule::Rac01),
        },
        ReadRule::Lead => match ctx.proposal {
            Some(x) => open(receiving(state, account, x, Role::Applicant, now)),
            None => deny(DenyRule::Rac01),
        },
        ReadRule::Holder(role) => open(holds_in(state, account, role, ctx.programme, now)),
        ReadRule::DraftManager => open(holds_in(
            state,
            account,
            Role::ProgrammeManager,
            ctx.programme,
            now,
        )),
        ReadRule::Auditor => open(holds_in(state, account, Role::Auditor, ctx.programme, now)),
        ReadRule::Assignee => match ctx.assignment {
            Some(a) => open(a.reviewer == account && a.unreleased()),
            None => deny(DenyRule::Rac01),
        },
        ReadRule::AssignedReviewer => {
            declared_assignee(state, account, ctx, AssignmentKind::Reviewer, now).map(|()| rule)
        }
        ReadRule::IrcAssignee => {
            declared_assignee(state, account, ctx, AssignmentKind::Irc, now).map(|()| rule)
        }
        ReadRule::FindingsReader => {
            declared_assignee(state, account, ctx, AssignmentKind::Reviewer, now)?;
            open(p10(state, ctx) != Some(ReadAccess::OperatorStaffOnly))
        }
        ReadRule::ContentReader => content(p, account, state, ctx, now).map(|()| rule),
        ReadRule::Declarant => declarant(state, account, ctx, now).map(|()| rule),
        ReadRule::AnyOf(rules) => any_of(rules, p, state, ctx, now),
    }
}

fn any_of(
    rules: &'static [ReadRule],
    p: &Principal,
    state: &State,
    ctx: &Context<'_>,
    now: Timestamp,
) -> Result<ReadRule, Denied> {
    let mut worst: Option<Denied> = None;
    for r in rules {
        match judge(*r, p, state, ctx, now) {
            Ok(matched) => return Ok(matched),
            Err(d) => {
                if worst.is_none_or(|w| d.rule.rank() > w.rule.rank()) {
                    worst = Some(d);
                }
            }
        }
    }
    Err(worst.unwrap_or(Denied::new(DenyRule::Rac01)))
}

/// Whether `account` holds an active Receiving binding of `role` on
/// `proposal` at `now`.
fn receiving(
    state: &State,
    account: AccountId,
    proposal: ProposalId,
    role: Role,
    now: Timestamp,
) -> bool {
    state.roster().bindings().any(|(_, b)| {
        b.account == account && b.role == role && b.proposal() == Some(proposal) && b.active_at(now)
    })
}

/// Whether `account` is in the applicant team of `proposal` at `now`.
fn team(state: &State, account: AccountId, proposal: ProposalId, now: Timestamp) -> bool {
    [Role::Applicant, Role::ApplicantTeamMember, Role::Guardian]
        .iter()
        .any(|r| receiving(state, account, proposal, *r, now))
}

/// Whether `account` held a Receiving binding of lead or team member on
/// `proposal` that was active when it ended. The caller checks that the
/// proposal is terminal, where the domain ends these bindings. A voided
/// or suspended binding gives no such read. The guardian gets none: the
/// decision of 2026-11-06 names the lead and the team members.
fn former_team(state: &State, account: AccountId, proposal: ProposalId) -> bool {
    state.roster().ended().any(|(_, e)| {
        let b = e.binding;
        b.account == account
            && matches!(b.role, Role::Applicant | Role::ApplicantTeamMember)
            && b.proposal() == Some(proposal)
            && matches!(b.status, BindingStatus::Active)
    })
}

/// Whether `account` holds an active programme binding of `role` in
/// `programme` at `now`.
fn holds_in(
    state: &State,
    account: AccountId,
    role: Role,
    programme: Option<ProgrammeId>,
    now: Timestamp,
) -> bool {
    let Some(programme) = programme else {
        return false;
    };
    state.roster().bindings().any(|(_, b)| {
        b.account == account
            && b.role == role
            && b.programme == programme
            && b.scope == BindingScope::Programme
            && b.group() != Group::Receiving
            && b.active_at(now)
    })
}

/// Whether `account` holds an active programme binding of `role` in any
/// programme at `now`, outside the Receiving group.
fn holds_anywhere(state: &State, account: AccountId, role: Role, now: Timestamp) -> bool {
    state.roster().bindings().any(|(_, b)| {
        b.account == account
            && b.role == role
            && b.scope == BindingScope::Programme
            && b.group() != Group::Receiving
            && b.active_at(now)
    })
}

/// The assignee check of the score sheet, the stage 2 thread, the
/// findings and the IRC case. The target assignment must be the caller's
/// and of `kind`. A conflict refuses with I-03 and a missing declaration
/// with R-CF-02 (R-CF-02, I-03). A released assignment, or one over an
/// inactive binding, refuses with R-AC-01.
fn declared_assignee(
    state: &State,
    account: AccountId,
    ctx: &Context<'_>,
    kind: AssignmentKind,
    now: Timestamp,
) -> Result<(), Denied> {
    let (Some(a), Some(x)) = (ctx.assignment, ctx.proposal) else {
        return Err(Denied::new(DenyRule::Rac01));
    };
    if a.reviewer != account || a.kind != kind {
        return Err(Denied::new(DenyRule::Rac01));
    }
    if state.review().conflict_fact(account, x) {
        return Err(Denied::new(DenyRule::I03));
    }
    match a.status {
        AssignmentStatus::AwaitingDeclaration => Err(Denied::new(DenyRule::Rcf02)),
        AssignmentStatus::Released(_) => Err(Denied::new(DenyRule::Rac01)),
        AssignmentStatus::Active => {
            if holds_in(state, account, kind.role(), ctx.programme, now) {
                Ok(())
            } else {
                Err(Denied::new(DenyRule::Rac01))
            }
        }
    }
}

/// The unreleased assignment of `kind` that `account` holds on `proposal`,
/// if any.
fn own_assignment(
    state: &State,
    account: AccountId,
    proposal: ProposalId,
    kind: AssignmentKind,
) -> Option<&Assignment> {
    state
        .review()
        .assignments()
        .map(|(_, a)| a)
        .filter(|a| {
            a.reviewer == account && a.proposal == proposal && a.kind == kind && a.unreleased()
        })
        .max_by_key(|a| a.status == AssignmentStatus::Active)
}

/// P-10 of the call that governs the target, once the call is published.
fn p10(state: &State, ctx: &Context<'_>) -> Option<ReadAccess> {
    let call = state.calls().get(ctx.call?)?;
    call.frozen().map(|f| f.values().p10)
}

/// Whether P-75 is on for the call that governs the target: its typed
/// frozen value since change D6. An unpublished or unknown call keeps it
/// off.
fn p75_on(state: &State, ctx: &Context<'_>) -> bool {
    let Some(call) = ctx.call.and_then(|c| state.calls().get(c)) else {
        return false;
    };
    call.frozen()
        .is_some_and(|f| f.values().p75 == AgentContentAccess::On)
}

/// Full content of the proposal for a reader outside the team (R-AC-01,
/// P-10 NOTE 1, I-03, R-CF-02, D6, Q39):
///
/// - SUBMITTED: the coordinator who declared on the proposal;
/// - STAGE1 and STAGE2: under "assigned reviewers only", the declared
///   assigned reviewer; under "all committee members", also a committee
///   member who declared on the proposal; under "operator staff only",
///   only the declared coordinator (O-43);
/// - IRC_REVIEW: the declared IRC assignee;
/// - NEGOTIATION: the declared assigned reviewer, for the amount;
/// - every other state: nobody outside the team.
///
/// Through MCP, P-75 must be on as well. The domain's own check must agree.
fn content(
    p: &Principal,
    account: AccountId,
    state: &State,
    ctx: &Context<'_>,
    now: Timestamp,
) -> Result<(), Denied> {
    let (Some(x), Some(s)) = (ctx.proposal, ctx.state) else {
        return Err(Denied::new(DenyRule::Rac01));
    };
    if state.review().conflict_fact(account, x) {
        return Err(Denied::new(DenyRule::I03));
    }
    let coordinator = || {
        if !holds_in(state, account, Role::FstpCoordinator, ctx.programme, now) {
            Err(Denied::new(DenyRule::Rac01))
        } else if state.review().cleared(account, x) {
            Ok(())
        } else {
            Err(Denied::new(DenyRule::Rcf02))
        }
    };
    let assignee = |kind: AssignmentKind| match own_assignment(state, account, x, kind) {
        Some(a) if a.active() && holds_in(state, account, kind.role(), ctx.programme, now) => {
            Ok(())
        }
        Some(a) if a.status == AssignmentStatus::AwaitingDeclaration => {
            Err(Denied::new(DenyRule::Rcf02))
        }
        _ => Err(Denied::new(DenyRule::Rac01)),
    };
    let basis = match s {
        StateTag::Submitted => coordinator(),
        StateTag::Stage1 | StateTag::Stage2 => match p10(state, ctx) {
            Some(ReadAccess::OperatorStaffOnly) => coordinator(),
            Some(ReadAccess::AssignedReviewersOnly) => assignee(AssignmentKind::Reviewer),
            Some(ReadAccess::AllCommitteeMembers) => match assignee(AssignmentKind::Reviewer) {
                Ok(()) => Ok(()),
                Err(e) => {
                    if holds_in(state, account, Role::CommitteeMember, ctx.programme, now) {
                        if state.review().cleared(account, x) {
                            Ok(())
                        } else {
                            Err(Denied::new(DenyRule::Rcf02))
                        }
                    } else {
                        Err(e)
                    }
                }
            },
            None => Err(Denied::new(DenyRule::Rac01)),
        },
        StateTag::IrcReview => assignee(AssignmentKind::Irc),
        StateTag::Negotiation => assignee(AssignmentKind::Reviewer),
        _ => Err(Denied::new(DenyRule::Rac01)),
    };
    basis?;
    if p.via() == Via::Mcp && !p75_on(state, ctx) {
        return Err(Denied::new(DenyRule::P75));
    }
    if !fstp_domain::visibility::can_read_content(state, account, x, now) {
        return Err(Denied::new(DenyRule::Rac01));
    }
    Ok(())
}

/// The title and neutral summary before a declaration (R-CF-02, Q9). It
/// opens to the coordinator in SUBMITTED, and in STAGE1 and STAGE2 under
/// "operator staff only"; to the reviewer assignee in SUBMITTED, STAGE1,
/// STAGE2 and NEGOTIATION; to every committee member in STAGE1 and STAGE2
/// under "all committee members"; and to the IRC assignee in IRC_REVIEW.
/// A conflict refuses it.
fn declarant(
    state: &State,
    account: AccountId,
    ctx: &Context<'_>,
    now: Timestamp,
) -> Result<(), Denied> {
    let (Some(x), Some(s)) = (ctx.proposal, ctx.state) else {
        return Err(Denied::new(DenyRule::Rac01));
    };
    if state.review().conflict_fact(account, x) {
        return Err(Denied::new(DenyRule::I03));
    }
    let staged = matches!(s, StateTag::Stage1 | StateTag::Stage2);
    let p10 = p10(state, ctx);
    let holds = |role: Role| holds_in(state, account, role, ctx.programme, now);
    let assigned = |kind: AssignmentKind| {
        own_assignment(state, account, x, kind).is_some() && holds(kind.role())
    };
    let coordinator = holds(Role::FstpCoordinator)
        && (s == StateTag::Submitted || (staged && p10 == Some(ReadAccess::OperatorStaffOnly)));
    let reviewer = assigned(AssignmentKind::Reviewer)
        && (staged || matches!(s, StateTag::Submitted | StateTag::Negotiation));
    let committee =
        holds(Role::CommitteeMember) && staged && p10 == Some(ReadAccess::AllCommitteeMembers);
    let irc = assigned(AssignmentKind::Irc) && s == StateTag::IrcReview;
    if coordinator || reviewer || committee || irc {
        Ok(())
    } else {
        Err(Denied::new(DenyRule::Rac01))
    }
}
