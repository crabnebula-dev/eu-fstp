//! Core commands and the command context (design sections 3.1 and 3.3).
//!
//! - No command names a target state. `decide` computes every outcome
//!   (design section 3.5).
//! - The shell supplies every new id inside the command.
//! - [`CommandKind`] is the fieldless tag of a command. The actor rule of
//!   each kind is in [`crate::rules::ACTOR_RULES`], the single source for
//!   the M4 authorisation matrix and MCP parity (I-84).

use std::collections::BTreeSet;

use fstp_money::NonNegAmount;

use crate::amendment::AmendmentRoute;
use crate::assignment::AssignmentKind;
use crate::decision::{IrcVerdict, Vote};
use crate::grant::IneligibleCost;
use crate::id::{
    AccountId, AmendmentId, AssignmentId, BindingId, CallId, CommandId, ContentDigest, ContractId,
    DecisionId, DeliverableId, Handle, KnockOutCriterionId, LineId, LlmConfigId, MilestoneId,
    OrganisationId, PlanVersionId, PolicyVersionId, ProgrammeId, ProposalId, RequestId, TextRef,
    VaultEpoch,
};
use crate::payment::{CheckPhase, CheckResult, PaymentKind, PaymentLine};
use crate::policy::activation::ReportDigest;
use crate::policy::{ModelRef, PolicyVersion, SpdxId};
use crate::proposal::{EthicsDeclaration, NoticeVersion, PlanOrigin, Task};
use crate::roles::Role;
use crate::scoring::{ScoreKey, ScoreVector};
use crate::time::{Timestamp, ZoneName};

/// The context of one command, supplied by the shell.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ctx {
    /// The instant the shell read once for this command. `decide` never reads a clock.
    pub now: Timestamp,
    /// Who issues the command.
    pub actor: Actor,
    /// The idempotency key.
    pub command: CommandId,
    /// The channel the command arrived through.
    pub via: Via,
    /// Whether the shell attests that the actor is a tenant admin at tenant
    /// scope, from the M3 and M4 tenant configuration.
    ///
    /// [`crate::rules::ActorRule::TenantAdmin`] reads it for the actor check.
    /// Lane L-LIFE also reads it for SoD-03 at `CreateDraft`, where the actor
    /// is the account that the new Receiving binding binds.
    pub tenant_admin: bool,
    /// The second tenant admin whose approval of this command the shell
    /// verified, from the M3 and M4 tenant configuration (SoD-07).
    ///
    /// Lane L-SOD admits a self-grant only when `GrantRole::second_admin`
    /// names this account and it differs from the actor. `None` when no
    /// second admin approved.
    pub second_tenant_admin: Option<AccountId>,
    /// Whether the shell attests that the account this command binds holds a
    /// tenant-wide Operations role: tenant admin at tenant scope, or Financial
    /// or Legal signatory (NOTE 5). That account is `GrantRole::account`,
    /// `AddTeamMember::account` or `AddGuardian::account`, and the actor for
    /// `CreateDraft`. It is `false` for every other command.
    ///
    /// Lane L-LIFE reads it for SoD-03 at `AddTeamMember` and `AddGuardian`.
    /// A tenant admin at tenant scope counts as holding an Operations role in
    /// every programme of the tenant. The role is tenant-wide, the shell
    /// attests it, and the Roles table places it in Operations
    /// (`SPEC/02-domain/roles-and-sod.md`, confirmed 2026-10-25).
    /// The signatory roles are tenant-wide Operations roles too (SA-01), so
    /// the shell sets this flag for their holders as well.
    pub binds_tenant_admin: bool,
}

/// Who issues a command. There is no assessor variant, so findings can
/// never issue a core command (I-10).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Actor {
    /// A named human, by tenant account.
    Account(AccountId),
    /// The platform itself.
    System(SystemCause),
}

/// What made the platform issue a System command.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SystemCause {
    /// A deadline or start date reached, from `due` and the M6 timeline.
    Timeline,
    /// A vault epoch change (enforcement point 3).
    Vault,
    /// A fact from the M5 contract port.
    ContractPort,
    /// A fact from the M5 payment port.
    PaymentPort,
}

/// The channel a command arrived through (I-84, I-85, R-MC-05).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Via {
    /// The web interface.
    Web,
    /// The MCP server.
    Mcp,
}

/// What a conflict declaration is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DeclarationSubject {
    /// An assignment awaiting its declaration (R-CF-02).
    Assignment(AssignmentId),
    /// A proposal, for the FSTP coordinator before the knock-out read, and for
    /// committee members under P-10 "all committee members".
    Proposal(ProposalId),
}

/// The result of one P-09 knock-out criterion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KnockOutResult {
    /// The criterion.
    pub criterion: KnockOutCriterionId,
    /// Whether the proposal passed it.
    pub passed: bool,
}

/// A fact from the M5 contract port.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ContractEvent {
    /// The contract became EFFECTIVE (`SPEC/02-domain/contracts.md`).
    Effective,
}

/// A core command. Field order follows the design's command catalogue.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Command {
    /// Create a programme with its first policy version (R-PC-01).
    CreateProgramme {
        /// The first policy version. Its `programme` names the new programme.
        policy: Box<PolicyVersion>,
    },
    /// Activate a draft programme (I-66, I-67, M4 change D2). The approver
    /// is the actor, a tenant admin outside the builder set. The engine
    /// composes it from the creator's approval only (D2e).
    ActivateProgramme {
        /// The draft programme.
        programme: ProgrammeId,
        /// The activation decision.
        decision: DecisionId,
        /// The digest of the clean validation report the creator recomputed.
        report: ReportDigest,
        /// The draft revision the report covers.
        revision: u32,
        /// The builders the creator knows beyond the core's own: creator
        /// record authors, import resolvers and acknowledgers (Q1).
        creator_builders: BTreeSet<AccountId>,
    },
    /// Append a new policy version on top of the current head (I-23).
    EditPolicy {
        /// The version the edit was made against. It must be the head.
        base: PolicyVersionId,
        /// The new version, whose parent is `base`.
        version: Box<PolicyVersion>,
    },
    /// Draft a call.
    DraftCall {
        /// The new call.
        call: CallId,
        /// Its programme.
        programme: ProgrammeId,
        /// Opening time.
        opens: Timestamp,
        /// Deadline as a UTC instant.
        deadline: Timestamp,
        /// Deadline zone, kept as text.
        deadline_zone: ZoneName,
        /// Call budget, display-only once published.
        budget: NonNegAmount,
        /// Call text.
        text: TextRef,
    },
    /// Edit an unpublished call.
    EditCall {
        /// The call.
        call: CallId,
        /// Opening time.
        opens: Timestamp,
        /// Deadline as a UTC instant.
        deadline: Timestamp,
        /// Deadline zone, kept as text.
        deadline_zone: ZoneName,
        /// Call budget.
        budget: NonNegAmount,
        /// Call text.
        text: TextRef,
    },
    /// Approve publication by a person other than the drafters (R-PC-03).
    ApproveCallPublication {
        /// The call.
        call: CallId,
        /// The approval decision.
        decision: DecisionId,
    },
    /// Publish an approved call, freezing the head policy (I-12, R-PC-02).
    PublishCall {
        /// The call.
        call: CallId,
        /// The pinned LLM configuration (I-11, R-LA-05).
        config: LlmConfigId,
        /// The configuration's model, which must equal the frozen P-21 primary.
        config_model: ModelRef,
    },
    /// Grant a Drafting, Judging or Operations role in a programme.
    GrantRole {
        /// The new binding.
        binding: BindingId,
        /// The account.
        account: AccountId,
        /// The programme.
        programme: ProgrammeId,
        /// The role.
        role: Role,
        /// Start of the binding, never before `ctx.now`.
        start: Timestamp,
        /// The approving second tenant admin of a self-grant (SoD-07).
        second_admin: Option<AccountId>,
        /// Accepted confidentiality terms, for Drafting and Judging roles.
        confidentiality: Option<TextRef>,
        /// The reviewer's organisation, for committee bindings (I-34).
        organisation: Option<OrganisationId>,
        /// A scheduled end, after `start` (Cooling-off NOTE, decided
        /// 2026-10-25). The binding stays held until the instant.
        end: Option<Timestamp>,
    },
    /// End an active binding.
    ///
    /// At `ctx.now` the binding ends at once. A later instant schedules
    /// the end, or brings an earlier scheduled end forward (Cooling-off
    /// NOTE, decided 2026-10-25).
    EndRole {
        /// The binding.
        binding: BindingId,
        /// End time, never before `ctx.now`.
        at: Timestamp,
    },
    /// Record the scheduled end of a binding once its instant is reached.
    /// [`crate::due`] lists it with a System actor from the instant on
    /// (Cooling-off NOTE, decided 2026-10-25).
    EndScheduledRole {
        /// The binding.
        binding: BindingId,
    },
    /// Reinstate a suspended binding after resolution.
    ReinstateBinding {
        /// The binding.
        binding: BindingId,
        /// The recorded reason.
        reason: TextRef,
    },
    /// Process a newer vault epoch (enforcement point 3).
    ///
    /// The driver first asks `ChangedSince { epoch: state.epoch }` at the new
    /// epoch and puts the answer's accounts in `changed`. The queries of the
    /// batch, such as `SameIdentityAsAny`, `InExcludedClass`, `HasConflict` and
    /// `AllRecipientsWithinCap`, then follow from `changed` and the state in
    /// one round. `queries` asks `ChangedSince` again, and lane L-SOD refuses
    /// with `StaleFacts` unless that answer lists exactly `changed`.
    VaultChanged {
        /// The new epoch.
        epoch: VaultEpoch,
        /// The accounts whose vault facts changed since `state.epoch`.
        changed: BTreeSet<AccountId>,
    },
    /// Create a draft proposal and the lead's Applicant binding.
    CreateDraft {
        /// The new proposal.
        proposal: ProposalId,
        /// Its call.
        call: CallId,
        /// The lead's new Receiving binding.
        binding: BindingId,
        /// Whether the lead is flagged as a minor (R-ID-04 seam).
        minor: bool,
    },
    /// Add a team member and their Receiving binding.
    AddTeamMember {
        /// The proposal.
        proposal: ProposalId,
        /// The member's account.
        account: AccountId,
        /// The new Receiving binding.
        binding: BindingId,
    },
    /// Add a guardian and their Receiving binding.
    AddGuardian {
        /// The proposal.
        proposal: ProposalId,
        /// The guardian's account.
        account: AccountId,
        /// The new Receiving binding.
        binding: BindingId,
    },
    /// Record a plan version.
    RecordPlanVersion {
        /// The new plan version.
        plan: PlanVersionId,
        /// The proposal.
        proposal: ProposalId,
        /// Where it comes from.
        origin: PlanOrigin,
        /// The version it supersedes.
        supersedes: Option<PlanVersionId>,
        /// Tasks with their milestones.
        tasks: Vec<Task>,
        /// Digest of the plan text held outside the domain.
        content: ContentDigest,
    },
    /// Submit a draft (DRAFT to SUBMITTED).
    Submit {
        /// The proposal.
        proposal: ProposalId,
        /// The submitted plan version.
        plan: PlanVersionId,
        /// The ethics self-declaration (R-SB-05).
        ethics: EthicsDeclaration,
        /// The data protection notice version shown (R-NG-06).
        notice: NoticeVersion,
    },
    /// Declare whether a conflict exists (R-CF-02, R-CF-04).
    DeclareConflict {
        /// What the declaration is about.
        subject: DeclarationSubject,
        /// Whether the declarer is conflicted.
        conflicted: bool,
        /// Whether the conflict is notifiable (R-CF-04).
        notifiable: bool,
    },
    /// Assign a reviewer or IRC member to a proposal.
    Assign {
        /// The new assignment.
        assignment: AssignmentId,
        /// The proposal.
        proposal: ProposalId,
        /// The assignee.
        reviewer: AccountId,
        /// The kind of assignment.
        kind: AssignmentKind,
        /// A never-issued handle under P-11 anonymous (R-AN-01).
        handle: Option<Handle>,
    },
    /// Release an assignment.
    Unassign {
        /// The assignment.
        assignment: AssignmentId,
    },
    /// Read a proposal's full content (R-AC-01, R-AU-01).
    ReadContent {
        /// The proposal.
        proposal: ProposalId,
    },
    /// Record the knock-out check. A failed criterion makes the proposal INELIGIBLE.
    RecordKnockOut {
        /// The decision.
        decision: DecisionId,
        /// The proposal.
        proposal: ProposalId,
        /// One result per P-09 criterion.
        outcomes: Vec<KnockOutResult>,
        /// The reason, required when a criterion failed.
        reason: Option<TextRef>,
    },
    /// Admit a proposal whose knock-out check passed (SUBMITTED to STAGE1).
    AdmitToStage1 {
        /// The decision.
        decision: DecisionId,
        /// The proposal.
        proposal: ProposalId,
    },
    /// Record a score.
    RecordScore {
        /// Assignment, stage and plan.
        key: ScoreKey,
        /// One value per criterion.
        values: ScoreVector,
    },
    /// Correct a score before its stage seals.
    CorrectScore {
        /// Assignment, stage and plan.
        key: ScoreKey,
        /// The corrected values.
        values: ScoreVector,
        /// The recorded reason.
        reason: TextRef,
    },
    /// Record the title, neutral summary and rationale that the committee
    /// ranking view shows (`SPEC/02-domain/roles-and-sod.md`, R-AC-01).
    /// They are written without identifying the applicant (I-17).
    RecordRankingSummary {
        /// The proposal.
        proposal: ProposalId,
        /// The writing reviewer's assignment.
        assignment: AssignmentId,
        /// The title.
        title: TextRef,
        /// The neutral summary.
        neutral_summary: TextRef,
        /// The reviewers' rationale.
        rationale: TextRef,
    },
    /// Record the stage 1 close. It carries no outcome, which is computed (I-07, I-08, NOTE 3).
    CloseStage1 {
        /// The proposal.
        proposal: ProposalId,
    },
    /// Ask a stage 2 question (R-EV-05).
    AskQuestion {
        /// The proposal.
        proposal: ProposalId,
        /// The asking reviewer's assignment.
        assignment: AssignmentId,
        /// The question.
        text: TextRef,
    },
    /// Record "no questions" in stage 2 (NOTE 4).
    RecordNoQuestions {
        /// The proposal.
        proposal: ProposalId,
        /// The recording reviewer's assignment.
        assignment: AssignmentId,
    },
    /// Answer the stage 2 questions.
    AnswerQuestions {
        /// The proposal.
        proposal: ProposalId,
        /// The answers.
        text: TextRef,
    },
    /// Submit a revised plan for rescoring.
    SubmitRevision {
        /// The proposal.
        proposal: ProposalId,
        /// The revised plan version.
        plan: PlanVersionId,
    },
    /// Rank a proposal after stage 2 (STAGE2 to RANKED). The effective score is computed (I-09).
    RankAfterStage2 {
        /// The proposal.
        proposal: ProposalId,
    },
    /// Defer a proposal whose stage 2 window elapsed (STAGE2 to DEFERRED).
    ExpireStage2 {
        /// The proposal.
        proposal: ProposalId,
    },
    /// Open a cut-off round of a call (M4 change D5, R-EV-08). Members then
    /// cast or delegate their own ballots in it.
    OpenCutOffRound {
        /// The new round, the decision id of its cut-off.
        round: DecisionId,
        /// The call.
        call: CallId,
        /// The total order of the call's RANKED proposals.
        order: Vec<ProposalId>,
        /// The cut-off rank position.
        nominated: u32,
        /// The recorded rationale (R-EV-08).
        rationale: TextRef,
        /// The recorded P-17 tie-break, if any.
        tie_breaks: Option<TextRef>,
    },
    /// Cast the actor's own ballot in a round (R-EV-09, D5). It names no
    /// voter, so no member states another member's vote.
    CastBallot {
        /// The round.
        round: DecisionId,
        /// The vote.
        vote: Vote,
    },
    /// Delegate the actor's own vote in a round to another committee
    /// member (P-16 NOTE 8, D5).
    DelegateVote {
        /// The round.
        round: DecisionId,
        /// The member who holds the vote.
        to: AccountId,
    },
    /// Record the cut-off of a round. It counts only the ballots cast in
    /// the round under P-16, and outcomes are computed per proposal (NOTE 6).
    RecordCutOff {
        /// The round.
        round: DecisionId,
    },
    /// Record one IRC review.
    RecordIrcReview {
        /// The IRC assignment.
        assignment: AssignmentId,
        /// The verdict.
        verdict: IrcVerdict,
    },
    /// Decline after a concern when no future call exists (IRC_REVIEW to DECLINED).
    DeclineAfterConcern {
        /// The proposal.
        proposal: ProposalId,
    },
    /// Re-enter a deferred proposal in the next call (NOTE 8).
    ReEnter {
        /// The proposal.
        proposal: ProposalId,
        /// The next call.
        call: CallId,
    },
    /// Determine the grant amount and reserve cap headroom (R-NG-03, I-13, I-14).
    DetermineAmount {
        /// The decision.
        decision: DecisionId,
        /// The proposal.
        proposal: ProposalId,
        /// The agreed plan version.
        agreed: PlanVersionId,
        /// Recorded deductions for ineligible costs.
        deductions: Vec<IneligibleCost>,
    },
    /// The applicant accepts the grant of the current amount (NOTE 9).
    AcceptGrant {
        /// The decision.
        decision: DecisionId,
        /// The proposal.
        proposal: ProposalId,
        /// The amount determination accepted, by its decision id. It must
        /// be the current one (R-NG-03, NOTE 9, decided 2026-10-28).
        determination: DecisionId,
    },
    /// The programme manager approves the grant of the current amount
    /// (NOTE 9).
    ApproveGrant {
        /// The decision.
        decision: DecisionId,
        /// The proposal.
        proposal: ProposalId,
        /// The amount determination approved, by its decision id. It must
        /// be the current one (R-NG-03, NOTE 9, decided 2026-10-28).
        determination: DecisionId,
    },
    /// A fact from the M5 contract port.
    ContractFact {
        /// The proposal.
        proposal: ProposalId,
        /// The contract.
        contract: ContractId,
        /// What happened.
        event: ContractEvent,
    },
    /// End a negotiation that cannot reach GRANTED (NEGOTIATION to DECLINED, NOTE 9).
    /// The reason is computed and recorded.
    DeclineNegotiation {
        /// The proposal.
        proposal: ProposalId,
    },
    /// Withdraw a proposal (NOTE 10).
    Withdraw {
        /// The proposal.
        proposal: ProposalId,
    },
    /// The lead asks for a copy of the submission record at an address
    /// (R-SB-04). The address is a sealed text of the text store. At most
    /// three a day per proposal (TH-21, M6 design reading 4).
    RequestCopy {
        /// The proposal.
        proposal: ProposalId,
        /// The sealed address text.
        address: TextRef,
    },
    /// Start execution at the earliest milestone start date (NOTE 11).
    StartExecution {
        /// The proposal.
        proposal: ProposalId,
    },
    /// Complete a grant (NOTE 12).
    Complete {
        /// The proposal.
        proposal: ProposalId,
    },
    /// Terminate a grant early.
    Terminate {
        /// The decision.
        decision: DecisionId,
        /// The proposal.
        proposal: ProposalId,
        /// The recorded reason.
        reason: TextRef,
    },
    /// Request a payment, or resubmit a returned one (M5 design reading 4).
    RequestPayment {
        /// The new request.
        request: RequestId,
        /// The grant.
        grant: ProposalId,
        /// Milestone claim or hardship contribution (R-PR-04).
        kind: PaymentKind,
        /// Its lines.
        lines: Vec<PaymentLine>,
        /// The request this one replaces: one in CHECKS_FAILED or
        /// CHANGES_REQUESTED, withdrawn in the same batch, so its pending
        /// amounts return first (I-58). `None` for a new request.
        replaces: Option<RequestId>,
    },
    /// Accept one line (`SPEC/02-domain/payment-requests.md`).
    AcceptLine {
        /// The request.
        request: RequestId,
        /// The line.
        line: LineId,
        /// The approved amount, at most the requested amount (I-60).
        approved: NonNegAmount,
        /// The reason, required for a lower approval (I-60).
        reason: Option<TextRef>,
    },
    /// Approve a payment.
    ApprovePayment {
        /// The request.
        request: RequestId,
    },
    /// Release a payment (I-05, I-31, I-33).
    ReleasePayment {
        /// The request.
        request: RequestId,
        /// The digest of the record-only payment record file, computed by
        /// the shell (M5 design reading 6).
        record_file: ContentDigest,
    },
    /// Confirm a payment as paid.
    ConfirmPaid {
        /// The request.
        request: RequestId,
    },
    /// Withdraw a payment request before release. Pending amounts return to available.
    WithdrawPaymentRequest {
        /// The request.
        request: RequestId,
    },
    /// Return a payment request with requested changes.
    RequestPaymentChanges {
        /// The request.
        request: RequestId,
        /// The requested changes.
        reason: TextRef,
    },
    /// Record a run of the automated checks with its evidence snapshot
    /// (I-32, R-PR-02, R-PR-03).
    RecordChecks {
        /// The request.
        request: RequestId,
        /// Submission or acceptance.
        phase: CheckPhase,
        /// The outcome of each check.
        results: Vec<CheckResult>,
        /// The digest of the evidence snapshot: identifiers, content hashes
        /// and retrieval time (TH-24).
        snapshot: ContentDigest,
    },
    /// Record a deliverable from the M5 checks (I-15).
    RecordDeliverable {
        /// The deliverable.
        deliverable: DeliverableId,
        /// The grant.
        grant: ProposalId,
        /// The milestone.
        milestone: MilestoneId,
        /// Where it is publicly available.
        public_location: TextRef,
        /// The release identifier.
        release: TextRef,
        /// Its SPDX licence.
        licence: SpdxId,
        /// The evidence snapshot.
        snapshot: ContentDigest,
        /// Whether it was accepted.
        accepted: bool,
    },
    /// Propose an amendment.
    ProposeAmendment {
        /// The new amendment.
        amendment: AmendmentId,
        /// The grant.
        grant: ProposalId,
        /// The amended plan version.
        plan: PlanVersionId,
    },
    /// Route an amendment through a P-14 exemption or IRC review.
    RouteAmendment {
        /// The amendment.
        amendment: AmendmentId,
        /// The route.
        route: AmendmentRoute,
    },
    /// Activate an amendment on the M5 contract-version fact.
    ActivateAmendment {
        /// The amendment.
        amendment: AmendmentId,
        /// The contract.
        contract: ContractId,
    },
    /// Close a milestone of a grant in execution (NOTE 12, O-51). No timer
    /// or balance closes a milestone.
    CloseMilestone {
        /// The grant.
        proposal: ProposalId,
        /// The milestone of the effective contract version.
        milestone: MilestoneId,
        /// The recorded reason.
        reason: TextRef,
    },
    /// Close a payment request waiting in CHECKS_FAILED or CHANGES_REQUESTED
    /// (`SPEC/02-domain/payment-requests.md` Milestone closure, O-51).
    ClosePaymentRequest {
        /// The request.
        request: RequestId,
        /// The recorded reason.
        reason: TextRef,
    },
    /// Ask the lead for consent to pseudonymised calibration use within the
    /// tenant (R-LA-09, P-42). Refused before the proposal's outcome notice
    /// record is committed (I-37). Lane M12 L12-I37, `crate::calibration`.
    RequestCalibrationConsent {
        /// The proposal.
        proposal: ProposalId,
    },
    /// The lead gives calibration consent to the wording shown (R-LA-09, I-37).
    GiveCalibrationConsent {
        /// The proposal.
        proposal: ProposalId,
        /// The consent wording shown. TODO(legal): the consent text and the
        /// legal basis for pseudonymised use.
        wording: TextRef,
    },
    /// The lead revokes calibration consent. The proposal leaves every later
    /// calibration run (R-LA-10, I-37).
    RevokeCalibrationConsent {
        /// The proposal.
        proposal: ProposalId,
    },
}

/// The fieldless tag of a [`Command`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CommandKind {
    /// [`Command::CreateProgramme`].
    CreateProgramme,
    /// [`Command::ActivateProgramme`].
    ActivateProgramme,
    /// [`Command::EditPolicy`].
    EditPolicy,
    /// [`Command::DraftCall`].
    DraftCall,
    /// [`Command::EditCall`].
    EditCall,
    /// [`Command::ApproveCallPublication`].
    ApproveCallPublication,
    /// [`Command::PublishCall`].
    PublishCall,
    /// [`Command::GrantRole`].
    GrantRole,
    /// [`Command::EndRole`].
    EndRole,
    /// [`Command::EndScheduledRole`].
    EndScheduledRole,
    /// [`Command::ReinstateBinding`].
    ReinstateBinding,
    /// [`Command::VaultChanged`].
    VaultChanged,
    /// [`Command::CreateDraft`].
    CreateDraft,
    /// [`Command::AddTeamMember`].
    AddTeamMember,
    /// [`Command::AddGuardian`].
    AddGuardian,
    /// [`Command::RecordPlanVersion`].
    RecordPlanVersion,
    /// [`Command::Submit`].
    Submit,
    /// [`Command::DeclareConflict`].
    DeclareConflict,
    /// [`Command::Assign`].
    Assign,
    /// [`Command::Unassign`].
    Unassign,
    /// [`Command::ReadContent`].
    ReadContent,
    /// [`Command::RecordKnockOut`].
    RecordKnockOut,
    /// [`Command::AdmitToStage1`].
    AdmitToStage1,
    /// [`Command::RecordScore`].
    RecordScore,
    /// [`Command::CorrectScore`].
    CorrectScore,
    /// [`Command::RecordRankingSummary`].
    RecordRankingSummary,
    /// [`Command::CloseStage1`].
    CloseStage1,
    /// [`Command::AskQuestion`].
    AskQuestion,
    /// [`Command::RecordNoQuestions`].
    RecordNoQuestions,
    /// [`Command::AnswerQuestions`].
    AnswerQuestions,
    /// [`Command::SubmitRevision`].
    SubmitRevision,
    /// [`Command::RankAfterStage2`].
    RankAfterStage2,
    /// [`Command::ExpireStage2`].
    ExpireStage2,
    /// [`Command::OpenCutOffRound`].
    OpenCutOffRound,
    /// [`Command::CastBallot`].
    CastBallot,
    /// [`Command::DelegateVote`].
    DelegateVote,
    /// [`Command::RecordCutOff`].
    RecordCutOff,
    /// [`Command::RecordIrcReview`].
    RecordIrcReview,
    /// [`Command::DeclineAfterConcern`].
    DeclineAfterConcern,
    /// [`Command::ReEnter`].
    ReEnter,
    /// [`Command::DetermineAmount`].
    DetermineAmount,
    /// [`Command::AcceptGrant`].
    AcceptGrant,
    /// [`Command::ApproveGrant`].
    ApproveGrant,
    /// [`Command::ContractFact`].
    ContractFact,
    /// [`Command::DeclineNegotiation`].
    DeclineNegotiation,
    /// [`Command::Withdraw`].
    Withdraw,
    /// [`Command::RequestCopy`].
    RequestCopy,
    /// [`Command::StartExecution`].
    StartExecution,
    /// [`Command::Complete`].
    Complete,
    /// [`Command::Terminate`].
    Terminate,
    /// [`Command::RequestPayment`].
    RequestPayment,
    /// [`Command::AcceptLine`].
    AcceptLine,
    /// [`Command::ApprovePayment`].
    ApprovePayment,
    /// [`Command::ReleasePayment`].
    ReleasePayment,
    /// [`Command::ConfirmPaid`].
    ConfirmPaid,
    /// [`Command::WithdrawPaymentRequest`].
    WithdrawPaymentRequest,
    /// [`Command::RequestPaymentChanges`].
    RequestPaymentChanges,
    /// [`Command::RecordChecks`].
    RecordChecks,
    /// [`Command::RecordDeliverable`].
    RecordDeliverable,
    /// [`Command::ProposeAmendment`].
    ProposeAmendment,
    /// [`Command::RouteAmendment`].
    RouteAmendment,
    /// [`Command::ActivateAmendment`].
    ActivateAmendment,
    /// [`Command::CloseMilestone`].
    CloseMilestone,
    /// [`Command::ClosePaymentRequest`].
    ClosePaymentRequest,
    /// [`Command::RequestCalibrationConsent`].
    RequestCalibrationConsent,
    /// [`Command::GiveCalibrationConsent`].
    GiveCalibrationConsent,
    /// [`Command::RevokeCalibrationConsent`].
    RevokeCalibrationConsent,
}

impl CommandKind {
    /// Every kind, in declaration order.
    pub const ALL: [CommandKind; 67] = [
        CommandKind::CreateProgramme,
        CommandKind::ActivateProgramme,
        CommandKind::EditPolicy,
        CommandKind::DraftCall,
        CommandKind::EditCall,
        CommandKind::ApproveCallPublication,
        CommandKind::PublishCall,
        CommandKind::GrantRole,
        CommandKind::EndRole,
        CommandKind::EndScheduledRole,
        CommandKind::ReinstateBinding,
        CommandKind::VaultChanged,
        CommandKind::CreateDraft,
        CommandKind::AddTeamMember,
        CommandKind::AddGuardian,
        CommandKind::RecordPlanVersion,
        CommandKind::Submit,
        CommandKind::DeclareConflict,
        CommandKind::Assign,
        CommandKind::Unassign,
        CommandKind::ReadContent,
        CommandKind::RecordKnockOut,
        CommandKind::AdmitToStage1,
        CommandKind::RecordScore,
        CommandKind::CorrectScore,
        CommandKind::RecordRankingSummary,
        CommandKind::CloseStage1,
        CommandKind::AskQuestion,
        CommandKind::RecordNoQuestions,
        CommandKind::AnswerQuestions,
        CommandKind::SubmitRevision,
        CommandKind::RankAfterStage2,
        CommandKind::ExpireStage2,
        CommandKind::OpenCutOffRound,
        CommandKind::CastBallot,
        CommandKind::DelegateVote,
        CommandKind::RecordCutOff,
        CommandKind::RecordIrcReview,
        CommandKind::DeclineAfterConcern,
        CommandKind::ReEnter,
        CommandKind::DetermineAmount,
        CommandKind::AcceptGrant,
        CommandKind::ApproveGrant,
        CommandKind::ContractFact,
        CommandKind::DeclineNegotiation,
        CommandKind::Withdraw,
        CommandKind::RequestCopy,
        CommandKind::StartExecution,
        CommandKind::Complete,
        CommandKind::Terminate,
        CommandKind::RequestPayment,
        CommandKind::AcceptLine,
        CommandKind::ApprovePayment,
        CommandKind::ReleasePayment,
        CommandKind::ConfirmPaid,
        CommandKind::WithdrawPaymentRequest,
        CommandKind::RequestPaymentChanges,
        CommandKind::RecordChecks,
        CommandKind::RecordDeliverable,
        CommandKind::ProposeAmendment,
        CommandKind::RouteAmendment,
        CommandKind::ActivateAmendment,
        CommandKind::CloseMilestone,
        CommandKind::ClosePaymentRequest,
        CommandKind::RequestCalibrationConsent,
        CommandKind::GiveCalibrationConsent,
        CommandKind::RevokeCalibrationConsent,
    ];

    /// Whether the kind is a high-risk action from the list in
    /// `SPEC/03-architecture/authentication.md`. The M3 shell enforces the
    /// step-up (I-78), and `decide` refuses it through MCP (I-85).
    ///
    /// Covered: granting or changing a Drafting, Judging or Operations role
    /// (every `GrantRole`, `EndRole` and `ReinstateBinding`, since Receiving
    /// bindings arise from proposals), approving or releasing a payment, and
    /// activating a programme or publishing a call. Since M4 change D2 the
    /// activation is its own step, `ActivateProgramme`. Creating a
    /// programme stays high risk too, the strict reading of Q10 (M4 design
    /// section 12.1 item 1, interim, pending Daniel).
    pub const fn high_risk(self) -> bool {
        matches!(
            self,
            CommandKind::CreateProgramme
                | CommandKind::ActivateProgramme
                | CommandKind::GrantRole
                | CommandKind::EndRole
                | CommandKind::ReinstateBinding
                | CommandKind::ApprovePayment
                | CommandKind::ReleasePayment
                | CommandKind::PublishCall
        )
    }

    /// Whether the kind is a binding action under P-77 (R-MC-05).
    /// With P-77 "draft only", `decide` refuses it through MCP.
    ///
    /// Every command a human issues is binding, except preparing a draft
    /// or a plan and reading content. System commands never arrive through
    /// MCP. `ConfirmPaid` is binding, because finance may issue it. The two
    /// decline commands are binding, because the programme manager records
    /// them (O-49).
    pub const fn binding_action(self) -> bool {
        !matches!(
            self,
            CommandKind::CreateDraft
                | CommandKind::RecordPlanVersion
                | CommandKind::ReadContent
                | CommandKind::RequestCopy
                | CommandKind::VaultChanged
                | CommandKind::EndScheduledRole
                | CommandKind::ExpireStage2
                | CommandKind::ReEnter
                | CommandKind::ContractFact
                | CommandKind::StartExecution
                | CommandKind::Complete
                | CommandKind::RecordDeliverable
                | CommandKind::RecordChecks
                | CommandKind::ActivateAmendment
        )
    }
}

impl Command {
    /// The tag of this command.
    pub const fn kind(&self) -> CommandKind {
        match self {
            Command::CreateProgramme { .. } => CommandKind::CreateProgramme,
            Command::ActivateProgramme { .. } => CommandKind::ActivateProgramme,
            Command::EditPolicy { .. } => CommandKind::EditPolicy,
            Command::DraftCall { .. } => CommandKind::DraftCall,
            Command::EditCall { .. } => CommandKind::EditCall,
            Command::ApproveCallPublication { .. } => CommandKind::ApproveCallPublication,
            Command::PublishCall { .. } => CommandKind::PublishCall,
            Command::GrantRole { .. } => CommandKind::GrantRole,
            Command::EndRole { .. } => CommandKind::EndRole,
            Command::EndScheduledRole { .. } => CommandKind::EndScheduledRole,
            Command::ReinstateBinding { .. } => CommandKind::ReinstateBinding,
            Command::VaultChanged { .. } => CommandKind::VaultChanged,
            Command::CreateDraft { .. } => CommandKind::CreateDraft,
            Command::AddTeamMember { .. } => CommandKind::AddTeamMember,
            Command::AddGuardian { .. } => CommandKind::AddGuardian,
            Command::RecordPlanVersion { .. } => CommandKind::RecordPlanVersion,
            Command::Submit { .. } => CommandKind::Submit,
            Command::DeclareConflict { .. } => CommandKind::DeclareConflict,
            Command::Assign { .. } => CommandKind::Assign,
            Command::Unassign { .. } => CommandKind::Unassign,
            Command::ReadContent { .. } => CommandKind::ReadContent,
            Command::RecordKnockOut { .. } => CommandKind::RecordKnockOut,
            Command::AdmitToStage1 { .. } => CommandKind::AdmitToStage1,
            Command::RecordScore { .. } => CommandKind::RecordScore,
            Command::CorrectScore { .. } => CommandKind::CorrectScore,
            Command::RecordRankingSummary { .. } => CommandKind::RecordRankingSummary,
            Command::CloseStage1 { .. } => CommandKind::CloseStage1,
            Command::AskQuestion { .. } => CommandKind::AskQuestion,
            Command::RecordNoQuestions { .. } => CommandKind::RecordNoQuestions,
            Command::AnswerQuestions { .. } => CommandKind::AnswerQuestions,
            Command::SubmitRevision { .. } => CommandKind::SubmitRevision,
            Command::RankAfterStage2 { .. } => CommandKind::RankAfterStage2,
            Command::ExpireStage2 { .. } => CommandKind::ExpireStage2,
            Command::OpenCutOffRound { .. } => CommandKind::OpenCutOffRound,
            Command::CastBallot { .. } => CommandKind::CastBallot,
            Command::DelegateVote { .. } => CommandKind::DelegateVote,
            Command::RecordCutOff { .. } => CommandKind::RecordCutOff,
            Command::RecordIrcReview { .. } => CommandKind::RecordIrcReview,
            Command::DeclineAfterConcern { .. } => CommandKind::DeclineAfterConcern,
            Command::ReEnter { .. } => CommandKind::ReEnter,
            Command::DetermineAmount { .. } => CommandKind::DetermineAmount,
            Command::AcceptGrant { .. } => CommandKind::AcceptGrant,
            Command::ApproveGrant { .. } => CommandKind::ApproveGrant,
            Command::ContractFact { .. } => CommandKind::ContractFact,
            Command::DeclineNegotiation { .. } => CommandKind::DeclineNegotiation,
            Command::Withdraw { .. } => CommandKind::Withdraw,
            Command::RequestCopy { .. } => CommandKind::RequestCopy,
            Command::StartExecution { .. } => CommandKind::StartExecution,
            Command::Complete { .. } => CommandKind::Complete,
            Command::Terminate { .. } => CommandKind::Terminate,
            Command::RequestPayment { .. } => CommandKind::RequestPayment,
            Command::AcceptLine { .. } => CommandKind::AcceptLine,
            Command::ApprovePayment { .. } => CommandKind::ApprovePayment,
            Command::ReleasePayment { .. } => CommandKind::ReleasePayment,
            Command::ConfirmPaid { .. } => CommandKind::ConfirmPaid,
            Command::WithdrawPaymentRequest { .. } => CommandKind::WithdrawPaymentRequest,
            Command::RequestPaymentChanges { .. } => CommandKind::RequestPaymentChanges,
            Command::RecordChecks { .. } => CommandKind::RecordChecks,
            Command::RecordDeliverable { .. } => CommandKind::RecordDeliverable,
            Command::ProposeAmendment { .. } => CommandKind::ProposeAmendment,
            Command::RouteAmendment { .. } => CommandKind::RouteAmendment,
            Command::ActivateAmendment { .. } => CommandKind::ActivateAmendment,
            Command::CloseMilestone { .. } => CommandKind::CloseMilestone,
            Command::ClosePaymentRequest { .. } => CommandKind::ClosePaymentRequest,
            Command::RequestCalibrationConsent { .. } => CommandKind::RequestCalibrationConsent,
            Command::GiveCalibrationConsent { .. } => CommandKind::GiveCalibrationConsent,
            Command::RevokeCalibrationConsent { .. } => CommandKind::RevokeCalibrationConsent,
        }
    }

    /// Whether this command is a high-risk action (I-78, I-85).
    pub const fn high_risk(&self) -> bool {
        self.kind().high_risk()
    }

    /// Whether this command is a binding action under P-77 (R-MC-05).
    pub const fn binding_action(&self) -> bool {
        self.kind().binding_action()
    }
}
