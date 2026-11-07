//! Core ledger records (design sections 2.5 to 2.14 and 5.1).
//!
//! - Records are append-only (I-23). A correction is a new record with
//!   `supersedes`. Ending a binding is [`BindingEnded`]. A policy change is
//!   a new policy version.
//! - Every decision carries the [`RulesVersion`] of the readings that
//!   produced it. The fold never re-runs guards, so old decisions stay valid.
//! - Free text appears only as [`TextRef`], never inside a record body.
//! - The payloads of stage 1 exits, effective scores, grants and releases
//!   have private fields. Only a builder that takes the matching witness can
//!   construct them (design section 3.5). They live in the lane modules that
//!   own those witnesses.
//! - Since M4 change D2 the activation payload [`ProgrammeActivated`] has
//!   private fields too. Only the core activation guard in
//!   `crate::policy::activation` and the record decoder build it.

use std::collections::BTreeSet;

use fstp_ledger::Seq;
use fstp_money::{Currency, NonNegAmount};

use crate::amendment::AmendmentRoute;
use crate::assignment::{AssignmentKind, ReleaseCause};
use crate::command::{Actor, ContractEvent, KnockOutResult};
use crate::decision::{
    Ballot, EffectiveScoreSet, IrcVerdict, NegotiationFailure, Stage1Closed, Vote,
};
use crate::grant::{GrantDecided, IneligibleCost};
use crate::id::{
    AccountId, AmendmentId, AssignmentId, BindingId, CallId, CallSeq, ContentDigest, ContractId,
    DecisionId, DeliverableId, Handle, LineId, LlmConfigId, MilestoneId, OrganisationId,
    PlanVersionId, PolicyVersionId, ProgrammeId, ProposalId, RequestId, RoleInvitationId, TextRef,
    VaultEpoch,
};
use crate::oracle::QueryKind;
use crate::payment::{CheckPhase, CheckResult, PaymentKind, PaymentLine, PaymentReleased};
pub use crate::policy::activation::ProgrammeActivated;
use crate::policy::{PolicyVersion, SpdxId};
use crate::proposal::{EthicsDeclaration, NoticeVersion, PlanOrigin, ReentryStage, Task};
use crate::refusal::RuleRef;
use crate::roles::{BindingScope, CoolingOff, Role};
use crate::rules::{Row, StateTag};
use crate::scoring::{ScoreKey, ScoreVector, VoidCause};
use crate::time::{Timestamp, ZoneName};

/// The version of the interim readings that produced a decision (design section 5.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RulesVersion(pub u16);

impl RulesVersion {
    /// The readings of milestone M2, with Daniel's answers of 2026-10-25.
    pub const M2: RulesVersion = RulesVersion(1);

    /// The M2 readings with Daniel's answers of 2026-10-29 on the minor
    /// flag (state-machine NOTE 14). The guard into GRANTED derives the
    /// flag again, and `DeclineNegotiation` asks the same questions. A
    /// `GrantDecided` under it follows the `IsVerifiedAdultAtDeadline`
    /// outcome of its batch, and the fold derives the flag from that bit.
    /// A `GrantDecided` under [`RulesVersion::M2`] keeps the gate's flag.
    pub const MINOR_FLAG_2026_10_29: RulesVersion = RulesVersion(2);

    /// The readings of milestone M4 (M4 design section 3.4, D7), each
    /// interim, pending Daniel. A programme is activated by a tenant admin
    /// outside its builder set (D2, Q1 and Q2). A cut-off counts only the
    /// ballots that committee members cast in its round, and its decision
    /// is the round (D5, Q4). The fold of a `CutOffRecorded` under it
    /// closes its open round. One under an earlier version keeps its own
    /// fresh decision id.
    pub const M4: RulesVersion = RulesVersion(3);
}

/// A role binding (design section 2.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BindingGranted {
    /// The binding.
    pub binding: BindingId,
    /// The account.
    pub account: AccountId,
    /// The programme.
    pub programme: ProgrammeId,
    /// The role.
    pub role: Role,
    /// Programme scope, or one proposal and its call for Receiving roles.
    pub scope: BindingScope,
    /// Start of the binding.
    pub start: Timestamp,
    /// Who granted it: a tenant admin, or the lead for Receiving roles.
    pub granted_by: AccountId,
    /// The approving second tenant admin of a self-grant (SoD-07).
    pub second_admin: Option<AccountId>,
    /// Accepted confidentiality terms, for Drafting and Judging roles.
    pub confidentiality: Option<TextRef>,
    /// The reviewer's organisation, for committee bindings (I-34).
    pub organisation: Option<OrganisationId>,
    /// The vault epoch of the SoD-09 answers used.
    pub verified_epoch: Option<VaultEpoch>,
}

/// The end of a binding, with its pinned cooling-off bar.
/// `barred_through` is the latest published call sequence number at the end
/// plus the P-12 value at the end. It is 0 plus P-12 when no call was published yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BindingEnded {
    /// The binding.
    pub binding: BindingId,
    /// End time.
    pub at: Timestamp,
    /// The pinned bar, in call sequence numbers.
    pub barred_through: u32,
    /// The P-12 value pinned at the end.
    pub p12: CoolingOff,
}

/// A suspension under enforcement point 3. A suspended binding is inactive for every action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BindingSuspended {
    /// The binding.
    pub binding: BindingId,
    /// The rule the binding would break.
    pub rule: RuleRef,
    /// The vault epoch of the change.
    pub epoch: VaultEpoch,
}

/// A voided Receiving binding under Identity discovery (I-04, I-06).
/// Voided bindings never count as held and pin no cooling-off bar.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BindingVoided {
    /// The binding.
    pub binding: BindingId,
    /// The invariant the binding would break.
    pub rule: RuleRef,
    /// The vault epoch of the discovery.
    pub epoch: VaultEpoch,
}

/// The reinstatement of a suspended binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BindingReinstated {
    /// The binding.
    pub binding: BindingId,
    /// Who reinstated it.
    pub by: AccountId,
    /// The recorded reason.
    pub reason: TextRef,
}

/// A new assignment (design section 2.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Assigned {
    /// The assignment.
    pub assignment: AssignmentId,
    /// The proposal.
    pub proposal: ProposalId,
    /// The call the assignment is made in. Re-entry makes fresh assignments (NOTE 8).
    pub call: CallId,
    /// The assignee.
    pub reviewer: AccountId,
    /// The kind of assignment.
    pub kind: AssignmentKind,
    /// The handle under P-11 anonymous.
    pub handle: Option<Handle>,
    /// Who assigned.
    pub by: AccountId,
    /// The vault epoch of the conflict answer.
    pub epoch: VaultEpoch,
}

/// What a conflict declaration is about, as recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Declared {
    /// An assignment.
    Assignment(AssignmentId),
    /// A proposal, by the declaring account (coordinator or committee member).
    Proposal {
        /// The proposal.
        proposal: ProposalId,
        /// The declaring account.
        account: AccountId,
    },
}

/// A conflict declaration (R-CF-02, R-CF-04).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ConflictDeclared {
    /// What the declaration is about.
    pub subject: Declared,
    /// Whether the declarer is conflicted.
    pub conflicted: bool,
    /// Whether the conflict is notifiable (R-CF-04).
    pub notifiable: bool,
}

/// A conflict the vault detected. No reason is recorded (R-CF-03).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ConflictDetected {
    /// The conflicted account.
    pub account: AccountId,
    /// The proposal.
    pub proposal: ProposalId,
    /// Whether it is notifiable, as for scores already given (R-CF-04).
    pub notifiable: bool,
    /// The vault epoch of the detection.
    pub epoch: VaultEpoch,
}

/// The release of an assignment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AssignmentReleased {
    /// The assignment.
    pub assignment: AssignmentId,
    /// Why.
    pub cause: ReleaseCause,
}

/// A read of proposal content (R-AU-01).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ContentRead {
    /// The reader.
    pub account: AccountId,
    /// The proposal.
    pub proposal: ProposalId,
}

/// A plan version (design section 2.8).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PlanVersionRecorded {
    /// The plan version.
    pub plan: PlanVersionId,
    /// The proposal.
    pub proposal: ProposalId,
    /// Where it comes from.
    pub origin: PlanOrigin,
    /// The version it supersedes.
    pub supersedes: Option<PlanVersionId>,
    /// Tasks with their milestones. Totals are derived, never stored.
    pub tasks: Vec<Task>,
    /// Digest of the plan text held outside the domain.
    pub content: ContentDigest,
}

/// A score, or a correction of one (design section 2.9).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ScoreRecorded {
    /// Assignment, stage and plan.
    pub key: ScoreKey,
    /// One value per criterion.
    pub values: ScoreVector,
    /// The entry of the score this one corrects.
    pub supersedes: Option<Seq>,
    /// The reason of a correction.
    pub reason: Option<TextRef>,
}

/// A score that stopped counting.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ScoreVoided {
    /// The score's key.
    pub key: ScoreKey,
    /// Why.
    pub cause: VoidCause,
}

/// The committee cut-off of one round (NOTE 6, R-EV-08, R-EV-09).
///
/// Under [`RulesVersion::M4`] the decision is the round that
/// `CutOffRoundOpened` opened, and the ballots are exactly the ballots the
/// members cast in it, each delegated vote with its delegate's ballot
/// (M4 change D5).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CutOffRecorded {
    /// The decision: the round since M4 change D5.
    pub decision: DecisionId,
    /// The call.
    pub call: CallId,
    /// The total order of the call's RANKED proposals in this round.
    pub order: Vec<ProposalId>,
    /// The cut-off rank position.
    pub nominated: u32,
    /// The recorded rationale.
    pub rationale: TextRef,
    /// The recorded P-17 tie-break.
    pub tie_breaks: Option<TextRef>,
    /// The ballots.
    pub ballots: Vec<Ballot>,
    /// Committee members recused for a conflict on a ranked proposal.
    pub recused: BTreeSet<AccountId>,
    /// The remaining call budget shown, signed because a call can be over-nominated.
    pub remaining_budget: fstp_money::Amount,
    /// The recording committee member.
    pub recorder: AccountId,
    /// The rules version.
    pub rules: RulesVersion,
}

/// A deliverable from the M5 checks (I-15).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DeliverableRecorded {
    /// The deliverable.
    pub deliverable: DeliverableId,
    /// The grant.
    pub grant: ProposalId,
    /// The milestone.
    pub milestone: MilestoneId,
    /// Where it is publicly available.
    pub public_location: TextRef,
    /// The release identifier.
    pub release: TextRef,
    /// Its SPDX licence.
    pub licence: SpdxId,
    /// The evidence snapshot.
    pub snapshot: ContentDigest,
    /// Whether it was accepted.
    pub accepted: bool,
}

/// A proposal state transition (R-AU-01).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Transitioned {
    /// The proposal.
    pub proposal: ProposalId,
    /// The state left.
    pub from: StateTag,
    /// The state reached.
    pub to: StateTag,
    /// The row taken.
    pub row: Row,
    /// The actor of the command that computed it. A NEGOTIATION to GRANTED
    /// completed by the contract port names the approving programme
    /// manager instead (R-LA-03, NOTE 13).
    pub actor: Actor,
    /// The decision behind it, when one was recorded.
    pub decision: Option<DecisionId>,
}

/// A notification or group event for M6 and M8, in the same batch (I-29 seam).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OutboxEvent {
    /// A proposal reached a state the applicant is told about, such as NOT_SELECTED (P-08).
    ProposalOutcome {
        /// The proposal.
        proposal: ProposalId,
        /// The state reached.
        state: StateTag,
    },
    /// An IRC concern for the applicant (R-IR-02).
    IrcConcern {
        /// The proposal.
        proposal: ProposalId,
        /// The concern.
        concern: TextRef,
    },
    /// A notifiable conflict, as a notification draft for the coordinator (R-CF-04).
    NotifiableConflict {
        /// The proposal.
        proposal: ProposalId,
    },
    /// A binding ended, so group membership removal is enqueued (I-29).
    BindingEnded {
        /// The binding.
        binding: BindingId,
    },
}

/// A core ledger record.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Record {
    /// A programme was created.
    ProgrammeCreated {
        /// The programme.
        programme: ProgrammeId,
        /// Its currency (ADR-006).
        currency: Currency,
        /// Who created it.
        by: AccountId,
    },
    /// A policy version was appended (I-23).
    PolicyVersionRecorded {
        /// The version.
        version: Box<PolicyVersion>,
        /// Its author.
        author: AccountId,
    },
    /// A draft programme was activated by a second person who did not
    /// build it (I-66, I-67, M4 change D2).
    ProgrammeActivated(ProgrammeActivated),
    /// A call was drafted.
    CallDrafted {
        /// The call.
        call: CallId,
        /// Its programme.
        programme: ProgrammeId,
        /// Opening time.
        opens: Timestamp,
        /// Deadline.
        deadline: Timestamp,
        /// Deadline zone.
        deadline_zone: ZoneName,
        /// Call budget.
        budget: NonNegAmount,
        /// Call text.
        text: TextRef,
        /// Its author.
        author: AccountId,
    },
    /// An unpublished call was edited.
    CallEdited {
        /// The call.
        call: CallId,
        /// Opening time.
        opens: Timestamp,
        /// Deadline.
        deadline: Timestamp,
        /// Deadline zone.
        deadline_zone: ZoneName,
        /// Call budget.
        budget: NonNegAmount,
        /// Call text.
        text: TextRef,
        /// Its author.
        author: AccountId,
    },
    /// Publication was approved (R-PC-03).
    CallApproved {
        /// The call.
        call: CallId,
        /// The decision.
        decision: DecisionId,
        /// The approver.
        approver: AccountId,
    },
    /// A call was published with its frozen policy (I-12, R-PC-02).
    CallPublished {
        /// The call.
        call: CallId,
        /// The policy version frozen.
        policy: PolicyVersionId,
        /// The publication sequence number in the programme.
        seq: CallSeq,
        /// The pinned LLM configuration (I-11).
        config: LlmConfigId,
        /// The publisher.
        by: AccountId,
    },
    /// The Guide for Applicants of a call, generated at its publication in
    /// the entry of its `CallPublished` (R-GA-01, I-52, I-53, M4 design
    /// section 3.10). The fold refuses a second one for a call.
    ///
    /// It holds the Guide itself: the canonical document, whose SHA-256
    /// through `fstp-crypto` is `digest`, and the page the public pages
    /// serve. The Guide is a document the platform generates, not free
    /// text a person wrote, and I-53 makes it immutable, so it is kept in
    /// the ledger with its digest (interim, pending Daniel).
    GuidePublished {
        /// The call.
        call: CallId,
        /// The Guide version, 1 at publication.
        version: u32,
        /// SHA-256 of `canonical`.
        digest: ContentDigest,
        /// The canonical document the digest is taken over.
        canonical: String,
        /// The HTML page of the Guide.
        page: String,
    },
    /// A binding was granted.
    BindingGranted(BindingGranted),
    /// A binding ended.
    BindingEnded(BindingEnded),
    /// A binding was suspended.
    BindingSuspended(BindingSuspended),
    /// A binding was voided.
    BindingVoided(BindingVoided),
    /// A suspended binding was reinstated.
    BindingReinstated(BindingReinstated),
    /// The end of an open binding was scheduled for a later instant, or
    /// brought forward (Cooling-off NOTE, decided 2026-10-25). The binding
    /// stays held until its `BindingEnded`, which pins the bar then.
    BindingEndScheduled {
        /// The binding.
        binding: BindingId,
        /// The scheduled end instant.
        at: Timestamp,
    },
    /// A vault epoch was processed (enforcement point 3).
    VaultEpochProcessed {
        /// The epoch.
        epoch: VaultEpoch,
    },
    /// A draft proposal was created.
    ProposalCreated {
        /// The proposal.
        proposal: ProposalId,
        /// Its call.
        call: CallId,
        /// The lead.
        lead: AccountId,
        /// Whether the lead is flagged as a minor.
        minor: bool,
    },
    /// A plan version was recorded.
    PlanVersionRecorded(PlanVersionRecorded),
    /// A proposal was submitted.
    Submitted {
        /// The proposal.
        proposal: ProposalId,
        /// The submitted plan.
        plan: PlanVersionId,
        /// The ethics self-declaration (R-SB-05).
        ethics: EthicsDeclaration,
        /// The notice version shown (R-NG-06).
        notice: NoticeVersion,
    },
    /// An assignment was made.
    Assigned(Assigned),
    /// A conflict declaration was recorded.
    ConflictDeclared(ConflictDeclared),
    /// The vault detected a conflict.
    ConflictDetected(ConflictDetected),
    /// An assignment was released.
    AssignmentReleased(AssignmentReleased),
    /// Proposal content was read.
    ContentRead(ContentRead),
    /// The knock-out check was recorded.
    KnockOutRecorded {
        /// The decision.
        decision: DecisionId,
        /// The proposal.
        proposal: ProposalId,
        /// The coordinator.
        coordinator: AccountId,
        /// One result per P-09 criterion.
        outcomes: Vec<KnockOutResult>,
        /// The reason, when a criterion failed.
        reason: Option<TextRef>,
        /// The rules version.
        rules: RulesVersion,
    },
    /// A score was recorded or corrected.
    ScoreRecorded(ScoreRecorded),
    /// A score stopped counting.
    ScoreVoided(ScoreVoided),
    /// The assigned reviewers' title, neutral summary and rationale for the ranking view.
    RankingSummaryRecorded {
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
    /// Stage 1 closed with a computed outcome.
    Stage1Closed(Stage1Closed),
    /// A stage 2 question was asked.
    QuestionAsked {
        /// The proposal.
        proposal: ProposalId,
        /// The asking reviewer's assignment.
        assignment: AssignmentId,
        /// The question.
        text: TextRef,
    },
    /// A reviewer recorded "no questions" (NOTE 4).
    NoQuestionsRecorded {
        /// The proposal.
        proposal: ProposalId,
        /// The recording reviewer's assignment.
        assignment: AssignmentId,
    },
    /// The applicant answered the stage 2 questions.
    AnswersRecorded {
        /// The proposal.
        proposal: ProposalId,
        /// The answers.
        text: TextRef,
    },
    /// A revised plan was submitted for rescoring.
    RevisionSubmitted {
        /// The proposal.
        proposal: ProposalId,
        /// The revised plan.
        plan: PlanVersionId,
    },
    /// The effective score after stage 2 was set (I-09).
    EffectiveScoreSet(EffectiveScoreSet),
    /// A committee member opened a cut-off round (M4 change D5, R-EV-08).
    CutOffRoundOpened {
        /// The round, the decision id of its cut-off.
        round: DecisionId,
        /// The call.
        call: CallId,
        /// The total order of the call's RANKED proposals.
        order: Vec<ProposalId>,
        /// The cut-off rank position.
        nominated: u32,
        /// The recorded rationale.
        rationale: TextRef,
        /// The recorded P-17 tie-break.
        tie_breaks: Option<TextRef>,
        /// The opening committee member.
        by: AccountId,
    },
    /// A committee member cast their own ballot in a round (R-EV-09, D5).
    BallotCast {
        /// The round.
        round: DecisionId,
        /// The member who cast it, the command's actor.
        voter: AccountId,
        /// The vote.
        vote: Vote,
    },
    /// A committee member delegated their own vote in a round to another
    /// member (P-16 NOTE 8, D5).
    VoteDelegated {
        /// The round.
        round: DecisionId,
        /// The delegating member, the command's actor.
        from: AccountId,
        /// The member who holds the delegated vote.
        to: AccountId,
    },
    /// The committee cut-off was recorded.
    CutOffRecorded(CutOffRecorded),
    /// An IRC review was recorded.
    IrcReviewRecorded {
        /// The IRC assignment.
        assignment: AssignmentId,
        /// The verdict.
        verdict: IrcVerdict,
    },
    /// A proposal was deferred.
    DeferralRecorded {
        /// The proposal.
        proposal: ProposalId,
        /// The call it was deferred from.
        from_call: CallId,
        /// The stage it left.
        left: ReentryStage,
    },
    /// A deferred proposal re-entered a later call. The original call's policy keeps governing it.
    ReEntered {
        /// The proposal.
        proposal: ProposalId,
        /// The call it was deferred from.
        from_call: CallId,
        /// The call it re-entered.
        to_call: CallId,
        /// The stage it re-entered at.
        stage: ReentryStage,
    },
    /// The grant amount was determined (R-NG-03, I-13).
    AmountDetermined {
        /// The decision.
        decision: DecisionId,
        /// The proposal.
        proposal: ProposalId,
        /// The effective plan total.
        plan_total: NonNegAmount,
        /// The recorded deductions.
        deductions: Vec<IneligibleCost>,
        /// The granted amount.
        granted: NonNegAmount,
        /// The agreed plan version.
        agreed: PlanVersionId,
        /// The determining reviewer.
        by: AccountId,
        /// The rules version.
        rules: RulesVersion,
    },
    /// Cap headroom was reserved (I-14).
    CapReserved {
        /// The proposal.
        proposal: ProposalId,
        /// The reserved amount.
        amount: NonNegAmount,
        /// The vault epoch of the cap answer.
        epoch: VaultEpoch,
    },
    /// A reservation was released.
    CapReleased {
        /// The proposal.
        proposal: ProposalId,
        /// The released amount.
        amount: NonNegAmount,
    },
    /// The applicant accepted the grant.
    GrantAccepted {
        /// The decision.
        decision: DecisionId,
        /// The proposal.
        proposal: ProposalId,
        /// The lead.
        by: AccountId,
    },
    /// The programme manager approved the grant.
    GrantApproved {
        /// The decision.
        decision: DecisionId,
        /// The proposal.
        proposal: ProposalId,
        /// The programme manager.
        by: AccountId,
    },
    /// A fact from the M5 contract port.
    ContractFactRecorded {
        /// The proposal.
        proposal: ProposalId,
        /// The contract.
        contract: ContractId,
        /// What happened.
        event: ContractEvent,
    },
    /// The grant was decided with a full clearance.
    GrantDecided(GrantDecided),
    /// A negotiation ended without a grant, with the computed reason (NOTE 9).
    NegotiationDeclined {
        /// The proposal.
        proposal: ProposalId,
        /// The reason.
        reason: NegotiationFailure,
        /// The rules version.
        rules: RulesVersion,
    },
    /// A grant was terminated early.
    TerminationRecorded {
        /// The decision.
        decision: DecisionId,
        /// The proposal.
        proposal: ProposalId,
        /// The programme manager.
        by: AccountId,
        /// The recorded reason.
        reason: TextRef,
    },
    /// A proposal changed state.
    Transitioned(Transitioned),
    /// A vault answer used by a decision, with no reason and no attributes.
    /// It holds the query's digest, never the query, so no candidate set or
    /// committed sum reaches the ledger body (overview NOTE 5, design section 4.4).
    VaultOutcome {
        /// The kind of query asked.
        kind: QueryKind,
        /// The digest of the query, from [`crate::oracle::Answer::digest`].
        digest: ContentDigest,
        /// The answer bit.
        holds: bool,
        /// The vault epoch.
        epoch: VaultEpoch,
    },
    /// An invitee accepted the confidentiality terms of a programme role
    /// ("Confidentiality on binding", M4 design section 2.2 J2, lane inv).
    ///
    /// The engine appends it for an accepted creator invitation. It names
    /// no contact address and no link token (I-86, ADR-007). The core
    /// projection keeps nothing of it. The creator projection folds it
    /// into the invitation, and the grant of the role is composed only
    /// from it (`fstp_engine::compose::terms_accepted`).
    TermsAccepted {
        /// The accepting account.
        account: AccountId,
        /// The programme.
        programme: ProgrammeId,
        /// The invited role.
        role: Role,
        /// The creator invitation accepted.
        invitation: RoleInvitationId,
        /// The version of the confidentiality terms the invitee was shown.
        version: u32,
        /// The terms as accepted, with the programme's P-75 and P-77
        /// choices bound, as a confidential text of the programme.
        terms: TextRef,
    },
    /// A notification or group event was enqueued.
    OutboxEnqueued(OutboxEvent),
    /// A payment was requested.
    PaymentRequested {
        /// The request.
        request: RequestId,
        /// The grant.
        grant: ProposalId,
        /// Milestone claim or hardship contribution (R-PR-04).
        kind: PaymentKind,
        /// Its lines.
        lines: Vec<PaymentLine>,
    },
    /// A run of the automated checks was recorded with its evidence
    /// snapshot (I-32, R-PR-02, R-PR-03).
    ChecksRecorded {
        /// The request.
        request: RequestId,
        /// Submission or acceptance.
        phase: CheckPhase,
        /// The outcome of each check.
        results: Vec<CheckResult>,
        /// The digest of the evidence snapshot (TH-24).
        snapshot: ContentDigest,
    },
    /// A line was accepted.
    LineAccepted {
        /// The request.
        request: RequestId,
        /// The line.
        line: LineId,
        /// The accepting reviewer.
        by: AccountId,
        /// The approved amount.
        approved: NonNegAmount,
        /// The reason of a lower approval (I-60).
        reason: Option<TextRef>,
    },
    /// A payment was approved.
    PaymentApproved {
        /// The request.
        request: RequestId,
        /// The finance approver.
        by: AccountId,
    },
    /// A payment was released (I-05).
    PaymentReleased(PaymentReleased),
    /// A payment was confirmed as paid.
    PaymentConfirmed {
        /// The request.
        request: RequestId,
        /// Who confirmed it: the System from the payment port, or a finance approver.
        by: Actor,
    },
    /// A payment request was withdrawn before release.
    PaymentRequestWithdrawn {
        /// The request.
        request: RequestId,
        /// The lead.
        by: AccountId,
    },
    /// A payment request was returned with requested changes.
    PaymentChangesRequested {
        /// The request.
        request: RequestId,
        /// The assigned reviewer.
        by: AccountId,
        /// The requested changes.
        reason: TextRef,
    },
    /// A deliverable was recorded.
    DeliverableRecorded(DeliverableRecorded),
    /// An amendment was proposed.
    AmendmentProposed {
        /// The amendment.
        amendment: AmendmentId,
        /// The grant.
        grant: ProposalId,
        /// The amended plan.
        plan: PlanVersionId,
        /// The proposer.
        by: AccountId,
    },
    /// An amendment was routed.
    AmendmentRouted {
        /// The amendment.
        amendment: AmendmentId,
        /// The route.
        route: AmendmentRoute,
        /// The programme manager.
        by: AccountId,
    },
    /// An amendment was activated on the M5 contract-version fact.
    AmendmentActivated {
        /// The amendment.
        amendment: AmendmentId,
        /// The amended plan.
        plan: PlanVersionId,
        /// The route taken.
        route: AmendmentRoute,
        /// The contract.
        contract: ContractId,
    },
    /// The programme manager closed a milestone (NOTE 12, O-51).
    MilestoneClosed {
        /// The grant.
        proposal: ProposalId,
        /// The milestone.
        milestone: MilestoneId,
        /// The programme manager.
        by: AccountId,
        /// The recorded reason.
        reason: TextRef,
    },
    /// The programme manager closed a waiting payment request (O-51).
    PaymentRequestClosed {
        /// The request.
        request: RequestId,
        /// The programme manager.
        by: AccountId,
        /// The recorded reason.
        reason: TextRef,
    },
}
