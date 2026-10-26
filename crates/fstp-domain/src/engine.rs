//! The pure engine functions: queries, decide, apply, replay and due (design section 3.1).
//!
//! - [`queries`] lists the vault questions a command needs.
//! - [`decide`] recomputes those questions itself. It refuses with
//!   `FactsIncomplete` when an answer is missing, and with `StaleFacts`
//!   when an answer's epoch differs from the expected one.
//! - [`apply`] is a structural fold. It never re-runs guards and fails only
//!   on a log the engine could not have produced.
//! - [`due`] lists the System commands enabled at an instant, for the M6
//!   timeline and for tests.
//! - [`stage1_ready`] lists the proposals whose stage 1 close a named FSTP
//!   coordinator may now record (R-LA-03, NOTE 3). `due` never returns
//!   `CloseStage1`, because a System actor cannot record it.
//!
//! This file is a fixed dispatcher, so lanes never edit it (design section 10).
//! It runs the checks that every command shares, then hands the command or
//! record to the lane module that owns it. Each lane fills only its own
//! `queries`, `decide`, `apply`, `due`, `contribute_queries`, `contribute`
//! and `governing_policy` functions.
//!
//! Batches that span lanes. The owning lane decides first. Then every other
//! lane, in the fixed order of [`Lane`], may add records to the batch
//! through its `contribute` function, which sees the records so far.
//! Examples are the end of a proposal's Receiving bindings at a terminal
//! state (lane L-SOD, Q11 A), the release of a reservation on withdrawal
//! (lane L-MONEY, row 15), and the conflicts, releases and voided scores of a
//! vault change (lanes L-REV and L-LIFE, enforcement point 3). Each
//! contributing lane lists the vault questions it needs through
//! `contribute_queries`, which reads only the state and the command. A
//! contribution never removes or reorders earlier records. A stub
//! contribution adds nothing, so a lane that lands later never blocks an
//! earlier one. The contributing lane's own tests start red instead.
//!
//! Shared checks, in order:
//!
//! 1. The command time is not before the latest recorded time.
//! 2. A System actor never arrives through MCP, and a high-risk command
//!    never completes through MCP (I-85).
//! 3. The actor is of a kind the command's actor rule admits, from
//!    [`crate::rules::ACTOR_RULES`] (I-84). Rules that need state, such as a
//!    binding or an assignment, are checked by the owning lane.
//! 4. A binding action through MCP needs P-77 to allow it (R-MC-05). The
//!    owning lane names the governing policy as a [`PolicyScope`], and lane
//!    L-POL reads P-77 from it.
//! 5. In `decide` only: every query has an answer at the expected epoch.
//!
//! Shell-supplied ids are checked by the owning lane against
//! [`crate::state::UsedIds`], because only that lane knows which ids a
//! command introduces and which it references.
//!
//! Status: step W5 integration. Every lane has landed. No command kind
//! reaches a `NotImplemented` refusal, and no fold returns
//! `FoldError::NotImplemented`. Both variants stay so that the codec keeps
//! decoding records and refusals written before. A lane fallback that no
//! command reaches refuses with an internal rule, such as `RuleRef::Row`.

use fstp_ledger::{Entry, Seq};

use crate::command::{Actor, Command, CommandKind, Ctx, Via};
use std::collections::HashSet;

use crate::id::{CallId, ProgrammeId, ProposalId, VaultEpoch};
use crate::oracle::{Answers, Query};
use crate::record::Record;
use crate::refusal::{Refusal, RefusalReason, RuleRef};
use crate::rules::{ActorRule, ParamId, actor_rule};
use crate::state::State;
use crate::time::Timestamp;
use crate::{amendment, assignment, decision, grant, payment, policy, programme, proposal, roles};

/// Why the fold refused a record. Each variant names a log the engine
/// could not have produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FoldError {
    /// The lane that folds this record has not landed yet.
    NotImplemented,
    /// The record refers to an entity that does not exist.
    UnknownEntity,
    /// The record reuses a taken id.
    DuplicateId,
    /// The entry's time is earlier than the latest recorded time.
    TimeBackwards,
    /// The entry's sequence number is not one more than the previous
    /// entry's, or the first entry's is not 1. Only [`replay`] checks it,
    /// because the projection keeps no sequence number (design section 2.14).
    OutOfOrder,
    /// A correction's target is missing or of another kind (I-23).
    CorrectionTarget,
    /// A correction targets a sealed stage (NOTE 3).
    SealedStage,
    /// The record contradicts the state, such as a second publication of a call.
    Inconsistent,
}

impl core::fmt::Display for FoldError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "fold refused the record: {self:?}")
    }
}

impl std::error::Error for FoldError {}

/// The lane module that owns a command kind or a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lane {
    /// L-POL, `policy/`.
    Policy,
    /// L-POL, `programme.rs`.
    Programme,
    /// L-SOD, `roles/`.
    Roles,
    /// L-REV, `assignment.rs`.
    Assignment,
    /// L-LIFE, `proposal/`.
    Proposal,
    /// L-LIFE, `decision.rs`.
    Decision,
    /// L-MONEY, `grant.rs`.
    Grant,
    /// L-MONEY, `payment.rs`.
    Payment,
    /// L-MONEY, `amendment.rs`.
    Amendment,
}

/// Every lane, in the order the dispatcher asks for contributions.
const LANES: [Lane; 9] = [
    Lane::Policy,
    Lane::Programme,
    Lane::Roles,
    Lane::Assignment,
    Lane::Proposal,
    Lane::Decision,
    Lane::Grant,
    Lane::Payment,
    Lane::Amendment,
];

/// The policy version whose P-77 governs a binding action through MCP (R-MC-05).
///
/// The lane that owns the command names it through its `governing_policy`
/// function. Lane L-POL reads P-77 from it in `policy::mcp_binding_allowed`.
#[allow(dead_code, reason = "lanes L-POL to L-MONEY construct and read it")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum PolicyScope {
    /// The frozen policy of a published call. This is the call of the
    /// proposal, assignment, grant, payment request or amendment that the
    /// command acts on.
    Call(CallId),
    /// The head policy version of a programme, for a binding action that no
    /// published call governs: `EditPolicy`, `DraftCall`, `EditCall`,
    /// `ApproveCallPublication` and a conflict declaration before publication.
    /// For `EditPolicy` it is the head the edit is based on, never the new
    /// version, so an edit through MCP cannot unlock itself. Interim reading,
    /// to be confirmed by Daniel.
    Programme(ProgrammeId),
}

/// The lane that decides `kind`.
const fn command_lane(kind: CommandKind) -> Lane {
    use CommandKind as K;
    match kind {
        K::CreateProgramme | K::EditPolicy => Lane::Policy,
        K::DraftCall | K::EditCall | K::ApproveCallPublication | K::PublishCall => Lane::Programme,
        K::GrantRole | K::EndRole | K::ReinstateBinding | K::VaultChanged => Lane::Roles,
        K::DeclareConflict | K::Assign | K::Unassign | K::ReadContent | K::RecordRankingSummary => {
            Lane::Assignment
        }
        K::CreateDraft
        | K::AddTeamMember
        | K::AddGuardian
        | K::RecordPlanVersion
        | K::Submit
        | K::RecordScore
        | K::CorrectScore
        | K::AskQuestion
        | K::RecordNoQuestions
        | K::AnswerQuestions
        | K::SubmitRevision
        | K::ExpireStage2
        | K::DeclineAfterConcern
        | K::ReEnter
        | K::Withdraw => Lane::Proposal,
        K::RecordKnockOut
        | K::AdmitToStage1
        | K::CloseStage1
        | K::RankAfterStage2
        | K::RecordCutOff
        | K::RecordIrcReview => Lane::Decision,
        K::DetermineAmount
        | K::AcceptGrant
        | K::ApproveGrant
        | K::ContractFact
        | K::DeclineNegotiation
        | K::StartExecution
        | K::Complete
        | K::Terminate
        | K::RecordDeliverable
        | K::CloseMilestone => Lane::Grant,
        K::RequestPayment
        | K::AcceptLine
        | K::ApprovePayment
        | K::ReleasePayment
        | K::ConfirmPaid
        | K::WithdrawPaymentRequest
        | K::RequestPaymentChanges
        | K::ClosePaymentRequest => Lane::Payment,
        K::ProposeAmendment | K::RouteAmendment | K::ActivateAmendment => Lane::Amendment,
    }
}

/// The lane that folds `record`. `None` for the audit and outbox records,
/// which leave the projection unchanged (design section 2.14).
const fn record_lane(record: &Record) -> Option<Lane> {
    let lane = match record {
        Record::ProgrammeCreated { .. } | Record::PolicyVersionRecorded { .. } => Lane::Policy,
        Record::CallDrafted { .. }
        | Record::CallEdited { .. }
        | Record::CallApproved { .. }
        | Record::CallPublished { .. } => Lane::Programme,
        Record::BindingGranted(_)
        | Record::BindingEnded(_)
        | Record::BindingSuspended(_)
        | Record::BindingVoided(_)
        | Record::BindingReinstated(_)
        | Record::VaultEpochProcessed { .. } => Lane::Roles,
        Record::Assigned(_)
        | Record::ConflictDeclared(_)
        | Record::ConflictDetected(_)
        | Record::AssignmentReleased(_)
        | Record::ContentRead(_)
        | Record::RankingSummaryRecorded { .. } => Lane::Assignment,
        Record::ProposalCreated { .. }
        | Record::PlanVersionRecorded(_)
        | Record::Submitted { .. }
        | Record::ScoreRecorded(_)
        | Record::ScoreVoided(_)
        | Record::QuestionAsked { .. }
        | Record::NoQuestionsRecorded { .. }
        | Record::AnswersRecorded { .. }
        | Record::RevisionSubmitted { .. }
        | Record::DeferralRecorded { .. }
        | Record::ReEntered { .. }
        | Record::Transitioned(_) => Lane::Proposal,
        Record::KnockOutRecorded { .. }
        | Record::Stage1Closed(_)
        | Record::EffectiveScoreSet(_)
        | Record::CutOffRecorded(_)
        | Record::IrcReviewRecorded { .. } => Lane::Decision,
        Record::AmountDetermined { .. }
        | Record::CapReserved { .. }
        | Record::CapReleased { .. }
        | Record::GrantAccepted { .. }
        | Record::GrantApproved { .. }
        | Record::ContractFactRecorded { .. }
        | Record::GrantDecided(_)
        | Record::NegotiationDeclined { .. }
        | Record::TerminationRecorded { .. }
        | Record::DeliverableRecorded(_)
        | Record::MilestoneClosed { .. } => Lane::Grant,
        Record::PaymentRequested { .. }
        | Record::LineAccepted { .. }
        | Record::PaymentApproved { .. }
        | Record::PaymentReleased(_)
        | Record::PaymentConfirmed { .. }
        | Record::PaymentRequestWithdrawn { .. }
        | Record::PaymentChangesRequested { .. }
        | Record::PaymentRequestClosed { .. } => Lane::Payment,
        Record::AmendmentProposed { .. }
        | Record::AmendmentRouted { .. }
        | Record::AmendmentActivated { .. } => Lane::Amendment,
        Record::VaultOutcome { .. } | Record::OutboxEnqueued(_) => return None,
    };
    Some(lane)
}

/// Whether `rule` admits the kind of actor in `ctx`. Rules that need state
/// admit every account here, and the owning lane checks the rest.
fn admits_actor_kind(rule: ActorRule, ctx: &Ctx) -> bool {
    match rule {
        ActorRule::AnyOf(options) => options.iter().any(|o| admits_actor_kind(*o, ctx)),
        ActorRule::System => matches!(ctx.actor, Actor::System(_)),
        ActorRule::TenantAdmin => matches!(ctx.actor, Actor::Account(_)) && ctx.tenant_admin,
        ActorRule::Lead
        | ActorRule::AnyAccount
        | ActorRule::Holder(_)
        | ActorRule::AssignedReviewer
        | ActorRule::AssignedReviewers
        | ActorRule::Assignee
        | ActorRule::IrcMember
        | ActorRule::IrcMembers
        | ActorRule::Committee
        | ActorRule::ContentReader
        | ActorRule::SystemRecordedBy(_)
        | ActorRule::LeadAndProgrammeManager => matches!(ctx.actor, Actor::Account(_)),
    }
}

/// The checks every command shares, before any lane runs (steps 1 to 4 above).
fn shared_checks(state: &State, cmd: &Command, ctx: &Ctx) -> Result<(), Refusal> {
    if ctx.now < state.now_floor {
        return Err(Refusal::new(RuleRef::Ledger, RefusalReason::ClockBackwards));
    }
    if ctx.via == Via::Mcp {
        if matches!(ctx.actor, Actor::System(_)) {
            return Err(Refusal::new(RuleRef::Actor, RefusalReason::WrongActor));
        }
        if cmd.high_risk() {
            return Err(Refusal::new(RuleRef::I85, RefusalReason::NotThroughMcp));
        }
    }
    let admitted = actor_rule(cmd.kind()).is_some_and(|rule| admits_actor_kind(rule, ctx));
    if !admitted {
        return Err(Refusal::new(RuleRef::Actor, RefusalReason::WrongActor));
    }
    if ctx.via == Via::Mcp && cmd.binding_action() {
        let scope = lane_governing_policy(command_lane(cmd.kind()), state, cmd)?;
        if !policy::mcp_binding_allowed(state, scope)? {
            return Err(Refusal::new(
                RuleRef::Param(ParamId::P77),
                RefusalReason::NotThroughMcp,
            ));
        }
    }
    Ok(())
}

/// The epoch that the answers to `cmd` must carry: the new epoch for
/// `VaultChanged`, and the state's epoch for every other command.
fn expected_epoch(state: &State, cmd: &Command) -> VaultEpoch {
    match cmd {
        Command::VaultChanged { epoch, .. } => *epoch,
        _ => state.epoch,
    }
}

/// The owning lane's vault questions for `cmd`.
fn lane_queries(
    lane: Lane,
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
) -> Result<Vec<Query>, Refusal> {
    match lane {
        Lane::Policy => policy::queries(state, cmd, ctx),
        Lane::Programme => programme::queries(state, cmd, ctx),
        Lane::Roles => roles::queries(state, cmd, ctx),
        Lane::Assignment => assignment::queries(state, cmd, ctx),
        Lane::Proposal => proposal::queries(state, cmd, ctx),
        Lane::Decision => decision::queries(state, cmd, ctx),
        Lane::Grant => grant::queries(state, cmd, ctx),
        Lane::Payment => payment::queries(state, cmd, ctx),
        Lane::Amendment => amendment::queries(state, cmd, ctx),
    }
}

/// The vault questions that `lane` needs for its contribution to the batch of `cmd`.
fn lane_contribute_queries(
    lane: Lane,
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
) -> Result<Vec<Query>, Refusal> {
    match lane {
        Lane::Policy => policy::contribute_queries(state, cmd, ctx),
        Lane::Programme => programme::contribute_queries(state, cmd, ctx),
        Lane::Roles => roles::contribute_queries(state, cmd, ctx),
        Lane::Assignment => assignment::contribute_queries(state, cmd, ctx),
        Lane::Proposal => proposal::contribute_queries(state, cmd, ctx),
        Lane::Decision => decision::contribute_queries(state, cmd, ctx),
        Lane::Grant => grant::contribute_queries(state, cmd, ctx),
        Lane::Payment => payment::contribute_queries(state, cmd, ctx),
        Lane::Amendment => amendment::contribute_queries(state, cmd, ctx),
    }
}

/// The owning lane's records for `cmd`.
fn lane_decide(
    lane: Lane,
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
    answers: &Answers,
) -> Result<Vec<Record>, Refusal> {
    match lane {
        Lane::Policy => policy::decide(state, cmd, ctx, answers),
        Lane::Programme => programme::decide(state, cmd, ctx, answers),
        Lane::Roles => roles::decide(state, cmd, ctx, answers),
        Lane::Assignment => assignment::decide(state, cmd, ctx, answers),
        Lane::Proposal => proposal::decide(state, cmd, ctx, answers),
        Lane::Decision => decision::decide(state, cmd, ctx, answers),
        Lane::Grant => grant::decide(state, cmd, ctx, answers),
        Lane::Payment => payment::decide(state, cmd, ctx, answers),
        Lane::Amendment => amendment::decide(state, cmd, ctx, answers),
    }
}

/// The records that `lane` adds to the batch of `cmd`, given the records so far.
fn lane_contribute(
    lane: Lane,
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
    answers: &Answers,
    batch: &[Record],
) -> Result<Vec<Record>, Refusal> {
    match lane {
        Lane::Policy => policy::contribute(state, cmd, ctx, answers, batch),
        Lane::Programme => programme::contribute(state, cmd, ctx, answers, batch),
        Lane::Roles => roles::contribute(state, cmd, ctx, answers, batch),
        Lane::Assignment => assignment::contribute(state, cmd, ctx, answers, batch),
        Lane::Proposal => proposal::contribute(state, cmd, ctx, answers, batch),
        Lane::Decision => decision::contribute(state, cmd, ctx, answers, batch),
        Lane::Grant => grant::contribute(state, cmd, ctx, answers, batch),
        Lane::Payment => payment::contribute(state, cmd, ctx, answers, batch),
        Lane::Amendment => amendment::contribute(state, cmd, ctx, answers, batch),
    }
}

/// The policy whose P-77 governs `cmd`, named by the lane that owns it.
fn lane_governing_policy(lane: Lane, state: &State, cmd: &Command) -> Result<PolicyScope, Refusal> {
    match lane {
        Lane::Policy => policy::governing_policy(state, cmd),
        Lane::Programme => programme::governing_policy(state, cmd),
        Lane::Roles => roles::governing_policy(state, cmd),
        Lane::Assignment => assignment::governing_policy(state, cmd),
        Lane::Proposal => proposal::governing_policy(state, cmd),
        Lane::Decision => decision::governing_policy(state, cmd),
        Lane::Grant => grant::governing_policy(state, cmd),
        Lane::Payment => payment::governing_policy(state, cmd),
        Lane::Amendment => amendment::governing_policy(state, cmd),
    }
}

/// The vault questions `cmd` needs in `state`, in a stable order: the owning
/// lane's questions, then each contributing lane's in the order of [`LANES`].
/// A question asked twice is kept once, at its first position.
pub fn queries(state: &State, cmd: &Command, ctx: &Ctx) -> Result<Vec<Query>, Refusal> {
    shared_checks(state, cmd, ctx)?;
    let owner = command_lane(cmd.kind());
    let mut out = lane_queries(owner, state, cmd, ctx)?;
    for lane in LANES {
        if lane != owner {
            out.extend(lane_contribute_queries(lane, state, cmd, ctx)?);
        }
    }
    let mut seen = HashSet::new();
    out.retain(|q| seen.insert(q.clone()));
    Ok(out)
}

/// The records `cmd` produces in `state`, or the refusal: the owning lane's
/// records, then each contributing lane's in the order of [`LANES`].
/// Nothing is recorded on a refusal, including a contributing lane's refusal.
pub fn decide(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
    answers: &Answers,
) -> Result<Vec<Record>, Refusal> {
    let needed = queries(state, cmd, ctx)?;
    let epoch = expected_epoch(state, cmd);
    for query in &needed {
        match answers.get(query) {
            None => {
                return Err(Refusal::new(
                    RuleRef::FactsIncomplete,
                    RefusalReason::AnswerMissing,
                ));
            }
            Some(answer) if answer.epoch != epoch => {
                return Err(Refusal::new(
                    RuleRef::StaleFacts,
                    RefusalReason::AnswerStale,
                ));
            }
            Some(_) => {}
        }
    }
    let owner = command_lane(cmd.kind());
    let mut batch = lane_decide(owner, state, cmd, ctx, answers)?;
    for lane in LANES {
        if lane != owner {
            let more = lane_contribute(lane, state, cmd, ctx, answers, &batch)?;
            batch.extend(more);
        }
    }
    Ok(batch)
}

/// Folds one ledger entry's record into `state`. `seq` and `at` come from the entry.
///
/// The fold takes the parts of an entry rather than `Entry<Envelope>`,
/// because the envelope lives in `fstp-engine`, which this crate cannot name (I-10).
/// A refused fold leaves the time floor unchanged. The fold does not check
/// `seq` ordering, because the projection keeps no sequence number. [`replay`]
/// checks it, and the store and `fstp_ledger::verify_append_only` hold the
/// ledger's order.
pub fn apply(state: &mut State, seq: Seq, at: Timestamp, record: &Record) -> Result<(), FoldError> {
    if at < state.now_floor {
        return Err(FoldError::TimeBackwards);
    }
    match record_lane(record) {
        Some(Lane::Policy) => policy::apply(state, seq, at, record)?,
        Some(Lane::Programme) => programme::apply(state, seq, at, record)?,
        Some(Lane::Roles) => roles::apply(state, seq, at, record)?,
        Some(Lane::Assignment) => assignment::apply(state, seq, at, record)?,
        Some(Lane::Proposal) => proposal::apply(state, seq, at, record)?,
        Some(Lane::Decision) => decision::apply(state, seq, at, record)?,
        Some(Lane::Grant) => grant::apply(state, seq, at, record)?,
        Some(Lane::Payment) => payment::apply(state, seq, at, record)?,
        Some(Lane::Amendment) => amendment::apply(state, seq, at, record)?,
        None => {}
    }
    state.now_floor = at;
    Ok(())
}

/// The state after folding `entries` from genesis, in order.
///
/// The ledger numbers entries from 1 with no gaps, so each entry's `seq`
/// must be one more than the previous entry's, starting at 1. Any other
/// sequence fails with [`FoldError::OutOfOrder`].
pub fn replay<'a>(
    entries: impl IntoIterator<Item = &'a Entry<Record>>,
) -> Result<State, FoldError> {
    let mut state = State::genesis();
    let mut previous = Seq::ZERO;
    for entry in entries {
        let expected = previous.raw().checked_add(1).ok_or(FoldError::OutOfOrder)?;
        if entry.seq.raw() != expected {
            return Err(FoldError::OutOfOrder);
        }
        previous = entry.seq;
        apply(
            &mut state,
            entry.seq,
            Timestamp::from_micros(entry.at),
            &entry.record,
        )?;
    }
    Ok(state)
}

/// The System commands enabled at `now`: `ExpireStage2` and `ReEnter` from
/// lane L-LIFE, and `StartExecution` and `Complete` from lane L-MONEY (design
/// section 3.6). Each is issued with a System actor. The two decline commands
/// are not due: the programme manager records them (O-49). `CloseStage1` is not among them, see [`stage1_ready`].
pub fn due(state: &State, now: Timestamp) -> Vec<Command> {
    let mut out = proposal::due(state, now);
    out.extend(grant::due(state, now));
    out
}

/// The proposals whose stage 1 close trigger holds at `now` (NOTE 3, Q2 A).
/// The FSTP coordinator records each close as a named human (R-LA-03), so
/// the M6 timeline offers these to the coordinator instead of issuing them.
pub fn stage1_ready(state: &State, now: Timestamp) -> Vec<ProposalId> {
    decision::stage1_ready(state, now)
}
