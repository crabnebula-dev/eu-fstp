//! The payments seam (design section 2.12, I-05, SoD-04, SoD-12).
//!
//! Owned by lane L-MONEY (docs/handoff/m2-design.md section 10). The rules
//! come from `SPEC/02-domain/payment-requests.md` (Flow, Line review,
//! States, Rules, the I-05 NOTE, Milestone closure, I-58 to I-60).
//!
//! - [`PaymentState`] keeps every payment request with its lines, its
//!   status, its finance approver and its releaser. The M5 checks are facts
//!   the domain does not hold in M2, so line review opens on SUBMITTED and
//!   no M2 command reaches CHECKS_FAILED.
//! - [`PaymentChain`] is the typestate of a release. Only
//!   [`PaymentChain::release`] builds a `PaymentChain<Released>`, and it
//!   refuses a releaser who accepted a line of the request or approved it
//!   (I-05, decided 2026-10-25). The only builder of the
//!   [`PaymentReleased`] record outside the decoder takes that chain.
//!
//! Commands this lane decides:
//!
//! - `RequestPayment`, by the lead, on a grant in IN_EXECUTION. Each line
//!   names a milestone of the effective contract version that is not
//!   closed (I-59), and the request keeps paid plus pending within each
//!   milestone amount (I-58).
//! - `AcceptLine`, by an assigned reviewer of the grant with a
//!   [`crate::assignment::ReviewerAct`]. A mentor of the lead is refused,
//!   because the vault relates the two (SoD-12, I-54). The approved amount
//!   is at most the requested amount, and a lower one carries a reason
//!   (I-60). Once every line is decided, the request is ACCEPTED with at
//!   least one approved line above zero, and REJECTED otherwise.
//! - `RequestPaymentChanges`, by an assigned reviewer, on a SUBMITTED request.
//! - `ApprovePayment`, by an active finance approver, on an ACCEPTED request.
//! - `ReleasePayment`, by an active payment releaser, on a
//!   PAYMENT_APPROVED request, through the chain above.
//! - `ConfirmPaid`, by the payment port or a finance approver, on a
//!   RELEASED request.
//! - `WithdrawPaymentRequest`, by the lead, before release.
//! - `ClosePaymentRequest`, by the programme manager, on a request waiting
//!   in CHECKS_FAILED or CHANGES_REQUESTED (O-51).
//!
//! PAID, REJECTED, WITHDRAWN and CLOSED are terminal. The paid total of a
//! grant is the approved amount of its released lines (I-64).
//!
//! Readings of this lane, reported to Daniel:
//!
//! - The acceptors of I-05 are the assigned reviewers who approved a line
//!   above zero. A reviewer who only rejected lines may release (I-05 NOTE).
//! - Reviewer acts end with the grant, since no reviewer act exists on a
//!   terminal proposal.
//! - `ApprovePayment` and `ReleasePayment` are refused once the grant is
//!   COMPLETED or TERMINATED. The counted sum of a closed grant is its paid
//!   total (I-64), so a later release would raise it above what I-14
//!   checked. Its open requests stay unclaimed under P-67.

use std::collections::{BTreeMap, BTreeSet};

use fstp_money::{NonNegAmount, PosAmount};

use crate::assignment::AssignmentKind;
use crate::command::{Actor, Command, Ctx, SystemCause};
use crate::engine::{FoldError, PolicyScope};
use crate::grant::{
    add_opt, at_most, guard, inactive, invalid, record_answer, reused, subject, unknown,
    wrong_state,
};
use crate::id::{AccountId, LineId, MilestoneId, ProposalId, RequestId, TextRef};
use crate::oracle::{Answers, Query};
use crate::record::Record;
use crate::refusal::{Refusal, RuleRef};
use crate::roles::Role;
use crate::rules::StateTag;
use crate::state::{State, UsedId};
use crate::time::Timestamp;

/// One line of a payment request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PaymentLine {
    /// The line.
    pub line: LineId,
    /// The milestone of the same grant it claims against (I-59).
    pub milestone: MilestoneId,
    /// The requested amount.
    pub amount: PosAmount,
}

// ---------------------------------------------------------------------------
// The release chain (I-05)
// ---------------------------------------------------------------------------

/// The typestate of one payment release (design 2.12). Its fields are
/// private, so only the methods below move it from state to state.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PaymentChain<S> {
    request: RequestId,
    grant: ProposalId,
    state: S,
}

/// Every line of the request is decided. The acceptors approved a line
/// above zero.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LinesAccepted {
    acceptors: BTreeSet<AccountId>,
}

/// The finance approver approved the payment.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Approved {
    acceptors: BTreeSet<AccountId>,
    approver: AccountId,
}

/// The payment releaser released the payment. Only
/// [`PaymentChain::release`] builds it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Released {
    acceptors: BTreeSet<AccountId>,
    approver: AccountId,
    releaser: AccountId,
}

impl<S> PaymentChain<S> {
    /// The payment request.
    pub fn request(&self) -> RequestId {
        self.request
    }

    /// The grant.
    pub fn grant(&self) -> ProposalId {
        self.grant
    }
}

impl PaymentChain<LinesAccepted> {
    /// The chain of `request` whose lines `acceptors` decided, rebuilt from
    /// the projection. It needs at least one acceptor.
    fn lines_accepted(
        request: RequestId,
        grant: ProposalId,
        acceptors: BTreeSet<AccountId>,
    ) -> Result<PaymentChain<LinesAccepted>, Refusal> {
        if acceptors.is_empty() {
            return Err(wrong_state());
        }
        Ok(PaymentChain {
            request,
            grant,
            state: LinesAccepted { acceptors },
        })
    }

    /// The approval by the finance approver `by`.
    pub fn approve(self, by: AccountId) -> Result<PaymentChain<Approved>, Refusal> {
        Ok(PaymentChain {
            request: self.request,
            grant: self.grant,
            state: Approved {
                acceptors: self.state.acceptors,
                approver: by,
            },
        })
    }

    /// The assigned reviewers who approved a line above zero.
    pub fn acceptors(&self) -> &BTreeSet<AccountId> {
        &self.state.acceptors
    }
}

impl PaymentChain<Approved> {
    /// The only constructor of `Released`. The releaser `by` is not an
    /// acceptor of any line and not the approver (I-05, SoD-04, R-EX-04).
    pub fn release(self, by: AccountId) -> Result<PaymentChain<Released>, Refusal> {
        if self.state.acceptors.contains(&by) || self.state.approver == by {
            return Err(guard(RuleRef::I05));
        }
        Ok(PaymentChain {
            request: self.request,
            grant: self.grant,
            state: Released {
                acceptors: self.state.acceptors,
                approver: self.state.approver,
                releaser: by,
            },
        })
    }

    /// The finance approver.
    pub fn approver(&self) -> AccountId {
        self.state.approver
    }
}

impl PaymentChain<Released> {
    /// The payment releaser.
    pub fn releaser(&self) -> AccountId {
        self.state.releaser
    }
}

/// The release record. Only [`PaymentReleased::from_chain`] builds it
/// outside the record decoder, so the releaser is never an acceptor or the
/// approver (I-05).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PaymentReleased {
    request: RequestId,
    grant: ProposalId,
    acceptors: BTreeSet<AccountId>,
    approver: AccountId,
    releaser: AccountId,
}

impl PaymentReleased {
    /// Every field, for the record decoder in `codec/` only (design section 3.5).
    pub(crate) fn from_decoded(
        request: RequestId,
        grant: ProposalId,
        acceptors: BTreeSet<AccountId>,
        approver: AccountId,
        releaser: AccountId,
    ) -> Self {
        PaymentReleased {
            request,
            grant,
            acceptors,
            approver,
            releaser,
        }
    }

    /// The release record of a released chain.
    pub fn from_chain(c: &PaymentChain<Released>) -> PaymentReleased {
        PaymentReleased {
            request: c.request,
            grant: c.grant,
            acceptors: c.state.acceptors.clone(),
            approver: c.state.approver,
            releaser: c.state.releaser,
        }
    }

    /// The payment request.
    pub fn request(&self) -> RequestId {
        self.request
    }

    /// The grant.
    pub fn grant(&self) -> ProposalId {
        self.grant
    }

    /// The accounts that accepted lines.
    pub fn acceptors(&self) -> &BTreeSet<AccountId> {
        &self.acceptors
    }

    /// The finance approver.
    pub fn approver(&self) -> AccountId {
        self.approver
    }

    /// The payment releaser.
    pub fn releaser(&self) -> AccountId {
        self.releaser
    }
}

// ---------------------------------------------------------------------------
// The projection
// ---------------------------------------------------------------------------

/// The status of a payment request (`SPEC/02-domain/payment-requests.md` States).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RequestStatus {
    /// Submitted for checks and review.
    Submitted,
    /// Returned with failed checks. The M5 checks reach it.
    ChecksFailed,
    /// Returned with requested changes.
    ChangesRequested,
    /// Every line decided, at least one approved.
    Accepted,
    /// Approved for payment.
    PaymentApproved,
    /// Released.
    Released,
    /// Payment confirmed. Terminal.
    Paid,
    /// Every line rejected. Terminal.
    Rejected,
    /// Withdrawn before release. Terminal.
    Withdrawn,
    /// Closed by the programme manager while waiting. Terminal.
    Closed,
}

impl RequestStatus {
    /// Whether the status is terminal: PAID, REJECTED, WITHDRAWN or CLOSED.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            RequestStatus::Paid
                | RequestStatus::Rejected
                | RequestStatus::Withdrawn
                | RequestStatus::Closed
        )
    }

    /// Whether the request's lines are pending: not yet released, rejected,
    /// withdrawn or closed.
    pub const fn pending(self) -> bool {
        matches!(
            self,
            RequestStatus::Submitted
                | RequestStatus::ChecksFailed
                | RequestStatus::ChangesRequested
                | RequestStatus::Accepted
                | RequestStatus::PaymentApproved
        )
    }

    /// Whether the request's approved lines count as paid.
    pub const fn paid(self) -> bool {
        matches!(self, RequestStatus::Released | RequestStatus::Paid)
    }
}

/// One line of a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Line {
    /// The milestone.
    milestone: MilestoneId,
    /// The requested amount.
    requested: PosAmount,
    /// The deciding reviewer and the approved amount.
    decision: Option<(AccountId, NonNegAmount)>,
}

impl Line {
    /// The amount the line holds against its milestone: the approved
    /// amount once decided, the requested amount before.
    fn holds(&self) -> Option<NonNegAmount> {
        match self.decision {
            Some((_, a)) => Some(a),
            None => NonNegAmount::new(self.requested.amount()).ok(),
        }
    }
}

/// One payment request.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Request {
    /// The grant.
    grant: ProposalId,
    /// The lines.
    lines: BTreeMap<LineId, Line>,
    /// The status.
    status: RequestStatus,
    /// The finance approver.
    approver: Option<AccountId>,
    /// The payment releaser.
    releaser: Option<AccountId>,
}

impl Request {
    /// The assigned reviewers who approved a line above zero (I-05 NOTE).
    /// A reviewer who only rejected lines, approving 0.00, accepted none.
    fn acceptors(&self) -> BTreeSet<AccountId> {
        self.lines
            .values()
            .filter_map(|l| l.decision)
            .filter(|(_, a)| a.amount().minor() > 0)
            .map(|(a, _)| a)
            .collect()
    }
}

/// Payment part of the projection: every payment request.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PaymentState {
    requests: BTreeMap<RequestId, Request>,
}

impl PaymentState {
    /// The payment state before any record.
    pub(crate) const fn genesis() -> PaymentState {
        PaymentState {
            requests: BTreeMap::new(),
        }
    }

    /// The status of `request`.
    pub fn status(&self, request: RequestId) -> Option<RequestStatus> {
        self.requests.get(&request).map(|r| r.status)
    }

    /// The grant of `request`.
    pub fn grant_of(&self, request: RequestId) -> Option<ProposalId> {
        self.requests.get(&request).map(|r| r.grant)
    }

    /// The releaser of `request`, once released.
    pub fn releaser(&self, request: RequestId) -> Option<AccountId> {
        self.requests.get(&request).and_then(|r| r.releaser)
    }

    fn of(&self, grant: ProposalId) -> impl Iterator<Item = &Request> {
        self.requests.values().filter(move |r| r.grant == grant)
    }
}

// ---------------------------------------------------------------------------
// Read API for lane L-MONEY's other modules
// ---------------------------------------------------------------------------

/// The paid total of `grant`: the approved amounts of the lines of its
/// RELEASED and PAID requests (I-64). `None` when nothing was paid.
pub(crate) fn paid_total(state: &State, grant: ProposalId) -> Option<NonNegAmount> {
    state
        .payments
        .of(grant)
        .filter(|r| r.status.paid())
        .flat_map(|r| r.lines.values())
        .filter_map(|l| l.decision.map(|(_, a)| a))
        .fold(None, |acc, a| add_opt(acc, Some(a)))
}

/// Paid plus pending on `milestone` of `grant` (I-58). `None` when nothing.
fn used(state: &State, grant: ProposalId, milestone: MilestoneId) -> Option<NonNegAmount> {
    state
        .payments
        .of(grant)
        .filter(|r| r.status.paid() || r.status.pending())
        .flat_map(|r| r.lines.values())
        .filter(|l| l.milestone == milestone)
        .filter_map(Line::holds)
        .fold(None, |acc, a| add_opt(acc, Some(a)))
}

/// Paid plus pending per milestone of `grant`, for the milestones where
/// it is above zero (I-58, I-61).
pub(crate) fn claimed(state: &State, grant: ProposalId) -> BTreeMap<MilestoneId, NonNegAmount> {
    let milestones: BTreeSet<MilestoneId> = state
        .payments
        .of(grant)
        .flat_map(|r| r.lines.values())
        .map(|l| l.milestone)
        .collect();
    milestones
        .into_iter()
        .filter_map(|m| used(state, grant, m).map(|a| (m, a)))
        .filter(|(_, a)| a.amount().minor() > 0)
        .collect()
}

/// The milestones of `grant` with a line approved above zero in a request
/// that was not withdrawn or closed (I-15, P-65).
pub(crate) fn accepted_milestones(state: &State, grant: ProposalId) -> BTreeSet<MilestoneId> {
    state
        .payments
        .of(grant)
        .filter(|r| !matches!(r.status, RequestStatus::Withdrawn | RequestStatus::Closed))
        .flat_map(|r| r.lines.values())
        .filter(|l| l.decision.is_some_and(|(_, a)| a.amount().minor() > 0))
        .map(|l| l.milestone)
        .collect()
}

/// Whether every payment request of `grant` is terminal (NOTE 12).
pub(crate) fn all_terminal(state: &State, grant: ProposalId) -> bool {
    state.payments.of(grant).all(|r| r.status.is_terminal())
}

// ---------------------------------------------------------------------------
// Guards
// ---------------------------------------------------------------------------

/// The request `request`.
fn request_of(state: &State, request: RequestId) -> Result<&Request, Refusal> {
    state.payments.requests.get(&request).ok_or_else(unknown)
}

/// Refuses unless the actor holds `role` in the programme of `grant`, and
/// returns the actor.
fn holder(state: &State, grant: ProposalId, role: Role, ctx: &Ctx) -> Result<AccountId, Refusal> {
    let by = crate::policy::actor_account(ctx)?;
    let s = subject(state, grant)?;
    crate::policy::require_holder(state, by, s.programme, &[role], ctx.now)?;
    Ok(by)
}

/// Refuses unless the actor holds a reviewer assignment on `grant` that
/// passes the structural reviewer checks, and returns the actor with its
/// `HasConflict` question (I-03, SoD-12).
fn reviewer(state: &State, grant: ProposalId, ctx: &Ctx) -> Result<(AccountId, Query), Refusal> {
    let by = crate::policy::actor_account(ctx)?;
    crate::assignment::qualifying_assignment(state, by, grant, AssignmentKind::Reviewer, ctx.now)
        .ok_or_else(inactive)?;
    Ok((by, crate::assignment::conflict_query(state, by, grant)))
}

/// The records of a `RequestPayment`.
fn check_request(
    state: &State,
    request: RequestId,
    grant: ProposalId,
    lines: &[PaymentLine],
    ctx: &Ctx,
) -> Result<Vec<Record>, Refusal> {
    crate::proposal::life::require_lead(state, grant, ctx)?;
    let s = subject(state, grant)?;
    if s.state != StateTag::InExecution {
        return Err(wrong_state());
    }
    if state.payments.requests.contains_key(&request)
        || state.used_ids.contains(UsedId::Request(request))
    {
        return Err(reused());
    }
    if lines.is_empty() {
        return Err(invalid());
    }
    let ids: BTreeSet<LineId> = lines.iter().map(|l| l.line).collect();
    if ids.len() != lines.len()
        || ids
            .iter()
            .any(|l| state.used_ids.contains(UsedId::Line(*l)))
    {
        return Err(reused());
    }
    let contract = crate::grant::contract_milestones(state, grant).ok_or_else(unknown)?;
    let mut asked: BTreeMap<MilestoneId, NonNegAmount> = BTreeMap::new();
    for l in lines {
        let Some((_, amount, _)) = contract.iter().find(|(m, _, _)| *m == l.milestone) else {
            return Err(invalid());
        };
        if state.money.milestone_closed(grant, l.milestone) {
            return Err(wrong_state());
        }
        if l.amount.amount().currency() != s.currency {
            return Err(invalid());
        }
        let line = NonNegAmount::new(l.amount.amount()).map_err(|_| invalid())?;
        let total = add_opt(asked.get(&l.milestone).copied(), Some(line)).ok_or_else(invalid)?;
        asked.insert(l.milestone, total);
        let claimed = add_opt(used(state, grant, l.milestone), Some(total)).ok_or_else(invalid)?;
        if !at_most(claimed.amount(), amount.amount())? {
            return Err(invalid());
        }
    }
    Ok(vec![Record::PaymentRequested {
        request,
        grant,
        lines: lines.to_vec(),
    }])
}

/// A checked `AcceptLine`, with the acting reviewer and its question.
struct LinePlan {
    record: Record,
    grant: ProposalId,
    reviewer: AccountId,
    conflict: Query,
}

fn check_line(
    state: &State,
    request: RequestId,
    line: LineId,
    approved: NonNegAmount,
    reason: Option<TextRef>,
    ctx: &Ctx,
) -> Result<LinePlan, Refusal> {
    let r = request_of(state, request)?;
    let (by, conflict) = reviewer(state, r.grant, ctx)?;
    if r.status != RequestStatus::Submitted {
        return Err(wrong_state());
    }
    let l = r.lines.get(&line).ok_or_else(unknown)?;
    if l.decision.is_some() {
        return Err(wrong_state());
    }
    if !at_most(approved.amount(), l.requested.amount())? {
        return Err(invalid());
    }
    if approved.amount() != l.requested.amount() && reason.is_none() {
        return Err(invalid());
    }
    Ok(LinePlan {
        record: Record::LineAccepted {
            request,
            line,
            by,
            approved,
            reason,
        },
        grant: r.grant,
        reviewer: by,
        conflict,
    })
}

fn check_changes(
    state: &State,
    request: RequestId,
    reason: TextRef,
    ctx: &Ctx,
) -> Result<LinePlan, Refusal> {
    let r = request_of(state, request)?;
    let (by, conflict) = reviewer(state, r.grant, ctx)?;
    if r.status != RequestStatus::Submitted {
        return Err(wrong_state());
    }
    Ok(LinePlan {
        record: Record::PaymentChangesRequested {
            request,
            by,
            reason,
        },
        grant: r.grant,
        reviewer: by,
        conflict,
    })
}

/// Whether the grant is COMPLETED or TERMINATED. Its counted sum is then
/// its paid total (I-64), so no further payment may be approved or
/// released: a release would raise the sum I-14 counts.
fn grant_closed(state: &State, grant: ProposalId) -> Result<bool, Refusal> {
    Ok(matches!(
        subject(state, grant)?.state,
        StateTag::Completed | StateTag::Terminated
    ))
}

/// The chain of `request` with its lines decided.
fn chain_of(request: RequestId, r: &Request) -> Result<PaymentChain<LinesAccepted>, Refusal> {
    if r.lines.values().any(|l| l.decision.is_none()) {
        return Err(wrong_state());
    }
    PaymentChain::lines_accepted(request, r.grant, r.acceptors())
}

/// The records of the payment commands that ask the vault nothing.
fn decide_plain(state: &State, cmd: &Command, ctx: &Ctx) -> Result<Vec<Record>, Refusal> {
    match cmd {
        Command::RequestPayment {
            request,
            grant,
            lines,
        } => check_request(state, *request, *grant, lines, ctx),
        Command::ApprovePayment { request } => {
            let r = request_of(state, *request)?;
            let by = holder(state, r.grant, Role::FinanceApprover, ctx)?;
            if r.status != RequestStatus::Accepted || grant_closed(state, r.grant)? {
                return Err(wrong_state());
            }
            let approved = chain_of(*request, r)?.approve(by)?;
            Ok(vec![Record::PaymentApproved {
                request: approved.request(),
                by: approved.approver(),
            }])
        }
        Command::ReleasePayment { request } => {
            let r = request_of(state, *request)?;
            let by = holder(state, r.grant, Role::PaymentReleaser, ctx)?;
            if r.status != RequestStatus::PaymentApproved || grant_closed(state, r.grant)? {
                return Err(wrong_state());
            }
            let approver = r.approver.ok_or_else(wrong_state)?;
            let released = chain_of(*request, r)?.approve(approver)?.release(by)?;
            Ok(vec![Record::PaymentReleased(PaymentReleased::from_chain(
                &released,
            ))])
        }
        Command::ConfirmPaid { request } => {
            let r = request_of(state, *request)?;
            match ctx.actor {
                Actor::System(SystemCause::PaymentPort) => {}
                Actor::Account(_) => {
                    holder(state, r.grant, Role::FinanceApprover, ctx)?;
                }
                Actor::System(_) => {
                    return Err(Refusal::new(
                        RuleRef::Actor,
                        crate::refusal::RefusalReason::WrongActor,
                    ));
                }
            }
            if r.status != RequestStatus::Released {
                return Err(wrong_state());
            }
            Ok(vec![Record::PaymentConfirmed {
                request: *request,
                by: ctx.actor,
            }])
        }
        Command::WithdrawPaymentRequest { request } => {
            let r = request_of(state, *request)?;
            let by = crate::proposal::life::require_lead(state, r.grant, ctx)?;
            if !r.status.pending() {
                return Err(wrong_state());
            }
            Ok(vec![Record::PaymentRequestWithdrawn {
                request: *request,
                by,
            }])
        }
        Command::ClosePaymentRequest { request, reason } => {
            let r = request_of(state, *request)?;
            let by = holder(state, r.grant, Role::ProgrammeManager, ctx)?;
            if !matches!(
                r.status,
                RequestStatus::ChecksFailed | RequestStatus::ChangesRequested
            ) {
                return Err(wrong_state());
            }
            Ok(vec![Record::PaymentRequestClosed {
                request: *request,
                by,
                reason: *reason,
            }])
        }
        _ => Err(wrong_state()),
    }
}

/// The checked line review of `cmd`, for the two commands that need a reviewer act.
fn review_plan(state: &State, cmd: &Command, ctx: &Ctx) -> Result<Option<LinePlan>, Refusal> {
    match cmd {
        Command::AcceptLine {
            request,
            line,
            approved,
            reason,
        } => check_line(state, *request, *line, *approved, *reason, ctx).map(Some),
        Command::RequestPaymentChanges { request, reason } => {
            check_changes(state, *request, *reason, ctx).map(Some)
        }
        _ => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// Engine entry points of this lane, called by `crate::engine`.
// ---------------------------------------------------------------------------

/// The vault questions of the payment request commands: `HasConflict` for
/// the reviewer of a line decision or a change request (I-03, SoD-12).
pub(crate) fn queries(state: &State, cmd: &Command, ctx: &Ctx) -> Result<Vec<Query>, Refusal> {
    match review_plan(state, cmd, ctx)? {
        Some(plan) => Ok(vec![plan.conflict]),
        None => {
            decide_plain(state, cmd, ctx)?;
            Ok(Vec::new())
        }
    }
}

/// The records of the payment request commands.
pub(crate) fn decide(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
    answers: &Answers,
) -> Result<Vec<Record>, Refusal> {
    let Some(plan) = review_plan(state, cmd, ctx)? else {
        return decide_plain(state, cmd, ctx);
    };
    let act = crate::assignment::reviewer_act_on(
        state,
        plan.reviewer,
        plan.grant,
        AssignmentKind::Reviewer,
        ctx.now,
        answers,
    )?;
    act.require_proposal(plan.grant)?;
    let mut out = vec![plan.record];
    record_answer(&mut out, &plan.conflict, answers)?;
    Ok(out)
}

/// The request `request` for a fold.
fn request_mut(state: &mut State, request: RequestId) -> Result<&mut Request, FoldError> {
    state
        .payments
        .requests
        .get_mut(&request)
        .ok_or(FoldError::UnknownEntity)
}

/// Moves `request` from one of `from` to `to`, for a fold.
fn move_status<'a>(
    state: &'a mut State,
    request: RequestId,
    from: &[RequestStatus],
    to: RequestStatus,
) -> Result<&'a mut Request, FoldError> {
    let r = request_mut(state, request)?;
    if !from.contains(&r.status) {
        return Err(FoldError::Inconsistent);
    }
    r.status = to;
    Ok(r)
}

/// Folds a payment request record. The fold checks structure only and
/// re-runs no guard, so it follows a release that breaks I-05.
pub(crate) fn apply(
    state: &mut State,
    seq: fstp_ledger::Seq,
    at: Timestamp,
    record: &Record,
) -> Result<(), FoldError> {
    let _ = (seq, at);
    use RequestStatus as S;
    match record {
        Record::PaymentRequested {
            request,
            grant,
            lines,
        } => {
            crate::proposal::draft::draft(state, *grant).ok_or(FoldError::UnknownEntity)?;
            let ids: BTreeSet<LineId> = lines.iter().map(|l| l.line).collect();
            let taken = state.used_ids.contains(UsedId::Request(*request))
                || state.payments.requests.contains_key(request)
                || ids.len() != lines.len()
                || ids
                    .iter()
                    .any(|l| state.used_ids.contains(UsedId::Line(*l)));
            if taken {
                return Err(FoldError::DuplicateId);
            }
            state.used_ids.insert(UsedId::Request(*request));
            for l in &ids {
                state.used_ids.insert(UsedId::Line(*l));
            }
            let lines = lines
                .iter()
                .map(|l| {
                    (
                        l.line,
                        Line {
                            milestone: l.milestone,
                            requested: l.amount,
                            decision: None,
                        },
                    )
                })
                .collect();
            state.payments.requests.insert(
                *request,
                Request {
                    grant: *grant,
                    lines,
                    status: S::Submitted,
                    approver: None,
                    releaser: None,
                },
            );
            Ok(())
        }
        Record::LineAccepted {
            request,
            line,
            by,
            approved,
            ..
        } => {
            let r = request_mut(state, *request)?;
            if r.status != S::Submitted {
                return Err(FoldError::Inconsistent);
            }
            let l = r.lines.get_mut(line).ok_or(FoldError::UnknownEntity)?;
            if l.decision.is_some() {
                return Err(FoldError::Inconsistent);
            }
            l.decision = Some((*by, *approved));
            if r.lines.values().all(|l| l.decision.is_some()) {
                let any = r
                    .lines
                    .values()
                    .any(|l| l.decision.is_some_and(|(_, a)| a.amount().minor() > 0));
                r.status = if any { S::Accepted } else { S::Rejected };
            }
            Ok(())
        }
        Record::PaymentChangesRequested { request, .. } => {
            move_status(state, *request, &[S::Submitted], S::ChangesRequested).map(|_| ())
        }
        Record::PaymentApproved { request, by } => {
            move_status(state, *request, &[S::Accepted], S::PaymentApproved)?.approver = Some(*by);
            Ok(())
        }
        Record::PaymentReleased(x) => {
            move_status(state, x.request, &[S::PaymentApproved], S::Released)?.releaser =
                Some(x.releaser);
            Ok(())
        }
        Record::PaymentConfirmed { request, .. } => {
            move_status(state, *request, &[S::Released], S::Paid).map(|_| ())
        }
        Record::PaymentRequestWithdrawn { request, .. } => move_status(
            state,
            *request,
            &[
                S::Submitted,
                S::ChecksFailed,
                S::ChangesRequested,
                S::Accepted,
                S::PaymentApproved,
            ],
            S::Withdrawn,
        )
        .map(|_| ()),
        Record::PaymentRequestClosed { request, .. } => move_status(
            state,
            *request,
            &[S::ChecksFailed, S::ChangesRequested],
            S::Closed,
        )
        .map(|_| ()),
        _ => Err(FoldError::Inconsistent),
    }
}

/// The vault questions this lane needs for its contribution to the batch of
/// a command that another lane owns. It asks none.
pub(crate) fn contribute_queries(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
) -> Result<Vec<Query>, Refusal> {
    let _ = (state, cmd, ctx);
    Ok(Vec::new())
}

/// The records this lane adds to the batch of a command that another lane
/// owns (`crate::engine` module docs). The payment lane adds none in M2.
pub(crate) fn contribute(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
    answers: &Answers,
    batch: &[Record],
) -> Result<Vec<Record>, Refusal> {
    let _ = (state, cmd, ctx, answers, batch);
    Ok(Vec::new())
}

/// The policy whose P-77 governs a binding action of this lane through MCP
/// (R-MC-05, `crate::engine::PolicyScope`): the frozen policy of the
/// grant's creation call.
pub(crate) fn governing_policy(state: &State, cmd: &Command) -> Result<PolicyScope, Refusal> {
    let grant = match cmd {
        Command::RequestPayment { grant, .. } => *grant,
        Command::AcceptLine { request, .. }
        | Command::ApprovePayment { request }
        | Command::ReleasePayment { request }
        | Command::ConfirmPaid { request }
        | Command::WithdrawPaymentRequest { request }
        | Command::RequestPaymentChanges { request, .. }
        | Command::ClosePaymentRequest { request, .. } => request_of(state, *request)?.grant,
        _ => return Err(wrong_state()),
    };
    crate::grant::call_scope(state, grant)
}
