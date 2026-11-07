//! The payments seam (design section 2.12, I-05, SoD-04, SoD-12).
//!
//! Owned by lane L-MONEY (docs/handoff/m2-design.md section 10). The rules
//! come from `SPEC/02-domain/payment-requests.md` (Flow, Line review,
//! States, Rules, the I-05 NOTE, Milestone closure, I-58 to I-60).
//!
//! - [`PaymentState`] keeps every payment request with its kind, lines,
//!   status, passed check snapshots, finance approver and releaser. Since
//!   M5 the checks are recorded facts (`RecordChecks`), so line review
//!   opens on UNDER_REVIEW (I-32, M5 design section 4.2).
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
//!   milestone amount (I-58). Hardship lines claim milestones too (Q4 A).
//!   A resubmission names the request in CHECKS_FAILED or
//!   CHANGES_REQUESTED it replaces, which the batch withdraws first.
//! - `RecordChecks`, by the System from the checks runner. The submission
//!   run moves SUBMITTED to UNDER_REVIEW or CHECKS_FAILED. A passed
//!   acceptance run on UNDER_REVIEW records its snapshot, and a failed one
//!   returns the request to CHECKS_FAILED (R-PR-02, R-PR-03).
//! - `AcceptLine`, by an assigned reviewer of the grant with a
//!   [`crate::assignment::ReviewerAct`]. A mentor of the lead is refused,
//!   because the vault relates the two (SoD-12, I-54). The approved amount
//!   is at most the requested amount, and a lower one carries a reason
//!   (I-60). Once every line is decided, the request is ACCEPTED with at
//!   least one approved line above zero, and REJECTED otherwise. The
//!   decision that makes it ACCEPTED needs both passed snapshots (I-32).
//! - `RequestPaymentChanges`, by an assigned reviewer, on a request in
//!   UNDER_REVIEW.
//! - `ApprovePayment`, by an active finance approver, on an ACCEPTED
//!   request. A hardship request needs the vault's `HardshipEvidenceVerified`.
//! - `ReleasePayment`, by an active payment releaser, on a
//!   PAYMENT_APPROVED request, through the chain above. Released plus this
//!   request stays within the granted amount (I-31), and the vault must
//!   answer `BankReleasable` under P-36 (I-33). Both fail closed.
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
    add_opt, at_most, guard, inactive, invalid, record_answer, reused, subject, unknown, vault,
    wrong_state,
};
use crate::id::{
    AccountId, ContentDigest, HardshipEvidenceId, LineId, MilestoneId, ProposalId, RequestId,
    TextRef,
};
use crate::oracle::{Answers, Query};
use crate::policy::SpdxId;
use crate::record::Record;
use crate::refusal::{Refusal, RuleRef};
use crate::roles::Role;
use crate::rules::{ParamId, StateTag};
use crate::state::{State, UsedId};
use crate::time::{Days, Timestamp};

/// One line of a payment request.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PaymentLine {
    /// The line.
    pub line: LineId,
    /// The milestone of the same grant it claims against (I-59).
    pub milestone: MilestoneId,
    /// The requested amount.
    pub amount: PosAmount,
    /// The deliverable evidence and report of the line (R-PR-01, P-34).
    pub evidence: LineEvidence,
}

/// The evidence of one line (`payment-requests.md` Flow, P-34). The
/// checks judge it before any line review (I-32, R-PR-02), so the domain
/// keeps it as given. P-65 lets a partial line carry a report alone.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LineEvidence {
    /// The public location of the deliverables.
    pub location: Option<TextRef>,
    /// The release or commit identifier.
    pub release: Option<TextRef>,
    /// The SPDX licence identifier.
    pub licence: Option<SpdxId>,
    /// The progress or delivery report for the milestone.
    pub report: Option<TextRef>,
}

/// The type of a payment request (`payment-requests.md` Flow, R-PR-04).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PaymentKind {
    /// A claim on milestones of delivered work.
    Milestone,
    /// A hardship contribution. Its lines claim milestones of partly
    /// delivered work, so I-58 and I-31 bound it (M5 design 12.1, Q4).
    /// The evidence stays in the vault, and the request names it only by
    /// this opaque reference. `TODO(legal)`: L-11, Annex 1 reporting.
    Hardship(HardshipEvidenceId),
}

/// The phase of a run of the automated checks (I-32, R-PR-03).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CheckPhase {
    /// At submission. It moves SUBMITTED to UNDER_REVIEW or CHECKS_FAILED.
    Submission,
    /// At acceptance. It must pass before the line decision that makes the
    /// request ACCEPTED.
    Acceptance,
}

/// One automated check (`payment-requests.md` Automated checks).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CheckKind {
    /// The deliverable location is publicly reachable without authentication.
    PublicLocation,
    /// The detected licence is in P-26.
    Licence,
    /// The line fits its milestone's available balance (I-58), and the
    /// request fits the contract total (I-31).
    Balance,
    /// The evidence requirements of P-34 are met.
    Evidence,
}

/// The outcome of one check on one line, or on the whole request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CheckResult {
    /// The line checked, or `None` for the whole request.
    pub line: Option<LineId>,
    /// The check.
    pub check: CheckKind,
    /// The reason of a failure, returned to the grantee (R-PR-02). `None`
    /// when the check passed.
    pub failure: Option<TextRef>,
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
    record_file: ContentDigest,
}

impl PaymentReleased {
    /// Every field, for the record decoder in `codec/` only (design section 3.5).
    pub(crate) fn from_decoded(
        request: RequestId,
        grant: ProposalId,
        acceptors: BTreeSet<AccountId>,
        approver: AccountId,
        releaser: AccountId,
        record_file: ContentDigest,
    ) -> Self {
        PaymentReleased {
            request,
            grant,
            acceptors,
            approver,
            releaser,
            record_file,
        }
    }

    /// The release record of a released chain, with the digest of its
    /// record-only payment record file (M5 design reading 6).
    pub fn from_chain(c: &PaymentChain<Released>, record_file: ContentDigest) -> PaymentReleased {
        PaymentReleased {
            request: c.request,
            grant: c.grant,
            acceptors: c.state.acceptors.clone(),
            approver: c.state.approver,
            releaser: c.state.releaser,
            record_file,
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

    /// The digest of the record-only payment record file. The file holds
    /// the request reference, amount and payee reference, and no bank
    /// details (M5 design reading 6).
    pub fn record_file(&self) -> ContentDigest {
        self.record_file
    }
}

// ---------------------------------------------------------------------------
// The projection
// ---------------------------------------------------------------------------

/// The status of a payment request (`SPEC/02-domain/payment-requests.md` States).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RequestStatus {
    /// Submitted for checks.
    Submitted,
    /// Returned with failed checks (R-PR-02).
    ChecksFailed,
    /// The submission checks passed. Line review is open.
    UnderReview,
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
                | RequestStatus::UnderReview
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
    /// Milestone claim or hardship contribution.
    kind: PaymentKind,
    /// The lines.
    lines: BTreeMap<LineId, Line>,
    /// The status.
    status: RequestStatus,
    /// The snapshot of the passed submission checks (I-32).
    submission: Option<ContentDigest>,
    /// The snapshot of the passed acceptance checks (I-32).
    acceptance: Option<ContentDigest>,
    /// The finance approver.
    approver: Option<AccountId>,
    /// The payment releaser.
    releaser: Option<AccountId>,
}

impl Request {
    /// The sum of the approved amounts of the decided lines. `None` when nothing.
    fn approved_total(&self) -> Option<NonNegAmount> {
        self.lines
            .values()
            .filter_map(|l| l.decision.map(|(_, a)| a))
            .fold(None, |acc, a| add_opt(acc, Some(a)))
    }

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

    /// A read view of every request, in id order (M5 lane L-API). It
    /// names a hardship request's kind only, never its vault evidence
    /// reference (I-86).
    pub fn summaries(&self) -> impl Iterator<Item = RequestSummary> + '_ {
        self.requests.iter().map(|(id, r)| RequestSummary {
            request: *id,
            grant: r.grant,
            hardship: matches!(r.kind, PaymentKind::Hardship(_)),
            status: r.status,
            submission_passed: r.submission.is_some(),
            acceptance_passed: r.acceptance.is_some(),
            lines: r
                .lines
                .iter()
                .map(|(line, l)| LineSummary {
                    line: *line,
                    milestone: l.milestone,
                    requested: l.requested,
                    decision: l.decision,
                })
                .collect(),
        })
    }
}

/// A read view of one payment request (M5 lane L-API).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestSummary {
    /// The request.
    pub request: RequestId,
    /// The grant.
    pub grant: ProposalId,
    /// Whether it is a hardship contribution.
    pub hardship: bool,
    /// The status.
    pub status: RequestStatus,
    /// Whether the submission checks passed (I-32).
    pub submission_passed: bool,
    /// Whether the acceptance checks passed (I-32).
    pub acceptance_passed: bool,
    /// The lines, in id order.
    pub lines: Vec<LineSummary>,
}

/// A read view of one line of a payment request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LineSummary {
    /// The line.
    pub line: LineId,
    /// The milestone it claims.
    pub milestone: MilestoneId,
    /// The requested amount.
    pub requested: PosAmount,
    /// The deciding reviewer and the approved amount, once decided.
    pub decision: Option<(AccountId, NonNegAmount)>,
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
    used_except(state, grant, milestone, None)
}

/// [`used`] without the lines of `except`, the request a resubmission
/// withdraws in the same batch (M5 design reading 4).
fn used_except(
    state: &State,
    grant: ProposalId,
    milestone: MilestoneId,
    except: Option<RequestId>,
) -> Option<NonNegAmount> {
    state
        .payments
        .requests
        .iter()
        .filter(|(id, r)| r.grant == grant && Some(**id) != except)
        .map(|(_, r)| r)
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

/// One `RequestPayment`, as the command carries it.
struct Ask<'a> {
    request: RequestId,
    grant: ProposalId,
    kind: PaymentKind,
    lines: &'a [PaymentLine],
    replaces: Option<RequestId>,
}

/// The records of a `RequestPayment`. A resubmission first withdraws the
/// request it replaces, in the same batch, so the new lines are checked
/// against paid plus pending without the old ones (M5 design reading 4).
fn check_request(state: &State, ask: &Ask<'_>, ctx: &Ctx) -> Result<Vec<Record>, Refusal> {
    let Ask {
        request,
        grant,
        kind,
        lines,
        replaces,
    } = *ask;
    let by = crate::proposal::life::require_lead(state, grant, ctx)?;
    let s = subject(state, grant)?;
    if s.state != StateTag::InExecution {
        return Err(wrong_state());
    }
    let mut out = Vec::new();
    if let Some(old) = replaces {
        let r = request_of(state, old)?;
        if r.grant != grant
            || !matches!(
                r.status,
                RequestStatus::ChecksFailed | RequestStatus::ChangesRequested
            )
        {
            return Err(wrong_state());
        }
        out.push(Record::PaymentRequestWithdrawn { request: old, by });
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
        let claimed = add_opt(
            used_except(state, grant, l.milestone, replaces),
            Some(total),
        )
        .ok_or_else(invalid)?;
        if !at_most(claimed.amount(), amount.amount())? {
            return Err(invalid());
        }
    }
    out.push(Record::PaymentRequested {
        request,
        grant,
        kind,
        lines: lines.to_vec(),
    });
    Ok(out)
}

/// Whether line review is open on a request in `status`: only after the
/// submission checks passed (I-32).
fn open_for_review(status: RequestStatus) -> bool {
    status == RequestStatus::UnderReview
}

/// The records of a `RecordChecks`, by the System from the checks runner.
/// The submission run needs SUBMITTED, the acceptance run UNDER_REVIEW.
/// Every result names a line of the request or the whole request, and
/// every line has at least one result (I-32, R-PR-02).
fn check_checks(
    state: &State,
    request: RequestId,
    phase: CheckPhase,
    results: &[CheckResult],
    snapshot: ContentDigest,
    ctx: &Ctx,
) -> Result<Vec<Record>, Refusal> {
    if !matches!(ctx.actor, Actor::System(_)) {
        return Err(Refusal::new(
            RuleRef::Actor,
            crate::refusal::RefusalReason::WrongActor,
        ));
    }
    let r = request_of(state, request)?;
    let wanted = match phase {
        CheckPhase::Submission => RequestStatus::Submitted,
        CheckPhase::Acceptance => RequestStatus::UnderReview,
    };
    if r.status != wanted {
        return Err(wrong_state());
    }
    let named: BTreeSet<LineId> = results.iter().filter_map(|c| c.line).collect();
    let covered = r.lines.keys().all(|l| named.contains(l));
    if results.is_empty() || !covered || named.iter().any(|l| !r.lines.contains_key(l)) {
        return Err(invalid());
    }
    Ok(vec![Record::ChecksRecorded {
        request,
        phase,
        results: results.to_vec(),
        snapshot,
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
    if !open_for_review(r.status) {
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
    // I-32: the decision that makes the request ACCEPTED needs passed
    // submission and acceptance checks with their snapshots.
    let completes = r
        .lines
        .iter()
        .all(|(id, x)| *id == line || x.decision.is_some());
    let accepts = approved.amount().minor() > 0
        || r.lines
            .values()
            .any(|x| x.decision.is_some_and(|(_, a)| a.amount().minor() > 0));
    if completes && accepts && (r.submission.is_none() || r.acceptance.is_none()) {
        return Err(guard(RuleRef::I32));
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
    if !open_for_review(r.status) {
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
            kind,
            lines,
            replaces,
        } => check_request(
            state,
            &Ask {
                request: *request,
                grant: *grant,
                kind: *kind,
                lines,
                replaces: *replaces,
            },
            ctx,
        ),
        Command::RecordChecks {
            request,
            phase,
            results,
            snapshot,
        } => check_checks(state, *request, *phase, results, *snapshot, ctx),
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
        Command::ReleasePayment {
            request,
            record_file,
        } => {
            let r = request_of(state, *request)?;
            let by = holder(state, r.grant, Role::PaymentReleaser, ctx)?;
            if r.status != RequestStatus::PaymentApproved || grant_closed(state, r.grant)? {
                return Err(wrong_state());
            }
            // I-31: released plus this request stays within the contract
            // amount, the granted total of the effective version.
            let granted = state.money.granted(r.grant).ok_or_else(unknown)?;
            let total =
                add_opt(paid_total(state, r.grant), r.approved_total()).ok_or_else(wrong_state)?;
            if !at_most(total.amount(), granted.amount())? {
                return Err(guard(RuleRef::I31));
            }
            let approver = r.approver.ok_or_else(wrong_state)?;
            let released = chain_of(*request, r)?.approve(approver)?.release(by)?;
            Ok(vec![Record::PaymentReleased(PaymentReleased::from_chain(
                &released,
                *record_file,
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

/// The P-36 hold of the programme of `grant`, from its live value
/// `{"days":N}` as `fstp-programme` records it. Without a readable value
/// the release fails closed (I-33).
fn p36(state: &State, grant: ProposalId) -> Result<Days, Refusal> {
    let refused = guard(RuleRef::Param(ParamId::P36));
    let s = subject(state, grant)?;
    let value = crate::policy::live_values(state, s.programme)
        .and_then(|l| l.opaque.get(&ParamId::P36))
        .ok_or(refused)?;
    let parsed = fstp_json::parse(value.as_str().as_bytes()).map_err(|_| refused)?;
    let fstp_json::Value::Object(o) = &parsed else {
        return Err(refused);
    };
    let days = match o.get("days") {
        Some(fstp_json::Value::Number(n)) if o.len() == 1 => n.as_u64(),
        _ => None,
    };
    days.and_then(|d| u16::try_from(d).ok())
        .map(Days::new)
        .ok_or(refused)
}

/// The vault question of an approval or a release, with the rule a "no"
/// refuses under. A hardship approval asks `HardshipEvidenceVerified`
/// (R-PR-04). A release asks `BankReleasable` at the command's instant
/// under P-36 (I-33). Both fail closed.
fn vault_question(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
) -> Result<Option<(Query, RuleRef)>, Refusal> {
    Ok(match cmd {
        Command::ApprovePayment { request } => {
            let r = request_of(state, *request)?;
            match r.kind {
                PaymentKind::Hardship(evidence) => Some((
                    Query::HardshipEvidenceVerified {
                        grant: r.grant,
                        evidence,
                    },
                    RuleRef::Rpr04,
                )),
                PaymentKind::Milestone => None,
            }
        }
        Command::ReleasePayment { request, .. } => {
            let grant = request_of(state, *request)?.grant;
            Some((
                Query::BankReleasable {
                    grant,
                    at: ctx.now,
                    hold: p36(state, grant)?,
                },
                RuleRef::I33,
            ))
        }
        _ => None,
    })
}

/// The vault questions of the payment request commands: `HasConflict` for
/// the reviewer of a line decision or a change request (I-03, SoD-12),
/// and the question of an approval or a release.
pub(crate) fn queries(state: &State, cmd: &Command, ctx: &Ctx) -> Result<Vec<Query>, Refusal> {
    match review_plan(state, cmd, ctx)? {
        Some(plan) => Ok(vec![plan.conflict]),
        None => {
            decide_plain(state, cmd, ctx)?;
            Ok(vault_question(state, cmd, ctx)?
                .map(|(q, _)| q)
                .into_iter()
                .collect())
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
        let mut out = decide_plain(state, cmd, ctx)?;
        if let Some((q, rule)) = vault_question(state, cmd, ctx)?
            && !record_answer(&mut out, &q, answers)?
        {
            return Err(vault(rule));
        }
        return Ok(out);
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
            kind,
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
                    kind: *kind,
                    lines,
                    status: S::Submitted,
                    submission: None,
                    acceptance: None,
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
            if !open_for_review(r.status) {
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
        Record::PaymentChangesRequested { request, .. } => move_status(
            state,
            *request,
            &[S::Submitted, S::UnderReview],
            S::ChangesRequested,
        )
        .map(|_| ()),
        Record::ChecksRecorded {
            request,
            phase,
            results,
            snapshot,
        } => {
            let passed = results.iter().all(|c| c.failure.is_none());
            let r = request_mut(state, *request)?;
            match (phase, r.status) {
                (CheckPhase::Submission, S::Submitted) if passed => {
                    r.status = S::UnderReview;
                    r.submission = Some(*snapshot);
                }
                (CheckPhase::Acceptance, S::UnderReview) if passed => {
                    r.acceptance = Some(*snapshot);
                }
                (CheckPhase::Submission, S::Submitted)
                | (CheckPhase::Acceptance, S::UnderReview) => r.status = S::ChecksFailed,
                _ => return Err(FoldError::Inconsistent),
            }
            Ok(())
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
                S::UnderReview,
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
        | Command::ReleasePayment { request, .. }
        | Command::RecordChecks { request, .. }
        | Command::ConfirmPaid { request }
        | Command::WithdrawPaymentRequest { request }
        | Command::RequestPaymentChanges { request, .. }
        | Command::ClosePaymentRequest { request, .. } => request_of(state, *request)?.grant,
        _ => return Err(wrong_state()),
    };
    crate::grant::call_scope(state, grant)
}
