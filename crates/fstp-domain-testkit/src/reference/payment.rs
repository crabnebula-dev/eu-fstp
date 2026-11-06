//! Independent reference for the payments seam, written from the spec text (design sections 2.12 and 6.1).
//!
//! Owned by lane L-MONEY (docs/handoff/m2-design.md section 10).
//!
//! Sources: `SPEC/02-domain/payment-requests.md` (Balances, Flow, Line
//! review, States, Rules, the I-05 NOTE, Milestone closure, I-58, I-60,
//! P-65), `SPEC/02-domain/roles-and-sod.md` (SoD-04),
//! `SPEC/02-domain/support-programme.md` (SoD-12),
//! `SPEC/02-domain/invariants.md` (I-05) and
//! `SPEC/01-requirements/functional.md` (R-EX-01, R-EX-04).
//!
//! - [`PayView`] folds the payment records: requests, lines, decisions,
//!   approval, release and confirmation. It keeps the balances of
//!   `payment-requests.md` per milestone in minor units.
//! - [`pay_verdict`] says whether a payment command must be accepted or
//!   refused, and what an accepted one records.
//! - [`check_i05`] is the I-05 and SoD-04 predicate, and [`check_sod12`]
//!   the SoD-12 one. Both read the view, which also records a breach for
//!   every folded release or line acceptance that broke them.
//!
//! # Readings
//!
//! - I-05 (decided 2026-10-25): the payment releaser differs from every
//!   assigned reviewer who approved a line of the request and from the
//!   finance approver (SoD-04). A reviewer who approved a line at 0.00
//!   rejected it, so only an approval above zero makes an acceptor.
//! - `RequestPayment` is the lead's, on a grant in IN_EXECUTION. Each line
//!   names a milestone of the effective contract version that is not
//!   closed (I-59), and the request keeps paid plus pending within each
//!   milestone amount (I-58). The request starts in SUBMITTED. Hardship
//!   lines claim milestones the same way (M5 design 12.1, Q4). A
//!   resubmission names a request of the grant in CHECKS_FAILED or
//!   CHANGES_REQUESTED, which is withdrawn first, so its pending lines do
//!   not count (reading 4).
//! - `RecordChecks` is the System's. Its submission run needs SUBMITTED
//!   and its acceptance run UNDER_REVIEW, and every line has a result. A
//!   passed submission run opens line review in UNDER_REVIEW. A failure in
//!   either run returns the request to CHECKS_FAILED (R-PR-02).
//! - `AcceptLine` is an assigned reviewer's without conflict (I-03), never
//!   a mentor of the grant, whom the vault relates to the lead (SoD-12,
//!   I-54). One decision per line. The approved amount is at most the
//!   requested amount, and a lower one needs a reason (I-60). When every
//!   line is decided, the request is ACCEPTED with at least one approved
//!   line above zero, and REJECTED otherwise. Line review needs
//!   UNDER_REVIEW, and the decision that makes the request ACCEPTED needs
//!   passed submission and acceptance runs with their snapshots (I-32).
//! - `RequestPaymentChanges` is an assigned reviewer's on a request in
//!   UNDER_REVIEW, and makes it CHANGES_REQUESTED.
//! - `ApprovePayment` is an active finance approver's on an ACCEPTED
//!   request. A hardship request needs evidence the vault verified for the
//!   grant (R-PR-04).
//! - `ReleasePayment` is an active payment releaser's on a
//!   PAYMENT_APPROVED request, under I-05. The paid total plus the request
//!   stays within the granted amount (I-31). The vault holds the latest
//!   bank detail write of the grant verified, P-36 days old or more, and
//!   undisputed (I-33). P-36 is read from the head policy as `{"days":N}`.
//!   Test-author choice: both are refused once the grant is COMPLETED or
//!   TERMINATED, since its counted sum is then its paid total (I-64) and a
//!   later release would raise it past the I-14 check.
//! - `ConfirmPaid` is the payment port's or a finance approver's on a
//!   RELEASED request, and makes it PAID.
//! - `WithdrawPaymentRequest` is the lead's before release.
//! - `ClosePaymentRequest` is the programme manager's on a request in
//!   CHECKS_FAILED or CHANGES_REQUESTED, with a reason, and makes it
//!   CLOSED (decided 2026-10-25, O-51).
//! - PAID, REJECTED, WITHDRAWN and CLOSED are terminal.
//! - Paid is the approved amount of released lines, RELEASED or PAID.
//!   Pending is the requested amount of undecided lines and the approved
//!   amount of decided lines in requests not yet released, rejected,
//!   withdrawn or closed.
//!
//! # I-05 compile-fail twins
//!
//! `PaymentChain<Released>` is built only by `release` (design 2.12).
//! Each forbidden construction below is paired with a `no_run` twin that
//! differs only in the forbidden line, so a typo in the shared text breaks
//! the twin and the pair cannot pass vacuously (design 3.5).
//!
//! I-05: `release` exists on an approved chain.
//!
//! ```no_run
//! use fstp_domain::id::AccountId;
//! use fstp_domain::payment::{Approved, LinesAccepted, PaymentChain, Released};
//! use fstp_domain::refusal::Refusal;
//! fn release(c: PaymentChain<Approved>, by: AccountId) -> Result<PaymentChain<Released>, Refusal> {
//!     c.release(by)
//! }
//! ```
//!
//! I-05: a chain whose lines are only accepted cannot be released.
//!
//! ```compile_fail
//! use fstp_domain::id::AccountId;
//! use fstp_domain::payment::{Approved, LinesAccepted, PaymentChain, Released};
//! use fstp_domain::refusal::Refusal;
//! fn release(c: PaymentChain<LinesAccepted>, by: AccountId) -> Result<PaymentChain<Released>, Refusal> {
//!     c.release(by)
//! }
//! ```
//!
//! I-05: a released chain is only ever the result of `release`.
//!
//! ```no_run
//! use fstp_domain::id::AccountId;
//! use fstp_domain::payment::{Approved, PaymentChain, Released};
//! use fstp_domain::refusal::Refusal;
//! fn forge(c: PaymentChain<Approved>, by: AccountId, s: Released) -> Result<PaymentChain<Released>, Refusal> {
//!     let _ = &s;
//!     c.release(by)
//! }
//! ```
//!
//! I-05: a struct literal cannot build a released chain.
//!
//! ```compile_fail
//! use fstp_domain::id::AccountId;
//! use fstp_domain::payment::{Approved, PaymentChain, Released};
//! use fstp_domain::refusal::Refusal;
//! fn forge(c: PaymentChain<Approved>, by: AccountId, s: Released) -> Result<PaymentChain<Released>, Refusal> {
//!     let _ = &s;
//!     Ok(PaymentChain { request: c.request, grant: c.grant, state: s })
//! }
//! ```
//!
//! I-05: the release state can be moved, but not rebuilt.
//!
//! ```no_run
//! use fstp_domain::payment::Released;
//! fn keep(s: Released) -> Released {
//!     s
//! }
//! ```
//!
//! I-05: the release state has private fields.
//!
//! ```compile_fail
//! use fstp_domain::payment::Released;
//! fn keep(s: Released) -> Released {
//!     Released { ..s }
//! }
//! ```
//!
//! I-05: the release record is built from a released chain.
//!
//! ```no_run
//! use fstp_domain::payment::{Approved, PaymentChain, PaymentReleased, Released};
//! use fstp_domain::id::ContentDigest;
//! fn record(c: &PaymentChain<Released>, f: ContentDigest) -> PaymentReleased {
//!     PaymentReleased::from_chain(c, f)
//! }
//! ```
//!
//! I-05: the release record cannot be built from an approved chain.
//!
//! ```compile_fail
//! use fstp_domain::payment::{Approved, PaymentChain, PaymentReleased, Released};
//! use fstp_domain::id::ContentDigest;
//! fn record(c: &PaymentChain<Approved>, f: ContentDigest) -> PaymentReleased {
//!     PaymentReleased::from_chain(c, f)
//! }
//! ```

use std::collections::{BTreeMap, BTreeSet};

use fstp_domain::command::{Actor, Command, SystemCause};
use fstp_domain::id::{
    AccountId, ContentDigest, LineId, MilestoneId, ProposalId, RequestId, TextRef,
};
use fstp_domain::payment::{CheckPhase, CheckResult, PaymentKind, PaymentLine};
use fstp_domain::record::Record;
use fstp_domain::roles::Role;
use fstp_domain::rules::StateTag;
use fstp_domain::time::Days;
use fstp_money::NonNegAmount;

use crate::reference::money::{
    MoneyCx, MoneyExpect, MoneyProposal, MoneyVerdict, Want, minor, sum,
};
use crate::reference::review::holds_active;
use crate::vault::GroundTruth;

/// The state of a payment request (`payment-requests.md` States).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RequestState {
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
    /// Payment confirmed.
    Paid,
    /// Every line rejected.
    Rejected,
    /// Withdrawn before release.
    Withdrawn,
    /// Closed by the programme manager.
    Closed,
}

impl RequestState {
    /// Whether the state is terminal: PAID, REJECTED, WITHDRAWN or CLOSED.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            RequestState::Paid
                | RequestState::Rejected
                | RequestState::Withdrawn
                | RequestState::Closed
        )
    }

    /// Whether the request's lines still count as pending.
    pub const fn pending(self) -> bool {
        matches!(
            self,
            RequestState::Submitted
                | RequestState::ChecksFailed
                | RequestState::UnderReview
                | RequestState::ChangesRequested
                | RequestState::Accepted
                | RequestState::PaymentApproved
        )
    }

    /// Whether the request's approved lines count as paid.
    pub const fn paid(self) -> bool {
        matches!(self, RequestState::Released | RequestState::Paid)
    }
}

/// One line of a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RefLine {
    /// The milestone.
    pub milestone: MilestoneId,
    /// The requested amount, minor units.
    pub requested: i64,
    /// The deciding reviewer and the approved amount.
    pub decided: Option<(AccountId, i64)>,
}

/// One payment request.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RefRequest {
    /// The grant.
    pub grant: ProposalId,
    /// Milestone claim or hardship contribution.
    pub kind: PaymentKind,
    /// Its lines.
    pub lines: BTreeMap<LineId, RefLine>,
    /// Its state.
    pub state: RequestState,
    /// The snapshot of the passed submission checks (I-32).
    pub submission: Option<ContentDigest>,
    /// The snapshot of the passed acceptance checks (I-32).
    pub acceptance: Option<ContentDigest>,
    /// The finance approver.
    pub approver: Option<AccountId>,
    /// The payment releaser.
    pub releaser: Option<AccountId>,
}

impl RefRequest {
    /// The assigned reviewers who approved a line of the request above
    /// zero (I-05 NOTE). A reviewer who only rejected lines approved none.
    pub fn acceptors(&self) -> BTreeSet<AccountId> {
        self.lines
            .values()
            .filter_map(|l| l.decided)
            .filter(|(_, a)| *a > 0)
            .map(|(a, _)| a)
            .collect()
    }
}

/// The payment reference's fold of core records.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PayView {
    /// Requests.
    pub requests: BTreeMap<RequestId, RefRequest>,
    /// Line ids taken.
    pub lines: BTreeSet<LineId>,
}

impl Default for PayView {
    fn default() -> PayView {
        PayView::new()
    }
}

impl PayView {
    /// The view of an empty ledger.
    pub fn new() -> PayView {
        PayView {
            requests: BTreeMap::new(),
            lines: BTreeSet::new(),
        }
    }

    /// The requests of `grant`.
    pub fn requests_of(&self, grant: ProposalId) -> impl Iterator<Item = &RefRequest> {
        self.requests.values().filter(move |r| r.grant == grant)
    }

    /// The paid total of `grant`: the approved amounts of released lines (I-64).
    pub fn paid_total(&self, grant: ProposalId) -> i64 {
        sum(self
            .requests_of(grant)
            .filter(|r| r.state.paid())
            .flat_map(|r| r.lines.values())
            .filter_map(|l| l.decided.map(|(_, a)| a)))
    }

    /// Paid plus pending on `milestone` of `grant`.
    pub fn used(&self, grant: ProposalId, milestone: MilestoneId) -> i64 {
        self.used_except(grant, milestone, None)
    }

    /// Paid plus pending on `milestone` of `grant` without the lines of
    /// `except`, a request a resubmission withdraws in the same batch.
    pub fn used_except(
        &self,
        grant: ProposalId,
        milestone: MilestoneId,
        except: Option<RequestId>,
    ) -> i64 {
        sum(self
            .requests
            .iter()
            .filter(|(id, r)| r.grant == grant && Some(**id) != except)
            .map(|(_, r)| r)
            .filter(|r| r.state.paid() || r.state.pending())
            .flat_map(|r| r.lines.values())
            .filter(|l| l.milestone == milestone)
            .map(|l| l.decided.map_or(l.requested, |(_, a)| a)))
    }

    /// The milestones of `grant` with a line approved above zero in a
    /// request that was not withdrawn or closed (I-15, P-65).
    pub fn accepted_milestones(&self, grant: ProposalId) -> BTreeSet<MilestoneId> {
        self.requests_of(grant)
            .filter(|r| !matches!(r.state, RequestState::Withdrawn | RequestState::Closed))
            .flat_map(|r| r.lines.values())
            .filter(|l| l.decided.is_some_and(|(_, a)| a > 0))
            .map(|l| l.milestone)
            .collect()
    }

    /// Closes `request` (`ClosePaymentRequest`).
    pub fn close(&mut self, request: RequestId) {
        if let Some(r) = self.requests.get_mut(&request) {
            r.state = RequestState::Closed;
        }
    }

    fn get_mut(&mut self, request: RequestId) -> Result<&mut RefRequest, String> {
        self.requests
            .get_mut(&request)
            .ok_or_else(|| format!("payment record on unknown request {request:?}"))
    }

    /// Folds one record. Records outside payments leave the view unchanged.
    /// A release or line acceptance that breaks I-05 or SoD-12 adds a breach.
    pub fn fold(
        &mut self,
        record: &Record,
        truth: &GroundTruth,
        proposals: &BTreeMap<ProposalId, MoneyProposal>,
        breaches: &mut BTreeSet<String>,
    ) -> Result<(), String> {
        match record {
            Record::PaymentRequested {
                request,
                grant,
                kind,
                lines,
            } => {
                let mut out = BTreeMap::new();
                for l in lines {
                    self.lines.insert(l.line);
                    out.insert(
                        l.line,
                        RefLine {
                            milestone: l.milestone,
                            requested: l.amount.amount().minor(),
                            decided: None,
                        },
                    );
                }
                self.requests.insert(
                    *request,
                    RefRequest {
                        grant: *grant,
                        kind: *kind,
                        lines: out,
                        state: RequestState::Submitted,
                        submission: None,
                        acceptance: None,
                        approver: None,
                        releaser: None,
                    },
                );
            }
            Record::LineAccepted {
                request,
                line,
                by,
                approved,
                ..
            } => {
                let r = self.get_mut(*request)?;
                let grant = r.grant;
                let l = r
                    .lines
                    .get_mut(line)
                    .ok_or("LineAccepted on an unknown line")?;
                l.decided = Some((*by, minor(*approved)));
                if r.lines.values().all(|l| l.decided.is_some()) {
                    let any = r
                        .lines
                        .values()
                        .any(|l| l.decided.is_some_and(|(_, a)| a > 0));
                    r.state = if any {
                        RequestState::Accepted
                    } else {
                        RequestState::Rejected
                    };
                }
                if let Some(p) = proposals.get(&grant)
                    && related(truth, *by, p.lead)
                {
                    breaches.insert(format!(
                        "SoD-12: {by:?} accepted a line of {grant:?}, whose lead the vault relates to them"
                    ));
                }
            }
            Record::PaymentChangesRequested { request, .. } => {
                self.get_mut(*request)?.state = RequestState::ChangesRequested;
            }
            Record::ChecksRecorded {
                request,
                phase,
                results,
                snapshot,
            } => {
                let passed = results.iter().all(|c| c.failure.is_none());
                let r = self.get_mut(*request)?;
                match (phase, passed) {
                    (CheckPhase::Submission, true) => {
                        r.submission = Some(*snapshot);
                        r.state = RequestState::UnderReview;
                    }
                    (CheckPhase::Acceptance, true) => r.acceptance = Some(*snapshot),
                    (_, false) => r.state = RequestState::ChecksFailed,
                }
            }
            Record::PaymentApproved { request, by } => {
                let r = self.get_mut(*request)?;
                r.approver = Some(*by);
                r.state = RequestState::PaymentApproved;
            }
            Record::PaymentReleased(x) => {
                let r = self.get_mut(x.request())?;
                let acceptors = r.acceptors();
                let releaser = x.releaser();
                if acceptors.contains(&releaser)
                    || r.approver == Some(releaser)
                    || x.acceptors().contains(&releaser)
                    || x.approver() == releaser
                {
                    breaches.insert(format!(
                        "I-05: {releaser:?} released {:?}, which they accepted or approved",
                        x.request()
                    ));
                }
                r.releaser = Some(releaser);
                r.state = RequestState::Released;
            }
            Record::PaymentConfirmed { request, .. } => {
                self.get_mut(*request)?.state = RequestState::Paid;
            }
            Record::PaymentRequestWithdrawn { request, .. } => {
                self.get_mut(*request)?.state = RequestState::Withdrawn;
            }
            _ => {}
        }
        Ok(())
    }
}

/// Whether the vault relates `a` to `lead`: the same identity, or a
/// recorded relation such as mentoring (I-54).
fn related(truth: &GroundTruth, a: AccountId, lead: AccountId) -> bool {
    match (truth.identity_of(a), truth.identity_of(lead)) {
        (Some(x), Some(y)) => truth.related(x, y),
        _ => false,
    }
}

/// I-05 and SoD-04: no release by an account that accepted a line of the
/// request or approved it, in every folded release.
pub fn check_i05(view: &PayView, breaches: &BTreeSet<String>) -> Result<(), String> {
    if let Some(b) = breaches.iter().find(|b| b.starts_with("I-05:")) {
        return Err(b.clone());
    }
    for (id, r) in &view.requests {
        if let Some(rel) = r.releaser
            && (r.acceptors().contains(&rel) || r.approver == Some(rel))
        {
            return Err(format!(
                "I-05: {rel:?} released {id:?}, which they accepted or approved"
            ));
        }
    }
    Ok(())
}

/// SoD-12: no line of a grant was accepted by an account the vault relates to its lead.
pub fn check_sod12(breaches: &BTreeSet<String>) -> Result<(), String> {
    match breaches.iter().find(|b| b.starts_with("SoD-12:")) {
        Some(b) => Err(b.clone()),
        None => Ok(()),
    }
}

fn refuse(why: impl Into<String>) -> MoneyVerdict {
    MoneyVerdict::Refuse(why.into())
}

fn account(actor: Actor) -> Option<AccountId> {
    match actor {
        Actor::Account(a) => Some(a),
        Actor::System(_) => None,
    }
}

/// The payment verdict on `cmd` by `actor`, or `None` for another command.
pub fn pay_verdict(cx: &MoneyCx<'_>, actor: Actor, cmd: &Command) -> Option<MoneyVerdict> {
    Some(match cmd {
        Command::RequestPayment {
            request,
            grant,
            kind,
            lines,
            replaces,
        } => request_payment(cx, actor, *request, *grant, *kind, lines, *replaces),
        Command::RecordChecks {
            request,
            phase,
            results,
            snapshot,
        } => record_checks(actor, cx, *request, *phase, results, *snapshot),
        Command::AcceptLine {
            request,
            line,
            approved,
            reason,
        } => accept_line(cx, actor, *request, *line, *approved, *reason),
        Command::RequestPaymentChanges { request, reason } => changes(cx, actor, *request, *reason),
        Command::ApprovePayment { request } => approve(cx, actor, *request),
        Command::ReleasePayment {
            request,
            record_file,
        } => release(cx, actor, *request, *record_file),
        Command::ConfirmPaid { request } => confirm(cx, actor, *request),
        Command::WithdrawPaymentRequest { request } => withdraw(cx, actor, *request),
        _ => return None,
    })
}

fn holds(cx: &MoneyCx<'_>, a: AccountId, role: Role, grant: ProposalId) -> bool {
    cx.money
        .programme_of(grant)
        .is_some_and(|p| holds_active(cx.sod, a, role, p, cx.now))
}

#[allow(clippy::too_many_arguments, reason = "one argument per command member")]
fn request_payment(
    cx: &MoneyCx<'_>,
    actor: Actor,
    request: RequestId,
    grant: ProposalId,
    kind: PaymentKind,
    lines: &[PaymentLine],
    replaces: Option<RequestId>,
) -> MoneyVerdict {
    let Some(a) = account(actor) else {
        return refuse("RequestPayment is the lead's");
    };
    if !cx.lead(a, grant) {
        return refuse("RequestPayment is the lead's");
    }
    if cx.money.proposals.get(&grant).map(|p| p.state) != Some(StateTag::InExecution) {
        return refuse("RequestPayment needs IN_EXECUTION");
    }
    if let Some(old) = replaces {
        let open = cx.money.pay.requests.get(&old).is_some_and(|r| {
            r.grant == grant
                && matches!(
                    r.state,
                    RequestState::ChecksFailed | RequestState::ChangesRequested
                )
        });
        if !open {
            return refuse("a resubmission replaces a returned request of the grant");
        }
    }
    if cx.money.pay.requests.contains_key(&request) {
        return refuse("request id reused");
    }
    if lines.is_empty() {
        return refuse("a request has at least one line");
    }
    let ids: BTreeSet<LineId> = lines.iter().map(|l| l.line).collect();
    if ids.len() != lines.len() || ids.iter().any(|l| cx.money.pay.lines.contains(l)) {
        return refuse("line id reused");
    }
    let Some(plan) = cx.money.contract_plan(grant) else {
        return refuse("no contract plan");
    };
    let closed = cx
        .money
        .proposals
        .get(&grant)
        .map(|p| p.closed_milestones.clone())
        .unwrap_or_default();
    let mut asked: BTreeMap<MilestoneId, i64> = BTreeMap::new();
    for l in lines {
        let Some(m) = plan.milestones.get(&l.milestone) else {
            return refuse("I-59: a line names a milestone outside the grant");
        };
        if closed.contains(&l.milestone) {
            return refuse("a line names a closed milestone");
        }
        let e = asked.entry(l.milestone).or_insert(0);
        *e = e.saturating_add(l.amount.amount().minor());
        let used = cx
            .money
            .pay
            .used_except(grant, l.milestone, replaces)
            .saturating_add(*e);
        if used > m.amount {
            return refuse("I-58: paid plus pending would exceed the milestone amount");
        }
    }
    let mut e = MoneyExpect::new();
    if let Some(old) = replaces {
        e.push_exact(Record::PaymentRequestWithdrawn {
            request: old,
            by: a,
        });
    }
    e.push_exact(Record::PaymentRequested {
        request,
        grant,
        kind,
        lines: lines.to_vec(),
    });
    MoneyVerdict::Accept(e)
}

fn open_for_review(r: &RequestState) -> bool {
    matches!(r, RequestState::UnderReview)
}

/// `RecordChecks` is the System's, from the checks runner. The submission
/// run needs SUBMITTED and the acceptance run UNDER_REVIEW. Every line has
/// a result, and every result names a line of the request or none.
fn record_checks(
    actor: Actor,
    cx: &MoneyCx<'_>,
    request: RequestId,
    phase: CheckPhase,
    results: &[CheckResult],
    snapshot: ContentDigest,
) -> MoneyVerdict {
    if !matches!(actor, Actor::System(_)) {
        return refuse("RecordChecks is the System's");
    }
    let Some(r) = cx.money.pay.requests.get(&request) else {
        return refuse("unknown request");
    };
    let wanted = match phase {
        CheckPhase::Submission => RequestState::Submitted,
        CheckPhase::Acceptance => RequestState::UnderReview,
    };
    if r.state != wanted {
        return refuse("the checks run on SUBMITTED, then on UNDER_REVIEW");
    }
    let named: BTreeSet<LineId> = results.iter().filter_map(|c| c.line).collect();
    if results.is_empty()
        || r.lines.keys().any(|l| !named.contains(l))
        || named.iter().any(|l| !r.lines.contains_key(l))
    {
        return refuse("R-PR-02: every line of the request has a check result");
    }
    let mut e = MoneyExpect::new();
    e.push_exact(Record::ChecksRecorded {
        request,
        phase,
        results: results.to_vec(),
        snapshot,
    });
    MoneyVerdict::Accept(e)
}

fn accept_line(
    cx: &MoneyCx<'_>,
    actor: Actor,
    request: RequestId,
    line: LineId,
    approved: NonNegAmount,
    reason: Option<TextRef>,
) -> MoneyVerdict {
    let Some(a) = account(actor) else {
        return refuse("AcceptLine is an assigned reviewer's");
    };
    let Some(r) = cx.money.pay.requests.get(&request) else {
        return refuse("unknown request");
    };
    if !cx.reviewer(a, r.grant) {
        return refuse("I-03, SoD-12: AcceptLine is an assigned reviewer's without conflict");
    }
    if !open_for_review(&r.state) {
        return refuse("the request is not under review");
    }
    let Some(l) = r.lines.get(&line) else {
        return refuse("unknown line");
    };
    if l.decided.is_some() {
        return refuse("the line is decided");
    }
    let amount = minor(approved);
    if amount > l.requested {
        return refuse("I-60: the approved amount exceeds the requested amount");
    }
    if amount < l.requested && reason.is_none() {
        return refuse("I-60: a lower approval needs a reason");
    }
    let last = r
        .lines
        .iter()
        .all(|(id, x)| *id == line || x.decided.is_some());
    let any = amount > 0
        || r.lines
            .values()
            .any(|x| x.decided.is_some_and(|(_, v)| v > 0));
    if last && any && (r.submission.is_none() || r.acceptance.is_none()) {
        return refuse("I-32: acceptance needs passed checks and both snapshots");
    }
    let mut e = MoneyExpect::new();
    e.push_exact(Record::LineAccepted {
        request,
        line,
        by: a,
        approved,
        reason,
    });
    MoneyVerdict::Accept(e)
}

fn changes(cx: &MoneyCx<'_>, actor: Actor, request: RequestId, reason: TextRef) -> MoneyVerdict {
    let Some(a) = account(actor) else {
        return refuse("RequestPaymentChanges is an assigned reviewer's");
    };
    let Some(r) = cx.money.pay.requests.get(&request) else {
        return refuse("unknown request");
    };
    if !cx.reviewer(a, r.grant) {
        return refuse("RequestPaymentChanges is an assigned reviewer's without conflict");
    }
    if !open_for_review(&r.state) {
        return refuse("the request is not under review");
    }
    let mut e = MoneyExpect::new();
    e.push_exact(Record::PaymentChangesRequested {
        request,
        by: a,
        reason,
    });
    MoneyVerdict::Accept(e)
}

/// Whether the grant reached COMPLETED or TERMINATED.
fn grant_closed(cx: &MoneyCx<'_>, grant: ProposalId) -> bool {
    cx.money
        .proposals
        .get(&grant)
        .is_some_and(crate::reference::money::MoneyProposal::closed)
}

fn approve(cx: &MoneyCx<'_>, actor: Actor, request: RequestId) -> MoneyVerdict {
    let Some(a) = account(actor) else {
        return refuse("ApprovePayment is the finance approver's");
    };
    let Some(r) = cx.money.pay.requests.get(&request) else {
        return refuse("unknown request");
    };
    if !holds(cx, a, Role::FinanceApprover, r.grant) {
        return refuse("ApprovePayment is the finance approver's");
    }
    if r.state != RequestState::Accepted {
        return refuse("ApprovePayment needs ACCEPTED");
    }
    if grant_closed(cx, r.grant) {
        return refuse("I-64: no approval once the grant is COMPLETED or TERMINATED");
    }
    if let PaymentKind::Hardship(evidence) = r.kind
        && !cx.truth.hardship_verified(r.grant, evidence)
    {
        return refuse("R-PR-04: the hardship evidence is not verified in the vault");
    }
    let mut e = MoneyExpect::new();
    e.push_exact(Record::PaymentApproved { request, by: a });
    MoneyVerdict::Accept(e)
}

fn release(
    cx: &MoneyCx<'_>,
    actor: Actor,
    request: RequestId,
    record_file: ContentDigest,
) -> MoneyVerdict {
    let Some(a) = account(actor) else {
        return refuse("ReleasePayment is the payment releaser's");
    };
    let Some(r) = cx.money.pay.requests.get(&request) else {
        return refuse("unknown request");
    };
    if !holds(cx, a, Role::PaymentReleaser, r.grant) {
        return refuse("ReleasePayment is the payment releaser's");
    }
    if r.state != RequestState::PaymentApproved {
        return refuse("ReleasePayment needs PAYMENT_APPROVED");
    }
    if grant_closed(cx, r.grant) {
        return refuse("I-64, I-14: no release once the grant is COMPLETED or TERMINATED");
    }
    let granted = cx.money.proposals.get(&r.grant).and_then(|p| p.granted);
    let this: i64 = r
        .lines
        .values()
        .filter_map(|l| l.decided.map(|(_, v)| v))
        .sum();
    if granted.is_none_or(|g| cx.money.pay.paid_total(r.grant).saturating_add(this) > g) {
        return refuse("I-31: the release would exceed the contract amount");
    }
    let hold = cx
        .money
        .programme_of(r.grant)
        .and_then(|p| cx.money.head(p))
        .and_then(|p| p.p36);
    if !hold.is_some_and(|d| cx.truth.bank_releasable(r.grant, cx.now, Days::new(d))) {
        return refuse("I-33: the bank details are inside the hold, unverified or disputed");
    }
    let acceptors = r.acceptors();
    let Some(approver) = r.approver else {
        return refuse("no approver");
    };
    if acceptors.contains(&a) || approver == a {
        return refuse("I-05, SoD-04: the releaser accepted a line or approved the payment");
    }
    let mut e = MoneyExpect::new();
    e.wants.push(Want::Release {
        request,
        grant: r.grant,
        acceptors: acceptors.clone(),
        approver,
        releaser: a,
        record_file,
    });
    if let Ok(rec) = forge_release(request, r.grant, &acceptors, approver, a, record_file) {
        e.synth.push(rec);
    }
    MoneyVerdict::Accept(e)
}

fn confirm(cx: &MoneyCx<'_>, actor: Actor, request: RequestId) -> MoneyVerdict {
    let Some(r) = cx.money.pay.requests.get(&request) else {
        return refuse("unknown request");
    };
    let ok = match actor {
        Actor::System(SystemCause::PaymentPort) => true,
        Actor::Account(a) => holds(cx, a, Role::FinanceApprover, r.grant),
        Actor::System(_) => false,
    };
    if !ok {
        return refuse("ConfirmPaid is the payment port's or the finance approver's");
    }
    if r.state != RequestState::Released {
        return refuse("ConfirmPaid needs RELEASED");
    }
    let mut e = MoneyExpect::new();
    e.push_exact(Record::PaymentConfirmed { request, by: actor });
    MoneyVerdict::Accept(e)
}

fn withdraw(cx: &MoneyCx<'_>, actor: Actor, request: RequestId) -> MoneyVerdict {
    let Some(a) = account(actor) else {
        return refuse("WithdrawPaymentRequest is the lead's");
    };
    let Some(r) = cx.money.pay.requests.get(&request) else {
        return refuse("unknown request");
    };
    if !cx.lead(a, r.grant) {
        return refuse("WithdrawPaymentRequest is the lead's");
    }
    if !r.state.pending() {
        return refuse("a request is withdrawn before release");
    }
    let mut e = MoneyExpect::new();
    e.push_exact(Record::PaymentRequestWithdrawn { request, by: a });
    MoneyVerdict::Accept(e)
}

/// Builds a `PaymentReleased` through the record codec, since its payload
/// has private fields. Used by reference runs and by the teeth faults.
pub fn forge_release(
    request: RequestId,
    grant: ProposalId,
    acceptors: &BTreeSet<AccountId>,
    approver: AccountId,
    releaser: AccountId,
    record_file: ContentDigest,
) -> Result<Record, String> {
    let list: Vec<String> = acceptors
        .iter()
        .map(|a| format!("\"{}\"", a.raw()))
        .collect();
    let hex: String = record_file
        .bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let text = format!(
        "{{\"acceptors\":[{}],\"approver\":\"{}\",\"grant\":\"{}\",\"record_file\":\"{}\",\
         \"releaser\":\"{}\",\"request\":\"{}\",\"type\":\"PaymentReleased\"}}",
        list.join(","),
        approver.raw(),
        grant.raw(),
        hex,
        releaser.raw(),
        request.raw()
    );
    crate::reference::money::decode_record(&text)
}
