//! Independent reference for negotiation, grants, execution and amendments, written from the spec text (design sections 2.11, 3.2 and 6.1).
//!
//! Owned by lane L-MONEY (docs/handoff/m2-design.md section 10).
//!
//! Sources:
//!
//! - `SPEC/02-domain/state-machine.md`: NEGOTIATION to its exits, GRANTED,
//!   IN_EXECUTION, COMPLETED, TERMINATED, NOTES 9, 11, 12 and 13, Amendments.
//! - `SPEC/02-domain/contracts.md`: Amount and recipient cap, Repeat grants
//!   and amendments, Parties, Rules.
//! - `SPEC/02-domain/payment-requests.md`: Milestone closure, P-65, P-67, I-64.
//! - `SPEC/02-domain/roles-and-sod.md`: Identity discovery.
//! - `SPEC/02-domain/invariants.md`: I-04, I-06, I-13, I-14, I-15, I-18, I-64.
//! - `SPEC/01-requirements/functional.md`: R-NG-02 to R-NG-05, R-EX-01 to R-EX-04.
//!
//! The reference shares only id, command and record
//! types with production. It never calls a production guard.
//!
//! - [`MoneyView`] folds core records into the money facts: policies,
//!   calls, plans, determinations, reservations, grants, closures,
//!   deliverables, amendments and payments ([`crate::reference::payment`]).
//!   Amounts are integer minor units, compared with plain integer
//!   arithmetic. [`MoneyView::fold_batch`] records a breach when a batch
//!   grants or reserves against I-13, I-14 or I-15, so the predicates also
//!   catch a broken engine whose records the view must follow.
//! - [`money_verdict`] says whether a command of this lane must be
//!   accepted or refused, and what an accepted one must record
//!   ([`MoneyExpect`]). [`check_money_batch`] compares a production batch
//!   with it. [`synthesize`] builds the records for a run on the
//!   references alone.
//! - [`check_i13`], [`check_i14`], [`check_i15`] and [`check_i64`] are the
//!   invariant predicates. They read the view and the vault facts only.
//!
//! # Readings
//!
//! Each reading is the strictest one the spec text allows that every
//! source satisfies at once. Readings marked as test-author choices fill a
//! gap. The implementer can match them or raise them with Daniel.
//!
//! - The recipient for P-05 is the verified identity of the applicant
//!   lead. An unverified lead counts alone, as the vault groups it. The
//!   counted sum of a proposal is its granted amount plus its open
//!   reservation. After COMPLETED or TERMINATED it is the paid total of the
//!   grant: the approved amounts of its released and paid requests (I-64).
//! - The cap a call enforces is the lower of its publication snapshot of
//!   P-05 and the live value (P-05 NOTE 7). Every state keeps each
//!   identity's counted sum within the live P-05 of the programme. Every
//!   batch that raises a proposal's counted sum, or records its grant,
//!   keeps the identity's counted sum within the cap of that proposal's
//!   call. Test-author choice: an open reservation counts under the
//!   recipient the vault knew when it opened, since a later verification
//!   may merge two of them above P-05 (Identity discovery).
//! - `DetermineAmount` is an assigned reviewer's: an active reviewer
//!   assignment on the proposal in its current call, an active committee
//!   member binding, no conflict fact and no vault conflict (I-03,
//!   R-NG-03). It needs NEGOTIATION and a fresh decision id.
//!   `agreed` names the plan the effective score carries forward (I-09),
//!   or a negotiated plan of the proposal. The granted amount is the total
//!   of the effective plan minus the recorded deductions, each with its
//!   reason, and lies within P-04 inclusive (I-13). The agreed plan's
//!   total equals the granted amount (design 2.11), so a deduction needs a
//!   negotiated plan that carries it. It must keep the identity's counted sum, without
//!   this proposal's own reservation, within the call's cap (I-14). It
//!   records `AmountDetermined` and `CapReserved` for the granted amount,
//!   and `CapReleased` for an earlier reservation of the proposal.
//!   Test-author choice: a determination after the lead's acceptance or
//!   the programme manager's approval is refused, because they accepted
//!   the amount determined. No test probes it.
//! - `AcceptGrant` is the lead's, `ApproveGrant` an active programme
//!   manager's, and `ContractFact` the System's, from the contract port.
//!   Each needs NEGOTIATION, and the two decisions need fresh ids. The
//!   command that completes the three facts takes NEGOTIATION to GRANTED
//!   in the same batch when every guard of the row holds: identity
//!   verified, guardian consent if minor (I-18), an open reservation equal
//!   to the determined amount within P-04 and the cap, SoD-09 for the lead,
//!   I-04 and I-06 for every held Receiving account of the proposal, and the
//!   I-15 record. When a guard fails, the completing command is refused,
//!   so it can be sent again once the guard holds. Test-author choice: before any
//!   determination these commands may be refused or recorded, and nothing
//!   is granted. A contract fact outside NEGOTIATION, or a repeated
//!   one, may be refused or recorded too, and never moves the proposal.
//! - `DeclineNegotiation` is an active programme manager's, never the
//!   System's (NOTE 13). It needs NEGOTIATION and a failure that NOTE 9
//!   lists: the lead is not verified; SoD-09 refuses the lead; a Receiving
//!   binding of the proposal was voided under I-04 or I-06; no amount can
//!   keep I-13, because the effective plan total lies below the P-04
//!   minimum and no deduction can raise it; no amount can keep I-14,
//!   because the cap headroom lies below the smallest amount still open;
//!   the I-15 record is incomplete; or guardian consent is missing for a
//!   minor. The smallest amount still open is the determined amount once
//!   the lead accepted or the programme manager approved it, and the P-04
//!   minimum before (NOTE 9, decided 2026-10-26). A plan total above the
//!   headroom is no failure while the P-04 minimum fits, since the lead
//!   may propose a smaller negotiated plan. A plan total above the P-04
//!   maximum is no failure either, for the same reason. The headroom reads
//!   the stricter of the snapshot and the live P-05. Amount failures count
//!   with or without an open reservation. The recorded reason
//!   is one of the failures that hold. The batch releases an open
//!   reservation.
//! - `Withdraw` from NEGOTIATION releases an open reservation in the same
//!   batch (row 15, design 2.11).
//! - `StartExecution` is the System's, in GRANTED, from the earliest
//!   milestone start date of the effective contract version: the agreed
//!   plan, or the plan of the last activated amendment (NOTE 11).
//! - `Terminate` is an active programme manager's, in GRANTED or
//!   IN_EXECUTION, with a fresh decision id and a reason.
//! - `CloseMilestone` is an active programme manager's, in IN_EXECUTION,
//!   for a milestone of the effective contract version not closed yet,
//!   with a reason (NOTE 12, O-51). No timer or balance closes a milestone.
//! - `Complete` is the System's, in IN_EXECUTION, once every milestone of
//!   the effective contract version is closed and every payment request of
//!   the grant is PAID, REJECTED, WITHDRAWN or CLOSED (NOTE 12).
//! - `RecordDeliverable` is the System's, from the M5 checks, on a grant
//!   in GRANTED or IN_EXECUTION, for a milestone of the effective contract
//!   version, with a fresh deliverable id.
//! - I-15: the same applicant is the verified identity of the lead,
//!   tenant-wide. Its prior deliverables are every deliverable accepted so
//!   far under that identity's earlier grants. Each must carry a licence in
//!   the P-26 of the call that funded it, read as the call the grant was
//!   created in (NOTE 8). Under P-65 "progress report", a partial claim
//!   without public deliverables leaves the record incomplete until the
//!   final claim. Test-author choice: every milestone of a prior grant with
//!   an accepted payment line needs an accepted deliverable under that
//!   P-26, whatever P-65 says. Under "public deliverables" every line
//!   carries its deliverables, so the rule only bites on a missing record.
//!   An amendment also needs this grant's own record complete.
//! - Amendments leave the proposal state unchanged. `ProposeAmendment` is
//!   the lead's or an assigned reviewer's, on a GRANTED or IN_EXECUTION
//!   grant, naming a live plan of origin "amendment" of the grant that no
//!   other amendment names. The programme manager routes it (P-14).
//!   `ActivateAmendment` is the System's, on a routed amendment whose plan
//!   is still live. It needs the I-15 record, the amended total within
//!   P-04 (I-13) and the identity's counted sum with the amended total
//!   within the cap (I-14). Every milestone with a paid or pending amount
//!   stays in the amended plan at no less than that amount (I-61), so the
//!   claims stay within the amended total (I-31). The amended total then
//!   counts.
//!   An exempt route activates at once. An IRC route needs the IRC review
//!   of the amendment first (R-IR-04).
//! - The IRC review of an amendment (step W5 integration, test-author
//!   choices where marked). The FSTP coordinator assigns IRC members to the
//!   grant with `AssignmentKind::Amendment` naming an amendment routed to
//!   IRC review and not yet activated, on a GRANTED or IN_EXECUTION grant.
//!   The assignment rules of an IRC assignment apply: an active IRC member
//!   binding, no duplicate, I-02 within the programme, no conflict fact or
//!   vault conflict (I-03), and the P-11 handle rule. Each assignee declares
//!   on the assignment and then records one `RecordIrcReview` on it. The
//!   batch holds no transition, since the proposal state never changes.
//!   Test-author choice: once a concern is recorded on the amendment, no
//!   further review is taken and the amendment cannot be activated. An IRC
//!   route activates once at least P-15 active amendment assignments exist,
//!   every one validated, and none awaits its declaration (R-IR-01 read for
//!   amendments, R-IR-04).
//! - New plans of origin "negotiated" (in NEGOTIATION) and "amendment" (in
//!   GRANTED or IN_EXECUTION) are the lead's, with the same structural
//!   checks as a submitted plan, superseding the live plan. An amendment
//!   plan may keep a milestone of the effective contract version under its
//!   id, and every other milestone id is fresh (I-61). The applicant
//!   lead proposes plan content, and the assigned reviewers set the amount
//!   with `DetermineAmount` (R-NG-03). The agreed plan of a determination is
//!   the effective plan or a negotiated plan of the proposal, and its total
//!   equals the granted amount, so a deduction needs a negotiated plan that
//!   carries it (design 2.11).

use std::collections::{BTreeMap, BTreeSet};

use fstp_domain::amendment::AmendmentRoute;
use fstp_domain::assignment::AssignmentKind;
use fstp_domain::command::{Actor, Command, ContractEvent};
use fstp_domain::decision::{IrcVerdict, NegotiationFailure};
use fstp_domain::grant::IneligibleCost;
use fstp_domain::id::{
    AccountId, AmendmentId, AssignmentId, CallId, ContractId, DecisionId, DeliverableId,
    MilestoneId, PlanVersionId, ProgrammeId, ProposalId, RequestId, TextRef,
};
use fstp_domain::proposal::{PlanOrigin, Task};
use fstp_domain::record::{Record, RulesVersion, Transitioned};
use fstp_domain::refusal::RuleRef;
use fstp_domain::roles::Role;
use fstp_domain::rules::{Row, StateTag};
use fstp_domain::time::Timestamp;
use fstp_json::{ToJson, Value};
use fstp_money::NonNegAmount;

use crate::reference::lifecycle::LifeView;
use crate::reference::payment::{PayView, RequestState, pay_verdict};
use crate::reference::review::{RevView, holds_active, team_of};
use crate::reference::sod::{self, RefGroup};
use crate::vault::{GroundTruth, IdentityTag};

// ---------------------------------------------------------------------------
// Amounts
// ---------------------------------------------------------------------------

/// The minor units of `a`, cents for EUR.
pub fn minor(a: NonNegAmount) -> i64 {
    a.amount().minor()
}

/// The sum of `items`, saturating. Amounts in the models are small.
pub fn sum(items: impl IntoIterator<Item = i64>) -> i64 {
    items.into_iter().fold(0i64, i64::saturating_add)
}

/// The total of `tasks` in minor units.
pub fn total_of(tasks: &[Task]) -> i64 {
    sum(tasks
        .iter()
        .flat_map(|t| t.milestones.iter())
        .map(|m| m.amount.amount().minor()))
}

// ---------------------------------------------------------------------------
// Extension commands, read through the command codec
// ---------------------------------------------------------------------------

/// A command that the stub interface does not declare yet, read from its
/// JSON form (`CloseMilestone` and `ClosePaymentRequest`, lane scope W5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Ext {
    /// `CloseMilestone { proposal, milestone, reason }`.
    CloseMilestone {
        /// The grant.
        proposal: ProposalId,
        /// The milestone.
        milestone: MilestoneId,
    },
    /// `ClosePaymentRequest { request, reason }`.
    ClosePaymentRequest {
        /// The request.
        request: RequestId,
    },
}

/// The member `name` of the object `v` as a canonical decimal id.
fn id_member(v: &Value, name: &str) -> Option<u128> {
    match v {
        Value::Object(o) => match o.get(name) {
            Some(Value::String(s)) => s.parse::<u128>().ok(),
            _ => None,
        },
        _ => None,
    }
}

/// The `type` member of the JSON form of a command or record.
pub fn type_name(v: &Value) -> Option<String> {
    match v {
        Value::Object(o) => match o.get("type") {
            Some(Value::String(s)) => Some(s.clone()),
            _ => None,
        },
        _ => None,
    }
}

/// The extension command `cmd` is, if any.
pub fn ext_of(cmd: &Command) -> Option<Ext> {
    let v = cmd.to_json();
    match type_name(&v)?.as_str() {
        "CloseMilestone" => Some(Ext::CloseMilestone {
            proposal: ProposalId::from_raw(id_member(&v, "proposal")?),
            milestone: MilestoneId::from_raw(id_member(&v, "milestone")?),
        }),
        "ClosePaymentRequest" => Some(Ext::ClosePaymentRequest {
            request: RequestId::from_raw(id_member(&v, "request")?),
        }),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// The view
// ---------------------------------------------------------------------------

/// The money values of one policy version.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MoneyPolicy {
    /// The programme.
    pub programme: ProgrammeId,
    /// P-04 minimum, minor units.
    pub p04_min: i64,
    /// P-04 maximum, minor units.
    pub p04_max: i64,
    /// P-05, minor units.
    pub p05: i64,
    /// P-26 SPDX identifiers.
    pub p26: BTreeSet<String>,
}

/// A call as the money reference sees it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MoneyCall {
    /// The programme.
    pub programme: ProgrammeId,
    /// The policy version frozen at publication.
    pub frozen: Option<fstp_domain::id::PolicyVersionId>,
}

/// One milestone of a plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MoneyMilestone {
    /// Its amount, minor units.
    pub amount: i64,
    /// Its start date.
    pub start: Timestamp,
}

/// A plan version.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MoneyPlan {
    /// The proposal.
    pub proposal: ProposalId,
    /// The origin.
    pub origin: PlanOrigin,
    /// Its milestones.
    pub milestones: BTreeMap<MilestoneId, MoneyMilestone>,
    /// Whether a later plan supersedes it.
    pub superseded: bool,
}

impl MoneyPlan {
    /// The plan total, minor units.
    pub fn total(&self) -> i64 {
        sum(self.milestones.values().map(|m| m.amount))
    }

    /// The earliest milestone start date.
    pub fn earliest_start(&self) -> Option<Timestamp> {
        self.milestones.values().map(|m| m.start).min()
    }
}

/// A recorded amount determination (R-NG-03).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Determination {
    /// The decision.
    pub decision: DecisionId,
    /// The effective plan total, minor units.
    pub plan_total: i64,
    /// The deductions, minor units.
    pub deductions: i64,
    /// The granted amount, minor units.
    pub granted: i64,
    /// The agreed plan.
    pub agreed: PlanVersionId,
}

/// A proposal as the money reference sees it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MoneyProposal {
    /// The lead.
    pub lead: AccountId,
    /// The creation call.
    pub call: CallId,
    /// Whether the lead is flagged as a minor.
    pub minor: bool,
    /// The state, from the transitions folded.
    pub state: StateTag,
    /// The latest determination.
    pub determined: Option<Determination>,
    /// The open reservation, minor units.
    pub reserved: Option<i64>,
    /// The recipient the vault grouped the lead under when the
    /// reservation opened (I-14).
    pub reserved_as: Option<Recipient>,
    /// The lead's acceptance.
    pub accepted: Option<DecisionId>,
    /// The programme manager's approval.
    pub approved: Option<DecisionId>,
    /// The contract that became EFFECTIVE.
    pub contract: Option<ContractId>,
    /// The granted amount, minor units: the amended total after an amendment.
    pub granted: Option<i64>,
    /// The plan of the effective contract version.
    pub effective_plan: Option<PlanVersionId>,
    /// The recorded negotiation failure.
    pub declined: Option<NegotiationFailure>,
    /// The milestones closed (NOTE 12).
    pub closed_milestones: BTreeSet<MilestoneId>,
}

impl MoneyProposal {
    /// Whether the grant reached COMPLETED or TERMINATED (I-64).
    pub fn closed(&self) -> bool {
        matches!(self.state, StateTag::Completed | StateTag::Terminated)
    }
}

/// A deliverable from the M5 checks (I-15).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MoneyDeliverable {
    /// The grant.
    pub grant: ProposalId,
    /// The milestone.
    pub milestone: MilestoneId,
    /// The SPDX licence.
    pub licence: String,
    /// Whether it was accepted.
    pub accepted: bool,
}

/// An amendment.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MoneyAmendment {
    /// The grant.
    pub grant: ProposalId,
    /// The amended plan.
    pub plan: PlanVersionId,
    /// The route, once routed.
    pub route: Option<AmendmentRoute>,
    /// Whether it was activated.
    pub activated: bool,
    /// The IRC reviews recorded on its amendment assignments: `true` for a
    /// validation, `false` for a concern (R-IR-04).
    pub reviews: BTreeMap<AssignmentId, bool>,
}

impl MoneyAmendment {
    /// Whether a concern was recorded on the amendment.
    pub fn concern(&self) -> bool {
        self.reviews.values().any(|ok| !*ok)
    }
}

/// The money reference's fold of core records.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MoneyView {
    /// Policy versions.
    pub policies: BTreeMap<fstp_domain::id::PolicyVersionId, MoneyPolicy>,
    /// The head version of each programme.
    pub heads: BTreeMap<ProgrammeId, fstp_domain::id::PolicyVersionId>,
    /// Calls.
    pub calls: BTreeMap<CallId, MoneyCall>,
    /// Plan versions.
    pub plans: BTreeMap<PlanVersionId, MoneyPlan>,
    /// Proposals.
    pub proposals: BTreeMap<ProposalId, MoneyProposal>,
    /// Deliverables.
    pub deliverables: BTreeMap<DeliverableId, MoneyDeliverable>,
    /// Amendments.
    pub amendments: BTreeMap<AmendmentId, MoneyAmendment>,
    /// The IRC assignments of amendments, by assignment (R-IR-04).
    pub amendment_assignments: BTreeMap<AssignmentId, AmendmentId>,
    /// Decision ids taken by this lane's records.
    pub decisions: BTreeSet<DecisionId>,
    /// Payment requests.
    pub pay: PayView,
    /// Breaches of I-05, I-13, I-14, I-15 and SoD-12 seen in folded batches,
    /// each starting with its id and a colon.
    pub breaches: BTreeSet<String>,
}

impl Default for MoneyView {
    fn default() -> MoneyView {
        MoneyView::new()
    }
}

/// The key the vault groups an account under for P-05: its verified
/// identity, or the account alone when it is not verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Recipient {
    /// A verified identity.
    Identity(IdentityTag),
    /// An unverified account.
    Account(AccountId),
}

/// The recipient of `lead` under `truth`.
pub fn recipient(truth: &GroundTruth, lead: AccountId) -> Recipient {
    truth
        .verified_identity(lead)
        .map_or(Recipient::Account(lead), Recipient::Identity)
}

impl MoneyView {
    /// The view of an empty ledger.
    pub fn new() -> MoneyView {
        MoneyView {
            policies: BTreeMap::new(),
            heads: BTreeMap::new(),
            calls: BTreeMap::new(),
            plans: BTreeMap::new(),
            proposals: BTreeMap::new(),
            deliverables: BTreeMap::new(),
            amendments: BTreeMap::new(),
            amendment_assignments: BTreeMap::new(),
            decisions: BTreeSet::new(),
            pay: PayView::new(),
            breaches: BTreeSet::new(),
        }
    }

    /// The programme of `call`.
    pub fn programme_of_call(&self, call: CallId) -> Option<ProgrammeId> {
        self.calls.get(&call).map(|c| c.programme)
    }

    /// The programme of `proposal`.
    pub fn programme_of(&self, proposal: ProposalId) -> Option<ProgrammeId> {
        self.programme_of_call(self.proposals.get(&proposal)?.call)
    }

    /// The live head policy of `programme`.
    pub fn head(&self, programme: ProgrammeId) -> Option<&MoneyPolicy> {
        self.policies.get(self.heads.get(&programme)?)
    }

    /// The frozen policy of `call`.
    pub fn frozen(&self, call: CallId) -> Option<&MoneyPolicy> {
        self.policies.get(&self.calls.get(&call)?.frozen?)
    }

    /// The governing frozen policy of `proposal`: that of its creation call (NOTE 8).
    pub fn governing(&self, proposal: ProposalId) -> Option<&MoneyPolicy> {
        self.frozen(self.proposals.get(&proposal)?.call)
    }

    /// The P-05 cap `call` enforces now: the lower of its snapshot and the live value.
    pub fn cap_of_call(&self, call: CallId) -> Option<i64> {
        let live = self.head(self.programme_of_call(call)?)?.p05;
        Some(match self.frozen(call) {
            Some(f) => live.min(f.p05),
            None => live,
        })
    }

    /// The counted sum of `proposal` (I-14, I-64).
    pub fn counted(&self, proposal: ProposalId) -> i64 {
        let Some(p) = self.proposals.get(&proposal) else {
            return 0;
        };
        if p.closed() {
            return self.pay.paid_total(proposal);
        }
        p.granted
            .unwrap_or(0)
            .saturating_add(p.reserved.unwrap_or(0))
    }

    /// The counted sum of the recipient of `lead` in `programme`, without `except`.
    pub fn counted_for(
        &self,
        truth: &GroundTruth,
        programme: ProgrammeId,
        lead: AccountId,
        except: Option<ProposalId>,
    ) -> i64 {
        let who = recipient(truth, lead);
        sum(self
            .proposals
            .iter()
            .filter(|(id, p)| {
                Some(**id) != except
                    && recipient(truth, p.lead) == who
                    && self.programme_of_call(p.call) == Some(programme)
            })
            .map(|(id, _)| self.counted(*id)))
    }

    /// Every recipient's counted sum in `programme`.
    pub fn recipients(
        &self,
        truth: &GroundTruth,
        programme: ProgrammeId,
    ) -> BTreeMap<Recipient, i64> {
        let mut out: BTreeMap<Recipient, i64> = BTreeMap::new();
        for (id, p) in &self.proposals {
            if self.programme_of_call(p.call) != Some(programme) {
                continue;
            }
            let e = out.entry(recipient(truth, p.lead)).or_insert(0);
            *e = e.saturating_add(self.counted(*id));
        }
        out
    }

    /// Every recipient's counted sum in `programme` as I-14 bounds it in
    /// every state. Granted amounts, or paid totals once closed (I-64),
    /// count under the lead's recipient now. An open reservation counts
    /// under the recipient the vault knew when it opened.
    pub fn standing_recipients(
        &self,
        truth: &GroundTruth,
        programme: ProgrammeId,
    ) -> BTreeMap<Recipient, i64> {
        let mut out: BTreeMap<Recipient, i64> = BTreeMap::new();
        for (id, p) in &self.proposals {
            if self.programme_of_call(p.call) != Some(programme) {
                continue;
            }
            let now = recipient(truth, p.lead);
            let (granted, reserved) = if p.closed() {
                (self.pay.paid_total(*id), 0)
            } else {
                (p.granted.unwrap_or(0), p.reserved.unwrap_or(0))
            };
            let e = out.entry(now).or_insert(0);
            *e = e.saturating_add(granted);
            if reserved > 0 {
                let e = out.entry(p.reserved_as.unwrap_or(now)).or_insert(0);
                *e = e.saturating_add(reserved);
            }
        }
        out
    }

    /// The plan of the effective contract version of `proposal`.
    pub fn contract_plan(&self, proposal: ProposalId) -> Option<&MoneyPlan> {
        self.plans
            .get(&self.proposals.get(&proposal)?.effective_plan?)
    }

    /// The live plan of `proposal`: the one no later plan supersedes.
    pub fn live_plan(&self, proposal: ProposalId) -> Option<PlanVersionId> {
        self.plans
            .iter()
            .find(|(_, p)| p.proposal == proposal && !p.superseded)
            .map(|(id, _)| *id)
    }

    /// Whether the I-15 record of the grant `g` is complete: every accepted
    /// deliverable under the P-26 of its call, and every milestone with an
    /// accepted payment line covered by such a deliverable.
    pub fn record_complete(&self, g: ProposalId) -> bool {
        let Some(p26) = self.governing(g).map(|f| &f.p26) else {
            return false;
        };
        let good = |d: &MoneyDeliverable| d.accepted && p26.contains(&d.licence);
        let mine: Vec<&MoneyDeliverable> = self
            .deliverables
            .values()
            .filter(|d| d.grant == g)
            .collect();
        if mine.iter().any(|d| d.accepted && !p26.contains(&d.licence)) {
            return false;
        }
        self.pay
            .accepted_milestones(g)
            .iter()
            .all(|m| mine.iter().any(|d| d.milestone == *m && good(d)))
    }

    /// The earlier grants of the identity of `lead`, tenant-wide, beside `except`.
    pub fn prior_grants(
        &self,
        truth: &GroundTruth,
        lead: AccountId,
        except: ProposalId,
    ) -> BTreeSet<ProposalId> {
        let who = recipient(truth, lead);
        self.proposals
            .iter()
            .filter(|(id, p)| {
                **id != except && p.granted.is_some() && recipient(truth, p.lead) == who
            })
            .map(|(id, _)| *id)
            .collect()
    }

    /// Whether a new grant to `lead` on `proposal` has a complete I-15 record.
    pub fn repeat_clear(&self, truth: &GroundTruth, lead: AccountId, proposal: ProposalId) -> bool {
        self.prior_grants(truth, lead, proposal)
            .into_iter()
            .all(|g| self.record_complete(g))
    }

    /// Folds `records` as one batch, then records a breach for each grant
    /// or reservation in it that broke I-13, I-14 or I-15 (design 6.1).
    pub fn fold_batch(&mut self, records: &[Record], truth: &GroundTruth) -> Result<(), String> {
        let before = self.clone();
        for r in records {
            self.fold(r, truth, &before)?;
        }
        for (id, p) in &self.proposals {
            let was = before.counted(*id);
            let now = self.counted(*id);
            // A reservation, a grant, an amendment or a release after
            // closure (I-64) may raise the counted sum. A grant batch is
            // checked even when it only turns a reservation into a grant.
            let granted_now = p.granted != before.proposals.get(id).and_then(|q| q.granted);
            let raised = now > was || (granted_now && p.granted.is_some());
            if !raised {
                continue;
            }
            let Some(programme) = self.programme_of_call(p.call) else {
                continue;
            };
            let total = self.counted_for(truth, programme, p.lead, None);
            let cap = before.cap_of_call(p.call).unwrap_or(i64::MAX);
            if total > cap {
                let msg = format!(
                    "I-14: a batch raised the counted sum of {id:?} so that its recipient holds {total} above the cap {cap}"
                );
                self.breaches.insert(msg);
            }
        }
        Ok(())
    }

    /// Notes the effect of an accepted extension command.
    pub fn note_ext(&mut self, ext: Ext) {
        match ext {
            Ext::CloseMilestone {
                proposal,
                milestone,
            } => {
                if let Some(p) = self.proposals.get_mut(&proposal) {
                    p.closed_milestones.insert(milestone);
                }
            }
            Ext::ClosePaymentRequest { request } => self.pay.close(request),
        }
    }

    fn proposal_mut(&mut self, p: ProposalId) -> Result<&mut MoneyProposal, String> {
        self.proposals
            .get_mut(&p)
            .ok_or_else(|| format!("money record on unknown proposal {p:?}"))
    }

    /// Folds one record. `before` is the view before its batch.
    fn fold(
        &mut self,
        record: &Record,
        truth: &GroundTruth,
        before: &MoneyView,
    ) -> Result<(), String> {
        match record {
            Record::PolicyVersionRecorded { version, .. } => {
                let p04 = version.frozen.p04;
                self.policies.insert(
                    version.id,
                    MoneyPolicy {
                        programme: version.programme,
                        p04_min: minor(p04.min()),
                        p04_max: minor(p04.max()),
                        p05: minor(version.live.p05),
                        p26: version.frozen.p26.0.iter().map(|s| s.0.clone()).collect(),
                    },
                );
                self.heads.insert(version.programme, version.id);
            }
            Record::CallDrafted {
                call, programme, ..
            } => {
                self.calls.insert(
                    *call,
                    MoneyCall {
                        programme: *programme,
                        frozen: None,
                    },
                );
            }
            Record::CallPublished { call, policy, .. } => {
                if let Some(c) = self.calls.get_mut(call) {
                    c.frozen = Some(*policy);
                }
            }
            Record::ProposalCreated {
                proposal,
                call,
                lead,
                minor,
            } => {
                self.proposals.insert(
                    *proposal,
                    MoneyProposal {
                        lead: *lead,
                        call: *call,
                        minor: *minor,
                        state: StateTag::Draft,
                        determined: None,
                        reserved: None,
                        reserved_as: None,
                        accepted: None,
                        approved: None,
                        contract: None,
                        granted: None,
                        effective_plan: None,
                        declined: None,
                        closed_milestones: BTreeSet::new(),
                    },
                );
            }
            Record::PlanVersionRecorded(p) => {
                if let Some(s) = p.supersedes
                    && let Some(old) = self.plans.get_mut(&s)
                {
                    old.superseded = true;
                }
                let milestones = p
                    .tasks
                    .iter()
                    .flat_map(|t| t.milestones.iter())
                    .map(|m| {
                        (
                            m.id,
                            MoneyMilestone {
                                amount: m.amount.amount().minor(),
                                start: m.start,
                            },
                        )
                    })
                    .collect();
                self.plans.insert(
                    p.plan,
                    MoneyPlan {
                        proposal: p.proposal,
                        origin: p.origin,
                        milestones,
                        superseded: false,
                    },
                );
            }
            Record::AmountDetermined {
                decision,
                proposal,
                plan_total,
                deductions,
                granted,
                agreed,
                ..
            } => {
                self.decisions.insert(*decision);
                let d = Determination {
                    decision: *decision,
                    plan_total: minor(*plan_total),
                    deductions: deductions_total(deductions),
                    granted: minor(*granted),
                    agreed: *agreed,
                };
                self.proposal_mut(*proposal)?.determined = Some(d);
            }
            Record::CapReserved {
                proposal, amount, ..
            } => {
                let q = self.proposal_mut(*proposal)?;
                q.reserved = Some(minor(*amount));
                q.reserved_as = Some(recipient(truth, q.lead));
            }
            Record::CapReleased { proposal, .. } => {
                let q = self.proposal_mut(*proposal)?;
                q.reserved = None;
                q.reserved_as = None;
            }
            Record::GrantAccepted {
                decision, proposal, ..
            } => {
                self.decisions.insert(*decision);
                self.proposal_mut(*proposal)?.accepted = Some(*decision);
            }
            Record::GrantApproved {
                decision, proposal, ..
            } => {
                self.decisions.insert(*decision);
                self.proposal_mut(*proposal)?.approved = Some(*decision);
            }
            Record::ContractFactRecorded {
                proposal,
                contract,
                event: ContractEvent::Effective,
            } => {
                self.proposal_mut(*proposal)?.contract = Some(*contract);
            }
            Record::GrantDecided(g) => self.fold_grant(g, truth, before)?,
            Record::NegotiationDeclined {
                proposal, reason, ..
            } => {
                self.proposal_mut(*proposal)?.declined = Some(*reason);
            }
            Record::TerminationRecorded { decision, .. } => {
                self.decisions.insert(*decision);
            }
            Record::Transitioned(t) => {
                self.proposal_mut(t.proposal)?.state = t.to;
            }
            Record::DeliverableRecorded(d) => {
                self.deliverables.insert(
                    d.deliverable,
                    MoneyDeliverable {
                        grant: d.grant,
                        milestone: d.milestone,
                        licence: d.licence.0.clone(),
                        accepted: d.accepted,
                    },
                );
            }
            Record::AmendmentProposed {
                amendment,
                grant,
                plan,
                ..
            } => {
                self.amendments.insert(
                    *amendment,
                    MoneyAmendment {
                        grant: *grant,
                        plan: *plan,
                        route: None,
                        activated: false,
                        reviews: BTreeMap::new(),
                    },
                );
            }
            Record::Assigned(a) => {
                if let AssignmentKind::Amendment(id) = a.kind {
                    self.amendment_assignments.insert(a.assignment, id);
                }
            }
            Record::IrcReviewRecorded {
                assignment,
                verdict,
            } => {
                if let Some(id) = self.amendment_assignments.get(assignment).copied() {
                    let a = self
                        .amendments
                        .get_mut(&id)
                        .ok_or("IRC review of an unknown amendment")?;
                    a.reviews
                        .insert(*assignment, matches!(verdict, IrcVerdict::Validate));
                }
            }
            Record::AmendmentRouted {
                amendment, route, ..
            } => {
                if let Some(a) = self.amendments.get_mut(amendment) {
                    a.route = Some(*route);
                }
            }
            Record::AmendmentActivated {
                amendment, plan, ..
            } => self.fold_activation(*amendment, *plan, truth, before)?,
            other => self
                .pay
                .fold(other, truth, &before.proposals, &mut self.breaches)?,
        }
        Ok(())
    }

    fn fold_grant(
        &mut self,
        g: &fstp_domain::grant::GrantDecided,
        truth: &GroundTruth,
        before: &MoneyView,
    ) -> Result<(), String> {
        let id = g.proposal();
        let granted = minor(g.granted());
        let p = before
            .proposals
            .get(&id)
            .ok_or_else(|| format!("GrantDecided on unknown proposal {id:?}"))?;
        let range = before.governing(id).map(|f| (f.p04_min, f.p04_max));
        match (&p.determined, range) {
            (Some(d), Some((lo, hi)))
                if d.granted == granted
                    && d.plan_total.saturating_sub(d.deductions) == granted
                    && before.plans.get(&g.agreed_plan()).map(MoneyPlan::total)
                        == Some(granted)
                    && lo <= granted
                    && granted <= hi => {}
            (d, r) => {
                self.breaches.insert(format!(
                    "I-13: {id:?} was granted {granted} with determination {d:?} under P-04 {r:?}"
                ));
            }
        }
        if !before.repeat_clear(truth, p.lead, id) {
            self.breaches.insert(format!(
                "I-15: {id:?} was granted while an earlier grant of its lead's identity has an incomplete public deliverable record"
            ));
        }
        let q = self.proposal_mut(id)?;
        q.granted = Some(granted);
        q.reserved = None;
        q.reserved_as = None;
        q.effective_plan = Some(g.agreed_plan());
        Ok(())
    }

    fn fold_activation(
        &mut self,
        amendment: AmendmentId,
        plan: PlanVersionId,
        truth: &GroundTruth,
        before: &MoneyView,
    ) -> Result<(), String> {
        let a = before
            .amendments
            .get(&amendment)
            .ok_or("AmendmentActivated on an unknown amendment")?;
        let g = a.grant;
        let p = before
            .proposals
            .get(&g)
            .ok_or("amendment of an unknown grant")?;
        let clear = before.repeat_clear(truth, p.lead, g) && before.record_complete(g);
        if !clear {
            self.breaches.insert(format!(
                "I-15: an amendment of {g:?} was activated while its identity's public deliverable record is incomplete"
            ));
        }
        let total = before.plans.get(&plan).map_or(0, MoneyPlan::total);
        if let Some(f) = before.governing(g)
            && !(f.p04_min <= total && total <= f.p04_max)
        {
            self.breaches.insert(format!(
                "I-13: the amended total {total} of {g:?} lies outside P-04"
            ));
        }
        if let Some(x) = self.amendments.get_mut(&amendment) {
            x.activated = true;
        }
        let q = self.proposal_mut(g)?;
        q.granted = Some(total);
        q.effective_plan = Some(plan);
        Ok(())
    }
}

fn deductions_total(d: &[IneligibleCost]) -> i64 {
    sum(d.iter().map(|c| c.amount.amount().minor()))
}

// ---------------------------------------------------------------------------
// Predicates
// ---------------------------------------------------------------------------

/// I-13: every granted amount equals its determination, the effective plan
/// total minus recorded deductions, and lies within P-04 inclusive.
pub fn check_i13(view: &MoneyView) -> Result<(), String> {
    if let Some(b) = view.breaches.iter().find(|b| b.starts_with("I-13:")) {
        return Err(b.clone());
    }
    for (id, p) in &view.proposals {
        let Some(g) = p.granted else { continue };
        let Some(f) = view.governing(*id) else {
            return Err(format!("I-13: {id:?} is granted without a frozen policy"));
        };
        if g < f.p04_min || g > f.p04_max {
            return Err(format!(
                "I-13: {id:?} is granted {g}, outside P-04 [{}, {}]",
                f.p04_min, f.p04_max
            ));
        }
    }
    Ok(())
}

/// I-14: every recipient's granted plus reserved sum stays within the
/// live P-05 of each programme, and no batch that raised a counted sum or
/// recorded a grant left the recipient above its call's cap.
///
/// Test-author reading: a reservation is checked when it opens, against
/// the identities the vault knows then, and keeps counting under that
/// recipient. A later verification can merge two open reservations above
/// P-05 (Identity discovery), which is no breach. Every grant batch after
/// it counts every reservation under the merged identity.
pub fn check_i14(view: &MoneyView, truth: &GroundTruth) -> Result<(), String> {
    if let Some(b) = view.breaches.iter().find(|b| b.starts_with("I-14:")) {
        return Err(b.clone());
    }
    for (programme, head) in &view.heads {
        let Some(cap) = view.policies.get(head).map(|p| p.p05) else {
            continue;
        };
        for (who, total) in view.standing_recipients(truth, *programme) {
            if total > cap {
                return Err(format!(
                    "I-14: recipient {who:?} holds {total} in {programme:?}, above P-05 {cap}"
                ));
            }
        }
    }
    Ok(())
}

/// I-15: no repeat grant or amendment was recorded while the identity's
/// public deliverable record was incomplete.
pub fn check_i15(view: &MoneyView) -> Result<(), String> {
    match view.breaches.iter().find(|b| b.starts_with("I-15:")) {
        Some(b) => Err(b.clone()),
        None => Ok(()),
    }
}

/// I-64: a closed grant counts exactly its paid total.
pub fn check_i64(view: &MoneyView) -> Result<(), String> {
    for (id, p) in &view.proposals {
        if p.closed() && view.counted(*id) != view.pay.paid_total(*id) {
            return Err(format!(
                "I-64: the closed grant {id:?} counts {} instead of its paid total {}",
                view.counted(*id),
                view.pay.paid_total(*id)
            ));
        }
        if p.closed() && p.reserved.is_some() {
            return Err(format!(
                "I-64: the closed grant {id:?} still holds a reservation"
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Verdicts
// ---------------------------------------------------------------------------

/// What the money reference reads to judge a command.
#[derive(Clone, Copy)]
pub struct MoneyCx<'a> {
    /// The L-SOD reference view.
    pub sod: &'a sod::View,
    /// The L-REV reference view.
    pub rev: &'a RevView,
    /// The lifecycle view.
    pub life: &'a LifeView,
    /// The money view.
    pub money: &'a MoneyView,
    /// The vault facts.
    pub truth: &'a GroundTruth,
    /// The instant of the command.
    pub now: Timestamp,
}

/// A record an accepted batch must hold, as a matcher, because some
/// payloads have private fields.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Want {
    /// This exact record.
    Exact(Record),
    /// A `CapReserved` of this amount for this proposal.
    Reserved(ProposalId, i64),
    /// A `CapReleased` for this proposal.
    Released(ProposalId),
    /// A `GrantDecided` with this proposal, amount and agreed plan.
    Grant(ProposalId, i64, PlanVersionId),
    /// A `NegotiationDeclined` with one of these reasons.
    Declined(ProposalId, BTreeSet<NegotiationFailure>),
    /// A `PaymentReleased` with these fields.
    Release {
        /// The request.
        request: RequestId,
        /// The grant.
        grant: ProposalId,
        /// The acceptors.
        acceptors: BTreeSet<AccountId>,
        /// The approver.
        approver: AccountId,
        /// The releaser.
        releaser: AccountId,
    },
    /// At least one record whose JSON type is this name.
    Typed(&'static str),
}

/// What an accepted command must record.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MoneyExpect {
    /// The records the batch must hold.
    pub wants: Vec<Want>,
    /// The proposal transitions the batch must hold, exactly.
    pub transitions: Vec<(ProposalId, StateTag, StateTag, Row)>,
    /// Whether the batch may hold transitions other lanes judge, as for a withdrawal.
    pub other_transitions: bool,
    /// The extension command to note in the view once accepted.
    pub ext: Option<Ext>,
    /// The records a run on the references alone appends.
    pub synth: Vec<Record>,
}

impl Default for MoneyExpect {
    fn default() -> MoneyExpect {
        MoneyExpect::new()
    }
}

impl MoneyExpect {
    /// An expectation of no record and no transition.
    pub fn new() -> MoneyExpect {
        MoneyExpect {
            wants: Vec::new(),
            transitions: Vec::new(),
            other_transitions: false,
            ext: None,
            synth: Vec::new(),
        }
    }

    /// Adds the exact record `r`, which a reference run also appends.
    pub fn push_exact(&mut self, r: Record) {
        self.wants.push(Want::Exact(r.clone()));
        self.synth.push(r);
    }

    fn exact(mut self, r: Record) -> MoneyExpect {
        self.push_exact(r);
        self
    }
}

/// The money verdict on a command.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum MoneyVerdict {
    /// The command is another lane's.
    NotMine,
    /// The command must be accepted with these records.
    Accept(MoneyExpect),
    /// The command may be refused, or accepted with these records.
    Either(MoneyExpect),
    /// The command must be refused, for the reason named.
    Refuse(String),
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

impl MoneyCx<'_> {
    fn programme(&self, p: ProposalId) -> Option<ProgrammeId> {
        self.money.programme_of(p)
    }

    fn state(&self, p: ProposalId) -> Option<StateTag> {
        self.money.proposals.get(&p).map(|q| q.state)
    }

    fn pm(&self, a: AccountId, p: ProposalId) -> bool {
        self.programme(p)
            .is_some_and(|prog| holds_active(self.sod, a, Role::ProgrammeManager, prog, self.now))
    }

    fn holder(&self, a: AccountId, role: Role, p: ProposalId) -> bool {
        self.programme(p)
            .is_some_and(|prog| holds_active(self.sod, a, role, prog, self.now))
    }

    /// The lead of `p` with an active Applicant binding on it.
    pub fn lead(&self, a: AccountId, p: ProposalId) -> bool {
        self.money.proposals.get(&p).is_some_and(|q| q.lead == a)
            && self.sod.bindings.values().any(|b| {
                b.account == a
                    && b.role == Role::Applicant
                    && b.proposal == Some(p)
                    && b.active()
                    && b.start <= self.now
            })
    }

    /// An assigned reviewer of `p`: an active reviewer assignment in its
    /// current call, an active committee member binding, no conflict fact
    /// and no vault conflict (I-03).
    pub fn reviewer(&self, a: AccountId, p: ProposalId) -> bool {
        let Some(l) = self.life.proposals.get(&p) else {
            return false;
        };
        let assigned = self
            .life
            .active_assignments(p, l.current_call, AssignmentKind::Reviewer)
            .iter()
            .any(|id| {
                self.life
                    .assignments
                    .get(id)
                    .is_some_and(|x| x.reviewer == a)
            });
        assigned
            && self.holder(a, Role::CommitteeMember, p)
            && !self.life.facts.contains(&(a, p))
            && !crate::reference::review::ConflictFacts::has_conflict(
                self.truth,
                a,
                &team_of(self.sod, p),
            )
    }

    fn decision_fresh(&self, d: DecisionId) -> bool {
        !self.life.decisions.contains(&d) && !self.money.decisions.contains(&d)
    }

    /// The plan the effective score of `p` carries forward (I-09).
    pub fn effective_plan(&self, p: ProposalId) -> Option<PlanVersionId> {
        self.life
            .proposals
            .get(&p)?
            .effective
            .last()
            .map(|e| e.plan)
    }

    /// The cap headroom of `p`: its call's cap minus its recipient's
    /// counted sum without `p`.
    pub fn headroom(&self, p: ProposalId) -> Option<i64> {
        let q = self.money.proposals.get(&p)?;
        let prog = self.programme(p)?;
        let cap = self.money.cap_of_call(q.call)?;
        Some(cap.saturating_sub(self.money.counted_for(self.truth, prog, q.lead, Some(p))))
    }

    /// The I-04, I-06 and SoD-09 state of the held Receiving bindings of `p`.
    fn receiving_clear(&self, p: ProposalId) -> bool {
        let Some(prog) = self.programme(p) else {
            return false;
        };
        let held: Vec<&sod::RefBinding> = self
            .sod
            .bindings
            .values()
            .filter(|b| b.proposal == Some(p) && b.group == RefGroup::Receiving)
            .collect();
        let lead_held = held.iter().any(|b| b.role == Role::Applicant && b.held());
        lead_held
            && held.iter().filter(|b| b.held()).all(|b| {
                !sod::i04_breaks(self.sod, self.truth, b)
                    && !sod::identity_clash(
                        self.sod,
                        self.truth,
                        b.account,
                        prog,
                        RefGroup::Receiving,
                        b.call_seq,
                    )
            })
    }

    /// The determined amount of `p` in cents once it is locked: the lead
    /// accepted it or the programme manager approved it. A determination
    /// after either is refused, so no other amount stays open (R-NG-03).
    pub fn locked(&self, p: ProposalId) -> Option<i64> {
        let q = self.money.proposals.get(&p)?;
        if q.accepted.is_none() && q.approved.is_none() {
            return None;
        }
        q.determined.as_ref().map(|d| d.granted)
    }

    /// The NOTE 9 amount failure of `p`, if any (decided 2026-10-26).
    ///
    /// Once the amount is locked, the locked amount decides: outside P-04
    /// fails I-13, and above the cap headroom fails I-14. Before, the lead
    /// may still propose a negotiated plan at any total from the P-04
    /// minimum up to the effective plan total, and a matching deduction
    /// grants it. A grant is never zero, since every milestone amount is
    /// positive. So the smallest grant amount within P-04 is the P-04
    /// minimum, or one cent when that minimum is zero. No amount within
    /// P-04 exists only when that floor lies above the effective plan
    /// total, or above the P-04 maximum. No amount fits the cap only when
    /// even that floor lies above the headroom. A plan total above the
    /// headroom is no failure while the floor fits.
    pub fn amount_failure(&self, p: ProposalId) -> Option<NegotiationFailure> {
        let total = self
            .effective_plan(p)
            .and_then(|e| self.money.plans.get(&e))
            .map(MoneyPlan::total)?;
        let (lo, hi) = self.money.governing(p).map(|f| (f.p04_min, f.p04_max))?;
        let smallest = match self.locked(p) {
            Some(amount) if lo <= amount && amount <= hi => amount,
            Some(_) => return Some(NegotiationFailure::NoAmountWithinRange),
            None => {
                let floor = lo.max(1);
                if floor > total || floor > hi {
                    return Some(NegotiationFailure::NoAmountWithinRange);
                }
                floor
            }
        };
        // The headroom reads the stricter of the snapshot and the live
        // P-05 for the lead's verified identity (P-05 NOTE 7).
        match self.headroom(p) {
            Some(h) if smallest > h => Some(NegotiationFailure::NoAmountWithinCap),
            _ => None,
        }
    }

    /// The NOTE 9 failures that hold for `p` now.
    pub fn failures(&self, p: ProposalId) -> BTreeSet<NegotiationFailure> {
        let mut out = BTreeSet::new();
        let Some(q) = self.money.proposals.get(&p) else {
            return out;
        };
        let Some(prog) = self.programme(p) else {
            return out;
        };
        if !self.truth.is_verified(q.lead) {
            out.insert(NegotiationFailure::IdentityNotVerified);
        } else {
            let seq = self.sod.lead_binding(p).and_then(|b| b.call_seq);
            if sod::identity_clash(self.sod, self.truth, q.lead, prog, RefGroup::Receiving, seq) {
                out.insert(NegotiationFailure::Sod09Refused);
            }
        }
        for b in self.sod.bindings.values() {
            if b.proposal == Some(p) && b.group == RefGroup::Receiving {
                match b.voided {
                    Some(RuleRef::I04) => {
                        out.insert(NegotiationFailure::ReceivingVoidedUnderI04);
                    }
                    Some(RuleRef::I06) => {
                        out.insert(NegotiationFailure::ReceivingVoidedUnderI06);
                    }
                    _ => {}
                }
            }
        }
        // Amount failures count whether or not a reservation is open, since
        // a later verification can leave a reservation above the headroom
        // (Identity discovery). NOTE 9 asks whether any amount within P-04
        // fits the recipient's remaining room (decided 2026-10-26).
        out.extend(self.amount_failure(p));
        if !self.money.repeat_clear(self.truth, q.lead, p) {
            out.insert(NegotiationFailure::RepeatRecordIncomplete);
        }
        if q.minor && !self.truth.has_consent(p) {
            out.insert(NegotiationFailure::GuardianConsentMissing);
        }
        out
    }

    /// Whether every guard of NEGOTIATION to GRANTED holds for `p`, given
    /// the three facts.
    pub fn grantable(&self, p: ProposalId) -> bool {
        let Some(q) = self.money.proposals.get(&p) else {
            return false;
        };
        let (Some(d), Some(r)) = (&q.determined, q.reserved) else {
            return false;
        };
        let Some(f) = self.money.governing(p) else {
            return false;
        };
        let in_range = f.p04_min <= d.granted && d.granted <= f.p04_max;
        let in_cap = self.headroom(p).is_some_and(|h| d.granted <= h);
        r == d.granted
            && in_range
            && in_cap
            && self.truth.is_verified(q.lead)
            && (!q.minor || self.truth.has_consent(p))
            && self.receiving_clear(p)
            && self.money.repeat_clear(self.truth, q.lead, p)
    }
}

/// Builds a `GrantDecided` through the record codec, since its payload has
/// private fields. Used by reference runs and by the teeth faults.
#[expect(clippy::too_many_arguments, reason = "one argument per record field")]
pub fn forge_grant(
    proposal: ProposalId,
    granted: i64,
    agreed: PlanVersionId,
    acceptance: DecisionId,
    approval: DecisionId,
    contract: ContractId,
    epoch: u64,
    rules: RulesVersion,
) -> Result<Record, String> {
    let amount = fstp_money::Amount::from_minor(granted, fstp_money::Currency::Eur)
        .map_err(|e| format!("amount: {e:?}"))?;
    let text = format!(
        "{{\"acceptance\":\"{}\",\"agreed_plan\":\"{}\",\"approval\":\"{}\",\"contract\":\"{}\",\
         \"currency\":\"EUR\",\"epoch\":\"{epoch}\",\"granted\":\"{amount}\",\"proposal\":\"{}\",\
         \"rules\":{},\"type\":\"GrantDecided\"}}",
        acceptance.raw(),
        agreed.raw(),
        approval.raw(),
        contract.raw(),
        proposal.raw(),
        rules.0
    );
    decode_record(&text)
}

/// Decodes the record JSON `text` at schema version 1.
pub fn decode_record(text: &str) -> Result<Record, String> {
    let v = fstp_json::parse(text.as_bytes()).map_err(|e| format!("json: {e:?}"))?;
    fstp_domain::codec::record_from_json_at(fstp_ledger::SCHEMA_V1, &v)
        .map_err(|e| format!("record codec: {e:?}"))
}

/// A transition record by `actor`.
pub fn transition(
    proposal: ProposalId,
    from: StateTag,
    to: StateTag,
    row: Row,
    actor: Actor,
) -> Record {
    Record::Transitioned(Transitioned {
        proposal,
        from,
        to,
        row,
        actor,
        decision: None,
    })
}

/// The money verdict on `cmd` by `actor` now.
pub fn money_verdict(cx: &MoneyCx<'_>, actor: Actor, cmd: &Command) -> MoneyVerdict {
    if let Some(ext) = ext_of(cmd) {
        return ext_verdict(cx, actor, ext);
    }
    if let Some(v) = pay_verdict(cx, actor, cmd) {
        return v;
    }
    if let Command::Assign {
        assignment,
        proposal,
        reviewer,
        kind: AssignmentKind::Amendment(amendment),
        handle,
    } = cmd
    {
        return amendment_assign(
            cx,
            actor,
            *assignment,
            *proposal,
            *reviewer,
            *amendment,
            *handle,
        );
    }
    if let Command::RecordIrcReview {
        assignment,
        verdict,
    } = cmd
        && let Some(amendment) = cx.money.amendment_assignments.get(assignment).copied()
    {
        return amendment_review(cx, actor, *assignment, amendment, *verdict);
    }
    match cmd {
        Command::DetermineAmount {
            decision,
            proposal,
            agreed,
            deductions,
        } => determine(cx, actor, *decision, *proposal, *agreed, deductions),
        Command::AcceptGrant { decision, proposal } => {
            grant_fact(cx, actor, *proposal, GrantFact::Accept(*decision))
        }
        Command::ApproveGrant { decision, proposal } => {
            grant_fact(cx, actor, *proposal, GrantFact::Approve(*decision))
        }
        Command::ContractFact {
            proposal,
            contract,
            event: ContractEvent::Effective,
        } => grant_fact(cx, actor, *proposal, GrantFact::Contract(*contract)),
        Command::DeclineNegotiation { proposal } => decline(cx, actor, *proposal),
        Command::StartExecution { proposal } => start(cx, actor, *proposal),
        Command::Terminate {
            decision,
            proposal,
            reason,
        } => terminate(cx, actor, *decision, *proposal, *reason),
        Command::Complete { proposal } => complete(cx, actor, *proposal),
        Command::RecordDeliverable {
            deliverable,
            grant,
            milestone,
            public_location,
            release,
            licence,
            snapshot,
            accepted,
        } => {
            if let v @ MoneyVerdict::Refuse(_) =
                deliverable_ok(cx, actor, *deliverable, *grant, *milestone)
            {
                return v;
            }
            MoneyVerdict::Accept(MoneyExpect::new().exact(Record::DeliverableRecorded(
                fstp_domain::record::DeliverableRecorded {
                    deliverable: *deliverable,
                    grant: *grant,
                    milestone: *milestone,
                    public_location: *public_location,
                    release: *release,
                    licence: licence.clone(),
                    snapshot: *snapshot,
                    accepted: *accepted,
                },
            )))
        }
        Command::RecordPlanVersion {
            plan,
            proposal,
            origin: origin @ (PlanOrigin::Negotiated | PlanOrigin::Amendment),
            supersedes,
            tasks,
            content,
        } => money_plan(
            cx,
            actor,
            *plan,
            *proposal,
            *origin,
            *supersedes,
            tasks,
            *content,
        ),
        Command::ProposeAmendment {
            amendment,
            grant,
            plan,
        } => propose(cx, actor, *amendment, *grant, *plan),
        Command::RouteAmendment { amendment, route } => {
            route_amendment(cx, actor, *amendment, *route)
        }
        Command::ActivateAmendment {
            amendment,
            contract,
        } => activate(cx, actor, *amendment, *contract),
        Command::EditPolicy { version, base } => {
            let Some(prog) = cx.money.policies.get(base).map(|p| p.programme) else {
                return MoneyVerdict::NotMine;
            };
            let new_cap = minor(version.live.p05);
            let over = cx
                .money
                .recipients(cx.truth, prog)
                .into_iter()
                .find(|(_, total)| *total > new_cap);
            match over {
                Some((who, total)) => refuse(format!(
                    "I-14: P-05 {new_cap} lies below the counted sum {total} of {who:?}"
                )),
                None => MoneyVerdict::NotMine,
            }
        }
        _ => MoneyVerdict::NotMine,
    }
}

fn determine(
    cx: &MoneyCx<'_>,
    actor: Actor,
    decision: DecisionId,
    proposal: ProposalId,
    agreed: PlanVersionId,
    deductions: &[IneligibleCost],
) -> MoneyVerdict {
    let Some(a) = account(actor) else {
        return refuse("R-NG-03: the System does not set the amount");
    };
    let Some(q) = cx.money.proposals.get(&proposal) else {
        return refuse("unknown proposal");
    };
    if q.state != StateTag::Negotiation {
        return refuse("DetermineAmount needs NEGOTIATION");
    }
    if !cx.reviewer(a, proposal) {
        return refuse("R-NG-03, I-03: only an assigned reviewer without conflict sets the amount");
    }
    if q.accepted.is_some() || q.approved.is_some() {
        return refuse("test-author choice: the amount is locked once accepted or approved");
    }
    if !cx.decision_fresh(decision) {
        return refuse("decision id reused");
    }
    let negotiated = cx
        .money
        .plans
        .get(&agreed)
        .is_some_and(|p| p.proposal == proposal && p.origin == PlanOrigin::Negotiated);
    let effective = cx.effective_plan(proposal);
    if effective != Some(agreed) && !negotiated {
        return refuse("I-13: the agreed plan is not the effective plan of the proposal");
    }
    let Some(plan_total) = effective
        .and_then(|e| cx.money.plans.get(&e))
        .map(MoneyPlan::total)
    else {
        return refuse("I-13: no effective plan");
    };
    let Some(agreed_total) = cx.money.plans.get(&agreed).map(MoneyPlan::total) else {
        return refuse("unknown plan");
    };
    let cut = deductions_total(deductions);
    let granted = plan_total.saturating_sub(cut);
    if granted < 0 {
        return refuse("I-13: deductions above the plan total");
    }
    if agreed_total != granted {
        return refuse(format!(
            "I-13, design 2.11: the agreed plan total {agreed_total} is not the granted amount {granted}"
        ));
    }
    let Some(f) = cx.money.governing(proposal) else {
        return refuse("no governing policy");
    };
    if granted < f.p04_min || granted > f.p04_max {
        return refuse(format!(
            "I-13: {granted} lies outside P-04 [{}, {}]",
            f.p04_min, f.p04_max
        ));
    }
    let Some(head) = cx.headroom(proposal) else {
        return refuse("no cap");
    };
    if granted > head {
        return refuse(format!(
            "I-14: {granted} exceeds the cap headroom {head} of the recipient"
        ));
    }
    let Ok(granted_amount) = fstp_money::Amount::from_minor(granted, fstp_money::Currency::Eur)
        .and_then(NonNegAmount::new)
    else {
        return refuse("amount");
    };
    let Ok(total_amount) = fstp_money::Amount::from_minor(plan_total, fstp_money::Currency::Eur)
        .and_then(NonNegAmount::new)
    else {
        return refuse("amount");
    };
    let mut e = MoneyExpect::new().exact(Record::AmountDetermined {
        decision,
        proposal,
        plan_total: total_amount,
        deductions: deductions.to_vec(),
        granted: granted_amount,
        agreed,
        by: a,
        rules: RulesVersion::M2,
    });
    if let Some(old) = q.reserved
        && let Ok(old_amount) = fstp_money::Amount::from_minor(old, fstp_money::Currency::Eur)
            .and_then(NonNegAmount::new)
    {
        e.wants.push(Want::Released(proposal));
        e.synth.push(Record::CapReleased {
            proposal,
            amount: old_amount,
        });
    }
    e.wants.push(Want::Reserved(proposal, granted));
    e.synth.push(Record::CapReserved {
        proposal,
        amount: granted_amount,
        epoch: cx.sod.epoch,
    });
    MoneyVerdict::Accept(e)
}

/// One of the three facts NEGOTIATION to GRANTED needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GrantFact {
    Accept(DecisionId),
    Approve(DecisionId),
    Contract(ContractId),
}

fn grant_fact(
    cx: &MoneyCx<'_>,
    actor: Actor,
    proposal: ProposalId,
    fact: GrantFact,
) -> MoneyVerdict {
    let Some(q) = cx.money.proposals.get(&proposal) else {
        return refuse("unknown proposal");
    };
    if q.state != StateTag::Negotiation {
        // Test-author choice: the contract port may report a fact on a
        // proposal outside NEGOTIATION (design 3.3, "NEGOTIATION or
        // later"). It may be recorded, but it never moves the proposal.
        if let GrantFact::Contract(c) = fact
            && matches!(actor, Actor::System(_))
        {
            return MoneyVerdict::Either(MoneyExpect::new().exact(Record::ContractFactRecorded {
                proposal,
                contract: c,
                event: ContractEvent::Effective,
            }));
        }
        return refuse("the grant facts need NEGOTIATION");
    }
    let mut e = MoneyExpect::new();
    let mut after = q.clone();
    match fact {
        GrantFact::Accept(d) => {
            let Some(a) = account(actor) else {
                return refuse("AcceptGrant is the lead's");
            };
            if !cx.lead(a, proposal) {
                return refuse("AcceptGrant is the lead's");
            }
            if q.accepted.is_some() {
                return refuse("already accepted");
            }
            if !cx.decision_fresh(d) {
                return refuse("decision id reused");
            }
            e = e.exact(Record::GrantAccepted {
                decision: d,
                proposal,
                by: a,
            });
            after.accepted = Some(d);
        }
        GrantFact::Approve(d) => {
            let Some(a) = account(actor) else {
                return refuse("ApproveGrant is the programme manager's");
            };
            if !cx.pm(a, proposal) {
                return refuse("ApproveGrant is the programme manager's");
            }
            if q.approved.is_some() {
                return refuse("already approved");
            }
            if !cx.decision_fresh(d) {
                return refuse("decision id reused");
            }
            e = e.exact(Record::GrantApproved {
                decision: d,
                proposal,
                by: a,
            });
            after.approved = Some(d);
        }
        GrantFact::Contract(c) => {
            if !matches!(actor, Actor::System(_)) {
                return refuse("ContractFact comes from the contract port");
            }
            let repeated = q.contract.is_some();
            e = e.exact(Record::ContractFactRecorded {
                proposal,
                contract: c,
                event: ContractEvent::Effective,
            });
            if repeated {
                // Test-author choice: a repeated fact may be refused or recorded again.
                return MoneyVerdict::Either(e);
            }
            after.contract = Some(c);
        }
    }
    let complete = after.accepted.is_some() && after.approved.is_some() && after.contract.is_some();
    if q.reserved.is_none() {
        return MoneyVerdict::Either(e);
    }
    if !complete {
        return MoneyVerdict::Accept(e);
    }
    if !cx.grantable(proposal) {
        // Row NEGOTIATION to GRANTED: the fact that completes the set is
        // refused while a guard fails, so it can be sent again once the
        // guard holds and the negotiation is never left without an exit.
        return refuse(
            "NOTE 9: a guard of NEGOTIATION to GRANTED fails, so the completing fact is refused",
        );
    }
    let (Some(d), Some(acc), Some(app), Some(con)) = (
        &q.determined,
        after.accepted,
        after.approved,
        after.contract,
    ) else {
        return MoneyVerdict::Either(e);
    };
    e.wants.push(Want::Grant(proposal, d.granted, d.agreed));
    if let Ok(r) = forge_grant(
        proposal,
        d.granted,
        d.agreed,
        acc,
        app,
        con,
        cx.sod.epoch.raw(),
        RulesVersion::M2,
    ) {
        e.synth.push(r);
    }
    e.transitions.push((
        proposal,
        StateTag::Negotiation,
        StateTag::Granted,
        Row::NegotiationToGranted,
    ));
    e.synth.push(transition(
        proposal,
        StateTag::Negotiation,
        StateTag::Granted,
        Row::NegotiationToGranted,
        actor,
    ));
    MoneyVerdict::Accept(e)
}

fn decline(cx: &MoneyCx<'_>, actor: Actor, proposal: ProposalId) -> MoneyVerdict {
    let Some(a) = account(actor) else {
        return refuse("NOTE 13: the programme manager records NEGOTIATION to DECLINED");
    };
    let Some(q) = cx.money.proposals.get(&proposal) else {
        return refuse("unknown proposal");
    };
    if !cx.pm(a, proposal) {
        return refuse("NOTE 13: the programme manager records NEGOTIATION to DECLINED");
    }
    if q.state != StateTag::Negotiation {
        return refuse("DeclineNegotiation needs NEGOTIATION");
    }
    let failures = cx.failures(proposal);
    let Some(first) = failures.iter().next().copied() else {
        return refuse("NOTE 9: no listed failure holds");
    };
    let mut e = MoneyExpect::new();
    e.wants.push(Want::Declined(proposal, failures));
    e.synth.push(Record::NegotiationDeclined {
        proposal,
        reason: first,
        rules: RulesVersion::M2,
    });
    if let Some(old) = q.reserved
        && let Ok(amount) = fstp_money::Amount::from_minor(old, fstp_money::Currency::Eur)
            .and_then(NonNegAmount::new)
    {
        e.wants.push(Want::Released(proposal));
        e.synth.push(Record::CapReleased { proposal, amount });
    }
    e.transitions.push((
        proposal,
        StateTag::Negotiation,
        StateTag::Declined,
        Row::NegotiationToDeclined,
    ));
    e.synth.push(transition(
        proposal,
        StateTag::Negotiation,
        StateTag::Declined,
        Row::NegotiationToDeclined,
        actor,
    ));
    MoneyVerdict::Accept(e)
}

fn start(cx: &MoneyCx<'_>, actor: Actor, proposal: ProposalId) -> MoneyVerdict {
    if !matches!(actor, Actor::System(_)) {
        return refuse("StartExecution is the System's");
    }
    if cx.state(proposal) != Some(StateTag::Granted) {
        return refuse("StartExecution needs GRANTED");
    }
    let Some(first) = cx
        .money
        .contract_plan(proposal)
        .and_then(MoneyPlan::earliest_start)
    else {
        return refuse("no contract plan");
    };
    if cx.now < first {
        return refuse("NOTE 11: the earliest milestone start date is not reached");
    }
    let mut e = MoneyExpect::new();
    e.transitions.push((
        proposal,
        StateTag::Granted,
        StateTag::InExecution,
        Row::GrantedToInExecution,
    ));
    e.synth.push(transition(
        proposal,
        StateTag::Granted,
        StateTag::InExecution,
        Row::GrantedToInExecution,
        actor,
    ));
    MoneyVerdict::Accept(e)
}

fn terminate(
    cx: &MoneyCx<'_>,
    actor: Actor,
    decision: DecisionId,
    proposal: ProposalId,
    reason: TextRef,
) -> MoneyVerdict {
    let Some(a) = account(actor) else {
        return refuse("Terminate is the programme manager's");
    };
    if !cx.pm(a, proposal) {
        return refuse("Terminate is the programme manager's");
    }
    let (from, row) = match cx.state(proposal) {
        Some(StateTag::Granted) => (StateTag::Granted, Row::GrantedToTerminated),
        Some(StateTag::InExecution) => (StateTag::InExecution, Row::InExecutionToTerminated),
        _ => return refuse("Terminate needs GRANTED or IN_EXECUTION"),
    };
    if !cx.decision_fresh(decision) {
        return refuse("decision id reused");
    }
    let mut e = MoneyExpect::new().exact(Record::TerminationRecorded {
        decision,
        proposal,
        by: a,
        reason,
    });
    e.transitions
        .push((proposal, from, StateTag::Terminated, row));
    e.synth
        .push(transition(proposal, from, StateTag::Terminated, row, actor));
    MoneyVerdict::Accept(e)
}

fn complete(cx: &MoneyCx<'_>, actor: Actor, proposal: ProposalId) -> MoneyVerdict {
    if !matches!(actor, Actor::System(_)) {
        return refuse("Complete is the System's");
    }
    if cx.state(proposal) != Some(StateTag::InExecution) {
        return refuse("Complete needs IN_EXECUTION");
    }
    let Some(q) = cx.money.proposals.get(&proposal) else {
        return refuse("unknown proposal");
    };
    let Some(plan) = cx.money.contract_plan(proposal) else {
        return refuse("no contract plan");
    };
    if !plan
        .milestones
        .keys()
        .all(|m| q.closed_milestones.contains(m))
    {
        return refuse("NOTE 12: a milestone is not closed");
    }
    if !cx
        .money
        .pay
        .requests_of(proposal)
        .all(|r| r.state.is_terminal())
    {
        return refuse("NOTE 12: a payment request is not terminal");
    }
    let mut e = MoneyExpect::new();
    e.transitions.push((
        proposal,
        StateTag::InExecution,
        StateTag::Completed,
        Row::InExecutionToCompleted,
    ));
    e.synth.push(transition(
        proposal,
        StateTag::InExecution,
        StateTag::Completed,
        Row::InExecutionToCompleted,
        actor,
    ));
    MoneyVerdict::Accept(e)
}

/// The verdict on an extension command by `actor`.
pub fn ext_verdict(cx: &MoneyCx<'_>, actor: Actor, ext: Ext) -> MoneyVerdict {
    match ext {
        Ext::CloseMilestone {
            proposal,
            milestone,
        } => {
            let Some(a) = account(actor) else {
                return refuse("NOTE 12: the programme manager closes a milestone");
            };
            if !cx.pm(a, proposal) {
                return refuse("NOTE 12: the programme manager closes a milestone");
            }
            if cx.state(proposal) != Some(StateTag::InExecution) {
                return refuse("a milestone closes in IN_EXECUTION");
            }
            let Some(q) = cx.money.proposals.get(&proposal) else {
                return refuse("unknown proposal");
            };
            let ours = cx
                .money
                .contract_plan(proposal)
                .is_some_and(|p| p.milestones.contains_key(&milestone));
            if !ours {
                return refuse("not a milestone of the effective contract version");
            }
            if q.closed_milestones.contains(&milestone) {
                return refuse("milestone already closed");
            }
            let mut e = MoneyExpect::new();
            e.wants.push(Want::Typed("MilestoneClosed"));
            e.synth.push(Record::MilestoneClosed {
                proposal,
                milestone,
                by: a,
                reason: crate::r#gen::money::milestone_close_reason(milestone),
            });
            e.ext = Some(ext);
            MoneyVerdict::Accept(e)
        }
        Ext::ClosePaymentRequest { request } => {
            let Some(a) = account(actor) else {
                return refuse("the programme manager closes a request");
            };
            let Some(r) = cx.money.pay.requests.get(&request) else {
                return refuse("unknown request");
            };
            if !cx.pm(a, r.grant) {
                return refuse("the programme manager closes a request");
            }
            if !matches!(
                r.state,
                RequestState::ChecksFailed | RequestState::ChangesRequested
            ) {
                return refuse("only a request in CHECKS_FAILED or CHANGES_REQUESTED closes");
            }
            let mut e = MoneyExpect::new();
            e.wants.push(Want::Typed("PaymentRequestClosed"));
            e.synth.push(Record::PaymentRequestClosed {
                request,
                by: a,
                reason: crate::r#gen::money::request_close_reason(request),
            });
            e.ext = Some(ext);
            MoneyVerdict::Accept(e)
        }
    }
}

fn deliverable_ok(
    cx: &MoneyCx<'_>,
    actor: Actor,
    deliverable: DeliverableId,
    grant: ProposalId,
    milestone: MilestoneId,
) -> MoneyVerdict {
    if !matches!(actor, Actor::System(_)) {
        return refuse("RecordDeliverable comes from the M5 checks");
    }
    if !matches!(
        cx.state(grant),
        Some(StateTag::Granted | StateTag::InExecution)
    ) {
        return refuse("RecordDeliverable needs GRANTED or IN_EXECUTION");
    }
    if cx.money.deliverables.contains_key(&deliverable) {
        return refuse("deliverable id reused");
    }
    let ours = cx
        .money
        .contract_plan(grant)
        .is_some_and(|p| p.milestones.contains_key(&milestone));
    if !ours {
        return refuse("not a milestone of the grant");
    }
    MoneyVerdict::Accept(MoneyExpect::new())
}

#[expect(clippy::too_many_arguments, reason = "one argument per command field")]
fn money_plan(
    cx: &MoneyCx<'_>,
    actor: Actor,
    plan: PlanVersionId,
    proposal: ProposalId,
    origin: PlanOrigin,
    supersedes: Option<PlanVersionId>,
    tasks: &[Task],
    content: fstp_domain::id::ContentDigest,
) -> MoneyVerdict {
    let Some(a) = account(actor) else {
        return refuse("plans are the lead's");
    };
    if !cx.lead(a, proposal) {
        return refuse("plans are the lead's");
    }
    let open = match origin {
        PlanOrigin::Negotiated => cx.state(proposal) == Some(StateTag::Negotiation),
        PlanOrigin::Amendment => matches!(
            cx.state(proposal),
            Some(StateTag::Granted | StateTag::InExecution)
        ),
        _ => false,
    };
    if !open {
        return refuse("origin not open in this state");
    }
    if cx.money.plans.contains_key(&plan) {
        return refuse("plan id reused");
    }
    if supersedes != cx.money.live_plan(proposal) {
        return refuse("a new plan supersedes the live plan, and only it");
    }
    let complete = !tasks.is_empty() && tasks.iter().all(|t| !t.milestones.is_empty());
    let dated = tasks
        .iter()
        .flat_map(|t| t.milestones.iter())
        .all(|m| m.start <= m.due);
    // I-61: an amendment plan keeps a milestone of the effective contract
    // version under its id, so its paid and pending lines stay on it.
    // Every other milestone is new and needs an id never used before.
    let kept = |m: MilestoneId| {
        origin == PlanOrigin::Amendment
            && cx
                .money
                .contract_plan(proposal)
                .is_some_and(|c| c.milestones.contains_key(&m))
    };
    let fresh = tasks.iter().flat_map(|t| t.milestones.iter()).all(|m| {
        kept(m.id)
            || (!cx.life.milestones.contains(&m.id)
                && !cx
                    .money
                    .plans
                    .values()
                    .any(|p| p.milestones.contains_key(&m.id)))
    });
    let ids: Vec<MilestoneId> = tasks
        .iter()
        .flat_map(|t| t.milestones.iter())
        .map(|m| m.id)
        .collect();
    let distinct = ids.iter().collect::<BTreeSet<_>>().len() == ids.len();
    if !(complete && dated && fresh && distinct) {
        return refuse("plan structure");
    }
    MoneyVerdict::Accept(MoneyExpect::new().exact(Record::PlanVersionRecorded(
        fstp_domain::record::PlanVersionRecorded {
            plan,
            proposal,
            origin,
            supersedes,
            tasks: tasks.to_vec(),
            content,
        },
    )))
}

fn propose(
    cx: &MoneyCx<'_>,
    actor: Actor,
    amendment: AmendmentId,
    grant: ProposalId,
    plan: PlanVersionId,
) -> MoneyVerdict {
    let Some(a) = account(actor) else {
        return refuse("an amendment is proposed by the lead or a reviewer");
    };
    if !(cx.lead(a, grant) || cx.reviewer(a, grant)) {
        return refuse("an amendment is proposed by the lead or a reviewer");
    }
    if !matches!(
        cx.state(grant),
        Some(StateTag::Granted | StateTag::InExecution)
    ) {
        return refuse("an amendment needs GRANTED or IN_EXECUTION");
    }
    if cx.money.amendments.contains_key(&amendment) {
        return refuse("amendment id reused");
    }
    let ok = cx
        .money
        .plans
        .get(&plan)
        .is_some_and(|p| p.proposal == grant && p.origin == PlanOrigin::Amendment);
    if !ok {
        return refuse("the amended plan is an amendment plan of the grant");
    }
    // Only the latest plan version counts, and one plan backs at most one
    // amendment.
    if cx.money.plans.get(&plan).is_some_and(|p| p.superseded) {
        return refuse("the amended plan is superseded");
    }
    if cx.money.amendments.values().any(|x| x.plan == plan) {
        return refuse("another amendment names the plan");
    }
    MoneyVerdict::Accept(MoneyExpect::new().exact(Record::AmendmentProposed {
        amendment,
        grant,
        plan,
        by: a,
    }))
}

fn route_amendment(
    cx: &MoneyCx<'_>,
    actor: Actor,
    amendment: AmendmentId,
    route: AmendmentRoute,
) -> MoneyVerdict {
    let Some(a) = account(actor) else {
        return refuse("the programme manager routes an amendment");
    };
    let Some(x) = cx.money.amendments.get(&amendment) else {
        return refuse("unknown amendment");
    };
    if !cx.pm(a, x.grant) {
        return refuse("the programme manager routes an amendment");
    }
    if x.route.is_some() || x.activated {
        return refuse("already routed");
    }
    MoneyVerdict::Accept(MoneyExpect::new().exact(Record::AmendmentRouted {
        amendment,
        route,
        by: a,
    }))
}

fn activate(
    cx: &MoneyCx<'_>,
    actor: Actor,
    amendment: AmendmentId,
    contract: ContractId,
) -> MoneyVerdict {
    if !matches!(actor, Actor::System(_)) {
        return refuse("ActivateAmendment comes from the contract port");
    }
    let Some(x) = cx.money.amendments.get(&amendment) else {
        return refuse("unknown amendment");
    };
    let Some(route) = x.route else {
        return refuse("an amendment is activated once routed");
    };
    if x.activated {
        return refuse("already activated");
    }
    let g = x.grant;
    let Some(q) = cx.money.proposals.get(&g) else {
        return refuse("unknown grant");
    };
    if !matches!(q.state, StateTag::Granted | StateTag::InExecution) {
        return refuse("an amendment needs GRANTED or IN_EXECUTION");
    }
    if !(cx.money.repeat_clear(cx.truth, q.lead, g) && cx.money.record_complete(g)) {
        return refuse("I-15: the public deliverable record is incomplete");
    }
    let total = cx.money.plans.get(&x.plan).map_or(0, MoneyPlan::total);
    let Some(f) = cx.money.governing(g) else {
        return refuse("no governing policy");
    };
    if total < f.p04_min || total > f.p04_max {
        return refuse("I-13: the amended total lies outside P-04");
    }
    if cx.money.plans.get(&x.plan).is_none_or(|p| p.superseded) {
        return refuse("a later plan supersedes the amended plan");
    }
    // I-61, per milestone: every milestone with a paid or pending amount
    // stays in the amended plan, at no less than that amount. Then the
    // claims stay within the amended total too (I-31).
    let claimed: BTreeSet<MilestoneId> = cx
        .money
        .pay
        .requests_of(g)
        .flat_map(|r| r.lines.values().map(|l| l.milestone))
        .collect();
    let amended = cx.money.plans.get(&x.plan);
    for m in claimed {
        let used = cx.money.pay.used(g, m);
        if used == 0 {
            continue;
        }
        let amount = amended.and_then(|p| p.milestones.get(&m)).map(|x| x.amount);
        if amount.is_none_or(|a| a < used) {
            return refuse(
                "I-61: the amendment sets a milestone below its paid plus pending amount",
            );
        }
    }
    if cx.headroom(g).is_none_or(|h| total > h) {
        return refuse("I-14: the amended total exceeds the cap headroom");
    }
    let e = MoneyExpect::new().exact(Record::AmendmentActivated {
        amendment,
        plan: x.plan,
        route,
        contract,
    });
    match route {
        AmendmentRoute::Exempt => MoneyVerdict::Accept(e),
        AmendmentRoute::Irc if irc_review_complete(cx, amendment, g) => MoneyVerdict::Accept(e),
        AmendmentRoute::Irc => {
            refuse("R-IR-04: an IRC-routed amendment needs its completed IRC review")
        }
    }
}

/// The amendment assignments of `amendment` on `grant` with their state:
/// active ones, and ones that await their declaration. Assignments whose
/// assignee holds a conflict fact on the grant count in neither.
fn amendment_assignments(
    cx: &MoneyCx<'_>,
    amendment: AmendmentId,
    grant: ProposalId,
) -> (BTreeSet<AssignmentId>, BTreeSet<AssignmentId>) {
    let mut active = BTreeSet::new();
    let mut awaiting = BTreeSet::new();
    for (id, a) in &cx.life.assignments {
        if a.proposal != grant
            || a.kind != AssignmentKind::Amendment(amendment)
            || a.released
            || cx.life.facts.contains(&(a.reviewer, grant))
        {
            continue;
        }
        if a.declared {
            active.insert(*id);
        } else {
            awaiting.insert(*id);
        }
    }
    (active, awaiting)
}

/// Whether the IRC review of `amendment` is complete (R-IR-01 read for
/// amendments, R-IR-04): at least P-15 active amendment assignments, every
/// one validated, none awaiting its declaration and no concern recorded.
fn irc_review_complete(cx: &MoneyCx<'_>, amendment: AmendmentId, grant: ProposalId) -> bool {
    let Some(x) = cx.money.amendments.get(&amendment) else {
        return false;
    };
    let Some(p15) = cx.life.governing(grant).map(|p| p.p15) else {
        return false;
    };
    let (active, awaiting) = amendment_assignments(cx, amendment, grant);
    !x.concern()
        && active.len() >= usize::from(p15)
        && awaiting.is_empty()
        && active.iter().all(|id| x.reviews.get(id) == Some(&true))
}

/// The verdict on an `Assign` of kind `AssignmentKind::Amendment` (R-IR-04).
fn amendment_assign(
    cx: &MoneyCx<'_>,
    actor: Actor,
    assignment: AssignmentId,
    proposal: ProposalId,
    reviewer: AccountId,
    amendment: AmendmentId,
    handle: Option<fstp_domain::id::Handle>,
) -> MoneyVerdict {
    let Some(a) = account(actor) else {
        return refuse("the FSTP coordinator assigns IRC members");
    };
    if !cx.holder(a, Role::FstpCoordinator, proposal) {
        return refuse("the FSTP coordinator assigns IRC members");
    }
    let Some(x) = cx.money.amendments.get(&amendment) else {
        return refuse("unknown amendment");
    };
    if x.grant != proposal {
        return refuse("the amendment belongs to another grant");
    }
    if x.route != Some(AmendmentRoute::Irc) || x.activated {
        return refuse("R-IR-04: only an IRC-routed amendment not yet activated gets IRC members");
    }
    if x.concern() {
        return refuse("test-author choice: a concern ends the IRC review of the amendment");
    }
    if !matches!(
        cx.state(proposal),
        Some(StateTag::Granted | StateTag::InExecution)
    ) {
        return refuse("an amendment needs GRANTED or IN_EXECUTION");
    }
    if cx.life.assignments.contains_key(&assignment) || cx.rev.assignments.contains_key(&assignment)
    {
        return refuse("assignment id reused");
    }
    if !cx.holder(reviewer, Role::IrcMember, proposal) {
        return refuse("the assignee holds no active IRC member binding");
    }
    let duplicate = cx.life.assignments.values().any(|y| {
        y.reviewer == reviewer && y.kind == AssignmentKind::Amendment(amendment) && !y.released
    });
    if duplicate {
        return refuse("already assigned to this amendment");
    }
    let programme = cx.programme(proposal);
    let reviewing = cx.life.assignments.values().any(|y| {
        y.reviewer == reviewer
            && y.kind == AssignmentKind::Reviewer
            && !y.released
            && cx.programme(y.proposal) == programme
    });
    if reviewing {
        return refuse("I-02: the IRC member holds a reviewer assignment in the programme");
    }
    if cx.life.facts.contains(&(reviewer, proposal))
        || crate::reference::review::ConflictFacts::has_conflict(
            cx.truth,
            reviewer,
            &team_of(cx.sod, proposal),
        )
    {
        return refuse("I-03: the IRC member is conflicted on the grant");
    }
    match cx.rev.governing_policy(proposal).map(|p| p.p11) {
        Some(fstp_domain::policy::ReviewerAnonymity::Anonymous) => match handle {
            None => return refuse("R-AN-01: no handle under P-11 anonymous"),
            Some(h) if cx.rev.handles.contains_key(&h) => {
                return refuse("R-AN-01: handle issued before");
            }
            Some(_) => {}
        },
        Some(fstp_domain::policy::ReviewerAnonymity::Named) if handle.is_some() => {
            return refuse("R-AN-01: no handle under P-11 named");
        }
        Some(fstp_domain::policy::ReviewerAnonymity::Named) => {}
        None => return refuse("no governing policy"),
    }
    let Some(call) = cx.life.proposals.get(&proposal).map(|p| p.current_call) else {
        return refuse("unknown proposal");
    };
    MoneyVerdict::Accept(MoneyExpect::new().exact(Record::Assigned(
        fstp_domain::record::Assigned {
            assignment,
            proposal,
            call,
            reviewer,
            kind: AssignmentKind::Amendment(amendment),
            handle,
            by: a,
            epoch: cx.sod.epoch,
        },
    )))
}

/// The verdict on a `RecordIrcReview` on an amendment assignment (R-IR-04).
/// The batch holds no transition: the proposal state never changes.
fn amendment_review(
    cx: &MoneyCx<'_>,
    actor: Actor,
    assignment: AssignmentId,
    amendment: AmendmentId,
    verdict: IrcVerdict,
) -> MoneyVerdict {
    let Some(a) = account(actor) else {
        return refuse("the IRC assignee records the review");
    };
    let Some(y) = cx.life.assignments.get(&assignment) else {
        return refuse("unknown assignment");
    };
    if y.reviewer != a || !y.active() {
        return refuse("the active IRC assignee records the review");
    }
    let grant = y.proposal;
    if !cx.holder(a, Role::IrcMember, grant) {
        return refuse("the assignee holds no active IRC member binding");
    }
    if cx.life.facts.contains(&(a, grant))
        || crate::reference::review::ConflictFacts::has_conflict(
            cx.truth,
            a,
            &team_of(cx.sod, grant),
        )
    {
        return refuse("I-03: the IRC member is conflicted on the grant");
    }
    let Some(x) = cx.money.amendments.get(&amendment) else {
        return refuse("unknown amendment");
    };
    if x.route != Some(AmendmentRoute::Irc) || x.activated {
        return refuse("R-IR-04: the amendment is not under IRC review");
    }
    if !matches!(
        cx.state(grant),
        Some(StateTag::Granted | StateTag::InExecution)
    ) {
        return refuse("an amendment needs GRANTED or IN_EXECUTION");
    }
    if x.reviews.contains_key(&assignment) {
        return refuse("R-IR-01: the review is recorded");
    }
    if x.concern() {
        return refuse("test-author choice: a concern ends the IRC review of the amendment");
    }
    MoneyVerdict::Accept(MoneyExpect::new().exact(Record::IrcReviewRecorded {
        assignment,
        verdict,
    }))
}

/// The records of a withdrawal that this lane adds: the release of an open reservation.
pub fn withdraw_release(cx: &MoneyCx<'_>, proposal: ProposalId) -> Option<Record> {
    let q = cx.money.proposals.get(&proposal)?;
    let old = q.reserved?;
    let amount = fstp_money::Amount::from_minor(old, fstp_money::Currency::Eur)
        .and_then(NonNegAmount::new)
        .ok()?;
    Some(Record::CapReleased { proposal, amount })
}

/// Whether `want` is met by `batch`.
fn met(want: &Want, batch: &[Record]) -> bool {
    batch.iter().any(|r| match (want, r) {
        (Want::Exact(x), r) => x == r,
        (
            Want::Reserved(p, a),
            Record::CapReserved {
                proposal, amount, ..
            },
        ) => proposal == p && minor(*amount) == *a,
        (Want::Released(p), Record::CapReleased { proposal, .. }) => proposal == p,
        (Want::Grant(p, a, plan), Record::GrantDecided(g)) => {
            g.proposal() == *p && minor(g.granted()) == *a && g.agreed_plan() == *plan
        }
        (
            Want::Declined(p, reasons),
            Record::NegotiationDeclined {
                proposal, reason, ..
            },
        ) => proposal == p && reasons.contains(reason),
        (
            Want::Release {
                request,
                grant,
                acceptors,
                approver,
                releaser,
            },
            Record::PaymentReleased(x),
        ) => {
            x.request() == *request
                && x.grant() == *grant
                && x.acceptors() == acceptors
                && x.approver() == *approver
                && x.releaser() == *releaser
        }
        (Want::Typed(name), r) => type_name(&r.to_json()).as_deref() == Some(*name),
        _ => false,
    })
}

/// Checks an accepted batch against `exp`: every wanted record is there,
/// the transitions are exactly the expected ones, no grant appears that
/// the expectation does not name, and an unexpected reservation or
/// release names a proposal of the expectation.
pub fn check_money_batch(context: &str, exp: &MoneyExpect, batch: &[Record]) -> Result<(), String> {
    for w in &exp.wants {
        if !met(w, batch) {
            return Err(format!(
                "{context}: the batch lacks {w:?}\n  batch: {batch:?}"
            ));
        }
    }
    if !exp.other_transitions {
        let got: Vec<(ProposalId, StateTag, StateTag, Row)> = batch
            .iter()
            .filter_map(|r| match r {
                Record::Transitioned(t) => Some((t.proposal, t.from, t.to, t.row)),
                _ => None,
            })
            .collect();
        if got != exp.transitions {
            return Err(format!(
                "{context}: the batch transitions {got:?}, the reference expects {:?}",
                exp.transitions
            ));
        }
    }
    let grants_wanted = exp.wants.iter().any(|w| matches!(w, Want::Grant(..)));
    if !grants_wanted && batch.iter().any(|r| matches!(r, Record::GrantDecided(_))) {
        return Err(format!(
            "{context}: the batch records a grant the reference does not expect: {batch:?}"
        ));
    }
    let reserve_wanted = exp.wants.iter().any(|w| matches!(w, Want::Reserved(..)));
    if !reserve_wanted
        && batch
            .iter()
            .any(|r| matches!(r, Record::CapReserved { .. }))
    {
        return Err(format!(
            "{context}: the batch reserves cap headroom the reference does not expect: {batch:?}"
        ));
    }
    Ok(())
}

/// The records a run on the references alone appends for an accepted `exp`.
pub fn synthesize(exp: &MoneyExpect) -> Vec<Record> {
    exp.synth.clone()
}
