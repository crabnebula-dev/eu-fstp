//! Grants, reservations and deliverables (design section 2.11, I-13, I-14, I-15, I-64).
//!
//! Owned by lane L-MONEY (docs/handoff/m2-design.md section 10). The rules
//! come from `SPEC/02-domain/state-machine.md` (NOTE 9, 11, 12 and 13),
//! `SPEC/02-domain/contracts.md` (Amount and recipient cap, Repeat grants
//! and amendments) and `SPEC/02-domain/payment-requests.md` (Milestone
//! closure, P-67, I-64).
//!
//! - [`MoneyState`] keeps, per proposal, the negotiation facts: the latest
//!   amount determination, the open reservation, the acceptance, the
//!   approval and the contract fact. Per grant it keeps the granted amount,
//!   the plan of the effective contract version and the closed milestones.
//!   It also keeps the deliverables of the M5 checks and the amendments.
//! - The counted sum of a proposal for P-05 is its granted amount plus its
//!   open reservation. Once the grant is COMPLETED or TERMINATED it is the
//!   paid total of the grant instead (I-64). The vault groups the per
//!   account sums by verified identity, so the recipient is the verified
//!   identity of the applicant lead (Q7 A).
//! - The cap a proposal meets is the stricter of the publication snapshot
//!   of P-05 and the live value, read from its creation call (P-05 NOTE 7).
//!
//! Commands this lane decides:
//!
//! - `DetermineAmount`, by an assigned reviewer of the proposal with a
//!   [`crate::assignment::ReviewerAct`] (R-NG-03, I-03), in NEGOTIATION,
//!   before the lead accepts and the programme manager approves. The
//!   granted amount is the total of the plan the effective score carries
//!   forward (I-09) minus the recorded deductions, each with a reason, and
//!   lies within P-04 inclusive (I-13). The agreed plan is that plan or a
//!   negotiated plan of the proposal, and its total equals the granted
//!   amount (design 2.11). A deduction therefore needs a negotiated plan
//!   that carries it. The vault confirms that the recipient stays within
//!   the cap with the other proposals' counted sums (I-14). The batch
//!   releases an earlier reservation of the proposal and reserves the new
//!   amount, so two negotiations of one identity cannot both pass.
//! - `AcceptGrant` by the lead, `ApproveGrant` by the programme manager and
//!   `ContractFact` from the M5 contract port, each in NEGOTIATION once an
//!   amount is reserved. The command that completes the three facts asks
//!   the grant clearance questions. When every guard of NEGOTIATION to
//!   GRANTED holds, the batch records the fact, `GrantDecided`, which only
//!   a [`GrantClearance`] builds, and the transition. Otherwise the
//!   completing fact is refused with the rule of the first guard that
//!   fails, so it can be sent again once that guard holds.
//! - [`grant_preconditions`] and [`check_grant_preconditions`] are the
//!   contract seam of design 2.11. M5 asks them before a contract goes to
//!   SENT and again at countersignature.
//! - `DeclineNegotiation`, by the programme manager (NOTE 13), when one of
//!   the NOTE 9 failures holds. The reason recorded is the first failure
//!   that holds, in declaration order. The batch releases the reservation.
//!   The amount failures look at the smallest amount still open (NOTE 9,
//!   decided 2026-10-26). That is the determined amount once the lead
//!   accepted or the programme manager approved it, since it is then
//!   locked. Before, it is the P-04 minimum, since the lead may still
//!   propose a smaller negotiated plan. No grant amount can keep I-13 when
//!   that amount lies outside P-04 or above the effective plan total. No
//!   grant amount can keep I-14 when it does not fit the recipient's room
//!   under the stricter of the snapshot and live P-05. A plan total above
//!   the cap is no ground for declining while the P-04 minimum fits.
//! - `StartExecution`, by the System, at the earliest milestone start date
//!   of the effective contract version (NOTE 11).
//! - `Terminate`, by the programme manager, in GRANTED or IN_EXECUTION,
//!   with a reason.
//! - `CloseMilestone`, by the programme manager, in IN_EXECUTION, with a
//!   reason (NOTE 12, O-51).
//! - `Complete`, by the System, once every milestone of the effective
//!   contract version is closed and every payment request of the grant is
//!   terminal (NOTE 12).
//! - `RecordDeliverable`, by the System from the M5 checks, on a grant in
//!   GRANTED or IN_EXECUTION, for a milestone of the effective contract version.
//!
//! The grant clearance (design 3.3) asks `IsVerified` for the lead,
//! `HasGuardianConsent` for a minor, `WithinRecipientCap` for the
//! determined amount, `InExcludedClass` and `SameIdentityAsAny` for every
//! held Receiving account of the proposal (I-04, I-06, SoD-09), and the
//! I-15 question. The candidate set of `SameIdentityAsAny` holds the
//! Drafting and Judging accounts that would break I-01 with the binding.
//!
//! I-15 (decided 2026-10-25): the same applicant is the verified identity
//! of the lead, tenant-wide. Its prior deliverables are every deliverable
//! accepted so far under that identity's earlier grants. Each is checked
//! against the P-26 of the call that funded it. A grant's record is
//! complete when no accepted deliverable carries a licence outside that
//! P-26, and every milestone with an approved payment line has an accepted
//! deliverable under it. A partial claim without one leaves the record
//! incomplete until the final claim (P-65). The platform checks the lead's
//! own earlier grants itself. The vault then answers whether the lead
//! shares an identity with the lead of any other incomplete earlier grant.
//!
//! Readings of this lane, reported to Daniel:
//!
//! - The amount is locked once the lead accepted or the programme manager
//!   approved, since both accepted the amount determined.
//! - A grant fact before any determination is refused, as is a repeated
//!   contract fact or one outside NEGOTIATION.
//! - The lead records a negotiated plan in NEGOTIATION (step W5
//!   integration). A non-zero deduction needs one whose total equals the
//!   granted amount, and is refused under I-13 otherwise. Every negotiated
//!   plan of the proposal counts as an agreed plan, a superseded one too.
//!   Whether only the live one should count is open for Daniel.

use std::collections::{BTreeMap, BTreeSet};

use fstp_money::{Amount, Currency, NonNegAmount, PosAmount};

use crate::assignment::AssignmentKind;
use crate::command::{Actor, Command, ContractEvent, Ctx};
use crate::decision::NegotiationFailure;
use crate::engine::{FoldError, PolicyScope};
use crate::id::{
    AccountId, CallId, ContractId, DecisionId, DeliverableId, MilestoneId, PlanVersionId,
    ProgrammeId, ProposalId, TextRef, VaultEpoch,
};
use crate::oracle::{Answer, Answers, Query};
use crate::policy::SpdxId;
use crate::proposal::PlanOrigin;
use crate::record::{DeliverableRecorded, Record, RulesVersion, Transitioned};
use crate::refusal::{Refusal, RefusalReason, RuleRef};
use crate::roles::{Group, Role};
use crate::rules::{Row, StateTag};
use crate::state::{State, UsedId};
use crate::time::Timestamp;

/// One recorded deduction for ineligible costs, with its reason (I-13).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IneligibleCost {
    /// The amount deducted.
    pub amount: PosAmount,
    /// The recorded reason.
    pub reason: TextRef,
}

// ---------------------------------------------------------------------------
// Witnesses
// ---------------------------------------------------------------------------

/// I-13: a granted amount that equals the agreed plan total minus the
/// recorded deductions and lies within P-04 inclusive. Built only in this
/// module, by the amount check of `DetermineAmount` and of the grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GrantAmount {
    proposal: ProposalId,
    granted: NonNegAmount,
    agreed_plan: PlanVersionId,
    decision: DecisionId,
}

impl GrantAmount {
    /// The proposal.
    pub fn proposal(&self) -> ProposalId {
        self.proposal
    }

    /// The granted amount.
    pub fn granted(&self) -> NonNegAmount {
        self.granted
    }

    /// The agreed plan version.
    pub fn agreed_plan(&self) -> PlanVersionId {
        self.agreed_plan
    }

    /// The amount decision.
    pub fn decision(&self) -> DecisionId {
        self.decision
    }
}

/// I-14: the vault answered that the amount keeps the recipient within the
/// cap, over every other grant and open reservation in the programme.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CapReservation {
    proposal: ProposalId,
    amount: NonNegAmount,
    epoch: VaultEpoch,
}

impl CapReservation {
    /// The proposal.
    pub fn proposal(&self) -> ProposalId {
        self.proposal
    }

    /// The reserved amount.
    pub fn amount(&self) -> NonNegAmount {
        self.amount
    }

    /// The vault epoch of the cap answer.
    pub fn epoch(&self) -> VaultEpoch {
        self.epoch
    }
}

/// I-15: the lead's earlier grants have complete public deliverable records,
/// checked locally and through one vault answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RepeatClearance {
    subject: AccountId,
    epoch: VaultEpoch,
}

impl RepeatClearance {
    /// The applicant lead.
    pub fn subject(&self) -> AccountId {
        self.subject
    }

    /// The vault epoch of the check.
    pub fn epoch(&self) -> VaultEpoch {
        self.epoch
    }
}

/// The lead is verified and passes SoD-09, and every held Receiving
/// account of the proposal keeps I-04 and I-06.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IdentityCleared {
    lead: AccountId,
    epoch: VaultEpoch,
}

impl IdentityCleared {
    /// The applicant lead.
    pub fn lead(&self) -> AccountId {
        self.lead
    }

    /// The vault epoch of the answers.
    pub fn epoch(&self) -> VaultEpoch {
        self.epoch
    }
}

/// I-18: the lead is not flagged as a minor, or the vault holds a verified
/// guardian consent for the proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MinorCleared {
    proposal: ProposalId,
    minor: bool,
}

impl MinorCleared {
    /// The proposal.
    pub fn proposal(&self) -> ProposalId {
        self.proposal
    }

    /// Whether the lead is flagged as a minor, so consent was checked.
    pub fn minor(&self) -> bool {
        self.minor
    }
}

/// The M5 contract port reported the contract EFFECTIVE.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ContractEffective {
    contract: ContractId,
}

impl ContractEffective {
    /// The contract.
    pub fn contract(&self) -> ContractId {
        self.contract
    }
}

/// Everything NEGOTIATION to GRANTED needs, checked in one step. Built
/// only by the grant clearance of this module.
///
/// Outside the crate a clearance cannot be written as a literal:
///
/// ```compile_fail
/// use fstp_domain::grant::GrantClearance;
/// fn forge(c: GrantClearance) -> GrantClearance {
///     GrantClearance { ..c }
/// }
/// ```
///
/// The twin below differs only in the forbidden line:
///
/// ```no_run
/// use fstp_domain::grant::GrantClearance;
/// fn forge(c: GrantClearance) -> GrantClearance {
///     c
/// }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GrantClearance {
    amount: GrantAmount,
    cap: CapReservation,
    repeat: RepeatClearance,
    identity: IdentityCleared,
    minor: MinorCleared,
    contract: ContractEffective,
    acceptance: DecisionId,
    approval: DecisionId,
}

impl GrantClearance {
    /// The I-13 amount.
    pub fn amount(&self) -> &GrantAmount {
        &self.amount
    }

    /// The I-14 cap answer.
    pub fn cap(&self) -> &CapReservation {
        &self.cap
    }

    /// The I-15 clearance.
    pub fn repeat(&self) -> &RepeatClearance {
        &self.repeat
    }

    /// The identity checks.
    pub fn identity(&self) -> &IdentityCleared {
        &self.identity
    }

    /// The I-18 check.
    pub fn minor(&self) -> &MinorCleared {
        &self.minor
    }

    /// The effective contract.
    pub fn contract(&self) -> &ContractEffective {
        &self.contract
    }

    /// The lead's acceptance.
    pub fn acceptance(&self) -> DecisionId {
        self.acceptance
    }

    /// The programme manager's approval.
    pub fn approval(&self) -> DecisionId {
        self.approval
    }
}

/// The NEGOTIATION to GRANTED record. Only [`GrantDecided::from_clearance`]
/// builds it outside the record decoder (I-13, I-14, I-15).
///
/// ```compile_fail
/// use fstp_domain::grant::GrantDecided;
/// fn forge(g: GrantDecided) -> GrantDecided {
///     GrantDecided { ..g }
/// }
/// ```
///
/// The twin below differs only in the forbidden line:
///
/// ```no_run
/// use fstp_domain::grant::GrantDecided;
/// fn forge(g: GrantDecided) -> GrantDecided {
///     g
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GrantDecided {
    proposal: ProposalId,
    granted: NonNegAmount,
    agreed_plan: PlanVersionId,
    acceptance: DecisionId,
    approval: DecisionId,
    contract: ContractId,
    epoch: VaultEpoch,
    rules: RulesVersion,
}

impl GrantDecided {
    /// Every field, for the record decoder in `codec/` only (design section 3.5).
    #[expect(
        clippy::too_many_arguments,
        reason = "one argument per field of the decoded record"
    )]
    pub(crate) fn from_decoded(
        proposal: ProposalId,
        granted: NonNegAmount,
        agreed_plan: PlanVersionId,
        acceptance: DecisionId,
        approval: DecisionId,
        contract: ContractId,
        epoch: VaultEpoch,
        rules: RulesVersion,
    ) -> Self {
        GrantDecided {
            proposal,
            granted,
            agreed_plan,
            acceptance,
            approval,
            contract,
            epoch,
            rules,
        }
    }

    /// The grant record of a full clearance, under the M2 readings.
    pub fn from_clearance(c: &GrantClearance) -> GrantDecided {
        GrantDecided {
            proposal: c.amount.proposal,
            granted: c.amount.granted,
            agreed_plan: c.amount.agreed_plan,
            acceptance: c.acceptance,
            approval: c.approval,
            contract: c.contract.contract,
            epoch: c.cap.epoch,
            rules: RulesVersion::M2,
        }
    }

    /// The proposal.
    pub fn proposal(&self) -> ProposalId {
        self.proposal
    }

    /// The granted amount.
    pub fn granted(&self) -> NonNegAmount {
        self.granted
    }

    /// The agreed plan version.
    pub fn agreed_plan(&self) -> PlanVersionId {
        self.agreed_plan
    }

    /// The applicant's acceptance decision.
    pub fn acceptance(&self) -> DecisionId {
        self.acceptance
    }

    /// The programme manager's approval decision.
    pub fn approval(&self) -> DecisionId {
        self.approval
    }

    /// The effective contract.
    pub fn contract(&self) -> ContractId {
        self.contract
    }

    /// The vault epoch of the clearance answers.
    pub fn epoch(&self) -> VaultEpoch {
        self.epoch
    }

    /// The rules version that produced the decision.
    pub fn rules(&self) -> RulesVersion {
        self.rules
    }
}

// ---------------------------------------------------------------------------
// The projection
// ---------------------------------------------------------------------------

/// The latest amount determination of a proposal (R-NG-03).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Determination {
    /// The amount decision.
    decision: DecisionId,
    /// The effective plan total.
    plan_total: NonNegAmount,
    /// The recorded deductions, summed.
    deducted: NonNegAmount,
    /// The granted amount.
    granted: NonNegAmount,
    /// The agreed plan.
    agreed: PlanVersionId,
}

/// The negotiation facts of a proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct Negotiation {
    /// The latest determination.
    determined: Option<Determination>,
    /// The open reservation.
    reserved: Option<NonNegAmount>,
    /// The lead's acceptance.
    accepted: Option<DecisionId>,
    /// The programme manager's approval.
    approved: Option<DecisionId>,
    /// The programme manager who approved, who records the grant when the
    /// contract port completes the facts (R-LA-03, NOTE 13).
    approver: Option<AccountId>,
    /// The contract the port reported EFFECTIVE.
    contract: Option<ContractId>,
}

impl Negotiation {
    const fn new() -> Negotiation {
        Negotiation {
            determined: None,
            reserved: None,
            accepted: None,
            approved: None,
            approver: None,
            contract: None,
        }
    }
}

/// One grant.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Grant {
    /// The granted amount: the amended total after an amendment.
    granted: NonNegAmount,
    /// The plan of the effective contract version.
    plan: PlanVersionId,
    /// The milestones the programme manager closed (NOTE 12).
    closed: BTreeSet<MilestoneId>,
}

/// One deliverable from the M5 checks (I-15).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Deliverable {
    /// The grant.
    grant: ProposalId,
    /// The milestone.
    milestone: MilestoneId,
    /// Its SPDX licence.
    licence: SpdxId,
    /// Whether it was accepted.
    accepted: bool,
}

/// Money part of the projection: negotiations with their reservations,
/// grants, deliverables and amendments.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct MoneyState {
    /// Negotiation facts per proposal.
    negotiations: BTreeMap<ProposalId, Negotiation>,
    /// Grants per proposal.
    grants: BTreeMap<ProposalId, Grant>,
    /// Deliverables.
    deliverables: BTreeMap<DeliverableId, Deliverable>,
    /// Amendments, kept for `crate::amendment`.
    pub(crate) amendments: BTreeMap<crate::id::AmendmentId, crate::amendment::Amendment>,
}

impl MoneyState {
    /// The money state before any record.
    pub(crate) const fn genesis() -> MoneyState {
        MoneyState {
            negotiations: BTreeMap::new(),
            grants: BTreeMap::new(),
            deliverables: BTreeMap::new(),
            amendments: BTreeMap::new(),
        }
    }

    /// The open reservation of `proposal`, if any (I-14).
    pub fn reserved(&self, proposal: ProposalId) -> Option<NonNegAmount> {
        self.negotiations.get(&proposal).and_then(|n| n.reserved)
    }

    /// The granted amount of `proposal`, the amended total after an amendment.
    pub fn granted(&self, proposal: ProposalId) -> Option<NonNegAmount> {
        self.grants.get(&proposal).map(|g| g.granted)
    }

    /// The plan of the effective contract version of the grant `proposal`.
    pub fn contract_plan(&self, proposal: ProposalId) -> Option<PlanVersionId> {
        self.grants.get(&proposal).map(|g| g.plan)
    }

    /// Whether the programme manager closed `milestone` of the grant `proposal`.
    pub fn milestone_closed(&self, proposal: ProposalId, milestone: MilestoneId) -> bool {
        self.grants
            .get(&proposal)
            .is_some_and(|g| g.closed.contains(&milestone))
    }
}

// ---------------------------------------------------------------------------
// Shared helpers of the money lanes
// ---------------------------------------------------------------------------

/// The refusal of an unknown entity.
pub(crate) const fn unknown() -> Refusal {
    Refusal::new(RuleRef::Input, RefusalReason::UnknownEntity)
}

/// The refusal of a command the state does not admit.
pub(crate) const fn wrong_state() -> Refusal {
    Refusal::new(RuleRef::Row, RefusalReason::WrongState)
}

/// The refusal of a shell-supplied id that is already taken.
pub(crate) const fn reused() -> Refusal {
    Refusal::new(RuleRef::Ledger, RefusalReason::IdReused)
}

/// The refusal of a value the command may not carry.
pub(crate) const fn invalid() -> Refusal {
    Refusal::new(RuleRef::Input, RefusalReason::InvalidValue)
}

/// The refusal of a guard of `rule` that does not hold.
pub(crate) const fn guard(rule: RuleRef) -> Refusal {
    Refusal::new(rule, RefusalReason::GuardFailed)
}

/// The refusal of a vault answer that refuses under `rule`.
pub(crate) const fn vault(rule: RuleRef) -> Refusal {
    Refusal::new(rule, RefusalReason::VaultRefused)
}

/// The refusal of an actor without the binding the command needs.
pub(crate) const fn inactive() -> Refusal {
    Refusal::new(RuleRef::Actor, RefusalReason::BindingInactive)
}

/// The answer to `q`, or the refusal of a missing one.
pub(crate) fn answer<'a>(answers: &'a Answers, q: &Query) -> Result<&'a Answer, Refusal> {
    answers.get(q).ok_or(Refusal::new(
        RuleRef::FactsIncomplete,
        RefusalReason::AnswerMissing,
    ))
}

/// Appends the record of the answer to `q` unless `out` holds it already
/// (overview NOTE 5), and returns the answer bit.
pub(crate) fn record_answer(
    out: &mut Vec<Record>,
    q: &Query,
    answers: &Answers,
) -> Result<bool, Refusal> {
    let a = answer(answers, q)?;
    let r = Record::VaultOutcome {
        kind: q.kind(),
        digest: a.digest,
        holds: a.holds,
        epoch: a.epoch,
    };
    if !out.contains(&r) {
        out.push(r);
    }
    Ok(a.holds)
}

/// A transition record of `proposal` with the command's actor (R-AU-01).
pub(crate) const fn transition(
    proposal: ProposalId,
    from: StateTag,
    to: StateTag,
    row: Row,
    ctx: &Ctx,
    decision: Option<DecisionId>,
) -> Record {
    Record::Transitioned(Transitioned {
        proposal,
        from,
        to,
        row,
        actor: ctx.actor,
        decision,
    })
}

/// What the money lanes read about a proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Subject {
    /// The lead.
    pub(crate) lead: AccountId,
    /// Whether the lead is flagged as a minor.
    pub(crate) minor: bool,
    /// The creation call, whose frozen policy governs the proposal (NOTE 8).
    pub(crate) call: CallId,
    /// The programme.
    pub(crate) programme: ProgrammeId,
    /// The proposal state.
    pub(crate) state: StateTag,
    /// The programme currency (ADR-006).
    pub(crate) currency: Currency,
}

/// The facts the money lanes read about `proposal`.
pub(crate) fn subject(state: &State, proposal: ProposalId) -> Result<Subject, Refusal> {
    let d = crate::proposal::draft::draft(state, proposal).ok_or_else(unknown)?;
    let programme = crate::assignment::programme_of(state, proposal)?;
    let tag = crate::proposal::intake::proposal_state(state, proposal).ok_or_else(unknown)?;
    let currency = crate::policy::programme_currency(state, programme).ok_or_else(unknown)?;
    Ok(Subject {
        lead: d.lead,
        minor: d.minor,
        call: d.call,
        programme,
        state: tag,
        currency,
    })
}

/// The governing call of `proposal` as the scope of P-77 (R-MC-05).
pub(crate) fn call_scope(state: &State, proposal: ProposalId) -> Result<PolicyScope, Refusal> {
    crate::proposal::draft::proposal_call(state, proposal)
        .map(PolicyScope::Call)
        .ok_or_else(unknown)
}

/// `a + b`, or the largest amount when the sum leaves the money range.
/// A larger sum only refuses more, so the saturation is conservative.
pub(crate) fn add(a: NonNegAmount, b: NonNegAmount) -> NonNegAmount {
    match a
        .amount()
        .checked_add(b.amount())
        .and_then(NonNegAmount::new)
    {
        Ok(sum) => sum,
        Err(_) => Amount::from_minor(Amount::MAX_ABS_MINOR, a.amount().currency())
            .and_then(NonNegAmount::new)
            .unwrap_or(a),
    }
}

/// The sum of two optional amounts, `None` standing for nothing.
pub(crate) fn add_opt(a: Option<NonNegAmount>, b: Option<NonNegAmount>) -> Option<NonNegAmount> {
    match (a, b) {
        (Some(x), Some(y)) => Some(add(x, y)),
        (x, None) => x,
        (None, y) => y,
    }
}

/// `a - b`, or `None` below zero or across currencies.
pub(crate) fn sub(a: NonNegAmount, b: NonNegAmount) -> Option<NonNegAmount> {
    a.amount()
        .checked_sub(b.amount())
        .and_then(NonNegAmount::new)
        .ok()
}

/// Whether `a <= b`, refusing mixed currencies.
pub(crate) fn at_most(a: Amount, b: Amount) -> Result<bool, Refusal> {
    a.cmp_same(b)
        .map(|o| o != core::cmp::Ordering::Greater)
        .map_err(|_| invalid())
}

/// Whether `a` is zero.
pub(crate) fn is_zero(a: NonNegAmount) -> bool {
    a.amount().minor() == 0
}

/// One milestone of a plan: id, amount and start date.
pub(crate) type PlanMilestone = (MilestoneId, PosAmount, Timestamp);

/// The milestones of the plan version `plan`.
pub(crate) fn plan_milestones(state: &State, plan: PlanVersionId) -> Option<Vec<PlanMilestone>> {
    let p = crate::proposal::intake::plan(state, plan)?;
    Some(
        p.tasks
            .iter()
            .flat_map(|t| t.milestones.iter())
            .map(|m| (m.id, m.amount, m.start))
            .collect(),
    )
}

/// The total of the plan version `plan`.
pub(crate) fn plan_total(state: &State, plan: PlanVersionId) -> Option<NonNegAmount> {
    crate::proposal::intake::plan(state, plan).and_then(crate::proposal::intake::plan_total)
}

/// The milestones of the effective contract version of the grant `proposal`.
pub(crate) fn contract_milestones(
    state: &State,
    proposal: ProposalId,
) -> Option<Vec<PlanMilestone>> {
    plan_milestones(state, state.money.contract_plan(proposal)?)
}

// ---------------------------------------------------------------------------
// Counted sums (I-14, I-64)
// ---------------------------------------------------------------------------

/// The counted sum of `proposal`: granted plus reserved, or the paid total
/// once the grant is COMPLETED or TERMINATED (I-64). `None` counts nothing.
fn counted(state: &State, proposal: ProposalId) -> Option<NonNegAmount> {
    let closed = matches!(
        crate::proposal::intake::proposal_state(state, proposal),
        Some(StateTag::Completed | StateTag::Terminated)
    );
    let sum = if closed {
        crate::payment::paid_total(state, proposal)
    } else {
        add_opt(
            state.money.granted(proposal),
            state.money.reserved(proposal),
        )
    };
    sum.filter(|a| !is_zero(*a))
}

/// The counted sum per applicant lead account in `programme`, without
/// `except`, for the cap questions (I-14, design 4.2). Accounts with a
/// zero sum are left out. The vault groups the accounts by verified identity.
pub(crate) fn committed(
    state: &State,
    programme: ProgrammeId,
    except: Option<ProposalId>,
) -> BTreeMap<AccountId, NonNegAmount> {
    let proposals: BTreeSet<ProposalId> = state
        .money
        .negotiations
        .keys()
        .chain(state.money.grants.keys())
        .copied()
        .filter(|p| Some(*p) != except)
        .collect();
    let mut out: BTreeMap<AccountId, NonNegAmount> = BTreeMap::new();
    for p in proposals {
        if crate::assignment::programme_of(state, p).ok() != Some(programme) {
            continue;
        }
        let Some(d) = crate::proposal::draft::draft(state, p) else {
            continue;
        };
        let Some(n) = counted(state, p) else {
            continue;
        };
        let sum = add_opt(out.get(&d.lead).copied(), Some(n));
        if let Some(sum) = sum {
            out.insert(d.lead, sum);
        }
    }
    out
}

/// The cap question for `amount` on top of the other proposals' counted
/// sums of the recipient of `proposal` (I-14, P-05 NOTE 7).
pub(crate) fn cap_query(
    state: &State,
    proposal: ProposalId,
    amount: NonNegAmount,
) -> Result<Query, Refusal> {
    let s = subject(state, proposal)?;
    Ok(Query::WithinRecipientCap {
        subject: s.lead,
        amount,
        committed: committed(state, s.programme, Some(proposal)),
        cap: crate::policy::effective_p05(state, s.call)?,
    })
}

// ---------------------------------------------------------------------------
// I-15
// ---------------------------------------------------------------------------

/// Whether the I-15 record of the grant `g` is complete. No accepted
/// deliverable may carry a licence outside the P-26 of the call that
/// funded it. Every milestone with an approved payment line needs an
/// accepted deliverable under that P-26 (P-65).
pub(crate) fn record_complete(state: &State, g: ProposalId) -> bool {
    let Ok(values) = crate::assignment::governing_values(state, g) else {
        return false;
    };
    let p26 = &values.p26.0;
    let mine: Vec<&Deliverable> = state
        .money
        .deliverables
        .values()
        .filter(|d| d.grant == g)
        .collect();
    if mine.iter().any(|d| d.accepted && !p26.contains(&d.licence)) {
        return false;
    }
    crate::payment::accepted_milestones(state, g)
        .iter()
        .all(|m| {
            mine.iter()
                .any(|d| d.milestone == *m && d.accepted && p26.contains(&d.licence))
        })
}

/// The I-15 check of a grant to `lead` on `proposal`: whether the lead's
/// own earlier grants have complete records, and the vault question about
/// the leads of the other incomplete earlier grants, tenant-wide.
pub(crate) fn repeat_check(
    state: &State,
    lead: AccountId,
    proposal: ProposalId,
) -> (bool, Option<Query>) {
    let mut local = true;
    let mut others: BTreeSet<AccountId> = BTreeSet::new();
    for g in state
        .money
        .grants
        .keys()
        .copied()
        .filter(|g| *g != proposal)
    {
        if record_complete(state, g) {
            continue;
        }
        match crate::proposal::draft::draft(state, g) {
            Some(d) if d.lead == lead => local = false,
            Some(d) => {
                others.insert(d.lead);
            }
            None => {}
        }
    }
    let query = (!others.is_empty()).then_some(Query::SameIdentityAsAny {
        subject: lead,
        others,
    });
    (local, query)
}

/// The I-15 clearance from the local check and the vault answer.
pub(crate) fn clear_repeat(
    state: &State,
    lead: AccountId,
    proposal: ProposalId,
    answers: &Answers,
    out: &mut Vec<Record>,
) -> Result<Option<RepeatClearance>, Refusal> {
    let (local, query) = repeat_check(state, lead, proposal);
    let shared = match &query {
        Some(q) => record_answer(out, q, answers)?,
        None => false,
    };
    Ok((local && !shared).then_some(RepeatClearance {
        subject: lead,
        epoch: state.epoch,
    }))
}

// ---------------------------------------------------------------------------
// Identity checks (SoD-09, I-04, I-06)
// ---------------------------------------------------------------------------

/// The identity questions of one held Receiving account of the proposal.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ReceivingCheck {
    /// `InExcludedClass` against the classes of the binding's call (I-04).
    excluded: Query,
    /// `SameIdentityAsAny` against the Drafting and Judging accounts that
    /// would break I-01 with the binding (I-06, SoD-09). None for an empty set.
    identity: Option<Query>,
}

/// The `SameIdentityAsAny` question of `account` in `programme` for a
/// Receiving binding opened at `opened`, or `None` for an empty set.
fn sod09_query(
    state: &State,
    account: AccountId,
    programme: ProgrammeId,
    opened: u32,
) -> Option<Query> {
    let others = crate::roles::guards::breaking_candidates(
        state,
        account,
        programme,
        &[Group::Drafting, Group::Judging],
        opened,
        None,
    );
    (!others.is_empty()).then_some(Query::SameIdentityAsAny {
        subject: account,
        others,
    })
}

/// The checks of every held Receiving binding of `proposal`, and whether
/// the lead's Applicant binding is held.
fn receiving_checks(
    state: &State,
    proposal: ProposalId,
    lead: AccountId,
) -> Result<(bool, Vec<ReceivingCheck>), Refusal> {
    let mut lead_held = false;
    let mut out = Vec::new();
    for (_, b) in state.roster.bindings() {
        if b.proposal() != Some(proposal) || b.group() != Group::Receiving || !b.held() {
            continue;
        }
        if b.account == lead && b.role == Role::Applicant {
            lead_held = true;
        }
        let call = b.call().ok_or_else(unknown)?;
        out.push(ReceivingCheck {
            excluded: Query::InExcludedClass {
                account: b.account,
                programme: b.programme,
                classes: crate::policy::effective_p13(state, call)?,
            },
            identity: sod09_query(state, b.account, b.programme, b.opened),
        });
    }
    Ok((lead_held, out))
}

/// The opening of the lead's Applicant binding on `proposal`, held,
/// voided or ended, or 0 when none is found.
fn lead_opening(state: &State, proposal: ProposalId, lead: AccountId) -> u32 {
    let is_lead = |b: &crate::roles::Binding| {
        b.account == lead && b.role == Role::Applicant && b.proposal() == Some(proposal)
    };
    state
        .roster
        .bindings()
        .map(|(_, b)| b)
        .chain(state.roster.ended().map(|(_, e)| &e.binding))
        .find(|b| is_lead(b))
        .map_or(0, |b| b.opened)
}

/// The rules under which Receiving bindings of `proposal` were voided.
fn voided_rules(state: &State, proposal: ProposalId) -> BTreeSet<RuleRef> {
    state
        .roster
        .bindings()
        .map(|(_, b)| b)
        .chain(state.roster.ended().map(|(_, e)| &e.binding))
        .filter(|b| b.proposal() == Some(proposal) && b.group() == Group::Receiving)
        .filter_map(|b| match b.status {
            crate::roles::BindingStatus::Voided(rule) => Some(rule),
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// DetermineAmount (R-NG-03, I-13, I-14)
// ---------------------------------------------------------------------------

/// A checked `DetermineAmount`.
struct DeterminePlan {
    reviewer: AccountId,
    proposal: ProposalId,
    decision: DecisionId,
    agreed: PlanVersionId,
    plan_total: NonNegAmount,
    granted: NonNegAmount,
    deductions: Vec<IneligibleCost>,
    previous: Option<NonNegAmount>,
    conflict: Query,
    cap: Query,
}

/// Whether `agreed` may be the agreed plan of `proposal`: the plan its
/// effective score carries forward (I-09), or a negotiated plan of it.
fn agreed_plan_ok(state: &State, proposal: ProposalId, agreed: PlanVersionId) -> bool {
    let effective = effective_plan(state, proposal);
    let negotiated = crate::proposal::intake::plan(state, agreed)
        .is_some_and(|p| p.proposal == proposal && p.origin == PlanOrigin::Negotiated);
    effective == Some(agreed) || negotiated
}

/// The plan the effective score of `proposal` carries forward (I-09).
fn effective_plan(state: &State, proposal: ProposalId) -> Option<PlanVersionId> {
    crate::proposal::life::facts(state, proposal)
        .and_then(|f| f.effective.as_ref())
        .map(crate::decision::EffectiveScoreSet::plan)
}

/// The I-13 amount of `proposal`, with the effective plan total: that
/// total minus `deducted`, within P-04 inclusive. The agreed plan's total
/// must equal the granted amount (design 2.11), so the contract built
/// from it never lets the grantee claim more than the grant (I-31).
fn determine_amount(
    state: &State,
    proposal: ProposalId,
    agreed: PlanVersionId,
    deducted: NonNegAmount,
    decision: DecisionId,
) -> Result<(GrantAmount, NonNegAmount), Refusal> {
    let effective = effective_plan(state, proposal).ok_or_else(|| guard(RuleRef::I13))?;
    let total = plan_total(state, effective).ok_or_else(unknown)?;
    let granted = sub(total, deducted).ok_or_else(|| guard(RuleRef::I13))?;
    let agreed_total = plan_total(state, agreed).ok_or_else(unknown)?;
    if agreed_total.amount() != granted.amount() {
        return Err(guard(RuleRef::I13));
    }
    let p04 = crate::assignment::governing_values(state, proposal)?.p04;
    if !p04.contains(granted).map_err(|_| invalid())? {
        return Err(guard(RuleRef::I13));
    }
    Ok((
        GrantAmount {
            proposal,
            granted,
            agreed_plan: agreed,
            decision,
        },
        total,
    ))
}

fn check_determine(state: &State, cmd: &Command, ctx: &Ctx) -> Result<DeterminePlan, Refusal> {
    let Command::DetermineAmount {
        decision,
        proposal,
        agreed,
        deductions,
    } = cmd
    else {
        return Err(wrong_state());
    };
    let reviewer = crate::policy::actor_account(ctx)?;
    let s = subject(state, *proposal)?;
    if s.state != StateTag::Negotiation {
        return Err(wrong_state());
    }
    crate::assignment::qualifying_assignment(
        state,
        reviewer,
        *proposal,
        AssignmentKind::Reviewer,
        ctx.now,
    )
    .ok_or_else(inactive)?;
    let n = state.money.negotiations.get(proposal).copied();
    if n.is_some_and(|n| n.accepted.is_some() || n.approved.is_some()) {
        return Err(guard(RuleRef::Rng03));
    }
    if state.used_ids.contains(UsedId::Decision(*decision)) {
        return Err(reused());
    }
    if !agreed_plan_ok(state, *proposal, *agreed) {
        return Err(guard(RuleRef::I13));
    }
    let amounts: Vec<Amount> = deductions.iter().map(|d| d.amount.amount()).collect();
    let deducted = fstp_money::checked_sum(s.currency, amounts)
        .and_then(NonNegAmount::new)
        .map_err(|_| invalid())?;
    let (amount, plan_total) = determine_amount(state, *proposal, *agreed, deducted, *decision)?;
    Ok(DeterminePlan {
        reviewer,
        proposal: *proposal,
        decision: *decision,
        agreed: *agreed,
        plan_total,
        granted: amount.granted,
        deductions: deductions.clone(),
        previous: n.and_then(|n| n.reserved),
        conflict: crate::assignment::conflict_query(state, reviewer, *proposal),
        cap: cap_query(state, *proposal, amount.granted)?,
    })
}

/// The I-14 reservation of `amount`, from the vault's cap answer to `q`.
fn reserve_cap(
    state: &State,
    amount: &GrantAmount,
    q: &Query,
    answers: &Answers,
    out: &mut Vec<Record>,
) -> Result<Option<CapReservation>, Refusal> {
    let within = record_answer(out, q, answers)?;
    Ok(within.then_some(CapReservation {
        proposal: amount.proposal,
        amount: amount.granted,
        epoch: state.epoch,
    }))
}

fn decide_determine(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
    answers: &Answers,
) -> Result<Vec<Record>, Refusal> {
    let plan = check_determine(state, cmd, ctx)?;
    let act = crate::assignment::reviewer_act_on(
        state,
        plan.reviewer,
        plan.proposal,
        AssignmentKind::Reviewer,
        ctx.now,
        answers,
    )?;
    act.require_proposal(plan.proposal)?;
    let mut outcomes = Vec::new();
    record_answer(&mut outcomes, &plan.conflict, answers)?;
    let amount = GrantAmount {
        proposal: plan.proposal,
        granted: plan.granted,
        agreed_plan: plan.agreed,
        decision: plan.decision,
    };
    let cap = reserve_cap(state, &amount, &plan.cap, answers, &mut outcomes)?
        .ok_or_else(|| vault(RuleRef::I14))?;
    let mut out = vec![Record::AmountDetermined {
        decision: amount.decision,
        proposal: amount.proposal,
        plan_total: plan.plan_total,
        deductions: plan.deductions,
        granted: amount.granted,
        agreed: amount.agreed_plan,
        by: act.account(),
        rules: RulesVersion::M2,
    }];
    if let Some(old) = plan.previous {
        out.push(Record::CapReleased {
            proposal: plan.proposal,
            amount: old,
        });
    }
    out.push(Record::CapReserved {
        proposal: cap.proposal,
        amount: cap.amount,
        epoch: cap.epoch,
    });
    out.extend(outcomes);
    Ok(out)
}

// ---------------------------------------------------------------------------
// The grant facts and NEGOTIATION to GRANTED
// ---------------------------------------------------------------------------

/// The grant clearance questions of `proposal` (design 3.3).
#[derive(Clone, Debug, PartialEq, Eq)]
struct ClearancePlan {
    lead: AccountId,
    minor: bool,
    verified: Query,
    consent: Option<Query>,
    cap: Query,
    lead_held: bool,
    receiving: Vec<ReceivingCheck>,
    repeat_local: bool,
    repeat: Option<Query>,
    determination: Determination,
    reserved: Option<NonNegAmount>,
}

impl ClearancePlan {
    fn queries(&self) -> Vec<Query> {
        let mut out = vec![self.verified.clone()];
        out.extend(self.consent.iter().cloned());
        out.push(self.cap.clone());
        for r in &self.receiving {
            out.push(r.excluded.clone());
            out.extend(r.identity.iter().cloned());
        }
        out.extend(self.repeat.iter().cloned());
        out
    }
}

fn clearance_plan(
    state: &State,
    proposal: ProposalId,
    n: &Negotiation,
) -> Result<ClearancePlan, Refusal> {
    let s = subject(state, proposal)?;
    let determination = n.determined.ok_or_else(|| guard(RuleRef::Rng03))?;
    let (lead_held, receiving) = receiving_checks(state, proposal, s.lead)?;
    let (repeat_local, repeat) = repeat_check(state, s.lead, proposal);
    Ok(ClearancePlan {
        lead: s.lead,
        minor: s.minor,
        verified: Query::IsVerified { account: s.lead },
        consent: s.minor.then_some(Query::HasGuardianConsent { proposal }),
        cap: cap_query(state, proposal, determination.granted)?,
        lead_held,
        receiving,
        repeat_local,
        repeat,
        determination,
        reserved: n.reserved,
    })
}

/// The witnesses of every NEGOTIATION to GRANTED guard apart from the
/// three grant facts.
struct Cleared {
    amount: GrantAmount,
    cap: CapReservation,
    repeat: RepeatClearance,
    identity: IdentityCleared,
    minor: MinorCleared,
}

/// Every guard of NEGOTIATION to GRANTED apart from the three facts,
/// checked in one step. Every answer used is recorded in `out`. A guard
/// that does not hold refuses with its rule, the first in this order:
/// SoD-09 verification, I-18 consent, I-04 and I-06 for each held
/// Receiving account, the lead's binding, I-13, I-14, then I-15.
fn clear(
    state: &State,
    proposal: ProposalId,
    plan: &ClearancePlan,
    answers: &Answers,
    out: &mut Vec<Record>,
) -> Result<Cleared, Refusal> {
    let mut failed: Option<Refusal> = None;
    let mut fail = |r: Refusal| {
        failed.get_or_insert(r);
    };
    if !record_answer(out, &plan.verified, answers)? {
        fail(vault(RuleRef::Sod09));
    }
    if let Some(q) = &plan.consent
        && !record_answer(out, q, answers)?
    {
        fail(vault(RuleRef::I18));
    }
    for r in &plan.receiving {
        if record_answer(out, &r.excluded, answers)? {
            fail(vault(RuleRef::I04));
        }
        if let Some(q) = &r.identity
            && record_answer(out, q, answers)?
        {
            fail(vault(RuleRef::I06));
        }
    }
    if !plan.lead_held {
        fail(guard(RuleRef::Sod09));
    }
    let d = plan.determination;
    let amount = match determine_amount(state, proposal, d.agreed, d.deducted, d.decision) {
        Ok((a, _)) if a.granted == d.granted && plan.reserved == Some(d.granted) => Some(a),
        _ => None,
    };
    if amount.is_none() {
        fail(guard(RuleRef::I13));
    }
    let cap = match &amount {
        Some(a) => reserve_cap(state, a, &plan.cap, answers, out)?,
        None => {
            record_answer(out, &plan.cap, answers)?;
            None
        }
    };
    if amount.is_some() && cap.is_none() {
        fail(vault(RuleRef::I14));
    }
    let repeat = clear_repeat(state, plan.lead, proposal, answers, out)?;
    if repeat.is_none() {
        fail(guard(RuleRef::I15));
    }
    if let Some(r) = failed {
        return Err(r);
    }
    let (Some(amount), Some(cap), Some(repeat)) = (amount, cap, repeat) else {
        return Err(guard(RuleRef::Row));
    };
    Ok(Cleared {
        amount,
        cap,
        repeat,
        identity: IdentityCleared {
            lead: plan.lead,
            epoch: state.epoch,
        },
        minor: MinorCleared {
            proposal,
            minor: plan.minor,
        },
    })
}

/// Every guard of NEGOTIATION to GRANTED, checked in one step, with the
/// three facts. The refusal of the first guard that does not hold otherwise.
fn clear_grant(
    state: &State,
    proposal: ProposalId,
    plan: &ClearancePlan,
    facts: (DecisionId, DecisionId, ContractId),
    answers: &Answers,
    out: &mut Vec<Record>,
) -> Result<GrantClearance, Refusal> {
    let (acceptance, approval, contract) = facts;
    let c = clear(state, proposal, plan, answers, out)?;
    Ok(GrantClearance {
        amount: c.amount,
        cap: c.cap,
        repeat: c.repeat,
        identity: c.identity,
        minor: c.minor,
        contract: ContractEffective { contract },
        acceptance,
        approval,
    })
}

/// The clearance plan of `proposal` without the three facts: it must be
/// in NEGOTIATION with an amount determined and reserved.
fn precondition_plan(state: &State, proposal: ProposalId) -> Result<ClearancePlan, Refusal> {
    let s = subject(state, proposal)?;
    if s.state != StateTag::Negotiation {
        return Err(wrong_state());
    }
    let n = state
        .money
        .negotiations
        .get(&proposal)
        .copied()
        .unwrap_or(Negotiation::new());
    if n.determined.is_none() || n.reserved.is_none() {
        return Err(guard(RuleRef::Rng03));
    }
    clearance_plan(state, proposal, &n)
}

/// The vault questions of every NEGOTIATION to GRANTED guard of
/// `proposal` apart from the three grant facts (design 2.11, contract
/// seam). M5 asks them before a contract goes to SENT and again at
/// countersignature, then calls [`check_grant_preconditions`]. They are
/// the questions the completing grant fact asks.
pub fn grant_preconditions(state: &State, proposal: ProposalId) -> Result<Vec<Query>, Refusal> {
    Ok(precondition_plan(state, proposal)?.queries())
}

/// Whether every NEGOTIATION to GRANTED guard of `proposal` apart from the
/// three grant facts holds under `answers`, the answers to
/// [`grant_preconditions`]. `Ok(())` when they hold, so a countersigned
/// contract cannot fail I-13, I-14, I-15, SoD-09, I-04, I-06 or I-18 at
/// GRANTED while the vault facts stay the same. Otherwise the refusal the
/// completing grant fact would get.
pub fn check_grant_preconditions(
    state: &State,
    proposal: ProposalId,
    answers: &Answers,
) -> Result<(), Refusal> {
    let plan = precondition_plan(state, proposal)?;
    let mut out = Vec::new();
    clear(state, proposal, &plan, answers, &mut out).map(|_| ())
}

/// One of the three grant facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fact {
    Accept(DecisionId, AccountId),
    Approve(DecisionId, AccountId),
    Contract(ContractId),
}

/// A checked grant fact, with the clearance plan when it completes the set.
struct FactPlan {
    proposal: ProposalId,
    record: Record,
    facts: Option<(DecisionId, DecisionId, ContractId)>,
    /// The approving programme manager, once approved.
    approver: Option<AccountId>,
    clearance: Option<ClearancePlan>,
}

fn check_fact(state: &State, cmd: &Command, ctx: &Ctx) -> Result<FactPlan, Refusal> {
    let (proposal, fact) = match cmd {
        Command::AcceptGrant { decision, proposal } => {
            let lead = crate::proposal::life::require_lead(state, *proposal, ctx)?;
            (*proposal, Fact::Accept(*decision, lead))
        }
        Command::ApproveGrant { decision, proposal } => {
            let by = crate::policy::actor_account(ctx)?;
            let s = subject(state, *proposal)?;
            crate::policy::require_holder(
                state,
                by,
                s.programme,
                &[Role::ProgrammeManager],
                ctx.now,
            )?;
            (*proposal, Fact::Approve(*decision, by))
        }
        Command::ContractFact {
            proposal,
            contract,
            event: ContractEvent::Effective,
        } => (*proposal, Fact::Contract(*contract)),
        _ => return Err(wrong_state()),
    };
    let s = subject(state, proposal)?;
    if s.state != StateTag::Negotiation {
        return Err(wrong_state());
    }
    let n = state
        .money
        .negotiations
        .get(&proposal)
        .copied()
        .unwrap_or(Negotiation::new());
    if n.determined.is_none() || n.reserved.is_none() {
        return Err(guard(RuleRef::Rng03));
    }
    let mut after = n;
    let fresh = |d: DecisionId| {
        if state.used_ids.contains(UsedId::Decision(d)) {
            Err(reused())
        } else {
            Ok(())
        }
    };
    let record = match fact {
        Fact::Accept(d, by) => {
            fresh(d)?;
            if n.accepted.is_some() {
                return Err(wrong_state());
            }
            after.accepted = Some(d);
            Record::GrantAccepted {
                decision: d,
                proposal,
                by,
            }
        }
        Fact::Approve(d, by) => {
            fresh(d)?;
            if n.approved.is_some() {
                return Err(wrong_state());
            }
            after.approved = Some(d);
            after.approver = Some(by);
            Record::GrantApproved {
                decision: d,
                proposal,
                by,
            }
        }
        Fact::Contract(c) => {
            if n.contract.is_some() {
                return Err(wrong_state());
            }
            after.contract = Some(c);
            Record::ContractFactRecorded {
                proposal,
                contract: c,
                event: ContractEvent::Effective,
            }
        }
    };
    let facts = match (after.accepted, after.approved, after.contract) {
        (Some(a), Some(b), Some(c)) => Some((a, b, c)),
        _ => None,
    };
    let clearance = match facts {
        Some(_) => Some(clearance_plan(state, proposal, &after)?),
        None => None,
    };
    Ok(FactPlan {
        proposal,
        record,
        facts,
        approver: after.approver,
        clearance,
    })
}

fn decide_fact(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
    answers: &Answers,
) -> Result<Vec<Record>, Refusal> {
    let plan = check_fact(state, cmd, ctx)?;
    let mut out = vec![plan.record.clone()];
    let (Some(clearance), Some(facts)) = (&plan.clearance, plan.facts) else {
        return Ok(out);
    };
    let mut outcomes = Vec::new();
    let c = clear_grant(
        state,
        plan.proposal,
        clearance,
        facts,
        answers,
        &mut outcomes,
    )?;
    out.push(Record::GrantDecided(GrantDecided::from_clearance(&c)));
    // R-LA-03, NOTE 13: the row's actor is the applicant and the programme
    // manager. When the contract port completes the facts, the approving
    // programme manager records the grant, never the System.
    let actor = match (ctx.actor, plan.approver) {
        (Actor::System(_), Some(pm)) => Actor::Account(pm),
        (a, _) => a,
    };
    out.push(Record::Transitioned(Transitioned {
        proposal: plan.proposal,
        from: StateTag::Negotiation,
        to: StateTag::Granted,
        row: Row::NegotiationToGranted,
        actor,
        decision: Some(c.approval),
    }));
    out.extend(outcomes);
    Ok(out)
}

// ---------------------------------------------------------------------------
// NEGOTIATION to DECLINED (NOTE 9, NOTE 13)
// ---------------------------------------------------------------------------

/// The questions of a `DeclineNegotiation`.
struct DeclinePlan {
    proposal: ProposalId,
    minor: bool,
    verified: Query,
    sod09: Option<Query>,
    consent: Option<Query>,
    range_failed: bool,
    cap: Option<Query>,
    repeat_local: bool,
    repeat: Option<Query>,
    voided: BTreeSet<RuleRef>,
    reserved: Option<NonNegAmount>,
}

/// The smallest grant amount of `proposal` still open within P-04, or
/// `None` without an effective plan total (NOTE 9, decided 2026-10-26).
/// The inner `None` means that no amount within P-04 can exist at all.
///
/// Once the lead accepted or the programme manager approved, the
/// determined amount is locked, so it alone is open. It counts only
/// within P-04 as frozen for the governing call. Before, the lead may
/// still propose a negotiated plan at any total from the P-04 minimum up
/// to the effective plan total, and a matching deduction grants it
/// (R-NG-03, design 2.11). A grant is never zero, though. The agreed plan
/// total equals the granted amount, and every milestone carries a positive
/// amount. So the smallest grant amount within P-04 is the P-04 minimum,
/// or one minor unit when that minimum is zero (NOTE 9, row "no grant
/// amount can keep I-13 and I-14"). It is open exactly when it lies
/// within P-04 and at most at the effective plan total. A plan total
/// above the P-04 maximum or above the cap headroom is no failure while
/// that smallest amount fits.
fn reachable_amounts(
    state: &State,
    proposal: ProposalId,
) -> Result<Option<Option<NonNegAmount>>, Refusal> {
    let Some(total) = effective_plan(state, proposal).and_then(|e| plan_total(state, e)) else {
        return Ok(None);
    };
    let p04 = crate::assignment::governing_values(state, proposal)?.p04;
    let locked = state
        .money
        .negotiations
        .get(&proposal)
        .filter(|n| n.accepted.is_some() || n.approved.is_some())
        .and_then(|n| n.determined)
        .map(|d| d.granted);
    let smallest = match locked {
        Some(l) => p04.contains(l).map_err(|_| invalid())?.then_some(l),
        None => {
            let floor = smallest_grant(p04.min())?;
            (p04.contains(floor).map_err(|_| invalid())?
                && at_most(floor.amount(), total.amount())?)
            .then_some(floor)
        }
    };
    Ok(Some(smallest))
}

/// The smallest grant amount at or above `min`: `min` itself, or one
/// minor unit of its currency when `min` is zero. A granted amount is the
/// total of a plan with at least one positive milestone, so it is never
/// zero (R-NG-03, design 2.11).
fn smallest_grant(min: NonNegAmount) -> Result<NonNegAmount, Refusal> {
    if !is_zero(min) {
        return Ok(min);
    }
    Amount::from_minor(1, min.amount().currency())
        .and_then(NonNegAmount::new)
        .map_err(|_| invalid())
}

fn check_decline(state: &State, cmd: &Command, ctx: &Ctx) -> Result<DeclinePlan, Refusal> {
    let Command::DeclineNegotiation { proposal } = cmd else {
        return Err(wrong_state());
    };
    let by = crate::policy::actor_account(ctx)?;
    let s = subject(state, *proposal)?;
    crate::policy::require_holder(state, by, s.programme, &[Role::ProgrammeManager], ctx.now)?;
    if s.state != StateTag::Negotiation {
        return Err(wrong_state());
    }
    let reserved = state.money.reserved(*proposal);
    let mut range_failed = false;
    let mut cap = None;
    match reachable_amounts(state, *proposal)? {
        // Some amount within P-04 fits the room exactly when the smallest
        // open one does. The vault answers for the stricter of the
        // snapshot and live P-05, for the lead's verified identity. A
        // vault change can leave even an open reservation above the room
        // (Identity discovery).
        Some(Some(smallest)) => cap = Some(cap_query(state, *proposal, smallest)?),
        Some(None) => range_failed = true,
        None => {}
    }
    let (repeat_local, repeat) = repeat_check(state, s.lead, *proposal);
    Ok(DeclinePlan {
        proposal: *proposal,
        minor: s.minor,
        verified: Query::IsVerified { account: s.lead },
        sod09: sod09_query(
            state,
            s.lead,
            s.programme,
            lead_opening(state, *proposal, s.lead),
        ),
        consent: s.minor.then_some(Query::HasGuardianConsent {
            proposal: *proposal,
        }),
        range_failed,
        cap,
        repeat_local,
        repeat,
        voided: voided_rules(state, *proposal),
        reserved,
    })
}

impl DeclinePlan {
    fn queries(&self) -> Vec<Query> {
        let mut out = vec![self.verified.clone()];
        out.extend(self.sod09.iter().cloned());
        out.extend(self.cap.iter().cloned());
        out.extend(self.repeat.iter().cloned());
        out.extend(self.consent.iter().cloned());
        out
    }

    /// The NOTE 9 failures that hold.
    fn failures(
        &self,
        answers: &Answers,
        out: &mut Vec<Record>,
    ) -> Result<BTreeSet<NegotiationFailure>, Refusal> {
        let mut f = BTreeSet::new();
        if !record_answer(out, &self.verified, answers)? {
            f.insert(NegotiationFailure::IdentityNotVerified);
        } else if let Some(q) = &self.sod09
            && record_answer(out, q, answers)?
        {
            f.insert(NegotiationFailure::Sod09Refused);
        }
        if self.voided.contains(&RuleRef::I04) {
            f.insert(NegotiationFailure::ReceivingVoidedUnderI04);
        }
        if self.voided.contains(&RuleRef::I06) {
            f.insert(NegotiationFailure::ReceivingVoidedUnderI06);
        }
        if self.range_failed {
            f.insert(NegotiationFailure::NoAmountWithinRange);
        }
        if let Some(q) = &self.cap
            && !record_answer(out, q, answers)?
        {
            f.insert(NegotiationFailure::NoAmountWithinCap);
        }
        let shared = match &self.repeat {
            Some(q) => record_answer(out, q, answers)?,
            None => false,
        };
        if !self.repeat_local || shared {
            f.insert(NegotiationFailure::RepeatRecordIncomplete);
        }
        if let Some(q) = &self.consent
            && self.minor
            && !record_answer(out, q, answers)?
        {
            f.insert(NegotiationFailure::GuardianConsentMissing);
        }
        Ok(f)
    }
}

fn decide_decline(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
    answers: &Answers,
) -> Result<Vec<Record>, Refusal> {
    let plan = check_decline(state, cmd, ctx)?;
    let mut outcomes = Vec::new();
    let failures = plan.failures(answers, &mut outcomes)?;
    let reason = failures
        .iter()
        .next()
        .copied()
        .ok_or_else(|| guard(RuleRef::Row))?;
    let mut out = vec![Record::NegotiationDeclined {
        proposal: plan.proposal,
        reason,
        rules: RulesVersion::M2,
    }];
    if let Some(amount) = plan.reserved {
        out.push(Record::CapReleased {
            proposal: plan.proposal,
            amount,
        });
    }
    out.push(transition(
        plan.proposal,
        StateTag::Negotiation,
        StateTag::Declined,
        Row::NegotiationToDeclined,
        ctx,
        None,
    ));
    out.extend(outcomes);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

/// The earliest milestone start date of the effective contract version of
/// the grant `proposal` (NOTE 11).
fn earliest_start(state: &State, proposal: ProposalId) -> Option<Timestamp> {
    contract_milestones(state, proposal)?
        .into_iter()
        .map(|(_, _, start)| start)
        .min()
}

/// Whether the grant `proposal` may complete: every milestone of the
/// effective contract version closed and every payment request terminal (NOTE 12).
fn completable(state: &State, proposal: ProposalId) -> bool {
    let Some(ms) = contract_milestones(state, proposal) else {
        return false;
    };
    ms.iter()
        .all(|(m, _, _)| state.money.milestone_closed(proposal, *m))
        && crate::payment::all_terminal(state, proposal)
}

fn decide_start(state: &State, proposal: ProposalId, ctx: &Ctx) -> Result<Vec<Record>, Refusal> {
    let s = subject(state, proposal)?;
    if s.state != StateTag::Granted {
        return Err(wrong_state());
    }
    let first = earliest_start(state, proposal).ok_or_else(unknown)?;
    if ctx.now < first {
        return Err(guard(RuleRef::Row));
    }
    Ok(vec![transition(
        proposal,
        StateTag::Granted,
        StateTag::InExecution,
        Row::GrantedToInExecution,
        ctx,
        None,
    )])
}

fn decide_complete(state: &State, proposal: ProposalId, ctx: &Ctx) -> Result<Vec<Record>, Refusal> {
    let s = subject(state, proposal)?;
    if s.state != StateTag::InExecution {
        return Err(wrong_state());
    }
    if !completable(state, proposal) {
        return Err(guard(RuleRef::Row));
    }
    Ok(vec![transition(
        proposal,
        StateTag::InExecution,
        StateTag::Completed,
        Row::InExecutionToCompleted,
        ctx,
        None,
    )])
}

fn decide_terminate(
    state: &State,
    decision: DecisionId,
    proposal: ProposalId,
    reason: TextRef,
    ctx: &Ctx,
) -> Result<Vec<Record>, Refusal> {
    let by = crate::policy::actor_account(ctx)?;
    let s = subject(state, proposal)?;
    crate::policy::require_holder(state, by, s.programme, &[Role::ProgrammeManager], ctx.now)?;
    let (from, row) = match s.state {
        StateTag::Granted => (StateTag::Granted, Row::GrantedToTerminated),
        StateTag::InExecution => (StateTag::InExecution, Row::InExecutionToTerminated),
        _ => return Err(wrong_state()),
    };
    if state.used_ids.contains(UsedId::Decision(decision)) {
        return Err(reused());
    }
    Ok(vec![
        Record::TerminationRecorded {
            decision,
            proposal,
            by,
            reason,
        },
        transition(
            proposal,
            from,
            StateTag::Terminated,
            row,
            ctx,
            Some(decision),
        ),
    ])
}

fn decide_close_milestone(
    state: &State,
    proposal: ProposalId,
    milestone: MilestoneId,
    reason: TextRef,
    ctx: &Ctx,
) -> Result<Vec<Record>, Refusal> {
    let by = crate::policy::actor_account(ctx)?;
    let s = subject(state, proposal)?;
    crate::policy::require_holder(state, by, s.programme, &[Role::ProgrammeManager], ctx.now)?;
    if s.state != StateTag::InExecution {
        return Err(wrong_state());
    }
    let ours = contract_milestones(state, proposal)
        .is_some_and(|ms| ms.iter().any(|(m, _, _)| *m == milestone));
    if !ours {
        return Err(unknown());
    }
    if state.money.milestone_closed(proposal, milestone) {
        return Err(wrong_state());
    }
    Ok(vec![Record::MilestoneClosed {
        proposal,
        milestone,
        by,
        reason,
    }])
}

fn decide_deliverable(state: &State, cmd: &Command) -> Result<Vec<Record>, Refusal> {
    let Command::RecordDeliverable {
        deliverable,
        grant,
        milestone,
        public_location,
        release,
        licence,
        snapshot,
        accepted,
    } = cmd
    else {
        return Err(wrong_state());
    };
    let s = subject(state, *grant)?;
    if !matches!(s.state, StateTag::Granted | StateTag::InExecution) {
        return Err(wrong_state());
    }
    if state.money.deliverables.contains_key(deliverable)
        || state.used_ids.contains(UsedId::Deliverable(*deliverable))
    {
        return Err(reused());
    }
    let ours = contract_milestones(state, *grant)
        .is_some_and(|ms| ms.iter().any(|(m, _, _)| m == milestone));
    if !ours {
        return Err(unknown());
    }
    Ok(vec![Record::DeliverableRecorded(DeliverableRecorded {
        deliverable: *deliverable,
        grant: *grant,
        milestone: *milestone,
        public_location: *public_location,
        release: *release,
        licence: licence.clone(),
        snapshot: *snapshot,
        accepted: *accepted,
    })])
}

// ---------------------------------------------------------------------------
// Engine entry points of this lane, called by `crate::engine`.
// ---------------------------------------------------------------------------

/// The vault questions of the grant, negotiation and execution commands.
pub(crate) fn queries(state: &State, cmd: &Command, ctx: &Ctx) -> Result<Vec<Query>, Refusal> {
    match cmd {
        Command::DetermineAmount { .. } => {
            let plan = check_determine(state, cmd, ctx)?;
            Ok(vec![plan.conflict, plan.cap])
        }
        Command::AcceptGrant { .. }
        | Command::ApproveGrant { .. }
        | Command::ContractFact { .. } => {
            let plan = check_fact(state, cmd, ctx)?;
            Ok(plan
                .clearance
                .as_ref()
                .map(ClearancePlan::queries)
                .unwrap_or_default())
        }
        Command::DeclineNegotiation { .. } => Ok(check_decline(state, cmd, ctx)?.queries()),
        _ => {
            decide_plain(state, cmd, ctx)?;
            Ok(Vec::new())
        }
    }
}

/// The records of the commands of this lane that ask the vault nothing.
fn decide_plain(state: &State, cmd: &Command, ctx: &Ctx) -> Result<Vec<Record>, Refusal> {
    match cmd {
        Command::StartExecution { proposal } => decide_start(state, *proposal, ctx),
        Command::Complete { proposal } => decide_complete(state, *proposal, ctx),
        Command::Terminate {
            decision,
            proposal,
            reason,
        } => decide_terminate(state, *decision, *proposal, *reason, ctx),
        Command::CloseMilestone {
            proposal,
            milestone,
            reason,
        } => decide_close_milestone(state, *proposal, *milestone, *reason, ctx),
        Command::RecordDeliverable { .. } => decide_deliverable(state, cmd),
        _ => Err(wrong_state()),
    }
}

/// The records of the grant, negotiation and execution commands.
pub(crate) fn decide(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
    answers: &Answers,
) -> Result<Vec<Record>, Refusal> {
    match cmd {
        Command::DetermineAmount { .. } => decide_determine(state, cmd, ctx, answers),
        Command::AcceptGrant { .. }
        | Command::ApproveGrant { .. }
        | Command::ContractFact { .. } => decide_fact(state, cmd, ctx, answers),
        Command::DeclineNegotiation { .. } => decide_decline(state, cmd, ctx, answers),
        _ => decide_plain(state, cmd, ctx),
    }
}

/// The negotiation entry of `proposal` for a fold, created on first use.
/// The proposal must exist.
fn negotiation_mut(state: &mut State, proposal: ProposalId) -> Result<&mut Negotiation, FoldError> {
    crate::proposal::draft::draft(state, proposal).ok_or(FoldError::UnknownEntity)?;
    Ok(state
        .money
        .negotiations
        .entry(proposal)
        .or_insert_with(Negotiation::new))
}

/// Marks the decision `d` as taken, failing on a reused one.
fn take_decision(state: &mut State, d: DecisionId) -> Result<(), FoldError> {
    if state.used_ids.insert(UsedId::Decision(d)) {
        Ok(())
    } else {
        Err(FoldError::DuplicateId)
    }
}

/// Folds a grant, negotiation and execution record. The fold checks
/// structure only and re-runs no guard.
pub(crate) fn apply(
    state: &mut State,
    seq: fstp_ledger::Seq,
    at: Timestamp,
    record: &Record,
) -> Result<(), FoldError> {
    let _ = (seq, at);
    match record {
        Record::AmountDetermined {
            decision,
            proposal,
            plan_total,
            deductions,
            granted,
            agreed,
            ..
        } => {
            let c = granted.amount().currency();
            let amounts: Vec<Amount> = deductions.iter().map(|d| d.amount.amount()).collect();
            let deducted = fstp_money::checked_sum(c, amounts)
                .and_then(NonNegAmount::new)
                .map_err(|_| FoldError::Inconsistent)?;
            negotiation_mut(state, *proposal)?;
            take_decision(state, *decision)?;
            let n = negotiation_mut(state, *proposal)?;
            n.determined = Some(Determination {
                decision: *decision,
                plan_total: *plan_total,
                deducted,
                granted: *granted,
                agreed: *agreed,
            });
            Ok(())
        }
        Record::CapReserved {
            proposal, amount, ..
        } => {
            let n = negotiation_mut(state, *proposal)?;
            if n.reserved.is_some() {
                return Err(FoldError::Inconsistent);
            }
            n.reserved = Some(*amount);
            Ok(())
        }
        Record::CapReleased { proposal, .. } => {
            let n = negotiation_mut(state, *proposal)?;
            if n.reserved.take().is_none() {
                return Err(FoldError::Inconsistent);
            }
            Ok(())
        }
        Record::GrantAccepted {
            decision, proposal, ..
        } => {
            negotiation_mut(state, *proposal)?;
            take_decision(state, *decision)?;
            negotiation_mut(state, *proposal)?.accepted = Some(*decision);
            Ok(())
        }
        Record::GrantApproved {
            decision,
            proposal,
            by,
        } => {
            negotiation_mut(state, *proposal)?;
            take_decision(state, *decision)?;
            let n = negotiation_mut(state, *proposal)?;
            n.approved = Some(*decision);
            n.approver = Some(*by);
            Ok(())
        }
        Record::ContractFactRecorded {
            proposal,
            contract,
            event: ContractEvent::Effective,
        } => {
            let n = negotiation_mut(state, *proposal)?;
            if n.contract.is_none() {
                n.contract = Some(*contract);
            }
            Ok(())
        }
        Record::GrantDecided(g) => {
            if state.money.grants.contains_key(&g.proposal) {
                return Err(FoldError::Inconsistent);
            }
            negotiation_mut(state, g.proposal)?.reserved = None;
            state.money.grants.insert(
                g.proposal,
                Grant {
                    granted: g.granted,
                    plan: g.agreed_plan,
                    closed: BTreeSet::new(),
                },
            );
            Ok(())
        }
        Record::NegotiationDeclined { proposal, .. } => {
            crate::proposal::draft::draft(state, *proposal).ok_or(FoldError::UnknownEntity)?;
            Ok(())
        }
        Record::TerminationRecorded {
            decision, proposal, ..
        } => {
            crate::proposal::draft::draft(state, *proposal).ok_or(FoldError::UnknownEntity)?;
            take_decision(state, *decision)
        }
        Record::DeliverableRecorded(d) => {
            crate::proposal::draft::draft(state, d.grant).ok_or(FoldError::UnknownEntity)?;
            if state.money.deliverables.contains_key(&d.deliverable)
                || !state.used_ids.insert(UsedId::Deliverable(d.deliverable))
            {
                return Err(FoldError::DuplicateId);
            }
            state.money.deliverables.insert(
                d.deliverable,
                Deliverable {
                    grant: d.grant,
                    milestone: d.milestone,
                    licence: d.licence.clone(),
                    accepted: d.accepted,
                },
            );
            Ok(())
        }
        Record::MilestoneClosed {
            proposal,
            milestone,
            ..
        } => {
            let g = state
                .money
                .grants
                .get_mut(proposal)
                .ok_or(FoldError::UnknownEntity)?;
            if !g.closed.insert(*milestone) {
                return Err(FoldError::Inconsistent);
            }
            Ok(())
        }
        _ => Err(FoldError::Inconsistent),
    }
}

/// Sets the effective contract version of the grant `proposal` to `plan`,
/// with `total` as its amended total, for the fold of an amendment.
pub(crate) fn amend(
    state: &mut State,
    proposal: ProposalId,
    plan: PlanVersionId,
    total: NonNegAmount,
) -> Result<(), FoldError> {
    let g = state
        .money
        .grants
        .get_mut(&proposal)
        .ok_or(FoldError::UnknownEntity)?;
    g.plan = plan;
    g.granted = total;
    Ok(())
}

/// The System commands of this lane that are enabled at `now` (design
/// section 3.6): `StartExecution` and `Complete`.
pub(crate) fn due(state: &State, now: Timestamp) -> Vec<Command> {
    let mut out = Vec::new();
    for proposal in state.money.grants.keys().copied() {
        match crate::proposal::intake::proposal_state(state, proposal) {
            Some(StateTag::Granted)
                if earliest_start(state, proposal).is_some_and(|t| t <= now) =>
            {
                out.push(Command::StartExecution { proposal });
            }
            Some(StateTag::InExecution) if completable(state, proposal) => {
                out.push(Command::Complete { proposal });
            }
            _ => {}
        }
    }
    out
}

/// The vault questions this lane needs for its contribution to the batch of
/// a command that another lane owns. The release of a reservation asks none.
pub(crate) fn contribute_queries(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
) -> Result<Vec<Query>, Refusal> {
    let _ = (state, cmd, ctx);
    Ok(Vec::new())
}

/// The records this lane adds to the batch of a command that another lane
/// owns. A batch that takes a proposal from NEGOTIATION to a terminal
/// state, such as a withdrawal, releases its open reservation (row 15,
/// design 2.11).
pub(crate) fn contribute(
    state: &State,
    cmd: &Command,
    ctx: &Ctx,
    answers: &Answers,
    batch: &[Record],
) -> Result<Vec<Record>, Refusal> {
    let _ = (cmd, ctx, answers);
    let mut out = Vec::new();
    for r in batch {
        let Record::Transitioned(t) = r else {
            continue;
        };
        if t.from != StateTag::Negotiation || !t.to.is_terminal() {
            continue;
        }
        let released = batch
            .iter()
            .any(|x| matches!(x, Record::CapReleased { proposal, .. } if *proposal == t.proposal));
        if let (Some(amount), false) = (state.money.reserved(t.proposal), released) {
            out.push(Record::CapReleased {
                proposal: t.proposal,
                amount,
            });
        }
    }
    Ok(out)
}

/// The policy whose P-77 governs a binding action of this lane through MCP
/// (R-MC-05, `crate::engine::PolicyScope`): the frozen policy of the
/// proposal's creation call.
pub(crate) fn governing_policy(state: &State, cmd: &Command) -> Result<PolicyScope, Refusal> {
    match cmd {
        Command::DetermineAmount { proposal, .. }
        | Command::AcceptGrant { proposal, .. }
        | Command::ApproveGrant { proposal, .. }
        | Command::ContractFact { proposal, .. }
        | Command::DeclineNegotiation { proposal }
        | Command::StartExecution { proposal }
        | Command::Complete { proposal }
        | Command::Terminate { proposal, .. }
        | Command::CloseMilestone { proposal, .. }
        | Command::RecordDeliverable {
            grant: proposal, ..
        } => call_scope(state, *proposal),
        _ => Err(wrong_state()),
    }
}
