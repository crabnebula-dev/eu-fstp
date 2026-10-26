//! The money models for fstp-mc: M-MONEY, the M-RACE reservation part, the I-15 repeat model and the after-negotiation lifecycle, with their properties and faults (design sections 6.2 and 6.3).
//!
//! Owned by lane L-MONEY (docs/handoff/m2-design.md section 10).
//!
//! - [`MoneyMc`] is one model over a [`MoneyWorld`] built from genesis by
//!   production commands. [`McConfig`] picks the setup, a prelude of
//!   steps after it, the proposals and the action families.
//! - [`m_money`] is M-MONEY: identities {a, b} and {c}, three proposals in
//!   NEGOTIATION, P-04 = [2.00, 4.00], P-05 = 6.00, deductions of 0.00 or
//!   1.00 and one P-05 edit. [`race`] is the reservation part of M-RACE:
//!   two negotiations of one identity whose amounts together exceed P-05,
//!   and the vault verification that merges an unverified lead into that
//!   identity after both reserved.
//!   [`repeat`] is the I-15 model: a granted Sybil in execution with its
//!   payment and deliverable record, and a second negotiation of the same
//!   identity. [`after`] runs one proposal from NEGOTIATION through every
//!   later row.
//! - The property builders read only the reference views, the ghost flags
//!   and the vault facts, never production structures.
//! - The faults inject records a broken engine would emit through the
//!   public structural `apply` (design 6.1 "Teeth"). Payloads with private
//!   fields are built through the record codec.

use std::collections::BTreeSet;

use fstp_domain::command::Actor;
use fstp_domain::decision::NegotiationFailure;
use fstp_domain::id::{DeliverableId, LineId, PolicyVersionId, ProposalId, RequestId};
use fstp_domain::proposal::PlanOrigin;
use fstp_domain::record::{Record, RulesVersion};
use fstp_domain::rules::{Row, StateTag};
use fstp_mc::{Model, Property};

use crate::r#gen::money::{
    FINREL, LA, LB, MoneyDraft, MoneySetup, MoneyWorld, PA, PB, PC, REL, accept_grant, accept_line,
    amount_decision, approve_grant, approve_payment, complete, confirm_paid, contract_effective,
    contract_of, decline_negotiation, determine, edit_p05, money_plan, record_deliverable,
    release_payment, request_payment, start_execution, terminate,
};
use crate::r#gen::review::{R1, plan_of, withdraw};
use crate::r#gen::roster::{Backend, STAFF_PM, Step};
use crate::reference::money::{
    Ext, MoneyVerdict, Recipient, check_i13, check_i14, check_i15, check_i64, forge_grant,
    recipient, transition,
};
use crate::reference::payment::RequestState;

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

/// Which of the three grant facts completes the set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Fact {
    /// The lead's acceptance.
    Accept,
    /// The programme manager's approval.
    Approve,
    /// The contract port's EFFECTIVE fact.
    Contract,
}

/// One action of a money model.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum McAction {
    /// R1 determines the amount with a deduction of these cents, 0 for none.
    /// A deduction first records the lead's negotiated plan that carries it.
    Determine(ProposalId, i64),
    /// The two other facts, then this one, which completes the set.
    Grant(ProposalId, Fact),
    /// One grant fact alone.
    One(ProposalId, Fact),
    /// The programme manager records NEGOTIATION to DECLINED.
    Decline(ProposalId),
    /// The lead withdraws.
    Withdraw(ProposalId),
    /// The programme manager sets P-05 to these cents.
    SetP05(i64),
    /// The System starts execution.
    Start(ProposalId),
    /// The programme manager terminates the grant.
    Terminate(ProposalId),
    /// The lead requests the full amount of the first milestone.
    Request(ProposalId),
    /// R1 accepts the open line in full.
    AcceptLine(ProposalId),
    /// Approval by a finance approver, release by a third account and confirmation.
    Pay(ProposalId),
    /// The M5 checks record a deliverable on the first milestone: under a
    /// P-26 licence or not, accepted or not.
    Deliverable(ProposalId, bool, bool),
    /// The programme manager closes every milestone.
    CloseMilestones(ProposalId),
    /// The System completes the grant.
    Complete(ProposalId),
    /// The vault withdraws the guardian consent, and the reaction runs in the same step.
    WithdrawConsent(ProposalId),
    /// The vault verifies the lead, and the reaction runs in the same step
    /// (Identity discovery).
    Verify(ProposalId),
}

/// The action families a model offers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Families {
    /// Amount determination with deductions.
    pub determine: bool,
    /// The composite grant: two facts, then the completing one.
    pub grant: bool,
    /// The three grant facts one by one.
    pub facts: bool,
    /// Decline and withdrawal.
    pub exits: bool,
    /// One P-05 edit to these cents, 0 for none.
    pub p05: i64,
    /// Execution: start, termination, milestone closure and completion.
    pub execution: bool,
    /// Payments and deliverables on the grants in execution.
    pub payments: bool,
    /// Withdrawal of a guardian consent in NEGOTIATION.
    pub consent: bool,
    /// Verification of an unverified lead in NEGOTIATION.
    pub verify: bool,
}

/// One model instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McConfig {
    /// The setup from genesis.
    pub setup: MoneySetup,
    /// Steps after the setup, each accepted by production and the references.
    pub prelude: Vec<McAction>,
    /// The proposals the actions name.
    pub proposals: Vec<ProposalId>,
    /// The deductions offered, cents.
    pub deductions: Vec<i64>,
    /// The action families.
    pub families: Families,
}

/// One model state.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct McState {
    /// Production, the vault and the reference views.
    pub world: MoneyWorld,
    /// Whether the P-05 edit was made.
    pub edited: bool,
    /// Ghost: a determination of a Sybil was refused under I-14 by both sides.
    pub cap_blocked: bool,
    /// Ghost: the fact that completes the three grant facts of a proposal
    /// with a verified lead was refused by both sides, so GRANTED was
    /// disabled. The fact can be sent again later.
    pub grant_blocked: bool,
    /// Deliverables recorded.
    pub deliverables: u8,
    /// Set when production and the references disagree.
    pub divergence: Option<String>,
}

/// A money model.
pub struct MoneyMc {
    /// The instance.
    pub config: McConfig,
    /// The start state.
    pub start: McState,
}

fn lead_of(w: &MoneyWorld, p: ProposalId) -> Option<fstp_domain::id::AccountId> {
    w.money.proposals.get(&p).map(|x| x.lead)
}

/// The request id of the `n`-th request of `p`.
pub fn request_of(p: ProposalId, n: usize) -> RequestId {
    RequestId::from_raw(
        30_000u128
            .saturating_add(p.raw().saturating_mul(100))
            .saturating_add(u128::try_from(n).unwrap_or(0)),
    )
}

fn line_of(r: RequestId) -> LineId {
    LineId::from_raw(r.raw().saturating_add(100_000))
}

fn fact_step(w: &MoneyWorld, p: ProposalId, f: Fact) -> Option<Step> {
    Some(match f {
        Fact::Accept => accept_grant(lead_of(w, p)?, p),
        Fact::Approve => approve_grant(STAFF_PM, p),
        Fact::Contract => contract_effective(p),
    })
}

/// The steps of `action` in `w`, or `None` where it does not apply.
fn steps(w: &MoneyWorld, versions: usize, action: &McAction) -> Option<Vec<Step>> {
    let money = &w.money;
    Some(match action {
        McAction::Determine(p, cut) if *cut > 0 => {
            // A deduction needs a negotiated plan whose total is the
            // effective plan total minus the deduction (design 2.11).
            let n = determinations(w, *p).saturating_add(1);
            let total = money.plans.get(&plan_of(*p))?.total();
            let plan = negotiated_of(*p, n);
            vec![
                money_plan(
                    lead_of(w, *p)?,
                    *p,
                    plan,
                    PlanOrigin::Negotiated,
                    money.live_plan(*p),
                    &[(
                        negotiated_milestone(*p, n),
                        total.checked_sub(*cut)?,
                        crate::r#gen::roster::T0,
                    )],
                )
                .ok()?,
                determine(R1, *p, amount_decision(*p, n), plan, &[*cut]).ok()?,
            ]
        }
        McAction::Determine(p, _) => {
            let n = determinations(w, *p).saturating_add(1);
            vec![determine(R1, *p, amount_decision(*p, n), plan_of(*p), &[]).ok()?]
        }
        McAction::Grant(p, last) => {
            // The facts already recorded are not sent again, so a refused
            // completing fact can be retried alone.
            let q = money.proposals.get(p)?;
            let held = |f: Fact| match f {
                Fact::Accept => q.accepted.is_some(),
                Fact::Approve => q.approved.is_some(),
                Fact::Contract => q.contract.is_some(),
            };
            if held(*last) {
                return None;
            }
            let mut out: Vec<Step> = [Fact::Accept, Fact::Approve, Fact::Contract]
                .into_iter()
                .filter(|f| f != last && !held(*f))
                .filter_map(|f| fact_step(w, *p, f))
                .collect();
            out.push(fact_step(w, *p, *last)?);
            out
        }
        McAction::One(p, f) => vec![fact_step(w, *p, *f)?],
        McAction::Decline(p) => vec![decline_negotiation(Actor::Account(STAFF_PM), *p)],
        McAction::Withdraw(p) => vec![withdraw(lead_of(w, *p)?, *p)],
        McAction::SetP05(c) => {
            let head = w.head.as_deref()?;
            let id =
                PolicyVersionId::from_raw(800u128.saturating_add(u128::try_from(versions).ok()?));
            vec![edit_p05(head, id, *c).ok()?]
        }
        McAction::Start(p) => vec![start_execution(*p)],
        McAction::Terminate(p) => vec![terminate(STAFF_PM, *p)],
        McAction::Request(p) => {
            let n = money.pay.requests_of(*p).count();
            let plan = money.contract_plan(*p)?;
            let (m, ms) = plan.milestones.iter().next()?;
            let r = request_of(*p, n);
            vec![request_payment(lead_of(w, *p)?, r, *p, &[(line_of(r), *m, ms.amount)]).ok()?]
        }
        McAction::AcceptLine(p) => {
            let (id, r) = money
                .pay
                .requests
                .iter()
                .find(|(_, r)| r.grant == *p && r.state == RequestState::Submitted)?;
            let (line, l) = r.lines.iter().find(|(_, l)| l.decided.is_none())?;
            vec![accept_line(R1, *id, *line, l.requested, false).ok()?]
        }
        McAction::Pay(p) => {
            let (id, _) = money
                .pay
                .requests
                .iter()
                .find(|(_, r)| r.grant == *p && r.state == RequestState::Accepted)?;
            vec![
                approve_payment(FINREL, *id),
                release_payment(REL, *id),
                confirm_paid(*id),
            ]
        }
        McAction::Deliverable(p, good, accepted) => {
            let plan = money.contract_plan(*p)?;
            let m = *plan.milestones.keys().next()?;
            let d = DeliverableId::from_raw(
                40_000u128
                    .saturating_add(p.raw().saturating_mul(10))
                    .saturating_add(u128::try_from(money.deliverables.len()).ok()?),
            );
            let licence = if *good { "MIT" } else { "GPL-3.0-only" };
            vec![record_deliverable(*p, d, m, licence, *accepted)]
        }
        McAction::Complete(p) => vec![complete(*p)],
        McAction::CloseMilestones(_) | McAction::WithdrawConsent(_) | McAction::Verify(_) => {
            return None;
        }
    })
}

fn diverged(s: &McState, why: String) -> McState {
    let mut next = s.clone();
    next.divergence = Some(why);
    next
}

/// Runs `action` on `s`. `None` when the first step is refused by both sides.
pub fn run_action(s: &McState, action: &McAction) -> Option<McState> {
    if s.divergence.is_some() {
        return None;
    }
    if let McAction::CloseMilestones(p) = action {
        return close_all(s, *p);
    }
    if let McAction::WithdrawConsent(p) = action {
        let mut next = s.clone();
        return match next.world.vault(|t| t.withdraw_consent(*p)) {
            Ok(_) => Some(next),
            Err(e) => Some(diverged(s, format!("{action:?}: {e}"))),
        };
    }
    if let McAction::Verify(p) = action {
        let lead = lead_of(&s.world, *p)?;
        let mut next = s.clone();
        return match next.world.vault(|t| t.verify(lead)) {
            Ok(_) => Some(next),
            Err(e) => Some(diverged(s, format!("{action:?}: {e}"))),
        };
    }
    let versions = s.world.money.policies.len();
    let steps = steps(&s.world, versions, action)?;
    let mut w = s.world.clone();
    let mut next = s.clone();
    let last = steps.len().saturating_sub(1);
    for (i, st) in steps.iter().enumerate() {
        let verdict = w.verdict(st);
        match w.step(st) {
            Ok(Some((nw, _))) => w = nw,
            Ok(None) if i == last && completing(&w, action) => {
                // Row NEGOTIATION to GRANTED disabled: the completing fact
                // was refused by both sides, and the facts before it stay.
                if s.grant_blocked {
                    if i == 0 {
                        return None;
                    }
                    break;
                }
                next.world = w;
                next.grant_blocked = true;
                return Some(next);
            }
            // A deduction and its negotiated plan stand or fall together.
            Ok(None) if matches!(action, McAction::Determine(_, cut) if *cut > 0) => return None,
            Ok(None) if i == 0 => {
                let sybil = matches!(action, McAction::Determine(p, _) if [PA, PB].contains(p));
                let cap = matches!(&verdict, MoneyVerdict::Refuse(why) if why.starts_with("I-14"));
                if sybil && cap && !s.cap_blocked {
                    next.cap_blocked = true;
                    return Some(next);
                }
                return None;
            }
            Ok(None) => break,
            Err(e) => return Some(diverged(s, format!("{action:?}: {e}"))),
        }
    }
    next.world = w;
    match action {
        McAction::SetP05(_) => next.edited = true,
        McAction::Deliverable(..) => next.deliverables = next.deliverables.saturating_add(1),
        _ => {}
    }
    Some(next)
}

/// Whether the last step of `action` in `w` is the fact that completes
/// the three grant facts of a proposal with a verified lead in NEGOTIATION.
fn completing(w: &MoneyWorld, action: &McAction) -> bool {
    let (McAction::Grant(p, f) | McAction::One(p, f)) = action else {
        return false;
    };
    let Some(q) = w.money.proposals.get(p) else {
        return false;
    };
    let others = [Fact::Accept, Fact::Approve, Fact::Contract]
        .into_iter()
        .filter(|x| x != f)
        .all(|x| match x {
            Fact::Accept => q.accepted.is_some(),
            Fact::Approve => q.approved.is_some(),
            Fact::Contract => q.contract.is_some(),
        });
    others
        && q.state == StateTag::Negotiation
        && q.reserved.is_some()
        && w.truth().is_verified(q.lead)
}

fn close_all(s: &McState, p: ProposalId) -> Option<McState> {
    let plan = s.world.money.contract_plan(p)?;
    let ms: Vec<_> = plan.milestones.keys().copied().collect();
    let mut w = s.world.clone();
    let mut any = false;
    for m in ms {
        let x = Ext::CloseMilestone {
            proposal: p,
            milestone: m,
        };
        match w.ext(Actor::Account(STAFF_PM), x) {
            Ok(Some((nw, _))) => {
                w = nw;
                any = true;
            }
            Ok(None) => {}
            Err(e) => return Some(diverged(s, format!("CloseMilestones({p:?}): {e}"))),
        }
    }
    if !any {
        return None;
    }
    let mut next = s.clone();
    next.world = w;
    Some(next)
}

impl MoneyMc {
    /// The model of `config` over `backend`, with its start built from genesis.
    pub fn new(config: McConfig, backend: Backend) -> Result<MoneyMc, String> {
        let world = config.setup.world(backend)?;
        let mut start = McState {
            world,
            edited: false,
            cap_blocked: false,
            grant_blocked: false,
            deliverables: 0,
            divergence: None,
        };
        for a in &config.prelude {
            start = match run_action(&start, a) {
                Some(s) if s.divergence.is_none() => s,
                Some(s) => {
                    return Err(format!(
                        "prelude {a:?}: {}",
                        s.divergence.unwrap_or_default()
                    ));
                }
                None => return Err(format!("prelude {a:?} was refused")),
            };
        }
        start.cap_blocked = false;
        start.grant_blocked = false;
        Ok(MoneyMc { config, start })
    }
}

impl Model for MoneyMc {
    type State = McState;
    type Action = McAction;

    fn init(&self) -> Vec<McState> {
        vec![self.start.clone()]
    }

    fn actions(&self, s: &McState, actions: &mut Vec<McAction>) {
        if s.divergence.is_some() {
            return;
        }
        let f = self.config.families;
        for p in &self.config.proposals {
            let Some(q) = s.world.money.proposals.get(p) else {
                continue;
            };
            match q.state {
                StateTag::Negotiation => {
                    let locked = q.accepted.is_some() || q.approved.is_some();
                    if f.determine && !locked && determinations(&s.world, *p) < 2 {
                        let total = s
                            .world
                            .money
                            .plans
                            .get(&plan_of(*p))
                            .map_or(0, |x| x.total());
                        let current = q.determined.as_ref().map(|d| d.granted);
                        for d in &self.config.deductions {
                            if current != Some(total.saturating_sub(*d)) {
                                actions.push(McAction::Determine(*p, *d));
                            }
                        }
                    }
                    if q.reserved.is_some() {
                        if f.grant {
                            for last in [Fact::Accept, Fact::Approve, Fact::Contract] {
                                actions.push(McAction::Grant(*p, last));
                            }
                        }
                        if f.facts {
                            for one in [Fact::Accept, Fact::Approve, Fact::Contract] {
                                actions.push(McAction::One(*p, one));
                            }
                        }
                    }
                    if f.exits {
                        actions.push(McAction::Decline(*p));
                        actions.push(McAction::Withdraw(*p));
                    }
                    if f.consent && q.minor && s.world.truth().has_consent(*p) {
                        actions.push(McAction::WithdrawConsent(*p));
                    }
                    if f.verify && !s.world.truth().is_verified(q.lead) {
                        actions.push(McAction::Verify(*p));
                    }
                }
                StateTag::Granted if f.execution => {
                    actions.push(McAction::Start(*p));
                    actions.push(McAction::Terminate(*p));
                }
                StateTag::InExecution => {
                    if f.execution {
                        actions.push(McAction::Terminate(*p));
                        actions.push(McAction::CloseMilestones(*p));
                        actions.push(McAction::Complete(*p));
                    }
                    if f.payments {
                        if s.world.money.pay.requests_of(*p).count() == 0 {
                            actions.push(McAction::Request(*p));
                        }
                        actions.push(McAction::AcceptLine(*p));
                        actions.push(McAction::Pay(*p));
                        if s.deliverables == 0 {
                            for good in [true, false] {
                                for acc in [true, false] {
                                    actions.push(McAction::Deliverable(*p, good, acc));
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        if f.p05 > 0 && !s.edited {
            actions.push(McAction::SetP05(f.p05));
        }
    }

    fn step(&self, s: &McState, action: &McAction) -> Option<McState> {
        run_action(s, action)
    }

    fn is_terminal(&self, s: &McState) -> bool {
        s.divergence.is_some()
            || self.config.proposals.iter().all(|p| {
                s.world
                    .money
                    .proposals
                    .get(p)
                    .is_none_or(|q| q.state != StateTag::Negotiation)
            })
    }
}

// ---------------------------------------------------------------------------
// Instances
// ---------------------------------------------------------------------------

/// M-MONEY (design 6.3): identities {a, b} and {c}, three proposals in
/// NEGOTIATION from genesis with plans of 4.00, 2.00 and 1.00, P-04 =
/// [2.00, 4.00], P-05 = 6.00, deductions of 0.00 or 1.00, and one P-05
/// edit down to 4.00. The agreed plan's total must equal the granted
/// amount (design 2.11), so a deduction comes with a negotiated plan that
/// carries it: the lead records the plan of the effective total minus the
/// deduction, and R1 determines the amount on it (R-NG-03). The action is
/// atomic: when the determination is refused, the plan is not kept.
/// Step W5 integration restored this branch, which lane L-MONEY had to
/// leave out while negotiated plans were refused.
pub fn m_money() -> McConfig {
    McConfig {
        setup: MoneySetup::sybil([400, 200, 100]),
        prelude: Vec::new(),
        proposals: vec![PA, PB, PC],
        deductions: vec![0, 100],
        families: Families {
            determine: true,
            grant: true,
            facts: false,
            exits: true,
            p05: 400,
            execution: false,
            payments: false,
            consent: false,
            verify: false,
        },
    }
}

/// The reservation part of M-RACE: leads a and b of one identity, plans of
/// 4.00 each, P-04 = [3.00, 4.00], P-05 = 6.00, the three grant facts one
/// by one, the decline and the withdrawal, so two negotiations
/// interleave. Lead b starts unverified, so the vault groups b alone, and
/// the vault change of M-RACE verifies b at any point (Identity
/// discovery). Two reservations opened before it then hold 8.00.
pub fn race() -> McConfig {
    let mut setup = MoneySetup::sybil([400, 400, 100]);
    setup.drafts.truncate(2);
    setup.p04 = (300, 400);
    setup.unverified = vec![LB];
    McConfig {
        setup,
        prelude: Vec::new(),
        proposals: vec![PA, PB],
        deductions: vec![0],
        families: Families {
            determine: true,
            grant: false,
            facts: true,
            exits: true,
            p05: 0,
            execution: false,
            payments: false,
            consent: false,
            verify: true,
        },
    }
}

/// The I-15 model: lead a granted 4.00 and in execution, lead b of the same
/// identity in NEGOTIATION, P-05 = 10.00 so the cap never decides. Lead a
/// requests and gets the first milestone accepted, and the M5 checks record
/// at most one deliverable, under a P-26 licence or not, accepted or not.
pub fn repeat() -> McConfig {
    let mut setup = MoneySetup::sybil([400, 400, 100]);
    setup.drafts.truncate(2);
    setup.p05 = 1_000;
    setup.staff = vec![
        (FINREL, fstp_domain::roles::Role::FinanceApprover),
        (REL, fstp_domain::roles::Role::PaymentReleaser),
    ];
    McConfig {
        setup,
        prelude: vec![
            McAction::Determine(PA, 0),
            McAction::Grant(PA, Fact::Contract),
            McAction::Start(PA),
        ],
        proposals: vec![PA, PB],
        deductions: vec![0],
        families: Families {
            determine: true,
            grant: true,
            facts: false,
            exits: true,
            p05: 0,
            execution: false,
            payments: true,
            consent: false,
            verify: false,
        },
    }
}

/// The after-negotiation lifecycle: lead c alone, a minor with a verified
/// guardian consent, with a plan of two milestones of 2.00 each. The vault
/// may withdraw the consent in NEGOTIATION (I-18, R-NG-02, NOTE 9). The
/// run goes through GRANTED, IN_EXECUTION, a paid milestone, milestone
/// closure and COMPLETED, TERMINATED from GRANTED and from IN_EXECUTION,
/// DECLINED and WITHDRAWN.
pub fn after() -> McConfig {
    let mut setup = MoneySetup::sybil([400, 400, 400]);
    setup.drafts = vec![MoneyDraft {
        lead: crate::r#gen::money::LC,
        proposal: PC,
        minor: true,
        milestones: vec![
            (
                crate::r#gen::money::milestone_n(PC, 0),
                200,
                crate::r#gen::roster::T0,
            ),
            (
                crate::r#gen::money::milestone_n(PC, 1),
                200,
                crate::r#gen::roster::T0,
            ),
        ],
        negotiate: true,
    }];
    setup.consents = vec![PC];
    setup.staff = vec![
        (FINREL, fstp_domain::roles::Role::FinanceApprover),
        (REL, fstp_domain::roles::Role::PaymentReleaser),
    ];
    McConfig {
        setup,
        prelude: Vec::new(),
        proposals: vec![PC],
        deductions: vec![0],
        families: Families {
            determine: true,
            grant: true,
            facts: false,
            exits: true,
            p05: 0,
            execution: true,
            payments: true,
            consent: true,
            verify: false,
        },
    }
}

/// The measured state count of M-MONEY, on the references.
pub const M_MONEY_STATES: usize = 864;
/// The measured state count of the M-RACE reservation part, on the references.
pub const M_RACE_RESERVATION_STATES: usize = 1_682;
/// The measured state count of the I-15 repeat model, on the references.
pub const M_MONEY_REPEAT_STATES: usize = 256;
/// The measured state count of the after-negotiation lifecycle, on the references.
pub const M_AFTER_STATES: usize = 203;

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

/// Production and the references agree on every step.
pub fn two_way<'a, M: Model<State = McState>>() -> Property<'a, M> {
    Property::always_with("two-way", |s: &McState| match &s.divergence {
        Some(d) => Err(d.clone()),
        None => Ok(()),
    })
}

/// I-13 on the money view.
pub fn i13(s: &McState) -> Result<(), String> {
    check_i13(&s.world.money)
}

/// I-14 on the money view and the vault facts.
pub fn i14(s: &McState) -> Result<(), String> {
    check_i14(&s.world.money, s.world.truth())
}

/// I-15 on the money view.
pub fn i15(s: &McState) -> Result<(), String> {
    check_i15(&s.world.money)
}

/// I-64 on the money view.
pub fn i64_closure(s: &McState) -> Result<(), String> {
    check_i64(&s.world.money)
}

/// The state of `p`.
pub fn state_of(s: &McState, p: ProposalId) -> Option<StateTag> {
    s.world.money.proposals.get(&p).map(|q| q.state)
}

/// Whether a proposal is granted exactly `cents`.
pub fn granted(s: &McState, cents: i64) -> bool {
    s.world
        .money
        .proposals
        .values()
        .any(|q| q.granted == Some(cents))
}

/// The granted sum of the identity of lead a.
pub fn sybil_granted(s: &McState) -> i64 {
    let who = recipient(s.world.truth(), LA);
    s.world
        .money
        .proposals
        .values()
        .filter(|q| recipient(s.world.truth(), q.lead) == who)
        .filter_map(|q| q.granted)
        .fold(0i64, i64::saturating_add)
}

/// Whether some proposal was declined for `reason`.
pub fn declined_for(s: &McState, reason: NegotiationFailure) -> bool {
    s.world
        .money
        .proposals
        .values()
        .any(|q| q.declined == Some(reason))
}

/// The P-05 edit transition (I-14): an accepted edit to `cents` left
/// every recipient's counted sum in `before` within the new cap.
pub fn p05_edit_transition(
    before: &McState,
    action: &McAction,
    after: &McState,
) -> Result<(), String> {
    let McAction::SetP05(cents) = action else {
        return Ok(());
    };
    if !after.edited {
        return Ok(());
    }
    let Some(programme) = before.world.money.heads.keys().next().copied() else {
        return Ok(());
    };
    let over: Vec<(Recipient, i64)> = before
        .world
        .money
        .recipients(before.world.truth(), programme)
        .into_iter()
        .filter(|(_, t)| t > cents)
        .collect();
    if over.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "I-14: P-05 was lowered to {cents} while recipients held {over:?}"
        ))
    }
}

/// The I-15 transition: entering GRANTED needs the identity's record
/// complete in `before`.
pub fn i15_transition(before: &McState, _a: &McAction, after: &McState) -> Result<(), String> {
    for (id, q) in &after.world.money.proposals {
        let was = before.world.money.proposals.get(id).map(|b| b.state);
        if q.state == StateTag::Granted && was == Some(StateTag::Negotiation) {
            let lead = q.lead;
            if !before
                .world
                .money
                .repeat_clear(before.world.truth(), lead, *id)
            {
                return Err(format!(
                    "I-15: {id:?} entered GRANTED while its identity's record was incomplete"
                ));
            }
        }
    }
    Ok(())
}

/// The M-MONEY properties (design 6.2).
pub fn m_money_properties<'a, M: Model<State = McState, Action = McAction> + 'a>()
-> Vec<Property<'a, M>> {
    vec![
        two_way(),
        Property::always_with("I-13", i13),
        Property::always_with("I-14", i14),
        Property::transition_with("I-14 P-05 edit", p05_edit_transition),
        Property::reachable(
            "I-13 witness: granted at the P-04 minimum",
            |s: &McState| granted(s, 200),
        ),
        Property::reachable(
            "I-13 witness: granted at the P-04 maximum",
            |s: &McState| granted(s, 400),
        ),
        Property::reachable(
            "I-14 witness: a recipient's granted sum is exactly P-05",
            |s: &McState| sybil_granted(s) == 600,
        ),
        Property::reachable(
            "I-14 witness: a Sybil pair blocked by the cap",
            |s: &McState| s.cap_blocked,
        ),
        Property::reachable(
            "R-NG-03 witness: granted on a recorded deduction with its negotiated plan",
            granted_after_deduction,
        ),
        Property::reachable("I-14 witness: P-05 lowered to 4.00", |s: &McState| {
            s.edited
                && s.world
                    .head
                    .as_ref()
                    .is_some_and(|h| h.live.p05.amount().minor() == 400)
        }),
        Property::reachable(
            "NOTE 9 witness: declined, no amount within P-04",
            |s: &McState| declined_for(s, NegotiationFailure::NoAmountWithinRange),
        ),
        Property::reachable(
            "NOTE 9 witness: declined, no amount within the cap",
            |s: &McState| declined_for(s, NegotiationFailure::NoAmountWithinCap),
        ),
        Property::reachable(
            "NOTE 9 witness: a declined for the cap while the P-04 minimum fits the headroom",
            declined_above_floor,
        ),
    ]
}

/// Whether lead a was declined for the cap although the P-04 minimum 2.00
/// fits its headroom. Only the plan total 4.00 breaks the cap: P-05 was
/// lowered to 4.00 and b holds 2.00 (NOTE 9, I-14). The witness rests on
/// the interim reading that only recorded negotiated plans count, open for
/// Daniel (`fstp_domain::grant` module doc).
pub fn declined_above_floor(s: &McState) -> bool {
    let m = &s.world.money;
    let Some(q) = m.proposals.get(&PA) else {
        return false;
    };
    let floor = m.governing(PA).map(|f| f.p04_min);
    let head = m
        .programme_of(PA)
        .zip(m.cap_of_call(q.call))
        .map(|(prog, cap)| {
            cap.saturating_sub(m.counted_for(s.world.truth(), prog, q.lead, Some(PA)))
        });
    q.declined == Some(NegotiationFailure::NoAmountWithinCap)
        && matches!((floor, head), (Some(f), Some(h)) if f <= h)
}

/// The M-RACE reservation properties.
pub fn race_properties<'a, M: Model<State = McState, Action = McAction> + 'a>()
-> Vec<Property<'a, M>> {
    vec![
        two_way(),
        Property::always_with("I-14", i14),
        Property::always_with("I-14 race: never both granted", |s: &McState| {
            if state_of(s, PA) == Some(StateTag::Granted)
                && state_of(s, PB) == Some(StateTag::Granted)
            {
                Err("I-14 race: both negotiations of one identity were granted 4.00 under P-05 6.00".to_owned())
            } else {
                Ok(())
            }
        }),
        Property::reachable("I-14 witness: a granted", |s: &McState| {
            state_of(s, PA) == Some(StateTag::Granted)
        }),
        Property::reachable("I-14 witness: b granted", |s: &McState| {
            state_of(s, PB) == Some(StateTag::Granted)
        }),
        Property::reachable(
            "I-14 witness: the second reservation blocked",
            |s: &McState| s.cap_blocked,
        ),
        Property::reachable(
            "I-14 witness: two reservations merged above P-05 by a verification",
            |s: &McState| {
                s.world.truth().is_verified(LB)
                    && s.world
                        .money
                        .proposals
                        .values()
                        .all(|q| q.reserved == Some(400))
            },
        ),
        Property::reachable(
            "I-14 witness: GRANTED disabled by the cap after the merge",
            |s: &McState| s.grant_blocked,
        ),
        Property::reachable(
            "NOTE 9 witness: declined after the merge, no amount within the cap",
            |s: &McState| declined_for(s, NegotiationFailure::NoAmountWithinCap),
        ),
        Property::reachable(
            "NOTE 9 witness: granted after a blocked completing fact is sent again",
            |s: &McState| {
                s.grant_blocked
                    && (state_of(s, PA) == Some(StateTag::Granted)
                        || state_of(s, PB) == Some(StateTag::Granted))
            },
        ),
    ]
}

/// The I-15 repeat properties.
pub fn repeat_properties<'a, M: Model<State = McState, Action = McAction> + 'a>()
-> Vec<Property<'a, M>> {
    vec![
        two_way(),
        Property::always_with("I-15", i15),
        Property::transition_with("I-15 transition", i15_transition),
        Property::always_with("I-13", i13),
        Property::reachable("I-15 witness: a repeat grant exists", |s: &McState| {
            state_of(s, PB) == Some(StateTag::Granted)
        }),
        Property::reachable(
            "I-15 witness: a repeat grant after a public deliverable",
            |s: &McState| {
                state_of(s, PB) == Some(StateTag::Granted)
                    && s.world.money.deliverables.values().any(|d| d.accepted)
            },
        ),
        Property::reachable(
            "I-15 witness: GRANTED disabled by a missing record",
            |s: &McState| s.grant_blocked && state_of(s, PB) == Some(StateTag::Negotiation),
        ),
        Property::reachable(
            "I-15 witness: granted once the missing record is completed",
            |s: &McState| s.grant_blocked && state_of(s, PB) == Some(StateTag::Granted),
        ),
        Property::reachable(
            "I-15 witness: declined for an incomplete record",
            |s: &McState| declined_for(s, NegotiationFailure::RepeatRecordIncomplete),
        ),
    ]
}

/// The after-negotiation reachability properties.
pub fn after_properties<'a, M: Model<State = McState, Action = McAction> + 'a>()
-> Vec<Property<'a, M>> {
    let mut out = vec![
        two_way(),
        Property::always_with("I-13", i13),
        Property::always_with("I-14", i14),
        Property::always_with("I-64", i64_closure),
    ];
    for (id, tag) in [
        ("reachable: GRANTED", StateTag::Granted),
        ("reachable: IN_EXECUTION", StateTag::InExecution),
        ("reachable: COMPLETED", StateTag::Completed),
        ("reachable: TERMINATED", StateTag::Terminated),
        ("reachable: DECLINED", StateTag::Declined),
        ("reachable: WITHDRAWN", StateTag::Withdrawn),
    ] {
        out.push(Property::reachable(id, move |s: &McState| {
            state_of(s, PC) == Some(tag)
        }));
    }
    out.push(Property::reachable(
        "I-18 witness: GRANTED disabled once the consent is withdrawn",
        |s: &McState| s.grant_blocked && state_of(s, PC) == Some(StateTag::Negotiation),
    ));
    out.push(Property::reachable(
        "NOTE 9 witness: declined for a missing guardian consent",
        |s: &McState| declined_for(s, NegotiationFailure::GuardianConsentMissing),
    ));
    out.push(Property::reachable(
        "reachable: COMPLETED after a paid milestone",
        |s: &McState| {
            state_of(s, PC) == Some(StateTag::Completed) && s.world.money.pay.paid_total(PC) > 0
        },
    ));
    out.push(Property::reachable(
        "reachable: TERMINATED from IN_EXECUTION",
        |s: &McState| {
            state_of(s, PC) == Some(StateTag::Terminated)
                && s.world
                    .life
                    .life
                    .proposals
                    .get(&PC)
                    .is_some_and(|p| p.rows.contains(&Row::InExecutionToTerminated))
        },
    ));
    out
}

// ---------------------------------------------------------------------------
// Faults
// ---------------------------------------------------------------------------

/// I-13 fault: an engine that grants b its plan total of 3.00 plus 2.00, above P-04.
pub fn fault_out_of_range(s: &McState) -> Option<McState> {
    forged_grant(s, PB, 500)
}

/// I-14 fault: an engine that grants b 3.00 while a holds 4.00 of the same identity.
pub fn fault_above_cap(s: &McState) -> Option<McState> {
    let a = s.world.money.counted(PA);
    if a < 400 {
        return None;
    }
    forged_grant(s, PB, 300)
}

/// I-15 fault: an engine that grants b while a's record is incomplete.
pub fn fault_repeat_without_records(s: &McState) -> Option<McState> {
    let truth = s.world.truth();
    if s.world.money.repeat_clear(truth, LB, PB) {
        return None;
    }
    forged_grant(s, PB, 400)
}

/// Injects `AmountDetermined`, `GrantDecided` and the NEGOTIATION to
/// GRANTED transition for `p` at `cents`, as a broken engine would.
fn forged_grant(s: &McState, p: ProposalId, cents: i64) -> Option<McState> {
    if s.divergence.is_some() || state_of(s, p) != Some(StateTag::Negotiation) {
        return None;
    }
    let plan = plan_of(p);
    let total = s.world.money.plans.get(&plan)?.total();
    let records = vec![
        Record::AmountDetermined {
            decision: amount_decision(p, 99),
            proposal: p,
            plan_total: crate::r#gen::money::nonneg(total).ok()?,
            deductions: Vec::new(),
            granted: crate::r#gen::money::nonneg(cents).ok()?,
            agreed: plan,
            by: R1,
            rules: RulesVersion::M2,
        },
        forge_grant(
            p,
            cents,
            plan,
            crate::r#gen::money::accept_decision(p),
            crate::r#gen::money::approve_decision(p),
            contract_of(p),
            s.world.truth().epoch().raw(),
            RulesVersion::M2,
        )
        .ok()?,
        transition(
            p,
            StateTag::Negotiation,
            StateTag::Granted,
            Row::NegotiationToGranted,
            Actor::Account(STAFF_PM),
        ),
    ];
    let w = s.world.inject(&records).ok()?;
    let mut next = s.clone();
    next.world = w;
    Some(next)
}

/// The proposals a fault may target, for the documentation of the teeth tests.
pub fn targets() -> BTreeSet<ProposalId> {
    [PA, PB, PC].into_iter().collect()
}

/// The negotiated plan of the `n`-th amount decision of `p`.
pub fn negotiated_of(p: ProposalId, n: u128) -> fstp_domain::id::PlanVersionId {
    fstp_domain::id::PlanVersionId::from_raw(
        4_800u128
            .saturating_add(p.raw().saturating_mul(10))
            .saturating_add(n),
    )
}

/// The milestone of [`negotiated_of`] for `p` and `n`.
pub fn negotiated_milestone(p: ProposalId, n: u128) -> fstp_domain::id::MilestoneId {
    crate::r#gen::money::milestone_n(p, 30u128.saturating_add(n))
}

/// Whether some proposal was granted on a recorded deduction (R-NG-03).
pub fn granted_after_deduction(s: &McState) -> bool {
    s.world
        .money
        .proposals
        .values()
        .any(|q| q.granted.is_some() && q.determined.as_ref().is_some_and(|d| d.deductions > 0))
}

/// The number of amount decisions recorded for `p`, read from the decision
/// ids of [`amount_decision`]. A model offers at most one redetermination.
pub fn determinations(w: &MoneyWorld, p: ProposalId) -> u128 {
    let base = amount_decision(p, 0).raw();
    let n = w
        .money
        .decisions
        .iter()
        .filter(|d| d.raw() > base && d.raw() < base.saturating_add(100))
        .count();
    u128::try_from(n).unwrap_or(u128::MAX)
}
