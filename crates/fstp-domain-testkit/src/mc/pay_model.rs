//! The payment model M-PAY and the I-05 machine (design sections 6.2 and 6.3).
//!
//! Owned by lane L-MONEY (docs/handoff/m2-design.md section 10).
//!
//! - [`pay_setup`] builds, from genesis by production commands, one grant
//!   of lead c in IN_EXECUTION with two milestones of 2.00 each. Its
//!   assigned reviewers are R1, R2 and R3. R1 is also a payment releaser,
//!   R2 also a finance approver, FINREL both, and REL a payment releaser
//!   only. After the grant, the vault records R3 as the mentor of lead c
//!   (I-54), and the reaction runs in the same step.
//! - [`PayMc`] is M-PAY: one request with two lines, each line accepted
//!   once by one of the reviewers, one approval, one release by any of the
//!   releasers, and the confirmation.
//! - [`PayMachine`] is the fstp-prop machine of
//!   `i05_sod04_releaser_is_never_acceptor_or_approver`: random requests,
//!   line decisions, approvals, releases, confirmations, withdrawals,
//!   requested changes and closures by accounts holding random
//!   combinations of the three roles. It favours complete chains, so a
//!   release by an account that accepted a line is drawn in most cases.
//! - [`fault_releaser_is_approver`] injects a release by the approver
//!   through the public structural `apply`, as a broken engine would.

use fstp_domain::command::Actor;
use fstp_domain::id::{AccountId, LineId, RequestId};
use fstp_domain::record::Record;
use fstp_domain::roles::Role;
use fstp_mc::{Model, Property};
use fstp_prop::{Gen, StateMachine};

use crate::r#gen::money::{
    FINREL, LC, MoneyDraft, MoneySetup, MoneyWorld, PC, REL, accept_line, approve_payment,
    confirm_paid, milestone_n, release_payment, request_changes, request_payment, withdraw_request,
};
use crate::r#gen::review::{R1, R2, R3, tag};
use crate::r#gen::roster::{Backend, Step, T0};
use crate::mc::money_model::{Fact, McAction, McState, run_action};
use crate::reference::money::Ext;
use crate::reference::payment::{RequestState, check_i05, check_sod12, forge_release};
use crate::vault::{GroundTruth, Relation};

/// The request of M-PAY.
pub const REQ: RequestId = RequestId::from_raw(31_001);
/// Its first line, on the first milestone.
pub const LINE1: LineId = LineId::from_raw(131_001);
/// Its second line, on the second milestone.
pub const LINE2: LineId = LineId::from_raw(131_002);

/// The payment setup: lead c with two milestones of 2.00, reviewers R1,
/// R2 and R3, and the payment roles.
pub fn pay_setup() -> MoneySetup {
    let mut s = MoneySetup::sybil([400, 400, 400]);
    s.drafts = vec![MoneyDraft {
        lead: LC,
        proposal: PC,
        minor: false,
        milestones: vec![(milestone_n(PC, 0), 200, T0), (milestone_n(PC, 1), 200, T0)],
        negotiate: true,
    }];
    s.reviewers = vec![R1, R2, R3];
    s.staff = vec![
        (R1, Role::PaymentReleaser),
        (R2, Role::FinanceApprover),
        (FINREL, Role::FinanceApprover),
        (FINREL, Role::PaymentReleaser),
        (REL, Role::PaymentReleaser),
    ];
    s
}

/// The grant of [`pay_setup`] in IN_EXECUTION, with R3 recorded as the
/// mentor of lead c (I-54, SoD-12).
pub fn pay_world(backend: Backend) -> Result<MoneyWorld, String> {
    let world = pay_setup().world(backend)?;
    let mut s = McState {
        world,
        edited: false,
        cap_blocked: false,
        grant_blocked: false,
        deliverables: 0,
        divergence: None,
    };
    for a in [
        McAction::Determine(PC, 0),
        McAction::Grant(PC, Fact::Contract),
        McAction::Start(PC),
    ] {
        s = match run_action(&s, &a) {
            Some(n) if n.divergence.is_none() => n,
            Some(n) => return Err(format!("{a:?}: {}", n.divergence.unwrap_or_default())),
            None => return Err(format!("{a:?} was refused")),
        };
    }
    let mut w = s.world;
    w.vault(|t: &mut GroundTruth| t.relate(tag(R3), tag(LC), Relation::Mentoring))?;
    Ok(w)
}

/// One action of M-PAY.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum PayAction {
    /// A line accepted in full by the reviewer.
    Accept(LineId, AccountId),
    /// The approval by the account.
    Approve(AccountId),
    /// The release by the account.
    Release(AccountId),
    /// The payment port's confirmation.
    Confirm,
}

/// One M-PAY state.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PayState {
    /// Production, the vault and the reference views.
    pub world: MoneyWorld,
    /// Ghost: the mentor's line acceptance was refused by both sides (SoD-12).
    pub mentor_refused: bool,
    /// Ghost: a release by an acceptor or by the approver was refused by both sides (I-05).
    pub releaser_refused: bool,
    /// Set when production and the references disagree.
    pub divergence: Option<String>,
}

impl PayState {
    /// The state of the request.
    pub fn request(&self) -> Option<RequestState> {
        self.world.money.pay.requests.get(&REQ).map(|r| r.state)
    }
}

/// M-PAY (design 6.3).
pub struct PayMc {
    /// The start state.
    pub start: PayState,
}

impl PayMc {
    /// M-PAY over `backend`, with the request of two lines submitted.
    pub fn new(backend: Backend) -> Result<PayMc, String> {
        let w = pay_world(backend)?;
        let req = request_payment(
            LC,
            REQ,
            PC,
            &[
                (LINE1, milestone_n(PC, 0), 200),
                (LINE2, milestone_n(PC, 1), 200),
            ],
        )?;
        let w = w.must(&req)?;
        Ok(PayMc {
            start: PayState {
                world: w,
                mentor_refused: false,
                releaser_refused: false,
                divergence: None,
            },
        })
    }
}

fn pay_step(action: &PayAction) -> Result<Step, String> {
    Ok(match action {
        PayAction::Accept(line, by) => accept_line(*by, REQ, *line, 200, false)?,
        PayAction::Approve(by) => approve_payment(*by, REQ),
        PayAction::Release(by) => release_payment(*by, REQ),
        PayAction::Confirm => confirm_paid(REQ),
    })
}

impl Model for PayMc {
    type State = PayState;
    type Action = PayAction;

    fn init(&self) -> Vec<PayState> {
        vec![self.start.clone()]
    }

    fn actions(&self, s: &PayState, actions: &mut Vec<PayAction>) {
        if s.divergence.is_some() {
            return;
        }
        for line in [LINE1, LINE2] {
            for by in [R1, R2, R3] {
                actions.push(PayAction::Accept(line, by));
            }
        }
        for by in [R2, FINREL] {
            actions.push(PayAction::Approve(by));
        }
        for by in [R1, R2, FINREL, REL] {
            actions.push(PayAction::Release(by));
        }
        actions.push(PayAction::Confirm);
    }

    fn step(&self, s: &PayState, action: &PayAction) -> Option<PayState> {
        if s.divergence.is_some() {
            return None;
        }
        let step = match pay_step(action) {
            Ok(st) => st,
            Err(e) => {
                let mut n = s.clone();
                n.divergence = Some(format!("harness: {e}"));
                return Some(n);
            }
        };
        match s.world.step(&step) {
            Ok(Some((w, _))) => {
                let mut n = s.clone();
                n.world = w;
                Some(n)
            }
            Ok(None) => {
                let mut n = s.clone();
                match action {
                    PayAction::Accept(_, by) if *by == R3 && !s.mentor_refused => {
                        n.mentor_refused = true;
                        Some(n)
                    }
                    PayAction::Release(by)
                        if !s.releaser_refused
                            && s.request() == Some(RequestState::PaymentApproved)
                            && s.world.money.pay.requests.get(&REQ).is_some_and(|r| {
                                r.acceptors().contains(by) || r.approver == Some(*by)
                            }) =>
                    {
                        n.releaser_refused = true;
                        Some(n)
                    }
                    _ => None,
                }
            }
            Err(e) => {
                let mut n = s.clone();
                n.divergence = Some(format!("{action:?}: {e}"));
                Some(n)
            }
        }
    }

    fn is_terminal(&self, s: &PayState) -> bool {
        s.divergence.is_some() || s.request() == Some(RequestState::Paid)
    }
}

/// The state count of M-PAY, measured on production in step W6. The
/// references store the same count.
pub const M_PAY_STATES: usize = 162;

/// I-05 and SoD-04 on the payment view.
pub fn i05(s: &PayState) -> Result<(), String> {
    check_i05(&s.world.money.pay, &s.world.money.breaches)
}

/// SoD-12 on the payment view.
pub fn sod12(s: &PayState) -> Result<(), String> {
    check_sod12(&s.world.money.breaches)
}

/// The M-PAY properties (design 6.2).
pub fn pay_properties<'a, M: Model<State = PayState, Action = PayAction> + 'a>()
-> Vec<Property<'a, M>> {
    vec![
        Property::always_with("two-way", |s: &PayState| match &s.divergence {
            Some(d) => Err(d.clone()),
            None => Ok(()),
        }),
        Property::always_with("I-05", i05),
        Property::always_with("SoD-12", sod12),
        Property::transition_with("SoD-04", |_b: &PayState, a: &PayAction, t: &PayState| {
            let PayAction::Release(by) = a else {
                return Ok(());
            };
            match t.world.money.pay.requests.get(&REQ) {
                Some(r) if r.releaser == Some(*by) && r.approver == Some(*by) => Err(format!(
                    "SoD-04: {by:?} approved and released the same payment"
                )),
                _ => Ok(()),
            }
        }),
        Property::reachable(
            "I-05 witness: a release by a third account",
            |s: &PayState| {
                matches!(
                    s.request(),
                    Some(RequestState::Released | RequestState::Paid)
                )
            },
        ),
        Property::reachable("I-05 witness: the payment is confirmed", |s: &PayState| {
            s.request() == Some(RequestState::Paid)
        }),
        Property::reachable(
            "I-05 witness: an acceptor or the approver may not release",
            |s: &PayState| s.releaser_refused,
        ),
        Property::reachable(
            "SoD-12 witness: the mentor's acceptance is refused",
            |s: &PayState| s.mentor_refused,
        ),
    ]
}

/// I-05 fault: an engine that releases the approved request with the
/// approver as releaser.
pub fn fault_releaser_is_approver(s: &PayState) -> Option<PayState> {
    if s.divergence.is_some() || s.request() != Some(RequestState::PaymentApproved) {
        return None;
    }
    let r = s.world.money.pay.requests.get(&REQ)?;
    let approver = r.approver?;
    let rec = forge_release(REQ, r.grant, &r.acceptors(), approver, approver).ok()?;
    let w = s.world.inject(&[rec]).ok()?;
    let mut n = s.clone();
    n.world = w;
    Some(n)
}

// ---------------------------------------------------------------------------
// The fstp-prop machine
// ---------------------------------------------------------------------------

/// One I-05 machine command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PayCmd {
    /// A request of one line per (milestone index, cents).
    Request(Vec<(u8, i64)>),
    /// A line decision on the `n`-th request's `k`-th line: full, or a lower amount with a reason.
    Accept(usize, usize, AccountId, bool),
    /// Requested changes on the `n`-th request.
    Changes(usize, AccountId),
    /// An approval of the `n`-th request.
    Approve(usize, AccountId),
    /// A release of the `n`-th request.
    Release(usize, AccountId),
    /// A confirmation of the `n`-th request.
    Confirm(usize),
    /// The lead withdraws the `n`-th request.
    Withdraw(usize),
    /// The programme manager closes the `n`-th request.
    Close(usize),
    /// A complete chain on a new request of one line of 1.00 on the
    /// milestone of this index: the line accepted in full by the first
    /// account, approved by the second and released by the third. It
    /// gives the acceptor half of I-05 its teeth, since R1 both reviews
    /// and releases.
    Chain(u8, AccountId, AccountId, AccountId),
}

/// The I-05 machine model.
#[derive(Clone, Debug)]
pub struct PayModel {
    /// The world.
    pub world: MoneyWorld,
    /// The requests made, in order.
    pub requests: Vec<RequestId>,
    /// Set when production and the references disagree.
    pub divergence: Option<String>,
}

/// The fstp-prop machine over payment chains (I-05, SoD-04, SoD-12).
#[derive(Debug)]
pub struct PayMachine {
    /// The start world, built once from genesis.
    pub start: Result<MoneyWorld, String>,
}

impl PayMachine {
    /// The machine over `backend`.
    pub fn new(backend: Backend) -> PayMachine {
        PayMachine {
            start: pay_world(backend),
        }
    }
}

const ACTORS: [AccountId; 6] = [R1, R2, R3, FINREL, REL, LC];

fn nth(m: &PayModel, n: usize) -> RequestId {
    m.requests
        .get(n.checked_rem(m.requests.len().max(1)).unwrap_or(0))
        .copied()
        .unwrap_or(RequestId::from_raw(0))
}

fn machine_step(m: &PayModel, cmd: &PayCmd) -> Result<Option<Step>, String> {
    let lines_of = |r: RequestId| -> Vec<(LineId, i64)> {
        m.world
            .money
            .pay
            .requests
            .get(&r)
            .map(|x| x.lines.iter().map(|(l, v)| (*l, v.requested)).collect())
            .unwrap_or_default()
    };
    Ok(Some(match cmd {
        PayCmd::Request(lines) => {
            let n = m.requests.len();
            let r = RequestId::from_raw(32_000u128.saturating_add(u128::try_from(n).unwrap_or(0)));
            let ls: Vec<(LineId, fstp_domain::id::MilestoneId, i64)> = lines
                .iter()
                .enumerate()
                .map(|(k, (mi, c))| {
                    (
                        LineId::from_raw(
                            132_000u128
                                .saturating_add(u128::try_from(n).unwrap_or(0).saturating_mul(10))
                                .saturating_add(u128::try_from(k).unwrap_or(0)),
                        ),
                        milestone_n(PC, u128::from(*mi)),
                        *c,
                    )
                })
                .collect();
            request_payment(LC, r, PC, &ls)?
        }
        PayCmd::Accept(n, k, by, full) => {
            if m.requests.is_empty() {
                return Ok(None);
            }
            let r = nth(m, *n);
            let ls = lines_of(r);
            let Some((line, req)) = ls.get(k.checked_rem(ls.len().max(1)).unwrap_or(0)).copied()
            else {
                return Ok(None);
            };
            if *full || req <= 50 {
                accept_line(*by, r, line, req, false)?
            } else {
                accept_line(*by, r, line, req.saturating_sub(50), true)?
            }
        }
        PayCmd::Changes(n, by) if !m.requests.is_empty() => request_changes(*by, nth(m, *n)),
        PayCmd::Approve(n, by) if !m.requests.is_empty() => approve_payment(*by, nth(m, *n)),
        PayCmd::Release(n, by) if !m.requests.is_empty() => release_payment(*by, nth(m, *n)),
        PayCmd::Confirm(n) if !m.requests.is_empty() => confirm_paid(nth(m, *n)),
        PayCmd::Withdraw(n) if !m.requests.is_empty() => withdraw_request(LC, nth(m, *n)),
        _ => return Ok(None),
    }))
}

impl StateMachine for PayMachine {
    type Model = PayModel;
    type Sut = ();
    type Command = PayCmd;
    type Output = ();

    fn init_model(&self) -> PayModel {
        match &self.start {
            Ok(w) => PayModel {
                world: w.clone(),
                requests: Vec::new(),
                divergence: None,
            },
            Err(e) => PayModel {
                world: MoneyWorld::new(Backend::Reference, GroundTruth::new()),
                requests: Vec::new(),
                divergence: Some(format!("the start from genesis failed: {e}")),
            },
        }
    }

    fn init_sut(&self) {}

    fn command(&self, g: &mut Gen, _m: &PayModel) -> PayCmd {
        let n = g.usize_in(0..=3);
        let by = *g.pick(&ACTORS);
        match g.weighted(&[3, 6, 1, 3, 4, 2, 1, 1, 6]) {
            0 => {
                let k = g.usize_in(1..=2);
                let lines = (0..k)
                    .map(|_| (*g.pick(&[0u8, 1]), *g.pick(&[100i64, 200])))
                    .collect();
                PayCmd::Request(lines)
            }
            1 => PayCmd::Accept(
                n,
                g.usize_in(0..=1),
                *g.pick(&[R1, R2, R3, FINREL]),
                g.bool(),
            ),
            2 => PayCmd::Changes(n, *g.pick(&[R1, R2])),
            3 => PayCmd::Approve(n, *g.pick(&[R1, R2, FINREL])),
            4 => PayCmd::Release(n, by),
            5 => PayCmd::Confirm(n),
            6 => PayCmd::Withdraw(n),
            7 => PayCmd::Close(n),
            _ => PayCmd::Chain(
                *g.pick(&[0u8, 1]),
                *g.pick(&[R1, R1, R2, FINREL]),
                *g.pick(&[R2, FINREL]),
                *g.pick(&[R1, R1, R2, FINREL, REL]),
            ),
        }
    }

    fn precondition(&self, m: &PayModel, _cmd: &PayCmd) -> bool {
        m.divergence.is_none()
    }

    fn run(&self, _sut: &mut (), _cmd: &PayCmd) {}

    fn next_state(&self, m: &mut PayModel, cmd: &PayCmd) {
        if let PayCmd::Chain(mi, acceptor, approver, releaser) = cmd {
            let before = m.requests.len();
            self.next_state(m, &PayCmd::Request(vec![(*mi, 100)]));
            if m.requests.len() == before {
                return;
            }
            let n = before;
            for c in [
                PayCmd::Accept(n, 0, *acceptor, true),
                PayCmd::Approve(n, *approver),
                PayCmd::Release(n, *releaser),
            ] {
                if m.divergence.is_some() {
                    return;
                }
                self.next_state(m, &c);
            }
            return;
        }
        if let PayCmd::Close(n) = cmd {
            if m.requests.is_empty() {
                return;
            }
            let x = Ext::ClosePaymentRequest {
                request: nth(m, *n),
            };
            match m
                .world
                .ext(Actor::Account(crate::r#gen::roster::STAFF_PM), x)
            {
                Ok(Some((w, _))) => m.world = w,
                Ok(None) => {}
                Err(e) => m.divergence = Some(e),
            }
            return;
        }
        let step = match machine_step(m, cmd) {
            Ok(Some(s)) => s,
            Ok(None) => return,
            Err(e) => {
                m.divergence = Some(format!("harness: {e}"));
                return;
            }
        };
        match m.world.step(&step) {
            Ok(Some((w, records))) => {
                m.world = w;
                for r in &records {
                    if let Record::PaymentRequested { request, .. } = r {
                        m.requests.push(*request);
                    }
                }
            }
            Ok(None) => {
                if let PayCmd::Request(_) = cmd {
                    // A refused request leaves its id unused; the next one reuses it.
                }
            }
            Err(e) => m.divergence = Some(e),
        }
    }

    fn invariant(&self, m: &PayModel, _sut: &()) -> Result<(), String> {
        if let Some(d) = &m.divergence {
            return Err(format!("two-way: {d}"));
        }
        check_i05(&m.world.money.pay, &m.world.money.breaches)?;
        check_sod12(&m.world.money.breaches)
    }

    fn max_commands(&self) -> usize {
        20
    }
}
