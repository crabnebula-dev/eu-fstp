//! I-58, R-PR-07: the read view of a grant's milestones, which
//! `grant.overview` serves to the payment form (M5 reads follow-up).
//!
//! The machine runs random milestone and hardship requests, line
//! decisions, approvals, releases and withdrawals over the world of
//! `m5_pay`. After every step, for each milestone of grant c, the view
//! [`fstp_domain::payment::grant_milestones`] agrees with the payment
//! reference: paid plus pending is the reference's paid plus pending, and
//! paid, pending and available add up to the milestone amount. The view
//! never offers more than the I-58 check admits.
//!
//! The example tests check the edge both ways: a request of exactly the
//! available amount is accepted, and one cent more is refused.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod m5_pay;

use fstp_domain::id::{MilestoneId, RequestId};
use fstp_domain::payment::{MilestoneFunds, grant_milestones};
use fstp_domain::state::State;
use fstp_domain_testkit::r#gen::money::{
    FINREL, LC, MoneyWorld, PC, accept_line, approve_payment, withdraw_request,
};
use fstp_domain_testkit::r#gen::review::R1;
use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::vault::GroundTruth;
use fstp_prop::{Config, Gen, StateMachine, check_machine_with};
use m5_pay::{ask, line_id, milestone, must, release, request_id, run, world};

#[derive(Clone, Debug)]
enum Cmd {
    /// A request of one line: milestone, cents, hardship.
    Request(u8, i64, bool),
    /// The `n`-th request's line accepted in full.
    Accept(usize),
    /// FINREL approves the `n`-th request.
    Approve(usize),
    /// REL releases the `n`-th request.
    Release(usize),
    /// The lead withdraws the `n`-th request.
    Withdraw(usize),
}

#[derive(Clone, Debug)]
struct Model {
    world: MoneyWorld,
    requests: Vec<RequestId>,
    next: u128,
    breach: Option<String>,
}

struct Machine {
    start: Result<MoneyWorld, String>,
}

fn nth(m: &Model, n: usize) -> Option<RequestId> {
    m.requests
        .get(n.checked_rem(m.requests.len().max(1)).unwrap_or(0))
        .copied()
}

fn state(w: &MoneyWorld) -> &State {
    &w.life.rev.sod.state
}

/// The view's row of milestone `m` of grant c.
fn row(w: &MoneyWorld, m: MilestoneId) -> Result<MilestoneFunds, String> {
    let view = grant_milestones(state(w), PC).ok_or("grant c has no milestone view")?;
    view.milestones
        .iter()
        .find(|r| r.milestone == m)
        .copied()
        .ok_or_else(|| format!("milestone {m:?} is missing from the view"))
}

/// I-58, R-PR-07: the view agrees with the payment reference.
fn agrees(w: &MoneyWorld) -> Result<(), String> {
    for n in [0u8, 1] {
        let m = milestone(n);
        let r = row(w, m)?;
        let amount = r.amount.amount().minor();
        let paid = r.paid.amount().minor();
        let pending = r.pending.amount().minor();
        let available = r.available.amount().minor();
        let used = w.money.pay.used(PC, m);
        if paid.checked_add(pending) != Some(used) {
            return Err(format!(
                "I-58: milestone {n}: paid {paid} plus pending {pending} is not the reference's {used}"
            ));
        }
        if r.closed {
            if available != 0 {
                return Err(format!("milestone {n} is closed yet offers {available}"));
            }
        } else if paid
            .checked_add(pending)
            .and_then(|u| u.checked_add(available))
            != Some(amount)
        {
            return Err(format!(
                "R-PR-07: milestone {n}: paid {paid}, pending {pending} and available {available} do not add up to {amount}"
            ));
        }
        if amount != 200 {
            return Err(format!("milestone {n} has amount {amount}, not 200"));
        }
    }
    Ok(())
}

impl StateMachine for Machine {
    type Model = Model;
    type Sut = ();
    type Command = Cmd;
    type Output = ();

    fn init_model(&self) -> Model {
        let (world, breach) = match &self.start {
            Ok(w) => (w.clone(), None),
            Err(e) => (
                MoneyWorld::new(Backend::Production, GroundTruth::new()),
                Some(format!("the start from genesis failed: {e}")),
            ),
        };
        Model {
            world,
            requests: Vec::new(),
            next: 0,
            breach,
        }
    }

    fn init_sut(&self) {}

    fn command(&self, g: &mut Gen, _m: &Model) -> Cmd {
        let n = g.usize_in(0..=4);
        match g.weighted(&[4, 4, 3, 3, 1]) {
            0 => Cmd::Request(*g.pick(&[0u8, 1]), *g.pick(&[50i64, 100, 150]), g.bool()),
            1 => Cmd::Accept(n),
            2 => Cmd::Approve(n),
            3 => Cmd::Release(n),
            _ => Cmd::Withdraw(n),
        }
    }

    fn precondition(&self, m: &Model, _cmd: &Cmd) -> bool {
        m.breach.is_none()
    }

    fn run(&self, _sut: &mut (), _cmd: &Cmd) {}

    fn next_state(&self, m: &mut Model, cmd: &Cmd) {
        let step = match cmd {
            Cmd::Request(ms, cents, hardship) => {
                let n = m.next;
                m.next = m.next.saturating_add(1);
                ask(n, *ms, *cents, hardship.then_some(m5_pay::EVIDENCE), None)
            }
            Cmd::Accept(k) => {
                let Some(r) = nth(m, *k) else { return };
                let n = r.raw().saturating_sub(41_000);
                let cents = m
                    .world
                    .money
                    .pay
                    .requests
                    .get(&r)
                    .and_then(|x| x.lines.get(&line_id(n)))
                    .map_or(0, |l| l.requested);
                accept_line(R1, r, line_id(n), cents, false)
            }
            Cmd::Approve(k) => {
                let Some(r) = nth(m, *k) else { return };
                Ok(approve_payment(FINREL, r))
            }
            Cmd::Release(k) => {
                let Some(r) = nth(m, *k) else { return };
                Ok(release(r.raw().saturating_sub(41_000)))
            }
            Cmd::Withdraw(k) => {
                let Some(r) = nth(m, *k) else { return };
                Ok(withdraw_request(LC, r))
            }
        };
        let step = match step {
            Ok(s) => s,
            Err(e) => {
                m.breach = Some(format!("harness: {e}"));
                return;
            }
        };
        match run(&mut m.world, &step) {
            Ok(Some(_)) => {
                if let fstp_domain::command::Command::RequestPayment { request, .. } = &step.cmd {
                    m.requests.push(*request);
                }
            }
            Ok(None) => {}
            Err(e) => m.breach = Some(e),
        }
        if m.breach.is_none()
            && let Err(e) = agrees(&m.world)
        {
            m.breach = Some(e);
        }
    }

    fn invariant(&self, m: &Model, _sut: &()) -> Result<(), String> {
        match &m.breach {
            Some(b) => Err(b.clone()),
            None => Ok(()),
        }
    }

    fn max_commands(&self) -> usize {
        24
    }
}

/// I-58, R-PR-07: after any run of requests, decisions, releases and
/// withdrawals, the milestone view agrees with the payment reference.
#[test]
fn i58_r_pr_07_milestone_view_agrees_with_the_payment_reference() {
    check_machine_with(
        "i58_r_pr_07_milestone_view_agrees_with_the_payment_reference",
        Config::default().with_cases(48),
        &Machine {
            start: world(Backend::Production, false),
        },
    );
}

/// I-58, R-PR-07: the view names the plan of the effective contract, and
/// a fresh grant offers each milestone in full.
#[test]
fn r_pr_07_fresh_grant_offers_every_milestone_in_full() {
    let w = world(Backend::Production, false).unwrap();
    let view = grant_milestones(state(&w), PC).expect("a view");
    assert_eq!(
        Some(view.plan),
        state(&w).money().contract_plan(PC),
        "the view names the contract's plan"
    );
    for n in [0u8, 1] {
        let r = row(&w, milestone(n)).unwrap();
        assert_eq!(r.available.amount().minor(), 200);
        assert_eq!(r.paid.amount().minor(), 0);
        assert_eq!(r.pending.amount().minor(), 0);
        assert!(!r.closed);
    }
}

/// I-58: a request of exactly the available amount is accepted, and one
/// cent above it is refused, so the view never offers what the check
/// refuses.
#[test]
fn i58_available_is_the_exact_edge_of_the_check() {
    let mut w = world(Backend::Production, false).unwrap();
    must(&mut w, &ask(0, 0, 50, None, None).unwrap()).unwrap();
    let left = row(&w, milestone(0)).unwrap().available.amount().minor();
    assert_eq!(left, 150);
    let over = ask(1, 0, left.saturating_add(1), None, None).unwrap();
    assert!(
        run(&mut w, &over).unwrap().is_none(),
        "one cent above available is accepted"
    );
    must(&mut w, &ask(2, 0, left, None, None).unwrap()).unwrap();
    assert_eq!(row(&w, milestone(0)).unwrap().available.amount().minor(), 0);
    agrees(&w).unwrap();
}

/// I-58: a withdrawn request frees its amount again.
#[test]
fn i58_withdrawal_frees_the_amount() {
    let mut w = world(Backend::Production, false).unwrap();
    must(&mut w, &ask(0, 1, 100, None, None).unwrap()).unwrap();
    assert_eq!(
        row(&w, milestone(1)).unwrap().available.amount().minor(),
        100
    );
    must(&mut w, &withdraw_request(LC, request_id(0))).unwrap();
    assert_eq!(
        row(&w, milestone(1)).unwrap().available.amount().minor(),
        200
    );
    agrees(&w).unwrap();
}

/// The view of a proposal with no grant or determination is `None`.
#[test]
fn r_pr_07_unknown_grant_has_no_view() {
    let w = world(Backend::Production, false).unwrap();
    assert!(grant_milestones(state(&w), fstp_domain::id::ProposalId::from_raw(987_654)).is_none());
}
