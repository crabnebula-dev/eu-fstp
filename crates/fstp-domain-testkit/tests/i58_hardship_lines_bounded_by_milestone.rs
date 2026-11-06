//! I-58, R-PR-04: hardship lines claim milestones of partly delivered
//! work, so paid plus pending never exceeds a milestone amount over
//! milestone and hardship requests together (M5 design 12.1, Q4).
//!
//! The machine runs random milestone and hardship requests, line
//! decisions, approvals, releases and withdrawals over the world of
//! `m5_pay`, with two milestones of 2.00. After every step, each
//! milestone's paid plus pending, as the payment reference folds it from
//! the records, is within 2.00. The example test checks that approving a
//! hardship request asks the vault for verified evidence.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod m5_pay;

use fstp_domain::id::RequestId;
use fstp_domain_testkit::r#gen::money::{
    FINREL, LC, MoneyWorld, PC, accept_line, approve_payment, withdraw_request,
};
use fstp_domain_testkit::r#gen::review::R1;
use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::reference::payment::RequestState;
use fstp_domain_testkit::vault::GroundTruth;
use fstp_prop::{Config, Gen, StateMachine, check_machine_with};
use m5_pay::{
    EVIDENCE, UNVERIFIED, ask, line_id, milestone, must, release, request_id, run, world,
};

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

/// I-58 on the payment reference view, for both milestones of grant c.
fn i58(w: &MoneyWorld) -> Result<(), String> {
    for n in [0u8, 1] {
        let used = w.money.pay.used(PC, milestone(n));
        if used > 200 {
            return Err(format!(
                "I-58: milestone {n} holds {used} paid plus pending above 200"
            ));
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
                ask(n, *ms, *cents, hardship.then_some(EVIDENCE), None)
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
            && let Err(e) = i58(&m.world)
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

/// I-58, R-PR-04: hardship and milestone lines together keep paid plus
/// pending within each milestone amount.
#[test]
fn i58_hardship_lines_are_bounded_by_the_milestone_amount() {
    check_machine_with(
        "i58_hardship_lines_are_bounded_by_the_milestone_amount",
        Config::default().with_cases(64),
        &Machine {
            start: world(Backend::Production, false),
        },
    );
}

/// R-PR-04: a hardship request is approved only when the vault answers
/// that its evidence is verified for the grant.
#[test]
fn r_pr_04_hardship_approval_needs_verified_vault_evidence() {
    let mut w = world(Backend::Production, false).unwrap();
    must(&mut w, &ask(0, 0, 50, Some(UNVERIFIED), None).unwrap()).unwrap();
    must(
        &mut w,
        &accept_line(R1, request_id(0), line_id(0), 50, false).unwrap(),
    )
    .unwrap();
    let approve = approve_payment(FINREL, request_id(0));
    assert_eq!(
        run(&mut w, &approve).unwrap(),
        None,
        "R-PR-04: approved on unverified hardship evidence"
    );
    w.vault(|t| t.verify_hardship(PC, UNVERIFIED)).unwrap();
    must(&mut w, &approve).unwrap();
    assert_eq!(
        w.money.pay.requests.get(&request_id(0)).map(|r| r.state),
        Some(RequestState::PaymentApproved)
    );
}
