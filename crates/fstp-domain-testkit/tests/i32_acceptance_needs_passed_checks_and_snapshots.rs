//! I-32, R-PR-02, R-PR-03: a payment request is accepted only after the
//! automated checks pass and evidence snapshots are recorded (M5 design
//! sections 4.2 and 8, reading 4).
//!
//! The synthetic checks runner is off. The machine runs random requests,
//! check runs of either phase that pass or fail, line decisions, requested
//! changes and resubmissions over the world of `m5_pay`. A ghost reads the
//! checks from the records alone. After every step, every line decision
//! followed a passed submission run with its snapshot, and every request
//! that became ACCEPTED also had a passed acceptance run with its snapshot
//! before the decision that accepted it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod m5_pay;

use std::collections::BTreeMap;

use fstp_domain::id::{ContentDigest, LineId, RequestId};
use fstp_domain::payment::CheckPhase;
use fstp_domain::record::Record;
use fstp_domain_testkit::r#gen::money::{MoneyWorld, accept_line, record_checks, request_changes};
use fstp_domain_testkit::r#gen::review::{R1, R2};
use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::reference::payment::RequestState;
use fstp_domain_testkit::vault::GroundTruth;
use fstp_prop::{Config, Gen, StateMachine, check_machine_with};
use m5_pay::{ask, line_id, must, request_id, run, world};

/// The passed check runs of one request, from the records.
#[derive(Clone, Debug, Default)]
struct Checked {
    submission: Option<ContentDigest>,
    acceptance: Option<ContentDigest>,
}

#[derive(Clone, Debug)]
enum Cmd {
    /// A new request of one line of 50 cents on this milestone.
    Request(u8),
    /// A check run on the `n`-th request: phase and whether it fails.
    Checks(usize, CheckPhase, bool),
    /// A line decision on the `n`-th request, in full or at zero.
    Accept(usize, bool),
    /// Requested changes on the `n`-th request.
    Changes(usize),
    /// A resubmission that replaces the `n`-th request.
    Resubmit(usize),
}

#[derive(Clone, Debug)]
struct Model {
    world: MoneyWorld,
    requests: Vec<RequestId>,
    checked: BTreeMap<RequestId, Checked>,
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

fn state(m: &Model, r: RequestId) -> Option<RequestState> {
    m.world.money.pay.requests.get(&r).map(|x| x.state)
}

/// Folds `records` into the ghost and checks I-32 on each line decision.
fn observe(m: &mut Model, records: &[Record]) {
    for r in records {
        match r {
            Record::PaymentRequested { request, .. } => {
                m.requests.push(*request);
                m.checked.insert(*request, Checked::default());
            }
            Record::ChecksRecorded {
                request,
                phase,
                results,
                snapshot,
            } if results.iter().all(|c| c.failure.is_none()) => {
                let c = m.checked.entry(*request).or_default();
                match phase {
                    CheckPhase::Submission => c.submission = Some(*snapshot),
                    CheckPhase::Acceptance => c.acceptance = Some(*snapshot),
                }
            }
            Record::LineAccepted { request, .. } => {
                let c = m.checked.get(request).cloned().unwrap_or_default();
                if c.submission.is_none() {
                    m.breach = Some(format!(
                        "I-32: a line of {request:?} was decided without passed submission checks"
                    ));
                }
                if state(m, *request) == Some(RequestState::Accepted) && c.acceptance.is_none() {
                    m.breach = Some(format!(
                        "I-32: {request:?} was accepted without passed acceptance checks"
                    ));
                }
            }
            _ => {}
        }
    }
}

impl StateMachine for Machine {
    type Model = Model;
    type Sut = ();
    type Command = Cmd;
    type Output = ();

    fn init_model(&self) -> Model {
        let (world, breach) = match &self.start {
            Ok(w) => {
                let mut w = w.clone();
                w.auto_checks = false;
                (w, None)
            }
            Err(e) => (
                MoneyWorld::new(Backend::Production, GroundTruth::new()),
                Some(format!("the start from genesis failed: {e}")),
            ),
        };
        Model {
            world,
            requests: Vec::new(),
            checked: BTreeMap::new(),
            next: 0,
            breach,
        }
    }

    fn init_sut(&self) {}

    fn command(&self, g: &mut Gen, _m: &Model) -> Cmd {
        let n = g.usize_in(0..=3);
        match g.weighted(&[3, 6, 5, 1, 2]) {
            0 => Cmd::Request(*g.pick(&[0u8, 1])),
            1 => Cmd::Checks(
                n,
                *g.pick(&[CheckPhase::Submission, CheckPhase::Acceptance]),
                g.weighted(&[3, 1]) == 1,
            ),
            2 => Cmd::Accept(n, g.weighted(&[4, 1]) == 0),
            3 => Cmd::Changes(n),
            _ => Cmd::Resubmit(n),
        }
    }

    fn precondition(&self, m: &Model, _cmd: &Cmd) -> bool {
        m.breach.is_none()
    }

    fn run(&self, _sut: &mut (), _cmd: &Cmd) {}

    fn next_state(&self, m: &mut Model, cmd: &Cmd) {
        let n = m.next;
        let step = match cmd {
            Cmd::Request(milestone) => {
                m.next = m.next.saturating_add(1);
                ask(n, *milestone, 50, None, None)
            }
            Cmd::Resubmit(k) => {
                let Some(old) = nth(m, *k) else { return };
                m.next = m.next.saturating_add(1);
                ask(n, 0, 50, None, Some(old))
            }
            Cmd::Checks(k, phase, fail) => {
                let Some(r) = nth(m, *k) else { return };
                let lines: Vec<LineId> = m
                    .world
                    .money
                    .pay
                    .requests
                    .get(&r)
                    .map(|x| x.lines.keys().copied().collect())
                    .unwrap_or_default();
                Ok(record_checks(r, *phase, &lines, *fail))
            }
            Cmd::Accept(k, full) => {
                let Some(r) = nth(m, *k) else { return };
                let n = r.raw().saturating_sub(41_000);
                let cents = if *full { 50 } else { 0 };
                accept_line(R1, r, line_id(n), cents, !*full)
            }
            Cmd::Changes(k) => {
                let Some(r) = nth(m, *k) else { return };
                Ok(request_changes(R2, r))
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
            Ok(Some(records)) => observe(m, &records),
            Ok(None) => {}
            Err(e) => m.breach = Some(e),
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

/// I-32, R-PR-03: no line decision before passed submission checks with a
/// snapshot, and no acceptance before passed acceptance checks with a
/// snapshot.
#[test]
fn i32_no_acceptance_without_passed_checks_and_snapshots() {
    check_machine_with(
        "i32_no_acceptance_without_passed_checks_and_snapshots",
        Config::default().with_cases(64),
        &Machine {
            start: world(Backend::Production, false),
        },
    );
}

/// I-32: with passed submission checks only, the line decision that would
/// make the request ACCEPTED is refused, under I-32.
#[test]
fn i32_final_line_decision_needs_passed_acceptance_checks() {
    let mut w = world(Backend::Production, false).unwrap();
    w.auto_checks = false;
    must(&mut w, &ask(0, 0, 50, None, None).unwrap()).unwrap();
    let lines = [line_id(0)];
    must(
        &mut w,
        &record_checks(request_id(0), CheckPhase::Submission, &lines, false),
    )
    .unwrap();
    let accept = accept_line(R1, request_id(0), line_id(0), 50, false).unwrap();
    assert_eq!(
        run(&mut w, &accept).unwrap(),
        None,
        "I-32: accepted without acceptance checks"
    );
    must(
        &mut w,
        &record_checks(request_id(0), CheckPhase::Acceptance, &lines, false),
    )
    .unwrap();
    must(&mut w, &accept).unwrap();
    assert_eq!(
        w.money.pay.requests.get(&request_id(0)).map(|r| r.state),
        Some(RequestState::Accepted)
    );
}

/// R-PR-02: a failed submission check returns the request in CHECKS_FAILED
/// with its reasons recorded, and line review stays closed.
#[test]
fn r_pr_02_failed_checks_return_the_request_with_reasons() {
    let mut w = world(Backend::Production, false).unwrap();
    w.auto_checks = false;
    must(&mut w, &ask(0, 0, 50, None, None).unwrap()).unwrap();
    let records = must(
        &mut w,
        &record_checks(request_id(0), CheckPhase::Submission, &[line_id(0)], true),
    )
    .unwrap();
    let reasons = records.iter().any(|r| {
        matches!(r, Record::ChecksRecorded { results, .. }
            if results.iter().all(|c| c.failure.is_some()))
    });
    assert!(
        reasons,
        "R-PR-02: the failure reasons are recorded: {records:?}"
    );
    assert_eq!(
        w.money.pay.requests.get(&request_id(0)).map(|r| r.state),
        Some(RequestState::ChecksFailed)
    );
    let accept = accept_line(R1, request_id(0), line_id(0), 50, false).unwrap();
    assert_eq!(run(&mut w, &accept).unwrap(), None);
}

/// I-58, M5 design reading 4: a resubmission withdraws the failed request
/// in the same batch, so its pending amount returns before the new lines
/// are checked against the milestone.
#[test]
fn i58_resubmission_returns_the_failed_request_first() {
    let mut w = world(Backend::Production, false).unwrap();
    w.auto_checks = false;
    must(&mut w, &ask(0, 0, 200, None, None).unwrap()).unwrap();
    must(
        &mut w,
        &record_checks(request_id(0), CheckPhase::Submission, &[line_id(0)], true),
    )
    .unwrap();
    assert_eq!(
        run(&mut w, &ask(1, 0, 200, None, None).unwrap()).unwrap(),
        None,
        "I-58: a second full claim while the first is pending"
    );
    let records = must(&mut w, &ask(2, 0, 200, None, Some(request_id(0))).unwrap()).unwrap();
    let withdrawn = records.iter().any(|r| {
        matches!(r, Record::PaymentRequestWithdrawn { request, .. } if *request == request_id(0))
    });
    assert!(
        withdrawn,
        "reading 4: the failed request is withdrawn: {records:?}"
    );
    assert_eq!(
        w.money.pay.requests.get(&request_id(2)).map(|r| r.state),
        Some(RequestState::Submitted)
    );
}
