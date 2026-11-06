//! I-31: total released payments under a contract, including hardship
//! contributions, never exceed the contract amount (M5 design sections 4.2
//! and 8, 12.1 Q4: hardship lines claim milestones).
//!
//! The machine runs random milestone and hardship requests, line decisions
//! in full or lower, approvals, releases and withdrawals over the world of
//! `m5_pay`, where grant c holds 4.00. After every step, the approved
//! amounts of the released lines stay within the granted amount. The
//! direct guard test forges a release of the whole contract amount into
//! the ledger, as a broken engine would, and checks that `ReleasePayment`
//! then refuses one more release under I-31.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod m5_pay;

use fstp_domain::command::Command;
use fstp_domain::id::{CommandId, RequestId};
use fstp_domain::payment::CheckPhase;
use fstp_domain::record::Record;
use fstp_domain::refusal::RuleRef;
use fstp_domain_testkit::r#gen::money::{
    FINREL, MoneyWorld, PC, REL, accept_line, nonneg, record_checks, record_file_of,
    withdraw_request,
};
use fstp_domain_testkit::r#gen::money::{LC, pos};
use fstp_domain_testkit::r#gen::review::R1;
use fstp_domain_testkit::r#gen::roster::{Backend, Flags, Step};
use fstp_domain_testkit::reference::payment::forge_release;
use fstp_domain_testkit::vault::GroundTruth;
use fstp_prop::{Config, Gen, StateMachine, check_machine_with};
use m5_pay::{
    EVIDENCE, kind, line_id, milestone, prepare, release, releases, request_id, run, world,
};

#[derive(Clone, Debug)]
enum Cmd {
    /// A new request prepared up to PAYMENT_APPROVED: milestone, cents and
    /// whether it is a hardship request.
    Prepare(u8, i64, bool),
    /// A new request whose line is approved lower, with a reason.
    Lower(u8, i64),
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

/// I-31 on the payment reference view: released total within the grant.
fn i31(w: &MoneyWorld) -> Result<(), String> {
    let granted = w
        .money
        .proposals
        .get(&PC)
        .and_then(|p| p.granted)
        .ok_or("no granted amount")?;
    let released = w.money.pay.paid_total(PC);
    if released > granted {
        return Err(format!(
            "I-31: released {released} above the contract amount {granted}"
        ));
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
        let cents = *g.pick(&[50i64, 100, 150, 200]);
        match g.weighted(&[5, 2, 6, 1]) {
            0 => Cmd::Prepare(*g.pick(&[0u8, 1]), cents, g.bool()),
            1 => Cmd::Lower(*g.pick(&[0u8, 1]), cents),
            2 => Cmd::Release(g.usize_in(0..=4)),
            _ => Cmd::Withdraw(g.usize_in(0..=4)),
        }
    }

    fn precondition(&self, m: &Model, _cmd: &Cmd) -> bool {
        m.breach.is_none()
    }

    fn run(&self, _sut: &mut (), _cmd: &Cmd) {}

    fn next_state(&self, m: &mut Model, cmd: &Cmd) {
        let n = m.next;
        let outcome = match cmd {
            Cmd::Prepare(ms, cents, hardship) => {
                m.next = m.next.saturating_add(1);
                prepare(&mut m.world, n, *ms, *cents, hardship.then_some(EVIDENCE)).map(|ok| {
                    if ok {
                        m.requests.push(request_id(n));
                    }
                })
            }
            Cmd::Lower(ms, cents) => {
                m.next = m.next.saturating_add(1);
                let mut w = m.world.clone();
                let r = (|| -> Result<bool, String> {
                    if run(&mut w, &m5_pay::ask(n, *ms, *cents, None, None)?)?.is_none() {
                        return Ok(false);
                    }
                    let lower = accept_line(R1, request_id(n), line_id(n), cents / 2, true)?;
                    if run(&mut w, &lower)?.is_none() {
                        return Ok(false);
                    }
                    let approve =
                        fstp_domain_testkit::r#gen::money::approve_payment(FINREL, request_id(n));
                    Ok(run(&mut w, &approve)?.is_some())
                })();
                r.map(|ok| {
                    m.world = w;
                    if ok {
                        m.requests.push(request_id(n));
                    }
                })
            }
            Cmd::Release(k) => match nth(m, *k) {
                Some(r) => run(&mut m.world, &release(r.raw().saturating_sub(41_000))).map(|_| ()),
                None => Ok(()),
            },
            Cmd::Withdraw(k) => match nth(m, *k) {
                Some(r) => run(&mut m.world, &withdraw_request(LC, r)).map(|_| ()),
                None => Ok(()),
            },
        };
        if let Err(e) = outcome {
            m.breach = Some(e);
        } else if let Err(e) = i31(&m.world) {
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

/// I-31, R-PR-04: over milestone and hardship requests, lower approvals,
/// releases and withdrawals, the released total stays within the contract
/// amount.
#[test]
fn i31_released_total_with_hardship_stays_within_contract_amount() {
    check_machine_with(
        "i31_released_total_with_hardship_stays_within_contract_amount",
        Config::default().with_cases(64),
        &Machine {
            start: world(Backend::Production, false),
        },
    );
}

/// I-31: after a forged release of the whole contract amount, the guard at
/// `ReleasePayment` refuses one more release, and names I-31. The forged
/// records stand for a broken engine; the fold checks structure only.
#[test]
fn i31_release_guard_refuses_beyond_the_contract_amount() {
    let mut w = world(Backend::Production, false).unwrap();
    assert!(prepare(&mut w, 0, 0, 200, None).unwrap());
    let forged = RequestId::from_raw(49_999);
    let line = fstp_domain::id::LineId::from_raw(149_999);
    let lines = [line];
    let mut records = vec![Record::PaymentRequested {
        request: forged,
        grant: PC,
        kind: kind(None),
        lines: vec![fstp_domain::payment::PaymentLine {
            line,
            milestone: milestone(1),
            amount: pos(400).unwrap(),
            evidence: fstp_domain_testkit::r#gen::money::line_evidence(line),
        }],
    }];
    for phase in [CheckPhase::Submission, CheckPhase::Acceptance] {
        let Command::RecordChecks {
            request,
            phase,
            results,
            snapshot,
        } = record_checks(forged, phase, &lines, false).cmd
        else {
            panic!("record_checks builds RecordChecks");
        };
        records.push(Record::ChecksRecorded {
            request,
            phase,
            results,
            snapshot,
        });
    }
    records.push(Record::LineAccepted {
        request: forged,
        line,
        by: R1,
        approved: nonneg(400).unwrap(),
        reason: None,
    });
    records.push(Record::PaymentApproved {
        request: forged,
        by: FINREL,
    });
    records.push(
        forge_release(
            forged,
            PC,
            &[R1].into_iter().collect(),
            FINREL,
            REL,
            record_file_of(forged),
        )
        .unwrap(),
    );
    let mut w = w.inject(&records).unwrap();

    let cmd = Command::ReleasePayment {
        request: request_id(0),
        record_file: record_file_of(request_id(0)),
    };
    let ctx = Step::by(REL, Flags::NONE, cmd.clone())
        .ctx(w.now(), CommandId::from_bytes(*b"test:i31:guard01"));
    let state = &w.life.rev.sod.state;
    let asked = fstp_domain::queries(state, &cmd, &ctx);
    assert_eq!(
        asked.as_ref().map_err(|r| r.rule),
        Err(RuleRef::I31),
        "I-31: the guard refuses before the vault is asked: {asked:?}"
    );
    let answers = fstp_domain::oracle::Answers::new();
    let refused = fstp_domain::decide(state, &cmd, &ctx, &answers);
    assert_eq!(
        refused.as_ref().map_err(|r| r.rule),
        Err(RuleRef::I31),
        "I-31: {refused:?}"
    );
    assert_eq!(
        run(&mut w, &release(0)).unwrap().map(|r| releases(&r)),
        None,
        "I-31: both sides refuse the release"
    );
}
