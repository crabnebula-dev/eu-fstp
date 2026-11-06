//! I-33, R-PR-05: after a bank detail change, no payment is released until
//! re-verification completes and P-36 elapses (M5 design sections 4.2 and 8,
//! 12.1: every write starts the hold, the first one included).
//!
//! The machine runs random clock steps, bank detail writes, verifications,
//! disputes and their resolution, prepared payment requests and releases
//! over the world of `m5_pay`. A ghost keeps the bank events apart from the
//! vault twin. After every step, each release happened when the latest
//! write had a later verification, at least P-36 (7 days) had passed since
//! that write, and no dispute was open. One machine starts with verified
//! details from before the hold, the other with none, so the first write
//! is covered.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod m5_pay;

use fstp_domain::command::Command;
use fstp_domain::id::{CommandId, RequestId};
use fstp_domain::oracle::Answers;
use fstp_domain::refusal::RuleRef;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::money::{BANK_SET, MoneyWorld, PC, REL, record_file_of};
use fstp_domain_testkit::r#gen::roster::{Backend, Flags, Step};
use fstp_domain_testkit::vault::GroundTruth;
use fstp_prop::{Config, Gen, StateMachine, check_machine_with};
use m5_pay::{HOLD, later, must, prepare, release, releases, request_id, run, world};

/// The bank events as the test sees them.
#[derive(Clone, Debug, Default)]
struct Ghost {
    /// The latest write.
    written: Option<Timestamp>,
    /// Whether a verification followed it.
    verified: bool,
    /// Whether a dispute is open.
    disputed: bool,
}

impl Ghost {
    /// I-33 at `t`: a verified latest write, P-36 since it, no dispute.
    fn releasable(&self, t: Timestamp) -> bool {
        self.verified && !self.disputed && self.written.is_some_and(|w| later(w, HOLD) <= t)
    }
}

#[derive(Clone, Debug)]
enum Cmd {
    /// Moves the clock on by this many hours.
    Advance(i64),
    /// The lead writes new bank details.
    Write,
    /// The finance approver verifies the latest write.
    Verify,
    /// The lead opens (`true`) or resolves a dispute.
    Dispute(bool),
    /// A new request on this milestone, accepted and approved.
    Prepare(u8),
    /// REL releases the `n`-th prepared request.
    Release(usize),
}

#[derive(Clone, Debug)]
struct Model {
    world: MoneyWorld,
    ghost: Ghost,
    prepared: Vec<RequestId>,
    next: u128,
    breach: Option<String>,
}

struct Machine {
    start: Result<MoneyWorld, String>,
    ghost: Ghost,
}

impl Machine {
    fn new(unbanked: bool) -> Machine {
        Machine {
            start: world(Backend::Production, unbanked),
            ghost: if unbanked {
                Ghost::default()
            } else {
                Ghost {
                    written: Some(BANK_SET),
                    verified: true,
                    disputed: false,
                }
            },
        }
    }
}

fn bank(m: &mut Model, change: impl FnOnce(&mut GroundTruth)) {
    if let Err(e) = m.world.vault(change) {
        m.breach = Some(format!("harness: {e}"));
    }
}

impl StateMachine for Machine {
    type Model = Model;
    type Sut = ();
    type Command = Cmd;
    type Output = ();

    fn init_model(&self) -> Model {
        match &self.start {
            Ok(w) => Model {
                world: w.clone(),
                ghost: self.ghost.clone(),
                prepared: Vec::new(),
                next: 0,
                breach: None,
            },
            Err(e) => Model {
                world: MoneyWorld::new(Backend::Production, GroundTruth::new()),
                ghost: Ghost::default(),
                prepared: Vec::new(),
                next: 0,
                breach: Some(format!("the start from genesis failed: {e}")),
            },
        }
    }

    fn init_sut(&self) {}

    fn command(&self, g: &mut Gen, _m: &Model) -> Cmd {
        match g.weighted(&[4, 2, 2, 1, 3, 5]) {
            0 => Cmd::Advance(*g.pick(&[1i64, 24, 100, 167, 168, 169])),
            1 => Cmd::Write,
            2 => Cmd::Verify,
            3 => Cmd::Dispute(g.bool()),
            4 => Cmd::Prepare(*g.pick(&[0u8, 1])),
            _ => Cmd::Release(g.usize_in(0..=3)),
        }
    }

    fn precondition(&self, m: &Model, _cmd: &Cmd) -> bool {
        m.breach.is_none()
    }

    fn run(&self, _sut: &mut (), _cmd: &Cmd) {}

    fn next_state(&self, m: &mut Model, cmd: &Cmd) {
        let now = m.world.now();
        match cmd {
            Cmd::Advance(hours) => m
                .world
                .set_now(later(now, hours.saturating_mul(3_600_000_000))),
            Cmd::Write => {
                bank(m, |t| t.write_bank(PC, now));
                m.ghost.written = Some(now);
                m.ghost.verified = false;
            }
            Cmd::Verify => {
                bank(m, |t| t.verify_bank(PC));
                m.ghost.verified = m.ghost.written.is_some();
            }
            Cmd::Dispute(open) => {
                bank(m, |t| t.dispute_bank(PC, *open));
                m.ghost.disputed = *open && m.ghost.written.is_some();
            }
            Cmd::Prepare(milestone) => {
                let n = m.next;
                m.next = m.next.saturating_add(1);
                match prepare(&mut m.world, n, *milestone, 10, None) {
                    Ok(true) => m.prepared.push(request_id(n)),
                    Ok(false) => {}
                    Err(e) => m.breach = Some(e),
                }
            }
            Cmd::Release(k) => {
                let Some(r) = m
                    .prepared
                    .get(k.checked_rem(m.prepared.len().max(1)).unwrap_or(0))
                    .copied()
                else {
                    return;
                };
                let n = r.raw().saturating_sub(41_000);
                match run(&mut m.world, &release(n)) {
                    Ok(Some(records)) if releases(&records).contains(&r) => {
                        if !m.ghost.releasable(now) {
                            m.breach = Some(format!(
                                "I-33: {r:?} was released at {now:?} under {:?}",
                                m.ghost
                            ));
                        }
                    }
                    Ok(_) => {}
                    Err(e) => m.breach = Some(e),
                }
            }
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

/// I-33, R-PR-05: with verified details from before the hold, no release
/// follows a later write before its verification and P-36, or happens
/// while a dispute is open.
#[test]
fn i33_no_release_inside_the_hold_after_a_bank_detail_change() {
    check_machine_with(
        "i33_no_release_inside_the_hold_after_a_bank_detail_change",
        Config::default().with_cases(48),
        &Machine::new(false),
    );
}

/// I-33 (M5 design 12.1): the first bank detail write starts the hold too,
/// and a grant without bank details is never released.
#[test]
fn i33_first_bank_detail_write_starts_the_hold() {
    check_machine_with(
        "i33_first_bank_detail_write_starts_the_hold",
        Config::default().with_cases(48),
        &Machine::new(true),
    );
}

/// I-33: the release opens exactly when P-36 has elapsed after a verified
/// first write, and not one microsecond earlier.
#[test]
fn i33_release_opens_when_p36_elapses_after_verification() {
    let mut w = world(Backend::Production, true).unwrap();
    assert!(prepare(&mut w, 0, 0, 50, None).unwrap());
    let written = w.now();
    w.vault(|t| t.write_bank(PC, written)).unwrap();
    w.vault(|t| t.verify_bank(PC)).unwrap();
    w.set_now(later(written, HOLD - 1));
    assert_eq!(
        run(&mut w, &release(0)).unwrap(),
        None,
        "I-33: released one microsecond before P-36 elapsed"
    );
    w.set_now(later(written, HOLD));
    let records = must(&mut w, &release(0)).unwrap();
    assert_eq!(releases(&records), vec![request_id(0)]);
}

/// I-33, overview NOTE 2: without the vault's answer the release is
/// refused and records nothing (fail closed).
#[test]
fn i33_release_fails_closed_without_the_vault_answer() {
    let mut w = world(Backend::Production, false).unwrap();
    assert!(prepare(&mut w, 0, 0, 50, None).unwrap());
    let state = &w.life.rev.sod.state;
    let cmd = Command::ReleasePayment {
        request: request_id(0),
        record_file: record_file_of(request_id(0)),
    };
    let ctx = Step::by(REL, Flags::NONE, cmd.clone())
        .ctx(w.now(), CommandId::from_bytes(*b"test:i33:down:01"));
    let asked = fstp_domain::queries(state, &cmd, &ctx).unwrap();
    assert!(
        asked
            .iter()
            .any(|q| matches!(q, fstp_domain::Query::BankReleasable { grant, .. } if *grant == PC)),
        "I-33: the release asks the vault BankReleasable, got {asked:?}"
    );
    let refused = fstp_domain::decide(state, &cmd, &ctx, &Answers::new()).unwrap_err();
    assert_eq!(refused.rule, RuleRef::FactsIncomplete, "{refused:?}");
}
