//! Self-tests of the synchronous reference driver (`docs/handoff/m2-design.md`
//! section 3.1, `SPEC/03-architecture/overview.md` NOTE 2 and NOTE 3, I-23).
//!
//! The driver runs four steps for each command. When the vault epoch is
//! ahead of the state, it processes `VaultChanged` first. It asks the vault
//! the command's questions and fails closed when the vault cannot answer.
//! It decides, appends against the expected head and applies. On a stale
//! head it retries from a fresh state. After every `execute`, the state
//! equals the replay of the store.
//!
//! The domain lanes are still stubs that refuse every command. So most
//! tests here drive the driver through a scripted [`Decider`], a test double
//! for `fstp_domain::queries` and `decide`. Its records are `VaultOutcome`
//! records, whose fold is structural and lands with the interface (W1c).
//! The tests that use the default domain decider rely only on the shared
//! checks of the dispatcher, which do not change when the lanes land.
//!
//! API this file is written against, from design section 3.1 plus the
//! seams the harness lane adds (recorded in the lane report):
//! - `fstp_engine::{Engine, EngineState, Command, Record, ExecError,
//!   OpenError, IdentityOracle, replay}`;
//! - `fstp_engine::driver::{Decider, DomainDecider}`, with
//!   `Engine::open_with(store, oracle, decider)`;
//! - `Engine::state`, `Engine::store` and `Engine::execute`.
//!
//! Readings taken where the design is silent:
//! - a vault that cannot answer gives the refusal
//!   `Refusal::new(RuleRef::OracleDown, RefusalReason::OracleUnavailable)`;
//! - the driver builds `VaultChanged` from the `ChangedSince` answer at the
//!   state's epoch, with a `System(Vault)` actor and the caller's instant;
//! - a refused `VaultChanged` is propagated, and the command is not decided;
//! - retries on a stale head are bounded, and a driver that gives up still
//!   holds the replay of the store.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::rc::Rc;

use fstp_domain::command::{Actor, Command as CoreCommand, Ctx, SystemCause, Via};
use fstp_domain::engine::FoldError;
use fstp_domain::id::{AccountId, CommandId, ContentDigest, ProposalId, VaultEpoch};
use fstp_domain::oracle::{Answer, Answers, OracleDown, Query, QueryKind};
use fstp_domain::record::Record as CoreRecord;
use fstp_domain::refusal::{Refusal, RefusalReason, RuleRef};
use fstp_domain::state::State;
use fstp_domain::time::Timestamp;
use fstp_engine::driver::{Decider, DomainDecider};
use fstp_engine::{
    Command, Engine, EngineState, ExecError, IdentityOracle, OpenError, Record, replay,
};
use fstp_ledger::{AppendError, Entry, MemStore, RecordStore, Seq, StoreError};
use fstp_prop::{check, prop_assert, prop_assert_eq};

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

/// What the test vault does, shared with the test through an `Rc`.
#[derive(Default)]
struct OracleScript {
    /// The vault epoch it reports.
    epoch: Cell<u64>,
    /// Whether `epoch` fails.
    epoch_down: Cell<bool>,
    /// Whether `ask` fails.
    ask_down: Cell<bool>,
    /// The accounts a `ChangedSince` answer lists.
    changed: RefCell<BTreeSet<AccountId>>,
    /// Every question asked, in order.
    asked: RefCell<Vec<Query>>,
}

/// A vault double that the test steers and that logs every question.
#[derive(Clone, Default)]
struct TestOracle(Rc<OracleScript>);

impl IdentityOracle for TestOracle {
    fn ask(&self, q: &Query) -> Result<Answer, OracleDown> {
        self.0.asked.borrow_mut().push(q.clone());
        if self.0.ask_down.get() {
            return Err(OracleDown);
        }
        let accounts = match q {
            Query::ChangedSince { .. } => Some(self.0.changed.borrow().clone()),
            _ => None,
        };
        Ok(Answer {
            holds: false,
            accounts,
            epoch: VaultEpoch::from_raw(self.0.epoch.get()),
            digest: ContentDigest::from_bytes([0; 32]),
        })
    }

    fn epoch(&self) -> Result<VaultEpoch, OracleDown> {
        if self.0.epoch_down.get() {
            Err(OracleDown)
        } else {
            Ok(VaultEpoch::from_raw(self.0.epoch.get()))
        }
    }
}

/// One call of the scripted decider's `decide`.
#[derive(Clone, Debug)]
struct Decided {
    command: Command,
    ctx: Ctx,
    /// The time floor of the state the decision saw.
    floor: Timestamp,
    answers: Answers,
}

/// What the scripted decider does, shared with the test through an `Rc`.
#[derive(Default)]
struct DeciderScript {
    /// The questions every command other than `VaultChanged` needs.
    queries: Vec<Query>,
    /// The refusal for every command other than `VaultChanged`.
    refuse: Option<Refusal>,
    /// The refusal for `VaultChanged`.
    refuse_vault_changed: Option<Refusal>,
    /// How many records an accepted command produces.
    records: usize,
    /// Every decision, in order.
    decided: Vec<Decided>,
}

/// A stand-in for the domain's `queries` and `decide`, so the driver steps
/// can be tested while every domain lane is still a stub.
#[derive(Clone, Default)]
struct ScriptedDecider(Rc<RefCell<DeciderScript>>);

fn is_vault_changed(cmd: &Command) -> bool {
    matches!(cmd, Command::Core(CoreCommand::VaultChanged { .. }))
}

impl Decider for ScriptedDecider {
    fn queries(
        &self,
        _state: &EngineState,
        cmd: &Command,
        _ctx: &Ctx,
    ) -> Result<Vec<Query>, Refusal> {
        if is_vault_changed(cmd) {
            Ok(Vec::new())
        } else {
            Ok(self.0.borrow().queries.clone())
        }
    }

    fn decide(
        &self,
        state: &EngineState,
        cmd: &Command,
        ctx: &Ctx,
        answers: &Answers,
    ) -> Result<Vec<Record>, Refusal> {
        let mut script = self.0.borrow_mut();
        script.decided.push(Decided {
            command: cmd.clone(),
            ctx: *ctx,
            floor: state.core.now_floor(),
            answers: answers.clone(),
        });
        let refusal = if is_vault_changed(cmd) {
            script.refuse_vault_changed
        } else {
            script.refuse
        };
        if let Some(r) = refusal {
            return Err(r);
        }
        Ok((0..script.records).map(|i| outcome(i % 2 == 0)).collect())
    }
}

/// A record whose fold is structural today: the vault outcome of a query.
fn outcome(holds: bool) -> Record {
    Record::Core(CoreRecord::VaultOutcome {
        kind: QueryKind::IsVerified,
        digest: ContentDigest::from_bytes([7; 32]),
        holds,
        epoch: VaultEpoch::GENESIS,
    })
}

/// A store in which another writer appends one foreign entry just before
/// each of the next `races` appends, so those appends meet a stale head.
struct RacingStore {
    inner: MemStore<Record>,
    races: Rc<Cell<usize>>,
    /// The time of the foreign entries.
    foreign_at: Rc<Cell<i64>>,
    foreign_count: u8,
}

impl RacingStore {
    fn new(races: usize, foreign_at: i64) -> RacingStore {
        RacingStore {
            inner: MemStore::new(),
            races: Rc::new(Cell::new(races)),
            foreign_at: Rc::new(Cell::new(foreign_at)),
            foreign_count: 0,
        }
    }

    fn foreign_command(n: u8) -> [u8; 16] {
        let mut id = [0xF0; 16];
        id[15] = n;
        id
    }
}

impl RecordStore<Record> for RacingStore {
    fn head(&self) -> Seq {
        self.inner.head()
    }

    fn append(
        &mut self,
        expected: Seq,
        at: i64,
        command: [u8; 16],
        batch: Vec<Record>,
    ) -> Result<Seq, AppendError> {
        if self.races.get() > 0 {
            self.races.set(self.races.get() - 1);
            self.foreign_count = self.foreign_count.wrapping_add(1);
            let head = self.inner.head();
            self.inner.append(
                head,
                self.foreign_at.get(),
                RacingStore::foreign_command(self.foreign_count),
                vec![outcome(true)],
            )?;
        }
        self.inner.append(expected, at, command, batch)
    }

    fn read(
        &self,
        from: Seq,
        limit: usize,
        out: &mut Vec<Entry<Record>>,
    ) -> Result<(), StoreError> {
        self.inner.read(from, limit, out)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn read_all<S: RecordStore<Record>>(store: &S) -> Vec<Entry<Record>> {
    let mut out = Vec::new();
    store
        .read(Seq::ZERO, usize::MAX, &mut out)
        .expect("read the store");
    out
}

fn ctx(now: i64, id: u8, actor: Actor) -> Ctx {
    Ctx {
        now: Timestamp::from_micros(now),
        actor,
        command: CommandId::from_bytes([id; 16]),
        via: Via::Web,
        tenant_admin: false,
        second_tenant_admin: None,
        binds_tenant_admin: false,
    }
}

fn lead() -> Actor {
    Actor::Account(AccountId::from_raw(11))
}

/// A command whose actor rule needs an account (row 15, Lead).
fn withdraw() -> Command {
    Command::Core(CoreCommand::Withdraw {
        proposal: ProposalId::from_raw(7),
    })
}

fn oracle_down() -> Refusal {
    Refusal::new(RuleRef::OracleDown, RefusalReason::OracleUnavailable)
}

fn is_refusal(r: &Result<Seq, ExecError>, expected: Refusal) -> bool {
    matches!(r, Err(ExecError::Refused(x)) if *x == expected)
}

// ---------------------------------------------------------------------------
// Engine::open
// ---------------------------------------------------------------------------

/// Opening over an empty store gives the genesis state and appends nothing.
#[test]
fn driver_open_over_empty_store_is_genesis() {
    let engine = Engine::open(MemStore::<Record>::new(), TestOracle::default()).expect("open");
    assert_eq!(engine.state().core, State::genesis());
    assert_eq!(engine.store().head(), Seq::ZERO);
    let entries = read_all(engine.store());
    assert!(entries.is_empty());
    assert_eq!(replay(&entries), Ok(engine.state().clone()));
}

/// I-23: opening replays a store whose records fold structurally today.
/// The state is the replay of the stored entries, including their time floor.
#[test]
fn i23_driver_open_replays_structural_records() {
    let mut store = MemStore::<Record>::new();
    store
        .append(Seq::ZERO, 10, [1; 16], vec![outcome(true), outcome(false)])
        .expect("first batch");
    store
        .append(Seq::from_raw(2), 20, [2; 16], vec![outcome(true)])
        .expect("second batch");
    let engine = Engine::open(store, TestOracle::default()).expect("open");
    let entries = read_all(engine.store());
    assert_eq!(entries.len(), 3);
    assert_eq!(engine.state().core.now_floor(), Timestamp::from_micros(20));
    assert_eq!(engine.state().core.epoch(), VaultEpoch::GENESIS);
    assert_eq!(replay(&entries), Ok(engine.state().clone()));
}

/// I-23: opening refuses a log the engine could not have produced. Here the
/// time of the second entry is earlier than the first.
#[test]
fn i23_driver_open_refuses_a_log_the_fold_rejects() {
    let mut store = MemStore::<Record>::new();
    store
        .append(Seq::ZERO, 20, [1; 16], vec![outcome(true)])
        .expect("first batch");
    store
        .append(Seq::from_raw(1), 10, [2; 16], vec![outcome(true)])
        .expect("second batch");
    let opened = Engine::open(store, TestOracle::default());
    assert!(matches!(
        opened,
        Err(OpenError::Fold(FoldError::TimeBackwards))
    ));
}

// ---------------------------------------------------------------------------
// Fail closed (overview NOTE 2)
// ---------------------------------------------------------------------------

/// Overview NOTE 2: when the vault cannot report its epoch, the command is
/// refused as `OracleDown` and nothing is appended.
#[test]
fn driver_fails_closed_when_the_vault_epoch_is_unavailable() {
    let oracle = TestOracle::default();
    oracle.0.epoch_down.set(true);
    let mut engine = Engine::open(MemStore::<Record>::new(), oracle).expect("open");
    let r = engine.execute(withdraw(), ctx(10, 1, lead()));
    assert!(is_refusal(&r, oracle_down()), "{r:?}");
    assert_eq!(engine.store().head(), Seq::ZERO);
    assert_eq!(engine.state().core, State::genesis());
}

/// Overview NOTE 2: when the vault cannot answer a question the command
/// needs, the command is refused as `OracleDown`. It is never decided and
/// nothing is appended.
#[test]
fn driver_fails_closed_when_a_vault_question_is_unanswered() {
    let oracle = TestOracle::default();
    oracle.0.ask_down.set(true);
    let decider = ScriptedDecider::default();
    let question = Query::IsVerified {
        account: AccountId::from_raw(11),
    };
    {
        let mut s = decider.0.borrow_mut();
        s.queries = vec![question.clone()];
        s.records = 1;
    }
    let mut engine = Engine::open_with(MemStore::<Record>::new(), oracle.clone(), decider.clone())
        .expect("open");
    let r = engine.execute(withdraw(), ctx(10, 1, lead()));
    assert!(is_refusal(&r, oracle_down()), "{r:?}");
    assert!(oracle.0.asked.borrow().contains(&question));
    assert!(decider.0.borrow().decided.is_empty());
    assert_eq!(engine.store().head(), Seq::ZERO);
    assert_eq!(engine.state().core, State::genesis());
}

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

/// A refusal of the domain core is propagated unchanged and nothing is
/// appended. A System actor fails the Lead actor rule of `Withdraw` in the
/// dispatcher's shared checks, before any lane runs (I-84 seed).
#[test]
fn driver_propagates_a_domain_refusal_with_nothing_appended() {
    let oracle = TestOracle::default();
    let mut engine = Engine::open(MemStore::<Record>::new(), oracle.clone()).expect("open");
    let r = engine.execute(withdraw(), ctx(10, 1, Actor::System(SystemCause::Timeline)));
    let wrong_actor = Refusal::new(RuleRef::Actor, RefusalReason::WrongActor);
    assert!(is_refusal(&r, wrong_actor), "{r:?}");
    assert!(oracle.0.asked.borrow().is_empty());
    assert_eq!(engine.store().head(), Seq::ZERO);
    assert_eq!(engine.state().core, State::genesis());
}

/// The default decider is the domain core, so `open` and `open_with` with
/// `DomainDecider` refuse the same command in the same way.
#[test]
fn driver_default_decider_is_the_domain_core() {
    let mut a = Engine::open(MemStore::<Record>::new(), TestOracle::default()).expect("open");
    let mut b = Engine::open_with(
        MemStore::<Record>::new(),
        TestOracle::default(),
        DomainDecider,
    )
    .expect("open_with");
    let c = ctx(10, 1, Actor::System(SystemCause::Timeline));
    let ra = a.execute(withdraw(), c);
    let rb = b.execute(withdraw(), c);
    assert_eq!(format!("{ra:?}"), format!("{rb:?}"));
}

/// A refusal after the vault answered is propagated unchanged, and nothing
/// is appended.
#[test]
fn driver_propagates_a_decider_refusal_with_nothing_appended() {
    let refusal = Refusal::new(RuleRef::Row, RefusalReason::GuardFailed);
    let decider = ScriptedDecider::default();
    {
        let mut s = decider.0.borrow_mut();
        s.queries = vec![Query::IsVerified {
            account: AccountId::from_raw(11),
        }];
        s.refuse = Some(refusal);
        s.records = 1;
    }
    let mut engine = Engine::open_with(
        MemStore::<Record>::new(),
        TestOracle::default(),
        decider.clone(),
    )
    .expect("open");
    let r = engine.execute(withdraw(), ctx(10, 1, lead()));
    assert!(is_refusal(&r, refusal), "{r:?}");
    assert_eq!(decider.0.borrow().decided.len(), 1);
    assert_eq!(engine.store().head(), Seq::ZERO);
    assert_eq!(engine.state().core, State::genesis());
}

// ---------------------------------------------------------------------------
// Accepted commands
// ---------------------------------------------------------------------------

/// An accepted batch is appended once, under the command's id and instant,
/// then applied. The decision saw every answer at the state's epoch.
#[test]
fn driver_appends_and_applies_an_accepted_batch() {
    let question = Query::IsVerified {
        account: AccountId::from_raw(11),
    };
    let decider = ScriptedDecider::default();
    {
        let mut s = decider.0.borrow_mut();
        s.queries = vec![question.clone()];
        s.records = 2;
    }
    let mut engine = Engine::open_with(
        MemStore::<Record>::new(),
        TestOracle::default(),
        decider.clone(),
    )
    .expect("open");
    let c = ctx(10, 1, lead());
    let r = engine.execute(withdraw(), c);
    assert_eq!(r.ok(), Some(Seq::from_raw(2)));
    let entries = read_all(engine.store());
    assert_eq!(entries.len(), 2);
    for e in &entries {
        assert_eq!(e.at, 10);
        assert_eq!(e.command, c.command.bytes());
    }
    assert_eq!(engine.state().core.now_floor(), Timestamp::from_micros(10));
    assert_eq!(replay(&entries), Ok(engine.state().clone()));
    let script = decider.0.borrow();
    assert_eq!(script.decided.len(), 1);
    let answer = script.decided[0].answers.get(&question).expect("answered");
    assert_eq!(answer.epoch, VaultEpoch::GENESIS);
}

// ---------------------------------------------------------------------------
// Stale head
// ---------------------------------------------------------------------------

/// Design 3.1 step 4: on a stale head the driver retries from a fresh state.
/// The retry decides on the state that includes the other writer's entry,
/// and the command is appended once, after it.
#[test]
fn driver_retries_on_stale_head_from_a_fresh_state() {
    let decider = ScriptedDecider::default();
    decider.0.borrow_mut().records = 1;
    let store = RacingStore::new(1, 5);
    let mut engine =
        Engine::open_with(store, TestOracle::default(), decider.clone()).expect("open");
    let c = ctx(10, 1, lead());
    let r = engine.execute(withdraw(), c);
    assert_eq!(r.ok(), Some(Seq::from_raw(2)));
    let entries = read_all(engine.store());
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].at, 5);
    assert_eq!(entries[0].command, RacingStore::foreign_command(1));
    assert_eq!(entries[1].at, 10);
    assert_eq!(entries[1].command, c.command.bytes());
    let floors: Vec<Timestamp> = decider.0.borrow().decided.iter().map(|d| d.floor).collect();
    assert_eq!(
        floors,
        vec![Timestamp::from_micros(0), Timestamp::from_micros(5)]
    );
    assert_eq!(replay(&entries), Ok(engine.state().clone()));
}

/// Retries are bounded. Under contention that never ends, `execute` fails
/// instead of looping, the command is never appended, and the state is the
/// replay of the store.
#[test]
fn driver_gives_up_under_endless_contention_and_keeps_the_replay() {
    let decider = ScriptedDecider::default();
    decider.0.borrow_mut().records = 1;
    let store = RacingStore::new(10_000, 5);
    let mut engine = Engine::open_with(store, TestOracle::default(), decider).expect("open");
    let c = ctx(10, 1, lead());
    let r = engine.execute(withdraw(), c);
    assert!(r.is_err(), "{r:?}");
    let entries = read_all(engine.store());
    assert!(entries.iter().all(|e| e.command != c.command.bytes()));
    assert!(entries.len() < 10_000);
    assert_eq!(replay(&entries), Ok(engine.state().clone()));
}

// ---------------------------------------------------------------------------
// Vault epochs (overview NOTE 3)
// ---------------------------------------------------------------------------

/// Overview NOTE 3 and design 3.1 step 1: when the vault epoch is ahead of
/// the state, the driver asks which accounts changed since the state's
/// epoch and decides `VaultChanged` before the command. If `VaultChanged`
/// is refused, the refusal is propagated, the command is never decided and
/// nothing is appended.
#[test]
fn driver_processes_vault_changed_first_when_the_vault_is_ahead() {
    let oracle = TestOracle::default();
    oracle.0.epoch.set(3);
    let changed: BTreeSet<AccountId> = [AccountId::from_raw(11)].into_iter().collect();
    *oracle.0.changed.borrow_mut() = changed.clone();
    let refusal = Refusal::new(RuleRef::Row, RefusalReason::GuardFailed);
    let decider = ScriptedDecider::default();
    {
        let mut s = decider.0.borrow_mut();
        s.refuse_vault_changed = Some(refusal);
        s.records = 1;
    }
    let mut engine = Engine::open_with(MemStore::<Record>::new(), oracle.clone(), decider.clone())
        .expect("open");
    let c = ctx(10, 1, lead());
    let r = engine.execute(withdraw(), c);
    assert!(is_refusal(&r, refusal), "{r:?}");
    assert_eq!(
        oracle.0.asked.borrow().first(),
        Some(&Query::ChangedSince {
            epoch: VaultEpoch::GENESIS
        })
    );
    let script = decider.0.borrow();
    assert_eq!(script.decided.len(), 1);
    let first = &script.decided[0];
    assert_eq!(
        first.command,
        Command::Core(CoreCommand::VaultChanged {
            epoch: VaultEpoch::from_raw(3),
            changed,
        })
    );
    assert_eq!(first.ctx.actor, Actor::System(SystemCause::Vault));
    assert_eq!(first.ctx.now, c.now);
    assert_eq!(engine.store().head(), Seq::ZERO);
    assert_eq!(engine.state().core, State::genesis());
}

/// Overview NOTE 3: when the vault epoch equals the state's, no change is
/// processed and the command alone is decided.
#[test]
fn driver_skips_vault_changed_when_the_epoch_is_current() {
    let oracle = TestOracle::default();
    let decider = ScriptedDecider::default();
    decider.0.borrow_mut().records = 1;
    let mut engine = Engine::open_with(MemStore::<Record>::new(), oracle.clone(), decider.clone())
        .expect("open");
    let r = engine.execute(withdraw(), ctx(10, 1, lead()));
    assert_eq!(r.ok(), Some(Seq::from_raw(1)));
    assert!(
        oracle
            .0
            .asked
            .borrow()
            .iter()
            .all(|q| !matches!(q, Query::ChangedSince { .. }))
    );
    let script = decider.0.borrow();
    assert_eq!(script.decided.len(), 1);
    assert_eq!(script.decided[0].command, withdraw());
}

// ---------------------------------------------------------------------------
// Replay after every execute (I-23)
// ---------------------------------------------------------------------------

/// What one step of the replay property does.
#[derive(Clone, Copy, Debug)]
enum Step {
    /// The command is accepted with this many records.
    Accept(usize),
    /// Another writer appends first, then the command is accepted.
    RaceThenAccept(usize),
    /// The decider refuses.
    Refuse,
    /// The vault cannot answer a question.
    AskDown,
    /// The vault cannot report its epoch.
    EpochDown,
}

/// I-23 and design 6.1: after every `execute`, accepted, refused, failed
/// closed or raced, the state equals the replay of the store, and every
/// earlier read of the store is a prefix of the later one.
#[test]
fn i23_driver_replay_equals_state_after_every_execute() {
    check("i23_driver_replay_equals_state_after_every_execute", |g| {
        let steps = g.vec(1..=12, |g| match g.u8_in(0..=4) {
            0 => Step::Accept(g.usize_in(1..=3)),
            1 => Step::RaceThenAccept(g.usize_in(1..=3)),
            2 => Step::Refuse,
            3 => Step::AskDown,
            _ => Step::EpochDown,
        });
        g.note("steps", &steps);
        let oracle = TestOracle::default();
        let decider = ScriptedDecider::default();
        decider.0.borrow_mut().queries = vec![Query::IsVerified {
            account: AccountId::from_raw(11),
        }];
        let store = RacingStore::new(0, 0);
        let races = Rc::clone(&store.races);
        let foreign_at = Rc::clone(&store.foreign_at);
        let mut engine = Engine::open_with(store, oracle.clone(), decider.clone())
            .map_err(|e| format!("open: {e:?}"))?;
        let mut previous: Vec<Entry<Record>> = Vec::new();
        for (i, step) in steps.iter().enumerate() {
            let now = 10 * (i as i64 + 1);
            {
                let mut s = decider.0.borrow_mut();
                s.refuse = None;
                s.records = 1;
            }
            oracle.0.ask_down.set(false);
            oracle.0.epoch_down.set(false);
            let mut expected_growth = 0usize;
            match *step {
                Step::Accept(n) => {
                    decider.0.borrow_mut().records = n;
                    expected_growth = n;
                }
                Step::RaceThenAccept(n) => {
                    decider.0.borrow_mut().records = n;
                    races.set(1);
                    foreign_at.set(now - 5);
                    expected_growth = n + 1;
                }
                Step::Refuse => {
                    decider.0.borrow_mut().refuse =
                        Some(Refusal::new(RuleRef::Row, RefusalReason::GuardFailed));
                }
                Step::AskDown => oracle.0.ask_down.set(true),
                Step::EpochDown => oracle.0.epoch_down.set(true),
            }
            let r = engine.execute(withdraw(), ctx(now, i as u8 + 1, lead()));
            let current = read_all(engine.store());
            prop_assert_eq!(replay(&current), Ok(engine.state().clone()));
            prop_assert!(current.len() >= previous.len(), "the ledger shrank");
            prop_assert_eq!(&current[..previous.len()], &previous[..]);
            prop_assert_eq!(current.len(), previous.len() + expected_growth);
            match *step {
                Step::Accept(_) | Step::RaceThenAccept(_) => {
                    prop_assert_eq!(r.ok(), Some(engine.store().head()));
                }
                Step::Refuse | Step::AskDown | Step::EpochDown => {
                    prop_assert!(r.is_err(), "step {step:?} was accepted");
                }
            }
            previous = current;
        }
        Ok(())
    });
}
