//! Self-tests of the driver's command-id namespace, vault epochs and batch
//! folds (`docs/handoff/m2-design.md` section 3.1,
//! `SPEC/03-architecture/overview.md` NOTE 3, I-23).
//!
//! - Caller command ids never enter the namespace the driver uses for
//!   `VaultChanged`, so no caller can stop a vault change from being recorded.
//! - An entry that holds a `VaultChanged` id without processing its epoch
//!   gives a typed error, never `StaleFacts`.
//! - `VaultChanged` carries the epoch of its `ChangedSince` answer.
//! - A batch that the fold refuses is never appended (I-23).
//!
//! The domain lanes are stubs, so a scripted decider stands in for
//! `fstp_domain::queries` and `decide`. Its records are `VaultOutcome`
//! records, whose fold is structural today.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use fstp_domain::command::{Actor, Command as CoreCommand, Ctx, Via};
use fstp_domain::engine::FoldError;
use fstp_domain::id::{AccountId, CommandId, ContentDigest, ProposalId, VaultEpoch};
use fstp_domain::oracle::{Answer, Answers, OracleDown, Query, QueryKind};
use fstp_domain::record::Record as CoreRecord;
use fstp_domain::refusal::Refusal;
use fstp_domain::time::Timestamp;
use fstp_engine::driver::Decider;
use fstp_engine::{
    Command, Engine, EngineState, ExecError, IdentityOracle, RESERVED_COMMAND_PREFIX, Record,
    is_reserved_command_id, replay,
};
use fstp_ledger::{Entry, MemStore, RecordStore, Seq};

/// A vault that reports `reported` as its epoch and answers at `answered`.
#[derive(Clone)]
struct SplitOracle {
    reported: Rc<Cell<u64>>,
    answered: Rc<Cell<u64>>,
}

impl SplitOracle {
    fn at(e: u64) -> SplitOracle {
        SplitOracle {
            reported: Rc::new(Cell::new(e)),
            answered: Rc::new(Cell::new(e)),
        }
    }
}

impl IdentityOracle for SplitOracle {
    fn ask(&self, q: &Query) -> Result<Answer, OracleDown> {
        Ok(Answer {
            holds: false,
            accounts: matches!(q, Query::ChangedSince { .. }).then(Default::default),
            epoch: VaultEpoch::from_raw(self.answered.get()),
            digest: ContentDigest::from_bytes([0; 32]),
        })
    }

    fn epoch(&self) -> Result<VaultEpoch, OracleDown> {
        Ok(VaultEpoch::from_raw(self.reported.get()))
    }
}

/// A decider that accepts every command with one `VaultOutcome` record and
/// logs what it decided. It never checks the clock, so a test can make it
/// return a batch that the fold refuses.
#[derive(Clone, Default)]
struct Accepting {
    decided: Rc<RefCell<Vec<Command>>>,
}

fn outcome() -> Record {
    Record::Core(CoreRecord::VaultOutcome {
        kind: QueryKind::IsVerified,
        digest: ContentDigest::from_bytes([4; 32]),
        holds: true,
        epoch: VaultEpoch::GENESIS,
    })
}

impl Decider for Accepting {
    fn queries(&self, _: &EngineState, _: &Command, _: &Ctx) -> Result<Vec<Query>, Refusal> {
        Ok(Vec::new())
    }

    fn decide(
        &self,
        _: &EngineState,
        cmd: &Command,
        _: &Ctx,
        _: &Answers,
    ) -> Result<Vec<Record>, Refusal> {
        self.decided.borrow_mut().push(cmd.clone());
        Ok(vec![outcome()])
    }
}

fn ctx(now: i64, id: [u8; 16]) -> Ctx {
    Ctx {
        now: Timestamp::from_micros(now),
        actor: Actor::Account(AccountId::from_raw(11)),
        command: CommandId::from_bytes(id),
        via: Via::Web,
        tenant_admin: false,
        second_tenant_admin: None,
        binds_tenant_admin: false,
    }
}

fn withdraw() -> Command {
    Command::Core(CoreCommand::Withdraw {
        proposal: ProposalId::from_raw(7),
    })
}

fn reserved(epoch: u64) -> [u8; 16] {
    let mut id = [0u8; 16];
    id[..8].copy_from_slice(&RESERVED_COMMAND_PREFIX);
    id[8..].copy_from_slice(&epoch.to_be_bytes());
    id
}

fn read_all<S: RecordStore<Record>>(store: &S) -> Vec<Entry<Record>> {
    let mut out = Vec::new();
    store.read(Seq::ZERO, usize::MAX, &mut out).expect("read");
    out
}

/// NOTE 3: a caller command whose id is in the driver's reserved namespace
/// is refused before the vault is asked or anything is decided, and nothing
/// is appended. Ids outside the namespace are accepted as before.
#[test]
fn driver_refuses_a_caller_command_in_the_reserved_namespace() {
    assert!(is_reserved_command_id(CommandId::from_bytes(reserved(3))));
    assert!(!is_reserved_command_id(CommandId::from_bytes([1; 16])));
    let decider = Accepting::default();
    let mut engine = Engine::open_with(
        MemStore::<Record>::new(),
        SplitOracle::at(0),
        decider.clone(),
    )
    .expect("open");
    let r = engine.execute(withdraw(), ctx(10, reserved(3)));
    assert_eq!(r, Err(ExecError::ReservedCommandId));
    assert!(decider.decided.borrow().is_empty());
    assert_eq!(engine.store().head(), Seq::ZERO);
    let r = engine.execute(withdraw(), ctx(10, [1; 16]));
    assert_eq!(r, Ok(Seq::from_raw(1)));
}

/// NOTE 3: an entry written by another writer under the id of the driver's
/// `VaultChanged` for epoch 3, which did not process epoch 3, is not taken
/// as the processed change. The driver reports a typed error, not
/// `StaleFacts`, and appends nothing. The state stays the replay of the store.
#[test]
fn driver_reports_a_vault_changed_id_held_by_an_entry_that_did_not_process_it() {
    let mut store = MemStore::<Record>::new();
    store
        .append(Seq::ZERO, 5, reserved(3), vec![outcome()])
        .expect("foreign entry");
    let mut engine =
        Engine::open_with(store, SplitOracle::at(3), Accepting::default()).expect("open");
    let r = engine.execute(withdraw(), ctx(10, [1; 16]));
    assert_eq!(
        r,
        Err(ExecError::CommandIdTaken {
            at: Seq::from_raw(1),
            epoch: VaultEpoch::from_raw(3),
        })
    );
    let entries = read_all(engine.store());
    assert_eq!(entries.len(), 1);
    assert_eq!(replay(&entries), Ok(engine.state().clone()));
}

/// NOTE 3: when the vault's `ChangedSince` answer is at a newer epoch than
/// the epoch it reported a moment before, `VaultChanged` carries the
/// answer's epoch, so its changed set and its epoch agree.
#[test]
fn driver_takes_the_vault_changed_epoch_from_its_answer() {
    let oracle = SplitOracle::at(2);
    oracle.answered.set(3);
    let decider = Accepting::default();
    let mut engine =
        Engine::open_with(MemStore::<Record>::new(), oracle, decider.clone()).expect("open");
    let _ = engine.sync_vault(ctx(10, [1; 16]));
    let decided = decider.decided.borrow();
    assert_eq!(decided.len(), 1);
    assert!(
        matches!(
            &decided[0],
            Command::Core(CoreCommand::VaultChanged { epoch, .. }) if *epoch == VaultEpoch::from_raw(3)
        ),
        "{decided:?}"
    );
    let entries = read_all(engine.store());
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].command, reserved(3));
}

/// NOTE 3: a `ChangedSince` answer older than the epoch the vault reported
/// is stale. The driver refuses with `StaleFacts` and appends nothing.
#[test]
fn driver_refuses_a_changed_since_answer_older_than_the_reported_epoch() {
    let oracle = SplitOracle::at(3);
    oracle.answered.set(2);
    let decider = Accepting::default();
    let mut engine =
        Engine::open_with(MemStore::<Record>::new(), oracle, decider.clone()).expect("open");
    let r = engine.execute(withdraw(), ctx(10, [1; 16]));
    assert!(
        matches!(r, Err(ExecError::Refused(x)) if x.rule == fstp_domain::refusal::RuleRef::StaleFacts),
        "{r:?}"
    );
    assert!(decider.decided.borrow().is_empty());
    assert_eq!(engine.store().head(), Seq::ZERO);
}

/// I-23: a batch that `decide` returns but `apply` refuses is never
/// appended, so the store stays replayable. Here the decider ignores the
/// clock and returns a record earlier than the time floor.
#[test]
fn i23_driver_never_appends_a_batch_the_fold_refuses() {
    let mut store = MemStore::<Record>::new();
    store
        .append(Seq::ZERO, 20, [9; 16], vec![outcome()])
        .expect("first entry");
    let mut engine =
        Engine::open_with(store, SplitOracle::at(0), Accepting::default()).expect("open");
    let r = engine.execute(withdraw(), ctx(10, [1; 16]));
    assert_eq!(r, Err(ExecError::Unfoldable(FoldError::TimeBackwards)));
    let entries = read_all(engine.store());
    assert_eq!(entries.len(), 1);
    assert_eq!(replay(&entries), Ok(engine.state().clone()));
}

/// Design 6.1: an engine is a value. A clone runs the same command to the
/// same state, and `into_parts` gives back a store that reopens to it.
#[test]
fn driver_engine_clones_and_reopens_from_its_parts() {
    let mut a = Engine::open_with(MemStore::<Record>::new(), SyntheticOracle, AcceptingPlain)
        .expect("open");
    let mut b = a.clone();
    assert_eq!(a, b);
    let ra = a.execute(withdraw(), ctx(10, [1; 16]));
    let rb = b.execute(withdraw(), ctx(10, [1; 16]));
    assert_eq!(ra, rb);
    assert_eq!(a, b);
    let state = a.state().clone();
    let (store, oracle, decider) = a.into_parts();
    let reopened = Engine::open_with(store, oracle, decider).expect("reopen");
    assert_eq!(reopened.state(), &state);
}

/// A vault at epoch 0 that answers nothing, comparable and hashable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct SyntheticOracle;

impl IdentityOracle for SyntheticOracle {
    fn ask(&self, _: &Query) -> Result<Answer, OracleDown> {
        Err(OracleDown)
    }

    fn epoch(&self) -> Result<VaultEpoch, OracleDown> {
        Ok(VaultEpoch::GENESIS)
    }
}

/// [`Accepting`] without the log, comparable and hashable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct AcceptingPlain;

impl Decider for AcceptingPlain {
    fn queries(&self, _: &EngineState, _: &Command, _: &Ctx) -> Result<Vec<Query>, Refusal> {
        Ok(Vec::new())
    }

    fn decide(
        &self,
        _: &EngineState,
        _: &Command,
        _: &Ctx,
        _: &Answers,
    ) -> Result<Vec<Record>, Refusal> {
        Ok(vec![outcome()])
    }
}
