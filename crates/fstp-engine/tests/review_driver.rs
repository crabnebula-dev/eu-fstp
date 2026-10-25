//! Review reproducers for the reference driver (design section 3.1,
//! `SPEC/03-architecture/overview.md` NOTE 3).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use fstp_domain::command::{Actor, Command as CoreCommand, Ctx, Via};
use fstp_domain::id::{AccountId, CommandId, ContentDigest, ProposalId, VaultEpoch};
use fstp_domain::oracle::{Answer, Answers, OracleDown, Query, QueryKind};
use fstp_domain::record::Record as CoreRecord;
use fstp_domain::refusal::{Refusal, RefusalReason, RuleRef};
use fstp_domain::time::Timestamp;
use fstp_engine::driver::Decider;
use fstp_engine::{Command, Engine, EngineState, IdentityOracle, Record};
use fstp_ledger::{Entry, MemStore, RecordStore, Seq};

/// A vault whose `epoch` reports the values of `epochs` in turn, then the
/// last one forever. Every answer carries `answer_epoch`.
#[derive(Clone)]
struct StepOracle {
    epochs: Rc<RefCell<Vec<u64>>>,
    answer_epoch: Rc<Cell<u64>>,
}

impl StepOracle {
    fn fixed(e: u64) -> StepOracle {
        StepOracle {
            epochs: Rc::new(RefCell::new(vec![e])),
            answer_epoch: Rc::new(Cell::new(e)),
        }
    }
}

impl IdentityOracle for StepOracle {
    fn ask(&self, q: &Query) -> Result<Answer, OracleDown> {
        Ok(Answer {
            holds: false,
            accounts: matches!(q, Query::ChangedSince { .. }).then(Default::default),
            epoch: VaultEpoch::from_raw(self.answer_epoch.get()),
            digest: ContentDigest::from_bytes([0; 32]),
        })
    }

    fn epoch(&self) -> Result<VaultEpoch, OracleDown> {
        let mut e = self.epochs.borrow_mut();
        let v = if e.len() > 1 { e.remove(0) } else { e[0] };
        Ok(VaultEpoch::from_raw(v))
    }
}

/// A decider that, like `fstp_domain::decide`, refuses `StaleFacts` when an
/// answer's epoch is not the expected one. `VaultChanged` produces a
/// `ChangedSince` marker record, every other command an `IsVerified` one.
#[derive(Clone, Default)]
struct MarkerDecider {
    decided: Rc<RefCell<Vec<Command>>>,
}

fn marker(kind: QueryKind) -> Record {
    Record::Core(CoreRecord::VaultOutcome {
        kind,
        digest: ContentDigest::from_bytes([9; 32]),
        holds: true,
        epoch: VaultEpoch::GENESIS,
    })
}

fn is_vault_changed(cmd: &Command) -> bool {
    matches!(cmd, Command::Core(CoreCommand::VaultChanged { .. }))
}

impl Decider for MarkerDecider {
    fn queries(&self, _: &EngineState, cmd: &Command, _: &Ctx) -> Result<Vec<Query>, Refusal> {
        if is_vault_changed(cmd) {
            Ok(Vec::new())
        } else {
            Ok(vec![Query::IsVerified {
                account: AccountId::from_raw(11),
            }])
        }
    }

    fn decide(
        &self,
        state: &EngineState,
        cmd: &Command,
        ctx: &Ctx,
        answers: &Answers,
    ) -> Result<Vec<Record>, Refusal> {
        self.decided.borrow_mut().push(cmd.clone());
        let expected = match cmd {
            Command::Core(CoreCommand::VaultChanged { epoch, .. }) => *epoch,
            _ => state.epoch(),
        };
        for q in self.queries(state, cmd, ctx)? {
            match answers.get(&q) {
                Some(a) if a.epoch == expected => {}
                _ => {
                    return Err(Refusal::new(
                        RuleRef::StaleFacts,
                        RefusalReason::AnswerStale,
                    ));
                }
            }
        }
        Ok(vec![if is_vault_changed(cmd) {
            marker(QueryKind::ChangedSince)
        } else {
            marker(QueryKind::IsVerified)
        }])
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

fn read_all<S: RecordStore<Record>>(store: &S) -> Vec<Entry<Record>> {
    let mut out = Vec::new();
    store.read(Seq::ZERO, usize::MAX, &mut out).expect("read");
    out
}

/// NOTE 3: a caller command whose id happens to equal the driver's
/// `VaultChanged` id for a later epoch must not stop that change from being
/// processed. Today the driver reads the `DuplicateCommand` as "already
/// processed", never records the vault change, and refuses later commands.
#[test]
fn review_vault_changed_id_cannot_be_squatted_by_a_caller_command() {
    let oracle = StepOracle::fixed(0);
    let decider = MarkerDecider::default();
    let mut engine = Engine::open_with(MemStore::<Record>::new(), oracle.clone(), decider.clone())
        .expect("open");

    let mut squatted = [0u8; 16];
    squatted[..8].copy_from_slice(b"fstp:vc:");
    squatted[8..].copy_from_slice(&3u64.to_be_bytes());
    // The caller's command may be accepted or refused; either way the vault
    // change for epoch 3 must later be recorded.
    let _ = engine.execute(withdraw(), ctx(10, squatted));

    *oracle.epochs.borrow_mut() = vec![3];
    oracle.answer_epoch.set(3);
    let _ = engine.execute(withdraw(), ctx(20, [2; 16]));

    let recorded_vault_change = read_all(engine.store()).iter().any(|e| {
        matches!(
            e.record,
            Record::Core(CoreRecord::VaultOutcome {
                kind: QueryKind::ChangedSince,
                ..
            })
        )
    });
    assert!(
        recorded_vault_change,
        "the VaultChanged for epoch 3 was never appended: the driver took the caller's \
         command id as proof that the change was processed"
    );
}

/// NOTE 3 and design 4.3: when an answer comes back at a vault epoch newer
/// than the state's, the vault has reported a newer epoch. The driver must
/// process `VaultChanged` first and ask again. Today it hands the newer
/// answers to `decide`, which refuses the legal command with `StaleFacts`.
#[test]
fn review_answer_at_a_newer_epoch_triggers_vault_changed_and_a_new_ask() {
    // The vault reports epoch 0 at the first check, then moves to 1 before
    // the command's question is answered.
    let oracle = StepOracle {
        epochs: Rc::new(RefCell::new(vec![0, 1])),
        answer_epoch: Rc::new(Cell::new(1)),
    };
    let decider = MarkerDecider::default();
    let mut engine =
        Engine::open_with(MemStore::<Record>::new(), oracle, decider.clone()).expect("open");
    let r = engine.execute(withdraw(), ctx(10, [1; 16]));
    let saw_vault_changed = decider.decided.borrow().iter().any(|c| {
        matches!(
            c,
            Command::Core(CoreCommand::VaultChanged { epoch, .. }) if *epoch == VaultEpoch::from_raw(1)
        )
    });
    assert!(
        saw_vault_changed,
        "the driver never processed VaultChanged for the newer epoch; execute gave {r:?}"
    );
}
