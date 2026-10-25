//! Review reproducers for the reference driver's vault-epoch handling
//! (design sections 3.1 and 4.3, `SPEC/03-architecture/overview.md`
//! NOTE 2 and NOTE 3).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use fstp_domain::command::{Actor, Command as CoreCommand, Ctx, Via};
use fstp_domain::id::{AccountId, CommandId, ContentDigest, ProposalId, VaultEpoch};
use fstp_domain::oracle::{Answer, Answers, OracleDown, Query, QueryKind};
use fstp_domain::record::Record as CoreRecord;
use fstp_domain::refusal::Refusal;
use fstp_domain::time::Timestamp;
use fstp_engine::driver::Decider;
use fstp_engine::{Command, Engine, EngineState, ExecError, IdentityOracle, Record};
use fstp_ledger::{MemStore, RecordStore, Seq};

/// A vault whose `epoch` endpoint reports `reported` while every answer
/// carries `answered`. `ChangedSince` lists `changed`, or no list at all
/// when `changed` is `None`.
#[derive(Clone)]
struct Vault {
    reported: Rc<Cell<u64>>,
    answered: Rc<Cell<u64>>,
    changed: Rc<RefCell<Option<std::collections::BTreeSet<AccountId>>>>,
}

impl IdentityOracle for Vault {
    fn ask(&self, q: &Query) -> Result<Answer, OracleDown> {
        let accounts = match q {
            Query::ChangedSince { .. } => self.changed.borrow().clone(),
            _ => None,
        };
        Ok(Answer {
            holds: true,
            accounts,
            epoch: VaultEpoch::from_raw(self.answered.get()),
            digest: ContentDigest::from_bytes([0; 32]),
        })
    }

    fn epoch(&self) -> Result<VaultEpoch, OracleDown> {
        Ok(VaultEpoch::from_raw(self.reported.get()))
    }
}

/// Every command other than `VaultChanged` asks one question. Every command
/// is accepted with one structural record, and every decision is logged.
#[derive(Clone, Default)]
struct Logging {
    decided: Rc<RefCell<Vec<Command>>>,
}

impl Decider for Logging {
    fn queries(&self, _: &EngineState, cmd: &Command, _: &Ctx) -> Result<Vec<Query>, Refusal> {
        if matches!(cmd, Command::Core(CoreCommand::VaultChanged { .. })) {
            Ok(Vec::new())
        } else {
            Ok(vec![Query::IsVerified {
                account: AccountId::from_raw(11),
            }])
        }
    }

    fn decide(
        &self,
        _: &EngineState,
        cmd: &Command,
        _: &Ctx,
        _: &Answers,
    ) -> Result<Vec<Record>, Refusal> {
        self.decided.borrow_mut().push(cmd.clone());
        Ok(vec![Record::Core(CoreRecord::VaultOutcome {
            kind: QueryKind::ChangedSince,
            digest: ContentDigest::from_bytes([1; 32]),
            holds: true,
            epoch: VaultEpoch::GENESIS,
        })])
    }
}

fn ctx(now: i64) -> Ctx {
    Ctx {
        now: Timestamp::from_micros(now),
        actor: Actor::Account(AccountId::from_raw(11)),
        command: CommandId::from_bytes([1; 16]),
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

/// NOTE 3: an answer that carries a newer epoch is the vault reporting
/// that epoch. The driver must then process `VaultChanged` for it and ask
/// again. When the vault's `epoch` endpoint lags its answers, the driver
/// today never processes the change. It retries until `Contended`, so
/// every command is over-denied while the endpoint lags.
#[test]
fn review_answer_epoch_ahead_of_a_lagging_epoch_endpoint_processes_vault_changed() {
    let vault = Vault {
        reported: Rc::new(Cell::new(0)),
        answered: Rc::new(Cell::new(1)),
        changed: Rc::new(RefCell::new(Some(Default::default()))),
    };
    let decider = Logging::default();
    let mut engine =
        Engine::open_with(MemStore::<Record>::new(), vault, decider.clone()).expect("open");
    let r = engine.execute(withdraw(), ctx(10));
    let saw = decider.decided.borrow().iter().any(|c| {
        matches!(
            c,
            Command::Core(CoreCommand::VaultChanged { epoch, .. }) if *epoch == VaultEpoch::from_raw(1)
        )
    });
    assert!(
        saw,
        "an answer at epoch 1 never led to VaultChanged for epoch 1; execute gave {r:?}"
    );
}

/// NOTE 2 and NOTE 3: a `ChangedSince` answer without its list of changed
/// accounts is no answer to the change query. The driver must fail closed
/// and append nothing. Today it reads the missing list as "no account
/// changed" and records `VaultChanged` with an empty set at the new epoch,
/// so the reaction to the real changes is skipped for good.
#[test]
fn review_changed_since_answer_without_accounts_fails_closed() {
    let vault = Vault {
        reported: Rc::new(Cell::new(1)),
        answered: Rc::new(Cell::new(1)),
        changed: Rc::new(RefCell::new(None)),
    };
    let decider = Logging::default();
    let mut engine =
        Engine::open_with(MemStore::<Record>::new(), vault, decider.clone()).expect("open");
    let r = engine.execute(withdraw(), ctx(10));
    let decided_vault_changed = decider
        .decided
        .borrow()
        .iter()
        .any(|c| matches!(c, Command::Core(CoreCommand::VaultChanged { .. })));
    assert!(
        !decided_vault_changed,
        "the driver decided VaultChanged from a ChangedSince answer with no account list; \
         execute gave {r:?}"
    );
    assert!(matches!(r, Err(ExecError::Refused(_))), "{r:?}");
    assert_eq!(engine.store().head(), Seq::ZERO);
}
