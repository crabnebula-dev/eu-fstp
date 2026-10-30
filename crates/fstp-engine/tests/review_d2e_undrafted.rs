//! Review reproducers for D2e (M4 design section 3.4, I-66, I-67).
//!
//! D2e: `DomainDecider` refuses every core `ActivateProgramme` that
//! arrives through `execute`, and the fold refuses every entry with a
//! `ProgrammeActivated` and no `Creator(ActivationApproved)` beside it.
//! The lane applies both rules only to a programme with a creator draft.
//! A programme created by a core `CreateProgramme` is in `Draft` status
//! (D1) and can take policy edits, yet it activates with no validation
//! report and no creator approval. These tests fail until D2e holds for
//! every programme.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use fstp_domain::command::{Actor, Ctx};
use fstp_domain::id::{
    AccountId, CommandId, ContentDigest, DecisionId, PolicyVersionId, ProgrammeId, VaultEpoch,
};
use fstp_domain::oracle::{Answer, Answers, OracleDown, Query};
use fstp_domain::refusal::RuleRef;
use fstp_domain::time::Timestamp;
use fstp_domain::{State, Via};
use fstp_engine::{Command, Engine, ExecError, IdentityOracle, Record, replay};
use fstp_ledger::{Entry, MemStore, RecordStore, Seq};

const P: ProgrammeId = ProgrammeId::from_raw(1);
const ADMIN: AccountId = AccountId::from_raw(11);
const ADMIN_2: AccountId = AccountId::from_raw(12);

/// Every account verified with its own identity, at epoch 0.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Vault;

impl IdentityOracle for Vault {
    fn ask(&self, q: &Query) -> Result<Answer, OracleDown> {
        let holds = matches!(
            q,
            Query::IsVerified { .. }
                | Query::WithinRecipientCap { .. }
                | Query::AllRecipientsWithinCap { .. }
        );
        Ok(Answer {
            holds,
            accounts: matches!(q, Query::ChangedSince { .. }).then(BTreeSet::new),
            epoch: VaultEpoch::from_raw(0),
            digest: ContentDigest::from_bytes([0x5a; 32]),
        })
    }

    fn epoch(&self) -> Result<VaultEpoch, OracleDown> {
        Ok(VaultEpoch::from_raw(0))
    }
}

fn ctx(actor: AccountId, now: i64, n: u8) -> Ctx {
    let mut id = [0x72u8; 16];
    id[15] = n;
    Ctx {
        now: Timestamp::from_micros(now),
        actor: Actor::Account(actor),
        command: CommandId::from_bytes(id),
        via: Via::Web,
        tenant_admin: true,
        second_tenant_admin: None,
        binds_tenant_admin: false,
    }
}

fn create() -> fstp_domain::Command {
    let fixture = fstp_programme::supersafe_fixture().unwrap();
    let policy = fstp_programme::compile(
        &fixture.spec,
        &fstp_programme::FunderProfile::horizon_europe(),
        fstp_programme::CompileIds::new(P, PolicyVersionId::from_raw(P.raw()), None),
    )
    .unwrap()
    .policy;
    fstp_domain::Command::CreateProgramme {
        policy: Box::new(policy),
    }
}

fn activate() -> fstp_domain::Command {
    fstp_domain::Command::ActivateProgramme {
        programme: P,
        decision: DecisionId::from_raw(66),
        report: fstp_domain::policy::activation::ReportDigest::from_bytes([6; 32]),
        revision: 1,
        creator_builders: BTreeSet::new(),
    }
}

fn decided(core: &State, cmd: &fstp_domain::Command, c: &Ctx) -> Vec<fstp_domain::Record> {
    let mut answers = Answers::new();
    for q in fstp_domain::queries(core, cmd, c).unwrap() {
        answers.insert(q.clone(), Vault.ask(&q).unwrap());
    }
    fstp_domain::decide(core, cmd, c, &answers).unwrap()
}

/// I-66, D2e: a core `ActivateProgramme` through `execute` is refused with
/// I-66 for a programme created by a core `CreateProgramme` too. Today
/// the engine appends it, so the programme goes live with no validation
/// report.
#[test]
fn review_d2e_execute_refuses_core_activate_of_undrafted_programme() {
    let mut e = Engine::open(MemStore::<Record>::new(), Vault).unwrap();
    e.execute(Command::Core(create()), ctx(ADMIN, 1, 1))
        .unwrap();
    let r = e.execute(Command::Core(activate()), ctx(ADMIN_2, 2, 2));
    match r {
        Err(ExecError::Refused(refusal)) => assert_eq!(refusal.rule, RuleRef::I66),
        other => panic!(
            "I-66, D2e: a core ActivateProgramme from outside the creator was not refused: {other:?}"
        ),
    }
}

/// I-66, D2e: the fold refuses a `ProgrammeActivated` with no
/// `ActivationApproved` in its entry, for a programme without a creator
/// draft too ("a ledger written outside the engine"). Today the replay
/// accepts it.
#[test]
fn review_d2e_fold_refuses_unpaired_activation_of_undrafted_programme() {
    let c1 = ctx(ADMIN, 1, 1);
    let mut core = State::genesis();
    let created = decided(&core, &create(), &c1);
    let mut store = MemStore::<Record>::new();
    let mut head = Seq::ZERO;
    for (i, r) in created.iter().enumerate() {
        let n = u64::try_from(i).unwrap().saturating_add(1);
        fstp_domain::apply(&mut core, Seq::from_raw(n), Timestamp::from_micros(1), r).unwrap();
    }
    head = store
        .append(
            head,
            1,
            c1.command.bytes(),
            created.into_iter().map(Record::Core).collect(),
        )
        .unwrap();
    let c2 = ctx(ADMIN_2, 2, 2);
    let activated = decided(&core, &activate(), &c2);
    store
        .append(
            head,
            2,
            c2.command.bytes(),
            activated.into_iter().map(Record::Core).collect(),
        )
        .unwrap();
    let mut all: Vec<Entry<Record>> = Vec::new();
    store.read(Seq::ZERO, usize::MAX, &mut all).unwrap();
    assert!(
        replay(&all).is_err(),
        "I-66, D2e: the fold accepted a ProgrammeActivated without its ActivationApproved"
    );
}
