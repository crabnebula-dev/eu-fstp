//! The `Contract` envelope through the reference driver (M5 design
//! sections 3.1 and 4.1, lane L-CON; I-23, I-30).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use fstp_contract::{ContractCommand, ContractRecord, Digest, Party, PartyRole};
use fstp_domain::command::{Actor, ContractEvent, Ctx, SystemCause, Via};
use fstp_domain::engine::FoldError;
use fstp_domain::id::{
    AccountId, CommandId, ContentDigest, ContractId, DecisionId, PlanVersionId, ProposalId,
    VaultEpoch,
};
use fstp_domain::oracle::{Answer, OracleDown, Query};
use fstp_domain::time::Timestamp;
use fstp_engine::{
    Command, Engine, EngineState, EnvelopeKind, ExecError, IdentityOracle, Record, apply_in,
    envelope_from_json, finish,
};
use fstp_json::{FromJson, ToJson};
use fstp_ledger::{MemStore, RecordStore, Seq};

const PM: AccountId = AccountId::from_raw(31);
const LEAD: AccountId = AccountId::from_raw(32);
const SIGNATORY: AccountId = AccountId::from_raw(33);
const C: ContractId = ContractId::from_raw(41);
const P: ProposalId = ProposalId::from_raw(42);

struct Vault;

impl IdentityOracle for Vault {
    fn ask(&self, _q: &Query) -> Result<Answer, OracleDown> {
        Ok(Answer {
            holds: true,
            accounts: None,
            epoch: VaultEpoch::from_raw(0),
            digest: ContentDigest::from_bytes([0; 32]),
        })
    }

    fn epoch(&self) -> Result<VaultEpoch, OracleDown> {
        Ok(VaultEpoch::from_raw(0))
    }
}

fn ctx(n: u8, actor: AccountId) -> Ctx {
    Ctx {
        now: Timestamp::from_micros(1_000_000 + i64::from(n)),
        actor: Actor::Account(actor),
        command: CommandId::from_bytes([n; 16]),
        via: Via::Web,
        tenant_admin: false,
        second_tenant_admin: None,
        binds_tenant_admin: false,
    }
}

fn draft() -> ContractCommand {
    ContractCommand::Draft {
        contract: C,
        proposal: P,
        version: 1,
        template: 1,
        plan: PlanVersionId::from_raw(3),
        determination: DecisionId::from_raw(4),
        parties: vec![
            Party::new("lead", PartyRole::Lead, LEAD),
            Party::new("signatory", PartyRole::Signatory, SIGNATORY),
        ],
        base: Digest::from_bytes([1; 32]),
    }
}

/// I-23, M5 design 4.1: a contract command appends its records under the
/// `contract` member, and they replay into the contract store.
#[test]
fn i23_contract_records_append_and_replay() {
    let mut engine = Engine::open(MemStore::<Record>::new(), Vault).unwrap();
    engine
        .execute(Command::Contract(draft()), ctx(1, PM))
        .unwrap();
    let mut entries = Vec::new();
    engine
        .store()
        .read(Seq::ZERO, usize::MAX, &mut entries)
        .unwrap();
    assert_eq!(entries.len(), 1);
    let json = entries[0].record.to_json();
    let (kind, _) = envelope_from_json(&json).unwrap();
    assert_eq!(kind, EnvelopeKind::Contract);
    assert_eq!(kind.member(), "contract");
    assert_eq!(Record::from_json(&json).unwrap(), entries[0].record);
    let replayed = fstp_engine::replay(&entries).unwrap();
    assert_eq!(replayed.contracts, engine.state().contracts);
    assert!(replayed.contracts.contract(C).is_some());
}

/// I-30, `contracts.md` Rules: sending a contract asks the grant
/// preconditions, so a proposal the core does not hold in NEGOTIATION
/// cannot be sent; nothing is appended.
#[test]
fn i30_send_needs_the_grant_preconditions() {
    let mut engine = Engine::open(MemStore::<Record>::new(), Vault).unwrap();
    engine
        .execute(Command::Contract(draft()), ctx(1, PM))
        .unwrap();
    let send = ContractCommand::Send {
        contract: C,
        version: 1,
        revision0: Digest::from_bytes([2; 32]),
    };
    let e = engine.execute(Command::Contract(send), ctx(2, PM));
    assert!(matches!(e, Err(ExecError::Refused(_))), "{e:?}");
}

/// I-30, M5 design 4.1: the fold refuses a `ContractEffective` whose
/// entry holds no core `ContractFactRecorded` of the same contract.
#[test]
fn i30_effective_without_core_fact_is_refused_by_the_fold() {
    let mut state = EngineState::genesis();
    let records = fstp_contract::decide(&state.contracts, &draft(), Some(PM)).unwrap();
    for r in &records {
        apply_in(
            &mut state,
            Seq::from_raw(1),
            Timestamp::from_micros(10),
            Some([1; 16]),
            &Record::Contract(r.clone()),
        )
        .unwrap();
    }
    finish(&mut state).unwrap();
    let effective = Record::Contract(ContractRecord::Effective {
        contract: C,
        version: 1,
        final_digest: Digest::from_bytes([3; 32]),
    });
    let mut copy = state.clone();
    assert_eq!(
        apply_in(
            &mut copy,
            Seq::from_raw(2),
            Timestamp::from_micros(11),
            Some([2; 16]),
            &effective
        ),
        Err(FoldError::Inconsistent)
    );
    // The composed core command is the contract port's System fact.
    let (core, system) = fstp_engine::contract::contract_fact(P, C, &ctx(3, PM));
    assert_eq!(
        core,
        fstp_domain::Command::ContractFact {
            proposal: P,
            contract: C,
            event: ContractEvent::Effective
        }
    );
    assert_eq!(system.actor, Actor::System(SystemCause::ContractPort));
}
