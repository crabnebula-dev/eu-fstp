//! I-10 through the reference driver: a finding command appends only its
//! own finding records, and the ledger stays time-monotone across both
//! sides of the envelope (design sections 2.2 and 3.1).
//!
//! The setup from genesis publishes call 1 with configuration 1 and call 2
//! with configuration 2 (`pin_scenario`).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::engine::FoldError;
use fstp_domain::id::{LlmConfigId, VaultEpoch};
use fstp_domain::refusal::RefusalReason;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::findings::{
    ASSESSOR, INJECTION_PHRASES, assessor_ctx, finding, finding_command_id,
};
use fstp_domain_testkit::r#gen::review::{
    COORDINATOR, L1, PR1, after, plan_of, run_on, submit, tag,
};
use fstp_domain_testkit::r#gen::roster::{T0, call};
use fstp_domain_testkit::mc::findings_model::{engine_command, exec_finding, pin_scenario};
use fstp_domain_testkit::vault::Relation;
use fstp_engine::{ExecError, IdentityOracle, Record};
use fstp_findings::{Finding, FindingCommand, FindingKind, FindingRecord};
use fstp_ledger::Seq;

fn f(id: u128) -> Finding {
    finding(
        id,
        call(1),
        PR1,
        LlmConfigId::from_raw(1),
        FindingKind::Quality,
        INJECTION_PHRASES[0],
    )
}

/// I-10: with the vault ahead of the processed epoch, a finding command
/// appends only its finding record. It never processes `VaultChanged`,
/// so it adds no core record and leaves the core as it was.
#[test]
fn i10_finding_command_never_processes_a_vault_change() {
    let (mut engine, _) = pin_scenario().unwrap().0.into_parts();
    engine
        .oracle_mut()
        .truth_mut()
        .relate(tag(L1), tag(COORDINATOR), Relation::CoWorker);
    let core = engine.state().core.clone();
    let epoch: VaultEpoch = engine.state().epoch();
    assert!(
        engine.oracle().epoch().unwrap() > epoch,
        "the vault did not move ahead"
    );
    let cmd = engine_command(FindingCommand::Record(f(1))).unwrap();
    let head = engine
        .execute(cmd, assessor_ctx(T0, finding_command_id(1)))
        .unwrap();
    assert_eq!(head.raw(), engine.head().raw());
    let mut entries = Vec::new();
    fstp_ledger::RecordStore::read(engine.store(), Seq::ZERO, usize::MAX, &mut entries).unwrap();
    let last = entries.last().map(|e| &e.record);
    assert!(
        matches!(last, Some(Record::Finding(FindingRecord::Recorded(_)))),
        "the last entry is {last:?}"
    );
    let trailing = entries
        .iter()
        .rev()
        .take_while(|e| matches!(e.record, Record::Finding(_)))
        .count();
    assert_eq!(
        trailing, 1,
        "the command appended more than its finding record"
    );
    assert_eq!(
        engine.state().epoch(),
        epoch,
        "I-10: a finding command processed the vault"
    );
    assert_eq!(
        engine.state().core,
        core,
        "I-10: a finding command changed the core"
    );
}

/// Design 2.2, I-10: a finding entry is a recorded time. A later finding
/// command or core command before it is refused with `ClockBackwards`,
/// and the ledger's times never go backwards.
#[test]
fn i10_finding_entry_raises_the_ledger_time_floor() {
    let (mut s, _) = pin_scenario().unwrap();
    let later = after(T0, 1_000_000);
    exec_finding(&mut s, FindingCommand::Record(f(1)), ASSESSOR, later)
        .unwrap()
        .unwrap();
    let finding_cmd = exec_finding(&mut s, FindingCommand::Record(f(2)), ASSESSOR, T0).unwrap();
    let core_cmd = run_on(&mut s, &submit(L1, PR1, plan_of(PR1), false), T0);
    for (what, r) in [("finding", &finding_cmd), ("core", &core_cmd)] {
        assert!(
            matches!(r, Err(ExecError::Refused(x)) if x.reason == RefusalReason::ClockBackwards),
            "a {what} command before the finding entry was {r:?}"
        );
    }
    let ats: Vec<i64> = s.entries().unwrap().iter().map(|e| e.at).collect();
    assert!(ats.windows(2).all(|w| w[0] <= w[1]), "ledger times {ats:?}");
    assert_eq!(s.state().now_floor(), later);
    let ok = run_on(&mut s, &submit(L1, PR1, plan_of(PR1), false), later);
    assert!(ok.is_ok(), "a core command at the floor was {ok:?}");
}

/// Design 2.2: the fold refuses an entry of either side whose time is
/// before the latest finding entry, so a replayed log stays time-monotone.
#[test]
fn i10_fold_refuses_entries_before_the_latest_finding_entry() {
    let (s, _) = pin_scenario().unwrap();
    let mut state = s.state().clone();
    let later = after(state.now_floor(), 1_000_000);
    let early = Timestamp::from_micros(state.now_floor().micros());
    fstp_engine::apply(
        &mut state,
        Seq::from_raw(1),
        later,
        &Record::Finding(FindingRecord::Recorded(f(1))),
    )
    .unwrap();
    let finding_back = fstp_engine::apply(
        &mut state.clone(),
        Seq::from_raw(2),
        early,
        &Record::Finding(FindingRecord::Recorded(f(2))),
    );
    let core_back = fstp_engine::apply(
        &mut state.clone(),
        Seq::from_raw(2),
        early,
        &Record::Core(fstp_domain::Record::VaultEpochProcessed {
            epoch: VaultEpoch::from_raw(state.epoch().raw().saturating_add(1)),
        }),
    );
    assert_eq!(finding_back, Err(FoldError::TimeBackwards));
    assert_eq!(core_back, Err(FoldError::TimeBackwards));
}
