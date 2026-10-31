//! I-66, I-67, D2e: the engine refuses every path to an active programme but the creator's (M4 design section 3.4).
//!
//! NOT YET COMPILED. Cargo does not discover files in `tests/pending_d2e/`.
//! This file is written against the API of design section 3.4, which W1b
//! lands (D1, D2, D7). Move it to `tests/` once these exist:
//!
//! - `fstp_domain::Command::ActivateProgramme { programme, decision,
//!   report, revision, creator_builders }` (D2);
//! - `fstp_domain::Record::ProgrammeActivated` (D2);
//! - `fstp_domain::refusal::RuleRef::I66` (D7).
//!
//! The field types of `ActivateProgramme` are not fixed by the design. The
//! only place that names them is [`activate_cmd`], so the move touches
//! that function alone.
//!
//! - `i66_execute_refuses_core_activate_programme`: the engine refuses a
//!   core `ActivateProgramme` that arrives through `execute`, with
//!   `RuleRef::I66`, and appends nothing. The same command with the same
//!   context and vault answers passes `fstp_domain::decide`, so the
//!   refusal is the engine's and not a core guard's.
//! - `i66_fold_refuses_unpaired_programme_activated`: the records that
//!   decide returns form one forged entry with no
//!   `Creator(ActivationApproved)` beside them. The prefix replays and the
//!   core fold accepts them, so the engine fold's refusal comes from the
//!   missing creator record.
//! - `i66_open_refuses_store_with_unpaired_programme_activated`: a driver
//!   opened over that store refuses to open.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use fstp_domain::command::{Actor, Command as CoreCommand, Ctx};
use fstp_domain::id::{ContentDigest, DecisionId};
use fstp_domain::oracle::Answers;
use fstp_domain::refusal::RuleRef;
use fstp_domain::time::Timestamp;
use fstp_domain::{FoldError, Record as CoreRecord};
use fstp_domain_testkit::r#gen::review::run_on;
use fstp_domain_testkit::r#gen::roster::{ADMIN_2, P1, SodSetup, T0, sod_truth};
use fstp_domain_testkit::scenario::Scenario;
use fstp_domain_testkit::vault::SyntheticVault;
use fstp_engine::{Command, Engine, ExecError, IdentityOracle, OpenError, Record};
use fstp_ledger::{Entry, MemStore, RecordStore, Seq};

/// The command id of the forged entry, outside the driver's reserved namespace.
const FORGED: [u8; 16] = *b"forged:activate1";

/// A scenario from genesis whose only command is the `CreateProgramme` of
/// P1 by the setup tenant admin. So P1 is a `Draft` programme (D1), and
/// that admin is its only builder.
fn draft() -> Scenario {
    let steps = SodSetup::one(0, &[])
        .steps()
        .unwrap_or_else(|e| panic!("{e}"));
    let first = steps
        .iter()
        .find(|s| matches!(s.cmd, CoreCommand::CreateProgramme { .. }))
        .unwrap_or_else(|| panic!("the setup creates P1"));
    let mut s = Scenario::new(sod_truth()).unwrap_or_else(|e| panic!("open: {e:?}"));
    run_on(&mut s, first, T0).unwrap_or_else(|e| panic!("CreateProgramme: {e:?}"));
    s
}

/// The core activation of P1 that a second tenant admin would issue.
///
/// W1b seam: the field names follow design D2. The types of `report` and
/// `revision` are the ones W1b lands in `fstp_domain::id`.
fn activate_cmd() -> CoreCommand {
    CoreCommand::ActivateProgramme {
        programme: P1,
        decision: DecisionId::from_raw(66),
        report: fstp_domain::id::ReportDigest::from(ContentDigest::from_bytes([0x66; 32])),
        revision: fstp_domain::id::DraftRevisionRef::new(1, ContentDigest::from_bytes([0x67; 32])),
        creator_builders: BTreeSet::new(),
    }
}

/// The context of the activation: [`ADMIN_2`], a tenant admin outside the
/// builder set, verified with its own identity.
fn approver_ctx(s: &mut Scenario) -> Ctx {
    let mut ctx = s.ctx(T0, Actor::Account(ADMIN_2));
    ctx.tenant_admin = true;
    ctx
}

/// The core records `fstp_domain::decide` returns for `cmd` at `ctx`, with
/// the vault answers of the scenario's synthetic vault.
fn core_decide(s: &Scenario, cmd: &CoreCommand, ctx: &Ctx) -> Vec<CoreRecord> {
    let core = &s.state().core;
    let queries = fstp_domain::queries(core, cmd, ctx).unwrap_or_else(|r| panic!("queries: {r}"));
    let mut answers = Answers::new();
    for q in queries {
        let a = s
            .engine()
            .oracle()
            .ask(&q)
            .unwrap_or_else(|e| panic!("vault: {e:?}"));
        answers.insert(q, a);
    }
    fstp_domain::decide(core, cmd, ctx, &answers).unwrap_or_else(|r| panic!("decide: {r}"))
}

fn read_all(store: &MemStore<Record>) -> Vec<Entry<Record>> {
    let mut out = Vec::new();
    store
        .read(Seq::ZERO, usize::MAX, &mut out)
        .unwrap_or_else(|e| panic!("store read: {e:?}"));
    out
}

/// I-66, I-67, D2e: a core `ActivateProgramme` through `execute` is
/// refused with I-66 and appends nothing, although the core decide would
/// accept it at the same context.
#[test]
fn i66_execute_refuses_core_activate_programme() {
    let mut s = draft();
    let cmd = activate_cmd();
    let ctx = approver_ctx(&mut s);
    let records = core_decide(&s, &cmd, &ctx);
    assert!(
        records
            .iter()
            .any(|r| matches!(r, CoreRecord::ProgrammeActivated { .. })),
        "the core decide activates P1 at this context"
    );
    let before = s.state().clone();
    let len = s.entries().unwrap().len();
    match s.execute(Command::Core(cmd), ctx) {
        Err(ExecError::Refused(r)) => assert_eq!(
            r.rule,
            RuleRef::I66,
            "I-66: the engine names I-66 for the core activation"
        ),
        other => panic!("I-66: the core activation went through execute: {other:?}"),
    }
    assert_eq!(s.state(), &before, "I-66: a refusal changes no state");
    assert_eq!(
        s.entries().unwrap().len(),
        len,
        "I-66: a refusal appends nothing"
    );
}

/// The scenario's store with one more entry holding exactly the records
/// the core decide returns for the activation, and the prefix before it.
fn forged() -> (MemStore<Record>, Vec<Entry<Record>>) {
    let mut s = draft();
    let cmd = activate_cmd();
    let ctx = approver_ctx(&mut s);
    let records = core_decide(&s, &cmd, &ctx);
    let mut core = s.state().core.clone();
    let at = Timestamp::from_micros(T0.micros());
    for r in &records {
        assert_eq!(
            fstp_domain::apply(&mut core, Seq::from_raw(u64::MAX), at, r),
            Ok(()),
            "the forged records are well formed for the core fold"
        );
    }
    let (engine, _) = s.into_parts();
    let (mut store, _, _) = engine.into_parts();
    let prefix = read_all(&store);
    let head = store.head();
    store
        .append(
            head,
            T0.micros(),
            FORGED,
            records.into_iter().map(Record::Core).collect(),
        )
        .unwrap_or_else(|e| panic!("forged append: {e:?}"));
    (store, prefix)
}

/// Whether `e` refuses the entry's content, not its time or sequence, and
/// is not a fold lane that has not landed.
fn content_refusal(e: FoldError) -> bool {
    !matches!(
        e,
        FoldError::TimeBackwards | FoldError::OutOfOrder | FoldError::NotImplemented
    )
}

/// I-66, D2e: replay refuses an entry holding `ProgrammeActivated` without
/// a `Creator(ActivationApproved)` for the same programme, revision and
/// report digest.
#[test]
fn i66_fold_refuses_unpaired_programme_activated() {
    let (store, prefix) = forged();
    assert!(
        fstp_engine::replay(&prefix).is_ok(),
        "I-23: the prefix replays"
    );
    match fstp_engine::replay(&read_all(&store)) {
        Err(e) => assert!(
            content_refusal(e),
            "I-66: the refusal names the unpaired record, got {e:?}"
        ),
        Ok(_) => panic!("I-66: replay folded a ProgrammeActivated with no ActivationApproved"),
    }
}

/// I-66, D2e: a driver opened over a store that holds the unpaired
/// `ProgrammeActivated` refuses to open.
#[test]
fn i66_open_refuses_store_with_unpaired_programme_activated() {
    let (store, _) = forged();
    match Engine::open(store, SyntheticVault::new(sod_truth())) {
        Err(OpenError::Fold(e)) => assert!(
            content_refusal(e),
            "I-66: the refusal names the unpaired record, got {e:?}"
        ),
        Err(e) => panic!("I-66: expected a fold refusal, got {e:?}"),
        Ok(_) => panic!("I-66: the driver opened a ledger with an unpaired ProgrammeActivated"),
    }
}
