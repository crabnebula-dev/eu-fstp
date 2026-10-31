//! Reproducers of the independent review of lane w3ae (M3 W3a agent
//! two). Each test fails against the reviewed code and passes once the
//! defect it names is fixed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::future::Future;

use fstp_audit::anchor::{Receipt, ReceiptFields};
use fstp_audit::anchorer::{PrepareWitness, WitnessFault};
use fstp_audit::witness::Prepare;
use fstp_audit::{CompositeSigningKey, Link};
use fstp_cell::engine::{AppendRequest, CellStore};
use fstp_cell::tasks::{system_now, timeline};
use fstp_cell::witness::store::{AnchoredStore, MemDatabase, OpenPrepare, StoreKeys};
use fstp_cell_core::driver::SideEffects;
use fstp_cell_core::{CellCommand, CellRecord, CellState, KeyRecord};
use fstp_crypto::composite;
use fstp_domain::assignment::AssignmentKind;
use fstp_domain::command::{Actor, Command, DeclarationSubject};
use fstp_domain::id::CommandId;
use fstp_domain::scoring::{ScoreKey, Stage};
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::review::{COORDINATOR, L1, PR1, R1, R2, declare, plan_of, submit};
use fstp_domain_testkit::r#gen::roster::{Step, T0, call, publish};
use fstp_domain_testkit::mc::life_model::{
    T_EVAL, admit, assign_declared, assignment_of, close, expire, knock_out, score,
};
use fstp_domain_testkit::mc::lifecycle_model::lifecycle_config;
use fstp_domain_testkit::scenario::Scenario;
use fstp_keys::envelope::DataKey;
use fstp_ledger::{Entry, Seq};

const CELL: [u8; 16] = [0x7E; 16];
const MINUTE_US: i64 = 60_000_000;
const DAY_US: i64 = 86_400_000_000;

// ---------------------------------------------------------------------------
// Timeline: a due system command that recurs gets the id of its first
// occurrence, so the engine reports it as a duplicate and never commits it.
// ---------------------------------------------------------------------------

fn run(scn: &mut Scenario, now: Timestamp, step: &Step, id: Option<[u8; 16]>) {
    let drawn = scn.ctx(now, step.actor).command;
    let command = id.map(CommandId::from_bytes).unwrap_or(drawn);
    let ctx = step.ctx(now, command);
    if let Err(e) = scn.execute(fstp_engine::Command::Core(step.cmd.clone()), ctx) {
        panic!("{:?} refused: {e:?}", step.cmd.kind());
    }
}

fn cell_state(scn: &Scenario) -> CellState {
    let entries: Vec<Entry<CellRecord>> = scn
        .entries()
        .unwrap()
        .into_iter()
        .map(|e| e.map_record(CellRecord::Engine))
        .collect();
    fstp_cell_core::replay(&entries).unwrap()
}

fn due(scn: &Scenario, now: Timestamp, want: fn(&Command) -> bool) -> Option<[u8; 16]> {
    timeline::due_commands(&cell_state(scn), now)
        .into_iter()
        .find(|(c, _)| matches!(c, CellCommand::Engine(fstp_engine::Command::Core(core)) if want(core)))
        .map(|(_, id)| id)
}

fn is_expire(c: &Command) -> bool {
    matches!(c, Command::ExpireStage2 { proposal } if *proposal == PR1)
}

fn is_reenter(c: &Command) -> bool {
    matches!(c, Command::ReEnter { proposal, .. } if *proposal == PR1)
}

/// state-machine.md rows STAGE2 to DEFERRED and DEFERRED re-entry, NOTE 5
/// and NOTE 8, design section 5.1: a proposal deferred from STAGE2
/// re-enters STAGE2 in the next call, and its P-07 window can elapse
/// again. The second `ExpireStage2` is a new command and must get a new
/// id. `timeline::command_id` hashes only the canonical command, so the
/// second occurrence gets the id the first one committed under, and the
/// engine answers it as a duplicate: the proposal stays in STAGE2.
#[test]
fn review_timeline_gives_a_recurring_due_command_a_fresh_id() {
    let setup = lifecycle_config().setup;
    let mut scn = Scenario::new(setup.truth()).unwrap();
    for s in setup.draft_steps().unwrap() {
        run(&mut scn, T0, &s, None);
    }
    run(&mut scn, T0, &submit(L1, PR1, plan_of(PR1), false), None);
    for r in [R1, R2] {
        for s in assign_declared(r, PR1, call(1), AssignmentKind::Reviewer) {
            run(&mut scn, T_EVAL, &s, None);
        }
    }
    let coordinator = declare(COORDINATOR, DeclarationSubject::Proposal(PR1), false, false);
    run(&mut scn, T_EVAL, &coordinator, None);
    run(&mut scn, T_EVAL, &knock_out(PR1, true), None);
    run(&mut scn, T_EVAL, &admit(PR1), None);
    for r in [R1, R2] {
        let key = ScoreKey {
            assignment: assignment_of(r, PR1, call(1), AssignmentKind::Reviewer),
            stage: Stage::One,
            plan: plan_of(PR1),
        };
        run(&mut scn, T_EVAL, &score(r, key, &[2, 2]), None);
    }
    run(
        &mut scn,
        T_EVAL,
        &close(Actor::Account(COORDINATOR), PR1),
        None,
    );

    // First occurrence: the P-07 window of call 1 elapses.
    let t1 = Timestamp::from_micros(T_EVAL.micros() + 29 * DAY_US);
    let first = due(&scn, t1, is_expire).expect("ExpireStage2 is due in call 1");
    run(&mut scn, t1, &expire(PR1), Some(first));
    run(&mut scn, t1, &publish(call(2)), None);

    // Re-entry into call 2, as the timeline issues it.
    let mut now = t1;
    let mut reentered = false;
    for _ in 0..800 {
        now = Timestamp::from_micros(now.micros() + DAY_US);
        if let Some(id) = due(&scn, now, is_reenter) {
            let cmd = due_command(&scn, now, is_reenter);
            run(&mut scn, now, &system_step(cmd), Some(id));
            reentered = true;
            break;
        }
    }
    assert!(reentered, "PR1 never re-entered call 2");

    // Second occurrence: the P-07 window elapses again in call 2.
    let mut second = None;
    for _ in 0..800 {
        now = Timestamp::from_micros(now.micros() + DAY_US);
        if let Some(id) = due(&scn, now, is_expire) {
            second = Some(id);
            break;
        }
    }
    let second = second.expect("ExpireStage2 is due again in call 2");
    let committed: Vec<[u8; 16]> = scn.entries().unwrap().iter().map(|e| e.command).collect();
    assert!(
        second != first && !committed.contains(&second),
        "the second ExpireStage2 of PR1 reuses the committed id of the first, so the engine \
         reports it as a duplicate and PR1 is never deferred again"
    );
}

fn due_command(scn: &Scenario, now: Timestamp, want: fn(&Command) -> bool) -> Command {
    timeline::due_commands(&cell_state(scn), now)
        .into_iter()
        .find_map(|(c, _)| match c {
            CellCommand::Engine(fstp_engine::Command::Core(core)) if want(&core) => Some(core),
            _ => None,
        })
        .unwrap()
}

fn system_step(cmd: Command) -> Step {
    fstp_domain_testkit::mc::life_model::system(cmd)
}

// ---------------------------------------------------------------------------
// Anchored store: step-up freshness is checked again at commit against the
// admission instant, not the commit instant.
// ---------------------------------------------------------------------------

/// A witness that receipts every prepare for its own head, signed with
/// its receipt key, which the store pins (ADR-010 "Keys").
struct Echo(CompositeSigningKey);

impl PrepareWitness for Echo {
    fn prepare(&self, p: &Prepare) -> impl Future<Output = Result<Receipt, WitnessFault>> + Send {
        let a = &p.anchor;
        let fields = ReceiptFields {
            n: a.n,
            link: a.link,
            witness_seq: a.n,
            witness_link: a.link,
            received_at: a.at,
        };
        std::future::ready(
            fstp_witness::sign_receipt(&self.0, a.cell, a.chain, &fields)
                .map_err(|_| WitnessFault::Refused),
        )
    }

    fn abort(&self, _head: (u64, Link)) -> impl Future<Output = Result<(), WitnessFault>> + Send {
        std::future::ready(Ok(()))
    }

    fn in_doubt_absent(
        &self,
        _head: (u64, Link),
    ) -> impl Future<Output = Result<(), WitnessFault>> + Send {
        std::future::ready(Ok(()))
    }
}

impl OpenPrepare for Echo {
    fn open_prepare(
        &self,
    ) -> impl Future<Output = Result<Option<(u64, Link)>, WitnessFault>> + Send {
        std::future::ready(Ok(None))
    }
}

fn stepup_append(expected: u64, at: i64, id: u8, fresh_until: i64) -> AppendRequest {
    AppendRequest {
        expected: Seq::from_raw(expected),
        at,
        command: [id; 16],
        batch: vec![CellRecord::Key(KeyRecord::KeyOpRecorded {
            op: format!("{{\"n\":{id}}}").into_bytes(),
        })],
        side: SideEffects {
            stepup_consumed: Some([id; 16]),
            stepup_fresh_until: Some(fresh_until),
            sessions_ended: Vec::new(),
        },
    }
}

/// I-78, design section 8.4 and ADR-008: step-up freshness
/// (`now - asserted_at <= P-71`) is checked at admission and again at
/// commit. `SideEffects::stepup_fresh_until` documents that the store
/// checks it against its commit instant. `AnchoredStore` compares it with
/// `req.at`, the admission instant the gate already checked, so a
/// high-risk command whose step-up went stale while it waited in the
/// queue or for the witness still commits.
///
/// The first append (fresh at commit) must commit, which needs composite
/// signing of anchors (lane w2gs). The second was fresh at admission ten
/// minutes ago and is stale at commit, so it must be refused.
#[test]
fn review_anchored_store_rechecks_stepup_freshness_at_commit() {
    let receipt_key = composite::generate().unwrap();
    let keys = StoreKeys {
        anchor: composite::generate().unwrap(),
        ledger: DataKey::generate().unwrap(),
        witness: vec![receipt_key.public_key().to_bytes().to_vec()],
    };
    let mut store = AnchoredStore::new(MemDatabase::new(), Echo(receipt_key), CELL, keys).unwrap();
    let now = system_now();
    fstp_rt::future::block_on(async {
        store.start().await.unwrap();
        let fresh = stepup_append(0, now - 20 * MINUTE_US, 1, now + 5 * MINUTE_US);
        assert!(
            store.append_cell(fresh).await.is_ok(),
            "a step-up still fresh at commit must commit (needs anchor signing, lane w2gs)"
        );
        let stale = stepup_append(1, now - 10 * MINUTE_US, 2, now - 5 * MINUTE_US);
        assert!(
            store.append_cell(stale).await.is_err(),
            "a step-up that expired five minutes before the commit instant was committed"
        );
    });
}

// ---------------------------------------------------------------------------
// Serve: a drain that times out never returns while the engine task is
// stuck, so a cell whose in-flight command hangs never exits on SIGTERM.
// ---------------------------------------------------------------------------

/// A vault that never answers.
struct StuckVault;

impl fstp_cell::engine::VaultClient for StuckVault {
    fn epoch(
        &self,
    ) -> impl Future<
        Output = Result<fstp_domain::id::VaultEpoch, fstp_cell_core::driver::VaultFault>,
    > + Send {
        std::future::pending()
    }

    fn ask(
        &self,
        _queries: &[fstp_domain::oracle::Query],
        _reaction_for: Option<fstp_domain::id::VaultEpoch>,
        _at: Timestamp,
    ) -> impl Future<
        Output = Result<fstp_domain::oracle::Answers, fstp_cell_core::driver::VaultFault>,
    > + Send {
        std::future::pending()
    }

    fn ack(
        &self,
        _epoch: fstp_domain::id::VaultEpoch,
        _seq: Seq,
        _link: [u8; 32],
    ) -> impl Future<Output = Result<(), fstp_cell_core::driver::VaultFault>> + Send {
        std::future::pending()
    }
}

/// A termination listener that reports SIGTERM 200 ms after it is asked.
struct TermSoon(fstp_rt::tokio::TokioRuntime);

impl fstp_rt::signal::TerminationListener for TermSoon {
    fn recv(&mut self) -> impl Future<Output = fstp_rt::signal::Termination> + Send {
        use fstp_rt::Runtime as _;
        let sleep = self.0.sleep(std::time::Duration::from_millis(200));
        async move {
            sleep.await;
            fstp_rt::signal::Termination::Terminate
        }
    }
}

/// ADR-002 review note of 2026-10-28, design section 2.3: SIGTERM drains
/// the cell within the drain deadline, then the process exits. When the
/// command in flight never finishes (here a vault that never answers, as
/// a hung connection does), `serve_until_terminated` logs
/// `DrainTimedOut` and then awaits the engine task with no bound, so it
/// never returns and the binary never exits.
#[test]
fn review_serve_returns_after_a_timed_out_drain() {
    use fstp_cell::engine::serve::{Drain, ServeOptions, serve_until_terminated};
    use fstp_cell::engine::{CellEngine, Unanchored};
    use fstp_cell_core::gate::{self, Action};
    use fstp_cell_core::{KeyCommand, SystemTask, system_command_id};
    use fstp_ledger::MemStore;
    use fstp_rt::Runtime as _;
    use fstp_rt::Shutdown;

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = fstp_rt::tokio::TokioRuntime::new_multi_thread(2).unwrap();
        let rt2 = rt.clone();
        let r = rt.block_on(async move {
            let store = Unanchored::open(MemStore::<CellRecord>::new(), CELL)
                .await
                .unwrap();
            let rt3 = rt2.clone();
            let on_started = move |engine: &CellEngine, _s: &Shutdown| {
                let engine = engine.clone();
                let s = CellState::genesis();
                let admitted = gate::admit_system(
                    &s,
                    Action::Command(CellCommand::Key(KeyCommand::RecordKeyOp {
                        op: b"{\"n\":1}".to_vec(),
                    })),
                    SystemTask::ErasureRunner,
                    system_command_id(*b"review01"),
                    s.now_floor(),
                )
                .unwrap();
                drop(rt3.spawn(async move {
                    let _ = engine.execute(admitted).await;
                }));
            };
            let opts = ServeOptions {
                drain: std::time::Duration::from_millis(200),
                queue: 8,
            };
            serve_until_terminated(
                &rt2,
                TermSoon(rt2.clone()),
                store,
                StuckVault,
                opts,
                on_started,
            )
            .await
            .map(|(_, d)| d)
        });
        let _ = tx.send(r.map_err(|_| ()));
    });
    match rx.recv_timeout(std::time::Duration::from_secs(10)) {
        Ok(Ok(Drain::TimedOut { .. })) => {}
        Ok(other) => panic!("the drain ended as {other:?}, not timed out"),
        Err(_) => panic!(
            "serve_until_terminated did not return 10 s after a 200 ms drain deadline: the \
             cell never exits while its in-flight command hangs"
        ),
    }
}
