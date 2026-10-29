//! The async engine over the in-memory store (M3 design sections 5.2, 5.4
//! and 5.5, ADR-007, I-23, NOTE 2).
//!
//! Lane W3a (agent two, test author) wrote these tests before the engine.
//! Each test drives `fstp_cell::engine::CellEngine` through one seam
//! function below. The seam runs the engine over `fstp_ledger::MemStore`
//! and a scripted vault on one `fstp_rt::tokio::TokioRuntime`. The
//! production agent replaced each seam body with a call into
//! `fstp_cell::engine` and left the assertions alone. The ledger is read
//! through `fstp_cell::engine::Unanchored`, which wraps the `MemStore`.
//!
//! The expected ledgers come from the decider's rule for the erasure
//! runner's key commands (design section 3.5, `decide_key` in
//! `fstp-cell-core`): one `KeyOpRecorded` per new command id, and nothing
//! for a retry. They are written here, not read from the engine, so they
//! are an independent reference.
//!
//! Gap (for the lead): the M2 generator equivalence of design section
//! 14.6 needs the admission of M2 steps and the ground-truth vault of
//! `fstp_celltest::mc::driver_model`. `fstp-celltest` depends on
//! `fstp-cell`, so these tests cannot use it, and the equivalence stays
//! behind [`m2_generator_ledgers`].

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;

use fstp_cell::engine::{CellEngine, EngineError, Unanchored, VaultClient, read_after};

use fstp_cell_core::driver::{Done, ExecError, VaultFault};
use fstp_cell_core::gate::{self, Action, Admitted};
use fstp_cell_core::{
    CellCommand, CellRecord, CellState, KeyCommand, KeyRecord, SystemTask, is_system_command_id,
    system_command_id,
};
use fstp_domain::id::{ContentDigest, VaultEpoch};
use fstp_domain::oracle::{Answer, Answers, Query};
use fstp_domain::time::Timestamp;
use fstp_ledger::{MemStore, Seq};
use fstp_prop::{Config, prop_assert_eq};
use fstp_rt::tokio::TokioRuntime;
use fstp_rt::{Runtime, Shutdown};

/// The seam of the M2 generator equivalence (design section 14.6).
const M2_EQUIVALENCE_SEAM: &str = "the M2 generators reach fstp-cell tests, but their admission of M2 \
     steps and the ground-truth vault live in fstp_celltest::mc::driver_model, which fstp-cell \
     tests cannot depend on (fstp-celltest depends on fstp-cell); the equivalence through \
     CellEngine belongs in fstp-celltest (design section 14.6; lane W3a) (NotImplemented)";

/// How the scripted vault answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Vault {
    /// Reports the genesis epoch on every `Epoch` request and answers every
    /// query. Key commands ask nothing else.
    Genesis,
    /// Every request fails as unavailable (NOTE 2).
    Unavailable,
}

/// One ledger entry as the store holds it, after decryption.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Stored {
    seq: u64,
    at: i64,
    command: [u8; 16],
    record: CellRecord,
}

/// What a run produced: one result per submitted command, in submission
/// order, and the whole store after the last result.
#[derive(Debug)]
struct Run {
    results: Vec<Result<Done, ExecError>>,
    ledger: Vec<Stored>,
}

/// The scripted vault of these tests, as the engine reaches it.
struct ScriptedVault(Vault);

impl VaultClient for ScriptedVault {
    fn epoch(&self) -> impl Future<Output = Result<VaultEpoch, VaultFault>> + Send {
        std::future::ready(match self.0 {
            Vault::Genesis => Ok(VaultEpoch::GENESIS),
            Vault::Unavailable => Err(VaultFault::Unavailable),
        })
    }

    fn ask(
        &self,
        queries: &[Query],
        _reaction_for: Option<VaultEpoch>,
        _at: Timestamp,
    ) -> impl Future<Output = Result<Answers, VaultFault>> + Send {
        let r = match self.0 {
            Vault::Unavailable => Err(VaultFault::Unavailable),
            Vault::Genesis => {
                let mut a = Answers::new();
                for q in queries {
                    let accounts = matches!(q, Query::ChangedSince { .. }).then(BTreeSet::new);
                    a.insert(
                        q.clone(),
                        Answer {
                            holds: false,
                            accounts,
                            epoch: VaultEpoch::GENESIS,
                            digest: ContentDigest::from_bytes([0; 32]),
                        },
                    );
                }
                Ok(a)
            }
        };
        std::future::ready(r)
    }

    fn ack(
        &self,
        _epoch: VaultEpoch,
        _seq: Seq,
        _link: [u8; 32],
    ) -> impl Future<Output = Result<(), VaultFault>> + Send {
        std::future::ready(match self.0 {
            Vault::Genesis => Ok(()),
            Vault::Unavailable => Err(VaultFault::Unavailable),
        })
    }
}

/// The cell id of these tests.
const CELL: [u8; 16] = [0xCE; 16];

fn runtime() -> Result<TokioRuntime, &'static str> {
    TokioRuntime::new_multi_thread(2).map_err(|_| "the tokio runtime did not start")
}

fn exec_result(r: Result<Done, EngineError>) -> Result<Result<Done, ExecError>, &'static str> {
    match r {
        Ok(d) => Ok(Ok(d)),
        Err(EngineError::Exec(e)) => Ok(Err(e)),
        Err(EngineError::ShuttingDown) => Err("the engine refused as shutting down"),
        Err(EngineError::Stopped) => Err("the engine task stopped"),
    }
}

/// The whole store as [`Stored`] entries.
async fn whole(store: &Unanchored<MemStore<CellRecord>>) -> Result<Vec<Stored>, &'static str> {
    let entries = read_after(store, Seq::ZERO)
        .await
        .map_err(|_| "the store read failed")?;
    Ok(entries
        .into_iter()
        .map(|e| Stored {
            seq: e.seq.raw(),
            at: e.at,
            command: e.command,
            record: e.record,
        })
        .collect())
}

/// Runs `admitted` in order on a fresh engine over `store` and gives the
/// results and the store back.
async fn run_on(
    rt: &TokioRuntime,
    store: Unanchored<MemStore<CellRecord>>,
    vault: Vault,
    admitted: &[Admitted],
) -> Result<
    (
        Vec<Result<Done, ExecError>>,
        Unanchored<MemStore<CellRecord>>,
    ),
    &'static str,
> {
    let shutdown = Shutdown::new();
    let (engine, task) = CellEngine::start(rt, store, ScriptedVault(vault), &shutdown, 16)
        .await
        .map_err(|_| "the engine did not start")?;
    let mut results = Vec::new();
    for a in admitted {
        results.push(exec_result(engine.execute(a.clone()).await)?);
    }
    drop(engine);
    let store = task.await.map_err(|_| "the engine task failed")?;
    Ok((results, store))
}

/// Seam: starts `CellEngine` over an empty `MemStore` and `vault`, sends
/// each admitted command through `CellEngine::execute` in order, waits for
/// each result before the next, then reads the whole store.
fn run_engine(vault: Vault, admitted: &[Admitted]) -> Result<Run, &'static str> {
    let rt = runtime()?;
    let rt2 = rt.clone();
    rt.block_on(async move {
        let store = Unanchored::open(MemStore::new(), CELL)
            .await
            .map_err(|_| "the store did not open")?;
        let (results, store) = run_on(&rt2, store, vault, admitted).await?;
        let ledger = whole(&store).await?;
        Ok(Run { results, ledger })
    })
}

/// Seam: as [`run_engine`], but `callers` handler tasks submit the
/// commands at the same time over the engine's bounded channel. Caller
/// `k` submits the commands at positions `k`, `k + callers`, and so on.
/// The results stay in the order of `admitted`.
fn run_engine_concurrently(
    vault: Vault,
    admitted: &[Admitted],
    callers: usize,
) -> Result<Run, &'static str> {
    let rt = runtime()?;
    let rt2 = rt.clone();
    let admitted = admitted.to_vec();
    rt.block_on(async move {
        let store = Unanchored::open(MemStore::new(), CELL)
            .await
            .map_err(|_| "the store did not open")?;
        let shutdown = Shutdown::new();
        let (engine, task) = CellEngine::start(&rt2, store, ScriptedVault(vault), &shutdown, 4)
            .await
            .map_err(|_| "the engine did not start")?;
        let mut handles = Vec::new();
        for k in 0..callers.max(1) {
            let mine: Vec<(usize, Admitted)> = admitted
                .iter()
                .cloned()
                .enumerate()
                .skip(k)
                .step_by(callers.max(1))
                .collect();
            let e = engine.clone();
            handles.push(rt2.spawn(async move {
                let mut out = Vec::new();
                for (i, a) in mine {
                    out.push((i, e.execute(a).await));
                }
                out
            }));
        }
        let mut slots: Vec<Option<Result<Done, ExecError>>> = vec![None; admitted.len()];
        for h in handles {
            for (i, r) in h.await.map_err(|_| "a caller task failed")? {
                slots[i] = Some(exec_result(r)?);
            }
        }
        drop(engine);
        let store = task.await.map_err(|_| "the engine task failed")?;
        let results = slots
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or("a caller lost a result")?;
        let ledger = whole(&store).await?;
        Ok(Run { results, ledger })
    })
}

/// Seam: runs `before` as [`run_engine`] does, drops the engine, starts a
/// new `CellEngine` over the same `MemStore`, which replays it (design
/// section 5.5), and runs `after`. The results are those of `after`. The
/// ledger is the whole store at the end.
fn run_engine_with_restart(
    vault: Vault,
    before: &[Admitted],
    after: &[Admitted],
) -> Result<Run, &'static str> {
    let rt = runtime()?;
    let rt2 = rt.clone();
    rt.block_on(async move {
        let store = Unanchored::open(MemStore::new(), CELL)
            .await
            .map_err(|_| "the store did not open")?;
        let (_, store) = run_on(&rt2, store, vault, before).await?;
        // A restart keeps only the stored ledger: the links are computed
        // again from it, and the engine replays it.
        let store = Unanchored::open(store.into_inner(), CELL)
            .await
            .map_err(|_| "the store did not open again")?;
        let (results, store) = run_on(&rt2, store, vault, after).await?;
        let ledger = whole(&store).await?;
        Ok(Run { results, ledger })
    })
}

/// The canonical record bytes of a ledger, in sequence order.
type Ledger = Vec<Vec<u8>>;

/// Seam: the M2 generators of `fstp-domain-testkit` run through
/// `fstp_engine::Engine<MemStore, SyntheticVault>` and through `CellEngine`
/// over `MemStore` and the same synthetic vault. Returns the canonical
/// record bytes of each ledger, the engine's first.
fn m2_generator_ledgers() -> Result<(Ledger, Ledger), &'static str> {
    Err(M2_EQUIVALENCE_SEAM)
}

/// A key operation as the erasure runner records it: a canonical JSON
/// object (design section 3.5, ADR-004 Reconciliation).
fn key_op(n: u32) -> Vec<u8> {
    format!("{{\"n\":{n}}}").into_bytes()
}

/// The erasure runner's command id with suffix `n`.
fn runner_id(n: u8) -> [u8; 16] {
    system_command_id([b'k', b'e', b'y', b'o', b'p', b'-', b'0', n])
}

/// Admits `RecordKeyOp { op }` for the erasure runner under `id`, at the
/// genesis instant.
fn admit_key_op(op: Vec<u8>, id: [u8; 16]) -> Admitted {
    let s = CellState::genesis();
    gate::admit_system(
        &s,
        Action::Command(CellCommand::Key(KeyCommand::RecordKeyOp { op })),
        SystemTask::ErasureRunner,
        id,
        s.now_floor(),
    )
    .unwrap()
}

/// The expected run of `commands` from an empty store: each new id
/// appends one `KeyOpRecorded` at the next sequence, and a repeated id
/// appends nothing and reports the entry of its first commit. Results are
/// `(head, duplicate)`.
fn expected(commands: &[(Vec<u8>, [u8; 16])]) -> (Vec<(u64, Option<u64>)>, Vec<Stored>) {
    let mut ledger: Vec<Stored> = Vec::new();
    let mut first: BTreeMap<[u8; 16], u64> = BTreeMap::new();
    let mut results = Vec::new();
    for (op, id) in commands {
        let head = ledger.len() as u64;
        if let Some(at) = first.get(id) {
            results.push((head, Some(*at)));
            continue;
        }
        let seq = head + 1;
        first.insert(*id, seq);
        ledger.push(Stored {
            seq,
            at: 0,
            command: *id,
            record: CellRecord::Key(KeyRecord::KeyOpRecorded { op: op.clone() }),
        });
        results.push((seq, None));
    }
    (results, ledger)
}

/// `(head, duplicate)` of each result, or the error text.
fn heads(results: &[Result<Done, ExecError>]) -> Result<Vec<(u64, Option<u64>)>, String> {
    results
        .iter()
        .map(|r| match r {
            Ok(d) => Ok((d.head.raw(), d.duplicate.map(|s| s.raw()))),
            Err(e) => Err(format!("a key command failed: {e:?}")),
        })
        .collect()
}

/// I-23, ADR-007, design section 5.2: over any sequence of erasure-runner
/// commands, some of them retries under an earlier id, the engine commits
/// each new id once, in order, from sequence 1 without gaps. A retry
/// appends nothing and reports the stored entry as a duplicate.
#[test]
fn i23_cell_engine_commits_each_command_id_once_in_order() {
    fstp_prop::check_with(
        "i23_cell_engine_commits_each_command_id_once_in_order",
        Config::default().with_cases(64),
        |g| {
            let commands: Vec<(Vec<u8>, [u8; 16])> = g.vec(1..=8, |g| {
                let n = g.u32_in(0..=3);
                (key_op(n), runner_id(g.u8_in(0..=3)))
            });
            g.note("commands", &commands);
            let admitted: Vec<Admitted> = commands
                .iter()
                .map(|(op, id)| admit_key_op(op.clone(), *id))
                .collect();
            let run = run_engine(Vault::Genesis, &admitted).map_err(str::to_owned)?;
            let (want_results, want_ledger) = expected(&commands);
            prop_assert_eq!(heads(&run.results)?, want_results);
            prop_assert_eq!(run.ledger, want_ledger);
            Ok(())
        },
    );
}

/// NOTE 2, design section 5.2: when the vault cannot answer, the engine
/// fails the command closed and appends nothing.
#[test]
fn seam_note2_cell_engine_vault_fault_fails_closed_and_appends_nothing() {
    let admitted = [admit_key_op(key_op(1), runner_id(1))];
    let run = run_engine(Vault::Unavailable, &admitted).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        matches!(run.results.as_slice(), [Err(ExecError::VaultFault)]) && run.ledger.is_empty(),
        "results {:?}, ledger {:?}",
        run.results,
        run.ledger
    );
}

/// I-23, design section 5.2: a system task's command must carry an id in
/// the system namespace. The engine passes the driver's refusal through
/// and appends nothing.
#[test]
fn i23_cell_engine_refuses_a_system_command_outside_the_system_namespace() {
    let id = [0x42; 16];
    assert!(!is_system_command_id(id));
    let admitted = [admit_key_op(key_op(1), id)];
    let run = run_engine(Vault::Genesis, &admitted).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        matches!(
            run.results.as_slice(),
            [Err(ExecError::NotASystemCommandId)]
        ) && run.ledger.is_empty(),
        "results {:?}, ledger {:?}",
        run.results,
        run.ledger
    );
}

/// ADR-007, design section 5.2 ("Single writer"): one engine task owns
/// the state and runs one driver at a time. Many handlers submitting at
/// once get one commit each, at distinct sequences from 1 without gaps,
/// and each result names its own entry.
#[test]
fn adr007_cell_engine_single_writer_serialises_concurrent_callers() {
    let admitted: Vec<Admitted> = (0..32u8)
        .map(|n| admit_key_op(key_op(u32::from(n)), runner_id(n)))
        .collect();
    let run =
        run_engine_concurrently(Vault::Genesis, &admitted, 8).unwrap_or_else(|e| panic!("{e}"));
    let seqs: Vec<u64> = run.ledger.iter().map(|e| e.seq).collect();
    let mut by_command: BTreeMap<[u8; 16], u64> = BTreeMap::new();
    for e in &run.ledger {
        by_command.insert(e.command, e.seq);
    }
    let own_entry = admitted.iter().zip(&run.results).all(|(a, r)| {
        let id = a.command_id().unwrap();
        matches!(r, Ok(d) if d.duplicate.is_none() && by_command.get(&id) == Some(&d.head.raw()))
    });
    assert!(
        seqs == (1..=32).collect::<Vec<u64>>() && by_command.len() == 32 && own_entry,
        "seqs {seqs:?}, results {:?}",
        run.results
    );
}

/// I-23, ADR-007, design section 5.5: a restarted engine replays its
/// store. A crash retry under a committed id is then a duplicate of the
/// stored entry, and a new command commits after the replayed head.
#[test]
fn i23_cell_engine_restart_replays_the_store_and_keeps_retries_duplicates() {
    let before = [
        admit_key_op(key_op(1), runner_id(1)),
        admit_key_op(key_op(2), runner_id(2)),
    ];
    let after = [
        admit_key_op(key_op(1), runner_id(1)),
        admit_key_op(key_op(3), runner_id(3)),
    ];
    let run =
        run_engine_with_restart(Vault::Genesis, &before, &after).unwrap_or_else(|e| panic!("{e}"));
    let got = heads(&run.results).unwrap_or_else(|e| panic!("{e}"));
    let seqs: Vec<u64> = run.ledger.iter().map(|e| e.seq).collect();
    assert!(
        got == vec![(2, Some(1)), (3, None)] && seqs == vec![1, 2, 3],
        "results {got:?}, ledger {seqs:?}"
    );
}

/// Design sections 5.2 and 14.6, I-23: the M2 generators through
/// `CellEngine` over the in-memory store give the same ledger, byte for
/// byte, as through the M2 reference engine.
#[test]
fn seam_cell_engine_matches_reference_engine_over_mem_store() {
    let (engine, reference) = m2_generator_ledgers().unwrap_or_else(|e| panic!("{e}"));
    assert!(
        !reference.is_empty() && engine == reference,
        "the cell engine's ledger differs from the M2 engine's ({} against {} records)",
        engine.len(),
        reference.len()
    );
}

/// The expected ledger itself: a retry under an earlier id appends
/// nothing. This checks the reference above, so a wrong expectation
/// cannot make the engine tests pass.
#[test]
fn i23_reference_counts_a_retry_as_a_duplicate() {
    let commands = vec![
        (key_op(1), runner_id(1)),
        (key_op(2), runner_id(1)),
        (key_op(2), runner_id(2)),
    ];
    let (results, ledger) = expected(&commands);
    let ok = results == vec![(1, None), (1, Some(1)), (2, None)]
        && ledger.len() == 2
        && ledger.iter().all(|e| is_system_command_id(e.command));
    assert!(ok, "results {results:?}, ledger {ledger:?}");
}
