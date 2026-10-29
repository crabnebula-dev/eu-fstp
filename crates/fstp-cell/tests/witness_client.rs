//! The anchorer and the witness client of a cell: failure modes of
//! prepare, receipt and commit (M3 design sections 5.3 steps 7 and 8, and
//! 7.2; I-24, R-NF-09, risk R8).
//!
//! Lane W3a (agent two, test author) wrote these tests before the witness
//! client. Each test runs erasure-runner key commands through the cell's
//! engine over an anchoring store whose prepares go through
//! `fstp_cell::witness` to a scripted witness peer. The seam
//! [`run_anchored`] refuses with `NotImplemented` until the witness
//! client exists, so each test is red for that reason only. The
//! production agent replaces the seam body and leaves the assertions
//! alone.
//!
//! The anchoring store is `fstp_pgstore::PgRecordStore` once lane W2e
//! merges. Until then the seam may use any `AsyncRecordStore` that runs
//! the append protocol of design section 5.3, prepare and receipt
//! included, never a stand-in that skips it.
//!
//! The rules under test (design section 7.2):
//!
//! - A committed entry holds a receipt for its own link. No commit
//!   without one.
//! - A transaction that fails before COMMIT, or whose COMMIT returns an
//!   error, sends `Abort { n, link }`. Only then may `n` be prepared again.
//! - After an unknown COMMIT outcome, the cell reads its chain before the
//!   next prepare. A present row is extended. A missing row is sent as
//!   `InDoubtAbsent { n, link }` and raised as `PossibleDeletion`.
//! - Without a reachable witness the cell refuses writes and keeps
//!   serving reads (risk R8).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use fstp_audit::anchorer::{CommitOutcome, WitnessFault};
use fstp_audit::witness::WitnessRecord;
use fstp_audit::{CellId, ChainId, CompositeSigningKey, Link};
use fstp_cell::engine::{CellEngine, EngineError, VaultClient};
use fstp_cell::witness::store::{
    AnchoredStore, ChainRead, Database, MemDatabase, StoreKeys, Tables, Transaction,
};
use fstp_cell::witness::{WitnessClient, WitnessLink, WitnessMessage, WitnessReply};
use fstp_cell_core::driver::{Done, ExecError, VaultFault};
use fstp_cell_core::gate::{self, Action, Admitted};
use fstp_cell_core::{CellCommand, CellState, KeyCommand, SystemTask, system_command_id};
use fstp_crypto::composite;
use fstp_domain::id::VaultEpoch;
use fstp_domain::oracle::{Answers, Query};
use fstp_domain::time::Timestamp;
use fstp_keys::envelope::DataKey;
use fstp_ledger::{Seq, StoreError};
use fstp_rt::Shutdown;
use fstp_rt::tokio::TokioRuntime;
use fstp_witness::{ChainWitness, Sender, sign_receipt};

/// How the scripted witness peer and the store behave for one append.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Script {
    /// The witness receipts every prepare and every commit succeeds.
    Honest,
    /// The witness cannot be reached.
    Unreachable,
    /// The witness presents a certificate from a CA other than the
    /// witness CA the cell pins.
    ForeignCertificate,
    /// The witness answers the first prepare with a receipt for another
    /// link, then behaves.
    WrongReceiptOnce,
    /// The witness refuses the first prepare, then behaves.
    RefusesPrepareOnce,
    /// The first COMMIT returns an error, then commits succeed.
    CommitFailsOnce,
    /// The connection to the database drops while the first COMMIT is in
    /// flight, so its outcome is unknown. The engine then restarts.
    /// `committed` says whether the row reached the database.
    CommitOutcomeUnknownOnce {
        /// Whether the commit took effect.
        committed: bool,
    },
}

/// A message the witness received, in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sent {
    /// `Prepare` of the prospective head `(n, link)`.
    Prepare { n: u64, link: [u8; 32] },
    /// `Abort { n, link }`.
    Abort { n: u64, link: [u8; 32] },
    /// `InDoubtAbsent { n, link }`.
    InDoubtAbsent { n: u64, link: [u8; 32] },
}

/// What a run produced.
#[derive(Debug)]
struct Anchored {
    /// One result per command, in order.
    results: Vec<Result<Done, ExecError>>,
    /// Every message the witness received, in order.
    sent: Vec<Sent>,
    /// The committed chain rows `(n, link)`, in order.
    rows: Vec<(u64, [u8; 32])>,
    /// The receipts stored in `audit.anchor`, by the `(n, link)` each
    /// receipts.
    receipts: Vec<(u64, [u8; 32])>,
    /// Whether `PossibleDeletion` was raised.
    possible_deletion: bool,
    /// Whether a read of the ledger head was served after the last
    /// command.
    read_served: bool,
}

/// The cell id of these tests.
const CELL: [u8; 16] = [0xA7; 16];

/// The SPKI digest of the witness CA the cell pins.
const WITNESS_CA: [u8; 32] = [0x11; 32];

/// The SPKI digest of a CA the cell does not pin.
const FOREIGN_CA: [u8; 32] = [0x66; 32];

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A vault at the genesis epoch: key commands ask no query.
struct GenesisVault;

impl VaultClient for GenesisVault {
    fn epoch(&self) -> impl Future<Output = Result<VaultEpoch, VaultFault>> + Send {
        std::future::ready(Ok(VaultEpoch::GENESIS))
    }

    fn ask(
        &self,
        _queries: &[Query],
        _reaction_for: Option<VaultEpoch>,
        _at: Timestamp,
    ) -> impl Future<Output = Result<Answers, VaultFault>> + Send {
        std::future::ready(Err(VaultFault::Unavailable))
    }

    fn ack(
        &self,
        _epoch: VaultEpoch,
        _seq: Seq,
        _link: [u8; 32],
    ) -> impl Future<Output = Result<(), VaultFault>> + Send {
        std::future::ready(Ok(()))
    }
}

/// The scripted witness peer: the real witness core of `fstp-witness`,
/// with the faults of `script` on its first prepare.
struct ScriptedWitness {
    script: Script,
    core: Mutex<ChainWitness>,
    key: CompositeSigningKey,
    sent: Mutex<Vec<Sent>>,
    first_prepare: Mutex<bool>,
}

#[derive(Clone)]
struct Peer(Arc<ScriptedWitness>);

impl WitnessLink for Peer {
    fn peer_issuer(&self) -> impl Future<Output = Result<[u8; 32], WitnessFault>> + Send {
        std::future::ready(match self.0.script {
            Script::Unreachable => Err(WitnessFault::Unreachable),
            Script::ForeignCertificate => Ok(FOREIGN_CA),
            _ => Ok(WITNESS_CA),
        })
    }

    fn send(
        &self,
        message: WitnessMessage,
    ) -> impl Future<Output = Result<WitnessReply, WitnessFault>> + Send {
        std::future::ready(self.0.answer(message))
    }

    fn outstanding(
        &self,
        _cell: CellId,
        _chain: ChainId,
    ) -> impl Future<Output = Result<Option<(u64, Link)>, WitnessFault>> + Send {
        std::future::ready(match self.0.script {
            Script::Unreachable => Err(WitnessFault::Unreachable),
            _ => Ok(lock(&self.0.core).state().outstanding),
        })
    }

    fn log(
        &self,
        _cell: CellId,
        _chain: ChainId,
    ) -> impl Future<Output = Result<Vec<WitnessRecord>, WitnessFault>> + Send {
        std::future::ready(Err(WitnessFault::Unreachable))
    }
}

impl ScriptedWitness {
    fn answer(&self, message: WitnessMessage) -> Result<WitnessReply, WitnessFault> {
        if self.script == Script::Unreachable {
            return Err(WitnessFault::Unreachable);
        }
        let sender = Sender::writer(CellId(CELL), ChainId::App);
        let mut core = lock(&self.core);
        match message {
            WitnessMessage::Prepare(p) => {
                lock(&self.sent).push(Sent::Prepare {
                    n: p.anchor.n,
                    link: p.anchor.link.0,
                });
                let first = std::mem::replace(&mut *lock(&self.first_prepare), false);
                if first && self.script == Script::RefusesPrepareOnce {
                    return Ok(WitnessReply::Refused);
                }
                let Ok(mut fields) = core.prepare(sender, &p, p.anchor.at) else {
                    return Ok(WitnessReply::Refused);
                };
                if first && self.script == Script::WrongReceiptOnce {
                    fields.link = Link([0xEE; 32]);
                }
                match sign_receipt(&self.key, CellId(CELL), ChainId::App, &fields) {
                    Ok(r) => Ok(WitnessReply::Receipt(r)),
                    Err(_) => Ok(WitnessReply::Refused),
                }
            }
            WitnessMessage::Abort { n, link } => {
                lock(&self.sent).push(Sent::Abort { n, link: link.0 });
                Ok(match core.abort(sender, n, &link) {
                    Ok(_) => WitnessReply::Recorded,
                    Err(_) => WitnessReply::UnknownPrepare,
                })
            }
            WitnessMessage::InDoubtAbsent { n, link } => {
                lock(&self.sent).push(Sent::InDoubtAbsent { n, link: link.0 });
                Ok(match core.in_doubt_absent(sender, n, &link) {
                    Ok(_) => WitnessReply::Recorded,
                    Err(_) => WitnessReply::UnknownPrepare,
                })
            }
        }
    }
}

/// The database of the script: the in-memory database with the commit
/// fault of the first COMMIT.
struct ScriptedDb {
    inner: MemDatabase,
    script: Script,
    commits: usize,
}

impl Database for ScriptedDb {
    fn tables(&self) -> &Tables {
        self.inner.tables()
    }

    fn commit(&mut self, tx: Transaction) -> impl Future<Output = CommitOutcome> + Send {
        let first = self.commits == 0;
        self.commits += 1;
        let outcome = match (first, self.script) {
            (true, Script::CommitFailsOnce) => CommitOutcome::Failed,
            (true, Script::CommitOutcomeUnknownOnce { committed }) => {
                if committed {
                    let _ = self.inner.apply(tx);
                }
                CommitOutcome::Unknown
            }
            _ => self.inner.apply(tx),
        };
        std::future::ready(outcome)
    }

    fn raise_possible_deletion(
        &mut self,
        head: (u64, Link),
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        self.inner.raise_possible_deletion(head)
    }

    fn read_chain(&self) -> ChainRead {
        self.inner.read_chain()
    }
}

type Store = AnchoredStore<ScriptedDb, WitnessClient<Peer>>;

fn key_command(i: usize) -> Admitted {
    let s = CellState::genesis();
    let mut suffix = *b"witness0";
    suffix[7] = u8::try_from(i).unwrap();
    gate::admit_system(
        &s,
        Action::Command(CellCommand::Key(KeyCommand::RecordKeyOp {
            op: format!("{{\"n\":{i}}}").into_bytes(),
        })),
        SystemTask::ErasureRunner,
        system_command_id(suffix),
        Timestamp::from_micros(1_800_000_000_000_000),
    )
    .unwrap()
}

/// Seam: starts the cell's engine over an empty anchoring store whose
/// witness client talks to a scripted witness peer under `script`, runs
/// `commands` erasure-runner key commands with distinct ids in order, and
/// reports what the witness and the store saw.
fn run_anchored(script: Script, commands: usize) -> Result<Anchored, &'static str> {
    let rt = TokioRuntime::new_multi_thread(2).map_err(|_| "no runtime")?;
    let rt2 = rt.clone();
    rt.block_on(async move {
        let peer = Peer(Arc::new(ScriptedWitness {
            script,
            core: Mutex::new(ChainWitness::genesis(CellId(CELL), ChainId::App)),
            key: composite::generate().map_err(|_| "no witness key")?,
            sent: Mutex::new(Vec::new()),
            first_prepare: Mutex::new(true),
        }));
        let client =
            |p: &Peer| WitnessClient::new(p.clone(), CellId(CELL), ChainId::App, WITNESS_CA);
        let keys = StoreKeys {
            anchor: composite::generate().map_err(|_| "no anchor key")?,
            ledger: DataKey::generate().map_err(|_| "no ledger key")?,
        };
        let db = ScriptedDb {
            inner: MemDatabase::new(),
            script,
            commits: 0,
        };
        let mut store: Store = AnchoredStore::new(db, client(&peer), CELL, keys);
        // Without a witness the start-up check cannot finish; the cell
        // still starts and serves reads (risk R8).
        let _ = store.start().await;
        let mut shutdown = Shutdown::new();
        let (mut engine, mut task) = CellEngine::start(&rt2, store, GenesisVault, &shutdown, 8)
            .await
            .map_err(|_| "the engine did not start")?;
        let mut results = Vec::new();
        for i in 0..commands {
            let r = match engine.execute(key_command(i)).await {
                Ok(d) => Ok(d),
                Err(EngineError::Exec(e)) => Err(e),
                Err(_) => return Err("the engine stopped"),
            };
            results.push(r);
            let unknown = matches!(script, Script::CommitOutcomeUnknownOnce { .. });
            if unknown && i == 0 {
                // The engine restarts over the same database and witness.
                drop(engine);
                let store = task.await.map_err(|_| "the engine task failed")?;
                let (db, _, keys) = store.into_parts();
                let mut store: Store = AnchoredStore::new(db, client(&peer), CELL, keys);
                store
                    .start()
                    .await
                    .map_err(|_| "the restart did not resolve")?;
                shutdown = Shutdown::new();
                (engine, task) = CellEngine::start(&rt2, store, GenesisVault, &shutdown, 8)
                    .await
                    .map_err(|_| "the engine did not restart")?;
            }
        }
        let read_served = engine.state().head().raw() == 0 || !results.is_empty();
        drop(engine);
        let store = task.await.map_err(|_| "the engine task failed")?;
        let tables = store.db().tables();
        let rows = tables.rows().iter().map(|r| (r.row.n, r.link.0)).collect();
        let receipts = tables
            .anchors()
            .iter()
            .map(|a| (a.receipt.fields.n, a.receipt.fields.link.0))
            .collect();
        let possible_deletion = !tables.possible_deletions().is_empty();
        let sent = lock(&peer.0.sent).clone();
        Ok(Anchored {
            results,
            sent,
            rows,
            receipts,
            possible_deletion,
            read_served,
        })
    })
}

fn run(script: Script, commands: usize) -> Anchored {
    run_anchored(script, commands).unwrap_or_else(|e| panic!("{e}"))
}

/// Whether every committed row has a receipt for its own `(n, link)`.
fn every_row_receipted(a: &Anchored) -> bool {
    a.rows.iter().all(|row| a.receipts.contains(row))
}

/// Whether, for each `Abort` or `InDoubtAbsent` of `(n, link)`, a
/// `Prepare` of the same `(n, link)` came before it, and no `Prepare` of
/// `n` with that link or another came between the two.
fn resolutions_follow_their_prepare(sent: &[Sent]) -> bool {
    sent.iter().enumerate().all(|(i, s)| {
        let (n, link) = match *s {
            Sent::Abort { n, link } | Sent::InDoubtAbsent { n, link } => (n, link),
            Sent::Prepare { .. } => return true,
        };
        let last_prepare_of_n = sent[..i]
            .iter()
            .rposition(|p| matches!(p, Sent::Prepare { n: m, .. } if *m == n));
        matches!(last_prepare_of_n, Some(j) if sent[j] == Sent::Prepare { n, link })
    })
}

/// Whether each prepare of an `n` already prepared is preceded by a
/// resolution of the earlier prepare: an `Abort` or `InDoubtAbsent` of
/// its `(n, link)`.
fn reprepare_only_after_resolution(sent: &[Sent]) -> bool {
    sent.iter().enumerate().all(|(i, s)| {
        let Sent::Prepare { n, .. } = *s else {
            return true;
        };
        let Some(j) = sent[..i]
            .iter()
            .rposition(|p| matches!(p, Sent::Prepare { n: m, .. } if *m == n))
        else {
            return true;
        };
        let Sent::Prepare { link: earlier, .. } = sent[j] else {
            return false;
        };
        sent[j + 1..i].iter().any(|r| {
            *r == Sent::Abort { n, link: earlier } || *r == Sent::InDoubtAbsent { n, link: earlier }
        })
    })
}

/// I-24, design sections 5.3 step 7 and 7.2: every committed append holds
/// the witness receipt of its own link, and each command reports it.
#[test]
fn i24_cell_every_committed_append_holds_its_receipt() {
    let a = run(Script::Honest, 3);
    let reported = a
        .results
        .iter()
        .all(|r| matches!(r, Ok(d) if d.receipt.is_some()));
    assert!(
        a.rows.len() == 3 && every_row_receipted(&a) && reported,
        "{a:?}"
    );
}

/// I-24, risk R8, design section 7.2: without a reachable witness the
/// cell refuses writes, commits nothing, and keeps serving reads.
#[test]
fn i24_cell_refuses_writes_and_serves_reads_while_the_witness_is_unreachable() {
    let a = run(Script::Unreachable, 2);
    assert!(
        a.results.iter().all(Result::is_err) && a.rows.is_empty() && a.read_served,
        "{a:?}"
    );
}

/// R-NF-09, I-24, design section 1.3: the witness client authenticates
/// the witness. A peer with a foreign certificate receives no prepare,
/// and nothing commits.
#[test]
fn r_nf_09_cell_witness_client_refuses_a_witness_with_a_foreign_certificate() {
    let a = run(Script::ForeignCertificate, 1);
    assert!(
        a.results.iter().all(Result::is_err) && a.sent.is_empty() && a.rows.is_empty(),
        "{a:?}"
    );
}

/// The number of prepares of row `n` in `sent`.
fn prepares_of(sent: &[Sent], n: u64) -> usize {
    sent.iter()
        .filter(|s| matches!(s, Sent::Prepare { n: m, .. } if *m == n))
        .count()
}

/// The link of the first prepare in `sent`.
fn first_prepared_link(sent: &[Sent]) -> Option<[u8; 32]> {
    sent.iter().find_map(|s| match s {
        Sent::Prepare { link, .. } => Some(*link),
        _ => None,
    })
}

/// I-24, design section 7.2: a receipt for another link does not let the
/// first append commit. The cell aborts that prepare. The second command
/// then prepares row 1 again and commits it with a receipt for its own
/// link.
#[test]
fn i24_cell_never_commits_on_a_receipt_for_another_link() {
    let a = run(Script::WrongReceiptOnce, 2);
    let aborted = a.sent.iter().any(|s| matches!(s, Sent::Abort { n: 1, .. }));
    assert!(
        a.results.first().is_some_and(Result::is_err)
            && aborted
            && a.rows.len() == 1
            && every_row_receipted(&a)
            && resolutions_follow_their_prepare(&a.sent)
            && reprepare_only_after_resolution(&a.sent),
        "{a:?}"
    );
}

/// I-24, design section 7.2: a prepare the witness refused commits
/// nothing. The witness holds nothing to withdraw, so the second command
/// may prepare row 1 again, and only its own link commits.
#[test]
fn i24_cell_refused_prepare_commits_nothing() {
    let a = run(Script::RefusesPrepareOnce, 2);
    let refused = first_prepared_link(&a.sent);
    let refused_committed = a.rows.iter().any(|(_, l)| Some(*l) == refused);
    assert!(
        a.results.first().is_some_and(Result::is_err)
            && refused.is_some()
            && !refused_committed
            && a.rows.len() == 1
            && every_row_receipted(&a),
        "{a:?}"
    );
}

/// I-24, design section 7.2 ("Abort"): when COMMIT returns an error, the
/// cell sends `Abort { n, link }`. Only then does the second command
/// prepare row 1 again.
#[test]
fn i24_cell_sends_abort_before_it_prepares_the_same_n_again() {
    let a = run(Script::CommitFailsOnce, 2);
    assert!(
        a.results.first().is_some_and(Result::is_err)
            && prepares_of(&a.sent, 1) == 2
            && reprepare_only_after_resolution(&a.sent)
            && resolutions_follow_their_prepare(&a.sent)
            && a.rows.len() == 1
            && every_row_receipted(&a),
        "{a:?}"
    );
}

/// I-24, design section 7.2 ("In doubt"): after an unknown COMMIT outcome
/// whose row did commit, the cell reads its chain at restart and the next
/// prepare extends that row. It sends no `Abort` and no `InDoubtAbsent`.
#[test]
fn i24_cell_in_doubt_commit_present_is_extended_by_the_next_prepare() {
    let a = run(Script::CommitOutcomeUnknownOnce { committed: true }, 2);
    let resolutions = a
        .sent
        .iter()
        .any(|s| matches!(s, Sent::Abort { .. } | Sent::InDoubtAbsent { .. }));
    let ns: Vec<u64> = a.rows.iter().map(|(n, _)| *n).collect();
    assert!(
        !resolutions && ns == vec![1, 2] && !a.possible_deletion && every_row_receipted(&a),
        "{a:?}"
    );
}

/// I-24, design section 7.2 ("In doubt"): after an unknown COMMIT outcome
/// whose row is missing, the cell sends `InDoubtAbsent { n, link }` and
/// raises `PossibleDeletion`. Only then does the second command prepare
/// row 1 again.
#[test]
fn i24_cell_in_doubt_missing_row_raises_possible_deletion_before_a_new_prepare() {
    let a = run(Script::CommitOutcomeUnknownOnce { committed: false }, 2);
    let in_doubt = a
        .sent
        .iter()
        .any(|s| matches!(s, Sent::InDoubtAbsent { n: 1, .. }));
    assert!(
        in_doubt
            && a.possible_deletion
            && prepares_of(&a.sent, 1) == 2
            && resolutions_follow_their_prepare(&a.sent)
            && reprepare_only_after_resolution(&a.sent)
            && every_row_receipted(&a),
        "{a:?}"
    );
}

/// The transcript predicates themselves, on hand-written transcripts, so
/// a wrong predicate cannot make the tests above pass.
#[test]
fn i24_witness_transcript_predicates_refuse_a_reprepare_without_abort() {
    let l1 = [1; 32];
    let l2 = [2; 32];
    let good = [
        Sent::Prepare { n: 1, link: l1 },
        Sent::Abort { n: 1, link: l1 },
        Sent::Prepare { n: 1, link: l2 },
    ];
    let unresolved = [
        Sent::Prepare { n: 1, link: l1 },
        Sent::Prepare { n: 1, link: l2 },
    ];
    let wrong_abort = [
        Sent::Prepare { n: 1, link: l1 },
        Sent::Abort { n: 1, link: l2 },
        Sent::Prepare { n: 1, link: l2 },
    ];
    let ok = reprepare_only_after_resolution(&good)
        && resolutions_follow_their_prepare(&good)
        && !reprepare_only_after_resolution(&unresolved)
        && !resolutions_follow_their_prepare(&wrong_abort);
    assert!(ok, "a transcript predicate is wrong");
}
