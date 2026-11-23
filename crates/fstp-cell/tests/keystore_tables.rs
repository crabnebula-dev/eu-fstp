//! The keystore of the App chain in its tables (ADR-004, decided by Daniel
//! on 2026-11-20; production MCP design section 3.5). Lane L3.
//!
//! A process restart reads the keystore from its tables only. These tests
//! run the real erasure runner over an in-memory engine and a table sink
//! that applies each batch as `fstp_pgstore::KeystoreTables` does, one
//! batch whole or not at all. A "restart" drops the runner and loads a new
//! one from the rows through the start-up path of `start_pg`: the
//! start-up unwrap, the group secrets, then `from_open`. The PostgreSQL
//! side of the same rows is tested in `fstp-pgstore/tests/keystore_tables.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod stepup_common;

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use fstp_auth::{Method, SessionView};
use fstp_cell::CellError;
use fstp_cell::engine::{CellEngine, Unanchored, VaultClient};
use fstp_cell::tasks::erasure::snapshot::{self, root_ref, seal_key_aad, wrapped_of};
use fstp_cell::tasks::erasure::{
    ErasureRunner, Keystore, KeystoreSink, LoginEmailSet, OpenRefusal, SinkFuture, display_key,
};
use fstp_cell_core::driver::VaultFault;
use fstp_cell_core::gate::{self, Action, HighRiskAction, LoginPolicy, StepUpView};
use fstp_cell_core::tenant::TenantCommand;
use fstp_cell_core::text::TextCommand;
use fstp_cell_core::{CellCommand, CellRecord, action_digest};
use fstp_crypto::aead;
use fstp_custody::{
    Aad, BackendId, Custody as CustodyBackend, CustodyError, CustodyHandle, DestroyReceipt,
    EcdsaSignature, Refusal, RootLabel, RootRef, SealKey, SignKeyRef, UsageCursor, UsagePage,
    WrappedSealKey,
};
use fstp_domain::id::{AccountId, VaultEpoch};
use fstp_domain::oracle::{Answers, Query};
use fstp_domain::time::Timestamp;
use fstp_keys::Purpose;
use fstp_ledger::{MemStore, Seq};
use fstp_pgstore::{
    ChainRow, Change, DataKeyRow, DisplayNameRow, GroupKeyRow, KeystoreChanges, KeystoreRows,
    KeystoreTextRow, LoginDigestRow, LoginTextRow, RootRow, RootStatus, SignerRow,
};
use fstp_rt::Shutdown;
use fstp_rt::tokio::TokioRuntime;

const CELL: [u8; 16] = [0xE7; 16];
const ADMIN: AccountId = AccountId::from_raw(1);
const SESSION: [u8; 16] = [0x5E; 16];
const GRANT_ADMIN: u8 = 0xA0;
const G1: [u8; 16] = [0x61; 16];
const G2: [u8; 16] = [0x62; 16];
/// T1 and T2 share G1. T1 is the text the tests erase.
const T1: [u8; 16] = [0x71; 16];
const T2: [u8; 16] = [0x72; 16];
const T3: [u8; 16] = [0x73; 16];
const TEXTS: [([u8; 16], [u8; 16], &str); 3] = [
    (G1, T1, "synthetic keystore text one"),
    (G1, T2, "synthetic keystore text two"),
    (G2, T3, "synthetic keystore text three"),
];
const ERASED: AccountId = AccountId::from_raw(0x51);
const LIVE: AccountId = AccountId::from_raw(0x52);
const ERASED_EMAIL: &str = "erased.person@keystore-tables.test";
const LIVE_EMAIL: &str = "live.person@keystore-tables.test";

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

// ---------------------------------------------------------------------------
// Custody: an in-memory simulator that keeps every root key and every seal
// key it wraps, so the tests can look for them in the rows (I-80). A
// destroy retried after a crash answers the same receipt, as `fstp-keyd`
// does (ADR-004 "Built by lane m3/erase-prod").

#[derive(Default)]
struct Sim {
    roots: Mutex<BTreeMap<Vec<u8>, [u8; 32]>>,
    destroyed: Mutex<BTreeSet<Vec<u8>>>,
    made: Mutex<Vec<[u8; 32]>>,
    seals: Mutex<Vec<[u8; 32]>>,
    next: Mutex<u64>,
}

#[derive(Clone, Default)]
struct Custodian(Arc<Sim>);

impl Custodian {
    fn root(&self, root: &RootRef) -> Result<aead::Key, CustodyError> {
        let rk = *lock(&self.0.roots)
            .get(&root.handle.0)
            .ok_or(CustodyError::Refused(Refusal::UnknownRoot))?;
        aead::Key::from_bytes(&rk).map_err(CustodyError::Crypto)
    }

    fn live_roots(&self) -> usize {
        lock(&self.0.roots).len()
    }
}

impl CustodyBackend for Custodian {
    fn create_root(
        &self,
        label: RootLabel,
    ) -> impl Future<Output = Result<RootRef, CustodyError>> + Send {
        let r = (|| {
            let key = fstp_crypto::random_array::<32>().map_err(CustodyError::Crypto)?;
            let handle = {
                let mut n = lock(&self.0.next);
                *n += 1;
                n.to_be_bytes().to_vec()
            };
            lock(&self.0.roots).insert(handle.clone(), key);
            lock(&self.0.made).push(key);
            Ok(RootRef {
                backend: BackendId::Simulator,
                cell: label.cell,
                chain: label.chain,
                epoch: label.epoch,
                handle: CustodyHandle(handle),
            })
        })();
        std::future::ready(r)
    }

    fn wrap(
        &self,
        root: &RootRef,
        key: &SealKey,
        aad: &Aad,
    ) -> impl Future<Output = Result<WrappedSealKey, CustodyError>> + Send {
        let r = (|| {
            let k = self.root(root)?;
            lock(&self.0.seals).push(*key.expose());
            let s = aead::seal(&k, &aad.0, key.expose()).map_err(CustodyError::Crypto)?;
            let mut out = s.nonce.to_vec();
            out.extend_from_slice(&s.body);
            Ok(WrappedSealKey(out))
        })();
        std::future::ready(r)
    }

    fn unwrap(
        &self,
        root: &RootRef,
        w: &WrappedSealKey,
        aad: &Aad,
    ) -> impl Future<Output = Result<SealKey, CustodyError>> + Send {
        let r = (|| {
            let k = self.root(root)?;
            let (nonce, body) =
                w.0.split_first_chunk::<{ aead::NONCE_LEN }>()
                    .ok_or(CustodyError::Refused(Refusal::UnwrapFailed))?;
            let pt = aead::open(&k, nonce, &aad.0, body)
                .map_err(|_| CustodyError::Refused(Refusal::UnwrapFailed))?;
            SealKey::from_slice(pt.as_slice())
        })();
        std::future::ready(r)
    }

    fn destroy(
        &self,
        root: &RootRef,
    ) -> impl Future<Output = Result<DestroyReceipt, CustodyError>> + Send {
        let gone = lock(&self.0.roots).remove(&root.handle.0).is_some();
        let mut destroyed = lock(&self.0.destroyed);
        let r = if gone || destroyed.contains(&root.handle.0) {
            destroyed.insert(root.handle.0.clone());
            Ok(DestroyReceipt(root.handle.0.clone()))
        } else {
            Err(CustodyError::Refused(Refusal::UnknownRoot))
        };
        drop(destroyed);
        std::future::ready(r)
    }

    fn sign(
        &self,
        _key: &SignKeyRef,
        _digest: &[u8; 32],
    ) -> impl Future<Output = Result<EcdsaSignature, CustodyError>> + Send {
        std::future::ready(Err(CustodyError::Refused(Refusal::NoSignKey)))
    }

    fn usage_since(
        &self,
        _root: &RootRef,
        _cursor: UsageCursor,
    ) -> impl Future<Output = Result<UsagePage, CustodyError>> + Send {
        std::future::ready(Ok(UsagePage::default()))
    }
}

// ---------------------------------------------------------------------------
// The table sink: the keystore tables in memory, one batch at a time, as
// `KeystoreTables::apply` writes them in one transaction. A scripted write
// fails whole.

#[derive(Clone, Default)]
struct Tables {
    chain: Option<ChainRow>,
    roots: BTreeMap<u64, RootRow>,
    groups: BTreeMap<([u8; 16], u32), GroupKeyRow>,
    keys: BTreeMap<[u8; 16], DataKeyRow>,
    texts: BTreeMap<[u8; 16], KeystoreTextRow>,
    signers: BTreeMap<(u8, u32), SignerRow>,
    digests: BTreeMap<[u8; 32], LoginDigestRow>,
    logins: BTreeMap<[u8; 16], LoginTextRow>,
    requested: BTreeSet<[u8; 16]>,
    displays: BTreeMap<[u8; 16], DisplayNameRow>,
    /// The `doc.blob` rows deleted, by data key, in write order (lane L39).
    blob_deletes: Vec<[u8; 16]>,
}

fn apply_to<K: Ord + Clone, R: Clone>(
    map: &mut BTreeMap<K, R>,
    changes: &[Change<K, R>],
    key: impl Fn(&R) -> K,
) {
    for c in changes {
        match c {
            Change::Put(r) => {
                map.insert(key(r), r.clone());
            }
            Change::Delete(k) => {
                map.remove(k);
            }
        }
    }
}

impl Tables {
    fn apply(&mut self, c: &KeystoreChanges) {
        if let Some(ch) = &c.chain {
            self.chain = Some(ch.clone());
        }
        apply_to(&mut self.roots, &c.roots, |r| r.epoch);
        apply_to(&mut self.groups, &c.groups, |g| (g.group, g.generation));
        apply_to(&mut self.keys, &c.keys, |k| k.id);
        apply_to(&mut self.texts, &c.texts, |t| t.id);
        for s in &c.signers {
            match s {
                // The upsert keeps a row's creation time, as the SQL does.
                Change::Put(r) => {
                    let mut r = r.clone();
                    if let Some(old) = self.signers.get(&(r.purpose, r.generation)) {
                        r.created_at = old.created_at;
                    }
                    self.signers.insert((r.purpose, r.generation), r);
                }
                Change::Delete(k) => {
                    self.signers.remove(k);
                }
            }
        }
        apply_to(&mut self.digests, &c.digests, |d| d.digest);
        apply_to(&mut self.logins, &c.logins, |l| l.account);
        apply_to(&mut self.displays, &c.displays, |d| d.account);
        // `keystore.display_name.fingerprint` is UNIQUE: a batch that
        // leaves one fingerprint on two accounts fails in PostgreSQL.
        let fingerprints: BTreeSet<[u8; 32]> =
            self.displays.values().map(|d| d.fingerprint).collect();
        assert_eq!(fingerprints.len(), self.displays.len(), "SA-11: UNIQUE");
        for r in &c.requested {
            match r {
                Change::Put(t) => {
                    self.requested.insert(*t);
                }
                Change::Delete(t) => {
                    self.requested.remove(t);
                }
            }
        }
        self.blob_deletes.extend(c.blobs.iter().copied());
    }

    fn rows(&self) -> KeystoreRows {
        KeystoreRows {
            chain: self.chain.clone(),
            roots: self.roots.values().cloned().collect(),
            groups: self.groups.values().cloned().collect(),
            keys: self.keys.values().cloned().collect(),
            texts: self.texts.values().cloned().collect(),
            signers: self.signers.values().cloned().collect(),
            digests: self.digests.values().copied().collect(),
            logins: self.logins.values().copied().collect(),
            requested: self.requested.iter().copied().collect(),
            displays: self.displays.values().copied().collect(),
        }
    }

    /// Every stored value, column by column.
    fn values(&self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        if let Some(c) = &self.chain {
            out.push(c.state.clone());
        }
        for r in self.roots.values() {
            out.push(r.handle.clone());
            out.push(r.wrapped.clone());
        }
        for g in self.groups.values() {
            out.push(g.public_key.clone());
            out.push(g.sealed_secret.clone());
        }
        for k in self.keys.values() {
            out.push(k.sealed.clone());
        }
        for t in self.texts.values() {
            out.push(t.envelope.clone());
        }
        for s in self.signers.values() {
            out.push(s.public_key.clone());
            if let Some((_, b)) = &s.sealed {
                out.push(b.clone());
            }
        }
        for d in self.digests.values() {
            out.push(d.digest.to_vec());
        }
        for d in self.displays.values() {
            out.push(d.fingerprint.to_vec());
        }
        out
    }
}

#[derive(Default)]
struct MemSink {
    tables: Mutex<Tables>,
    writes: Mutex<usize>,
    fail_at: Mutex<Option<usize>>,
}

impl KeystoreSink for MemSink {
    fn apply<'a>(&'a self, changes: &'a KeystoreChanges) -> SinkFuture<'a> {
        let n = {
            let mut w = lock(&self.writes);
            *w += 1;
            *w
        };
        let out = if *lock(&self.fail_at) == Some(n) {
            Err(CellError::Keys("a scripted keystore write failure"))
        } else {
            lock(&self.tables).apply(changes);
            Ok(())
        };
        Box::pin(std::future::ready(out))
    }
}

impl MemSink {
    fn rows(&self) -> KeystoreRows {
        lock(&self.tables).rows()
    }

    fn tables(&self) -> Tables {
        lock(&self.tables).clone()
    }

    /// Makes the write `ahead` writes from now fail, once.
    fn fail_in(&self, ahead: usize) {
        *lock(&self.fail_at) = Some(*lock(&self.writes) + ahead);
    }
}

// ---------------------------------------------------------------------------
// The cell: an in-memory engine with a tenant admin.

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

async fn as_admin(engine: &CellEngine, cmd: CellCommand, id: u8, stepup: Option<[u8; 16]>) {
    let now = Timestamp::from_micros(fstp_cell::tasks::system_now());
    let session = SessionView {
        id: SESSION,
        account: ADMIN,
        method: Method::Passkey,
        started: now,
        last_used: now,
    };
    let command_id = [id; 16];
    let action = Action::Command(cmd.clone());
    let high = HighRiskAction::of(&action).unwrap();
    let stepup = high.zip(stepup).map(|(_, stepup)| StepUpView {
        id: stepup,
        session: session.id,
        action_digest: action_digest(&cmd, command_id),
        asserted_at: now,
        strong: true,
        consumed: false,
    });
    let policy = LoginPolicy {
        stepup_freshness_us: 5 * 60 * 1_000_000,
    };
    let admitted = gate::admit_command(
        &engine.state(),
        &session,
        action,
        command_id,
        stepup.as_ref(),
        now,
        &policy,
    )
    .unwrap();
    engine.execute(admitted).await.unwrap();
}

/// A cell whose keystore writes through `sink`: two groups, three texts,
/// two login emails and a notice companion signing key, each recorded in
/// the ledger where an erasure needs it.
struct Cell {
    engine: CellEngine,
    sim: Custodian,
    sink: Arc<MemSink>,
    runner: ErasureRunner<Custodian>,
    _shutdown: Shutdown,
}

async fn cell(rt: &TokioRuntime) -> Cell {
    let mut mem: MemStore<CellRecord> = MemStore::new();
    let stepup = stepup_common::grant_stepup(
        &mut mem,
        SESSION,
        ADMIN,
        &CellCommand::Tenant(TenantCommand::GrantTenantAdmin { account: ADMIN }),
        [GRANT_ADMIN; 16],
        fstp_cell::tasks::system_now(),
    )
    .unwrap();
    let store = Unanchored::open(mem, CELL).await.unwrap();
    let shutdown = Shutdown::new();
    let (engine, _task) = CellEngine::start(rt, store, GenesisVault, &shutdown, 8)
        .await
        .unwrap();
    as_admin(
        &engine,
        CellCommand::Tenant(TenantCommand::GrantTenantAdmin { account: ADMIN }),
        GRANT_ADMIN,
        Some(stepup),
    )
    .await;
    let sim = Custodian::default();
    let sink = Arc::new(MemSink::default());
    let mut runner = ErasureRunner::genesis(sim.clone(), engine.clone(), CELL)
        .await
        .unwrap();
    runner.persist_to(sink.clone()).await.unwrap();
    let mut c = Cell {
        engine,
        sim,
        sink,
        runner,
        _shutdown: shutdown,
    };
    for g in [G1, G2] {
        c.runner.add_group(g).unwrap();
    }
    for (n, (g, t, text)) in TEXTS.into_iter().enumerate() {
        c.runner.put_text(g, t, text.as_bytes()).unwrap();
        let id = 0xA1 + u8::try_from(n).unwrap();
        as_admin(
            &c.engine,
            CellCommand::Text(TextCommand::PutText { id: t }),
            id,
            None,
        )
        .await;
    }
    for (a, e) in [(ERASED, ERASED_EMAIL), (LIVE, LIVE_EMAIL)] {
        assert_eq!(c.runner.set_login_email(a, e).unwrap(), LoginEmailSet::Set);
    }
    let login = c.runner.keystore().login_text(ERASED).unwrap();
    as_admin(
        &c.engine,
        CellCommand::Text(TextCommand::PutText { id: login }),
        0xA9,
        None,
    )
    .await;
    c.runner
        .ensure_signer(Purpose::NoticeCompanion)
        .await
        .unwrap();
    c.runner
        .rotate_signer(Purpose::NoticeCompanion)
        .await
        .unwrap();
    // The runner flushes around each step. A request served outside the
    // task flushes here, as `serve` does.
    c.runner.run_until_idle().await.unwrap();
    c
}

impl Cell {
    /// Records the erasure request of `ids` in the ledger.
    async fn erase(&self, ids: Vec<[u8; 16]>, id: u8) {
        as_admin(
            &self.engine,
            CellCommand::Text(TextCommand::EraseTexts { ids, cause: 2 }),
            id,
            None,
        )
        .await;
    }

    /// The process stops, and a new one loads the keystore from the
    /// tables through the start-up path of `start_pg`.
    async fn restart(&mut self) {
        let fresh = load(&self.sim, &self.engine, &self.sink).await.unwrap();
        self.runner = fresh;
    }
}

async fn load(
    sim: &Custodian,
    engine: &CellEngine,
    sink: &Arc<MemSink>,
) -> Result<ErasureRunner<Custodian>, CellError> {
    let mut ks = Keystore::from_rows(CELL, sink.rows(), sink.clone())?;
    let seal = ks.unwrap_current(sim).await?;
    let groups = ks.open_groups(&seal)?;
    ErasureRunner::from_open(sim.clone(), engine.clone(), ks, seal, groups).await
}

fn opens(runner: &ErasureRunner<Custodian>, engine: &CellEngine, id: [u8; 16]) -> Option<Vec<u8>> {
    runner
        .open_text(&engine.state(), id)
        .ok()
        .map(|t| t.to_vec())
}

fn block_on<F: Future>(f: impl FnOnce(TokioRuntime) -> F) -> F::Output {
    let rt = TokioRuntime::new_multi_thread(2).unwrap();
    rt.block_on(f(rt.clone()))
}

/// The erasure of T1 and of the login email of `ERASED`, run to its end. The
/// first request starts a batch at once, so the second joins the next
/// one: two batches, epochs 1 and 2.
async fn erase_and_complete(c: &mut Cell) {
    let login = c.runner.keystore().login_text(ERASED).unwrap();
    c.erase(vec![T1, login], 0xB0).await;
    c.runner.run_until_idle().await.unwrap();
    assert_eq!(c.runner.keystore().epoch(), 2);
}

// ---------------------------------------------------------------------------
// The tests.

/// ADR-004 (decided by Daniel on 2026-11-20): the keystore a restart
/// loads from its tables is the keystore the old process held: every row,
/// the chain state and the keyed index, before and after an erasure.
#[test]
fn adr004_keystore_round_trips_through_tables() {
    block_on(|rt| async move {
        let mut c = cell(&rt).await;
        let before = c.runner.keystore().fingerprint().unwrap();
        c.restart().await;
        assert_eq!(c.runner.keystore().fingerprint().unwrap(), before);
        erase_and_complete(&mut c).await;
        let before = c.runner.keystore().fingerprint().unwrap();
        c.restart().await;
        assert_eq!(c.runner.keystore().fingerprint().unwrap(), before);
        assert!(c.runner.keystore().writes_through());
    });
}

/// I-23: a process restart reads every text stored before it, and a text
/// stored after it survives the next one.
#[test]
fn i23_process_restart_reads_every_text() {
    block_on(|rt| async move {
        let mut c = cell(&rt).await;
        c.restart().await;
        for (_, t, text) in TEXTS {
            assert_eq!(
                opens(&c.runner, &c.engine, t).as_deref(),
                Some(text.as_bytes()),
                "I-23: {t:?}"
            );
        }
        c.runner.put_text(G2, [0x74; 16], b"after").unwrap();
        c.runner.run_until_idle().await.unwrap();
        c.restart().await;
        assert_eq!(
            opens(&c.runner, &c.engine, [0x74; 16]).as_deref(),
            Some(&b"after"[..])
        );
    });
}

/// I-79, design section 4.2: recovery finds an account by its login
/// email, so the keyed index survives a restart, and after an erasure that
/// replaced the `Lookup` key it still finds every live address and no
/// erased one.
#[test]
fn i79_login_email_lookup_survives_restart() {
    block_on(|rt| async move {
        let mut c = cell(&rt).await;
        c.restart().await;
        assert_eq!(
            c.runner.login_account(LIVE_EMAIL).unwrap(),
            Some(LIVE),
            "I-79"
        );
        assert_eq!(c.runner.login_account(ERASED_EMAIL).unwrap(), Some(ERASED));
        let state = c.engine.state();
        assert_eq!(
            c.runner.login_email(&state, LIVE).unwrap().as_deref(),
            Some(LIVE_EMAIL)
        );
        erase_and_complete(&mut c).await;
        c.restart().await;
        assert_eq!(
            c.runner.login_account(LIVE_EMAIL).unwrap(),
            Some(LIVE),
            "I-79"
        );
        assert_eq!(c.runner.login_account(ERASED_EMAIL).unwrap(), None);
    });
}

/// I-81: after a restart, an erased text stays unreadable: the cell
/// refuses it, the destroyed epoch's root row cannot be unwrapped, and no
/// seal key that custody still gives opens it from the rows. A live
/// sibling in the same group opens, so the check has teeth.
#[test]
fn i81_destroyed_epoch_stays_unreadable_after_restart() {
    block_on(|rt| async move {
        let mut c = cell(&rt).await;
        erase_and_complete(&mut c).await;
        c.restart().await;
        assert!(matches!(
            c.runner.open_text(&c.engine.state(), T1),
            Err(OpenRefusal::Erased)
        ));
        assert!(opens(&c.runner, &c.engine, T2).is_some());
        let rows = c.sink.rows();
        for old in rows.roots.iter().filter(|r| r.epoch < 2) {
            assert!(matches!(old.status, RootStatus::Destroyed(_)), "I-81");
        }
        let image = c.runner.keystore().image().unwrap();
        let mut seals = Vec::new();
        for r in &image.roots {
            let got = c
                .sim
                .unwrap(
                    &root_ref(CELL, r),
                    &wrapped_of(r),
                    &seal_key_aad(CELL, r.epoch),
                )
                .await;
            match r.epoch {
                0 | 1 => assert!(got.is_err(), "I-81: the destroyed epoch unwrapped"),
                _ => seals.push(got.unwrap()),
            }
        }
        let text = |id| image.texts.iter().find(|t| t.id == id).unwrap();
        assert_eq!(
            snapshot::open_text(CELL, &[&image], &seals, text(T1)),
            None,
            "I-81"
        );
        assert!(snapshot::open_text(CELL, &[&image], &seals, text(T2)).is_some());
    });
}

/// The steps of one healthy batch: request, rotate, create, wrap, reseal,
/// commit, snapshot, verify, destroy, complete.
const BATCH_STEPS: usize = 10;

/// I-81, ADR-004 (2026-11-20): a process that stops after any step of an
/// erasure resumes from the tables and completes it. Every step's rows
/// are durable before the next step runs, so the restart reuses the root
/// it created and leaves one live root in custody.
#[test]
fn i81_erasure_resumes_from_tables_after_a_restart_at_every_step() {
    for k in 0..BATCH_STEPS {
        block_on(|rt| async move {
            let mut c = cell(&rt).await;
            c.erase(vec![T1], 0xB0).await;
            for _ in 0..=k {
                assert!(c.runner.step().await.unwrap().is_some(), "step {k}");
            }
            c.restart().await;
            c.runner.run_until_idle().await.unwrap();
            assert_eq!(c.runner.keystore().epoch(), 1, "after step {k}");
            assert!(
                matches!(
                    c.runner.open_text(&c.engine.state(), T1),
                    Err(OpenRefusal::Erased)
                ),
                "after step {k}"
            );
            assert!(opens(&c.runner, &c.engine, T2).is_some(), "after step {k}");
            assert_eq!(c.sim.live_roots(), 1, "I-81: after step {k}");
            let rows = c.sink.rows();
            assert!(rows.requested.contains(&T1));
            assert!(rows.keys.iter().all(|r| r.id != T1), "after step {k}");
        });
    }
}

/// The table writes of one healthy batch: the steps that change the
/// keystore rows. Rotate, wrap and reseal live in process memory until the
/// commit, so they write nothing.
const BATCH_WRITES: usize = 7;

/// I-81, ADR-004 (2026-11-20): a table write that fails stops the batch
/// before its next step. A process that then stops resumes from the rows
/// written before, and completes the erasure. A failed write after a
/// root was created can leave that root unreferenced in custody, which
/// reconciliation reports.
#[test]
fn i81_erasure_resumes_after_a_failed_table_write_at_every_step() {
    for k in 1..=BATCH_WRITES {
        block_on(|rt| async move {
            let mut c = cell(&rt).await;
            c.erase(vec![T1], 0xB0).await;
            // Each step flushes before it runs and after. A flush with no
            // marked row writes nothing.
            c.sink.fail_in(k);
            let mut failed = false;
            for _ in 0..BATCH_STEPS {
                match c.runner.step().await {
                    Ok(Some(_)) => {}
                    Ok(None) => break,
                    Err(_) => {
                        failed = true;
                        break;
                    }
                }
            }
            assert!(failed, "write {k} never failed");
            c.restart().await;
            c.runner.run_until_idle().await.unwrap();
            assert_eq!(c.runner.keystore().epoch(), 1, "after write {k}");
            assert!(
                matches!(
                    c.runner.open_text(&c.engine.state(), T1),
                    Err(OpenRefusal::Erased)
                ),
                "after write {k}"
            );
            assert!(opens(&c.runner, &c.engine, T2).is_some(), "after write {k}");
            let ks = c.runner.keystore();
            assert_eq!(ks.live_roots(), vec![1], "after write {k}");
        });
    }
}

/// I-80, TH-59: no keystore row holds root material. No root key that
/// custody made and no seal key it wrapped appears in any stored value,
/// through texts, login emails, signing keys and an erasure.
#[test]
fn i80_keystore_rows_hold_no_root_material() {
    block_on(|rt| async move {
        let mut c = cell(&rt).await;
        erase_and_complete(&mut c).await;
        c.restart().await;
        let values = c.sink.tables().values();
        let roots = lock(&c.sim.0.made).clone();
        let seals = lock(&c.sim.0.seals).clone();
        assert!(roots.len() >= 2 && seals.len() >= 2);
        for needle in roots.iter().chain(seals.iter()) {
            for v in &values {
                assert!(
                    !v.windows(needle.len()).any(|w| w == needle),
                    "I-80: a row holds root material"
                );
            }
        }
    });
}

/// R-CR-01, ADR-004 (2026-11-20): the keystore rows are sealed at rest.
/// No text and no login email appears in clear in any stored value, and
/// the chain state is stored sealed, never in its plain form.
#[test]
fn r_cr_01_keystore_rows_sealed_at_rest() {
    block_on(|rt| async move {
        let c = cell(&rt).await;
        let tables = c.sink.tables();
        let values = tables.values();
        let mut plain: Vec<&[u8]> = TEXTS.iter().map(|(_, _, t)| t.as_bytes()).collect();
        plain.push(LIVE_EMAIL.as_bytes());
        plain.push(ERASED_EMAIL.as_bytes());
        for p in plain {
            for v in &values {
                assert!(
                    !v.windows(p.len()).any(|w| w == p),
                    "R-CR-01: a row holds plaintext"
                );
            }
        }
        let state = &tables.chain.as_ref().unwrap().state;
        assert!(fstp_keys::erasure::codec::decode(state).is_err());
        assert!(!state.windows(4).any(|w| w == b"FKC1"), "R-CR-01");
    });
}

// ---------------------------------------------------------------------------
// Display names (SA-11, SA-11 amendment, ADR-004 section "Written by lane
// L26"). Every name is synthetic.

use fstp_api_core::port::DisplayNameSet;

const ANNA: AccountId = AccountId::from_raw(0x61);
const BERG: AccountId = AccountId::from_raw(0x62);
const CARL: AccountId = AccountId::from_raw(0x63);

async fn set_name(c: &mut Cell, a: AccountId, name: Option<&str>) -> DisplayNameSet {
    c.runner.set_display_name(a, name).await.unwrap()
}

fn names(c: &Cell) -> BTreeMap<AccountId, String> {
    c.runner
        .display_names(&c.engine.state(), &[ANNA, BERG, CARL])
        .unwrap()
}

/// ADR-004 "Chains" (decided by Daniel on 2026-11-21): the display name
/// fingerprint key is HKDF-SHA256 of the `Lookup` key with the label
/// `fstp display name fingerprint v1`, as the API core derives it.
#[test]
fn sa11_unique_adr004_display_key_is_derived_from_lookup() {
    let lookup = SealKey::from_bytes([9; 32]);
    let key = display_key(&lookup).unwrap();
    assert_eq!(
        key.expose(),
        &fstp_api_core::display_name::fingerprint_key(&[9; 32]).unwrap()
    );
    assert_ne!(key.expose(), lookup.expose());
}

/// SA-11, SA-11 amendment, R-CR-01: a display name is sealed as a text,
/// read back as typed, and unique in the tenant under its comparison
/// form. The own name again changes nothing. No row holds it in clear.
#[test]
fn sa11_unique_production_display_name_is_sealed_unique_and_read_back() {
    block_on(|rt| async move {
        let mut c = cell(&rt).await;
        assert_eq!(
            set_name(&mut c, ANNA, Some("Synthetic Anna Berg")).await,
            DisplayNameSet::Set
        );
        let text = c.runner.keystore().display_text(ANNA).unwrap();
        for other in [
            "Synthetic Anna Berg",
            "  SYNTHETIC anna   berg",
            "Synthetic An\u{200d}na Berg",
        ] {
            assert_eq!(
                set_name(&mut c, BERG, Some(other)).await,
                DisplayNameSet::Taken,
                "SA-11 amendment: {other:?}"
            );
        }
        assert_eq!(
            set_name(&mut c, BERG, Some("Synthetic Berg")).await,
            DisplayNameSet::Set
        );
        let epoch = c.runner.keystore().epoch();
        assert_eq!(
            set_name(&mut c, ANNA, Some("Synthetic Anna Berg")).await,
            DisplayNameSet::Set
        );
        assert_eq!(c.runner.keystore().display_text(ANNA), Some(text));
        c.runner.run_until_idle().await.unwrap();
        assert_eq!(c.runner.keystore().epoch(), epoch, "no erasure ran");
        let want: BTreeMap<AccountId, String> = [
            (ANNA, "Synthetic Anna Berg".to_owned()),
            (BERG, "Synthetic Berg".to_owned()),
        ]
        .into_iter()
        .collect();
        assert_eq!(names(&c), want);
        let tables = c.sink.tables();
        assert_eq!(tables.displays.len(), 2, "keystore.display_name");
        for v in tables.values() {
            for p in [&b"Synthetic Anna Berg"[..], b"Synthetic Berg"] {
                assert!(
                    !v.windows(p.len()).any(|w| w == p),
                    "R-CR-01: a row holds a display name in clear"
                );
            }
        }
    });
}

/// SA-11, ADR-004 (decided by Daniel on 2026-11-21), I-81, ADR-007: a
/// replaced name is free at once and erased by a batch that replaces
/// `Lookup`. Step 2 recomputes every live fingerprint and login digest
/// under the new key, so uniqueness and login lookup still hold. A set
/// that meets the batch before its commit is served after it.
#[test]
fn sa11_unique_i81_replacing_a_name_erases_it_and_replaces_lookup() {
    block_on(|rt| async move {
        let mut c = cell(&rt).await;
        set_name(&mut c, ANNA, Some("Synthetic One")).await;
        set_name(&mut c, BERG, Some("Synthetic Two")).await;
        c.runner.run_until_idle().await.unwrap();
        let epoch = c.runner.keystore().epoch();
        let old = c.runner.keystore().display_text(ANNA).unwrap();
        let berg = c.runner.keystore().display_fingerprint(BERG).unwrap();
        let logins = c.runner.keystore().login_digests();
        assert_eq!(
            set_name(&mut c, ANNA, Some("Synthetic Three")).await,
            DisplayNameSet::Set
        );
        // The old name is free at once, while its batch is in flight.
        assert_eq!(
            set_name(&mut c, CARL, Some("synthetic one")).await,
            DisplayNameSet::Set
        );
        c.runner.run_until_idle().await.unwrap();
        assert!(c.runner.keystore().epoch() > epoch, "I-81: a batch ran");
        assert!(
            matches!(
                c.runner.open_text(&c.engine.state(), old),
                Err(OpenRefusal::Erased)
            ),
            "ADR-007: the replaced name is erased"
        );
        assert_ne!(
            c.runner.keystore().display_fingerprint(BERG),
            Some(berg),
            "ADR-004: step 2 recomputes the live fingerprints"
        );
        for d in c.runner.keystore().login_digests() {
            assert!(!logins.contains(&d), "G24: an old login digest survived");
        }
        assert_eq!(c.runner.login_account(LIVE_EMAIL).unwrap(), Some(LIVE));
        assert_eq!(
            set_name(&mut c, ANNA, Some("SYNTHETIC TWO")).await,
            DisplayNameSet::Taken,
            "SA-11 amendment: unique under the new key"
        );
        let want: BTreeMap<AccountId, String> = [
            (ANNA, "Synthetic Three".to_owned()),
            (BERG, "Synthetic Two".to_owned()),
            (CARL, "synthetic one".to_owned()),
        ]
        .into_iter()
        .collect();
        assert_eq!(names(&c), want);
    });
}

/// SA-11, ADR-007: a cleared name leaves the index at once, so another
/// account may take it, and its text is erased.
#[test]
fn sa11_unique_clearing_a_name_frees_and_erases_it() {
    block_on(|rt| async move {
        let mut c = cell(&rt).await;
        set_name(&mut c, ANNA, Some("Synthetic Clear")).await;
        let old = c.runner.keystore().display_text(ANNA).unwrap();
        assert_eq!(set_name(&mut c, ANNA, None).await, DisplayNameSet::Set);
        assert_eq!(c.runner.keystore().display_text(ANNA), None);
        assert_eq!(
            set_name(&mut c, BERG, Some("synthetic clear")).await,
            DisplayNameSet::Set
        );
        c.runner.run_until_idle().await.unwrap();
        assert!(matches!(
            c.runner.open_text(&c.engine.state(), old),
            Err(OpenRefusal::Erased)
        ));
        let tables = c.sink.tables();
        assert_eq!(tables.displays.len(), 1);
        assert!(tables.displays.contains_key(&BERG.raw().to_be_bytes()));
        assert_eq!(set_name(&mut c, ANNA, None).await, DisplayNameSet::Set);
    });
}

/// ADR-004 (2026-11-20), SA-11 amendment, I-23: the display names and
/// their index survive a restart from the tables, also after a batch that
/// replaced `Lookup`, and a taken name stays taken.
#[test]
fn sa11_unique_display_names_survive_a_restart() {
    block_on(|rt| async move {
        let mut c = cell(&rt).await;
        set_name(&mut c, ANNA, Some("Synthetic Restart")).await;
        set_name(&mut c, BERG, Some("Synthetic Before")).await;
        set_name(&mut c, BERG, Some("Synthetic After")).await;
        c.runner.run_until_idle().await.unwrap();
        let before = c.runner.keystore().fingerprint().unwrap();
        let named = names(&c);
        c.restart().await;
        assert_eq!(c.runner.keystore().fingerprint().unwrap(), before);
        assert_eq!(names(&c), named);
        assert_eq!(
            set_name(&mut c, CARL, Some("synthetic restart")).await,
            DisplayNameSet::Taken
        );
        assert_eq!(
            set_name(&mut c, CARL, Some("synthetic before")).await,
            DisplayNameSet::Set
        );
    });
}

/// SA-11, usability rule: a set that arrives while an erasure batch is
/// before its commit runs that batch to its commit and is then served,
/// rather than refused.
#[test]
fn sa11_set_during_a_batch_is_served_after_its_commit() {
    block_on(|rt| async move {
        let mut c = cell(&rt).await;
        c.erase(vec![T1], 0xB0).await;
        c.runner.step().await.unwrap();
        c.runner.step().await.unwrap();
        assert_eq!(
            set_name(&mut c, ANNA, Some("Synthetic Waiting")).await,
            DisplayNameSet::Set
        );
        c.runner.run_until_idle().await.unwrap();
        assert_eq!(
            names(&c).get(&ANNA).map(String::as_str),
            Some("Synthetic Waiting")
        );
        assert!(matches!(
            c.runner.open_text(&c.engine.state(), T1),
            Err(OpenRefusal::Erased)
        ));
    });
}

/// ADR-012 record of lane L27, row "App restore": tables restored from
/// before the last rotation open nothing, so the restore takes the newer
/// snapshot whole. The changes make the restored tables that snapshot, and
/// a restart over them opens the live text and refuses the erased one
/// (I-81). At an equal epoch the restored tables are kept as they are.
/// With no snapshot, tables under a destroyed epoch are refused.
#[test]
fn adr012_app_restore_takes_the_newest_copy_that_opens() {
    use fstp_cell::tasks::erasure::restore::{Source, choose};
    block_on(|rt| async move {
        let mut c = cell(&rt).await;
        let before = c.sink.rows();
        erase_and_complete(&mut c).await;
        let after = c.sink.rows();
        // The restored tables are from before the rotation.
        let (source, changes) = choose(&c.sim, CELL, Some(&before), Some(&after))
            .await
            .unwrap();
        assert_eq!(source, Source::Snapshot);
        let mut restored = Tables::default();
        restored.apply(&fstp_cell::tasks::erasure::restore::changes_to(
            None, &before,
        ));
        restored.apply(&changes.unwrap());
        assert_eq!(restored.rows(), after, "the restore mixed two copies");
        // A restart over the restored tables.
        let sink = Arc::new(MemSink::default());
        lock(&sink.tables).apply(&fstp_cell::tasks::erasure::restore::changes_to(
            None, &after,
        ));
        let runner = load(&c.sim, &c.engine, &sink).await.unwrap();
        assert!(opens(&runner, &c.engine, T2).is_some());
        assert!(
            matches!(
                runner.open_text(&c.engine.state(), T1),
                Err(OpenRefusal::Erased)
            ),
            "I-81: the restore brought back an erased text"
        );
        // An equal epoch: the restored tables stay.
        let (source, changes) = choose(&c.sim, CELL, Some(&after), Some(&after))
            .await
            .unwrap();
        assert_eq!((source, changes), (Source::Backup, None));
        // No snapshot: tables under a destroyed epoch open nothing.
        assert!(choose(&c.sim, CELL, Some(&before), None).await.is_err());
    });
}

/// R-KY-02, I-81, ADR-007 (lane L33): the erasure log names a replaced
/// display name with its account and kind as soon as it is replaced, and
/// the batch that destroys its key completes the entry with that epoch. A
/// ledger text's entry gains its destroyed epoch the same way. The log
/// survives a restart, since it is the ledger's.
#[test]
fn r_ky_02_i81_erasure_log_names_requests_and_destroyed_epochs() {
    block_on(|rt| async move {
        let mut c = cell(&rt).await;
        set_name(&mut c, ANNA, Some("Synthetic Logged")).await;
        let old = c.runner.keystore().display_text(ANNA).unwrap();
        set_name(&mut c, ANNA, Some("Synthetic Logged Again")).await;
        let entry = c.engine.state().erasure(old).expect("the request entry");
        assert_eq!(entry.by, ANNA, "the person authorised it");
        assert_eq!(entry.kind, fstp_cell_core::ERASURE_KIND_DISPLAY_NAME);
        assert_eq!(entry.cause, 2);
        assert_eq!(entry.completed_at, None, "R-KY-02: not before the key died");
        c.runner.run_until_idle().await.unwrap();
        let epoch = c.runner.keystore().epoch();
        let entry = c.engine.state().erasure(old).unwrap();
        assert_eq!(
            entry.destroyed_epoch,
            Some(epoch - 1),
            "I-81: its epoch died"
        );
        assert!(entry.completed_at.is_some());
        // A ledger text, erased by a tenant admin.
        c.erase(vec![T1], 0xB5).await;
        c.runner.run_until_idle().await.unwrap();
        let t1 = c.engine.state().erasure(T1).unwrap();
        assert_eq!(t1.kind, fstp_cell_core::ERASURE_KIND_LEDGER_TEXT);
        assert!(
            t1.destroyed_epoch.is_some(),
            "I-81: the ledger text's epoch"
        );
        let log = fstp_cell::tasks::erasure::erasure_log(&c.engine.state());
        assert!(log.iter().any(|(id, _)| *id == old));
        assert!(log.iter().any(|(id, _)| *id == T1));
        for w in log.windows(2) {
            assert!(w[0].1.requested_at <= w[1].1.requested_at, "oldest first");
        }
        // A restarted runner repeats no record.
        c.restart().await;
        c.runner.run_until_idle().await.unwrap();
        assert_eq!(
            fstp_cell::tasks::erasure::erasure_log(&c.engine.state()),
            log
        );
    });
}

/// A synthetic document's data key id and group (lane L39).
const DOC: [u8; 16] = [0x39; 16];
const DOC_GROUP: [u8; 16] = [0x3A; 16];
const DOC_REASON: [u8; 16] = [0x3B; 16];

/// I-81, R-KY-02, ADR-007 (Daniel, 2026-11-23, decision 2; lane L39): the
/// erasure of a document deletes its `doc.blob` row in a keystore batch,
/// and never before `ErasuresCompleted` names the document with its
/// destroyed epoch. A start deletes the row of every completed document
/// again, so a crash between the record and the batch loses nothing, and
/// a repeated deletion is harmless. The entry stays in the log.
#[test]
fn i81_l39_blob_row_deleted_after_completion_and_again_at_start() {
    block_on(|rt| async move {
        let mut c = cell(&rt).await;
        c.runner.add_group(DOC_GROUP).unwrap();
        let stored = c
            .runner
            .seal_document(DOC_GROUP, DOC, b"synthetic document L39")
            .unwrap();
        c.runner.run_until_idle().await.unwrap();
        c.runner
            .erase_document(DOC, 2, ADMIN, Some(DOC_REASON))
            .await
            .unwrap();
        assert!(
            c.sink.tables().blob_deletes.is_empty(),
            "not at the request"
        );
        while c.runner.step().await.unwrap().is_some() {
            if c.sink.tables().blob_deletes.contains(&DOC) {
                let e = c.engine.state().erasure(DOC).unwrap();
                assert!(
                    e.destroyed_epoch.is_some(),
                    "I-81: the row goes only after the completion"
                );
            }
        }
        assert_eq!(c.sink.tables().blob_deletes, vec![DOC], "deleted once");
        assert!(c.runner.open_document(DOC, &stored).is_err(), "I-81");
        let e = c.engine.state().erasure(DOC).unwrap();
        assert_eq!(e.reason, Some(DOC_REASON), "the log keeps its entry");
        // A restart deletes it again, which deletes nothing more.
        c.restart().await;
        assert_eq!(c.sink.tables().blob_deletes, vec![DOC, DOC]);
        c.runner.run_until_idle().await.unwrap();
        assert!(c.runner.open_document(DOC, &stored).is_err(), "I-81");
        assert!(c.engine.state().erasure(DOC).is_some());
        // The repeated request is a no-op.
        c.runner
            .erase_document(DOC, 2, ADMIN, Some(DOC_REASON))
            .await
            .unwrap();
        c.runner.run_until_idle().await.unwrap();
        assert_eq!(c.sink.tables().blob_deletes, vec![DOC, DOC]);
    });
}
