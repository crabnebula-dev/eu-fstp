//! Keystore snapshots of the Vault chain over a real PostgreSQL server
//! and the in-process fake S3 of lane L10 (ADR-012 and ADR-004 records of
//! lane L17, ADR-004 erasure step 5, I-81, R-KY-02, R-NF-08).
//!
//! Each test makes a fresh vault database with a keystore from genesis,
//! as `erasure_pg.rs` does, and attaches the snapshot writer of option A:
//! the vault's own snapshot key on the VaultBackup chain, in the same stub
//! custody, over the fake object store. Custody keeps one AES key per
//! root, so a destroyed root really stops unwrapping.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use fstp_crypto::hybrid_kem::HybridSecretKey;
use fstp_custody::{
    Aad, BackendId, Custody, CustodyError, CustodyHandle, DestroyReceipt, EcdsaSignature, Refusal,
    RootLabel, RootRef, SealKey, SignKeyRef, UsageCursor, UsagePage, WrappedSealKey,
};
use fstp_keys::Purpose;
use fstp_keys::envelope;
use fstp_pgtest::{PgServer, Role, tls as certs};
use fstp_pgwire::{Client, ClientTls, Config, Password};
use fstp_rt::tokio::TokioRuntime;
use fstp_vault::erasure::{ErasureEvent, Journal, Runner};
use fstp_vault::keystore::{self, KeystoreRows, VaultKeys};
use fstp_vault::service::AeadSealer;
use fstp_vault::{JournalEntry, Vault, VaultError, store};
use fstp_vault_core::Person;

use fstp_backup::s3::{Endpoint, S3Client};
use fstp_backup::sigv4::Credentials;
use fstp_backup::snapshot::{SnapshotKey, SnapshotOwner, Snapshots};
use fstp_vault::snapshot::{self, Source};

#[path = "../../fstp-backup/tests/support/fake_s3.rs"]
mod fake_s3;
use fake_s3::FakeS3;

const AK: &str = "TESTACCESSKEYV17";
const SK: &str = "vault/snapshot+key=lane-l17";
const REGION: &str = "gra";
const BUCKET: &str = "fstp-test-vault-snapshots";

type Pg = Client<TokioRuntime>;

fn rt() -> &'static TokioRuntime {
    static RT: OnceLock<TokioRuntime> = OnceLock::new();
    RT.get_or_init(|| TokioRuntime::new_multi_thread(2).unwrap())
}

fn block_on<F: Future>(f: F) -> F::Output {
    rt().block_on(f)
}

const CELL: [u8; 16] = [0x7e; 16];
const PINNED: [[u8; 32]; 1] = [[3; 32]];
const NOW: i64 = 1_800_000_000_000_000;

/// Synthetic attribute tuples (corpus only).
const ALICE: &[u8] = b"synthetic|manual|passport|name=Synthetic Alpha|0001";
const BRUNO: &[u8] = b"synthetic|manual|passport|name=Synthetic Bravo|0002";
const CARLA: &[u8] = b"synthetic|manual|passport|name=Synthetic Charlie|0003";

// ---------------------------------------------------------------------
// Custody: one AES key per root. A destroy drops the key, so the root
// never unwraps again. A retried destroy answers the same receipt.
// ---------------------------------------------------------------------

#[derive(Default)]
struct Roots {
    keys: BTreeMap<Vec<u8>, Option<Arc<fstp_crypto::aead::Key>>>,
    created: u32,
}

#[derive(Clone, Default)]
struct StubCustody {
    roots: Arc<Mutex<Roots>>,
    /// The next destroy destroys, then answers an error, as a crash after
    /// the custody call would look.
    fail_after_destroy: Arc<AtomicBool>,
}

fn bound(root: &RootRef, aad: &Aad) -> Vec<u8> {
    [&root.handle.0[..], &aad.0[..]].concat()
}

impl Custody for StubCustody {
    async fn create_root(&self, label: RootLabel) -> Result<RootRef, CustodyError> {
        let mut r = self.roots.lock().unwrap();
        r.created += 1;
        let handle = format!("stub-root-{}", r.created).into_bytes();
        r.keys.insert(
            handle.clone(),
            Some(Arc::new(fstp_crypto::aead::Key::generate().unwrap())),
        );
        Ok(RootRef {
            backend: BackendId::Keyd,
            cell: label.cell,
            chain: label.chain,
            epoch: label.epoch,
            handle: CustodyHandle(handle),
        })
    }

    async fn wrap(
        &self,
        root: &RootRef,
        key: &SealKey,
        aad: &Aad,
    ) -> Result<WrappedSealKey, CustodyError> {
        // As `fstp-keyd`: an AAD above its frame limit is refused (ADR-012
        // record of lane m10/backup-followups, row "Custody doubles").
        if aad.0.len() > fstp_custody::keyd::MAX_AAD_LEN {
            return Err(CustodyError::Refused(Refusal::BadRequest));
        }
        let k = self
            .roots
            .lock()
            .unwrap()
            .keys
            .get(&root.handle.0)
            .cloned()
            .ok_or(CustodyError::Refused(Refusal::UnknownRoot))?
            .ok_or(CustodyError::Refused(Refusal::Destroyed))?;
        let s = fstp_crypto::aead::seal(&k, &bound(root, aad), key.expose())
            .map_err(|_| CustodyError::Refused(Refusal::Internal))?;
        Ok(WrappedSealKey([s.nonce.to_vec(), s.body].concat()))
    }

    async fn unwrap(
        &self,
        root: &RootRef,
        w: &WrappedSealKey,
        aad: &Aad,
    ) -> Result<SealKey, CustodyError> {
        if aad.0.len() > fstp_custody::keyd::MAX_AAD_LEN {
            return Err(CustodyError::Refused(Refusal::BadRequest));
        }
        let k = self
            .roots
            .lock()
            .unwrap()
            .keys
            .get(&root.handle.0)
            .cloned()
            .ok_or(CustodyError::Refused(Refusal::UnknownRoot))?
            .ok_or(CustodyError::Refused(Refusal::Destroyed))?;
        let refused = CustodyError::Refused(Refusal::UnwrapFailed);
        let (nonce, body) = w.0.split_at_checked(12).ok_or(refused)?;
        let plain = fstp_crypto::aead::open(&k, nonce.try_into().unwrap(), &bound(root, aad), body)
            .map_err(|_| refused)?;
        SealKey::from_slice(&plain).map_err(|_| refused)
    }

    async fn destroy(&self, root: &RootRef) -> Result<DestroyReceipt, CustodyError> {
        {
            let mut r = self.roots.lock().unwrap();
            let slot = r
                .keys
                .get_mut(&root.handle.0)
                .ok_or(CustodyError::Refused(Refusal::UnknownRoot))?;
            *slot = None;
        }
        if self.fail_after_destroy.swap(false, Ordering::SeqCst) {
            return Err(CustodyError::Refused(Refusal::Internal));
        }
        Ok(DestroyReceipt(
            [b"stub-receipt|", &root.handle.0[..]].concat(),
        ))
    }

    async fn sign(&self, _: &SignKeyRef, _: &[u8; 32]) -> Result<EcdsaSignature, CustodyError> {
        Err(CustodyError::Refused(Refusal::NoSignKey))
    }

    async fn usage_since(&self, _: &RootRef, _: UsageCursor) -> Result<UsagePage, CustodyError> {
        Err(CustodyError::Refused(Refusal::Internal))
    }
}

// ---------------------------------------------------------------------
// The vault journal without the chain writer, with an optional failure.
// ---------------------------------------------------------------------

struct StoreJournal {
    client: Pg,
    sealer: AeadSealer,
    /// Fails the commit whose number this is (1 based), once.
    fail_on: Option<u32>,
    commits: AtomicU32,
    /// Every committed entry, in order.
    seen: Vec<JournalEntry>,
}

impl Journal for StoreJournal {
    async fn commit(&mut self, entries: &[JournalEntry], _now: i64) -> Result<(), VaultError> {
        let n = self.commits.fetch_add(1, Ordering::SeqCst) + 1;
        if self.fail_on == Some(n) {
            self.fail_on = None;
            return Err(VaultError::Unavailable("a test journal failure"));
        }
        store::persist(&mut self.client, &self.sealer, entries).await?;
        self.seen.extend_from_slice(entries);
        Ok(())
    }
}

// ---------------------------------------------------------------------
// A vault database with a keystore from genesis.
// ---------------------------------------------------------------------

struct Db {
    cfg: Config,
}

impl Db {
    fn connect(&self) -> Pg {
        block_on(Client::connect(rt(), &self.cfg)).unwrap_or_else(|e| panic!("connect: {e}"))
    }
}

fn fresh_db() -> Db {
    let server = PgServer::shared().unwrap_or_else(|e| panic!("{e}"));
    let role = Role::Superuser;
    let db = server
        .fresh_database_as(role)
        .unwrap_or_else(|e| panic!("{e}"));
    let tls = ClientTls::new(certs::CA_PEM, role.client_cert_pem(), role.client_key_pem()).unwrap();
    let cfg = Config::new(
        db.host.clone(),
        db.port,
        role.name(),
        Password::new(server.password(role)).unwrap(),
        db.dbname.clone(),
        tls,
    )
    .unwrap()
    .connect_timeout(Some(Duration::from_secs(20)));
    let d = Db { cfg };
    let mut c = d.connect();
    block_on(store::migrate(&mut c)).unwrap();
    block_on(c.close()).unwrap();
    d
}

/// The world of one test: the database, custody and the anchor public key
/// of genesis.
struct World {
    db: Db,
    custody: StubCustody,
    fake: FakeS3,
    snapshots: Snapshots,
}

fn genesis() -> World {
    let db = fresh_db();
    let custody = StubCustody::default();
    let keys = VaultKeys::generate().unwrap();
    let rows = block_on(keystore::genesis(&custody, CELL, &keys, NOW)).unwrap();
    let mut c = db.connect();
    block_on(keystore::write_rows(&mut c, &rows)).unwrap();
    block_on(c.close()).unwrap();
    let fake = FakeS3::start(rt(), AK, SK, REGION, BUCKET);
    let store = S3Client::with_tls(
        rt().clone(),
        Endpoint {
            host: "localhost".to_owned(),
            port: fake.port(),
            region: REGION.to_owned(),
            bucket: BUCKET.to_owned(),
        },
        Credentials::new(AK, SK).unwrap(),
        fstp_tls::ClientConfig::new(fake_s3::CA_PEM).unwrap(),
    );
    let key = block_on(SnapshotKey::create(&custody, CELL, SnapshotOwner::Vault)).unwrap();
    let key = SnapshotKey::decode(&key, CELL, SnapshotOwner::Vault).unwrap();
    World {
        db,
        custody,
        fake,
        snapshots: Snapshots::new(Arc::new(store), key),
    }
}

/// A running vault process: the runner over the keys login, the vault
/// and its journal over the vault login.
struct Process<'w> {
    runner: Runner<'w, TokioRuntime, StubCustody>,
    vault: Vault,
    journal: StoreJournal,
}

fn start(w: &World) -> Process<'_> {
    let runner = block_on(Runner::load(w.db.connect(), CELL, &w.custody))
        .unwrap_or_else(|e| {
            panic!("the runner did not load: {e}");
        })
        .with_snapshots(w.snapshots.clone());
    let (_, sealer) = runner.service_keys().unwrap().into_service_keys().unwrap();
    let mut vc = w.db.connect();
    let vault = block_on(store::load(&mut vc, &sealer, CELL, &PINNED)).unwrap();
    Process {
        runner,
        vault,
        journal: StoreJournal {
            client: vc,
            sealer,
            fail_on: None,
            commits: AtomicU32::new(0),
            seen: Vec::new(),
        },
    }
}

impl Process<'_> {
    fn register(&mut self, tuple: &[u8]) -> Person {
        block_on(
            self.runner
                .register_identity(&mut self.vault, &mut self.journal, tuple, NOW),
        )
        .unwrap()
    }

    fn step(&mut self) -> Result<Option<ErasureEvent>, VaultError> {
        block_on(self.runner.step(&mut self.vault, &mut self.journal, NOW))
    }

    fn run_to_idle(&mut self) -> Vec<ErasureEvent> {
        block_on(
            self.runner
                .run_to_idle(&mut self.vault, &mut self.journal, NOW),
        )
        .unwrap_or_else(|e| panic!("the batch did not complete: {e}"))
    }
}

fn read_rows(w: &World) -> KeystoreRows {
    let mut c = w.db.connect();
    let rows = block_on(keystore::read_rows(&mut c)).unwrap().unwrap();
    block_on(c.close()).unwrap();
    rows
}

// ---------------------------------------------------------------------
// The reader of copies.
// ---------------------------------------------------------------------

/// What a reader of `sets` opens through custody as it stands now.
struct Reach {
    kem: Vec<([u8; 16], u8, HybridSecretKey)>,
}

fn reach(w: &World, sets: &[&KeystoreRows]) -> Reach {
    let mut seals: Vec<SealKey> = Vec::new();
    for rows in sets {
        for r in rows.all_roots() {
            if r.wrapped.is_empty() {
                continue;
            }
            let root = RootRef {
                backend: BackendId::Keyd,
                cell: Some(fstp_custody::CellId(CELL)),
                chain: fstp_custody::Chain::Vault,
                epoch: fstp_custody::Epoch(r.epoch),
                handle: CustodyHandle(r.handle.clone()),
            };
            if let Ok(s) = block_on(w.custody.unwrap(
                &root,
                &WrappedSealKey(r.wrapped.clone()),
                &keystore::seal_aad(&CELL, r.epoch),
            )) {
                seals.push(s);
            }
        }
    }
    let mut kem = Vec::new();
    for rows in sets {
        for g in &rows.groups {
            if g.purpose == Purpose::Anchor.code() {
                continue;
            }
            for s in &seals {
                if let Ok(bytes) = keystore::open_group_secret(s, &CELL, g)
                    && let Ok(sk) = HybridSecretKey::from_bytes(&bytes)
                {
                    kem.push((g.group, g.purpose, sk));
                }
            }
        }
    }
    Reach { kem }
}

fn identity_dek(p: Person) -> [u8; 16] {
    p.0.to_be_bytes()
}

/// The tuple of `p` that the reader of `sets` opens, if any.
fn opens_tuple(w: &World, sets: &[&KeystoreRows], p: Person) -> Option<Vec<u8>> {
    let r = reach(w, sets);
    let id = identity_dek(p);
    for rows in sets {
        for d in rows.data_keys.iter().filter(|d| d.id == id) {
            let Ok(sealed) = envelope::decode_sealed_key(&d.sealed) else {
                continue;
            };
            for (group, _, sk) in r.kem.iter().filter(|(g, _, _)| *g == d.group) {
                let ctx = keystore::attribute_ctx(&CELL, group, d.generation, &id);
                let Ok(dk) = envelope::open_key(sk, &sealed, &ctx) else {
                    continue;
                };
                for set in sets {
                    for t in set.tuples.iter().filter(|t| t.identity == id) {
                        let Ok(blob) = envelope::decode_sealed_blob(&t.envelope) else {
                            continue;
                        };
                        let ctx = keystore::tuple_ctx(&CELL, &t.group, &id);
                        if let Ok(plain) = envelope::open_blob(&dk, &ctx, &blob) {
                            return Some(plain.to_vec());
                        }
                    }
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------
// Snapshot helpers.
// ---------------------------------------------------------------------

/// The snapshot objects in the fake store, by id, pointers left out.
fn snapshot_objects(w: &World) -> BTreeMap<String, Vec<u8>> {
    let prefix = format!("{}/keystore/", fstp_backup::sigv4::hex(&CELL));
    w.fake
        .state
        .objects
        .lock()
        .unwrap()
        .iter()
        .filter(|(k, _)| k.starts_with(&prefix) && !k.contains("latest"))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Every snapshot image, opened through the snapshot key.
fn snapshot_images(w: &World) -> Vec<KeystoreRows> {
    let secret = block_on(w.snapshots.key().open_secret(&w.custody)).unwrap();
    snapshot_objects(w)
        .values()
        .map(|bytes| {
            // ADR-012 record of lane m10/backup-followups: `FBC2`, signed by the
            // vault's snapshot writer key.
            let writer = w.snapshots.key().file().writer_public().unwrap();
            let opened = fstp_backup::open_object(&secret, &writer[..], bytes).unwrap();
            let (cell, rows) = snapshot::decode_image(&opened.plaintext).unwrap();
            assert_eq!(cell, CELL);
            rows
        })
        .collect()
}

/// The GET requests the fake served for `name`.
fn gets_of(w: &World, name: &str) -> usize {
    w.fake
        .state
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter(|(m, p)| m == "GET" && p.trim_end_matches('?').ends_with(name))
        .count()
}

/// Whether the root of `epoch` still unwraps its seal key in custody.
fn epoch_lives(w: &World, rows: &KeystoreRows, epoch: u64) -> bool {
    rows.all_roots()
        .filter(|r| r.epoch == epoch && !r.wrapped.is_empty())
        .any(|r| {
            let root = RootRef {
                backend: BackendId::Keyd,
                cell: Some(fstp_custody::CellId(CELL)),
                chain: fstp_custody::Chain::Vault,
                epoch: fstp_custody::Epoch(r.epoch),
                handle: CustodyHandle(r.handle.clone()),
            };
            block_on(w.custody.unwrap(
                &root,
                &WrappedSealKey(r.wrapped.clone()),
                &keystore::seal_aad(&CELL, r.epoch),
            ))
            .is_ok()
        })
}

/// Steps the runner until `want`, and returns every event on the way.
fn step_until(p: &mut Process<'_>, want: ErasureEvent) -> Vec<ErasureEvent> {
    let mut seen = Vec::new();
    loop {
        let e = p.step().unwrap().expect("the batch ended early");
        seen.push(e);
        if e == want {
            return seen;
        }
    }
}

// ---------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------

/// I-81, R-KY-02, ADR-004 step 5, ADR-012 record of lane L17: a rotation
/// on the Vault chain uploads a snapshot, fetches it back from the object
/// store, and opens it under `R(e+1)` before step 6. Until then `R(e)`
/// lives. The verified snapshot opens every live key, and the pointer
/// names it only once it verified.
#[test]
fn i81_vault_old_epoch_dies_only_after_a_fetched_snapshot_opens() {
    let w = genesis();
    let mut p = start(&w);
    let a = p.register(ALICE);
    let b = p.register(BRUNO);
    block_on(p.runner.request_erasure(b)).unwrap();
    step_until(&mut p, ErasureEvent::SnapshotTaken { epoch: 2 });
    let objects = snapshot_objects(&w);
    assert_eq!(objects.len(), 1, "one snapshot uploaded at step 5");
    let name = objects.keys().next().unwrap().clone();
    assert_eq!(gets_of(&w, &name), 0);
    assert_eq!(block_on(w.snapshots.latest()).unwrap(), None);
    let rows = read_rows(&w);
    assert!(epoch_lives(&w, &rows, 1), "R(1) died before step 5");
    assert_eq!(
        p.step().unwrap(),
        Some(ErasureEvent::SnapshotVerified { epoch: 2 })
    );
    assert_eq!(gets_of(&w, &name), 1, "step 5 did not fetch the snapshot");
    assert!(epoch_lives(&w, &rows, 1), "R(1) died at step 5");
    let latest = block_on(w.snapshots.latest()).unwrap().unwrap();
    assert!(name.ends_with(&fstp_backup::sigv4::hex(&latest)));
    assert_eq!(
        p.step().unwrap(),
        Some(ErasureEvent::RootDestroyed { epoch: 1 })
    );
    assert!(!epoch_lives(&w, &rows, 1), "R(1) outlived step 6");
    p.run_to_idle();
    // The verified snapshot opens every live key under R(2), and the
    // live identity's tuple from it alone.
    let images = snapshot_images(&w);
    assert_eq!(images[0].root.epoch, 2);
    block_on(fstp_vault::erasure::check_rows(
        &w.custody, &CELL, &images[0],
    ))
    .unwrap();
    assert_eq!(opens_tuple(&w, &[&images[0]], a).as_deref(), Some(ALICE));
    assert_eq!(opens_tuple(&w, &[&images[0]], b), None);
    assert!(w.fake.state.violations.lock().unwrap().is_empty());
}

/// I-81, ADR-012 record of lane L17 "Failure": a snapshot changed in the
/// object store fails step 5, and `R(e)` lives. The next attempt uploads
/// a fresh snapshot, verifies it, and only then destroys `R(e)`.
#[test]
fn i81_vault_tampered_snapshot_blocks_destroy() {
    let w = genesis();
    let mut p = start(&w);
    p.register(ALICE);
    let b = p.register(BRUNO);
    block_on(p.runner.request_erasure(b)).unwrap();
    step_until(&mut p, ErasureEvent::SnapshotTaken { epoch: 2 });
    let rows = read_rows(&w);
    {
        let mut objects = w.fake.state.objects.lock().unwrap();
        let (_, o) = objects
            .iter_mut()
            .find(|(k, _)| k.contains("/keystore/") && !k.contains("latest"))
            .unwrap();
        let at = o.len() - 5;
        o[at] ^= 0x40;
    }
    assert!(p.step().is_err(), "a changed snapshot verified");
    assert!(
        epoch_lives(&w, &rows, 1),
        "I-81: R(1) died after a failed check"
    );
    assert_eq!(block_on(w.snapshots.latest()).unwrap(), None);
    assert_eq!(
        p.step().unwrap(),
        Some(ErasureEvent::SnapshotVerified { epoch: 2 })
    );
    assert_eq!(snapshot_objects(&w).len(), 2, "no fresh snapshot");
    assert!(epoch_lives(&w, &rows, 1));
    let events = p.run_to_idle();
    assert!(events.contains(&ErasureEvent::RootDestroyed { epoch: 1 }));
    assert!(!epoch_lives(&w, &rows, 1));
}

/// I-81, ADR-012 record of lane L17 "Failure": a snapshot missing from
/// the object store fails step 5, and `R(e)` lives.
#[test]
fn i81_vault_missing_snapshot_blocks_destroy() {
    let w = genesis();
    let mut p = start(&w);
    p.register(ALICE);
    let b = p.register(BRUNO);
    block_on(p.runner.request_erasure(b)).unwrap();
    step_until(&mut p, ErasureEvent::SnapshotTaken { epoch: 2 });
    let rows = read_rows(&w);
    w.fake.state.objects.lock().unwrap().clear();
    let r = p.step();
    assert!(r.is_err(), "a missing snapshot verified: {r:?}");
    assert!(
        epoch_lives(&w, &rows, 1),
        "I-81: R(1) died with no snapshot"
    );
    assert_eq!(block_on(w.snapshots.latest()).unwrap(), None);
}

/// I-81, ADR-004 record of lane L13 "Snapshots and backups": once a batch
/// completes, no snapshot ever taken opens the erased identity's tuple,
/// through any root custody still holds. Before the second batch the
/// first snapshot opens it, so the check has teeth.
#[test]
fn i81_vault_erased_identity_unreadable_from_every_snapshot() {
    let w = genesis();
    let mut p = start(&w);
    let a = p.register(ALICE);
    let b = p.register(BRUNO);
    let c = p.register(CARLA);
    block_on(p.runner.request_erasure(c)).unwrap();
    p.run_to_idle();
    let first = snapshot_images(&w);
    assert_eq!(first.len(), 1);
    assert_eq!(
        opens_tuple(&w, &[&first[0]], b).as_deref(),
        Some(BRUNO),
        "the first snapshot does not open a live tuple"
    );
    block_on(p.runner.request_erasure(b)).unwrap();
    p.run_to_idle();
    let all = snapshot_images(&w);
    assert_eq!(all.len(), 2);
    let sets: Vec<&KeystoreRows> = all.iter().collect();
    assert_eq!(
        opens_tuple(&w, &sets, b),
        None,
        "I-81: B opens from a snapshot"
    );
    assert_eq!(
        opens_tuple(&w, &sets, c),
        None,
        "I-81: C opens from a snapshot"
    );
    assert_eq!(opens_tuple(&w, &sets, a).as_deref(), Some(ALICE));
}

/// ADR-012 record of lane L17, row "Restore rule, vault": a database
/// restored from before the last rotation opens nothing, so the restore
/// takes the newest snapshot whole, and the live identities open again
/// while the erased one stays unreadable. A restored database newer than
/// the snapshot is kept as it is, with the identity registered after the
/// snapshot. With no snapshot, an old database is refused.
#[test]
fn adr012_vault_restore_takes_the_newest_copy_that_opens() {
    let w = genesis();
    let mut p = start(&w);
    let a = p.register(ALICE);
    let c = p.register(CARLA);
    let before = read_rows(&w);
    block_on(p.runner.request_erasure(c)).unwrap();
    p.run_to_idle();
    drop(p);
    // A database restored from before the rotation.
    let old = fresh_db();
    let mut k = old.connect();
    block_on(snapshot::write_copy(&mut k, &before, NOW)).unwrap();
    block_on(keystore::read_rows(&mut k)).unwrap().unwrap();
    let source = block_on(snapshot::restore_with(
        &mut k,
        &w.custody,
        CELL,
        Some(&w.snapshots),
        None,
        NOW,
    ))
    .unwrap();
    assert_eq!(source, Source::Snapshot);
    let restored = block_on(keystore::read_rows(&mut k)).unwrap().unwrap();
    block_on(k.close()).unwrap();
    assert_eq!(restored.root.epoch, 2);
    let runner = block_on(Runner::load(old.connect(), CELL, &w.custody)).unwrap();
    assert_eq!(runner.tuple(a).unwrap(), ALICE.to_vec());
    assert!(runner.tuple(c).is_err(), "I-81: a restore brought back C");
    assert_eq!(opens_tuple(&w, &[&restored, &before], c), None);
    drop(runner);
    // A database newer than the snapshot: an identity registered since.
    let mut p = start(&w);
    let b = p.register(BRUNO);
    drop(p);
    let mut k = w.db.connect();
    let source = block_on(snapshot::restore_with(
        &mut k,
        &w.custody,
        CELL,
        Some(&w.snapshots),
        None,
        NOW,
    ))
    .unwrap();
    assert_eq!(source, Source::Backup);
    block_on(k.close()).unwrap();
    let runner = block_on(Runner::load(w.db.connect(), CELL, &w.custody)).unwrap();
    assert_eq!(runner.tuple(b).unwrap(), BRUNO.to_vec());
    drop(runner);
    // No snapshot: the old database opens nothing.
    let older = fresh_db();
    let mut k = older.connect();
    block_on(snapshot::write_copy(&mut k, &before, NOW)).unwrap();
    assert!(
        block_on(snapshot::restore_with(
            &mut k, &w.custody, CELL, None, None, NOW
        ))
        .is_err(),
        "I-81: a copy under a destroyed epoch was restored"
    );
    // A named snapshot that does not exist is refused.
    assert!(
        block_on(snapshot::restore_with(
            &mut k,
            &w.custody,
            CELL,
            Some(&w.snapshots),
            Some([0xee; 16]),
            NOW,
        ))
        .is_err()
    );
}

fn status_dir(what: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "fstp-vault-l27-{what}-{}",
        fstp_backup::sigv4::hex(&fstp_crypto::random_array::<6>().unwrap())
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// I-81, ADR-012 record of lane L27, row "Daily snapshot": the daily
/// snapshot uploads the keystore, fetches it back and opens it under the
/// current root, with no rotation: the epoch stays and no root dies. The
/// pointer names it and the status file says it verified.
#[test]
fn i81_vault_daily_snapshot_verifies_without_a_rotation() {
    use fstp_vault::snapshot::{Daily, DailySnapshot as _};
    let w = genesis();
    let mut p = start(&w);
    let a = p.register(ALICE);
    drop(p);
    let before = read_rows(&w);
    let dir = status_dir("ok");
    let daily = Daily {
        cell: CELL,
        snapshots: w.snapshots.clone(),
        custody: w.custody.clone(),
        status_dir: Some(dir.clone()),
    };
    assert!(
        block_on(daily.run(before.clone())),
        "the daily snapshot failed"
    );
    let after = read_rows(&w);
    assert!(after == before, "the daily snapshot changed the keystore");
    assert!(epoch_lives(&w, &after, 1));
    let images = snapshot_images(&w);
    assert_eq!(images.len(), 1);
    assert_eq!(images[0].root.epoch, 1);
    assert_eq!(opens_tuple(&w, &[&images[0]], a).as_deref(), Some(ALICE));
    assert!(block_on(w.snapshots.latest()).unwrap().is_some());
    let s = fstp_obs::snapshot_status::read(&dir);
    assert!(s.last_verified.is_some() && !s.failing());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// ADR-012 record of lane L27, rows "Daily snapshot" and "Status file": a
/// daily snapshot the object store refuses fails, shows as failing in the
/// status file, writes no pointer and changes no key.
#[test]
fn adr012_vault_daily_snapshot_failure_shows_on_status() {
    use fstp_vault::snapshot::{Daily, DailySnapshot as _};
    let w = genesis();
    let before = read_rows(&w);
    let wrong = S3Client::with_tls(
        rt().clone(),
        Endpoint {
            host: "localhost".to_owned(),
            port: w.fake.port(),
            region: REGION.to_owned(),
            bucket: BUCKET.to_owned(),
        },
        Credentials::new(AK, "not-the-secret").unwrap(),
        fstp_tls::ClientConfig::new(fake_s3::CA_PEM).unwrap(),
    );
    let dir = status_dir("fail");
    let daily = Daily {
        cell: CELL,
        snapshots: Snapshots::new(Arc::new(wrong), w.snapshots.key().clone()),
        custody: w.custody.clone(),
        status_dir: Some(dir.clone()),
    };
    assert!(
        !block_on(daily.run(before.clone())),
        "a refused upload verified"
    );
    let s = fstp_obs::snapshot_status::read(&dir);
    assert!(s.failing(), "the failure does not show on status");
    assert_eq!(block_on(w.snapshots.latest()).unwrap(), None);
    assert!(read_rows(&w) == before);
    assert!(epoch_lives(&w, &before, 1));
    std::fs::remove_dir_all(&dir).unwrap();
}
