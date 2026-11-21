//! Erasure on the Vault chain over a real PostgreSQL server (design
//! section 3.5, I-81, R-KY-02, G24, ADR-004 record of lane L11).
//!
//! Each test makes a fresh vault database, runs the vault keystore's
//! genesis as `fstp-vault init-keys` does, registers synthetic identities
//! and erases one through `fstp_vault::erasure`. Custody is a stub in this
//! process with one AES key per root, so a destroyed root really stops
//! unwrapping. The identity rekey and the step 7 records go through
//! `fstp_vault::store::persist`, since the vault chain writer needs a
//! witness (`vault_chain.rs` covers it).
//!
//! A "reader of copies" holds every keystore row ever read: the rows
//! before the erasure, as a backup or a WAL segment holds them, and the
//! live rows after it. It tries every root under custody, every group row
//! under every seal key it opened, and every data key under every group
//! secret it opened.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

use std::collections::{BTreeMap, BTreeSet};
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
use fstp_keys::erasure::Phase;
use fstp_pgtest::{PgServer, Role, tls as certs};
use fstp_pgwire::{Client, ClientTls, Config, Password};
use fstp_rt::tokio::TokioRuntime;
use fstp_vault::erasure::{ErasureEvent, Journal, Runner};
use fstp_vault::keystore::{self, KeystoreRows, VaultKeys};
use fstp_vault::service::AeadSealer;
use fstp_vault::{JournalEntry, Vault, VaultError, store};
use fstp_vault_core::Person;

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

impl StubCustody {
    fn created(&self) -> u32 {
        self.roots.lock().unwrap().created
    }

    fn live(&self) -> usize {
        self.roots
            .lock()
            .unwrap()
            .keys
            .values()
            .filter(|k| k.is_some())
            .count()
    }
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
    anchor: Vec<u8>,
}

fn genesis() -> World {
    let db = fresh_db();
    let custody = StubCustody::default();
    let keys = VaultKeys::generate().unwrap();
    let rows = block_on(keystore::genesis(&custody, CELL, &keys, NOW)).unwrap();
    let mut c = db.connect();
    block_on(keystore::write_rows(&mut c, &rows)).unwrap();
    block_on(c.close()).unwrap();
    World {
        db,
        custody,
        anchor: keys.anchor_public(),
    }
}

/// A running vault process: the runner over the keys login, the vault
/// and its journal over the vault login.
struct Process {
    runner: Runner<TokioRuntime, StubCustody>,
    vault: Vault,
    journal: StoreJournal,
}

fn start(w: &World) -> Process {
    let runner =
        block_on(Runner::load(w.db.connect(), CELL, w.custody.clone())).unwrap_or_else(|e| {
            panic!("the runner did not load: {e}");
        });
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

impl Process {
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

    fn stored_match_key(&self, p: Person) -> Option<[u8; 32]> {
        self.vault
            .identity_keys()
            .find(|(_, q)| *q == p)
            .map(|(k, _)| k)
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

/// Every `Match` HMAC key the reader of `sets` opens.
fn match_keys(w: &World, sets: &[&KeystoreRows]) -> Vec<[u8; 32]> {
    reach(w, sets)
        .kem
        .iter()
        .filter(|(_, p, _)| *p == Purpose::Match.code())
        .map(|(_, _, sk)| *keystore::match_hmac_key(sk).unwrap().expose())
        .collect()
}

/// The checks every finished batch passes: the erased identity's tuple
/// opens from no copy and its match key is recomputed by no key, while
/// the live identities open and match.
fn check_after(
    w: &World,
    p: &Process,
    before: &KeystoreRows,
    erased: (Person, &[u8], [u8; 32]),
    live: &[(Person, &[u8])],
) {
    let after = read_rows(w);
    assert_eq!(p.runner.phase(), Phase::Idle);
    assert_eq!(p.runner.epoch(), 2, "one rotation from epoch 1 to 2");
    assert_eq!(after.root.epoch, 2);
    assert_eq!(w.custody.live(), 1, "I-81: the old root still lives");
    assert!(
        after.all_roots().all(|r| r.epoch == 2 || r.state == 2),
        "I-81: an old root row is not marked destroyed"
    );
    let (gone, tuple, old_key) = erased;
    assert_eq!(
        opens_tuple(w, &[before, &after], gone),
        None,
        "I-81: an erased identity's tuple opens from a copy"
    );
    assert!(
        p.runner.tuple(gone).is_err(),
        "I-81: the live store opens it"
    );
    for k in match_keys(w, &[before, &after]) {
        assert_ne!(
            fstp_vault::match_key(&k, tuple),
            old_key,
            "G24: a live key recomputes the erased match key"
        );
        let now = fstp_vault::match_key(&k, tuple);
        assert!(
            p.vault.identity_keys().all(|(stored, _)| stored != now),
            "G24: the erased tuple still links to a stored identity"
        );
    }
    assert_ne!(p.stored_match_key(gone), Some(old_key));
    for (person, t) in live {
        assert_eq!(p.runner.tuple(*person).unwrap(), t.to_vec());
        assert_eq!(
            p.stored_match_key(*person),
            Some(p.runner.match_key(t).unwrap()),
            "a live identity's stored match key is not under the new Match key"
        );
        assert_eq!(opens_tuple(w, &[&after], *person).as_deref(), Some(*t));
    }
}

// ---------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------

/// I-81, R-KY-02, design section 3.5: after an erasure batch on the Vault
/// chain, the erased identity's sealed key and tuple open neither from
/// the keystore rows as they stood before the batch, as a backup holds
/// them, nor from the live store. Before the batch the same reader opens
/// them, so the check has teeth. The tuple is refused from the request
/// on, before any key moved.
#[test]
fn i81_vault_erased_identity_key_unreadable_from_backup_rows_and_live_store() {
    let w = genesis();
    let mut p = start(&w);
    let a = p.register(ALICE);
    let b = p.register(BRUNO);
    let c = p.register(CARLA);
    assert_eq!(
        p.register(BRUNO),
        b,
        "a known tuple resolves to its identity"
    );
    let before = read_rows(&w);
    assert_eq!(
        opens_tuple(&w, &[&before], b).as_deref(),
        Some(BRUNO),
        "the reader of copies opens a live tuple before the batch"
    );
    let old_key = p.stored_match_key(b).unwrap();
    block_on(p.runner.request_erasure(b)).unwrap();
    assert!(
        p.runner.tuple(b).is_err(),
        "I-81: a requested tuple still opens"
    );
    let events = p.run_to_idle();
    assert!(matches!(
        events.last(),
        Some(ErasureEvent::CompletionRecorded { epoch: 1 })
    ));
    check_after(
        &w,
        &p,
        &before,
        (b, BRUNO, old_key),
        &[(a, ALICE), (c, CARLA)],
    );
    // Step 7 recorded the destroyed epoch and the erased identity.
    assert!(
        p.journal
            .seen
            .iter()
            .any(|e| matches!(e, JournalEntry::KeyEpochDestroyed { epoch: 1, .. }))
    );
    assert!(p.journal.seen.iter().any(|e| matches!(
        e,
        JournalEntry::IdentityErased { identity } if *identity == b
    )));
}

/// G24, design section 3.5 "Keyed digests": after the batch no key that
/// any copy of the keystore opens recomputes the erased identity's match
/// key, and the query digest key moved with the `Match` key. Before the
/// batch the reader does recompute it, so the check has teeth.
#[test]
fn g24_vault_no_live_key_recomputes_an_erased_match_digest() {
    let w = genesis();
    let mut p = start(&w);
    let a = p.register(ALICE);
    let b = p.register(BRUNO);
    let before = read_rows(&w);
    let old_key = p.stored_match_key(b).unwrap();
    assert!(
        match_keys(&w, &[&before])
            .iter()
            .any(|k| fstp_vault::match_key(k, BRUNO) == old_key),
        "the reader recomputes a live match key before the batch"
    );
    let query_before = *p
        .runner
        .service_keys()
        .unwrap()
        .query_digest_key()
        .unwrap()
        .expose();
    block_on(p.runner.request_erasure(b)).unwrap();
    p.run_to_idle();
    for k in match_keys(&w, &[&before, &read_rows(&w)]) {
        assert_ne!(fstp_vault::match_key(&k, BRUNO), old_key, "G24");
    }
    let query_after = *p
        .runner
        .service_keys()
        .unwrap()
        .query_digest_key()
        .unwrap()
        .expose();
    assert_ne!(
        query_before, query_after,
        "G24: the query digest key did not rotate"
    );
    check_after(&w, &p, &before, (b, BRUNO, old_key), &[(a, ALICE)]);
    // The erased tuple, registered again, is a new identity.
    let again = p.register(BRUNO);
    assert!(
        again != a && again != b,
        "G24: the erased tuple still links"
    );
}

/// The work units of one clean batch, counted on a world of its own.
fn units_of_a_batch() -> usize {
    let w = genesis();
    let mut p = start(&w);
    p.register(ALICE);
    let b = p.register(BRUNO);
    block_on(p.runner.request_erasure(b)).unwrap();
    p.run_to_idle().len()
}

/// I-81, R-KY-02, design section 3.5 "A crash at any step loses nothing":
/// the process dies after every unit of the batch in turn, losing all its
/// memory. A new process loads the rows, resumes from the stored phase and
/// completes the batch. Nothing live is lost and nothing erased opens.
/// Two crashes inside a unit are covered as well: after the custody
/// destroy and before its row, and in the step 7 journal.
#[test]
fn i81_vault_erasure_resumes_after_crash_at_every_step() {
    let units = units_of_a_batch();
    assert!(units >= 10, "a batch of {units} units");
    for k in 0..=units {
        let w = genesis();
        let mut p = start(&w);
        let a = p.register(ALICE);
        let b = p.register(BRUNO);
        let c = p.register(CARLA);
        let before = read_rows(&w);
        let old_key = p.stored_match_key(b).unwrap();
        block_on(p.runner.request_erasure(b)).unwrap();
        for _ in 0..k {
            p.step()
                .unwrap_or_else(|e| panic!("unit before crash {k}: {e}"));
        }
        drop(p);
        let mut p = start(&w);
        p.run_to_idle();
        check_after(
            &w,
            &p,
            &before,
            (b, BRUNO, old_key),
            &[(a, ALICE), (c, CARLA)],
        );
        assert!(
            w.custody.created() <= 2,
            "crash after unit {k}: an orphan root was created"
        );
        let mut again = start(&w);
        assert!(again.step().unwrap().is_none(), "a finished batch resumed");
    }
    // Custody destroyed the root, but the process died before the row.
    let w = genesis();
    let mut p = start(&w);
    let a = p.register(ALICE);
    let b = p.register(BRUNO);
    let before = read_rows(&w);
    let old_key = p.stored_match_key(b).unwrap();
    block_on(p.runner.request_erasure(b)).unwrap();
    w.custody.fail_after_destroy.store(true, Ordering::SeqCst);
    let failed = block_on(p.runner.run_to_idle(&mut p.vault, &mut p.journal, NOW));
    assert!(failed.is_err(), "the failed destroy was not reported");
    drop(p);
    let mut p = start(&w);
    p.run_to_idle();
    check_after(&w, &p, &before, (b, BRUNO, old_key), &[(a, ALICE)]);
    // The step 7 journal failed once: the batch completes on the retry.
    let w = genesis();
    let mut p = start(&w);
    let a = p.register(ALICE);
    let b = p.register(BRUNO);
    let before = read_rows(&w);
    let old_key = p.stored_match_key(b).unwrap();
    block_on(p.runner.request_erasure(b)).unwrap();
    let n = p.journal.commits.load(Ordering::SeqCst);
    // The rekey is the next commit, and step 7 the one after it.
    p.journal.fail_on = Some(n + 2);
    assert!(block_on(p.runner.run_to_idle(&mut p.vault, &mut p.journal, NOW)).is_err());
    assert_eq!(p.runner.phase(), Phase::Destroyed);
    drop(p);
    let mut p = start(&w);
    p.run_to_idle();
    check_after(&w, &p, &before, (b, BRUNO, old_key), &[(a, ALICE)]);
}

/// R-KY-02, ADR-004 record of lane L11: live identities stay readable
/// after the rotation and after a restart of the vault. A new process
/// opens every live tuple, the stored match keys are those under the new
/// `Match` key, and the start path of `fstp_vault::run` opens the rotated
/// rows to the same anchor key. A second batch rotates again.
#[test]
fn r_ky_02_vault_live_identities_readable_after_rotation_and_restart() {
    let w = genesis();
    let mut p = start(&w);
    let a = p.register(ALICE);
    let b = p.register(BRUNO);
    let c = p.register(CARLA);
    let dek = p.runner.service_keys().unwrap().dek();
    block_on(p.runner.request_erasure(b)).unwrap();
    p.run_to_idle();
    drop(p);
    // A restart: new connections, nothing kept in memory.
    let mut p = start(&w);
    assert_eq!(p.runner.epoch(), 2);
    for (person, t) in [(a, ALICE), (c, CARLA)] {
        assert_eq!(p.runner.tuple(person).unwrap(), t.to_vec());
        assert_eq!(
            p.register(t),
            person,
            "a live tuple resolves to its identity"
        );
    }
    // The start path opens the rotated keystore.
    let rows = read_rows(&w);
    let keys = block_on(keystore::open(&w.custody, CELL, &rows)).unwrap();
    assert_eq!(keys.anchor_public(), w.anchor);
    assert_eq!(keys.dek(), dek, "the Fact data key changed");
    assert_eq!(
        keys.query_digest_key().unwrap().expose(),
        p.runner
            .service_keys()
            .unwrap()
            .query_digest_key()
            .unwrap()
            .expose()
    );
    // A second batch, from epoch 2 to 3.
    block_on(p.runner.request_erasure(c)).unwrap();
    p.run_to_idle();
    assert_eq!(p.runner.epoch(), 3);
    drop(p);
    let p = start(&w);
    assert_eq!(p.runner.tuple(a).unwrap(), ALICE.to_vec());
    assert!(p.runner.tuple(c).is_err());
    assert_eq!(w.custody.live(), 1);
    let erased: BTreeSet<_> = [b, c].into_iter().collect();
    assert!(p.vault.identity_keys().all(|(k, q)| {
        !erased.contains(&q)
            || k != p
                .runner
                .match_key(if q == b { BRUNO } else { CARLA })
                .unwrap()
    }));
}

/// I-81: an identity with no stored tuple, and an unknown identity, are
/// refused, and nothing is written.
#[test]
fn i81_vault_erasure_refuses_an_identity_without_a_tuple() {
    let w = genesis();
    let mut p = start(&w);
    p.register(ALICE);
    let before = read_rows(&w);
    assert!(block_on(p.runner.request_erasure(Person(999))).is_err());
    assert_eq!(p.runner.phase(), Phase::Idle);
    assert_eq!(read_rows(&w), before);
}
