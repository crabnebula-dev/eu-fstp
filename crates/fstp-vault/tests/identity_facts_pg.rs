//! Identity facts and their registration over a real PostgreSQL server
//! (ADR-004 record of lane L13, I-81, R-KY-02, R-NF-08).
//!
//! Each test makes a fresh vault database, runs the keystore genesis as
//! `fstp-vault init-keys` does, registers synthetic identities with their
//! accounts, writes their bank details and hardship evidence, and erases
//! one identity through `fstp_vault::erasure`. Custody is a stub in this
//! process with one AES key per root, so a destroyed root really stops
//! unwrapping (the stub of `erasure_pg.rs`).
//!
//! A "reader of copies" holds every keystore row it ever read, as a
//! backup, a WAL segment or a keystore snapshot holds them, and every
//! `vault.fact` row. It tries every root under custody, every group row
//! under every seal key it opened, every tuple data key under every group
//! secret it opened, and every fact body under every fact key it derived.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
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
use fstp_pgwire::{Client, ClientTls, Config, Password, Uuid};
use fstp_rt::tokio::TokioRuntime;
use fstp_vault::erasure::{ErasureEvent, Journal, Runner};
use fstp_vault::keystore::{self, KeystoreRows, VaultKeys};
use fstp_vault::service::AeadSealer;
use fstp_vault::store::{self, Sealer};
use fstp_vault::{JournalEntry, Vault, VaultError};
use fstp_vault_core::{Fact, Person};
use fstp_vault_proto::{
    VaultRequest, VaultResponse, WireAccount, WireEvidence, WireProgramme, WireProposal,
};

type Pg = Client<TokioRuntime>;

fn rt() -> &'static TokioRuntime {
    static RT: OnceLock<TokioRuntime> = OnceLock::new();
    RT.get_or_init(|| TokioRuntime::new_multi_thread(2).unwrap())
}

fn block_on<F: Future>(f: F) -> F::Output {
    rt().block_on(f)
}

const CELL: [u8; 16] = [0x7e; 16];
const NOW: i64 = 1_800_000_000_000_000;
/// The seed of the cell's ticket key in these tests.
const SIGNER: u8 = 3;

/// Synthetic attribute tuples (corpus only).
const ALICE: &[u8] = b"synthetic|manual|passport|name=Synthetic Alpha|0001";
const BRUNO: &[u8] = b"synthetic|manual|passport|name=Synthetic Bravo|0002";
const CARLA: &[u8] = b"synthetic|manual|passport|name=Synthetic Charlie|0003";

/// Synthetic accounts, one per tuple, and their grants.
const A_ACCOUNT: u128 = 101;
const B_ACCOUNT: u128 = 102;
const C_ACCOUNT: u128 = 103;
const IBAN: &str = "DE89370400440532013000";

fn grant_of(account: u128) -> WireProposal {
    WireProposal(account + 1000)
}

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
// The vault journal without the chain writer.
// ---------------------------------------------------------------------

struct StoreJournal {
    client: Pg,
    sealer: AeadSealer,
    /// Fails the next commit that writes a verification, once.
    fail_verification: bool,
}

impl Journal for StoreJournal {
    async fn commit(&mut self, entries: &[JournalEntry], _now: i64) -> Result<(), VaultError> {
        let verification = entries.iter().any(|e| {
            matches!(
                e,
                JournalEntry::Written {
                    fact: Fact::VerificationRecorded { .. },
                    ..
                }
            )
        });
        if verification && std::mem::take(&mut self.fail_verification) {
            return Err(VaultError::Unavailable("a test journal failure"));
        }
        store::persist(&mut self.client, &self.sealer, entries).await
    }
}

// ---------------------------------------------------------------------
// A vault database with a keystore from genesis.
// ---------------------------------------------------------------------

struct World {
    cfg: Config,
    custody: StubCustody,
}

impl World {
    fn connect(&self) -> Pg {
        block_on(Client::connect(rt(), &self.cfg)).unwrap_or_else(|e| panic!("connect: {e}"))
    }
}

fn genesis() -> World {
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
    let w = World {
        cfg,
        custody: StubCustody::default(),
    };
    let mut c = w.connect();
    block_on(store::migrate(&mut c)).unwrap();
    let keys = VaultKeys::generate().unwrap();
    let rows = block_on(keystore::genesis(&w.custody, CELL, &keys, NOW)).unwrap();
    block_on(keystore::write_rows(&mut c, &rows)).unwrap();
    block_on(c.close()).unwrap();
    w
}

/// A running vault process: the runner over the keys login, the vault
/// and its journal over the vault login, with the sealer that holds the
/// identity fact keys.
struct Process<'w> {
    runner: Runner<'w, TokioRuntime, StubCustody>,
    vault: Vault,
    journal: StoreJournal,
    seq: u64,
}

fn start(w: &World) -> Process<'_> {
    let runner = block_on(Runner::load(w.connect(), CELL, &w.custody))
        .unwrap_or_else(|e| panic!("the runner did not load: {e}"));
    let (_, sealer) = runner.service_keys().unwrap().into_service_keys().unwrap();
    let sealer = sealer.with_identities(runner.identity_keys());
    let mut vc = w.connect();
    let vault = block_on(store::load(
        &mut vc,
        &sealer,
        CELL,
        &[common::vc::Signer::new(SIGNER).public()],
    ))
    .unwrap();
    Process {
        runner,
        vault,
        journal: StoreJournal {
            client: vc,
            sealer,
            fail_verification: false,
        },
        seq: 1000,
    }
}

impl Process<'_> {
    fn register(&mut self, account: u128, tuple: &[u8]) -> Result<Person, VaultError> {
        block_on(self.runner.register_account(
            &mut self.vault,
            &mut self.journal,
            WireAccount(account),
            tuple,
            NOW,
        ))
    }

    fn commit(&mut self) {
        let entries = self.vault.take_journal();
        block_on(self.journal.commit(&entries, NOW)).unwrap();
    }

    /// Takes `fact`, persists it and acknowledges its epoch.
    fn write(&mut self, fact: Fact) {
        self.vault.take_fact(fact, NOW).unwrap();
        self.commit();
        let epoch = self.vault.state().provisional().unwrap().epoch();
        self.seq += 1;
        let r = self.vault.internal(
            &VaultRequest::Ack {
                epoch,
                ledger_seq: self.seq,
                link: [7; 32],
            },
            NOW,
        );
        assert_eq!(r, VaultResponse::Acked);
        self.commit();
    }

    /// The bank details and hardship evidence of `account`'s grant.
    fn identity_facts(&mut self, account: u128) {
        self.write(bank(account));
        self.write(Fact::HardshipEvidence {
            grant: grant_of(account),
            evidence: WireEvidence(account),
            account: WireAccount(account),
            statement: "Synthetic hardship statement".to_owned(),
        });
    }

    fn step(&mut self) -> Option<ErasureEvent> {
        block_on(self.runner.step(&mut self.vault, &mut self.journal, NOW))
            .unwrap_or_else(|e| panic!("a unit failed: {e}"))
    }

    fn run_to_idle(&mut self) {
        block_on(
            self.runner
                .run_to_idle(&mut self.vault, &mut self.journal, NOW),
        )
        .unwrap_or_else(|e| panic!("the batch did not complete: {e}"));
    }
}

fn bank(account: u128) -> Fact {
    Fact::BankDetails {
        grant: grant_of(account),
        account: WireAccount(account),
        at: NOW,
        holder: "Synthetic Holder".to_owned(),
        iban: IBAN.to_owned(),
    }
}

fn read_rows(w: &World) -> KeystoreRows {
    let mut c = w.connect();
    let rows = block_on(keystore::read_rows(&mut c)).unwrap().unwrap();
    block_on(c.close()).unwrap();
    rows
}

/// One stored `vault.fact` row: epoch, kind, data key id and body.
#[derive(Clone, Debug, PartialEq, Eq)]
struct FactRow {
    epoch: u64,
    kind: i16,
    dek: [u8; 16],
    body: Vec<u8>,
}

fn fact_rows(w: &World) -> Vec<FactRow> {
    let mut c = w.connect();
    let rows = block_on(c.query(
        "SELECT epoch, kind, dek, body FROM vault.fact ORDER BY epoch",
        &[],
    ))
    .unwrap();
    block_on(c.close()).unwrap();
    rows.iter()
        .map(|r| FactRow {
            epoch: u64::try_from(r.get::<i64>(0).unwrap()).unwrap(),
            kind: r.get(1).unwrap(),
            dek: *r.get::<Uuid>(2).unwrap().as_bytes(),
            body: r.get(3).unwrap(),
        })
        .collect()
}

fn count(w: &World, sql: &'static str) -> i64 {
    let mut c = w.connect();
    let rows = block_on(c.query(sql, &[])).unwrap();
    block_on(c.close()).unwrap();
    rows[0].get(0).unwrap()
}

// ---------------------------------------------------------------------
// The reader of copies.
// ---------------------------------------------------------------------

/// Every `Attribute` group secret the reader of `sets` opens through
/// custody as it stands now.
fn attribute_secrets(w: &World, sets: &[&KeystoreRows]) -> Vec<([u8; 16], HybridSecretKey)> {
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
    let mut out = Vec::new();
    for rows in sets {
        for g in rows
            .groups
            .iter()
            .filter(|g| g.purpose == Purpose::Attribute.code())
        {
            for s in &seals {
                if let Ok(bytes) = keystore::open_group_secret(s, &CELL, g)
                    && let Ok(sk) = HybridSecretKey::from_bytes(&bytes)
                {
                    out.push((g.group, sk));
                }
            }
        }
    }
    out
}

/// Every fact key of `p` that the reader of `sets` derives.
fn fact_keys(w: &World, sets: &[&KeystoreRows], p: Person) -> Vec<SealKey> {
    let secrets = attribute_secrets(w, sets);
    let id = p.0.to_be_bytes();
    let mut out = Vec::new();
    for rows in sets {
        for d in rows.data_keys.iter().filter(|d| d.id == id) {
            let Ok(sealed) = envelope::decode_sealed_key(&d.sealed) else {
                continue;
            };
            for (group, sk) in secrets.iter().filter(|(g, _)| *g == d.group) {
                let ctx = keystore::attribute_ctx(&CELL, group, d.generation, &id);
                if let Ok(dk) = envelope::open_key(sk, &sealed, &ctx) {
                    out.push(keystore::identity_fact_key(&CELL, &id, &dk).unwrap());
                }
            }
        }
    }
    out
}

/// The bodies of `p`'s fact rows among `rows` that the reader of `sets`
/// opens.
fn opened_facts(w: &World, sets: &[&KeystoreRows], rows: &[FactRow], p: Person) -> Vec<Vec<u8>> {
    let keys = fact_keys(w, sets, p);
    let mut out = Vec::new();
    for r in rows.iter().filter(|r| r.dek == p.0.to_be_bytes()) {
        for k in &keys {
            let aead = fstp_crypto::aead::Key::from_bytes(k.expose()).unwrap();
            let (nonce, body) = r.body.split_at(fstp_crypto::aead::NONCE_LEN);
            if let Ok(plain) = fstp_crypto::aead::open(
                &aead,
                &nonce.try_into().unwrap(),
                &store::identity_fact_aad(r.epoch, p),
                body,
            ) {
                out.push(plain.to_vec());
            }
        }
    }
    out
}

// ---------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------

/// I-81, R-KY-02, ADR-004 record of lane L13 "Snapshots and backups":
/// after identity B is erased, no fact of B opens from the `vault.fact`
/// rows of a backup taken before the batch or from the live rows, under
/// any key the keystore rows before the batch, the step 5 snapshot or the
/// live store give. Before the batch the same reader opens them, so the
/// check has teeth. The facts of A and C still open, and the shared
/// facts of B's account stay. A restarted vault holds no bank detail and
/// no hardship evidence of B's grant, and B's account is unbound.
#[test]
fn i81_erased_identity_facts_unreadable_from_live_store_snapshot_and_backup() {
    let w = genesis();
    let mut p = start(&w);
    let a = p.register(A_ACCOUNT, ALICE).unwrap();
    let b = p.register(B_ACCOUNT, BRUNO).unwrap();
    let c = p.register(C_ACCOUNT, CARLA).unwrap();
    for account in [A_ACCOUNT, B_ACCOUNT, C_ACCOUNT] {
        p.identity_facts(account);
    }
    p.write(Fact::CountryStated {
        account: WireAccount(B_ACCOUNT),
        programme: WireProgramme(5),
        country: 276,
    });
    let backup_keys = read_rows(&w);
    let backup_facts = fact_rows(&w);
    assert_eq!(
        backup_facts
            .iter()
            .filter(|r| r.dek == b.0.to_be_bytes())
            .count(),
        2,
        "B's bank and hardship rows do not name B's key"
    );
    for r in &backup_facts {
        assert!(
            !r.body.windows(IBAN.len()).any(|x| x == IBAN.as_bytes()),
            "R-NF-08: a fact body holds the IBAN in plain text"
        );
    }
    assert_eq!(
        opened_facts(&w, &[&backup_keys], &backup_facts, b).len(),
        2,
        "the reader opens B's facts before the batch"
    );

    block_on(p.runner.request_erasure(b)).unwrap();
    let snapshot_keys = loop {
        match p.step() {
            Some(ErasureEvent::SnapshotTaken { .. }) => break read_rows(&w),
            Some(_) => {}
            None => panic!("the batch ended before its snapshot"),
        }
    };
    p.run_to_idle();
    assert_eq!(w.custody.live(), 1, "I-81: the old root still lives");
    let live_keys = read_rows(&w);
    let live_facts = fact_rows(&w);
    let every_key = [&backup_keys, &snapshot_keys, &live_keys];
    for rows in [&backup_facts, &live_facts] {
        assert!(
            opened_facts(&w, &every_key, rows, b).is_empty(),
            "I-81: an erased identity's fact opens from a copy"
        );
    }
    assert!(fact_keys(&w, &every_key, b).is_empty());
    for (person, account) in [(a, A_ACCOUNT), (c, C_ACCOUNT)] {
        assert_eq!(
            opened_facts(&w, &[&live_keys], &live_facts, person).len(),
            2,
            "R-KY-02: a live identity's facts do not open"
        );
        assert_eq!(p.vault.registered(WireAccount(account)), Some(person));
    }
    assert_eq!(p.vault.registered(WireAccount(B_ACCOUNT)), None);
    drop(p);

    // A restart over the live rows.
    let p = start(&w);
    let latest = p.vault.state().latest();
    assert!(
        latest.bank_of(grant_of(B_ACCOUNT)).is_none(),
        "I-81: the erased bank details replay"
    );
    assert!(
        latest
            .hardship_of(grant_of(B_ACCOUNT), WireEvidence(B_ACCOUNT))
            .is_none(),
        "I-81: the erased hardship evidence replays"
    );
    assert_eq!(
        latest.country_of(WireAccount(B_ACCOUNT), WireProgramme(5)),
        Some(276),
        "a shared fact of the account was dropped"
    );
    for account in [A_ACCOUNT, C_ACCOUNT] {
        let rec = latest.bank_of(grant_of(account)).unwrap();
        assert_eq!(rec.iban, IBAN);
    }
    assert_eq!(p.vault.registered(WireAccount(B_ACCOUNT)), None);
    assert_eq!(p.vault.registered(WireAccount(A_ACCOUNT)), Some(a));
    assert_eq!(
        p.journal
            .sealer
            .open_identity(b, &store::identity_fact_aad(1, b), &[0; 40])
            .unwrap(),
        None,
        "the live sealer still holds the erased identity's key"
    );
}

/// R-KY-02, ADR-004 record of lane L13: after an erasure and a restart,
/// a live identity's account keeps its binding and takes new identity
/// facts, which reload. The erased identity's account is refused until it
/// registers again, and its tuple then gives a new identity (G24).
#[test]
fn r_ky_02_live_identity_facts_open_after_erasure_and_restart() {
    let w = genesis();
    let mut p = start(&w);
    let a = p.register(A_ACCOUNT, ALICE).unwrap();
    let b = p.register(B_ACCOUNT, BRUNO).unwrap();
    p.identity_facts(A_ACCOUNT);
    p.identity_facts(B_ACCOUNT);
    block_on(p.runner.request_erasure(b)).unwrap();
    p.run_to_idle();
    drop(p);
    let mut p = start(&w);
    p.write(Fact::BankDetails {
        grant: grant_of(A_ACCOUNT),
        account: WireAccount(A_ACCOUNT),
        at: NOW + 1,
        holder: "Synthetic Holder Two".to_owned(),
        iban: IBAN.to_owned(),
    });
    let state = p.vault.state().clone();
    drop(p);
    let mut p = start(&w);
    assert_eq!(p.vault.state(), &state, "the reload differs");
    let rec = p
        .vault
        .state()
        .latest()
        .bank_of(grant_of(A_ACCOUNT))
        .unwrap();
    assert_eq!(rec.version, 2);
    assert_eq!(rec.holder, "Synthetic Holder Two");
    assert_eq!(p.vault.registered(WireAccount(A_ACCOUNT)), Some(a));
    let again = p.register(B_ACCOUNT, BRUNO).unwrap();
    assert!(
        again != a && again != b,
        "G24: the erased tuple still links"
    );
    p.identity_facts(B_ACCOUNT);
    drop(p);
    let p = start(&w);
    assert!(
        p.vault
            .state()
            .latest()
            .bank_of(grant_of(B_ACCOUNT))
            .is_some()
    );
}

/// ADR-004 record of lane L13 "Idempotence": registering the same
/// account and tuple again changes no row, a second account with the
/// same tuple joins the identity, and an account never moves to another
/// identity. The bindings survive a restart.
#[test]
fn adr004_identity_registration_is_idempotent() {
    let w = genesis();
    let mut p = start(&w);
    let a = p.register(A_ACCOUNT, ALICE).unwrap();
    let keys = read_rows(&w);
    let bindings = "SELECT count(*) FROM vault.identity_account";
    let identities = "SELECT count(*) FROM vault.identity";
    assert_eq!(count(&w, bindings), 1);
    assert_eq!(p.register(A_ACCOUNT, ALICE).unwrap(), a);
    assert_eq!(read_rows(&w), keys, "a repeat changed a keystore row");
    assert_eq!(count(&w, bindings), 1);
    assert_eq!(count(&w, identities), 1);
    assert_eq!(p.register(B_ACCOUNT, ALICE).unwrap(), a);
    assert_eq!(count(&w, bindings), 2);
    assert_eq!(read_rows(&w).tuples.len(), 1);
    assert!(
        p.register(A_ACCOUNT, BRUNO).is_err(),
        "an account moved to another identity"
    );
    assert!(p.register(A_ACCOUNT, b"").is_err(), "an empty tuple");
    assert_eq!(count(&w, bindings), 2);
    drop(p);
    let mut p = start(&w);
    assert_eq!(p.vault.registered(WireAccount(A_ACCOUNT)), Some(a));
    assert_eq!(p.vault.registered(WireAccount(B_ACCOUNT)), Some(a));
    assert_eq!(p.register(A_ACCOUNT, ALICE).unwrap(), a);
    assert_eq!(count(&w, bindings), 2);
}

/// I-81, ADR-004 record of lane L13 "Existing facts": the start check
/// refuses a vault that holds a bank detail or hardship evidence sealed
/// under the shared `Fact` key, which no erasure could make unreadable.
/// A vault whose identity facts are all sealed for their identities
/// passes.
#[test]
fn i81_start_refuses_shared_key_identity_facts() {
    let w = genesis();
    let mut p = start(&w);
    p.register(A_ACCOUNT, ALICE).unwrap();
    p.identity_facts(A_ACCOUNT);
    let mut c = w.connect();
    block_on(store::check_identity_facts(&mut c, &p.journal.sealer)).unwrap();
    // An unregistered account's bank details, through the library seam
    // the test world seeds with: sealed under the shared key.
    p.write(bank(B_ACCOUNT));
    assert!(
        block_on(store::check_identity_facts(&mut c, &p.journal.sealer)).is_err(),
        "I-81: a shared-key bank detail passed the start check"
    );
    block_on(c.close()).unwrap();
}

fn record(at: i64) -> fstp_vault_core::fact::VerificationRecord {
    use fstp_vault_core::fact::{Check, DocumentType, VerificationMethod, VerificationRecord};
    VerificationRecord {
        method: VerificationMethod::Manual,
        document_type: DocumentType::Passport,
        checks: [Check::DocumentAuthentic, Check::PhotoMatch]
            .into_iter()
            .collect(),
        at,
        verifier: WireAccount(0),
    }
}

/// A synthetic recorder account.
const RECORDER: u128 = 900;

impl Process<'_> {
    fn verify(
        &mut self,
        verifier: u128,
        account: u128,
        tuple: &[u8],
    ) -> Result<Person, VaultError> {
        block_on(self.runner.record_verification(
            &mut self.vault,
            &mut self.journal,
            WireAccount(verifier),
            WireAccount(account),
            record(NOW),
            tuple,
            NOW,
        ))
    }
}

/// R-ID-02, ADR-004 record of lane L13b "Verification with
/// registration" and "Retry": a verification registers the account
/// before it records the fact. When the fact's write fails, the account
/// is registered and unverified, and the same call again completes the
/// verification. A third call writes nothing. The account's bank details
/// are then taken and sealed for its identity, also after a restart.
#[test]
fn r_id_02_verification_registers_before_it_records_and_retries() {
    let w = genesis();
    let mut p = start(&w);
    let kind_6 = "SELECT count(*) FROM vault.fact WHERE kind = 6";
    let bindings = "SELECT count(*) FROM vault.identity_account";
    p.journal.fail_verification = true;
    assert!(p.verify(RECORDER, A_ACCOUNT, ALICE).is_err());
    assert_eq!(
        count(&w, bindings),
        1,
        "the registration did not come first"
    );
    assert_eq!(count(&w, kind_6), 0);
    let a = p.vault.registered(WireAccount(A_ACCOUNT)).unwrap();
    assert_eq!(p.verify(RECORDER, A_ACCOUNT, ALICE).unwrap(), a);
    assert_eq!(count(&w, kind_6), 1);
    assert_eq!(
        p.vault.state().latest().person_of(WireAccount(A_ACCOUNT)),
        Some(a)
    );
    assert_eq!(p.verify(RECORDER, A_ACCOUNT, ALICE).unwrap(), a);
    assert_eq!(count(&w, kind_6), 1, "a repeat wrote a second verification");
    assert_eq!(count(&w, bindings), 1);
    // The verification is provisional until the cell acknowledges it.
    let epoch = p.vault.state().provisional().unwrap().epoch();
    let r = p.vault.internal(
        &VaultRequest::Ack {
            epoch,
            ledger_seq: 1,
            link: [7; 32],
        },
        NOW,
    );
    assert_eq!(r, VaultResponse::Acked);
    p.commit();
    p.identity_facts(A_ACCOUNT);
    let rows = fact_rows(&w);
    assert!(
        rows.iter()
            .filter(|r| r.kind == 14 || r.kind == 17)
            .all(|r| r.dek == a.0.to_be_bytes()),
        "I-81: a verified account's identity fact is not sealed for its identity"
    );
    drop(p);
    let mut p = start(&w);
    assert_eq!(p.vault.registered(WireAccount(A_ACCOUNT)), Some(a));
    assert_eq!(p.verify(RECORDER, A_ACCOUNT, ALICE).unwrap(), a);
    assert_eq!(count(&w, kind_6), 1);
    assert!(
        p.vault
            .state()
            .latest()
            .bank_of(grant_of(A_ACCOUNT))
            .is_some()
    );
}

/// R-ID-02, ADR-008 rules 1 and 2: a recorder never verifies their own
/// account, nor an account of their own identity, and such a request
/// writes nothing: no identity, no tuple, no binding and no fact.
#[test]
fn r_id_02_recorder_never_registers_their_own_identity() {
    let w = genesis();
    let mut p = start(&w);
    let tuples = "SELECT count(*) FROM keystore.identity_tuple";
    let bindings = "SELECT count(*) FROM vault.identity_account";
    assert!(p.verify(A_ACCOUNT, A_ACCOUNT, ALICE).is_err(), "rule 1");
    assert_eq!(count(&w, tuples), 0);
    assert_eq!(count(&w, bindings), 0);
    // The recorder's own identity is Alice's.
    let a = p.register(RECORDER, ALICE).unwrap();
    let keys = read_rows(&w);
    assert!(p.verify(RECORDER, B_ACCOUNT, ALICE).is_err(), "rule 2");
    assert_eq!(read_rows(&w), keys);
    assert_eq!(count(&w, bindings), 1);
    assert_eq!(p.vault.registered(WireAccount(B_ACCOUNT)), None);
    assert_eq!(p.vault.registered(WireAccount(RECORDER)), Some(a));
    assert_eq!(
        count(&w, "SELECT count(*) FROM vault.fact WHERE kind = 6"),
        0
    );
    // Another person is verified by the same recorder.
    assert!(p.verify(RECORDER, B_ACCOUNT, BRUNO).is_ok());
}

// ---------------------------------------------------------------------
// The recorder route on the vault origin (ADR-004 record of lane L13b).
// ---------------------------------------------------------------------

const GRANT_77: u128 = 77;

fn ticket(kind: &str, holder: u128, proposal: Option<u128>, nonce: u8) -> Vec<u8> {
    scoped_ticket(kind, holder, proposal, String::new(), nonce)
}

fn scoped_ticket(
    kind: &str,
    holder: u128,
    proposal: Option<u128>,
    scope: String,
    nonce: u8,
) -> Vec<u8> {
    let t = common::vc::wire::RTicket {
        kind: kind.to_owned(),
        cell: CELL,
        account: holder,
        proposal,
        scope,
        issued_at: NOW - 1_000_000,
        expires_at: NOW + 200_000_000,
        nonce: [nonce; 16],
    };
    common::vc::Signer::new(SIGNER).sign(&t)
}

fn verification_body(family: &str) -> String {
    format!(
        "{{\"checks\":[\"document_authentic\",\"photo_match\"],\"document_type\":\"passport\",\"identity\":{{\"birth_date\":\"1990-02-28\",\"family_names\":\"{family}\",\"given_names\":\"Synthetic\",\"issuing_state\":\"DEU\"}},\"method\":\"manual\"}}"
    )
}

/// A recorder's write with the family name `family`, under a verification
/// ticket of `holder` naming the person `account` of grant 77.
fn verification_write(holder: u128, account: u128, family: &str, nonce: u8) -> Vec<u8> {
    common::origin_write(
        &scoped_ticket(
            "write:verification_recorded",
            holder,
            Some(GRANT_77),
            fstp_vault_proto::person_scope(WireAccount(account)),
            nonce,
        ),
        &verification_body(family),
    )
}

impl Process<'_> {
    /// The cell's negotiation fact of grant 77, listing `accounts`.
    fn negotiation(&mut self, accounts: &[u128]) {
        let r = self.vault.internal(
            &VaultRequest::NegotiationOpened {
                proposal: WireProposal(GRANT_77),
                accounts: accounts.iter().map(|a| WireAccount(*a)).collect(),
                ledger_seq: 1,
            },
            NOW,
        );
        assert_eq!(r, VaultResponse::Acked);
        self.commit();
    }

    fn recorder_write(&mut self, bytes: &[u8]) -> Result<Person, fstp_vault::OriginRefusal> {
        block_on(self.runner.take_verification_write(
            &mut self.vault,
            &mut self.journal,
            bytes,
            NOW,
        ))
    }
}

/// R-ID-02, I-17, ADR-004 record of lane L13b "Origin checks": a
/// recorder's write on the vault origin, under the cell's verification
/// ticket, registers the person's identity and records the verification
/// with the ticket's holder as verifier. The ticket is used. The person's
/// bank details are then taken on the origin and sealed for the identity.
#[test]
fn adr008_recorder_verification_registers_the_identity() {
    let w = genesis();
    let mut p = start(&w);
    p.negotiation(&[A_ACCOUNT, B_ACCOUNT]);
    let a = p
        .recorder_write(&verification_write(RECORDER, A_ACCOUNT, "Alpha", 1))
        .unwrap();
    assert_eq!(p.vault.registered(WireAccount(A_ACCOUNT)), Some(a));
    assert_eq!(
        p.vault.state().latest().person_of(WireAccount(A_ACCOUNT)),
        Some(a)
    );
    assert!(p.vault.used_tickets().contains(&[1; 16]));
    assert_eq!(
        count(&w, "SELECT count(*) FROM vault.fact WHERE kind = 6"),
        1
    );
    assert_eq!(count(&w, "SELECT count(*) FROM vault.ticket_used"), 1);
    let body = fstp_vault::codec::decode_verification_write(verification_body("Alpha").as_bytes())
        .unwrap();
    assert_eq!(
        p.runner.tuple(a).unwrap(),
        fstp_vault::codec::identity_tuple(&body.identity),
        "the stored tuple is not the body's"
    );
    // The verification's epoch is acknowledged, then the bank details
    // are taken on the origin.
    let epoch = p.vault.state().provisional().unwrap().epoch();
    p.vault.internal(
        &VaultRequest::Ack {
            epoch,
            ledger_seq: 2,
            link: [7; 32],
        },
        NOW,
    );
    p.commit();
    let bank = common::origin_write(
        &ticket("write:bank_details", A_ACCOUNT, Some(GRANT_77), 2),
        &format!(
            "{{\"account\":\"{A_ACCOUNT}\",\"grant\":\"{GRANT_77}\",\"holder\":\"Synthetic Holder\",\"iban\":\"{IBAN}\"}}"
        ),
    );
    p.vault.post_write(&bank, NOW).unwrap();
    p.commit();
    let rows = fact_rows(&w);
    assert!(
        rows.iter()
            .any(|r| r.kind == 14 && r.dek == a.0.to_be_bytes())
    );
}

/// R-ID-02, I-17, ADR-008 rules 1 and 2, ADR-004 record of lane L13b
/// "Origin checks": the route refuses a person that the negotiation fact
/// does not list, the recorder's own account, a recorder of the person's
/// identity, a ticket of another kind, and a ticket that names no person. Each refusal writes nothing and leaves the ticket unused.
#[test]
fn adr008_recorder_route_refuses_without_writing() {
    let w = genesis();
    let mut p = start(&w);
    p.negotiation(&[A_ACCOUNT, RECORDER]);
    // The recorder's own identity is the one a body with "Bravo" gives.
    let bravo = fstp_vault::codec::decode_verification_write(verification_body("Bravo").as_bytes())
        .unwrap();
    p.register(
        RECORDER,
        &fstp_vault::codec::identity_tuple(&bravo.identity),
    )
    .unwrap();
    let keys = read_rows(&w);
    let refused = [
        (
            verification_write(RECORDER, C_ACCOUNT, "Charlie", 1),
            fstp_vault::OriginRefusal::NoNegotiationFact,
        ),
        (
            verification_write(RECORDER, RECORDER, "Alpha", 2),
            fstp_vault::OriginRefusal::WrongKind,
        ),
        (
            verification_write(RECORDER, A_ACCOUNT, "Bravo", 3),
            fstp_vault::OriginRefusal::WrongKind,
        ),
        (
            common::origin_write(
                &ticket("write:bank_details", RECORDER, Some(GRANT_77), 4),
                &verification_body("Alpha"),
            ),
            fstp_vault::OriginRefusal::WrongKind,
        ),
        (
            common::origin_write(
                &ticket("write:verification_recorded", RECORDER, Some(GRANT_77), 5),
                &verification_body("Alpha"),
            ),
            fstp_vault::OriginRefusal::WrongKind,
        ),
    ];
    for (bytes, want) in refused {
        assert_eq!(p.recorder_write(&bytes).unwrap_err(), want);
    }
    assert_eq!(read_rows(&w), keys, "a refusal wrote a keystore row");
    assert_eq!(count(&w, "SELECT count(*) FROM vault.identity_account"), 1);
    assert_eq!(
        count(&w, "SELECT count(*) FROM vault.fact WHERE kind = 6"),
        0
    );
    assert_eq!(count(&w, "SELECT count(*) FROM vault.ticket_used"), 0);
    assert!(p.vault.used_tickets().is_empty());
    assert_eq!(p.vault.registered(WireAccount(A_ACCOUNT)), None);
    // Its valid twin is taken.
    assert!(
        p.recorder_write(&verification_write(RECORDER, A_ACCOUNT, "Alpha", 6))
            .is_ok()
    );
}

/// ADR-004 record of lane L13b "Ticket use" and "Retry": a write whose
/// verification fails to commit leaves the account registered and the
/// ticket unused. The same link again completes it, and a third use is
/// refused as replayed. One verification is recorded. A name with extra
/// spaces gives the same identity.
#[test]
fn adr008_recorder_retry_completes_and_replay_is_refused() {
    let w = genesis();
    let mut p = start(&w);
    p.negotiation(&[A_ACCOUNT, B_ACCOUNT]);
    let bytes = verification_write(RECORDER, A_ACCOUNT, "Alpha", 1);
    p.journal.fail_verification = true;
    assert_eq!(
        p.recorder_write(&bytes).unwrap_err(),
        fstp_vault::OriginRefusal::Unavailable
    );
    assert!(p.vault.used_tickets().is_empty());
    let a = p.vault.registered(WireAccount(A_ACCOUNT)).unwrap();
    assert_eq!(p.recorder_write(&bytes).unwrap(), a);
    assert_eq!(
        p.recorder_write(&bytes).unwrap_err(),
        fstp_vault::OriginRefusal::Replayed
    );
    assert_eq!(
        count(&w, "SELECT count(*) FROM vault.fact WHERE kind = 6"),
        1
    );
    // The same person, entered with extra spaces for another account.
    let spaced = verification_write(RECORDER, B_ACCOUNT, "  Alpha  ", 2);
    assert_eq!(p.recorder_write(&spaced).unwrap(), a);
}

// ---------------------------------------------------------------------
// The host command for the first admins (ADR-008 and ADR-004, decided by
// Daniel on 2026-11-21).
// ---------------------------------------------------------------------

/// A hand-written identity file: spaces, line breaks and any member order.
const ADMIN_FILE: &str = "{\n  \"method\": \"manual\",\n  \"document_type\": \"passport\",\n  \"checks\": [\"photo_match\", \"document_authentic\"],\n  \"identity\": {\n    \"family_names\": \"Alpha\",\n    \"given_names\": \"Synthetic\",\n    \"birth_date\": \"1990-02-28\",\n    \"issuing_state\": \"deu\"\n  }\n}\n";

impl Process<'_> {
    fn verify_first_admin(&mut self, account: u128, file: &str) -> Result<Person, VaultError> {
        let entry = fstp_vault::codec::decode_identity_file(file.as_bytes())?;
        block_on(self.runner.verify_first_admin(
            &mut self.vault,
            &mut self.journal,
            WireAccount(account),
            &entry,
            NOW,
        ))
    }
}

/// ADR-008, decided by Daniel on 2026-11-21: the technical admin verifies
/// a first admin on the host. The command registers the identity and
/// records the verification with the operator as verifier of record. A
/// repeat is idempotent. A second first admin is taken, a third account
/// is refused, and the refusal writes nothing. The verified admin's
/// identity then blocks a recorder verification of the same person by
/// that admin (rule 2).
#[test]
fn adr008_host_verifies_the_first_admins() {
    let w = genesis();
    let mut p = start(&w);
    let kind_6 = "SELECT count(*) FROM vault.fact WHERE kind = 6";
    let a = p.verify_first_admin(A_ACCOUNT, ADMIN_FILE).unwrap();
    assert_eq!(p.vault.registered(WireAccount(A_ACCOUNT)), Some(a));
    assert_eq!(
        p.vault.state().latest().person_of(WireAccount(A_ACCOUNT)),
        Some(a)
    );
    assert_eq!(count(&w, kind_6), 1);
    assert_eq!(p.verify_first_admin(A_ACCOUNT, ADMIN_FILE).unwrap(), a);
    assert_eq!(count(&w, kind_6), 1, "a repeat wrote a second verification");
    let b = p
        .verify_first_admin(B_ACCOUNT, &ADMIN_FILE.replace("Alpha", "Bravo"))
        .unwrap();
    assert_ne!(a, b);
    let keys = read_rows(&w);
    assert!(
        p.verify_first_admin(C_ACCOUNT, &ADMIN_FILE.replace("Alpha", "Charlie"))
            .is_err(),
        "a third first admin was verified"
    );
    assert_eq!(read_rows(&w), keys);
    assert_eq!(count(&w, kind_6), 2);
    assert_eq!(p.vault.registered(WireAccount(C_ACCOUNT)), None);
    // The limit survives a restart.
    drop(p);
    let mut p = start(&w);
    assert!(
        p.verify_first_admin(C_ACCOUNT, &ADMIN_FILE.replace("Alpha", "Charlie"))
            .is_err()
    );
    assert_eq!(
        p.verify_first_admin(B_ACCOUNT, &ADMIN_FILE.replace("Alpha", "Bravo"))
            .unwrap(),
        b
    );
}

/// ADR-004 record of lane L13b, row "Identity file": the host file takes
/// any JSON spelling of the recorder's members, and refuses a document
/// number, a missing field and an oversized file.
#[test]
fn adr008_identity_file_takes_any_spelling_and_refuses_extras() {
    use fstp_vault::codec::decode_identity_file;
    let e = decode_identity_file(ADMIN_FILE.as_bytes()).unwrap();
    assert_eq!(e.identity.issuing_state, "DEU", "the state is upper-cased");
    assert!(
        decode_identity_file(
            ADMIN_FILE
                .replace("\"method\"", "\"number\": \"X1\", \"method\"")
                .as_bytes()
        )
        .is_err()
    );
    assert!(
        decode_identity_file(
            ADMIN_FILE
                .replace("\"birth_date\": \"1990-02-28\",", "")
                .as_bytes()
        )
        .is_err()
    );
    assert!(
        decode_identity_file(
            ADMIN_FILE
                .replace("\"account\"", "")
                .replace("{\n  \"method\"", "{\n  \"account\": \"5\", \"method\"")
                .as_bytes()
        )
        .is_err()
    );
    let big = format!("{}{}", ADMIN_FILE, " ".repeat(5000));
    assert!(decode_identity_file(big.as_bytes()).is_err());
}
