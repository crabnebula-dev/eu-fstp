//! The vault database `v_<cell>` over a real PostgreSQL server from
//! `fstp-pgtest` (design sections 4.3 and 4.6, R-NF-08, NOTE 4, ADR-009
//! "Single use").
//!
//! Every test gets a fresh database on one shared server per test binary.
//! The sealer is a test sealer over `fstp_crypto::aead`, since the vault
//! chain's data keys come from `fstp-keys` (lane W2f).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use std::collections::BTreeSet;
use std::sync::OnceLock;
use std::time::Duration;

use common::origin_write;
use common::vc::wire::RTicket;
use common::vc::{Signer, fact};
use fstp_pgtest::{PgServer, Role, tls as certs};
use fstp_pgwire::{Client, ClientTls, Config, Password};
use fstp_rt::tokio::TokioRuntime;
use fstp_vault::store::{self, SealedValue, Sealer};
use fstp_vault::{CATALOGUE, JournalEntry, Vault, VaultError};
use fstp_vault_proto::{VaultRequest, VaultResponse, WireAccount, WireProposal, encode_request};

type Pg = Client<TokioRuntime>;

fn rt() -> &'static TokioRuntime {
    static RT: OnceLock<TokioRuntime> = OnceLock::new();
    RT.get_or_init(|| TokioRuntime::new_multi_thread(2).unwrap())
}

fn block_on<F: Future>(f: F) -> F::Output {
    rt().block_on(f)
}

fn fresh() -> Pg {
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
    block_on(Client::connect(rt(), &cfg)).unwrap_or_else(|e| panic!("connect failed: {e}"))
}

/// A test sealer: AES-256-GCM under one key, the nonce stored in front.
struct TestSealer {
    key: fstp_crypto::aead::Key,
}

impl TestSealer {
    fn new() -> TestSealer {
        TestSealer {
            key: fstp_crypto::aead::Key::from_bytes(&[0x42; 32]).unwrap(),
        }
    }
}

impl Sealer for TestSealer {
    fn seal(&self, aad: &[u8], plain: &[u8]) -> Result<SealedValue, VaultError> {
        let s = fstp_crypto::aead::seal(&self.key, aad, plain)
            .map_err(|_| VaultError::Unavailable("test sealer"))?;
        Ok(SealedValue {
            dek: [7; 16],
            bytes: [s.nonce.as_slice(), &s.body].concat(),
        })
    }

    fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, VaultError> {
        let (nonce, body) = sealed.split_at(fstp_crypto::aead::NONCE_LEN);
        let nonce: [u8; 12] = nonce.try_into().unwrap();
        fstp_crypto::aead::open(&self.key, &nonce, aad, body)
            .map(|z| z.to_vec())
            .map_err(|_| VaultError::Malformed("test sealer"))
    }

    fn digest(&self, data: &[u8]) -> [u8; 32] {
        fstp_crypto::hmac_sha256(&[0x24; 32], data)
    }
}

const CELL: [u8; 16] = [0xCE; 16];
const APPLICANT: u128 = 501;
const ISSUED: i64 = 10_000_000_000;
const NOW: i64 = ISSUED + 1_000_000;

fn country_write(key: &Signer, nonce: u8, programme: u128, country: u16) -> Vec<u8> {
    let t = RTicket {
        kind: "write:country_stated".to_owned(),
        cell: CELL,
        account: APPLICANT,
        proposal: None,
        scope: format!("programme:{programme}"),
        issued_at: ISSUED,
        expires_at: ISSUED + 300_000_000,
        nonce: [nonce; 16],
    };
    let body = String::from_utf8(fact::country(APPLICANT, programme, country).body).unwrap();
    origin_write(&key.sign(&t), &body)
}

/// Runs one vault call and persists its journal, as the service does.
fn persist(db: &mut Pg, v: &mut Vault) -> Result<(), VaultError> {
    let journal = v.take_journal();
    block_on(store::persist(db, &TestSealer::new(), &journal))
}

fn internal(v: &mut Vault, req: &VaultRequest) -> VaultResponse {
    let bytes = encode_request(req).unwrap();
    fstp_vault_proto::decode_response(&v.internal_bytes(&bytes, NOW)).unwrap()
}

/// R-NF-08, design sections 4.3, 4.5 and 4.6: the vault migrations create
/// exactly the catalogued tables, with the catalogued columns in order.
/// Every schema but `pg_catalog` and `information_schema` is checked, so
/// the runner's ledger and any new schema are covered too.
#[test]
fn r_nf_08_vault_migrations_create_exactly_the_catalogued_columns() {
    let mut db = fresh();
    block_on(store::migrate(&mut db)).unwrap();
    for t in CATALOGUE {
        let rows = block_on(db.query(
            "SELECT column_name::text FROM information_schema.columns WHERE table_schema = $1 AND table_name = $2 ORDER BY ordinal_position",
            &[&t.schema, &t.name],
        ))
        .unwrap();
        let got: Vec<String> = rows.iter().map(|r| r.get(0).unwrap()).collect();
        let want: Vec<String> = t.columns.iter().map(|c| c.name.to_owned()).collect();
        assert_eq!(got, want, "{}.{}", t.schema, t.name);
    }
    let rows = block_on(db.query(
        "SELECT table_schema::text, table_name::text FROM information_schema.tables WHERE table_schema NOT IN ('pg_catalog', 'information_schema') ORDER BY 1, 2",
        &[],
    ))
    .unwrap();
    let tables: BTreeSet<(String, String)> = rows
        .iter()
        .map(|r| (r.get(0).unwrap(), r.get(1).unwrap()))
        .collect();
    let catalogued: BTreeSet<(String, String)> = CATALOGUE
        .iter()
        .map(|t| (t.schema.to_owned(), t.name.to_owned()))
        .collect();
    assert_eq!(tables, catalogued, "no table outside the catalogue");
}

/// I-06, NOTE 4, design section 4.3: a vault rebuilt from its database
/// holds exactly the epochs, facts, used tickets and negotiation facts it
/// persisted. A queued write stays queued, and the reloaded vault answers
/// as the one that wrote.
#[test]
fn i06_note4_vault_reloads_what_it_persisted() {
    let mut db = fresh();
    block_on(store::migrate(&mut db)).unwrap();
    let key = Signer::new(1);
    let mut v = Vault::new(CELL, &[key.public()]).unwrap();

    let w1 = v.post_write(&country_write(&key, 1, 1, 250), NOW).unwrap();
    assert_eq!(w1.epoch, Some(1));
    persist(&mut db, &mut v).unwrap();
    let w2 = v.post_write(&country_write(&key, 2, 2, 276), NOW).unwrap();
    assert_eq!(w2.epoch, None, "the second write queues");
    persist(&mut db, &mut v).unwrap();
    let acked = internal(
        &mut v,
        &VaultRequest::Ack {
            epoch: 1,
            ledger_seq: 17,
            link: [0xAB; 32],
        },
    );
    assert_eq!(acked, VaultResponse::Acked);
    persist(&mut db, &mut v).unwrap();
    let opened = internal(
        &mut v,
        &VaultRequest::NegotiationOpened {
            proposal: WireProposal(9),
            accounts: vec![WireAccount(APPLICANT)],
            ledger_seq: 18,
        },
    );
    assert_eq!(opened, VaultResponse::Acked);
    persist(&mut db, &mut v).unwrap();
    let changed = fstp_vault_proto::Query::ChangedSince { epoch: 0 }
        .to_wire()
        .unwrap();
    let asked = internal(
        &mut v,
        &VaultRequest::Ask {
            at: 1,
            reaction_for: None,
            queries: vec![changed],
        },
    );
    assert!(matches!(asked, VaultResponse::Answers(_)), "{asked:?}");
    persist(&mut db, &mut v).unwrap();
    let logged: i64 = block_on(db.query_one("SELECT count(*) FROM vault.query_log", &[]))
        .unwrap()
        .get(0)
        .unwrap();
    assert_eq!(logged, 1, "the answer is logged as a keyed digest");

    let loaded = block_on(store::load(
        &mut db,
        &TestSealer::new(),
        CELL,
        &[key.public()],
    ))
    .unwrap();
    assert_eq!(loaded.state(), v.state());
    assert_eq!(loaded.used_tickets(), v.used_tickets());
    assert_eq!(loaded.state().effective(), 1);
    assert_eq!(loaded.state().current(), 2);
}

/// ADR-009 "Single use": the database refuses a second use of a ticket
/// id, even when memory would have let it through.
#[test]
fn i17_vault_database_refuses_a_replayed_ticket() {
    let mut db = fresh();
    block_on(store::migrate(&mut db)).unwrap();
    let entry = [JournalEntry::TicketUsed {
        nonce: [5; 16],
        at: NOW,
    }];
    block_on(store::persist(&mut db, &TestSealer::new(), &entry)).unwrap();
    assert_eq!(
        block_on(store::persist(&mut db, &TestSealer::new(), &entry)),
        Err(VaultError::Conflict("a used ticket"))
    );
}

/// ADR-009 "Single use", I-23 style insert-only rows: a used ticket and a
/// query log row can be neither changed nor deleted, and an effective
/// epoch cannot go back to provisional.
#[test]
fn adr009_vault_insert_only_rows_refuse_change() {
    let mut db = fresh();
    block_on(store::migrate(&mut db)).unwrap();
    let key = Signer::new(1);
    let mut v = Vault::new(CELL, &[key.public()]).unwrap();
    v.post_write(&country_write(&key, 1, 1, 250), NOW).unwrap();
    internal(
        &mut v,
        &VaultRequest::Ack {
            epoch: 1,
            ledger_seq: 3,
            link: [1; 32],
        },
    );
    persist(&mut db, &mut v).unwrap();
    for sql in [
        "UPDATE vault.ticket_used SET used_at = 0",
        "DELETE FROM vault.ticket_used",
        "UPDATE vault.epoch SET state = 1, ack_seq = NULL, acked_at = NULL",
        "DELETE FROM vault.epoch",
    ] {
        assert!(block_on(db.execute(sql, &[])).is_err(), "{sql} was allowed");
    }
}

/// A migrated database holding four writes: epoch 1 effective, epoch 2
/// provisional, and epochs 3 and 4 queued.
fn four_epochs() -> (Pg, Signer) {
    let mut db = fresh();
    block_on(store::migrate(&mut db)).unwrap();
    let key = Signer::new(1);
    let mut v = Vault::new(CELL, &[key.public()]).unwrap();
    v.post_write(&country_write(&key, 1, 1, 250), NOW).unwrap();
    let ack = VaultRequest::Ack {
        epoch: 1,
        ledger_seq: 4,
        link: [2; 32],
    };
    assert_eq!(internal(&mut v, &ack), VaultResponse::Acked);
    v.post_write(&country_write(&key, 2, 2, 276), NOW).unwrap();
    v.post_write(&country_write(&key, 3, 3, 380), NOW).unwrap();
    v.post_write(&country_write(&key, 4, 4, 724), NOW).unwrap();
    assert_eq!((v.state().current(), v.state().queued()), (2, 2));
    persist(&mut db, &mut v).unwrap();
    (db, key)
}

fn reload(db: &mut Pg, key: &Signer) -> Result<Vault, VaultError> {
    block_on(store::load(db, &TestSealer::new(), CELL, &[key.public()]))
}

/// Runs `sql` as the superuser with triggers off, as an attacker or a
/// broken restore would change the rows.
fn tamper(db: &mut Pg, sql: &'static str) {
    block_on(db.execute("SET session_replication_role = replica", &[])).unwrap();
    block_on(db.execute(sql, &[])).unwrap();
    block_on(db.execute("SET session_replication_role = origin", &[])).unwrap();
}

/// NOTE 2, NOTE 4: a gap between stored epochs fails the load closed.
/// Without the check, the queued write at epoch 4 would replay as epoch 3
/// and every later write would collide with the stored rows.
#[test]
fn note2_vault_load_fails_closed_on_a_gap_between_epochs() {
    let (mut db, key) = four_epochs();
    assert!(reload(&mut db, &key).is_ok(), "the untouched rows load");
    tamper(&mut db, "DELETE FROM vault.fact WHERE epoch = 3");
    tamper(&mut db, "DELETE FROM vault.epoch WHERE epoch = 3");
    assert_eq!(
        reload(&mut db, &key).err(),
        Some(VaultError::Malformed("a stored vault row"))
    );
}

/// NOTE 2: an epoch row with no fact row fails the load closed, instead
/// of being skipped.
#[test]
fn note2_vault_load_fails_closed_on_an_epoch_without_its_fact() {
    let (mut db, key) = four_epochs();
    tamper(&mut db, "DELETE FROM vault.fact WHERE epoch = 4");
    assert_eq!(
        reload(&mut db, &key).err(),
        Some(VaultError::Malformed("a stored vault row"))
    );
}

/// NOTE 2: a fact row whose kind column is not its sealed body's kind
/// fails the load closed.
#[test]
fn note2_vault_load_fails_closed_on_a_wrong_kind_column() {
    let (mut db, key) = four_epochs();
    tamper(&mut db, "UPDATE vault.fact SET kind = 2 WHERE epoch = 1");
    assert_eq!(
        reload(&mut db, &key).err(),
        Some(VaultError::Malformed("a stored vault row"))
    );
}

/// NOTE 6: a programme's P-17 condition is persisted, so it stays fixed
/// across a restart. The reloaded vault refuses a different condition,
/// accepts the same one, and its table refuses change.
#[test]
fn note6_p17_condition_survives_a_restart() {
    let mut db = fresh();
    block_on(store::migrate(&mut db)).unwrap();
    let key = Signer::new(1);
    let mut v = Vault::new(CELL, &[key.public()]).unwrap();
    let p = fstp_vault_proto::WireProgramme(1);
    v.set_p17(p, &BTreeSet::from([250, 380])).unwrap();
    persist(&mut db, &mut v).unwrap();
    let mut loaded = reload(&mut db, &key).unwrap();
    assert_eq!(loaded.state(), v.state());
    assert!(loaded.set_p17(p, &BTreeSet::from([276])).is_err());
    loaded.set_p17(p, &BTreeSet::from([250, 380])).unwrap();
    assert!(
        loaded.take_journal().is_empty(),
        "a repeat journals nothing"
    );
    for sql in [
        "UPDATE vault.p17_condition SET countries = '\\x5b5d'",
        "DELETE FROM vault.p17_condition",
    ] {
        assert!(block_on(db.execute(sql, &[])).is_err(), "{sql} was allowed");
    }
}

/// I-17, design section 6.5: the highest negotiation sequence survives a
/// restart. After a close at seq 8, a stale open at seq 7 reopens nothing
/// in the reloaded vault, and a close that came first is kept too.
#[test]
fn i17_negotiation_sequence_survives_a_restart() {
    let mut db = fresh();
    block_on(store::migrate(&mut db)).unwrap();
    let key = Signer::new(1);
    let mut v = Vault::new(CELL, &[key.public()]).unwrap();
    let open = |proposal, seq| VaultRequest::NegotiationOpened {
        proposal: WireProposal(proposal),
        accounts: vec![WireAccount(APPLICANT)],
        ledger_seq: seq,
    };
    let close = |proposal, seq| VaultRequest::NegotiationClosed {
        proposal: WireProposal(proposal),
        ledger_seq: seq,
    };
    for req in [open(1, 7), close(1, 8), close(2, 8), open(3, 5)] {
        assert_eq!(internal(&mut v, &req), VaultResponse::Acked);
    }
    persist(&mut db, &mut v).unwrap();
    let mut loaded = reload(&mut db, &key).unwrap();
    assert_eq!(loaded.state(), v.state());
    for req in [open(1, 7), open(2, 7)] {
        assert_eq!(internal(&mut loaded, &req), VaultResponse::Acked);
    }
    assert!(
        loaded.take_journal().is_empty(),
        "stale opens change nothing"
    );
    let t = RTicket {
        kind: "release".to_owned(),
        cell: CELL,
        account: APPLICANT,
        proposal: Some(1),
        scope: "identity".to_owned(),
        issued_at: ISSUED,
        expires_at: ISSUED + 300_000_000,
        nonce: [9; 16],
    };
    assert!(loaded.post_release(&key.sign(&t), NOW).is_err());
    let t3 = RTicket {
        proposal: Some(3),
        ..t
    };
    assert!(loaded.post_release(&key.sign(&t3), NOW).is_ok(), "open 3");
}

/// I-20, Q17: identities persist in `vault.identity` by match key, so a
/// reloaded vault resolves a known key to the same identity and a new key
/// to a new one.
#[test]
fn i20_identities_survive_a_restart() {
    let mut db = fresh();
    block_on(store::migrate(&mut db)).unwrap();
    let key = Signer::new(1);
    let mut v = Vault::new(CELL, &[key.public()]).unwrap();
    let k1 = fstp_vault::match_key(&[0xA1; 32], b"synthetic|0001");
    let k2 = fstp_vault::match_key(&[0xA1; 32], b"synthetic|0002");
    let p1 = v.resolve_identity(k1).unwrap();
    persist(&mut db, &mut v).unwrap();
    let mut loaded = reload(&mut db, &key).unwrap();
    assert_eq!(loaded.resolve_identity(k1).unwrap(), p1);
    assert!(
        loaded.take_journal().is_empty(),
        "a known key journals nothing"
    );
    let p2 = loaded.resolve_identity(k2).unwrap();
    assert_ne!(p2, p1);
    persist(&mut db, &mut loaded).unwrap();
    let again = reload(&mut db, &key).unwrap();
    assert_eq!(again, {
        let mut l = loaded.clone();
        let _ = l.take_journal();
        l
    });
}
