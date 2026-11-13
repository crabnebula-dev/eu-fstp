//! The vault chain writer over the real vault service (I-24, ADR-010
//! "The vault chain is anchored by the vault only", open point 5). Lane
//! F-VCHAIN.
//!
//! Daniel decided on 2026-11-13 (m3-finish Q-C): each committed fact
//! batch and each identity release or read is a kind 1 row of
//! `vault_audit.chain`, and a KeyOp stays an event only. Each test runs
//! the vault over a migrated `v_<cell>` and a local witness over a file
//! store, and calls the internal API over mutual TLS with the cell's
//! `cell-app` certificate.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use common::vc::wire::RQuery;
use fstp_audit::anchor::{decode_receipt, receipt_signature_verifies};
use fstp_audit::{CellId, ChainId, CompositeSigningKey};
use fstp_pgtest::{PgServer, RoleLogin};
use fstp_pgwire::{Client, ClientTls, Config, Password};
use fstp_pki::cert::{
    CertKind, CertSpec, DistinguishedName, SignatureAlgorithm, Validity, assemble, key_identifier,
    tbs,
};
use fstp_pki::pem::{PemLabel, encode};
use fstp_rt::tokio::TokioRuntime;
use fstp_vault::chain::{VaultChainParts, VaultWitness};
use fstp_vault::service::{AeadSealer, RegisteredSpki, VaultHandle, VaultParts, serve};
use fstp_vault::start::ClusterRole;
use fstp_vault_proto::{
    RelationshipKind, VaultRequest, VaultResponse, WireAccount, WireProgramme, decode_response,
    encode_request,
};
use fstp_witness::{LocalWitnessParts, WitnessHandle, serve_local};

fn rt() -> &'static TokioRuntime {
    static RT: OnceLock<TokioRuntime> = OnceLock::new();
    RT.get_or_init(|| TokioRuntime::new_multi_thread(2).unwrap())
}

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    rt().block_on(f)
}

// ---------------------------------------------------------------------------
// A small PKI from fstp-pki and fstp-crypto.

struct Ca {
    name: String,
    key: fstp_crypto::sig::EcdsaP256KeyPair,
    der: Vec<u8>,
}

fn now_s() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

fn serial() -> Vec<u8> {
    let mut s = fstp_crypto::random_array::<16>().unwrap().to_vec();
    s[0] = (s[0] & 0x7f) | 0x01;
    s
}

fn pem_cert(der: &[u8]) -> Vec<u8> {
    encode(PemLabel::Certificate, der).unwrap().into_bytes()
}

fn pem_key(der: &[u8]) -> Vec<u8> {
    let b64 = {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = String::new();
        for chunk in der.chunks(3) {
            let n = chunk
                .iter()
                .enumerate()
                .fold(0u32, |n, (i, x)| n | (u32::from(*x) << (16 - 8 * i)));
            for k in 0..4 {
                if k <= chunk.len() {
                    s.push(char::from(
                        A[usize::try_from((n >> (18 - 6 * k)) & 63).unwrap()],
                    ));
                } else {
                    s.push('=');
                }
            }
        }
        s
    };
    let mut out = String::from("-----BEGIN PRIVATE KEY-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap());
        out.push('\n');
    }
    out.push_str("-----END PRIVATE KEY-----\n");
    out.into_bytes()
}

impl Ca {
    fn spki_digest(&self) -> [u8; 32] {
        fstp_crypto::sha256(&self.key.spki_der().unwrap())
    }

    fn new(name: &str) -> Ca {
        let key = fstp_crypto::sig::EcdsaP256KeyPair::generate().unwrap();
        let dn = DistinguishedName {
            common_name: name.to_owned(),
            organizational_unit: None,
        };
        let spec = CertSpec {
            serial: serial(),
            issuer: dn.clone(),
            subject: dn,
            validity: Validity {
                not_before: now_s() - 300,
                not_after: now_s() + 86_400,
            },
            spki_der: key.spki_der().unwrap(),
            issuer_key_id: None,
            kind: CertKind::Ca,
            dns_names: Vec::new(),
            ip_addrs: Vec::new(),
            algorithm: SignatureAlgorithm::EcdsaP256Sha256,
        };
        let t = tbs(&spec).unwrap();
        let der = assemble(&t, &key.sign(t.as_der()).unwrap()).unwrap();
        Ca {
            name: name.to_owned(),
            key,
            der,
        }
    }

    /// `(cert PEM, key PEM)` of a leaf of `kind` with subject `cn`, `ou`.
    fn issue(
        &self,
        kind: CertKind,
        cn: &str,
        ou: Option<&str>,
        dns: &[&str],
    ) -> (Vec<u8>, Vec<u8>) {
        let key = fstp_crypto::sig::EcdsaP256KeyPair::generate().unwrap();
        let spec = CertSpec {
            serial: serial(),
            issuer: DistinguishedName {
                common_name: self.name.clone(),
                organizational_unit: None,
            },
            subject: DistinguishedName {
                common_name: cn.to_owned(),
                organizational_unit: ou.map(str::to_owned),
            },
            validity: Validity {
                not_before: now_s() - 300,
                not_after: now_s() + 86_000,
            },
            spki_der: key.spki_der().unwrap(),
            issuer_key_id: Some(key_identifier(&self.key.spki_der().unwrap()).unwrap()),
            kind,
            dns_names: dns.iter().map(|d| (*d).to_owned()).collect(),
            ip_addrs: if kind == CertKind::Server {
                vec![std::net::IpAddr::V4(Ipv4Addr::LOCALHOST)]
            } else {
                Vec::new()
            },
            algorithm: SignatureAlgorithm::EcdsaP256Sha256,
        };
        let t = tbs(&spec).unwrap();
        let der = assemble(&t, &self.key.sign(t.as_der()).unwrap()).unwrap();
        (pem_cert(&der), pem_key(&key.pkcs8_der().unwrap()))
    }
}

// ---------------------------------------------------------------------------
// A vault database, a local witness and the vault.

const WITNESS_HOST: &str = "witness.vchain.test";

static NEXT: AtomicU32 = AtomicU32::new(0);

fn server() -> &'static PgServer {
    PgServer::shared_named("vchain_vault", "vault").unwrap_or_else(|e| panic!("{e}"))
}

fn first_der(pem: &[u8]) -> Vec<u8> {
    let text = std::str::from_utf8(pem).unwrap();
    let body: String = text
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE-----"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .collect();
    fstp_pgwire::base64::decode(body.as_bytes()).unwrap()
}

fn registered() -> Vec<RegisteredSpki> {
    let pem = std::fs::read(server().dir().join("tls").join("server.pem")).unwrap();
    let der = first_der(&pem);
    vec![RegisteredSpki {
        digest: fstp_crypto::sha256(fstp_witness::peer::read_cert(&der).unwrap().spki),
        role: ClusterRole::Vault,
    }]
}

fn config(server: &PgServer, dbname: &str, login: &RoleLogin) -> Config {
    let p = login.conn_params(server, dbname);
    let tls = ClientTls::new(p.server_ca_pem, p.client_cert_pem, p.client_key_pem).unwrap();
    Config::new(
        p.host.clone(),
        p.port,
        p.user.as_str(),
        Password::new(p.password.as_str()).unwrap(),
        p.dbname.clone(),
        tls,
    )
    .unwrap()
    .connect_timeout(Some(Duration::from_secs(20)))
}

/// A migrated `v_<cell>` with its placement row of kind 2.
fn vault_database() -> ([u8; 16], String, Config) {
    let s = server();
    let cell = fstp_crypto::random_array::<16>().unwrap();
    let hex: String = cell.iter().map(|b| format!("{b:02x}")).collect();
    let dbname = format!("v_{hex}");
    let role = format!("v_{hex}_vault");
    let login = s.create_login_role(&role).unwrap();
    s.create_database_for(&dbname, &[role.as_str()]).unwrap();
    s.psql(
        "postgres",
        &format!("GRANT CREATE ON DATABASE {dbname} TO {role}"),
    )
    .unwrap();
    let cfg = config(s, &dbname, &login);
    let mut client = block_on(Client::connect(rt(), &cfg)).unwrap();
    block_on(fstp_vault::store::migrate(&mut client)).unwrap();
    block_on(client.execute(
        "INSERT INTO fstp_meta.placement (cell_id, cluster_id, kind) VALUES ($1, $2, $3)",
        &[&cell.to_vec(), &vec![0x5a_u8; 16], &2i16],
    ))
    .unwrap();
    block_on(client.close()).unwrap();
    (cell, dbname, cfg)
}

/// A fresh directory, removed when dropped.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> TempDir {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let tag: String = fstp_crypto::random_array::<6>()
            .unwrap()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        TempDir(std::env::temp_dir().join(format!("fstp-vchain-{}-{n}-{tag}", std::process::id())))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Setup {
    cell: [u8; 16],
    dbname: String,
    db: Config,
    cell_ca: Ca,
    install_ca: Ca,
    store: TempDir,
    witness: Option<WitnessHandle<TokioRuntime>>,
    witness_key: Vec<u8>,
    anchor: Vec<u8>,
    sealer: ([u8; 32], [u8; 16], [u8; 32]),
}

impl Setup {
    fn new() -> Setup {
        let (cell, dbname, db) = vault_database();
        let key = fstp_crypto::composite::generate().unwrap();
        let anchor = fstp_crypto::composite::generate().unwrap();
        let data_key = fstp_crypto::random_array::<32>().unwrap();
        let mut s = Setup {
            cell,
            dbname,
            db,
            cell_ca: Ca::new("vchain cell CA"),
            install_ca: Ca::new("vchain install CA"),
            store: TempDir::new(),
            witness: None,
            witness_key: key.to_bytes().unwrap().to_vec(),
            anchor: anchor.to_bytes().unwrap().to_vec(),
            sealer: (
                data_key,
                fstp_crypto::random_array::<16>().unwrap(),
                fstp_crypto::random_array::<32>().unwrap(),
            ),
        };
        s.start_witness();
        let w = s.witness.as_ref().unwrap();
        block_on(w.register_cell(
            CellId(cell),
            &s.cell_ca.der,
            &[(ChainId::Vault, anchor.public_key().to_bytes().to_vec())],
        ))
        .unwrap();
        s
    }

    fn start_witness(&mut self) {
        let (chain, key) =
            self.install_ca
                .issue(CertKind::Server, WITNESS_HOST, None, &[WITNESS_HOST]);
        self.witness = Some(
            block_on(serve_local(
                rt().clone(),
                LocalWitnessParts {
                    dir: self.store.0.clone(),
                    receipt_key: CompositeSigningKey::from_bytes(&self.witness_key).unwrap(),
                    server_chain_pem: chain,
                    server_key_pem: key,
                    listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                },
            ))
            .unwrap(),
        );
    }

    fn stop_witness(&mut self) {
        if let Some(w) = self.witness.take() {
            block_on(w.shutdown(Duration::from_secs(10))).unwrap();
        }
    }

    fn witness_public(&self) -> Vec<u8> {
        CompositeSigningKey::from_bytes(&self.witness_key)
            .unwrap()
            .public_key()
            .to_bytes()
            .to_vec()
    }

    /// The vault over the database, with the chain writer when `chain`.
    fn vault(&self, chain: bool) -> Result<Vault, fstp_vault::VaultError> {
        let (server_cert, server_key) = self.cell_ca.issue(CertKind::Server, "vault", None, &[]);
        let tls = |roots: Option<&[u8]>| {
            let b = fstp_tls::ServerConfig::builder(&server_cert, &server_key);
            match roots {
                Some(r) => b.require_client_auth(r).build().unwrap(),
                None => b.build().unwrap(),
            }
        };
        let cell_ca_pem = pem_cert(&self.cell_ca.der);
        let chain = chain.then(|| {
            let (cert, key) = self.cell_ca.issue(
                CertKind::Client,
                "vault-witness",
                Some("vault-witness"),
                &[],
            );
            VaultChainParts {
                anchor_key: CompositeSigningKey::from_bytes(&self.anchor).unwrap(),
                witness: VaultWitness {
                    addr: self
                        .witness
                        .as_ref()
                        .map_or(SocketAddr::from((Ipv4Addr::LOCALHOST, 9)), |w| {
                            w.local_addr()
                        }),
                    server_name: WITNESS_HOST.to_owned(),
                    tls: fstp_tls::ClientConfig::mutual(
                        &pem_cert(&self.install_ca.der),
                        &cert,
                        &key,
                    )
                    .unwrap(),
                    ca_digest: self.install_ca.spki_digest(),
                },
                witness_keys: vec![self.witness_public()],
            }
        });
        let parts = VaultParts {
            cell: self.cell,
            db: self.db.clone(),
            registered_servers: registered(),
            sealer: Arc::new(AeadSealer::new(
                self.sealer.1,
                fstp_crypto::aead::Key::from_bytes(&self.sealer.0).unwrap(),
                self.sealer.2,
            )),
            ticket_keys: vec![
                fstp_crypto::sig::Ed25519SigningKey::generate()
                    .unwrap()
                    .public_key(),
            ],
            internal_tls: tls(Some(&cell_ca_pem)),
            tunnel_tls: Arc::new(tls(Some(&cell_ca_pem))),
            origin_tls: Arc::new(tls(None)),
            origin_host: "id.vchain.cell.fstp.localhost".to_owned(),
            internal_listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            origin_listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            chain,
        };
        let handle = block_on(serve(rt().clone(), parts))?;
        let (cert, key) = self
            .cell_ca
            .issue(CertKind::Client, "cell-app", Some("cell-app"), &[]);
        let client = fstp_http::Client::new(
            rt().clone(),
            fstp_http::ClientConfig {
                tls: Some(fstp_tls::ClientConfig::mutual(&cell_ca_pem, &cert, &key).unwrap()),
                ..fstp_http::ClientConfig::default()
            },
        );
        Ok(Vault { handle, client })
    }

    fn psql(&self, sql: &str) -> String {
        server().psql(&self.dbname, sql).unwrap()
    }
}

struct Vault {
    handle: VaultHandle<TokioRuntime>,
    client: fstp_http::Client<TokioRuntime>,
}

impl Vault {
    /// The status and, for a 200, the decoded response.
    fn call(&self, path: &str, req: &VaultRequest) -> (u16, Option<VaultResponse>) {
        let url = format!("https://{}{path}", self.handle.internal_addr());
        let request = fstp_http::Request::post(&url, encode_request(req).unwrap())
            .and_then(|r| r.try_with_header("content-type", "application/json"))
            .unwrap();
        let resp = block_on(self.client.send(request)).unwrap();
        let status = resp.status.as_u16();
        (
            status,
            (status == 200).then(|| decode_response(&resp.body).unwrap()),
        )
    }

    fn stop(self) {
        block_on(self.handle.shutdown(Duration::from_secs(10))).unwrap();
    }
}

fn relationship(seq: u64) -> VaultRequest {
    VaultRequest::RecordRelationship {
        a: WireAccount(u128::from(seq)),
        b: WireAccount(u128::from(seq) + 100),
        kind: RelationshipKind::Conflict,
        programme: WireProgramme(1),
        ledger_seq: seq,
    }
}

fn ask(reaction_for: Option<u64>) -> VaultRequest {
    VaultRequest::Ask {
        at: 1,
        reaction_for,
        queries: vec![
            RQuery::HasConflict {
                reviewer: 5,
                team: [105].into_iter().collect(),
            }
            .wire(),
        ],
    }
}

// ---------------------------------------------------------------------------
// Tests.

/// I-24, ADR-010 open point 5 (Q-C): a fact batch and a read each commit
/// one kind 1 row of `vault_audit.chain`, with its entry and an anchor
/// whose receipt verifies under the witness key. The vault answers the
/// write and the read instead of 503.
#[test]
fn i24_vault_chain_records_each_fact_batch_and_read_as_a_kind_1_row() {
    let s = Setup::new();
    let v = s.vault(true).unwrap();
    assert_eq!(
        v.call("/v1/ask", &relationship(5)),
        (200, Some(VaultResponse::Acked))
    );
    let (status, answer) = v.call("/v1/ask", &ask(Some(1)));
    assert_eq!(status, 200);
    assert!(
        matches!(answer, Some(VaultResponse::Answers(_))),
        "{answer:?}"
    );
    assert_eq!(
        v.call("/v1/epoch", &VaultRequest::Epoch),
        (200, Some(VaultResponse::Epoch(1)))
    );
    v.stop();
    let rows = s.psql(
        "SELECT n || ':' || kind || ':' || entry_seq || ':' || entry_schema || ':' || coalesce(epoch::text, '-') \
         FROM vault_audit.chain ORDER BY n",
    );
    assert_eq!(rows, "1:1:1:1:1\n2:1:2:3:-", "{rows}");
    let receipts = s.psql("SELECT encode(receipt, 'hex') FROM vault_audit.anchor ORDER BY n");
    let lines: Vec<&str> = receipts.lines().collect();
    assert_eq!(lines.len(), 2, "{receipts}");
    for hex in lines {
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        let rc = decode_receipt(&bytes).unwrap();
        assert_eq!((rc.cell, rc.chain), (CellId(s.cell), ChainId::Vault));
        assert!(receipt_signature_verifies(&rc, &[s.witness_public()]));
    }
}

/// I-24, ADR-010 "Start-up": a restarted vault verifies its chain against
/// the witness and keeps what it committed. A chain row deleted behind it
/// (by a superuser, with the triggers off) stops it from starting.
#[test]
fn i24_vault_restart_verifies_its_chain_against_the_witness() {
    let s = Setup::new();
    let v = s.vault(true).unwrap();
    for seq in [5, 6] {
        assert_eq!(
            v.call("/v1/ask", &relationship(seq)),
            (200, Some(VaultResponse::Acked))
        );
    }
    let before = v.call("/v1/epoch", &VaultRequest::Epoch);
    assert!(
        matches!(before, (200, Some(VaultResponse::Epoch(e))) if e >= 1),
        "{before:?}"
    );
    v.stop();
    let v = s.vault(true).unwrap();
    assert_eq!(v.call("/v1/epoch", &VaultRequest::Epoch), before);
    assert_eq!(s.psql("SELECT count(*) FROM vault_audit.chain"), "2");
    v.stop();
    s.psql(
        "ALTER TABLE vault_audit.anchor DISABLE TRIGGER ALL;\n\
         ALTER TABLE vault_audit.chain DISABLE TRIGGER ALL;\n\
         DELETE FROM vault_audit.anchor WHERE n = 2;\n\
         DELETE FROM vault_audit.chain WHERE n = 2;\n\
         ALTER TABLE vault_audit.chain ENABLE TRIGGER ALL;\n\
         ALTER TABLE vault_audit.anchor ENABLE TRIGGER ALL;",
    );
    assert!(
        s.vault(true).is_err(),
        "the vault started over a chain with a deleted tail row"
    );
}

/// ADR-010 "Witness unavailable": a vault without a reachable witness, or
/// with no chain writer configured, refuses each write with 503 and
/// keeps serving reads that write nothing. Nothing is persisted.
#[test]
fn i24_vault_without_a_witness_refuses_writes_and_serves_reads() {
    let mut s = Setup::new();
    let none = s.vault(false).unwrap();
    assert_eq!(none.call("/v1/ask", &relationship(5)).0, 503);
    assert_eq!(
        none.call("/v1/epoch", &VaultRequest::Epoch),
        (200, Some(VaultResponse::Epoch(0)))
    );
    none.stop();
    let v = s.vault(true).unwrap();
    s.stop_witness();
    assert_eq!(v.call("/v1/ask", &relationship(5)).0, 503);
    assert_eq!(
        v.call("/v1/epoch", &VaultRequest::Epoch),
        (200, Some(VaultResponse::Epoch(0)))
    );
    v.stop();
    assert_eq!(s.psql("SELECT count(*) FROM vault_audit.chain"), "0");
    assert_eq!(s.psql("SELECT count(*) FROM vault.epoch"), "0");
}
