//! Review of lane int5 (security and fidelity lens): the witness tells a
//! connection's sender from the leaf's own authorityKeyIdentifier, which
//! the TLS verifier never checks (ADR-010 "Witnesses", I-19, I-24).
//!
//! The helpers below are those of `service_pg.rs`, with one addition: a
//! cell CA can issue a leaf whose authorityKeyIdentifier names another
//! cell's CA.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
#![allow(
    dead_code,
    unused_imports,
    reason = "the helpers are shared with service_pg.rs"
)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use fstp_audit::anchor::{receipt_signature_verifies, sign_anchor};
use fstp_audit::chain::{genesis, link_of};
use fstp_audit::witness::{Prepare, WitnessRecord};
use fstp_audit::{CellId, ChainId, CompositeSigningKey, Link};
use fstp_pki::cert::{
    CertKind, CertSpec, DistinguishedName, SignatureAlgorithm, Validity, assemble, key_identifier,
    tbs,
};
use fstp_pki::pem::{PemLabel, encode};
use fstp_rt::Runtime as _;
use fstp_rt::tokio::TokioRuntime;
use fstp_witness::wire::{
    WireReply, WireRequest, decode_reply, encode_request, read_frame, write_frame,
};
use fstp_witness::{WitnessHandle, WitnessMessage, WitnessParts, serve};

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
            ip_addrs: Vec::new(),
            algorithm: SignatureAlgorithm::EcdsaP256Sha256,
        };
        let t = tbs(&spec).unwrap();
        let der = assemble(&t, &self.key.sign(t.as_der()).unwrap()).unwrap();
        (pem_cert(&der), pem_key(&key.pkcs8_der().unwrap()))
    }
}

// ---------------------------------------------------------------------------
// A witness over a fresh database.

const WITNESS_HOST: &str = "witness.fstp.test";

static NEXT: AtomicU32 = AtomicU32::new(0);

struct Setup {
    rt: TokioRuntime,
    witness: WitnessHandle<TokioRuntime>,
    server: &'static fstp_pgtest::PgServer,
    dbname: String,
    login: fstp_pgtest::RoleLogin,
    control_ca: Ca,
    receipt_key_public: Vec<u8>,
}

/// The witness database `dbname`, migrated by its migrator, with the
/// `witness_service` role holding INSERT and SELECT only.
fn witness_database() -> (
    &'static fstp_pgtest::PgServer,
    String,
    fstp_pgtest::RoleLogin,
) {
    let server = fstp_pgtest::PgServer::shared_named("int5witness", "witness").unwrap();
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let dbname = format!("witness_t{n}_{}", std::process::id());
    let migrator = format!("wmig_{n}_{}", std::process::id());
    let service = format!("wsvc_{n}_{}", std::process::id());
    server.create_login_role(&migrator).unwrap();
    let login = server.create_login_role(&service).unwrap();
    server
        .create_database_for(&dbname, &[migrator.as_str(), service.as_str()])
        .unwrap();
    server
        .psql(
            "postgres",
            &format!("GRANT CREATE ON DATABASE {dbname} TO {migrator}"),
        )
        .unwrap();
    for m in fstp_witness::MIGRATIONS {
        server
            .psql(&dbname, &format!("SET ROLE {migrator};\n{}", m.sql))
            .unwrap();
    }
    server
        .psql(
            &dbname,
            &format!(
                "SET ROLE {migrator};\n\
                 INSERT INTO fstp_meta.placement (cluster_id, kind) VALUES ('\\x{}'::bytea, 4);\n\
                 GRANT USAGE ON SCHEMA witness, fstp_meta TO {service};\n\
                 GRANT SELECT ON fstp_meta.placement TO {service};\n\
                 GRANT SELECT, INSERT ON witness.anchor, witness.receipt, witness.withdrawal, witness.cell_ca, witness.anchor_key TO {service};",
                "ab".repeat(16)
            ),
        )
        .unwrap();
    (server, dbname, login)
}

fn config(
    server: &fstp_pgtest::PgServer,
    dbname: &str,
    login: &fstp_pgtest::RoleLogin,
) -> fstp_pgwire::Config {
    let p = login.conn_params(server, dbname);
    let tls =
        fstp_pgwire::ClientTls::new(p.server_ca_pem, p.client_cert_pem, p.client_key_pem).unwrap();
    fstp_pgwire::Config::new(
        p.host.clone(),
        p.port,
        p.user.as_str(),
        fstp_pgwire::Password::new(p.password.as_str()).unwrap(),
        p.dbname.clone(),
        tls,
    )
    .unwrap()
}

fn start(
    rt: &TokioRuntime,
    server: &'static fstp_pgtest::PgServer,
    dbname: &str,
    login: &fstp_pgtest::RoleLogin,
    control_ca: &Ca,
    key: CompositeSigningKey,
) -> WitnessHandle<TokioRuntime> {
    let (chain, key_pem) = control_ca.issue(CertKind::Server, WITNESS_HOST, None, &[WITNESS_HOST]);
    rt.block_on(serve(
        rt.clone(),
        WitnessParts {
            db: config(server, dbname, login),
            receipt_key: key,
            server_chain_pem: chain,
            server_key_pem: key_pem,
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
        },
    ))
    .unwrap()
}

fn setup() -> Setup {
    let rt = TokioRuntime::new_multi_thread(2).unwrap();
    let (server, dbname, login) = witness_database();
    let control_ca = Ca::new("int5 control-plane CA");
    let key = fstp_crypto::composite::generate().unwrap();
    let receipt_key_public = key.public_key().to_bytes().to_vec();
    let witness = start(&rt, server, &dbname, &login, &control_ca, key);
    Setup {
        rt,
        witness,
        server,
        dbname,
        login,
        control_ca,
        receipt_key_public,
    }
}

/// One cell: its CA, its App anchor key and a client of the witness.
struct Cell {
    id: CellId,
    ca: Ca,
    anchor: CompositeSigningKey,
}

impl Cell {
    fn new(byte: u8) -> Cell {
        Cell {
            id: CellId([byte; 16]),
            ca: Ca::new(&format!("cell CA {byte}")),
            anchor: fstp_crypto::composite::generate().unwrap(),
        }
    }

    fn register(&self, s: &Setup) {
        s.rt.block_on(s.witness.register_cell(
            self.id,
            &self.ca.der,
            &[(ChainId::App, self.anchor.public_key().to_bytes().to_vec())],
        ))
        .unwrap();
    }
}

/// A connection with a client certificate of `ou` from `ca`.
struct Conn {
    stream: fstp_tls::TlsStream<<TokioRuntime as fstp_rt::Runtime>::Tcp>,
}

impl Conn {
    fn open(s: &Setup, ca: &Ca, ou: &str) -> std::io::Result<Conn> {
        Conn::open_at(s, s.witness.local_addr(), ca, ou)
    }

    fn open_at(s: &Setup, addr: SocketAddr, ca: &Ca, ou: &str) -> std::io::Result<Conn> {
        let (cert, key) = ca.issue(CertKind::Client, "cell", Some(ou), &[]);
        let roots = pem_cert(&s.control_ca.der);
        let cfg = fstp_tls::ClientConfig::mutual(&roots, &cert, &key).unwrap();
        s.rt.block_on(async {
            let tcp = s.rt.connect_tcp(addr).await?;
            let stream = fstp_tls::connect(&cfg, WITNESS_HOST, tcp).await?;
            Ok(Conn { stream })
        })
    }

    fn ask(&mut self, s: &Setup, req: &WireRequest) -> std::io::Result<WireReply> {
        let bytes = encode_request(req).unwrap();
        s.rt.block_on(async {
            write_frame(&mut self.stream, &bytes).await?;
            let frame =
                fstp_rt::timeout(&s.rt, Duration::from_secs(20), read_frame(&mut self.stream))
                    .await
                    .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
            let frame =
                frame.ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?;
            Ok(decode_reply(&frame).unwrap())
        })
    }
}

/// A prepare of one row with stored hash `sh` after `prev`, signed by the
/// cell's anchor key.
fn prepare(cell: &Cell, prev: (u64, Link), sh: [u8; 32]) -> Prepare {
    let n = prev.0 + 1;
    let link = link_of(&prev.1, cell.id, ChainId::App, n, &sh);
    Prepare {
        prev,
        stored_hashes: vec![sh],
        anchor: sign_anchor(
            &cell.anchor,
            cell.id,
            ChainId::App,
            n,
            &link,
            1_800_000_000_000_000,
        )
        .unwrap(),
    }
}

impl Ca {
    /// A `cell-witness` client leaf signed by this CA, whose issuer name is
    /// this CA's, but whose authorityKeyIdentifier is `aki`.
    fn issue_claiming(&self, aki: fstp_pki::cert::KeyIdentifier) -> (Vec<u8>, Vec<u8>) {
        let key = fstp_crypto::sig::EcdsaP256KeyPair::generate().unwrap();
        let spec = CertSpec {
            serial: serial(),
            issuer: DistinguishedName {
                common_name: self.name.clone(),
                organizational_unit: None,
            },
            subject: DistinguishedName {
                common_name: "cell".to_owned(),
                organizational_unit: Some("cell-witness".to_owned()),
            },
            validity: Validity {
                not_before: now_s() - 300,
                not_after: now_s() + 86_000,
            },
            spki_der: key.spki_der().unwrap(),
            issuer_key_id: Some(aki),
            kind: CertKind::Client,
            dns_names: Vec::new(),
            ip_addrs: Vec::new(),
            algorithm: SignatureAlgorithm::EcdsaP256Sha256,
        };
        let t = tbs(&spec).unwrap();
        let der = assemble(&t, &self.key.sign(t.as_der()).unwrap()).unwrap();
        (pem_cert(&der), pem_key(&key.pkcs8_der().unwrap()))
    }
}

/// I-19, I-24, ADR-010 "Witnesses": a certificate that cell A's CA signed
/// is cell A's, whatever its authorityKeyIdentifier says. Cell A's CA
/// issues a `cell-witness` leaf naming cell B's CA key identifier. The
/// witness must not take it as cell B's App chain writer: it must neither
/// abort B's outstanding prepare nor show B's witness log.
#[test]
fn review_witness_sender_is_not_the_leafs_claimed_issuer() {
    let s = setup();
    let a = Cell::new(0x51);
    let b = Cell::new(0x52);
    a.register(&s);
    b.register(&s);
    // Cell B prepares its first head; the prepare is outstanding.
    let mut honest = Conn::open(&s, &b.ca, "cell-witness").unwrap();
    let p = prepare(&b, (0, genesis(b.id, ChainId::App)), [9; 32]);
    assert!(matches!(
        honest
            .ask(
                &s,
                &WireRequest::Message(WitnessMessage::Prepare(p.clone()))
            )
            .unwrap(),
        WireReply::Receipt(_)
    ));
    // Cell A's CA signs a leaf that claims B's CA as its issuer key.
    let b_key_id = key_identifier(&b.ca.key.spki_der().unwrap()).unwrap();
    let (cert, key) = a.ca.issue_claiming(b_key_id);
    let roots = pem_cert(&s.control_ca.der);
    let cfg = fstp_tls::ClientConfig::mutual(&roots, &cert, &key).unwrap();
    let opened = s.rt.block_on(async {
        let tcp = s.rt.connect_tcp(s.witness.local_addr()).await?;
        fstp_tls::connect(&cfg, WITNESS_HOST, tcp).await
    });
    let Ok(stream) = opened else {
        // The handshake was refused: the witness took no message from it.
        return;
    };
    let mut spoof = Conn { stream };
    let abort = WitnessMessage::Abort {
        cell: b.id,
        chain: ChainId::App,
        n: p.anchor.n,
        link: p.anchor.link,
    };
    let reply = spoof.ask(&s, &WireRequest::Message(abort));
    let log = spoof.ask(
        &s,
        &WireRequest::Log {
            cell: b.id,
            chain: ChainId::App,
        },
    );
    let withdrawals = s
        .server
        .psql(
            &s.dbname,
            &format!(
                "SELECT count(*) FROM witness.withdrawal WHERE cell_id = '\\x{}'::bytea",
                "52".repeat(16)
            ),
        )
        .unwrap();
    assert_eq!(
        withdrawals, "0",
        "cell A's certificate aborted cell B's prepare: abort {reply:?}, log {log:?}"
    );
    assert!(
        !matches!(log, Ok(WireReply::Log(_))),
        "cell A's certificate read cell B's witness log: {log:?}"
    );
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// I-24, ADR-010 "Start-up": a cell verifies its chain against the whole
/// witness log at every start (`fstp_cell::engine::startup`). A chain
/// whose witness log has grown past `MAX_LOG_RECORDS` records, that is a
/// cell after 4097 commits, must still get its log. Otherwise that cell
/// can never start again. The rows here are written straight into the
/// witness tables, as the service would have written them over 4097
/// prepares; the replay checks the witness links, not the signatures.
/// Each signature has the composite length `fstp_audit::SIGNATURE_LEN`,
/// as every signature the service stores has, so the wire can carry it.
#[test]
fn review_witness_log_answers_a_chain_longer_than_one_frame() {
    use fstp_audit::witness::{RecordKind, witness_genesis, witness_link};
    let s = setup();
    let cell = Cell::new(0x61);
    cell.register(&s);
    let total = fstp_witness::wire::MAX_LOG_RECORDS as u64 + 1;
    let cell_hex = "61".repeat(16);
    let sig = format!("decode(repeat('00', {}), 'hex')", fstp_audit::SIGNATURE_LEN);
    let mut head = witness_genesis(cell.id, ChainId::App);
    let mut anchors = Vec::new();
    let mut receipts = Vec::new();
    for seq in 1..=total {
        let mut l = [0u8; 32];
        l[..8].copy_from_slice(&seq.to_be_bytes());
        let link = Link(l);
        head = witness_link(
            &head,
            cell.id,
            ChainId::App,
            RecordKind::Prepare,
            seq,
            seq,
            &link,
        );
        anchors.push(format!(
            "('\\x{cell_hex}'::bytea, 1, {seq}, '\\x{}'::bytea, 0, {sig}, 0, {seq}, '\\x{}'::bytea)",
            hex_of(&link.0),
            hex_of(&head.0)
        ));
        receipts.push(format!("('\\x{cell_hex}'::bytea, 1, {seq}, {sig})"));
    }
    s.server
        .psql(
            &s.dbname,
            &format!(
                "INSERT INTO witness.anchor (cell_id, chain, n, link, at, signature, received_at, witness_seq, witness_link) VALUES {};\n\
                 INSERT INTO witness.receipt (cell_id, chain, witness_seq, signature) VALUES {};",
                anchors.join(", "),
                receipts.join(", ")
            ),
        )
        .unwrap();
    let mut c = Conn::open(&s, &cell.ca, "cell-witness").unwrap();
    // The chain loads: its outstanding prepare is the last row.
    assert!(matches!(
        c.ask(
            &s,
            &WireRequest::Outstanding {
                cell: cell.id,
                chain: ChainId::App
            }
        )
        .unwrap(),
        WireReply::Outstanding(Some((n, _))) if n == total
    ));
    let log = c
        .ask(
            &s,
            &WireRequest::Log {
                cell: cell.id,
                chain: ChainId::App,
            },
        )
        .unwrap();
    assert!(
        matches!(log, WireReply::Log(_)),
        "the witness refused the log of a chain of {total} records: {log:?}"
    );
}
