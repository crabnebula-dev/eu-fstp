//! The witness service over PostgreSQL and mutual TLS (I-24, ADR-010
//! "Witnesses", "Prepare, receipt, commit", "Abort", design section 4.4).
//! Lane int5.
//!
//! Each test migrates a fresh witness database on a named PostgreSQL 16
//! server, starts `fstp_witness::serve` over it, registers one cell CA and
//! anchor key, and speaks the framed protocol of `fstp_witness::wire` over
//! a real TLS 1.3 connection with a `cell-witness` client certificate.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

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

/// I-24, ADR-010 "Prepare, receipt, commit": a prepare from the chain's
/// writer is stored before its receipt leaves the witness. The receipt
/// verifies under the witness's receipt key, and the witness's own
/// `witness.anchor` row holds the same head and witness fields. A
/// retransmit gets the same receipt and adds no row.
#[test]
fn i24_witness_stores_each_prepare_before_its_receipt() {
    let s = setup();
    let cell = Cell::new(0x31);
    cell.register(&s);
    let mut c = Conn::open(&s, &cell.ca, "cell-witness").unwrap();
    let p = prepare(&cell, (0, genesis(cell.id, ChainId::App)), [7; 32]);
    let first = c
        .ask(
            &s,
            &WireRequest::Message(WitnessMessage::Prepare(p.clone())),
        )
        .unwrap();
    let WireReply::Receipt(rc) = first.clone() else {
        panic!("no receipt: {first:?}");
    };
    assert!(receipt_signature_verifies(
        &rc,
        std::slice::from_ref(&s.receipt_key_public)
    ));
    assert_eq!((rc.fields.n, rc.fields.link), (p.anchor.n, p.anchor.link));
    let row = s
        .server
        .psql(
            &s.dbname,
            &format!(
                "SELECT n, encode(link, 'hex'), witness_seq, encode(witness_link, 'hex') FROM witness.anchor WHERE cell_id = '\\x{}'::bytea",
                "31".repeat(16)
            ),
        )
        .unwrap();
    let link_hex: String = rc
        .fields
        .link
        .0
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let wl_hex: String = rc
        .fields
        .witness_link
        .0
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(row, format!("1|{link_hex}|1|{wl_hex}"));
    let again = c
        .ask(&s, &WireRequest::Message(WitnessMessage::Prepare(p)))
        .unwrap();
    assert_eq!(again, first, "a retransmit got another receipt");
    let count = s
        .server
        .psql(&s.dbname, "SELECT count(*) FROM witness.anchor")
        .unwrap();
    assert_eq!(count, "1");
    assert_eq!(
        c.ask(
            &s,
            &WireRequest::Outstanding {
                cell: cell.id,
                chain: ChainId::App
            }
        )
        .unwrap(),
        WireReply::Outstanding(Some((rc.fields.n, rc.fields.link)))
    );
}

/// I-24, ADR-010 "Abort" and "Start-up": an abort is recorded, the same
/// `n` is prepared again with another link, and a restarted witness
/// rebuilds the chain from its rows: the same log and the same
/// outstanding prepare.
#[test]
fn i24_witness_records_aborts_and_rebuilds_after_restart() {
    let s = setup();
    let cell = Cell::new(0x32);
    cell.register(&s);
    let mut c = Conn::open(&s, &cell.ca, "cell-witness").unwrap();
    let g = (0, genesis(cell.id, ChainId::App));
    let p1 = prepare(&cell, g, [1; 32]);
    assert!(matches!(
        c.ask(
            &s,
            &WireRequest::Message(WitnessMessage::Prepare(p1.clone()))
        )
        .unwrap(),
        WireReply::Receipt(_)
    ));
    let abort = WitnessMessage::Abort {
        cell: cell.id,
        chain: ChainId::App,
        n: p1.anchor.n,
        link: p1.anchor.link,
    };
    assert_eq!(
        c.ask(&s, &WireRequest::Message(abort.clone())).unwrap(),
        WireReply::Recorded
    );
    assert_eq!(
        c.ask(&s, &WireRequest::Message(abort)).unwrap(),
        WireReply::UnknownPrepare
    );
    let p2 = prepare(&cell, g, [2; 32]);
    let WireReply::Receipt(r2) = c
        .ask(
            &s,
            &WireRequest::Message(WitnessMessage::Prepare(p2.clone())),
        )
        .unwrap()
    else {
        panic!("the re-prepare was refused");
    };
    assert_eq!(r2.fields.witness_seq, 3);
    let log = c
        .ask(
            &s,
            &WireRequest::Log {
                cell: cell.id,
                chain: ChainId::App,
            },
        )
        .unwrap();
    let WireReply::Log(page) = &log else {
        panic!("no log: {log:?}");
    };
    assert!(matches!(
        page.records.as_slice(),
        [
            WitnessRecord::Prepare(_),
            WitnessRecord::Abort { .. },
            WitnessRecord::Prepare(_)
        ]
    ));
    drop(c);
    s.rt.block_on(s.witness.shutdown(Duration::from_secs(10)))
        .unwrap();
    let key = fstp_crypto::composite::generate().unwrap();
    let again = start(&s.rt, s.server, &s.dbname, &s.login, &s.control_ca, key);
    let mut c = Conn::open_at(&s, again.local_addr(), &cell.ca, "cell-witness").unwrap();
    assert_eq!(
        c.ask(
            &s,
            &WireRequest::Log {
                cell: cell.id,
                chain: ChainId::App
            }
        )
        .unwrap(),
        log
    );
    assert_eq!(
        c.ask(
            &s,
            &WireRequest::Outstanding {
                cell: cell.id,
                chain: ChainId::App
            }
        )
        .unwrap(),
        WireReply::Outstanding(Some((r2.fields.n, r2.fields.link)))
    );
}

/// ADR-010 "Witnesses", I-90: a `vault-witness` certificate does not
/// write the App chain, an anchor under another key is refused, and a
/// client certificate of an unregistered CA gets no witness at all.
#[test]
fn adr010_witness_takes_only_the_chain_writer_and_its_anchor_key() {
    let s = setup();
    let cell = Cell::new(0x33);
    cell.register(&s);
    let g = (0, genesis(cell.id, ChainId::App));
    let p = prepare(&cell, g, [3; 32]);
    let mut vault = Conn::open(&s, &cell.ca, "vault-witness").unwrap();
    assert_eq!(
        vault
            .ask(
                &s,
                &WireRequest::Message(WitnessMessage::Prepare(p.clone()))
            )
            .unwrap(),
        WireReply::Refused
    );
    let mut forged = p.clone();
    let other = fstp_crypto::composite::generate().unwrap();
    forged.anchor = sign_anchor(
        &other,
        cell.id,
        ChainId::App,
        p.anchor.n,
        &p.anchor.link,
        p.anchor.at,
    )
    .unwrap();
    let mut app = Conn::open(&s, &cell.ca, "cell-witness").unwrap();
    assert_eq!(
        app.ask(&s, &WireRequest::Message(WitnessMessage::Prepare(forged)))
            .unwrap(),
        WireReply::Refused
    );
    let stranger = Ca::new("unregistered CA");
    let refused = Conn::open(&s, &stranger, "cell-witness")
        .and_then(|mut c| c.ask(&s, &WireRequest::Message(WitnessMessage::Prepare(p))));
    assert!(
        refused.is_err(),
        "an unregistered CA reached the witness: {refused:?}"
    );
    assert_eq!(
        s.server
            .psql(&s.dbname, "SELECT count(*) FROM witness.anchor")
            .unwrap(),
        "0"
    );
}

/// I-24, ADR-010 "Database link trigger": the witness tables refuse UPDATE
/// and DELETE for every role, and a record out of witness order.
#[test]
fn i24_witness_tables_are_insert_only_and_ordered() {
    let s = setup();
    let cell = Cell::new(0x34);
    cell.register(&s);
    let mut c = Conn::open(&s, &cell.ca, "cell-witness").unwrap();
    let p = prepare(&cell, (0, genesis(cell.id, ChainId::App)), [4; 32]);
    assert!(matches!(
        c.ask(&s, &WireRequest::Message(WitnessMessage::Prepare(p)))
            .unwrap(),
        WireReply::Receipt(_)
    ));
    for sql in [
        "UPDATE witness.anchor SET at = 0",
        "DELETE FROM witness.anchor",
        "DELETE FROM witness.receipt",
        "DELETE FROM witness.cell_ca",
        "TRUNCATE witness.withdrawal",
    ] {
        assert!(
            s.server.psql(&s.dbname, sql).is_err(),
            "{sql} was not refused"
        );
    }
    let out_of_order = format!(
        "INSERT INTO witness.withdrawal (cell_id, chain, witness_seq, kind, n, link, received_at, witness_link) \
         VALUES ('\\x{}'::bytea, 1, 5, 2, 1, '\\x{}'::bytea, 0, '\\x{}'::bytea)",
        "34".repeat(16),
        "00".repeat(32),
        "00".repeat(32)
    );
    assert!(s.server.psql(&s.dbname, &out_of_order).is_err());
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// I-24, ADR-010 "Start-up": a witness log longer than one page comes in
/// pages that join into the whole log, in witness order. The first page
/// holds `MAX_LOG_RECORDS` records and says more follow. The page after
/// them holds the rest and says none follow. A client that claims more
/// records than the log holds is refused. The rows are written straight
/// into the tables, each with its witness link and signatures of the
/// composite length.
#[test]
fn i24_witness_log_pages_join_into_the_whole_log() {
    use fstp_audit::witness::{RecordKind, witness_genesis, witness_link};
    use fstp_witness::wire::{LogPage, MAX_LOG_RECORDS};
    let s = setup();
    let cell = Cell::new(0x62);
    cell.register(&s);
    let total = MAX_LOG_RECORDS as u64 + 2;
    let cell_hex = "62".repeat(16);
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
    let (cell_id, chain) = (cell.id, ChainId::App);
    let WireReply::Log(first) = c
        .ask(
            &s,
            &WireRequest::Log {
                cell: cell_id,
                chain,
            },
        )
        .unwrap()
    else {
        panic!("no first page");
    };
    assert_eq!(first.records.len(), MAX_LOG_RECORDS);
    assert!(first.more);
    let after = MAX_LOG_RECORDS as u64;
    let WireReply::Log(second) = c
        .ask(
            &s,
            &WireRequest::LogAfter {
                cell: cell_id,
                chain,
                after,
            },
        )
        .unwrap()
    else {
        panic!("no second page");
    };
    assert_eq!(second.records.len(), 2);
    assert!(!second.more);
    let ns: Vec<u64> = first
        .records
        .iter()
        .chain(second.records.iter())
        .map(|r| match r {
            WitnessRecord::Prepare(row) => row.anchor.n,
            other => panic!("not a prepare: {other:?}"),
        })
        .collect();
    assert_eq!(ns, (1..=total).collect::<Vec<_>>());
    assert_eq!(
        c.ask(
            &s,
            &WireRequest::LogAfter {
                cell: cell_id,
                chain,
                after: total,
            },
        )
        .unwrap(),
        WireReply::Log(LogPage {
            records: Vec::new(),
            more: false,
        })
    );
    assert_eq!(
        c.ask(
            &s,
            &WireRequest::LogAfter {
                cell: cell_id,
                chain,
                after: total + 1,
            },
        )
        .unwrap(),
        WireReply::Refused
    );
}

/// ADR-010 "Witnesses", design sections 4.1 and 9.2: provisioning writes a
/// cell's registration (`registration_sql`), and the witness pins it on
/// `reload_registry`. A service login that may only read the registry
/// cannot register a cell itself. A second registration with another CA
/// is refused and changes nothing.
#[test]
fn adr010_provisioning_registers_cells_the_service_only_reads() {
    let s = setup();
    let service = &s.login.role;
    s.server
        .psql(
            &s.dbname,
            &format!("REVOKE INSERT ON witness.cell_ca, witness.anchor_key FROM {service}"),
        )
        .unwrap();
    let cell = Cell::new(0x63);
    let keys = [(ChainId::App, cell.anchor.public_key().to_bytes().to_vec())];
    assert!(
        s.rt.block_on(s.witness.register_cell(cell.id, &cell.ca.der, &keys))
            .is_err()
    );
    let sql = fstp_witness::store::registration_sql(cell.id, &cell.ca.der, &keys, 1);
    s.server.psql(&s.dbname, &sql).unwrap();
    // The same registration again changes nothing.
    s.server.psql(&s.dbname, &sql).unwrap();
    let other = Ca::new("another CA");
    let conflict = fstp_witness::store::registration_sql(cell.id, &other.der, &keys, 2);
    assert!(s.server.psql(&s.dbname, &conflict).is_err());
    s.rt.block_on(s.witness.reload_registry()).unwrap();
    let mut c = Conn::open(&s, &cell.ca, "cell-witness").unwrap();
    let p = prepare(&cell, (0, genesis(cell.id, ChainId::App)), [4; 32]);
    assert!(matches!(
        c.ask(&s, &WireRequest::Message(WitnessMessage::Prepare(p)))
            .unwrap(),
        WireReply::Receipt(_)
    ));
    let cas = s
        .server
        .psql(&s.dbname, "SELECT count(*) FROM witness.cell_ca")
        .unwrap();
    assert_eq!(cas, "1");
}
