//! Lane m10/saas-declare (ADR-012 record of the lane; Daniel decided on
//! 2026-11-25 to build the SaaS path): `fstp-control` declares a restore
//! at the SaaS witness as the two-operator job `DeclareRestore`, signed
//! with the restore declaration key.
//!
//! - The job runs only on two operators' approvals (ADR-011).
//! - The restore declaration key is sealed under a ControlPlane root of a
//!   real `fstp-keyd` and never leaves it open (I-80).
//! - `declare_restore` refuses a witness answer that does not match its
//!   statement or does not verify.
//! - Over a real PostgreSQL 16 witness and mutual TLS, a declared restore
//!   lets the cell's chain verify with the lost window as
//!   `LostInRestore`, and the cell's next prepare extends the declared
//!   head (I-24).
//!
//! Every value is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::cell::RefCell;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use fstp_audit::anchor::{AnchorRow, sign_anchor};
use fstp_audit::chain::{ChainWriter, RowKind, StoredRow};
use fstp_audit::verify::{ChainView, verify, verify_with_declaration_keys};
use fstp_audit::witness::{
    Declaration, Prepare, RestoreStatement, WitnessRecord, sign_declaration,
    statement_signature_verifies,
};
use fstp_audit::{ChainId, CompositeSigningKey, Link, LostInRestore};
use fstp_control::ControlError;
use fstp_control::api::CpApiRequest;
use fstp_control::approval::{ApprovalBook, ApprovedJob, DestructiveJob};
use fstp_control::declare::{
    RestoreWitness, TlsRestoreWitness, create_declaration_key, declare_restore,
    declare_restore_batch, declare_restore_jobs, decode_declaration_key_file,
    encode_declaration_key_file, open_declaration_key,
};
use fstp_cp_proto::{CellId, StaffRef};
use fstp_custody::KeydCustody;
use fstp_keyd::{ClientRole, ClientSocket, PassphraseSource};
use fstp_pki::cert::{
    CertKind, CertSpec, DistinguishedName, SignatureAlgorithm, Validity, assemble, key_identifier,
    tbs,
};
use fstp_pki::pem::{PemLabel, encode};
use fstp_rt::Runtime as _;
use fstp_rt::future::block_on;
use fstp_rt::tokio::TokioRuntime;
use fstp_witness::wire::{
    WireReply, WireRequest, decode_reply, encode_request, read_frame, write_frame,
};
use fstp_witness::{WitnessHandle, WitnessMessage, WitnessParts, serve};

const T0: i64 = 1_800_000_000;
const CELL: CellId = CellId([0x7A; 16]);
const JOB: [u8; 16] = [0x4D; 16];

fn staff(n: u8) -> StaffRef {
    StaffRef([n; 16])
}

/// The App chain job of one restore of `CELL` to `head`.
fn app_job(head: (u64, [u8; 32])) -> DestructiveJob {
    let [app, _] = declare_restore_jobs(CELL, JOB, head, (0, [0; 32]));
    app
}

/// How a fake witness answers a statement and its signature.
type Answer = Box<dyn Fn(&RestoreStatement, &[u8]) -> Result<Declaration, ControlError>>;

/// A witness that records what it is sent and answers with `answer`.
struct FakeWitness {
    sent: RefCell<Vec<(RestoreStatement, Vec<u8>)>>,
    answer: Answer,
}

impl RestoreWitness for FakeWitness {
    async fn declare(
        &self,
        statement: &RestoreStatement,
        signature: &[u8],
    ) -> Result<Declaration, ControlError> {
        self.sent
            .borrow_mut()
            .push((*statement, signature.to_vec()));
        (self.answer)(statement, signature)
    }
}

/// A witness that records the statement as an honest one would, with the
/// receipt key `witness`, and `tweak` applied to the record.
fn fake(witness: std::rc::Rc<CompositeSigningKey>, tweak: fn(&mut Declaration)) -> FakeWitness {
    FakeWitness {
        sent: RefCell::new(Vec::new()),
        answer: Box::new(move |st, sig| {
            let fields = fstp_audit::DeclarationFields {
                head: st.head,
                lost_to: st.head.0 + 2,
                job: st.job,
                witness_seq: 7,
                witness_link: Link([7; 32]),
                received_at: 9,
            };
            let mut d = sign_declaration(&witness, st.cell, st.chain, &fields).unwrap();
            d.statement = Some(sig.to_vec());
            tweak(&mut d);
            Ok(d)
        }),
    }
}

/// Both operators approve the App job, and the requester takes it.
fn approved_app(book: &mut ApprovalBook, head: (u64, [u8; 32])) -> ApprovedJob {
    for s in [1, 2] {
        book.approve(staff(s), &app_job(head), T0).unwrap();
    }
    book.take(staff(1), &app_job(head), T0 + 1).unwrap()
}

/// ADR-011 "Two-operator approval", ADR-012 record of lane
/// m10/saas-declare: `declare-restore` is destructive. The operator API
/// refuses it without approvals, one operator's approval does not admit
/// it, nor do two approvals from the same person, and a job of another
/// kind never declares. Only two distinct operators admit it, once.
#[test]
fn adr011_declare_restore_refused_without_a_second_operator() {
    let head = (3, [3; 32]);
    let job = app_job(head);
    let mut book = ApprovalBook::default();
    book.approve(staff(1), &job, T0).unwrap();
    assert_eq!(
        book.take(staff(1), &job, T0 + 1).unwrap_err(),
        ControlError::ApprovalRequired
    );
    book.approve(staff(1), &job, T0 + 2).unwrap();
    assert_eq!(
        book.take(staff(1), &job, T0 + 3).unwrap_err(),
        ControlError::ApprovalRequired,
        "one person twice"
    );
    book.approve(staff(2), &job, T0 + 4).unwrap();
    let approved = book.take(staff(1), &job, T0 + 5).unwrap();
    assert_eq!(approved.approvers(), [staff(1), staff(2)]);
    assert_eq!(
        book.take(staff(1), &job, T0 + 6).unwrap_err(),
        ControlError::ApprovalRequired,
        "approvals are single use"
    );
    // The operator API request is never admitted by one session alone.
    let req = CpApiRequest::DeclareRestore {
        cell: CELL,
        chain: ChainId::App,
        head_n: head.0,
        head_link: head.1,
        job: JOB,
    };
    let bytes = fstp_control::api::encode_cp_api(&req);
    assert_eq!(fstp_control::api::decode_cp_api(&bytes).unwrap(), req);
    // Another job kind, though approved by two, declares nothing.
    let erase = DestructiveJob::EraseCell { cell: CELL };
    let mut book = ApprovalBook::default();
    book.approve(staff(1), &erase, T0).unwrap();
    book.approve(staff(2), &erase, T0).unwrap();
    let other = book.take(staff(1), &erase, T0 + 1).unwrap();
    let signer = fstp_crypto::composite::generate().unwrap();
    let witness = fake(
        std::rc::Rc::new(fstp_crypto::composite::generate().unwrap()),
        |_| {},
    );
    assert_eq!(
        block_on(declare_restore(&other, &signer, &witness, &[])).unwrap_err(),
        ControlError::ApprovalRequired
    );
    assert!(witness.sent.borrow().is_empty());
    // The digest binds every field: another head or job is another job.
    assert_ne!(
        fstp_control::approval::job_digest(&app_job(head)),
        fstp_control::approval::job_digest(&app_job((3, [4; 32])))
    );
}

/// I-24, I-90, ADR-012 record of lane m10/saas-declare: the approved job
/// sends a statement under the restore declaration key, and accepts only
/// an answer that names it, carries its signature and verifies under the
/// pinned witness key.
#[test]
fn adr012_declare_restore_checks_the_witness_answer() {
    let signer = fstp_crypto::composite::generate().unwrap();
    let wkey = std::rc::Rc::new(fstp_crypto::composite::generate().unwrap());
    let witness_keys = vec![wkey.public_key().to_bytes().to_vec()];
    let head = (3, [3; 32]);
    let mut book = ApprovalBook::default();
    let approved = approved_app(&mut book, head);
    let honest = fake(wkey.clone(), |_| {});
    let d = block_on(declare_restore(&approved, &signer, &honest, &witness_keys)).unwrap();
    assert_eq!(d.fields.head, (3, Link([3; 32])));
    let (st, sig) = honest.sent.borrow()[0].clone();
    assert_eq!(st.job, JOB);
    assert!(statement_signature_verifies(
        &st,
        &sig,
        &[signer.public_key().to_bytes().to_vec()]
    ));
    let tweaks: [fn(&mut Declaration); 4] = [
        |d| d.fields.job = [0; 16],
        |d| d.statement = None,
        |d| d.signature[5] ^= 1,
        |d| d.fields.head.0 += 1,
    ];
    for t in tweaks {
        let w = fake(wkey.clone(), t);
        assert!(matches!(
            block_on(declare_restore(&approved, &signer, &w, &witness_keys)),
            Err(ControlError::Job(_))
        ));
    }
    let other_witness = fake(
        std::rc::Rc::new(fstp_crypto::composite::generate().unwrap()),
        |_| {},
    );
    assert!(
        block_on(declare_restore(
            &approved,
            &signer,
            &other_witness,
            &witness_keys
        ))
        .is_err()
    );
}

// ---------------------------------------------------------------------------
// The restore declaration key in a real fstp-keyd.

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scratch(name: &str) -> Scratch {
    let tag = fstp_crypto::random_array::<4>().unwrap();
    let tag: String = tag.iter().map(|b| format!("{b:02x}")).collect();
    let dir = std::env::temp_dir().join(format!("fstp-sd-{name}-{tag}"));
    std::fs::create_dir_all(&dir).unwrap();
    Scratch(dir)
}

/// A running `fstp-keyd` with a control socket and a cell socket.
fn keyd(dir: &Path) -> (KeydCustody, KeydCustody) {
    let volume = dir.join("volume");
    std::fs::create_dir_all(&volume).unwrap();
    let control = dir.join("control.sock");
    let cell = dir.join("cell.sock");
    {
        let sockets = vec![
            ClientSocket::owner_only(&control, ClientRole::Control),
            ClientSocket::owner_only(&cell, ClientRole::Cell),
        ];
        std::thread::spawn(move || {
            let _ = fstp_keyd::serve_sockets(&sockets, &volume, PassphraseSource::Credential);
        });
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    while !(control.exists() && cell.exists()) {
        assert!(Instant::now() < deadline, "fstp-keyd bound no sockets");
        std::thread::sleep(Duration::from_millis(10));
    }
    (
        KeydCustody::new(&control).unwrap(),
        KeydCustody::new(&cell).unwrap(),
    )
}

/// I-80, ADR-004 "Restore declaration key", ADR-012 record of lane
/// m10/saas-declare: the key is sealed under a seal key that `fstp-keyd`
/// wraps under a ControlPlane root, through the control socket, and opens
/// there to itself. The cell socket can neither create nor open it. The
/// file holds no open key, round-trips, is not a route feed key file, and
/// refuses a changed sealed byte and every cut.
#[test]
fn i80_restore_declaration_key_is_sealed_under_a_control_plane_root() {
    let dir = scratch("keyd");
    let (control, cell) = keyd(&dir.0);
    let key = fstp_crypto::composite::generate().unwrap();
    let file = block_on(create_declaration_key(&control, &key)).unwrap();
    let secret = key.to_bytes().unwrap();
    assert!(
        !file.windows(secret.len()).any(|w| w == &secret[..]),
        "the key file holds the open key"
    );
    let opened = block_on(open_declaration_key(&control, &file)).unwrap();
    assert_eq!(opened.public_key().to_bytes(), key.public_key().to_bytes());
    assert!(matches!(
        block_on(open_declaration_key(&cell, &file)),
        Err(ControlError::Custody(_))
    ));
    assert!(matches!(
        block_on(create_declaration_key(&cell, &key)),
        Err(ControlError::Custody(_))
    ));
    let decoded = decode_declaration_key_file(&file).unwrap();
    assert_eq!(encode_declaration_key_file(&decoded).unwrap(), file);
    assert!(fstp_control::route_feed::decode_feed_key_file(&file).is_err());
    assert!(block_on(fstp_control::route_feed::open_feed_key(&control, &file)).is_err());
    let mut changed = file.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert!(block_on(open_declaration_key(&control, &changed)).is_err());
    for cut in 0..file.len() {
        assert!(decode_declaration_key_file(&file[..cut]).is_err());
    }
}

// ---------------------------------------------------------------------------
// A PostgreSQL witness, a cell, and fstp-control over mutual TLS.

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
    let mut out = String::from("-----BEGIN PRIVATE KEY-----\n");
    for line in s.as_bytes().chunks(64) {
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

const WITNESS_HOST: &str = "witness.fstp.test";

static NEXT: AtomicU32 = AtomicU32::new(0);

/// A migrated witness database whose `witness_service` login holds INSERT
/// and SELECT on the witness records, and a witness served over it.
fn witness(
    rt: &TokioRuntime,
    control_ca: &Ca,
    receipt_key: CompositeSigningKey,
) -> (
    WitnessHandle<TokioRuntime>,
    &'static fstp_pgtest::PgServer,
    String,
) {
    let server = fstp_pgtest::PgServer::shared_named("saasdeclare", "witness").unwrap();
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let dbname = format!("witness_sd{n}_{pid}");
    let migrator = format!("wsdmig_{n}_{pid}");
    let service = format!("wsdsvc_{n}_{pid}");
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
                 GRANT SELECT, INSERT ON witness.anchor, witness.receipt, witness.withdrawal, \
                 witness.declaration, witness.cell_ca, witness.anchor_key TO {service};\n\
                 GRANT SELECT ON witness.cell_revocation TO {service};",
                "cd".repeat(16)
            ),
        )
        .unwrap();
    let p = login.conn_params(server, &dbname);
    let tls =
        fstp_pgwire::ClientTls::new(p.server_ca_pem, p.client_cert_pem, p.client_key_pem).unwrap();
    let db = fstp_pgwire::Config::new(
        p.host.clone(),
        p.port,
        p.user.as_str(),
        fstp_pgwire::Password::new(p.password.as_str()).unwrap(),
        p.dbname.clone(),
        tls,
    )
    .unwrap();
    let (chain, key_pem) = control_ca.issue(CertKind::Server, WITNESS_HOST, None, &[WITNESS_HOST]);
    let handle = rt
        .block_on(serve(
            rt.clone(),
            WitnessParts {
                db,
                receipt_key,
                server_chain_pem: chain,
                server_key_pem: key_pem,
                listen: SocketAddr::from(([127, 0, 0, 1], 0)),
            },
        ))
        .unwrap();
    (handle, server, dbname)
}

/// The cell: its App chain rows and anchor rows, as its database holds
/// them, and its connection to the witness.
struct Cell {
    id: fstp_audit::CellId,
    anchor: CompositeSigningKey,
    rows: Vec<StoredRow>,
    anchors: Vec<AnchorRow>,
    stream: fstp_tls::TlsStream<<TokioRuntime as fstp_rt::Runtime>::Tcp>,
    at: i64,
}

impl Cell {
    fn head(&self) -> (u64, Link) {
        self.rows.last().map_or(
            (0, fstp_audit::chain::genesis(self.id, ChainId::App)),
            |r| (r.row.n, r.link),
        )
    }

    fn ask(&mut self, rt: &TokioRuntime, req: &WireRequest) -> WireReply {
        let bytes = encode_request(req).unwrap();
        rt.block_on(async {
            write_frame(&mut self.stream, &bytes).await.unwrap();
            let frame = read_frame(&mut self.stream).await.unwrap().unwrap();
            decode_reply(&frame).unwrap()
        })
    }

    /// Appends `k` event rows under one prepare and commits them once the
    /// witness receipts it.
    fn commit(&mut self, rt: &TokioRuntime, k: usize) -> WireReply {
        self.at += 10;
        let prev = self.head();
        let mut w = ChainWriter::resume(prev.0, prev.1);
        let mut rows = Vec::new();
        for i in 0..k {
            let body = vec![u8::try_from(i).unwrap(); 3];
            rows.push(
                w.append(
                    self.id,
                    ChainId::App,
                    self.at,
                    RowKind::Event { body },
                    None,
                )
                .unwrap(),
            );
        }
        let (n, l) = w.head();
        let anchor = sign_anchor(&self.anchor, self.id, ChainId::App, n, &l, self.at).unwrap();
        let p = Prepare {
            prev,
            stored_hashes: rows.iter().map(|r| r.row.stored_hash).collect(),
            anchor: anchor.clone(),
        };
        let reply = self.ask(rt, &WireRequest::Message(WitnessMessage::Prepare(p)));
        if let WireReply::Receipt(receipt) = &reply {
            self.rows.extend(rows);
            self.anchors.push(AnchorRow {
                anchor,
                receipt: receipt.clone(),
            });
        }
        reply
    }

    fn log(&mut self, rt: &TokioRuntime) -> Vec<WitnessRecord> {
        match self.ask(
            rt,
            &WireRequest::Log {
                cell: self.id,
                chain: ChainId::App,
            },
        ) {
            WireReply::Log(page) if !page.more => page.records,
            other => panic!("no log: {other:?}"),
        }
    }
}

/// I-24, ADR-012 record of lane m10/saas-declare, ADR-011: over a real
/// PostgreSQL witness and mutual TLS. A cell commits rows 1 to 5, each
/// batch receipted. Its database is restored to row 3. Without a
/// declaration the cell's verifier reports `Truncated`, so the cell would
/// not start. Two operators approve the restore's `DeclareRestore` jobs,
/// and `fstp-control` declares the App chain at the witness with its
/// `control-witness` certificate and the restore declaration key. The
/// cell's verifier, with that key pinned, then verifies the chain and
/// reports rows 4 to 5 as `LostInRestore` by the job, and the cell starts:
/// its next prepare extends the declared head, and a prepare from the
/// lost tail is refused. The finding stays after the chain grows.
#[test]
fn i24_adr012_saas_declared_restore_through_fstp_control_reports_lost_in_restore() {
    let rt = TokioRuntime::new_multi_thread(2).unwrap();
    let control_ca = Ca::new("saas-declare control-plane CA");
    let receipt_key = fstp_crypto::composite::generate().unwrap();
    let witness_keys = vec![receipt_key.public_key().to_bytes().to_vec()];
    let (handle, server, dbname) = witness(&rt, &control_ca, receipt_key);
    let declaration_key = fstp_crypto::composite::generate().unwrap();
    let declaration_keys = vec![declaration_key.public_key().to_bytes().to_vec()];
    handle
        .accept_declarations(&control_ca.der, declaration_keys.clone())
        .unwrap();

    // The cell, registered at provisioning.
    let cell_ca = Ca::new("saas-declare cell CA");
    let anchor = fstp_crypto::composite::generate().unwrap();
    let id = fstp_audit::CellId(CELL.0);
    rt.block_on(handle.register_cell(
        id,
        &cell_ca.der,
        &[(ChainId::App, anchor.public_key().to_bytes().to_vec())],
    ))
    .unwrap();
    let (cert, key) = cell_ca.issue(CertKind::Client, "cell", Some("cell-witness"), &[]);
    let cfg = fstp_tls::ClientConfig::mutual(&pem_cert(&control_ca.der), &cert, &key).unwrap();
    let stream = rt
        .block_on(async {
            let tcp = rt.connect_tcp(handle.local_addr()).await?;
            fstp_tls::connect(&cfg, WITNESS_HOST, tcp).await
        })
        .unwrap();
    let mut cell = Cell {
        id,
        anchor,
        rows: Vec::new(),
        anchors: Vec::new(),
        stream,
        at: 1_000,
    };
    for k in [2, 1, 2] {
        assert!(matches!(cell.commit(&rt, k), WireReply::Receipt(_)));
    }
    let tail = cell.rows.clone();
    let tail_anchors = cell.anchors.clone();

    // The restore to row 3: the witness log stays.
    cell.rows.retain(|r| r.row.n <= 3);
    cell.anchors.retain(|a| a.anchor.n <= 3);
    let anchor_keys = vec![cell.anchor.public_key().to_bytes().to_vec()];
    let view_of = |cell: &Cell, log: &[WitnessRecord]| {
        let v = ChainView {
            cell: cell.id,
            chain: ChainId::App,
            rows: &cell.rows,
            ledger: &[],
            anchors: &cell.anchors,
            witness: log,
            anchor_keys: &anchor_keys,
            witness_keys: &witness_keys,
        };
        verify_with_declaration_keys(&v, &declaration_keys)
    };
    let log = cell.log(&rt);
    assert!(matches!(
        view_of(&cell, &log),
        Err(fstp_audit::AuditError::Tamper(
            fstp_audit::Tamper::Truncated { .. }
        ))
    ));

    // Two operators approve the restore once, as a batch.
    let head = cell.head();
    let app_head = (head.0, head.1.0);
    let vault_head = (0, fstp_audit::chain::genesis(id, ChainId::Vault).0);
    let jobs = declare_restore_jobs(CELL, JOB, app_head, vault_head);
    let mut book = ApprovalBook::default();
    let batch = declare_restore_batch(CELL, JOB, app_head, vault_head).unwrap();
    assert_eq!(batch.digests().len(), 2);
    book.approve(staff(1), &jobs[0], now_s()).unwrap();
    assert_eq!(
        book.take(staff(1), &jobs[0], now_s()).unwrap_err(),
        ControlError::ApprovalRequired,
        "one operator does not declare"
    );
    book.approve(staff(2), &jobs[0], now_s()).unwrap();
    let approved = book.take(staff(1), &jobs[0], now_s()).unwrap();

    // fstp-control declares through its control-witness certificate.
    let (ccert, ckey) = control_ca.issue(
        CertKind::Client,
        "fstp-control",
        Some("control-witness"),
        &[],
    );
    let control = TlsRestoreWitness::new(
        rt.clone(),
        handle.local_addr(),
        WITNESS_HOST,
        &pem_cert(&control_ca.der),
        &ccert,
        &ckey,
    )
    .unwrap();
    let d = rt
        .block_on(declare_restore(
            &approved,
            &declaration_key,
            &control,
            &witness_keys,
        ))
        .unwrap();
    assert_eq!(d.fields.lost(), Some((4, 5)));
    assert_eq!(
        server
            .psql(&dbname, "SELECT count(*) FROM witness.declaration")
            .unwrap(),
        "1"
    );

    // The cell's verifier, with the declaration key pinned, starts it.
    let log = cell.log(&rt);
    let v = view_of(&cell, &log).unwrap();
    let lost = LostInRestore {
        from: 4,
        to: 5,
        job: JOB,
    };
    assert_eq!(v.lost_in_restore, vec![lost]);
    // A verifier with no key pinned reads it as the self-hosted rule does.
    let plain = verify(&ChainView {
        cell: cell.id,
        chain: ChainId::App,
        rows: &cell.rows,
        ledger: &[],
        anchors: &cell.anchors,
        witness: &log,
        anchor_keys: &anchor_keys,
        witness_keys: &witness_keys,
    })
    .unwrap();
    assert_eq!(plain.lost_in_restore, vec![lost]);
    // A verifier pinning another declaration key refuses the declaration.
    let stranger = vec![
        fstp_crypto::composite::generate()
            .unwrap()
            .public_key()
            .to_bytes()
            .to_vec(),
    ];
    let v = ChainView {
        cell: cell.id,
        chain: ChainId::App,
        rows: &cell.rows,
        ledger: &[],
        anchors: &cell.anchors,
        witness: &log,
        anchor_keys: &anchor_keys,
        witness_keys: &witness_keys,
    };
    assert_eq!(
        verify_with_declaration_keys(&v, &stranger),
        Err(fstp_audit::AuditError::Tamper(
            fstp_audit::Tamper::BadSignature { n: 3 }
        ))
    );

    // The lost tail extends nothing; the restored chain grows.
    let lost_tail = {
        let last = tail_anchors.last().unwrap();
        let prev = tail_anchors[tail_anchors.len() - 2].anchor.n;
        let prev_link = tail[usize::try_from(prev).unwrap() - 1].link;
        Prepare {
            prev: (prev, prev_link),
            stored_hashes: tail[usize::try_from(prev).unwrap()..]
                .iter()
                .map(|r| r.row.stored_hash)
                .collect(),
            anchor: last.anchor.clone(),
        }
    };
    assert_eq!(
        cell.ask(
            &rt,
            &WireRequest::Message(WitnessMessage::Prepare(lost_tail))
        ),
        WireReply::Refused
    );
    assert!(matches!(cell.commit(&rt, 1), WireReply::Receipt(_)));
    let log = cell.log(&rt);
    let v = view_of(&cell, &log).unwrap();
    assert_eq!(v.rows, 4);
    assert_eq!(v.lost_in_restore, vec![lost], "the finding stays");
}
