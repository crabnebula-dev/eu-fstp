//! The local witness of a self-hosted install over its append-only file
//! store (I-24, ADR-010 "Self-hosted witness", Q9 A). Lane F-SELF.
//!
//! Each test starts `fstp_witness::serve_local` over a fresh directory,
//! registers one cell CA and anchor key, and speaks the framed protocol
//! of `fstp_witness::wire` over a real TLS 1.3 connection with a
//! `cell-witness` client certificate.
//!
//! Scope of the self-hosted I-24 claim (ADR-010 open point 7, Daniel,
//! 2026-11-13): the local witness detects a change or a deletion by any
//! database role and by the database owner. A root user on the cell node
//! can change both the database and the witness file store, so that is
//! outside what the local witness detects. Only the optional external
//! bucket would detect it. These tests change the file store as a writer
//! that is not root would have to: they show that the witness never
//! serves over a store that was changed behind it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
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
use fstp_witness::file_store::{chain_file_name, decode_file_store, load_file_store};
use fstp_witness::wire::{
    WireReply, WireRequest, decode_reply, encode_request, read_frame, write_frame,
};
use fstp_witness::{LocalWitnessParts, WitnessHandle, WitnessMessage, serve_local};

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
// A local witness over a fresh directory.

const WITNESS_HOST: &str = "witness.selfhosted.test";

static NEXT: AtomicU32 = AtomicU32::new(0);

/// A fresh directory for one witness store, removed when dropped.
struct StoreDir(PathBuf);

impl StoreDir {
    fn new() -> StoreDir {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let tag: String = fstp_crypto::random_array::<6>()
            .unwrap()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let dir = std::env::temp_dir().join(format!(
            "fstp-witness-file-{}-{n}-{tag}",
            std::process::id()
        ));
        StoreDir(dir)
    }
}

impl Drop for StoreDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Setup {
    rt: TokioRuntime,
    witness: WitnessHandle<TokioRuntime>,
    dir: StoreDir,
    install_ca: Ca,
    receipt_key: Vec<u8>,
    receipt_key_public: Vec<u8>,
}

fn start_at(
    rt: &TokioRuntime,
    dir: &Path,
    install_ca: &Ca,
    receipt_key: &[u8],
) -> Result<WitnessHandle<TokioRuntime>, fstp_witness::WitnessError> {
    let (chain, key_pem) = install_ca.issue(CertKind::Server, WITNESS_HOST, None, &[WITNESS_HOST]);
    rt.block_on(serve_local(
        rt.clone(),
        LocalWitnessParts {
            dir: dir.to_path_buf(),
            receipt_key: CompositeSigningKey::from_bytes(receipt_key).unwrap(),
            server_chain_pem: chain,
            server_key_pem: key_pem,
            listen: SocketAddr::from(([127, 0, 0, 1], 0)),
        },
    ))
}

fn setup() -> Setup {
    let rt = TokioRuntime::new_multi_thread(2).unwrap();
    let dir = StoreDir::new();
    let install_ca = Ca::new("self-hosted install CA");
    let key = fstp_crypto::composite::generate().unwrap();
    let receipt_key_public = key.public_key().to_bytes().to_vec();
    let receipt_key = key.to_bytes().unwrap().to_vec();
    let witness = start_at(&rt, &dir.0, &install_ca, &receipt_key).unwrap();
    Setup {
        rt,
        witness,
        dir,
        install_ca,
        receipt_key,
        receipt_key_public,
    }
}

impl Setup {
    /// Stops the witness and starts another over the same store.
    fn restart(&mut self) -> Result<(), fstp_witness::WitnessError> {
        self.rt
            .block_on(self.witness.shutdown(Duration::from_secs(10)))
            .unwrap();
        self.witness = start_at(&self.rt, &self.dir.0, &self.install_ca, &self.receipt_key)?;
        Ok(())
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

    fn chain_file(&self, s: &Setup) -> PathBuf {
        s.dir.0.join(chain_file_name(self.id, ChainId::App))
    }
}

/// A connection with a client certificate of `ou` from `ca`.
struct Conn {
    stream: fstp_tls::TlsStream<<TokioRuntime as fstp_rt::Runtime>::Tcp>,
}

impl Conn {
    fn open(s: &Setup, ca: &Ca, ou: &str) -> std::io::Result<Conn> {
        let (cert, key) = ca.issue(CertKind::Client, "cell", Some(ou), &[]);
        let roots = pem_cert(&s.install_ca.der);
        let cfg = fstp_tls::ClientConfig::mutual(&roots, &cert, &key).unwrap();
        let addr = s.witness.local_addr();
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

    fn message(&mut self, s: &Setup, m: WitnessMessage) -> WireReply {
        self.ask(s, &WireRequest::Message(m)).unwrap()
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

fn log_of(c: &mut Conn, s: &Setup, cell: &Cell) -> WireReply {
    c.ask(
        s,
        &WireRequest::Log {
            cell: cell.id,
            chain: ChainId::App,
        },
    )
    .unwrap()
}

/// Writes the prepare, abort, prepare sequence of the restart tests and
/// returns the second prepare's head.
fn three_records(s: &Setup, cell: &Cell) -> (u64, Link) {
    let mut c = Conn::open(s, &cell.ca, "cell-witness").unwrap();
    let g = (0, genesis(cell.id, ChainId::App));
    let p1 = prepare(cell, g, [1; 32]);
    assert!(matches!(
        c.message(s, WitnessMessage::Prepare(p1.clone())),
        WireReply::Receipt(_)
    ));
    assert_eq!(
        c.message(
            s,
            WitnessMessage::Abort {
                cell: cell.id,
                chain: ChainId::App,
                n: p1.anchor.n,
                link: p1.anchor.link,
            }
        ),
        WireReply::Recorded
    );
    let p2 = prepare(cell, g, [2; 32]);
    let WireReply::Receipt(r2) = c.message(s, WitnessMessage::Prepare(p2)) else {
        panic!("the re-prepare was refused");
    };
    assert_eq!(r2.fields.witness_seq, 3);
    (r2.fields.n, r2.fields.link)
}

// ---------------------------------------------------------------------------
// Tests.

/// I-24, ADR-010 "Self-hosted witness" and "Prepare, receipt, commit": a
/// prepare from the chain's writer is appended to the cell's chain file
/// before its receipt leaves the local witness. The receipt verifies
/// under the local receipt key. A retransmit gets the same receipt and
/// appends nothing.
#[test]
fn i24_local_witness_stores_each_prepare_before_its_receipt() {
    let s = setup();
    let cell = Cell::new(0x41);
    cell.register(&s);
    let mut c = Conn::open(&s, &cell.ca, "cell-witness").unwrap();
    let p = prepare(&cell, (0, genesis(cell.id, ChainId::App)), [7; 32]);
    let first = c.message(&s, WitnessMessage::Prepare(p.clone()));
    let WireReply::Receipt(rc) = first.clone() else {
        panic!("no receipt: {first:?}");
    };
    assert!(receipt_signature_verifies(
        &rc,
        std::slice::from_ref(&s.receipt_key_public)
    ));
    assert_eq!((rc.fields.n, rc.fields.link), (p.anchor.n, p.anchor.link));
    let file = std::fs::read(cell.chain_file(&s)).unwrap();
    let records = load_file_store(&file).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].witness_seq, rc.fields.witness_seq);
    let again = c.message(&s, WitnessMessage::Prepare(p));
    assert_eq!(again, first, "a retransmit got another receipt");
    assert_eq!(std::fs::read(cell.chain_file(&s)).unwrap(), file);
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

/// I-24, ADR-010 "Abort" and "Start-up": a restarted local witness
/// rebuilds each chain and its registry from its files. The cell reaches
/// it without registering again, and gets the same log and the same
/// outstanding prepare.
#[test]
fn i24_local_witness_rebuilds_after_restart() {
    let mut s = setup();
    let cell = Cell::new(0x42);
    cell.register(&s);
    let head = three_records(&s, &cell);
    let log = {
        let mut c = Conn::open(&s, &cell.ca, "cell-witness").unwrap();
        log_of(&mut c, &s, &cell)
    };
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
    s.restart().unwrap();
    let mut c = Conn::open(&s, &cell.ca, "cell-witness").unwrap();
    assert_eq!(log_of(&mut c, &s, &cell), log);
    assert_eq!(
        c.ask(
            &s,
            &WireRequest::Outstanding {
                cell: cell.id,
                chain: ChainId::App
            }
        )
        .unwrap(),
        WireReply::Outstanding(Some(head))
    );
}

/// I-24 within the self-hosted scope (module documentation): a chain file
/// with a deleted middle record, a changed byte in a stored link, or a
/// cut last record stops the local witness from starting. It never
/// serves over a store that was changed behind it.
#[test]
fn i24_local_witness_refuses_a_changed_store_at_start() {
    let mut s = setup();
    let cell = Cell::new(0x43);
    cell.register(&s);
    three_records(&s, &cell);
    s.rt.block_on(s.witness.shutdown(Duration::from_secs(10)))
        .unwrap();
    let path = cell.chain_file(&s);
    let whole = std::fs::read(&path).unwrap();
    let records = decode_file_store(&whole).unwrap();
    assert_eq!(records.len(), 3);
    let framed = |r: &fstp_witness::FileRecord| 12 + r.bytes.len();
    let first = framed(&records[0]);
    let second = framed(&records[1]);
    let mut deleted = whole[..first].to_vec();
    deleted.extend_from_slice(&whole[first + second..]);
    let mut changed = whole.clone();
    // A byte inside the first record's anchor link: version, tag, the
    // previous head (8 + 32), the row count (4) and one stored hash (32),
    // then the anchor's cell (16), chain (1) and n (8).
    changed[12 + 2 + 40 + 4 + 32 + 16 + 1 + 8] ^= 1;
    let cut = whole[..whole.len() - 1].to_vec();
    for (what, bytes) in [
        ("a deleted middle record", deleted),
        ("a changed link byte", changed),
        ("a cut last record", cut),
    ] {
        std::fs::write(&path, &bytes).unwrap();
        let started = start_at(&s.rt, &s.dir.0, &s.install_ca, &s.receipt_key);
        assert!(started.is_err(), "the witness started over {what}");
    }
    std::fs::write(&path, &whole).unwrap();
    s.witness = start_at(&s.rt, &s.dir.0, &s.install_ca, &s.receipt_key).unwrap();
    let mut c = Conn::open(&s, &cell.ca, "cell-witness").unwrap();
    assert!(matches!(log_of(&mut c, &s, &cell), WireReply::Log(_)));
}

/// ADR-010 "Witnesses", I-90: the local witness takes the App chain from
/// the `cell-witness` certificate only, and refuses an anchor under a key
/// outside the chain's anchor key history. Neither appends a record.
#[test]
fn adr010_local_witness_takes_only_the_chain_writer_and_its_anchor_key() {
    let s = setup();
    let cell = Cell::new(0x44);
    cell.register(&s);
    let p = prepare(&cell, (0, genesis(cell.id, ChainId::App)), [3; 32]);
    let mut vault = Conn::open(&s, &cell.ca, "vault-witness").unwrap();
    assert_eq!(
        vault.message(&s, WitnessMessage::Prepare(p.clone())),
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
        app.message(&s, WitnessMessage::Prepare(forged)),
        WireReply::Refused
    );
    let stored = std::fs::read(cell.chain_file(&s)).unwrap_or_default();
    assert!(load_file_store(&stored).unwrap().is_empty());
}
