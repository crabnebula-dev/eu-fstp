//! The guard of the off-host key copies (ADR-004 record of lane
//! `m10/guard-key`, F-018, TH-30, TH-59, I-81, R-NF-09).
//!
//! Decided by Daniel on 2026-11-23 (Q-L16-1, option A): a required second
//! custodian holds one hybrid KEM guard per pilot entry. Each copy is
//! sealed once more to the guard, and every destroy on the pilot entry
//! replaces the guard before its receipt goes out. These tests run the
//! pilot entry over its sockets and the custodian in process, or over
//! mutual TLS on loopback with certificates made here.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code"
)]

mod common;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use common::{Scratch, classify};
use fstp_crypto::hybrid_kem::{CIPHERTEXT_LEN, HybridPublicKey};
use fstp_custody::{
    Aad, Chain, Custody, CustodyError, Epoch, KeydCustody, Refusal, RootLabel, RootRef, SealKey,
    WrappedSealKey,
};
use fstp_keyd::export::{
    HOLD_FILE, export_guarded, import_guarded, import_volume, release_import_guarded,
};
use fstp_keyd::guard::copy::{self, HEADER_LEN};
use fstp_keyd::guard::link::{GuardListener, GuardSetup, TlsGuard};
use fstp_keyd::guard::state::read_state;
use fstp_keyd::guard::store::LocalCustodian;
use fstp_keyd::guard::{GuardClient, GuardEntry, GuardFault, GuardLink, Rotated};
use fstp_keyd::{ClientRole, ClientSocket, KeydError, Passphrase, PassphraseSource};
use fstp_rt::future::block_on;
use zeroize::Zeroizing;

fn pass() -> Passphrase {
    Passphrase::development().expect("development mode in a debug test build")
}

fn label(chain: Chain, epoch: u64) -> RootLabel {
    RootLabel {
        cell: None,
        chain,
        epoch: Epoch(epoch),
    }
}

/// The custodian, shared between the pilot entry and the test, and a
/// switch that makes it unreachable.
#[derive(Clone)]
struct Shared {
    custodian: Arc<LocalCustodian>,
    down: Arc<AtomicBool>,
}

impl Shared {
    fn new(volume: &Path) -> Shared {
        Shared {
            custodian: Arc::new(LocalCustodian::open(volume, &pass()).unwrap()),
            down: Arc::new(AtomicBool::new(false)),
        }
    }

    fn up(&self) -> Result<(), GuardFault> {
        if self.down.load(Ordering::SeqCst) {
            Err(GuardFault::Unreachable)
        } else {
            Ok(())
        }
    }

    fn link(&self) -> GuardLink {
        GuardLink {
            entry: GuardEntry::Cell,
            client: Box::new(self.clone()),
        }
    }
}

impl GuardClient for Shared {
    fn public(&self, entry: GuardEntry) -> Result<(u32, HybridPublicKey), GuardFault> {
        self.up()?;
        self.custodian.public(entry)
    }

    fn rotate(&self, entry: GuardEntry, event: [u8; 16]) -> Result<Rotated, GuardFault> {
        self.up()?;
        self.custodian.rotate(entry, event)
    }

    fn open(
        &self,
        entry: GuardEntry,
        generation: u32,
        header: &[u8; HEADER_LEN],
        ciphertext: &[u8; CIPHERTEXT_LEN],
    ) -> Result<Zeroizing<[u8; 32]>, GuardFault> {
        self.up()?;
        self.custodian.open(entry, generation, header, ciphertext)
    }
}

/// A pilot `fstp-keyd` entry with a console and a cell socket.
struct Pilot {
    scratch: Scratch,
    console: PathBuf,
    cell: PathBuf,
}

impl Pilot {
    fn new(name: &str) -> Pilot {
        let scratch = Scratch::new(name).unwrap_or_else(|e| panic!("{e}"));
        let console = scratch.socket_dir.join("console.sock");
        let cell = scratch.socket_dir.join("cell.sock");
        Pilot {
            scratch,
            console,
            cell,
        }
    }

    fn volume(&self) -> &Path {
        &self.scratch.volume
    }

    /// Starts the entry guarded by `guard`, and returns a console and a
    /// cell client.
    fn start(&self, guard: &Shared) -> (KeydCustody, KeydCustody) {
        let (done, exited) = std::sync::mpsc::channel();
        {
            let sockets = vec![
                ClientSocket::owner_only(&self.console, ClientRole::Console),
                ClientSocket::owner_only(&self.cell, ClientRole::Cell),
            ];
            let volume = self.volume().to_path_buf();
            let link = guard.link();
            std::thread::spawn(move || {
                let r = fstp_keyd::serve_sockets_with_guard(
                    &sockets,
                    &volume,
                    PassphraseSource::Credential,
                    GuardSetup::Pilot(link),
                );
                let _ = done.send(r.map_err(classify));
            });
        }
        wait_for(&[&self.console, &self.cell], &exited);
        (
            KeydCustody::new(&self.console).unwrap(),
            KeydCustody::new(&self.cell).unwrap(),
        )
    }

    fn stop(&self) {
        fstp_keyd::stop(&self.console).unwrap();
    }
}

impl Drop for Pilot {
    fn drop(&mut self) {
        let _ = fstp_keyd::stop(&self.console);
    }
}

fn wait_for<T: std::fmt::Debug>(paths: &[&Path], exited: &std::sync::mpsc::Receiver<T>) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !paths.iter().all(|p| p.exists()) {
        if let Ok(r) = exited.try_recv() {
            panic!("fstp-keyd stopped before binding: {r:?}");
        }
        assert!(Instant::now() < deadline, "fstp-keyd bound no socket");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn create(c: &KeydCustody, chain: Chain, epoch: u64) -> RootRef {
    block_on(c.create_root(label(chain, epoch))).unwrap()
}

fn wrap(c: &KeydCustody, root: &RootRef, n: u8) -> WrappedSealKey {
    block_on(c.wrap(root, &SealKey::from_bytes([n; 32]), &Aad(vec![n]))).unwrap()
}

fn unwrap(
    c: &KeydCustody,
    root: &RootRef,
    w: &WrappedSealKey,
    n: u8,
) -> Result<[u8; 32], CustodyError> {
    block_on(c.unwrap(root, w, &Aad(vec![n]))).map(|k| *k.expose())
}

/// A scratch volume of the custodian.
fn custodian_volume(name: &str) -> Scratch {
    Scratch::new(name).unwrap_or_else(|e| panic!("{e}"))
}

/// F-018, TH-30, I-81: a key copy made before an erasure, its passphrase
/// and a backup of the same age (here a seal key wrapped under the erased
/// epoch) do not open the erased data, once the destroy has replaced the
/// guard. A copy made after the erasure still restores the live state.
#[test]
fn m10_f018_th30_an_old_key_copy_and_an_old_backup_do_not_open_later_erased_data() {
    let cust = custodian_volume("f018-th30-custodian");
    let guard = Shared::new(&cust.volume);
    let a = Pilot::new("f018-th30-a");
    let (console, cell) = a.start(&guard);
    create(&console, Chain::ClusterBackup, 1);
    let app1 = create(&cell, Chain::App, 1);
    // The old backup: a row sealed under the epoch that is erased later.
    let old_row = wrap(&cell, &app1, 0x61);
    a.stop();
    let (_, old_copy) = export_guarded(a.volume(), &pass(), &guard.link()).unwrap();
    assert!(copy::is_guarded(&old_copy));
    assert_eq!(guard.custodian.live_generations(GuardEntry::Cell), vec![1]);

    // The erasure: R(e+1) is created, R(e) destroyed. The destroy answers
    // its receipt only after the custodian replaced the guard.
    let (_, cell) = a.start(&guard);
    let app2 = create(&cell, Chain::App, 2);
    let new_row = wrap(&cell, &app2, 0x62);
    block_on(cell.destroy(&app1)).unwrap();
    assert_eq!(guard.custodian.live_generations(GuardEntry::Cell), vec![2]);
    a.stop();
    let st = read_state(a.volume()).unwrap();
    assert_eq!((st.generation, st.owed), (2, None));

    // The attacker holds the old copy, the passphrase and the old row.
    let b = Pilot::new("f018-th30-b");
    let r = import_guarded(&old_copy, b.volume(), &pass(), Some(&guard.link()));
    assert_eq!(
        r.map(|_| ()),
        Err(KeydError::Guard(GuardFault::Refused(Refusal::Destroyed)))
    );
    assert!(import_volume(&old_copy, b.volume(), &pass()).is_err());
    assert!(
        std::fs::read_dir(b.volume()).unwrap().next().is_none(),
        "a refused import wrote to the volume"
    );

    // A copy made after the erasure restores the live state, and the
    // erased epoch is not in it.
    let (_, new_copy) = export_guarded(a.volume(), &pass(), &guard.link()).unwrap();
    import_guarded(&new_copy, b.volume(), &pass(), Some(&guard.link())).unwrap();
    assert!(b.volume().join(HOLD_FILE).exists());
    release_import_guarded(
        b.volume(),
        &pass(),
        &[(Chain::App, Epoch(2))],
        Some(guard.link()),
    )
    .unwrap();
    let (_, cell) = b.start(&guard);
    assert_eq!(unwrap(&cell, &app2, &new_row, 0x62).unwrap(), [0x62; 32]);
    assert!(
        unwrap(&cell, &app1, &old_row, 0x61).is_err(),
        "an erased row opened"
    );
}

/// F-018, I-81: while the custodian does not answer, a destroy answers no
/// receipt and the guard of the old copies stays owed, so step 7 of the
/// erasure cannot run. Once the custodian answers, the retried destroy
/// replaces the guard and only then answers its receipt.
#[test]
fn m10_f018_i81_an_erasure_is_not_complete_while_the_old_guard_lives() {
    let cust = custodian_volume("f018-i81-custodian");
    let guard = Shared::new(&cust.volume);
    let a = Pilot::new("f018-i81-a");
    let (_, cell) = a.start(&guard);
    let app1 = create(&cell, Chain::App, 1);
    create(&cell, Chain::App, 2);
    assert_eq!(guard.public(GuardEntry::Cell).unwrap().0, 1);

    guard.down.store(true, Ordering::SeqCst);
    for _ in 0..2 {
        assert_eq!(
            block_on(cell.destroy(&app1)),
            Err(CustodyError::Refused(Refusal::GuardPending)),
            "a destroy answered its receipt while the old guard lives"
        );
    }
    assert_eq!(guard.custodian.live_generations(GuardEntry::Cell), vec![1]);
    let owed = read_state(a.volume()).unwrap().owed;
    assert!(owed.is_some(), "no rotation is owed");

    guard.down.store(false, Ordering::SeqCst);
    let receipt = block_on(cell.destroy(&app1)).unwrap();
    assert!(!receipt.0.is_empty());
    assert_eq!(guard.custodian.live_generations(GuardEntry::Cell), vec![2]);
    let st = read_state(a.volume()).unwrap();
    assert_eq!((st.generation, st.owed), (2, None));
}

/// F-018, I-81: a guarded copy does not open without its custodian: not
/// with no custodian, not while it is unreachable, not with another
/// custodian, and not as a plain copy. Nothing is written to the volume.
#[test]
fn m10_f018_a_key_copy_does_not_open_without_the_custodian() {
    let cust = custodian_volume("f018-nocust-custodian");
    let guard = Shared::new(&cust.volume);
    let other_volume = custodian_volume("f018-nocust-other");
    let other = Shared::new(&other_volume.volume);
    let a = Pilot::new("f018-nocust-a");
    let (console, _) = a.start(&guard);
    create(&console, Chain::ClusterBackup, 1);
    a.stop();
    let (_, guarded) = export_guarded(a.volume(), &pass(), &guard.link()).unwrap();
    let b = Pilot::new("f018-nocust-b");
    assert!(import_guarded(&guarded, b.volume(), &pass(), None).is_err());
    assert!(import_volume(&guarded, b.volume(), &pass()).is_err());
    guard.down.store(true, Ordering::SeqCst);
    assert_eq!(
        import_guarded(&guarded, b.volume(), &pass(), Some(&guard.link())).map(|_| ()),
        Err(KeydError::Guard(GuardFault::Unreachable))
    );
    other.public(GuardEntry::Cell).unwrap();
    assert!(import_guarded(&guarded, b.volume(), &pass(), Some(&other.link())).is_err());
    assert!(std::fs::read_dir(b.volume()).unwrap().next().is_none());
    guard.down.store(false, Ordering::SeqCst);
    import_guarded(&guarded, b.volume(), &pass(), Some(&guard.link())).unwrap();
}

// ---------------------------------------------------------------------------
// The link over mutual TLS.

fn b64(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                out.push(char::from(A[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn pem(label: &str, der: &[u8]) -> Vec<u8> {
    let body = b64(der);
    let mut s = format!("-----BEGIN {label}-----\n");
    for line in body.as_bytes().chunks(64) {
        s.push_str(std::str::from_utf8(line).unwrap());
        s.push('\n');
    }
    s.push_str(&format!("-----END {label}-----\n"));
    s.into_bytes()
}

struct TestCa {
    name: String,
    key: fstp_crypto::sig::EcdsaP256KeyPair,
    spki: Vec<u8>,
    pem: Vec<u8>,
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn sign(issuer: &fstp_crypto::sig::EcdsaP256KeyPair, spec: &fstp_pki::cert::CertSpec) -> Vec<u8> {
    let t = fstp_pki::cert::tbs(spec).unwrap();
    let sig = issuer.sign(t.as_der()).unwrap();
    fstp_pki::cert::assemble(&t, &sig).unwrap()
}

impl TestCa {
    fn new(name: &str) -> TestCa {
        use fstp_pki::cert::{CertKind, CertSpec, DistinguishedName, SignatureAlgorithm, Validity};
        let key = fstp_crypto::sig::EcdsaP256KeyPair::generate().unwrap();
        let spki = key.spki_der().unwrap();
        let me = DistinguishedName::new(name);
        let der = sign(
            &key,
            &CertSpec {
                serial: vec![0x41; 16],
                issuer: me.clone(),
                subject: me,
                validity: Validity {
                    not_before: now() - 300,
                    not_after: now() + 86_400,
                },
                spki_der: spki.clone(),
                issuer_key_id: None,
                kind: CertKind::Ca,
                dns_names: Vec::new(),
                ip_addrs: Vec::new(),
                algorithm: SignatureAlgorithm::EcdsaP256Sha256,
            },
        );
        TestCa {
            name: name.to_owned(),
            key,
            spki,
            pem: pem("CERTIFICATE", &der),
        }
    }

    /// A certificate and key for `cn`, PEM.
    fn issue(&self, cn: &str, kind: fstp_pki::cert::CertKind) -> (Vec<u8>, Vec<u8>) {
        use fstp_pki::cert::{CertKind, CertSpec, DistinguishedName, SignatureAlgorithm, Validity};
        let key = fstp_crypto::sig::EcdsaP256KeyPair::generate().unwrap();
        let mut serial = fstp_crypto::random_array::<16>().unwrap().to_vec();
        serial[0] = (serial[0] & 0x7f) | 0x40;
        let der = sign(
            &self.key,
            &CertSpec {
                serial,
                issuer: DistinguishedName::new(&self.name),
                subject: DistinguishedName::new(cn),
                validity: Validity {
                    not_before: now() - 300,
                    not_after: now() + 3_600,
                },
                spki_der: key.spki_der().unwrap(),
                issuer_key_id: Some(fstp_pki::cert::key_identifier(&self.spki).unwrap()),
                kind,
                dns_names: Vec::new(),
                ip_addrs: if kind == CertKind::Server {
                    vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]
                } else {
                    Vec::new()
                },
                algorithm: SignatureAlgorithm::EcdsaP256Sha256,
            },
        );
        (
            pem("CERTIFICATE", &der),
            pem("PRIVATE KEY", &key.pkcs8_der().unwrap()),
        )
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// F-018, R-NF-09, ADR-004 "Certificates": over mutual TLS, the custodian
/// serves only a client certificate of the pilot's CA that names the entry
/// it asks for. A peer of another CA, of another entry, or with another
/// CN cannot ask it to open a copy or to destroy a guard. The right peer
/// still can afterwards, and the guard is unchanged.
#[test]
fn m10_f018_r_nf_09_a_peer_without_the_right_certificate_cannot_open_or_destroy() {
    use fstp_pki::cert::CertKind;
    let cell_ca = TestCa::new("fstp-cell-ca");
    let foreign_ca = TestCa::new("fstp-cell-ca");
    let (server_cert, server_key) = cell_ca.issue("keyd-custodian", CertKind::Server);
    let cust = custodian_volume("f018-tls-custodian");
    let console = cust.socket_dir.join("console.sock");
    let port = free_port();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let listener = GuardListener::new(addr, &cell_ca.pem, &server_cert, &server_key).unwrap();
    let (done, exited) = std::sync::mpsc::channel();
    {
        let sockets = vec![ClientSocket::owner_only(&console, ClientRole::Console)];
        let volume = cust.volume.clone();
        std::thread::spawn(move || {
            let r = fstp_keyd::serve_sockets_with_guard(
                &sockets,
                &volume,
                PassphraseSource::Credential,
                GuardSetup::Custodian(listener),
            );
            let _ = done.send(r.map_err(classify));
        });
    }
    wait_for(&[&console], &exited);
    let client = |ca: &TestCa, cn: &str| {
        let (cert, key) = ca.issue(cn, CertKind::Client);
        TlsGuard::new("127.0.0.1", port, &cell_ca.pem, &cert, &key).unwrap()
    };
    let right = client(&cell_ca, "keyd-guard-cell");
    let deadline = Instant::now() + Duration::from_secs(30);
    let (generation, public) = loop {
        match right.public(GuardEntry::Cell) {
            Ok(g) => break g,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => panic!("the custodian did not answer: {e}"),
        }
    };
    assert_eq!(generation, 1);
    let header = copy::GuardedHeader {
        entry: GuardEntry::Cell,
        generation,
        id: fstp_keyd::export::ExportId([9; 16]),
        created: 1,
    };
    let sealed = copy::seal(&header, &public, b"inner").unwrap();
    let (h, ct, rest) = copy::decode_guarded(&sealed).unwrap();
    let hb = h.encode();

    let wrong = [
        (client(&foreign_ca, "keyd-guard-cell"), None),
        (
            client(&cell_ca, "keyd-guard-vault"),
            Some(Refusal::NotPermitted),
        ),
        (client(&cell_ca, "cell-app"), Some(Refusal::NotPermitted)),
    ];
    for (peer, refusal) in &wrong {
        let want = refusal.map_or(GuardFault::Unreachable, GuardFault::Refused);
        assert_eq!(
            peer.open(GuardEntry::Cell, generation, &hb, &ct)
                .map(|_| ()),
            Err(want)
        );
        assert_eq!(
            peer.rotate(GuardEntry::Cell, [7; 16]).map(|_| ()),
            Err(want)
        );
    }
    assert_eq!(
        right.public(GuardEntry::Cell).unwrap().0,
        1,
        "a wrong peer replaced the guard"
    );
    let kek = right.open(GuardEntry::Cell, generation, &hb, &ct).unwrap();
    assert_eq!(&copy::open(&h, &kek, rest).unwrap()[..], b"inner");
    let rotated = right.rotate(GuardEntry::Cell, [8; 16]).unwrap();
    assert_eq!((rotated.destroyed, rotated.generation), (1, 2));
    assert_eq!(
        right
            .open(GuardEntry::Cell, generation, &hb, &ct)
            .map(|_| ()),
        Err(GuardFault::Refused(Refusal::Destroyed))
    );
    fstp_keyd::stop(&console).unwrap();
}
