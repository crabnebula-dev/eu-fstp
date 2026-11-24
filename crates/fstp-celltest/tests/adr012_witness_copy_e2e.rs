//! Lane m10/witness-copy (ADR-012 and ADR-028 records of the lane,
//! decided by Daniel on 2026-11-24: backup is mission critical): the copy
//! of the local witness store and its rebuild after its loss, over local
//! PostgreSQL 16 and the real binaries, in a temporary root.
//!
//! `fstp-admin setup` stands the host up with `"backup"` against the
//! in-process fake S3 of lane L10, and runs the first witness copy. The
//! first admin's creation is audited, so the witness store holds records
//! of the App and the Vault chains by then. The test copies the store
//! with `fstp-admin witness-copy`, as the timer does every minute, and
//! checks that `status` and the host status file show the copy. A base
//! backup follows, and the drill must pass its witness step. Then the
//! services stop, the local witness store is deleted, and `fstp-admin
//! restore` must rebuild it byte for byte before the witness starts. The
//! witness loads it and recomputes every link, and the cell and the vault
//! check their chains against it at start, so every service running
//! afterwards shows that every record came back. Last, a witness store
//! that differs from its copies stops the restore with the databases
//! unchanged.
//!
//! The host runs in `direct` mode with the custody simulator in place of
//! `fstp-keyd`, as in `adr012_backup_health_e2e.rs`. Direct mode has no
//! timers, so the test runs the timer's command itself. Every value is
//! synthetic.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code"
)]

#[path = "../../fstp-backup/tests/support/fake_s3.rs"]
mod fake_s3;

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fstp_admin::layout::{Cluster, Layout};
use fstp_obs::drill_status;
use fstp_obs::host_status::{self, WalArchive};
use fstp_rt::tokio::TokioRuntime;

use fake_s3::FakeS3;

const AK: &str = "WCACCESSKEY0001";
const SK: &str = "witness-copy/secret+key=0123";
const REGION: &str = "gra";
const BUCKET: &str = "fstp-wc-backups";

fn bin(name: &str) -> PathBuf {
    fstp_celltest::world_host::bin_path(name).unwrap_or_else(|e| {
        panic!(
            "{e:?}: build it first: cargo build -p fstp-admin -p fstp-cell -p fstp-vault \
             -p fstp-witness -p fstp-edge -p fstp-backup --bins, -p fstp-control --bin \
             fstp-pgagent and -p fstp-celltest --bin fstp-custody-sim"
        )
    })
}

fn pg_bin() -> PathBuf {
    if let Some(d) = std::env::var_os("FSTP_PG_BIN") {
        return PathBuf::from(d);
    }
    let out = Command::new("pg_config").arg("--bindir").output().unwrap();
    PathBuf::from(String::from_utf8(out.stdout).unwrap().trim())
}

/// A base port with the ten ports above it, and the drill ports 100
/// above those, free; and a public port.
fn ports() -> (u16, u16) {
    for _ in 0..200 {
        let r = fstp_crypto::random_array::<2>().unwrap();
        let base = 20_000 + u16::from_be_bytes(r) % 20_000;
        let held: Vec<_> = (0..11u16)
            .chain(106..108)
            .map(|i| TcpListener::bind((Ipv4Addr::LOCALHOST, base + i)))
            .collect();
        if held.iter().all(Result::is_ok) {
            return (base, base + 10);
        }
    }
    panic!("no free port range");
}

struct Host {
    root: PathBuf,
    config: PathBuf,
}

impl Host {
    fn admin(&self, args: &[&str]) -> Output {
        Command::new(bin("fstp-admin"))
            .arg("--config")
            .arg(&self.config)
            .args(args)
            .env("FSTP_DEPLOYMENT_MODE", "development")
            .output()
            .unwrap()
    }

    fn text(out: &Output) -> String {
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    }

    fn logs(&self) -> String {
        let mut s = String::new();
        for dir in ["state/admin/logs", "state/drill"] {
            if let Ok(rd) = std::fs::read_dir(self.root.join(dir)) {
                for e in rd.flatten() {
                    let text = std::fs::read_to_string(e.path()).unwrap_or_default();
                    let tail: Vec<&str> = text.lines().rev().take(40).collect();
                    s.push_str(&format!("--- {}\n", e.path().display()));
                    for l in tail.into_iter().rev() {
                        s.push_str(l);
                        s.push('\n');
                    }
                }
            }
        }
        s
    }

    fn expect_ok(&self, args: &[&str]) -> String {
        let out = self.admin(args);
        let text = Self::text(&out);
        assert!(
            out.status.success(),
            "fstp-admin {args:?} exited {:?}:\n{text}\n{}",
            out.status.code(),
            self.logs()
        );
        text
    }

    fn layout(&self) -> Layout {
        let bytes = std::fs::read(&self.config).unwrap();
        Layout::new(fstp_admin::config::decode(&bytes).unwrap())
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        let _ = self.admin(&["stop"]);
        if !std::thread::panicking() {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
}

fn link(from: &Path, to: &Path) {
    std::os::unix::fs::symlink(from, to).unwrap();
}

fn host(s3_port: u16) -> Host {
    let tag = fstp_crypto::random_array::<4>().unwrap();
    // A Unix socket path must stay short, so the root sits under /tmp.
    let root = PathBuf::from(format!("/tmp/fstp-wc-{}", fstp_admin::pki::hex(&tag)));
    let bins = root.join("bin");
    std::fs::create_dir_all(&bins).unwrap();
    for name in [
        "fstp-admin",
        "fstp-cell",
        "fstp-vault",
        "fstp-witness",
        "fstp-edge",
        "fstp-pgagent",
        "fstp-control",
        "fstp-backup",
    ] {
        link(&bin(name), &bins.join(name));
    }
    let share = root.join("share/migrations");
    std::fs::create_dir_all(&share).unwrap();
    let crates = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .canonicalize()
        .unwrap();
    link(
        &crates.join("fstp-pgstore/migrations/app"),
        &share.join("app"),
    );
    link(
        &crates.join("fstp-vault/migrations/vault"),
        &share.join("vault"),
    );
    let etc = root.join("etc");
    std::fs::create_dir_all(&etc).unwrap();
    std::fs::write(etc.join("mail.password"), "synthetic-relay-password\n").unwrap();
    std::fs::write(etc.join("s3-access-key"), AK).unwrap();
    std::fs::write(etc.join("s3-secret-key"), SK).unwrap();
    // The fake's CA, where each object store client reads it: the two
    // backup agents, and the cell and vault for their keystore snapshots.
    for dir in ["backup-app", "backup-vault", "cell", "vault"] {
        std::fs::create_dir_all(etc.join(dir)).unwrap();
        std::fs::write(etc.join(dir).join("s3-ca.pem"), fake_s3::CA_PEM).unwrap();
    }
    let (base, public) = ports();
    let config = etc.join("fstp.json");
    let text = format!(
        r#"{{
  "domain": "grants.wc.example.eu",
  "operator_email": "admin@bh.example.eu",
  "mail": {{"relay": "smtp.wc.example.eu", "username": "cell"}},
  "backup": {{"endpoint": "localhost", "port": {s3_port}, "region": "{REGION}",
             "bucket": "{BUCKET}", "access_key_file": "{ak}", "secret_key_file": "{sk}"}},
  "paths": {{
    "bin": "{bin}",
    "share": "{share}",
    "etc": "{etc}",
    "state": "{state}",
    "pg_bin": "{pg}",
    "token_dir": "{tokens}"
  }},
  "ports": {{"public": {public}, "base": {base}}},
  "services": "direct",
  "custody_simulator": "{sim}"
}}
"#,
        ak = etc.join("s3-access-key").display(),
        sk = etc.join("s3-secret-key").display(),
        bin = bins.display(),
        share = root.join("share").display(),
        etc = etc.display(),
        state = root.join("state").display(),
        pg = pg_bin().display(),
        tokens = root.join("tokens").display(),
        sim = bin("fstp-custody-sim").display(),
    );
    std::fs::write(&config, text).unwrap();
    Host { root, config }
}

fn host_file(l: &Layout) -> host_status::HostStatus {
    host_status::decode(&std::fs::read(l.host_status()).unwrap()).unwrap()
}

/// The files of the witness store, by name.
fn store_files(dir: &Path) -> BTreeMap<String, Vec<u8>> {
    std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| {
            (
                e.file_name().to_str().unwrap().to_owned(),
                std::fs::read(e.path()).unwrap(),
            )
        })
        .collect()
}

/// I-24, ADR-012 record of lane m10/witness-copy (items 1 to 4), ADR-028
/// record of the lane, R-CR-01 and F-043 (the copies are sealed and bound
/// to their file and offset): every witness record leaves the host, the
/// status shows it, the drill checks it, and after the loss of the local
/// store `fstp-admin restore` brings back every record before the witness
/// starts, so the witness, the vault and the cell all start over it.
#[test]
fn i24_adr012_wc_witness_copy_and_rebuild_over_real_postgres() {
    let rt = TokioRuntime::new_multi_thread(2).unwrap();
    let s3 = FakeS3::start(&rt, AK, SK, REGION, BUCKET);
    let h = host(s3.port());
    let first = h.expect_ok(&["setup"]);
    assert!(first.contains("Setup is complete."), "{first}");
    assert!(
        first.contains("done     every whole witness record is in each object store"),
        "setup runs the first copy: {first}"
    );
    let l = h.layout();
    let store = l.witness_store();

    // The audited activity of setup reached the witness: the registry and
    // at least one chain file hold records.
    let files = store_files(&store);
    assert!(
        files.get("registry").is_some_and(|b| !b.is_empty()),
        "{:?}",
        files.keys()
    );
    assert!(
        files
            .iter()
            .any(|(n, b)| n.starts_with("chain-") && !b.is_empty()),
        "no chain file: {:?}",
        files.keys()
    );

    // The timer's command copies what is new, and status shows it.
    let copied = h.expect_ok(&["witness-copy"]);
    assert!(
        copied.contains("done     every whole witness record is in each object store"),
        "{copied}"
    );
    let witness_objects = || {
        s3.state
            .objects
            .lock()
            .unwrap()
            .iter()
            .filter(|(k, _)| k.contains("/witness/"))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<BTreeMap<_, _>>()
    };
    let objects = witness_objects();
    assert!(objects.len() >= 2, "{:?}", objects.keys());
    for bytes in objects.values() {
        assert_eq!(&bytes[..4], b"FBC2", "a sealed, signed container");
        assert_eq!(bytes[7], 6, "of the witness kind");
    }
    assert!(
        s3.state.violations.lock().unwrap().is_empty(),
        "{:?}",
        s3.state.violations.lock().unwrap()
    );
    assert_eq!(*s3.state.bad_signatures.lock().unwrap(), 0);
    let status = Host::text(&h.admin(&["status"]));
    assert!(
        status.contains("witness copy  last copied 0 minutes ago"),
        "{status}"
    );
    let file = host_file(&l);
    assert_eq!(file.witness_copy, WalArchive::Ok);
    assert!(file.last_witness_copied.is_some());

    // The drill checks the witness copies against the live store.
    h.expect_ok(&["backup"]);
    let drill = h.expect_ok(&["drill"]);
    assert!(drill.contains("The restore drill passed."), "{drill}");
    assert!(
        drill.contains("the witness copies load and every link recomputes"),
        "{drill}"
    );
    assert_eq!(drill_status::read(&l.admin_dir()).failed, None);

    // The witness stops, the last records are copied, and the local
    // witness store is lost. Key custody keeps running: the custody
    // simulator holds its keys in memory only.
    let stop_witness = || {
        fstp_admin::svc::Manager::new(&l)
            .stop(&fstp_admin::stack::witness(&l))
            .unwrap();
    };
    stop_witness();
    h.expect_ok(&["witness-copy"]);
    let before = store_files(&store);
    std::fs::remove_dir_all(&store).unwrap();

    // `restore` rebuilds it before the witness starts, byte for byte.
    let restored = h.expect_ok(&["restore"]);
    assert!(
        restored.contains("done     the witness store holds every record of its copies"),
        "{restored}"
    );
    assert!(
        restored.contains("checked the witness store: every record loads"),
        "{restored}"
    );
    let after = store_files(&store);
    for (name, bytes) in &before {
        let now = after.get(name).unwrap_or_else(|| panic!("{name} is lost"));
        assert!(
            now.starts_with(bytes),
            "{name}: {} bytes before, {} after",
            bytes.len(),
            now.len()
        );
    }
    // Every service runs over the rebuilt store: the witness loaded it and
    // recomputed every link, and the vault and the cell checked their
    // chains against it at start.
    let status = h.admin(&["status"]);
    let text = Host::text(&status);
    assert!(
        !text.contains("STOPPED") && !text.contains("UNHEALTHY"),
        "{text}\n{}",
        h.logs()
    );
    // The copy resumes from the rebuilt state, with no foreign refusal.
    h.expect_ok(&["witness-copy"]);

    // A store that differs from its copies stops the restore before any
    // database changes, and says what to do.
    stop_witness();
    let registry = store.join("registry");
    let good = std::fs::read(&registry).unwrap();
    let mut changed = good.clone();
    changed[20] ^= 1;
    std::fs::write(&registry, &changed).unwrap();
    let data = l.pg_data(Cluster::App);
    let stamp = std::fs::metadata(&data).unwrap().modified().unwrap();
    let refused = h.admin(&["restore"]);
    let text = Host::text(&refused);
    assert!(!refused.status.success(), "{text}");
    assert!(text.contains("differs from its copies"), "{text}");
    assert_eq!(std::fs::read(&registry).unwrap(), changed, "left as found");
    assert_eq!(
        std::fs::metadata(&data).unwrap().modified().unwrap(),
        stamp,
        "the database was not swapped"
    );
    std::fs::write(&registry, &good).unwrap();
    h.expect_ok(&["start"]);
    s3.stop(&rt);
}
