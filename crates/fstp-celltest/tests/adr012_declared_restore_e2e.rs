//! Lane m10/declared-restore (ADR-012 record of the lane; Daniel decided
//! on 2026-11-24 to build declared restores): a restore to an earlier
//! point over local PostgreSQL 16 and the real binaries, in a temporary
//! root.
//!
//! `fstp-admin setup` stands the host up with `"backup"` against the
//! in-process fake S3 of lane L10, as `adr012_backup_health_e2e.rs` does.
//! The test takes a base backup, notes a time, then records a checked
//! identity in the vault, a receipted Vault chain entry after that time.
//! The WAL is archived past it. `fstp-admin restore --to <time>` then
//! loses that entry. It declares both chains at the witness, and the cell
//! and the vault start. The vault records the lost window as an event of
//! its own chain. The cell raises it from the signed declaration, once, as
//! an `ops.outbox` row of the store's own kind -1 with its event in the App
//! chain. A restart records nothing new.
//!
//! The host runs in `direct` mode with the custody simulator in place of
//! `fstp-keyd`. Every value is synthetic.

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

use std::io::Write as _;
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use fstp_admin::layout::{Cluster, Layout};
use fstp_rt::tokio::TokioRuntime;

use fake_s3::FakeS3;

const AK: &str = "DRACCESSKEY0001";
const SK: &str = "declared-restore/secret+key=0123";
const REGION: &str = "gra";
const BUCKET: &str = "fstp-dr-backups";

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
    let root = PathBuf::from(format!("/tmp/fstp-dr-{}", fstp_admin::pki::hex(&tag)));
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
  "domain": "grants.dr.example.eu",
  "operator_email": "admin@dr.example.eu",
  "mail": {{"relay": "smtp.dr.example.eu", "username": "cell"}},
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

fn sql(l: &Layout, c: Cluster, sql: &str) -> String {
    fstp_admin::pg::psql(l, c, "postgres", sql, "the test")
        .unwrap_or_else(|e| panic!("{sql}: {e:?}"))
}

/// Waits until `archive_command` uploaded more than `before` segments of
/// `c` and none waits, at most two minutes.
fn archived_past(l: &Layout, c: Cluster, before: u64) {
    let start = Instant::now();
    loop {
        let a = fstp_admin::archive::read(l, c);
        if let Some(a) = a
            && a.archived > before
            && a.oldest_waiting.is_none()
            && !a.failing()
        {
            return;
        }
        assert!(
            start.elapsed() < Duration::from_secs(120),
            "the WAL of {c:?} was not archived: {a:?}"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// The superuser's answer to `q` in the cell database of `c`.
fn in_db(l: &Layout, c: Cluster, cell: &[u8; 16], q: &str) -> String {
    fstp_admin::pg::psql(l, c, &fstp_admin::pg::dbname(c, cell), q, "the test")
        .unwrap_or_else(|e| panic!("{q}: {e:?}"))
}

/// `fstp-admin restore --to <time>`, answering `yes`.
fn restore_to(h: &Host, time: &str) -> Output {
    let mut child = Command::new(bin("fstp-admin"))
        .arg("--config")
        .arg(&h.config)
        .args(["restore", "--to", time])
        .env("FSTP_DEPLOYMENT_MODE", "development")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"yes\n").unwrap();
    child.wait_with_output().unwrap()
}

/// Waits until `fstp-admin status` shows every service running, at most
/// two minutes.
fn all_running(h: &Host) -> String {
    let start = Instant::now();
    loop {
        let text = Host::text(&h.admin(&["status"]));
        if !text.contains("STOPPED") && !text.contains("UNHEALTHY") {
            return text;
        }
        assert!(
            start.elapsed() < Duration::from_secs(120),
            "a service did not start:\n{text}\n{}",
            h.logs()
        );
        std::thread::sleep(Duration::from_secs(2));
    }
}

/// I-24, ADR-012 record of lane m10/declared-restore: a restore to an
/// earlier point that loses a receipted App chain entry is declared at
/// the witness, the cell and the vault start, and the lost window is
/// recorded once as a finding with its audit event.
#[test]
fn adr012_declared_restore_starts_cell_and_vault_with_the_lost_window_as_a_finding() {
    let rt = TokioRuntime::new_multi_thread(2).unwrap();
    let s3 = FakeS3::start(&rt, AK, SK, REGION, BUCKET);
    let h = host(s3.port());
    let first = h.expect_ok(&["setup"]);
    assert!(first.contains("Setup is complete."), "{first}");
    let l = h.layout();
    let state = fstp_admin::state::State::load(&l.admin_dir().join("state")).unwrap();
    let cell: [u8; 16] = state
        .get("cell")
        .and_then(fstp_admin::witness::unhex)
        .and_then(|b| b.try_into().ok())
        .unwrap();
    h.expect_ok(&["backup"]);
    let app_before = in_db(&l, Cluster::App, &cell, "SELECT count(*) FROM audit.chain");
    let rows_before = in_db(
        &l,
        Cluster::Vault,
        &cell,
        "SELECT count(*) FROM vault_audit.chain",
    );

    // The target time lies after the base backup and before the entry
    // the restore loses.
    std::thread::sleep(Duration::from_secs(2));
    let target = u64::try_from(fstp_admin::pki::now()).unwrap();
    std::thread::sleep(Duration::from_secs(2));
    // A checked identity of a synthetic admin: one receipted Vault chain
    // entry after the target.
    let id = fstp_admin::cellcmd::CheckedIdentity {
        document_type: "passport".to_owned(),
        family_names: "Synthetic".to_owned(),
        given_names: "Restore".to_owned(),
        birth_date: "1990-01-01".to_owned(),
        issuing_state: "DEU".to_owned(),
    };
    fstp_admin::cellcmd::verify_first_admin_file(
        &l,
        "0123456789abcdef0123456789abcdef",
        id.json().as_bytes(),
    )
    .unwrap_or_else(|e| panic!("a checked identity: {e:?}\n{}", h.logs()));
    let rows_after = in_db(
        &l,
        Cluster::Vault,
        &cell,
        "SELECT count(*) FROM vault_audit.chain",
    );
    assert_ne!(
        rows_before, rows_after,
        "the checked identity wrote no chain row"
    );
    h.expect_ok(&["start"]);
    for c in Cluster::ALL {
        let before = fstp_admin::archive::read(&l, c).unwrap().archived;
        sql(
            &l,
            c,
            "CREATE TABLE IF NOT EXISTS dr_tick (v int); INSERT INTO dr_tick VALUES (1);",
        );
        sql(&l, c, "SELECT pg_switch_wal();");
        archived_past(&l, c, before);
    }

    // The restore loses the entry, declares both chains, and starts the
    // cell and the vault.
    let out = restore_to(&h, &fstp_admin::pitr::format_time(target));
    let text = Host::text(&out);
    assert!(out.status.success(), "{text}\n{}", h.logs());
    assert!(
        text.contains("Tenant admins see it on the System page"),
        "{text}"
    );
    assert!(
        text.contains("declared the restore of both audit logs at the witness"),
        "{text}"
    );
    all_running(&h);
    let restored = in_db(
        &l,
        Cluster::Vault,
        &cell,
        "SELECT count(*) FROM vault_audit.chain",
    );
    let app_after = in_db(&l, Cluster::App, &cell, "SELECT count(*) FROM audit.chain");
    let lost: u64 = rows_after.parse::<u64>().unwrap() - rows_before.parse::<u64>().unwrap();
    assert!(lost >= 1);
    let findings = || {
        in_db(
            &l,
            Cluster::App,
            &cell,
            "SELECT count(*) FROM ops.outbox WHERE kind = -1",
        )
    };
    assert_eq!(
        findings(),
        "1",
        "one lost window of the Vault chain, raised by the cell"
    );
    assert_eq!(
        restored,
        (rows_before.parse::<u64>().unwrap() + 1).to_string(),
        "the restored Vault chain and the vault's own event of the window"
    );
    assert_eq!(
        in_db(
            &l,
            Cluster::Vault,
            &cell,
            "SELECT count(*) FROM vault_audit.chain WHERE kind = 2"
        ),
        "1"
    );
    assert!(
        app_after.parse::<u64>().unwrap() > app_before.parse::<u64>().unwrap(),
        "the cell's event of the window: {app_before} then {app_after}"
    );

    // A restart of the cell and the vault records nothing new, and every
    // service runs. The custody simulator keeps its roots in memory, so
    // the test restarts these two services only.
    let m = fstp_admin::svc::Manager::new(&l);
    m.stop(&fstp_admin::stack::cell(&l)).unwrap();
    m.stop(&fstp_admin::stack::vault(&l)).unwrap();
    h.expect_ok(&["start"]);
    all_running(&h);
    assert_eq!(findings(), "1", "a restart recorded the window again");
    s3.stop(&rt);
}
