//! Lane m10/backup-health (ADR-012 and ADR-028 records of the lane,
//! decided by Daniel on 2026-11-24: backup is mission critical): the
//! whole backup path of a host, over local PostgreSQL 16 and the real
//! binaries, in a temporary root.
//!
//! `fstp-admin setup` stands the host up with `"backup"` against the
//! in-process fake S3 of lane L10 (`fstp-backup/tests/support/fake_s3.rs`,
//! which checks every SigV4 signature on its own). The test then writes a
//! marker row, runs `fstp-admin backup` (`pg_basebackup` through
//! `fstp-backup`), writes a second marker that only the WAL archive
//! carries, switches the WAL and waits until `archive_command` uploaded
//! it. `fstp-admin drill` must pass and leave production as it was, and
//! `status` must show a healthy WAL archive. A restore along the drill's
//! own path must hold both markers. Last, a tampered base backup object
//! must fail the drill at the step `restore`, and the status and the host
//! status file must say so.
//!
//! Lane m10/backup-followups adds: setup publishes each cluster's key
//! file for the second custodian and the services write version 2
//! snapshot key files, and a server certificate renewed after the base
//! backup reaches the drill's restored copy before its server starts.
//!
//! The host runs in `direct` mode with the custody simulator in place of
//! `fstp-keyd`, as in `l19_admin_setup_e2e.rs`. Every value is synthetic.

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

use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use fstp_admin::layout::{Cluster, Layout};
use fstp_obs::drill_status::{self, Step};
use fstp_obs::host_status::{self, WalArchive};
use fstp_rt::tokio::TokioRuntime;

use fake_s3::FakeS3;

const AK: &str = "BHACCESSKEY0001";
const SK: &str = "backup-health/secret+key=0123";
const REGION: &str = "gra";
const BUCKET: &str = "fstp-bh-backups";

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
    let root = PathBuf::from(format!("/tmp/fstp-bh-{}", fstp_admin::pki::hex(&tag)));
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
  "domain": "grants.bh.example.eu",
  "operator_email": "admin@bh.example.eu",
  "mail": {{"relay": "smtp.bh.example.eu", "username": "cell"}},
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

/// Restores the application cluster along the drill's own path into
/// `dir` (`fstp-backup restore`, then the drill server's settings), and
/// returns the marker rows it holds.
fn markers_of_a_restore(h: &Host, l: &Layout, dir: &Path) -> String {
    let out = Command::new(bin("fstp-backup"))
        .env("FSTP_BACKUP_CONFIG", l.config_file("backup-app"))
        .arg("restore")
        .arg(dir)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", Host::text(&out));
    let port = fstp_admin::drill::port(l, Cluster::App);
    let log = std::fs::File::create(h.root.join("check.log")).unwrap();
    let mut server = Command::new(l.pg_bin("postgres"))
        .args(fstp_admin::drill::server_args(dir, port))
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .unwrap();
    let start = Instant::now();
    let rows = loop {
        let ready = fstp_admin::pg::psql_at(
            l,
            Cluster::App,
            port,
            "postgres",
            "SELECT pg_is_in_recovery();",
            "the test",
        );
        if ready.as_deref() == Ok("f") {
            break fstp_admin::pg::psql_at(
                l,
                Cluster::App,
                port,
                "postgres",
                "SELECT string_agg(v, ',' ORDER BY v) FROM bh_marker;",
                "the test",
            )
            .unwrap();
        }
        assert!(
            start.elapsed() < Duration::from_secs(120),
            "the restored copy did not recover: {}",
            std::fs::read_to_string(h.root.join("check.log")).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(500));
    };
    let stop = Command::new(l.pg_bin("pg_ctl"))
        .arg("-D")
        .arg(dir)
        .args(["-m", "fast", "-w", "stop"])
        .output()
        .unwrap();
    assert!(stop.status.success(), "{}", Host::text(&stop));
    let _ = server.wait();
    std::fs::remove_dir_all(dir).unwrap();
    rows
}

fn host_file(l: &Layout) -> host_status::HostStatus {
    host_status::decode(&std::fs::read(l.host_status()).unwrap()).unwrap()
}

/// ADR-012 record of lane m10/backup-health (items 1 to 3), ADR-028
/// record of the lane, ADR-005 (recovery point and time), R-NF-02 (the
/// host status file): a real base backup and WAL archive restore with a
/// row only the WAL carries; the drill passes over them and changes
/// nothing in production; status shows a healthy archive and the drill;
/// a tampered backup fails the drill at the step `restore`.
#[test]
fn adr012_bh_backup_wal_archive_and_drill_over_real_postgres() {
    let rt = TokioRuntime::new_multi_thread(2).unwrap();
    let s3 = FakeS3::start(&rt, AK, SK, REGION, BUCKET);
    let h = host(s3.port());
    let first = h.expect_ok(&["setup"]);
    let setup_done = fstp_obs::snapshot_status::now();
    assert!(first.contains("Setup is complete."), "{first}");
    let l = h.layout();

    // ADR-012 record of lane m10/backup-followups: setup published each
    // cluster's version 2 key file for the second custodian, so no copy
    // is owed, and the services wrote version 2 snapshot key files.
    {
        let objects = s3.state.objects.lock().unwrap();
        let published: Vec<&String> = objects
            .keys()
            .filter(|k| k.ends_with("/keys/cluster-backup.key"))
            .collect();
        assert_eq!(published.len(), 2, "{:?}", objects.keys());
        for k in published {
            assert_eq!(&objects[k][..4], b"FBK1", "{k}");
        }
        for (k, v) in objects.iter() {
            if k.contains("/keystore/") && !k.contains("latest") {
                assert_eq!(&v[..4], b"FBC2", "{k}");
            }
        }
    }
    for c in Cluster::ALL {
        assert!(!fstp_admin::ops::key_copy_owed(&l, c), "{c:?}");
    }
    for (service, name, magic) in [
        ("cell", "cell-snapshot.key", &b"fstp-cell-snapshots-v2"[..]),
        ("vault", "vault-snapshot.key", b"fstp-vault-snapshot-v2"),
    ] {
        let bytes = std::fs::read(l.creds(service).join(name)).unwrap();
        assert_eq!(&bytes[..22], magic, "{service}");
    }

    // A marker before the base backup, one after it that only the WAL
    // archive carries, and the WAL switched and uploaded.
    sql(
        &l,
        Cluster::App,
        "CREATE TABLE bh_marker (v text); INSERT INTO bh_marker VALUES ('before-backup');",
    );
    let backup = h.expect_ok(&["backup"]);
    assert!(
        backup.contains("done     base backup of the app database"),
        "{backup}"
    );
    sql(
        &l,
        Cluster::App,
        "INSERT INTO bh_marker VALUES ('after-backup-wal-only');",
    );
    for c in Cluster::ALL {
        let before = fstp_admin::archive::read(&l, c).unwrap().archived;
        // A switch with no WAL since the last one does nothing.
        sql(
            &l,
            c,
            "CREATE TABLE IF NOT EXISTS bh_tick (v int); INSERT INTO bh_tick VALUES (1);",
        );
        sql(&l, c, "SELECT pg_switch_wal();");
        archived_past(&l, c, before);
    }
    assert!(
        s3.state.violations.lock().unwrap().is_empty(),
        "{:?}",
        s3.state.violations.lock().unwrap()
    );
    assert_eq!(*s3.state.bad_signatures.lock().unwrap(), 0);

    // ADR-012 records of lanes L27 and m10/backup-followups, I-81: the
    // daily keystore snapshot of the cell and of the vault verifies on
    // this host, a minute after the services last started, and status
    // names no failed snapshot. Before lane m10/backup-followups, setup
    // restarted PostgreSQL to turn archiving on after the cell had
    // started, so the cell's store stayed unavailable and every snapshot
    // after setup failed.
    let snaps = wait_for_daily_snapshots(&h, &l, setup_done);
    assert!(
        !snaps.app.failing() && !snaps.vault.failing(),
        "{snaps:?}\n{}",
        h.logs()
    );
    let status = Host::text(&h.admin(&["status"]));
    assert!(
        !status.contains("FAILED: the last keystore snapshot"),
        "{status}"
    );
    for name in ["cell ", "vault"] {
        assert!(
            status.contains(&format!("snapshots  {name} last verified")),
            "{name}: {status}"
        );
    }
    let file = host_file(&l);
    assert!(!file.app_snapshot_failed && !file.vault_snapshot_failed);
    assert!(file.last_app_snapshot.is_some() && file.last_vault_snapshot.is_some());
    assert_ne!(file.next, host_status::Next::KeystoreSnapshot);
    {
        let objects = s3.state.objects.lock().unwrap();
        for owner in ["latest-app", "latest-vault"] {
            let pointer = objects
                .iter()
                .find(|(k, _)| k.ends_with(owner))
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| panic!("no {owner} pointer: {:?}", objects.keys()));
            assert_eq!(&pointer[..4], b"FKP1", "{owner}");
        }
    }

    // ADR-012 record of lane m10/backup-followups, row "TLS files after a
    // restore": the application database's server certificate is renewed
    // after the base backup, so the backup carries the old one, whose key
    // the cell no longer pins (I-83). The drill must put the live files in
    // place, or the cell's keystore check refuses the server.
    let spki_before = fstp_admin::state::State::load(&l.admin_dir().join("state"))
        .unwrap()
        .get("server-spki.app")
        .map(str::to_owned);
    std::fs::remove_file(l.pg_data(Cluster::App).join("tls/server.pem.expires")).unwrap();
    let renew = h.expect_ok(&["renew"]);
    assert!(renew.contains("certificates renewed"), "{renew}");
    let spki_after = fstp_admin::state::State::load(&l.admin_dir().join("state"))
        .unwrap()
        .get("server-spki.app")
        .map(str::to_owned);
    assert!(spki_after.is_some() && spki_after != spki_before);

    // The drill passes and records a duration.
    let drill = h.expect_ok(&["drill"]);
    assert!(drill.contains("The restore drill passed."), "{drill}");
    assert!(
        drill.contains("put the current TLS files into the restored app database"),
        "{drill}"
    );
    assert!(drill.contains("opened the keys of the app copy"), "{drill}");
    assert!(
        drill.contains("opened the keys of the vault copy"),
        "{drill}"
    );
    let st = drill_status::read(&l.admin_dir());
    assert_eq!(st.failed, None, "{st:?}");
    assert!(
        st.last_pass.is_some() && st.seconds.is_some_and(|s| s >= 1),
        "{st:?}"
    );

    // Production is as it was: every service answers, no scratch copy is
    // left, and the drill ports are closed again.
    let status = h.admin(&["status"]);
    let text = Host::text(&status);
    assert_eq!(status.status.code(), Some(0), "{text}\n{}", h.logs());
    assert!(
        !text.contains("STOPPED") && !text.contains("UNHEALTHY"),
        "{text}"
    );
    for c in Cluster::ALL {
        assert!(
            !fstp_admin::drill::root(&l).join(c.name()).exists(),
            "{c:?}"
        );
        assert!(
            TcpListener::bind((Ipv4Addr::LOCALHOST, fstp_admin::drill::port(&l, c))).is_ok(),
            "the drill port of {c:?} is still taken"
        );
    }

    // The WAL archive row is healthy, and the drill shows.
    for c in ["app  ", "vault"] {
        assert!(
            text.contains(&format!("wal archive  {c} last change saved")),
            "{c}: {text}"
        );
    }
    assert!(
        !text.contains("FAILING") && !text.contains("LATE"),
        "{text}"
    );
    assert!(
        text.contains("restore drill  last passed 0 days ago"),
        "{text}"
    );
    let file = host_file(&l);
    assert_eq!(file.wal_archive, WalArchive::Ok);
    assert!(file.last_wal_archived.is_some());
    assert_eq!(file.drill_step, None);
    assert!(file.last_drill_passed.is_some() && file.drill_seconds.is_some());

    // A restore along the drill's path holds the row only the WAL carried.
    let rows = markers_of_a_restore(&h, &l, &h.root.join("check"));
    assert_eq!(rows, "after-backup-wal-only,before-backup");

    // A tampered base backup fails the drill at the step `restore`, and
    // status and the host status file say so.
    {
        let mut objects = s3.state.objects.lock().unwrap();
        let mut tampered = 0;
        for (key, bytes) in objects.iter_mut() {
            if key.contains("/base/") {
                let last = bytes.len() - 1;
                bytes[last] ^= 0x01;
                tampered += 1;
            }
        }
        assert!(
            tampered >= 2,
            "the base backup objects: {:?}",
            objects.keys()
        );
    }
    let failed = h.admin(&["drill"]);
    let text = Host::text(&failed);
    assert!(!failed.status.success(), "{text}");
    assert!(text.contains("The restore drill FAILED"), "{text}");
    let st = drill_status::read(&l.admin_dir());
    assert_eq!(st.failed, Some(Step::Restore), "{st:?}");
    assert!(st.last_pass.is_some(), "the last pass stays");
    assert!(!fstp_admin::drill::root(&l).join("app").exists());
    let status = Host::text(&h.admin(&["status"]));
    assert!(
        status.contains("restore drill  FAILED: fstp-backup restore failed"),
        "{status}"
    );
    let file = host_file(&l);
    assert_eq!(file.drill_step, Some(Step::Restore));
    // `restore_drill` is the next word once the earlier steps are done;
    // this host still waits on its web admins, which come first (ADR-028
    // "Status"). The order is tested in `fstp_admin::status`.
    let mut f = fstp_admin::status::Findings {
        setup_done: true,
        all_running: true,
        route_current: Some(true),
        backups: true,
        backup_age_hours: Some(0),
        admins: vec!["a".into(), "b".into()],
        verified: 2,
        keys_copied: true,
        snapshot_age_hours: Some(0),
        wal_archive: file.wal_archive,
        drill: st,
        drill_due: st.due(u64::try_from(fstp_admin::pki::now()).unwrap()),
        ..fstp_admin::status::Findings::default()
    };
    assert_eq!(
        fstp_admin::status::next(&f),
        fstp_admin::status::Next::RestoreDrill
    );
    f.drill_due = false;
    assert_eq!(
        fstp_admin::status::next(&f),
        fstp_admin::status::Next::Nothing
    );
    s3.stop(&rt);
}

/// Waits until the cell and the vault each recorded a daily keystore
/// snapshot, verified or failed, at or after `since`, the end of setup,
/// at most three minutes, and returns both status files (ADR-012 record of lane L27, row "Status
/// file").
fn wait_for_daily_snapshots(h: &Host, l: &Layout, since: u64) -> fstp_admin::status::Snapshots {
    let start = Instant::now();
    loop {
        let s = fstp_admin::status::snapshot_status(l);
        let tried = |x: &fstp_obs::snapshot_status::SnapshotStatus| {
            x.last_verified
                .max(x.last_failed)
                .is_some_and(|t| t >= since)
        };
        if tried(&s.app) && tried(&s.vault) {
            return s;
        }
        assert!(
            start.elapsed() < Duration::from_secs(180),
            "no daily keystore snapshot ran: {s:?}\n{}",
            h.logs()
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}
