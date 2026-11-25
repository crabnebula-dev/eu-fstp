//! Point-in-time restore over a real PostgreSQL (ADR-012 record of lane
//! `m10/backup-pitr`).
//!
//! One scenario, against a test server of `fstp-pgtest` and the in-process
//! fake S3 of lane L10:
//!
//! 1. A base backup through the agent, as the timer runs it. Then row 1,
//!    the target time, and row 2 a second later. The harness plays
//!    `archive_command` for the segments.
//! 2. Restore A to the target. The check run of `fstp-backup` reaches the
//!    target and shuts down without promoting. PostgreSQL then starts on
//!    the directory, reads the prefetched segments from `pg_wal` with a
//!    `restore_command` that fails, stops at the target and promotes onto
//!    timeline 2. A holds row 1 and not row 2.
//! 3. A takes row 3 and archives its history file and its timeline 2
//!    segments.
//! 4. Restore B to the newest point, from the same base backup on
//!    timeline 1: it follows the switch into timeline 2, holds rows 1 and
//!    3 and not 2, and promotes onto timeline 3, above every archived one.
//! 5. Restore C to the old target follows timeline 2 too, and holds row 1.
//! 6. A target after the archive's last change exits as
//!    `TargetNotReached`, which the binary reports with status 3.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

#[path = "support/fake_s3.rs"]
mod fake_s3;
#[path = "support/mem_custody.rs"]
mod mem_custody;

use std::net::{Ipv4Addr, TcpListener};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fstp_backup::agent::{Agent, Archived};
use fstp_backup::{BackupError, config, index, recovery};
use fstp_rt::tokio::TokioRuntime;

use fake_s3::FakeS3;
use mem_custody::MemCustody;

const AK: &str = "PITRACCESSKEY01";
const SK: &str = "pitr/secret+key=abcdef0123";
const REGION: &str = "gra";
const BUCKET: &str = "fstp-pitr-backups";
const DB: &str = "pitr";

fn hex(b: &[u8]) -> String {
    fstp_backup::sigv4::hex(b)
}

fn temp_dir(what: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "fstp-pitr-{what}-{}",
        hex(&fstp_crypto::random_array::<6>().unwrap())
    ));
    std::fs::create_dir_all(&d).unwrap();
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

fn write_private(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Plays `archive_command` for every completed segment of `data` from
/// `from` on, and every history file. Only segments up to the one the
/// switch completed hold WAL; later names are recycled files.
fn archive(
    rt: &TokioRuntime,
    agent: &Agent<TokioRuntime>,
    data: &Path,
    from: &str,
    last: &str,
) -> usize {
    let pg_wal = data.join("pg_wal");
    let mut names: Vec<String> = std::fs::read_dir(&pg_wal)
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| {
            n.ends_with(".history")
                || (fstp_backup::parse_wal_name(n).is_ok()
                    && n.as_str() >= from
                    && n.get(8..).unwrap() <= last.get(8..).unwrap()
                    && n.get(..8) == last.get(..8))
        })
        .collect();
    names.sort();
    let mut uploaded = 0;
    for n in names {
        if rt.block_on(agent.archive(&pg_wal.join(&n), &n)).unwrap() == Archived::Uploaded {
            uploaded += 1;
        }
    }
    uploaded
}

/// A PostgreSQL server over a restored data directory, as in
/// `fstp-celltest/tests/adr012_backup_agent_pg.rs`.
struct Running {
    bindir: PathBuf,
    data: PathBuf,
    port: u16,
}

impl Running {
    fn start(bindir: &Path, data: &Path) -> Running {
        let sock = data.parent().unwrap().join("sock");
        std::fs::create_dir_all(&sock).unwrap();
        let r = Running {
            bindir: bindir.to_path_buf(),
            data: data.to_path_buf(),
            port: free_port(),
        };
        let opts = format!(
            "-c port={} -c unix_socket_directories={} -c archive_mode=off -c logging_collector=off",
            r.port,
            sock.display()
        );
        let log = data.parent().unwrap().join("server.log");
        let out = Command::new(bindir.join("pg_ctl"))
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .arg("-D")
            .arg(data)
            .arg("-l")
            .arg(&log)
            .args(["-w", "-t", "180", "-o", &opts, "start"])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "the restored server did not start: {}",
            std::fs::read_to_string(&log).unwrap_or_default()
        );
        r
    }

    fn psql(&self, server: &fstp_pgtest::PgServer, sql: &str) -> String {
        use std::io::Write as _;
        let mut child = Command::new(self.bindir.join("psql"))
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .env("PGPASSWORD", server.superuser_password())
            .env("PGSSLMODE", "verify-full")
            .env("PGSSLROOTCERT", server.dir().join("tls/ca.pem"))
            .env("PGSSLCERT", server.dir().join("client/fstp_super.pem"))
            .env("PGSSLKEY", server.dir().join("client/fstp_super-key.pem"))
            .args(["-X", "-A", "-t", "-q", "-v", "ON_ERROR_STOP=1"])
            .args(["-h", "127.0.0.1", "-p", &self.port.to_string()])
            .args(["-U", server.superuser(), "-d", DB])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(sql.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "psql on the restored server: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    }

    fn rows(&self, server: &fstp_pgtest::PgServer) -> String {
        self.psql(server, "SELECT string_agg(n::text, ',' ORDER BY n) FROM t;")
    }

    fn timeline(&self, server: &fstp_pgtest::PgServer) -> u32 {
        // The timeline of the current WAL position: a promotion's
        // checkpoint may still run, so pg_control can lag.
        let name = self.psql(server, "SELECT pg_walfile_name(pg_current_wal_lsn());");
        u32::from_str_radix(name.get(..8).unwrap(), 16).unwrap()
    }

    fn stop(&self) {
        let _ = Command::new(self.bindir.join("pg_ctl"))
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .arg("-D")
            .arg(&self.data)
            .args(["-m", "fast", "-w", "stop"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// The restore the binary runs for `restore <dir> [--to <t>]`: the
/// index entries that suit the target, the restore, and the check run.
fn restore(
    rt: &TokioRuntime,
    agent: &Agent<TokioRuntime>,
    custody: &MemCustody,
    cfg: &config::FileConfig,
    data: &Path,
    target: Option<u64>,
) -> Result<fstp_backup::agent::Restored, BackupError> {
    let entries = index::before(&cfg.state_dir, cfg.cluster, target)?;
    let secret = rt.block_on(agent.open_secret(custody)).unwrap();
    let r = rt.block_on(agent.restore_to(&secret, &entries, data, target))?;
    recovery::check(&cfg.pg_bindir, data, target)?;
    Ok(r)
}

/// ADR-012 record of lane `m10/backup-pitr`, items 1 and 2: a restore to
/// a time stops there, a later restore follows the new timeline through
/// the archived history file, each promoted cluster takes a timeline above
/// every archived one, and a target after the archive's end is reported.
#[test]
fn adr012_pitr_restores_to_a_time_and_follows_the_new_timeline() {
    let server = fstp_pgtest::PgServer::shared_named("pitr", "application").unwrap();
    let login = server.create_replication_role("fstp_repl").unwrap();
    server
        .psql("postgres", &format!("CREATE DATABASE {DB}"))
        .unwrap();
    server.psql(DB, "CREATE TABLE t (n int)").unwrap();

    let rt = TokioRuntime::new_multi_thread(2).unwrap();
    let fake = FakeS3::start(&rt, AK, SK, REGION, BUCKET);
    let custody = MemCustody::default();
    let cluster_id = fstp_crypto::random_array::<16>().unwrap();
    let creds = temp_dir("creds");
    let state = temp_dir("state");
    write_private(&creds.join("repl.pem"), &login.cert_pem);
    write_private(&creds.join("repl.key"), &login.key_pem);
    write_private(
        &creds.join("repl.password"),
        format!("{}\n", login.password).as_bytes(),
    );
    write_private(&creds.join("db-ca.pem"), server.server_ca_pem());
    write_private(
        &creds.join("s3-access-key-id"),
        format!("{AK}\n").as_bytes(),
    );
    write_private(
        &creds.join("s3-secret-access-key"),
        format!("{SK}\n").as_bytes(),
    );
    write_private(&creds.join("s3-ca.pem"), fake_s3::CA_PEM);
    let created = rt
        .block_on(fstp_backup::keyfile::create(&custody, cluster_id))
        .unwrap();
    write_private(
        &creds.join(fstp_backup::keyfile::KEY_FILE),
        &created.key_file,
    );
    write_private(
        &creds.join(fstp_backup::writer::WRITER_FILE),
        &created.writer_key,
    );
    let cfg_text = format!(
        r#"{{"cluster": "{}", "credentials_dir": "{}", "state_dir": "{}", "pg_bindir": "{}",
            "database": {{"host": "127.0.0.1", "port": {}}},
            "object_store": {{"endpoint": "localhost", "port": {}, "region": "{REGION}", "bucket": "{BUCKET}"}}}}"#,
        hex(&cluster_id),
        creds.display(),
        state.display(),
        server.bindir().display(),
        server.port(),
        fake.port(),
    );
    let cfg_path = creds.join("backup.json");
    std::fs::write(&cfg_path, cfg_text).unwrap();
    let cfg = config::load_from(&cfg_path).unwrap();
    let agent = Agent::from_config(rt.clone(), &cfg).unwrap();

    // 1. The base backup, row 1, the target, row 2.
    let from = server
        .psql("postgres", "SELECT pg_walfile_name(pg_current_wal_lsn())")
        .unwrap()
        .trim()
        .to_owned();
    let entry = rt.block_on(agent.base_backup(&cfg)).unwrap();
    std::thread::sleep(Duration::from_millis(1100));
    server.psql(DB, "INSERT INTO t VALUES (1)").unwrap();
    std::thread::sleep(Duration::from_millis(1100));
    let target = now_secs();
    assert!(entry.at < target);
    std::thread::sleep(Duration::from_millis(1100));
    server.psql(DB, "INSERT INTO t VALUES (2)").unwrap();
    let last = server
        .psql("postgres", "SELECT pg_walfile_name(pg_switch_wal())")
        .unwrap()
        .trim()
        .to_owned();
    assert!(archive(&rt, &agent, &server.dir().join("data"), &from, &last) >= 1);

    // A target before the base backup finished is refused.
    assert_eq!(
        index::before(&cfg.state_dir, cfg.cluster, Some(entry.at)).unwrap_err(),
        BackupError::Config("target before the oldest base backup")
    );

    // 2. Restore A to the target.
    let base_a = temp_dir("a");
    let data_a = base_a.join("data");
    let r = restore(&rt, &agent, &custody, &cfg, &data_a, Some(target)).unwrap();
    assert_eq!((r.timeline, r.histories), (1, 0));
    assert!(r.segments >= 1);
    assert!(data_a.join("recovery.signal").exists());
    let auto = std::fs::read_to_string(data_a.join("postgresql.auto.conf")).unwrap();
    assert!(
        auto.contains("recovery_target_action = 'promote'"),
        "{auto}"
    );
    let a = Running::start(server.bindir(), &data_a);
    assert_eq!(a.rows(server), "1", "A stops at the target");
    assert_eq!(a.timeline(server), 2, "A promotes onto timeline 2");

    // 3. A takes row 3 and archives its timeline.
    a.psql(server, "INSERT INTO t VALUES (3);");
    let last_a = a.psql(server, "SELECT pg_walfile_name(pg_switch_wal());");
    assert!(last_a.starts_with("00000002"), "{last_a}");
    let a_first = format!(
        "00000002{}",
        r.last_segment.unwrap().file_name().get(8..).unwrap()
    );
    assert!(archive(&rt, &agent, &data_a, &a_first, &last_a) >= 2);
    let after_row_3 = now_secs() + 2;
    a.stop();

    // 4. Restore B to the newest point follows timeline 2.
    let base_b = temp_dir("b");
    let data_b = base_b.join("data");
    let r = restore(&rt, &agent, &custody, &cfg, &data_b, None).unwrap();
    assert_eq!((r.timeline, r.histories), (2, 1));
    assert!(data_b.join("pg_wal/00000002.history").exists());
    let b = Running::start(server.bindir(), &data_b);
    assert_eq!(b.rows(server), "1,3", "B follows timeline 2");
    assert_eq!(b.timeline(server), 3, "B takes a timeline above 2");
    b.stop();

    // 5. Restore C to the old target follows timeline 2 too.
    let base_c = temp_dir("c");
    let data_c = base_c.join("data");
    restore(&rt, &agent, &custody, &cfg, &data_c, Some(target)).unwrap();
    let c = Running::start(server.bindir(), &data_c);
    assert_eq!(c.rows(server), "1");
    assert_eq!(c.timeline(server), 3);
    c.stop();

    // 6. A target after the archive's last change.
    std::thread::sleep(Duration::from_millis(2100));
    let base_d = temp_dir("d");
    let err = restore(
        &rt,
        &agent,
        &custody,
        &cfg,
        &base_d.join("data"),
        Some(after_row_3),
    )
    .unwrap_err();
    assert_eq!(err, BackupError::TargetNotReached);

    fake.stop(&rt);
    for d in [&creds, &state, &base_a, &base_b, &base_c, &base_d] {
        let _ = std::fs::remove_dir_all(d);
    }
}
