//! The production backup agent of `fstp-backup` over a PostgreSQL world
//! (ADR-012, record of lane L10): base backup, WAL archive and restore
//! through the S3 client, into fresh data directories that PostgreSQL
//! then starts on (R-CR-01, I-81, ADR-012 "Restore rule").
//!
//! One scenario runs once per test binary, and each test checks one part
//! of what it found:
//!
//! 1. A world with one cell signs in and runs `erase-text`: two texts are
//!    stored and one is erased before any backup.
//! 2. The agent runs from a configuration file, as the binary does:
//!    `pg_basebackup` of the application cluster over loopback as
//!    `fstp_repl`, sealed to the ClusterBackup key of `cluster-backup.key`
//!    and uploaded to an in-process fake S3 that verifies every SigV4
//!    signature on its own (`fstp-backup/tests/support/fake_s3.rs`).
//! 3. The harness plays `archive_command`: it switches the WAL and hands
//!    each completed segment since the backup to `Agent::archive`.
//!    Restore A goes into a fresh data directory.
//! 4. `erase-text` again erases the text that was live at the backup, and
//!    the WAL is archived again. Restore B follows.
//! 5. PostgreSQL starts on each restored directory and replays the
//!    fetched segments. The ledger head of each copy is read back, and the
//!    keystore of each copy is loaded from its tables over the keys login.
//!
//! Custody for the key file is an in-memory stand-in for the `fstp-keyd`
//! console socket (`fstp-backup/tests/support/mem_custody.rs`). The texts'
//! own keys live in the world's custody, as in production.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
#![allow(clippy::too_many_arguments)]

#[path = "../../fstp-backup/tests/support/fake_s3.rs"]
mod fake_s3;
#[path = "../../fstp-backup/tests/support/mem_custody.rs"]
mod mem_custody;

use std::net::{Ipv4Addr, TcpListener};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, OnceLock};

use fstp_backup::agent::{Agent, Archived};
use fstp_backup::config;
use fstp_celltest::backups::KEYSTORE_PREFIX;
use fstp_celltest::canary::CanaryKind;
use fstp_celltest::scan::StoreSet;
use fstp_celltest::world::{ClusterKind, CycleScript, DbMode, VaultLayout, World, WorldSpec};
use fstp_control::pg::CellDatabase;
use fstp_cp_proto::RoleName;
use fstp_rt::tokio::TokioRuntime;

use fake_s3::FakeS3;
use mem_custody::MemCustody;

const AK: &str = "PILOTACCESSKEY1";
const SK: &str = "pilot/secret+key=abcdef0123";
const REGION: &str = "gra";
const BUCKET: &str = "fstp-pilot-backups";

fn hex(b: &[u8]) -> String {
    fstp_backup::sigv4::hex(b)
}

fn holds(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

fn temp_dir(what: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "fstp-l10-{what}-{}",
        hex(&fstp_crypto::random_array::<8>().unwrap())
    ));
    std::fs::create_dir_all(&d).unwrap();
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

fn write_private(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// What one restored copy showed.
struct Copy {
    /// The parts and segments the restore wrote.
    parts: u32,
    segments: u32,
    /// The live ledger head at the archive: seq and SHA-256 of the body.
    live_head: (i64, String),
    /// The copy's head, and the copy's body digest at the live head's seq.
    head: (i64, String),
    at_live_seq: String,
    /// The copy's keystore image, as `keystore/<cell>/<name>`.
    keystore: StoreSet,
    /// `backup_label` of the copy held the start line.
    label_ok: bool,
}

/// What the scenario found.
struct Report {
    copies: Vec<Copy>,
    objects: Vec<(String, Vec<u8>)>,
    bodies: Vec<Vec<u8>>,
    bad_signatures: u32,
    violations: Vec<String>,
    erased_tried: usize,
    live_tried: usize,
    erased_opened: Vec<String>,
    live_failed: Vec<String>,
    /// Every text canary of the world, erased and live, rendered.
    canaries: Vec<Vec<u8>>,
    /// The archive results: how many uploaded.
    uploaded: usize,
    database: String,
}

fn scenario() -> &'static Report {
    static REPORT: OnceLock<Report> = OnceLock::new();
    REPORT.get_or_init(run_scenario)
}

fn run_cycle(world: &World, steps: &[&str]) {
    let script = CycleScript {
        steps: steps.iter().map(|s| (*s).to_owned()).collect(),
    };
    if let Err(e) = world.run_cycle(0, &script).result {
        panic!("{e}");
    }
}

/// The live ledger head of cell 0: seq and the SHA-256 of its body.
fn live_head(world: &World) -> (i64, String) {
    let out = world
        .app_superuser_sql(
            0,
            "SELECT seq || ' ' || encode(sha256(body), 'hex') FROM ledger.entry ORDER BY seq DESC LIMIT 1",
        )
        .unwrap();
    parse_head(&out)
}

fn parse_head(out: &str) -> (i64, String) {
    let line = out
        .lines()
        .rev()
        .find(|l| l.contains(' '))
        .unwrap_or_else(|| panic!("no ledger head in {out:?}"));
    let (seq, digest) = line.trim().split_once(' ').unwrap();
    (seq.parse().unwrap(), digest.to_owned())
}

/// Plays `archive_command`: switches the WAL and archives every completed
/// segment from `from` on.
fn archive_wal(
    rt: &TokioRuntime,
    agent: &Agent<TokioRuntime>,
    server: &fstp_pgtest::PgServer,
    from: &str,
) -> usize {
    // The segment the switch completed: the name of the switch's end,
    // which is the last segment that holds WAL.
    let last = server
        .psql("postgres", "SELECT pg_walfile_name(pg_switch_wal())")
        .unwrap();
    let last = last.trim().to_owned();
    let pg_wal = server.dir().join("data/pg_wal");
    let mut names: Vec<String> = std::fs::read_dir(&pg_wal)
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| fstp_backup::parse_wal_name(n).is_ok())
        .filter(|n| n.as_str() >= from && n.as_str() <= last.as_str())
        .collect();
    names.sort();
    let mut uploaded = 0;
    for n in names {
        let r = rt.block_on(agent.archive(&pg_wal.join(&n), &n)).unwrap();
        if r == Archived::Uploaded {
            uploaded += 1;
        }
    }
    uploaded
}

/// A PostgreSQL server over a restored data directory, on a free
/// loopback port, with the cluster's own TLS files and `pg_hba.conf`.
struct Restored {
    bindir: PathBuf,
    data: PathBuf,
    port: u16,
    root: bool,
}

fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn is_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false)
}

impl Restored {
    fn command(&self, program: &str) -> Command {
        let bin = self.bindir.join(program);
        let mut c = if self.root {
            let mut c = Command::new("runuser");
            c.args(["-u", "postgres", "--"]).arg(bin);
            c
        } else {
            Command::new(bin)
        };
        c.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C");
        c
    }

    fn start(bindir: &Path, data: &Path) -> Restored {
        let root = is_root();
        let sock = data.parent().unwrap().join("sock");
        std::fs::create_dir_all(&sock).unwrap();
        if root {
            for p in [data, sock.as_path()] {
                let ok = Command::new("chown")
                    .args(["-R", "postgres:postgres"])
                    .arg(p)
                    .status()
                    .unwrap()
                    .success();
                assert!(ok);
            }
        }
        let r = Restored {
            bindir: bindir.to_path_buf(),
            data: data.to_path_buf(),
            port: free_port(),
            root,
        };
        let opts = format!(
            "-c port={} -c unix_socket_directories={} -c archive_mode=off -c logging_collector=off",
            r.port,
            sock.display()
        );
        let out = r
            .command("pg_ctl")
            .arg("-D")
            .arg(data)
            .arg("-l")
            .arg(data.parent().unwrap().join("restored.log"))
            .args(["-w", "-t", "180", "-o", &opts, "start"])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        if !out.status.success() {
            let log = std::fs::read_to_string(data.parent().unwrap().join("restored.log"))
                .unwrap_or_default();
            panic!("the restored server did not start: {log}");
        }
        // Every restore runs archive recovery with `hot_standby = off`
        // (ADR-012 record of lane m10/backup-pitr). `pg_ctl -w` returns at
        // the consistent point, before the promotion, so the server still
        // refuses connections until it promotes.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(180);
        loop {
            let ready = r
                .command("pg_isready")
                .args(["-h", "127.0.0.1", "-p", &r.port.to_string(), "-q"])
                .stdin(Stdio::null())
                .status()
                .is_ok_and(|s| s.success());
            if ready {
                break;
            }
            if std::time::Instant::now() > deadline {
                let log = std::fs::read_to_string(data.parent().unwrap().join("restored.log"))
                    .unwrap_or_default();
                panic!("the restored server did not promote: {log}");
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        r
    }

    /// Runs `sql` as the cluster's superuser over TLS, as `psql` does on
    /// the live cluster.
    fn psql(&self, server: &fstp_pgtest::PgServer, db: &str, sql: &str) -> String {
        use std::io::Write as _;
        let mut c = Command::new(self.bindir.join("psql"));
        c.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .env("PGPASSWORD", server.superuser_password())
            .env("PGSSLMODE", "verify-full")
            .env("PGSSLROOTCERT", server.dir().join("tls/ca.pem"))
            .env("PGSSLCERT", server.dir().join("client/fstp_super.pem"))
            .env("PGSSLKEY", server.dir().join("client/fstp_super-key.pem"))
            .args(["-X", "-A", "-t", "-q", "-v", "ON_ERROR_STOP=1"])
            .args(["-h", "127.0.0.1", "-p", &self.port.to_string()])
            .args(["-U", server.superuser(), "-d", db])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = c.spawn().unwrap();
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
        String::from_utf8(out.stdout).unwrap()
    }

    fn stop(&self) {
        let _ = self
            .command("pg_ctl")
            .arg("-D")
            .arg(&self.data)
            .args(["-m", "immediate", "-w", "stop"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// The keystore image of the restored copy, loaded from its tables over
/// the cell's keys login, as a cell start loads it.
fn restored_keystore(
    world: &World,
    rt: &TokioRuntime,
    port: u16,
    server: &fstp_pgtest::PgServer,
    name: &str,
) -> StoreSet {
    let cell = world.cell(0).unwrap();
    let login = cell.role_login(CellDatabase::App, RoleName::Keys).unwrap();
    let p = login.conn_params(server, &cell.app_database());
    let tls =
        fstp_pgwire::ClientTls::new(p.server_ca_pem, p.client_cert_pem, p.client_key_pem).unwrap();
    let config = fstp_pgwire::Config::new(
        "127.0.0.1".to_owned(),
        port,
        p.user.as_str(),
        fstp_pgwire::Password::new(p.password.as_str()).unwrap(),
        p.dbname.clone(),
        tls,
    )
    .unwrap();
    let image = rt.block_on(async {
        let pool =
            fstp_pgstore::Pool::open(rt.clone(), cell.id(), fstp_pgstore::Role::Keys, config, 1)
                .await
                .unwrap();
        let tables = Arc::new(fstp_pgstore::KeystoreTables::new(pool).unwrap());
        let rows = tables.load().await.unwrap();
        let sink: Arc<dyn fstp_cell::tasks::erasure::KeystoreSink> = tables.clone();
        fstp_cell::tasks::erasure::Keystore::from_rows(cell.id(), rows, sink)
            .unwrap()
            .image()
            .unwrap()
    });
    let mut set = StoreSet::default();
    set.push(
        format!("{KEYSTORE_PREFIX}{}/{name}", hex(&cell.id())),
        fstp_cell::tasks::erasure::snapshot::encode_image(&image).unwrap(),
    );
    set
}

fn restore_copy(
    world: &World,
    rt: &TokioRuntime,
    agent: &Agent<TokioRuntime>,
    custody: &MemCustody,
    entry: &fstp_backup::index::IndexEntry,
    server: &fstp_pgtest::PgServer,
    live_head: (i64, String),
    name: &str,
) -> Copy {
    let base = temp_dir(name);
    let data = base.join("data");
    let secret = rt.block_on(agent.open_secret(custody)).unwrap();
    let r = rt.block_on(agent.restore(&secret, entry, &data)).unwrap();
    let label = std::fs::read(data.join("backup_label")).unwrap();
    let label_ok = fstp_backup::backup_label_start(&label).is_ok();
    let pg = Restored::start(server.bindir(), &data);
    let db = world.cell(0).unwrap().app_database();
    let head = parse_head(&pg.psql(
        server,
        &db,
        "SELECT seq || ' ' || encode(sha256(body), 'hex') FROM ledger.entry ORDER BY seq DESC LIMIT 1;",
    ));
    let at_live_seq = pg
        .psql(
            server,
            &db,
            &format!(
                "SELECT encode(sha256(body), 'hex') FROM ledger.entry WHERE seq = {};",
                live_head.0
            ),
        )
        .trim()
        .to_owned();
    let keystore = restored_keystore(world, rt, pg.port, server, name);
    pg.stop();
    let _ = std::fs::remove_dir_all(&base);
    Copy {
        parts: r.parts,
        segments: r.segments,
        live_head,
        head,
        at_live_seq,
        keystore,
        label_ok,
    }
}

fn run_scenario() -> Report {
    let world = World::start(WorldSpec {
        cells: 1,
        mode: DbMode::Shared,
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted: false,
        process_mode: false,
    })
    .unwrap_or_else(|e| panic!("{e}"));
    run_cycle(&world, &["login", "erase-text"]);
    let cluster = world.cluster(ClusterKind::Application).unwrap();
    let server = cluster.server();
    let login = cluster
        .replication_login()
        .unwrap()
        .expect("a replication role");

    let rt = TokioRuntime::new_multi_thread(2).unwrap();
    let fake = FakeS3::start(&rt, AK, SK, REGION, BUCKET);
    let custody = MemCustody::default();
    let cluster_id = fstp_crypto::random_array::<16>().unwrap();

    // The credentials directory and the configuration file, as the
    // operator guide lays them out.
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

    // The base backup, from the configuration, as the timer runs it.
    let from = server
        .psql("postgres", "SELECT pg_walfile_name(pg_current_wal_lsn())")
        .unwrap()
        .trim()
        .to_owned();
    let entry = rt.block_on(agent.base_backup(&cfg)).unwrap();
    assert_eq!(
        fstp_backup::index::newest(&cfg.state_dir, cluster_id).unwrap(),
        entry
    );
    // ADR-012 record of lane m10/backup-format, row "Start segment": the
    // index line names the start segment read from the real tar stream's
    // `backup_label`, which pruning needs.
    let line = *fstp_backup::index::read_lines(&cfg.state_dir)
        .unwrap()
        .last()
        .unwrap();
    assert!(line.start.is_some(), "no start segment in the index line");
    assert!(line.parts.is_some());

    // Copy A: the archive up to now.
    let head_a = live_head(&world);
    let mut uploaded = archive_wal(&rt, &agent, server, &from);
    let copy_a = restore_copy(
        &world, &rt, &agent, &custody, &entry, server, head_a, "copy-a",
    );

    // The text live at the backup is erased now, and copy B follows.
    run_cycle(&world, &["erase-text"]);
    let head_b = live_head(&world);
    uploaded += archive_wal(&rt, &agent, server, &from);
    let copy_b = restore_copy(
        &world, &rt, &agent, &custody, &entry, server, head_b, "copy-b",
    );

    let trial = world
        .try_every_text(&[copy_a.keystore.clone(), copy_b.keystore.clone()])
        .unwrap();
    let mut canaries = Vec::new();
    for kind in [CanaryKind::TextSalt, CanaryKind::ProposalText] {
        for erased in [true, false] {
            for c in world.text_canaries(kind, erased).unwrap() {
                canaries.push(c.text().into_bytes());
                canaries.push(c.secret_bytes().to_vec());
            }
        }
    }
    let s = &fake.state;
    let report = Report {
        copies: vec![copy_a, copy_b],
        objects: s
            .objects
            .lock()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        bodies: s.bodies.lock().unwrap().clone(),
        bad_signatures: *s.bad_signatures.lock().unwrap(),
        violations: s.violations.lock().unwrap().clone(),
        erased_tried: trial.erased_tried,
        live_tried: trial.live_tried,
        erased_opened: trial.erased_opened,
        live_failed: trial.live_failed,
        canaries,
        uploaded,
        database: world.cell(0).unwrap().app_database(),
    };
    fake.stop(&rt);
    let _ = std::fs::remove_dir_all(&creds);
    let _ = std::fs::remove_dir_all(&state);
    report
}

/// ADR-012 "Restore rule", record of lane L10: a base backup plus the
/// archived WAL restores the PostgreSQL world to the same ledger head.
/// Each copy holds the live head of its archive point with the same body
/// digest, and no entry beyond the live head of that moment. Every
/// request carried a signature the fake verified, and no object was
/// deleted.
#[test]
fn adr012_base_backup_and_wal_restore_reach_the_same_ledger_head() {
    let r = scenario();
    assert!(r.uploaded >= 1, "no WAL segment was archived");
    assert_eq!(r.bad_signatures, 0);
    assert!(r.violations.is_empty(), "{:?}", r.violations);
    for (i, c) in r.copies.iter().enumerate() {
        assert!(c.label_ok, "copy {i}");
        assert!(
            c.parts >= 1 && c.segments >= 1,
            "copy {i}: {} parts, {} segments",
            c.parts,
            c.segments
        );
        assert_eq!(
            c.at_live_seq, c.live_head.1,
            "copy {i}: the head entry differs"
        );
        assert_eq!(
            c.head, c.live_head,
            "copy {i}: the restored head is not the live head"
        );
    }
    assert!(
        r.copies[1].head.0 > r.copies[0].head.0,
        "copy B holds the entries of the second erase-text"
    );
}

/// R-CR-01: the backup bytes are sealed. No stored object and no request
/// body holds a plaintext the restored files hold (tar member names and
/// the `backup_label` start line), the database name, or a text canary.
/// Each object is an ADR-012 container.
#[test]
fn r_cr_01_backup_objects_hold_no_plaintext_row_content() {
    let r = scenario();
    let mut needles: Vec<Vec<u8>> = vec![
        b"backup_label".to_vec(),
        b"START WAL LOCATION".to_vec(),
        b"global/pg_control".to_vec(),
        b"PG_VERSION".to_vec(),
        r.database.as_bytes().to_vec(),
    ];
    needles.extend(r.canaries.iter().cloned());
    assert!(r.objects.len() >= 2);
    for (name, bytes) in &r.objects {
        assert!(fstp_backup::decode_container(bytes).is_ok(), "{name}");
        for n in &needles {
            assert!(!holds(bytes, n), "{name} holds plaintext");
        }
    }
    for body in &r.bodies {
        for n in &needles {
            assert!(!holds(body, n), "a request body holds plaintext");
        }
    }
}

/// I-81: an erasure leaves the erased texts unreadable after a restore.
/// The text erased before the backup and the text erased after it are
/// tried from both restored keystores, each loaded from the restored
/// tables, with every live custody root and the live keystore's rows
/// first (ADR-012 "Restore rule"). No erased text opens, and every live
/// text does, so the copies are real keystores.
#[test]
fn i81_erased_texts_stay_unreadable_after_a_restore() {
    let r = scenario();
    assert!(r.erased_tried >= 1, "no erased text was tried");
    assert!(r.live_tried >= 1, "no live text was tried");
    assert!(
        r.erased_opened.is_empty(),
        "erased texts opened: {:?}",
        r.erased_opened
    );
    assert!(
        r.live_failed.is_empty(),
        "live texts failed: {:?}",
        r.live_failed
    );
}
