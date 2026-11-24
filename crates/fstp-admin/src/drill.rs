//! `fstp-admin drill`: the monthly restore drill (ADR-012 record of lane
//! m10/backup-health, decided by Daniel on 2026-11-24).
//!
//! For each cluster in turn, the drill restores the newest base backup
//! and its archived WAL into a scratch directory with the plain
//! `fstp-backup restore <dir>`, starts a throwaway PostgreSQL on it,
//! waits until recovery ends, and checks it: the cell database answers a
//! query, and the restored keystore rows open through the live custody
//! entry (`fstp-cell check-keystore` and `fstp-vault check-keystore`,
//! which never write). Then it stops the server and deletes the scratch
//! directory, also after a failure.
//!
//! The throwaway server takes command-line settings that win over the
//! restored files ([`server_args`]): no archive, no Unix socket, and a
//! loopback listener on its own port with the restored TLS files and
//! `pg_hba.conf`. PostgreSQL offers no TLS over a Unix socket, and the
//! cell and the vault log in only over mutual TLS, so the drill server
//! listens on loopback (ADR-012, row "Deviation: TCP on loopback"). It
//! never serves a request and never reaches the witness.
//!
//! After both clusters, the drill fetches the witness copies into scratch
//! with `fstp-backup witness-fetch`, checks that each is a prefix of the
//! live witness store, and loads them with `fstp-witness check-store`
//! (ADR-012 record of lane m10/witness-copy).
//!
//! Before the first restore, the drill checks the free space of the
//! scratch location ([`needed_bytes`], [`parse_df`]). The result goes to
//! `fstp_obs::drill_status`, which `status` and the System page read.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use fstp_obs::drill_status::{self, DrillStatus, Step};

use crate::config::Services;
use crate::fail::Fail;
use crate::layout::{Cluster, Layout};
use crate::say::{Part, out};
use crate::state::State;
use crate::svc::{Manager, run_logged, run_ok};

/// The offset of a drill server's port from its cluster's port.
pub const PORT_OFFSET: u16 = 100;

/// The longest wait for recovery to end. Interim, pending Daniel.
pub const RECOVERY_LIMIT: Duration = Duration::from_secs(2 * 3600);

/// The room kept beyond the base backup for the archived WAL since it.
pub const WAL_MARGIN: u64 = 2 * 1024 * 1024 * 1024;

/// The scratch location of every drill.
#[must_use]
pub fn root(layout: &Layout) -> PathBuf {
    layout.state("drill")
}

/// The drill server's port of `c`.
#[must_use]
pub fn port(layout: &Layout, c: Cluster) -> u16 {
    layout.pg_port(c).saturating_add(PORT_OFFSET)
}

/// The bytes a drill needs free for a base backup of `largest` bytes:
/// half again for the cluster as it grows in recovery, and
/// [`WAL_MARGIN`] for the archived WAL since the backup.
#[must_use]
pub fn needed_bytes(largest: u64) -> u64 {
    largest
        .saturating_add(largest / 2)
        .saturating_add(WAL_MARGIN)
}

/// The available kibibytes in the output of `df -Pk <dir>`: a header line
/// that starts with `Filesystem`, then one line of six or more fields
/// whose fifth is a capacity such as `49%`. The fourth field is the
/// available space. Anything else is refused. Fuzzed
/// (`df_available_decode`).
#[must_use]
pub fn parse_df(text: &str) -> Option<u64> {
    if text.len() > 4096 {
        return None;
    }
    let mut lines = text.strip_suffix('\n')?.split('\n');
    let header = lines.next()?;
    let data = lines.next()?;
    if lines.next().is_some() || !header.starts_with("Filesystem") {
        return None;
    }
    let fields: Vec<&str> = data.split_whitespace().collect();
    if fields.len() < 6 {
        return None;
    }
    let capacity = fields.get(4)?.strip_suffix('%')?;
    let digits = |s: &str| {
        !s.is_empty()
            && s.len() <= 19
            && s.bytes().all(|b| b.is_ascii_digit())
            && !(s.len() > 1 && s.starts_with('0'))
    };
    if !digits(capacity) || !fields.get(1..4)?.iter().all(|f| digits(f)) {
        return None;
    }
    fields.get(3)?.parse().ok()
}

/// The free bytes under `dir`, from `df -Pk`.
fn free_bytes(dir: &Path) -> Option<u64> {
    let out = Command::new("df")
        .arg("-Pk")
        .arg(dir)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    parse_df(std::str::from_utf8(&out.stdout).ok()?)?.checked_mul(1024)
}

/// The plaintext size of the newest base backup of `c`, from the agent's
/// index: the fourth field of its last line (ADR-012 record of lane L10,
/// row "Base backup index").
#[must_use]
pub fn last_backup_bytes(layout: &Layout, c: Cluster) -> Option<u64> {
    let text = std::fs::read_to_string(layout.backup_state(c).join("base-backups.index")).ok()?;
    text.lines().last()?.split_whitespace().nth(3)?.parse().ok()
}

/// The command-line settings of the drill server on `scratch` at `port`
/// (module documentation). They win over `postgresql.conf` and
/// `postgresql.auto.conf` of the restored copy.
#[must_use]
pub fn server_args(scratch: &Path, port: u16) -> Vec<OsString> {
    let p = |leaf: &str| scratch.join(leaf).into_os_string();
    let set = |k: &str, v: OsString| {
        let mut s = OsString::from(format!("{k}="));
        s.push(v);
        s
    };
    let mut args: Vec<OsString> = vec!["-D".into(), scratch.as_os_str().to_owned()];
    for s in [
        set("listen_addresses", "127.0.0.1".into()),
        set("port", port.to_string().into()),
        set("unix_socket_directories", OsString::new()),
        set("archive_mode", "off".into()),
        set("archive_command", OsString::new()),
        set("max_wal_senders", "0".into()),
        set("ssl", "on".into()),
        set("ssl_cert_file", p("tls/server.pem")),
        set("ssl_key_file", p("tls/server.key")),
        set("ssl_ca_file", p("tls/ca.pem")),
        set("hba_file", p("pg_hba.conf")),
        set("cluster_name", "fstp-drill".into()),
        set("logging_collector", "off".into()),
    ] {
        args.push("-c".into());
        args.push(s);
    }
    args
}

/// Whether nothing listens on loopback at `port`.
fn port_free(port: u16) -> bool {
    std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).is_ok()
}

/// One cluster's scratch directory and throwaway server.
struct Scratch<'a> {
    layout: &'a Layout,
    m: &'a Manager,
    dir: PathBuf,
    server: Option<Child>,
}

impl Scratch<'_> {
    /// Stops the server and deletes the directory. `Err` when either
    /// failed.
    fn cleanup(&mut self) -> Result<(), ()> {
        let mut ok = true;
        // A server runs while its lock file stands, also one left by an
        // interrupted drill: a fast stop, then an immediate one.
        if self.dir.join("postmaster.pid").exists() {
            let stopped = ["fast", "immediate"].iter().any(|mode| {
                let mut stop = crate::stack::as_user(
                    self.layout,
                    crate::pg::PG_USER,
                    &self.layout.pg_bin("pg_ctl"),
                );
                stop.arg("-D")
                    .arg(&self.dir)
                    .args(["-m", mode, "-w", "-t", "120", "stop"]);
                run_ok(&mut stop, &self.m.log()).is_ok()
            });
            // A lock file left by a server that died is no server: `pg_ctl
            // status` exits 3 when none runs.
            let none_runs = || {
                let mut st = crate::stack::as_user(
                    self.layout,
                    crate::pg::PG_USER,
                    &self.layout.pg_bin("pg_ctl"),
                );
                st.arg("-D").arg(&self.dir).arg("status");
                matches!(run_logged(&mut st, &self.m.log()), Ok(Some(3)))
            };
            if !stopped && !none_runs() {
                ok = false;
            }
        }
        if let Some(mut child) = self.server.take() {
            if !matches!(child.try_wait(), Ok(Some(_))) {
                let _ = child.kill();
            }
            if child.wait().is_err() {
                ok = false;
            }
        }
        if !ok {
            // Never delete the files under a server that may still run.
            return Err(());
        }
        match std::fs::remove_dir_all(&self.dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => ok = false,
        }
        if ok { Ok(()) } else { Err(()) }
    }
}

fn chown_pg(layout: &Layout, m: &Manager, path: &Path) -> Result<(), ()> {
    if layout.cfg.services != Services::Systemd {
        return Ok(());
    }
    let mut g = Command::new("chown");
    g.arg("-R")
        .arg(format!("{0}:{0}", crate::pg::PG_USER))
        .arg(path);
    run_ok(&mut g, &m.log()).map_err(|_| ())
}

/// Restores, starts and checks one cluster (module documentation).
/// Returns the seconds from the restore's start to the end of the checks.
fn one(s: &mut Scratch<'_>, c: Cluster, cell: &[u8; 16]) -> Result<u64, Step> {
    let layout = s.layout;
    let started = Instant::now();
    let mut restore = Command::new(layout.bin("fstp-backup"));
    restore
        .env(
            "FSTP_BACKUP_CONFIG",
            layout.config_file(&format!("backup-{}", c.name())),
        )
        .arg("restore")
        .arg(&s.dir);
    run_ok(&mut restore, &s.m.log()).map_err(|_| Step::Restore)?;
    // ADR-012 record of lane m10/backup-followups: the live TLS files, whose
    // server key the keystore checks pin.
    crate::ops::put_current_tls(layout, c, &s.dir).map_err(|_| Step::Restore)?;
    chown_pg(layout, s.m, &s.dir).map_err(|_| Step::Restore)?;
    step_done("restored", c);
    let port = port(layout, c);
    if !port_free(port) {
        // Never talk to whatever holds the port (ADR-012 record of lane
        // m10/backup-health, row "Throwaway server").
        out(&[
            Part::T("The restore drill needs the free port "),
            Part::N(u64::from(port)),
            Part::T(
                " on 127.0.0.1 for its scratch copy, and something else listens there. Stop that program or wait for the other drill to end, then run fstp-admin drill again.",
            ),
        ]);
        return Err(Step::Recovery);
    }
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(root(layout).join(format!("{}.log", c.name())))
        .map_err(|_| Step::Recovery)?;
    let err = log.try_clone().map_err(|_| Step::Recovery)?;
    let mut server = crate::stack::as_user(layout, crate::pg::PG_USER, &layout.pg_bin("postgres"));
    server
        .args(server_args(&s.dir, port))
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(err));
    s.server = Some(server.spawn().map_err(|_| Step::Recovery)?);
    let waiting = Instant::now();
    loop {
        if let Some(child) = s.server.as_mut()
            && !matches!(child.try_wait(), Ok(None))
        {
            return Err(Step::Recovery);
        }
        // pg_isready first, so the wait writes no psql failure to the log.
        let mut ready = Command::new(layout.pg_bin("pg_isready"));
        ready
            .args(["-q", "-h", "127.0.0.1", "-p", &port.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if ready.status().is_ok_and(|st| st.success()) {
            let answer = crate::pg::psql_at(
                layout,
                c,
                port,
                "postgres",
                "SELECT pg_is_in_recovery();",
                "the restore drill",
            );
            if answer.as_deref() == Ok("f") {
                break;
            }
        }
        if waiting.elapsed() >= RECOVERY_LIMIT {
            return Err(Step::Recovery);
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    step_done("recovered", c);
    let db = crate::pg::dbname(c, cell);
    let answer = crate::pg::psql_at(
        layout,
        c,
        port,
        &db,
        "SELECT count(*) > 0 FROM pg_catalog.pg_class;",
        "the restore drill",
    );
    if answer.as_deref() != Ok("t") {
        return Err(Step::Database);
    }
    step_done("checked the database of", c);
    let (user, bin, env, service) = match c {
        Cluster::App => (
            crate::stack::CELL_USER,
            "fstp-cell",
            "FSTP_CELL_CONFIG",
            "cell",
        ),
        Cluster::Vault => (
            crate::stack::VAULT_USER,
            "fstp-vault",
            "FSTP_VAULT_CONFIG",
            "vault",
        ),
    };
    let mut check = crate::stack::as_user(layout, user, &layout.bin(bin));
    check
        .env(env, layout.config_file(service))
        .arg("check-keystore")
        .arg(port.to_string());
    match run_logged(&mut check, &s.m.log()) {
        Ok(Some(0)) => {}
        _ => return Err(Step::Keystore),
    }
    step_done("opened the keys of", c);
    Ok(started.elapsed().as_secs())
}

fn step_done(what: &'static str, c: Cluster) {
    out(&[
        Part::T("  done     "),
        Part::T(what),
        Part::T(" the "),
        Part::T(c.name()),
        Part::T(" copy"),
    ]);
}

/// The plain words of a failed step, for the screen.
#[must_use]
pub fn step_text(step: Step) -> &'static str {
    match step {
        Step::Space => "there is not enough free disk space for the restored copy",
        Step::Restore => "fstp-backup restore failed: the backup could not be fetched or opened",
        Step::Recovery => {
            "the restored database did not start or did not finish replaying its changes"
        }
        Step::Database => "the restored cell database is missing or does not answer",
        Step::Keystore => "the restored keys do not open with the live key custody",
        Step::Cleanup => "the scratch copy could not be stopped or deleted",
        Step::Witness => {
            "the witness copies could not be fetched, did not load, or differ from the live witness store"
        }
    }
}

fn record(layout: &Layout, s: &DrillStatus) {
    if drill_status::write(&layout.admin_dir(), s).is_err() {
        out(&[Part::T(
            "  The drill status file did not write, so status cannot show this drill.",
        )]);
    }
}

fn now_secs() -> u64 {
    u64::try_from(crate::pki::now()).unwrap_or(0)
}

/// Fails the drill at `step`: records it and returns the failure.
fn failed(layout: &Layout, step: Step) -> Fail {
    let s = drill_status::read(&layout.admin_dir()).after_fail(now_secs(), step);
    record(layout, &s);
    out(&[
        Part::T("The restore drill FAILED: "),
        Part::T(step_text(step)),
        Part::T(". Details are in admin/logs/fstp-admin.log and in "),
        Part::P(&root(layout)),
        Part::T("."),
    ]);
    Fail::Refused("the restore drill", Some(1))
}

/// The drill's witness step (ADR-012 record of lane m10/witness-copy, row
/// "Drill"): fetches every witness copy into `scratch`, checks that each
/// fetched file is a prefix of, or equal to, the live store file, and that
/// the fetched store loads with every link recomputed. A live store with
/// records but no copies fails.
fn witness_step(layout: &Layout, scratch: &Path) -> Result<(), ()> {
    crate::witness::fetch(layout, scratch).map_err(|_| ())?;
    let live = layout.witness_store();
    let mut fetched = 0u64;
    for e in std::fs::read_dir(scratch).map_err(|_| ())? {
        let e = e.map_err(|_| ())?;
        let copy = std::fs::read(e.path()).map_err(|_| ())?;
        let here = std::fs::read(live.join(e.file_name())).unwrap_or_default();
        if !here.starts_with(&copy) {
            out(&[
                Part::T("  The witness copy of "),
                Part::Name(&e.file_name().to_string_lossy()),
                Part::T(" is not a prefix of the live witness store."),
            ]);
            return Err(());
        }
        fetched = fetched.saturating_add(1);
    }
    if fetched == 0 {
        let live_records = std::fs::read_dir(&live).is_ok_and(|rd| {
            rd.flatten()
                .any(|e| e.metadata().is_ok_and(|m| m.is_file() && m.len() > 0))
        });
        if live_records {
            out(&[Part::T(
                "  The witness store holds records, but the object store holds no copy of them. Run fstp-admin witness-copy.",
            )]);
            return Err(());
        }
        out(&[Part::T(
            "  done     no witness records yet, so no witness copy to check",
        )]);
        return Ok(());
    }
    out(&[
        Part::T("  done     fetched "),
        Part::N(fetched),
        Part::T(" witness files, each this host's own history"),
    ]);
    crate::witness::check_store(layout, scratch).map_err(|_| ())?;
    out(&[Part::T(
        "  done     the witness copies load and every link recomputes",
    )]);
    Ok(())
}

/// `fstp-admin drill` (module documentation).
///
/// # Errors
///
/// [`Fail::Waits`] without backups, setup or a base backup of each
/// cluster, and [`Fail::Refused`] when a step failed, after the failure
/// is recorded.
pub fn run(layout: &Layout) -> Result<(), Fail> {
    if layout.cfg.backup.is_none() {
        return Err(Fail::Waits(
            "the restore drill needs \"backup\" in the configuration file, then fstp-admin setup",
        ));
    }
    let state = State::load(&layout.admin_dir().join("state")).unwrap_or_default();
    let cell: [u8; 16] = state
        .get("cell")
        .and_then(crate::witness::unhex)
        .and_then(|b| b.try_into().ok())
        .ok_or(Fail::Waits("the restore drill: run fstp-admin setup first"))?;
    let mut largest = 0u64;
    for c in Cluster::ALL {
        let bytes = last_backup_bytes(layout, c).ok_or(Fail::Waits(
            "the restore drill needs a base backup of each database: run fstp-admin backup first",
        ))?;
        largest = largest.max(bytes);
    }
    let dir = root(layout);
    {
        use std::os::unix::fs::DirBuilderExt as _;
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o711)
            .create(&dir);
        // Only root lists it. The PostgreSQL user passes through to the
        // scratch copy it owns.
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o711));
    }
    let needed = needed_bytes(largest);
    match free_bytes(&dir) {
        Some(free) if free >= needed => {}
        free => {
            const GIB: u64 = 1024 * 1024 * 1024;
            out(&[
                Part::T("The restore drill needs about "),
                Part::N(needed.div_ceil(GIB)),
                Part::T(" GiB free under "),
                Part::P(&dir),
                Part::T(", and "),
                Part::N(free.unwrap_or(0) / GIB),
                Part::T(
                    " GiB are free. Free some space on that disk, then run fstp-admin drill again.",
                ),
            ]);
            return Err(failed(layout, Step::Space));
        }
    }
    out(&[Part::T(
        "  done     enough free space for the restored copy",
    )]);
    let m = Manager::new(layout);
    let mut total = 0u64;
    for c in Cluster::ALL {
        let mut s = Scratch {
            layout,
            m: &m,
            dir: dir.join(c.name()),
            server: None,
        };
        // A copy left by an interrupted drill goes first.
        if s.cleanup().is_err() {
            return Err(failed(layout, Step::Cleanup));
        }
        let r = one(&mut s, c, &cell);
        let cleaned = s.cleanup();
        match (r, cleaned) {
            (Err(step), _) => return Err(failed(layout, step)),
            (Ok(_), Err(())) => return Err(failed(layout, Step::Cleanup)),
            (Ok(secs), Ok(())) => total = total.saturating_add(secs),
        }
        out(&[
            Part::T("  done     deleted the scratch copy of the "),
            Part::T(c.name()),
            Part::T(" database"),
        ]);
    }
    // ADR-012 record of lane m10/witness-copy, item 4: the witness copies
    // fetch into scratch, load, and are this host's history.
    let scratch = dir.join("witness");
    let _ = std::fs::remove_dir_all(&scratch);
    let checked = witness_step(layout, &scratch);
    let cleaned = std::fs::remove_dir_all(&scratch).is_ok() || !scratch.exists();
    match (checked, cleaned) {
        (Err(()), _) => return Err(failed(layout, Step::Witness)),
        (Ok(()), false) => return Err(failed(layout, Step::Cleanup)),
        (Ok(()), true) => {}
    }
    let s = drill_status::read(&layout.admin_dir()).after_pass(now_secs(), total);
    record(layout, &s);
    out(&[
        Part::T("The restore drill passed. Restoring both databases took "),
        Part::N(s.seconds.unwrap_or(total)),
        Part::T(" seconds."),
    ]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR-012 record of lane m10/backup-health, row "Throwaway server":
    /// the drill server archives nothing, has no Unix socket, listens on
    /// loopback at its own port only, and reads its TLS files and
    /// `pg_hba.conf` from the scratch copy.
    #[test]
    fn adr012_bh_drill_server_has_no_archive_and_no_socket() {
        let scratch = Path::new("/var/lib/fstp/drill/app");
        let args: Vec<String> = server_args(scratch, 5546)
            .into_iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let settings: Vec<&str> = args
            .iter()
            .zip(args.iter().skip(1))
            .filter(|(k, _)| *k == "-c")
            .map(|(_, v)| v.as_str())
            .collect();
        for want in [
            "archive_mode=off",
            "archive_command=",
            "unix_socket_directories=",
            "listen_addresses=127.0.0.1",
            "port=5546",
            "max_wal_senders=0",
            "ssl=on",
            "ssl_cert_file=/var/lib/fstp/drill/app/tls/server.pem",
            "ssl_key_file=/var/lib/fstp/drill/app/tls/server.key",
            "hba_file=/var/lib/fstp/drill/app/pg_hba.conf",
        ] {
            assert!(settings.contains(&want), "{want} in {settings:?}");
        }
        assert_eq!(
            args.get(..2),
            Some(&["-D".to_owned(), scratch.display().to_string()][..])
        );
        for s in &settings {
            if let Some((_, v)) = s.split_once('=')
                && v.starts_with('/')
            {
                assert!(v.starts_with("/var/lib/fstp/drill/app/"), "{s}");
            }
        }
        assert!(
            !settings
                .iter()
                .any(|s| s.starts_with("listen_addresses=") && *s != "listen_addresses=127.0.0.1")
        );
    }

    /// ADR-012 record of lane m10/backup-health, row "Disk check": the
    /// `df -Pk` output gives the available space in one shape, and the
    /// drill needs the larger base backup, half again, and 2 GiB.
    /// ADR-012 record of lane m10/witness-copy, row "Drill": the witness
    /// step has its own word in the drill status file and its own plain
    /// words on the screen.
    #[test]
    fn adr012_wc_drill_names_the_witness_step() {
        let s = DrillStatus::default().after_fail(9, Step::Witness);
        assert_eq!(drill_status::encode(&s), "v1 9 0 witness 0\n");
        assert_eq!(drill_status::decode(b"v1 9 0 witness 0\n"), Ok(s));
        assert!(step_text(Step::Witness).contains("witness copies"));
    }

    #[test]
    fn adr012_bh_df_output_gives_the_free_space() {
        let linux = "Filesystem     1024-blocks     Used Available Capacity Mounted on\n\
                     /dev/sda1        102400000 50000000  52400000      49% /\n";
        assert_eq!(parse_df(linux), Some(52_400_000));
        let mac = "Filesystem     1024-blocks      Used Available Capacity  Mounted on\n\
                   /dev/disk3s5     971350180 600000000 300000000    67%    /System/Volumes/Data\n";
        assert_eq!(parse_df(mac), Some(300_000_000));
        let spaced = "Filesystem 1024-blocks Used Available Capacity Mounted on\n\
                      /dev/x 10 5 5 50% /mnt/my disk\n";
        assert_eq!(parse_df(spaced), Some(5));
        for bad in [
            "",
            "Filesystem 1024-blocks Used Available Capacity Mounted on\n",
            "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/x 10 5 5 50% /",
            "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/x 10 5 -5 50% /\n",
            "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/x 10 5 05 50% /\n",
            "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/x 10 5 5 50 /\n",
            "Filesystem 1024-blocks Used Available Capacity Mounted on\nmy fs 10 5 5 50% /\n",
            "Disk 1024-blocks Used Available Capacity Mounted on\n/dev/x 10 5 5 50% /\n",
            "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/x 10 5 5 50% /\n/dev/y 1 1 1 1% /y\n",
        ] {
            assert_eq!(parse_df(bad), None, "{bad:?}");
        }
        const GIB: u64 = 1024 * 1024 * 1024;
        assert_eq!(needed_bytes(0), 2 * GIB);
        assert_eq!(needed_bytes(4 * GIB), 8 * GIB);
        assert_eq!(needed_bytes(u64::MAX), u64::MAX);
    }

    fn layout(tag: &str, backup: bool) -> (Layout, PathBuf) {
        let rnd = fstp_crypto::random_array::<6>().unwrap_or([7; 6]);
        let dir = std::env::temp_dir().join(format!(
            "fstp-drill-{tag}-{}",
            rnd.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ));
        let backup = if backup {
            r#","backup":{"endpoint":"s3.example.eu","region":"eu-west","bucket":"fstp-backups","access_key_file":"/k1","secret_key_file":"/k2"}"#
        } else {
            ""
        };
        let cfg = format!(
            r#"{{"domain":"grants.example.eu","operator_email":"admin@example.eu",
            "mail":{{"relay":"smtp.example.eu","username":"cell"}},
            "services":"direct",
            "paths":{{"state":"{s}","etc":"{e}","bin":"{b}"}}{backup}}}"#,
            s = dir.join("state").display(),
            e = dir.join("etc").display(),
            b = dir.join("bin").display(),
        );
        let config = crate::config::decode(cfg.as_bytes());
        assert!(config.is_ok(), "{config:?}");
        let Ok(config) = config else { unreachable!() };
        (Layout::new(config), dir)
    }

    /// ADR-012 record of lane m10/backup-health, row "Disk check": a
    /// drill without room refuses before any restore, says so, and
    /// records the step `space`. Without backups or a base backup it
    /// waits and records nothing.
    #[test]
    fn adr012_bh_drill_refuses_without_room() {
        let (l, dir) = layout("room", true);
        let admin = l.admin_dir();
        assert!(matches!(run(&l), Err(Fail::Waits(_))), "before setup");
        let mut st = State::load(&admin.join("state")).unwrap_or_default();
        assert!(st.set("cell", &"ab".repeat(16)).is_ok());
        assert!(matches!(run(&l), Err(Fail::Waits(_))), "no base backup");
        assert_eq!(drill_status::read(&admin), DrillStatus::default());
        for c in Cluster::ALL {
            let d = l.backup_state(c);
            assert!(std::fs::create_dir_all(&d).is_ok());
            // A base backup larger than any disk.
            let line = format!(
                "{} {} 1795000000 18000000000000000000\n",
                "11".repeat(16),
                "22".repeat(16)
            );
            assert!(std::fs::write(d.join("base-backups.index"), line).is_ok());
            assert_eq!(last_backup_bytes(&l, c), Some(18_000_000_000_000_000_000));
        }
        assert!(matches!(run(&l), Err(Fail::Refused(..))));
        let s = drill_status::read(&admin);
        assert_eq!(s.failed, Some(Step::Space));
        assert_eq!(s.last_pass, None);
        assert!(!root(&l).join("app").exists(), "nothing restored");
        let (none, dir2) = layout("nobackup", false);
        assert!(matches!(run(&none), Err(Fail::Waits(_))));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&dir2);
    }

    /// ADR-012 record of lane m10/backup-health, row "Drill status file":
    /// a failed restore is recorded as the step `restore`, keeps the last
    /// pass, and leaves no scratch copy behind.
    #[test]
    fn adr012_bh_drill_records_each_outcome() {
        let (l, dir) = layout("outcome", true);
        let admin = l.admin_dir();
        let mut st = State::load(&admin.join("state")).unwrap_or_default();
        assert!(st.set("cell", &"ab".repeat(16)).is_ok());
        for c in Cluster::ALL {
            let d = l.backup_state(c);
            assert!(std::fs::create_dir_all(&d).is_ok());
            let line = format!("{} {} 1795000000 1024\n", "11".repeat(16), "22".repeat(16));
            assert!(std::fs::write(d.join("base-backups.index"), line).is_ok());
        }
        let before = DrillStatus::default().after_pass(1_790_000_000, 300);
        assert!(drill_status::write(&admin, &before).is_ok());
        // No fstp-backup is installed under bin, so the restore fails.
        assert!(matches!(run(&l), Err(Fail::Refused(..))));
        let s = drill_status::read(&admin);
        assert_eq!(s.failed, Some(Step::Restore));
        assert_eq!((s.last_pass, s.seconds), (Some(1_790_000_000), Some(300)));
        assert!(!root(&l).join("app").exists(), "the scratch copy is gone");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
