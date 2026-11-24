//! The day-to-day commands: backups, restore, the off-host key copy,
//! certificate renewal, start and stop (ADR-028).

use std::path::{Path, PathBuf};
use std::process::Command;

use fstp_pki::cert::CertKind;

use crate::config::Services;
use crate::fail::{Cause, Fail, TimeRefusal};
use crate::layout::{Cluster, Entry, Layout};
use crate::pki::{Leaf, random_hex, write_pair};
use crate::say::{Part, out};
use crate::setup::Cas;
use crate::stack;
use crate::state::{State, write_atomic};
use crate::svc::{Manager, RunFail, run_logged, run_ok};

/// The replication role of every cluster (ADR-005, `HBA_REPLICATION_LINE`).
pub const REPL_ROLE: &str = "fstp_repl";

/// The backup agent's key file (ADR-012 record of lane L10).
const KEY_FILE: &str = "cluster-backup.key";
/// The backup agent's writer key (ADR-012 record of lane m10/backup-format).
const WRITER_FILE: &str = "cluster-backup-writer.key";

fn io(step: &'static str) -> impl Fn(std::io::Error) -> Fail {
    move |_| Fail::Step(step, Cause::Io)
}

pub(crate) fn backup_env(layout: &Layout, c: Cluster) -> (&'static str, PathBuf) {
    (
        "FSTP_BACKUP_CONFIG",
        layout.config_file(&format!("backup-{}", c.name())),
    )
}

/// Sets up the backup agent of each cluster when the configuration names
/// an object store. `None` when it names none.
///
/// # Errors
///
/// [`Fail::Step`] naming the part that failed.
pub fn setup_backups(
    layout: &Layout,
    m: &Manager,
    state: &mut State,
    cas: &Cas,
) -> Result<Option<bool>, Fail> {
    let Some(b) = layout.cfg.backup.clone() else {
        return Ok(None);
    };
    let step = "backups";
    let mut did = false;
    let mut restarted = false;
    for (c, ca) in [(Cluster::App, &cas.app_db), (Cluster::Vault, &cas.vault_db)] {
        let dir = layout.creds(&format!("backup-{}", c.name()));
        std::fs::create_dir_all(&dir).map_err(io(step))?;
        std::fs::create_dir_all(layout.backup_state(c)).map_err(io(step))?;
        // ADR-012 record of lane m10/backup-format: store `n` from 1 takes
        // `s3-<n>-access-key-id` and `s3-<n>-secret-access-key`.
        let mut files = vec![
            (b.access_key_file.clone(), "s3-access-key-id".to_owned()),
            (b.secret_key_file.clone(), "s3-secret-access-key".to_owned()),
        ];
        for (i, s) in b.copies.iter().enumerate() {
            let n = i.saturating_add(1);
            files.push((s.access_key_file.clone(), format!("s3-{n}-access-key-id")));
            files.push((
                s.secret_key_file.clone(),
                format!("s3-{n}-secret-access-key"),
            ));
        }
        for (from, to) in &files {
            let bytes = std::fs::read(from).map_err(io(step))?;
            write_atomic(&dir.join(to), &bytes, 0o640).map_err(io(step))?;
        }
        write_atomic(&dir.join("db-ca.pem"), &ca.pem, 0o600).map_err(io(step))?;
        if crate::pki::needs_issue(&dir.join("repl.pem")) {
            let i = ca
                .issue(&Leaf {
                    cn: REPL_ROLE,
                    ou: None,
                    kind: CertKind::Client,
                    dns: &[],
                    ips: &[],
                })
                .map_err(|e| Fail::Step(step, Cause::Pki(e)))?;
            write_pair(&dir, "repl.pem", "repl.key", &i)
                .map_err(|e| Fail::Step(step, Cause::Pki(e)))?;
        }
        let password = match std::fs::read_to_string(dir.join("repl.password")) {
            Ok(p) if !p.trim().is_empty() => p.trim().to_owned(),
            _ => {
                let p = random_hex(24).map_err(|e| Fail::Step(step, Cause::Pki(e)))?;
                write_atomic(&dir.join("repl.password"), p.as_bytes(), 0o600).map_err(io(step))?;
                p
            }
        };
        crate::pg::psql(
            layout,
            c,
            "postgres",
            &format!(
                "DO $$BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{REPL_ROLE}') THEN \
                 CREATE ROLE {REPL_ROLE} LOGIN REPLICATION PASSWORD '{password}'; \
                 ELSE ALTER ROLE {REPL_ROLE} LOGIN REPLICATION PASSWORD '{password}'; END IF; END$$;\n"
            ),
            "the login roles",
        )
        .map_err(|e| Fail::Step(step, e.into()))?;
        let id = match state.get(&format!("cluster.{}", c.name())) {
            Some(id) => id.to_owned(),
            None => return Err(Fail::Step(step, Cause::Io)),
        };
        if let Some(text) = crate::render::backup(layout, c, &id) {
            write_atomic(&backup_env(layout, c).1, text.as_bytes(), 0o644).map_err(io(step))?;
        }
        if layout.cfg.services == Services::Systemd {
            // archive_command runs as postgres: it reads the object store
            // keys and the key file, never the replication login.
            let mut g = Command::new("chown");
            g.arg("-R").arg("root:postgres").arg(&dir);
            run_ok(&mut g, &m.log()).map_err(|e| Fail::Step(step, e.into()))?;
            let mut d = Command::new("chmod");
            d.arg("0750").arg(&dir);
            run_ok(&mut d, &m.log()).map_err(|e| Fail::Step(step, e.into()))?;
        }
        // ADR-012 record of lane m10/backup-format: the key file is bound
        // to the agent's writer key. A key file from before that lane has
        // no writer key, so `upgrade-keys` binds one, and a base backup
        // follows at once, so a restore never needs an older container.
        let mut fresh_base = false;
        let key_files = [KEY_FILE, WRITER_FILE];
        if !dir.join(KEY_FILE).is_file() {
            let mut cmd = Command::new(layout.bin("fstp-backup"));
            let (k, v) = backup_env(layout, c);
            cmd.env(k, v).arg("init-keys");
            run_ok(&mut cmd, &m.log()).map_err(|e| Fail::Step(step, e.into()))?;
            did = true;
        } else if !dir.join(WRITER_FILE).is_file() {
            let mut cmd = Command::new(layout.bin("fstp-backup"));
            let (k, v) = backup_env(layout, c);
            cmd.env(k, v).arg("upgrade-keys");
            run_ok(&mut cmd, &m.log()).map_err(|e| Fail::Step(step, e.into()))?;
            fresh_base = true;
            did = true;
        }
        if layout.cfg.services == Services::Systemd {
            // archive_command runs as postgres and signs with the writer
            // key: both files are root:postgres, mode 0640.
            for name in key_files {
                let mut g = Command::new("chown");
                g.arg("root:postgres").arg(dir.join(name));
                run_ok(&mut g, &m.log()).map_err(|e| Fail::Step(step, e.into()))?;
                let mut g = Command::new("chmod");
                g.arg("0640").arg(dir.join(name));
                run_ok(&mut g, &m.log()).map_err(|e| Fail::Step(step, e.into()))?;
            }
        }
        if crate::pg::enable_archive(layout, c, &backup_env(layout, c).1)
            .map_err(|e| Fail::Step(step, e.into()))?
        {
            let s = crate::pg::service(layout, c);
            m.stop(&s).map_err(|e| Fail::Step(step, e.into()))?;
            m.ensure(&s).map_err(|e| Fail::Step(step, e.into()))?;
            did = true;
            restarted = true;
        }
        if fresh_base {
            let mut cmd = Command::new(layout.bin("fstp-backup"));
            let (k, v) = backup_env(layout, c);
            cmd.env(k, v).arg("base-backup");
            run_ok(&mut cmd, &m.log()).map_err(|e| Fail::Step(step, e.into()))?;
            out(&[
                Part::T("  done     a fresh base backup of the "),
                Part::T(c.name()),
                Part::T(" database in the new backup format"),
            ]);
        }
        // ADR-012 record of lane m10/backup-followups: the second custodian
        // reads the version 2 key file from the stores.
        publish_key_if_owed(layout, m, c);
    }
    // ADR-012 record of lane m10/backup-followups, row "Database restart":
    // the services that held connections to a restarted cluster start
    // again, so the cell's store and the vault's keys login are fresh.
    if restarted {
        restart_database_clients(layout, m).map_err(|e| Fail::Step(step, e.into()))?;
    }
    m.timer(
        "fstp-admin-backup",
        &layout.bin("fstp-admin"),
        "backup",
        "*-*-* 02:30:00",
    )
    .map_err(|e| Fail::Step(step, e.into()))?;
    // ADR-012 record of lane m10/backup-health: the monthly restore drill,
    // after the backup at 02:30 and the renewal at 03:30.
    m.timer(
        "fstp-admin-drill",
        &layout.bin("fstp-admin"),
        "drill",
        "*-*-01 04:30:00",
    )
    .map_err(|e| Fail::Step(step, e.into()))?;
    // ADR-012 record of lane m10/witness-copy: the witness store leaves
    // the host every minute, and once now. A failed first run is reported
    // and does not stop setup: status shows it, and the timer tries again.
    m.timer_with_delay(
        "fstp-admin-witness-copy",
        &layout.bin("fstp-admin"),
        "witness-copy",
        "*-*-* *:*:00",
        0,
    )
    .map_err(|e| Fail::Step(step, e.into()))?;
    if let Err(e) = crate::witness::copy(layout) {
        crate::fail::report(&e);
    }
    Ok(Some(did))
}

/// The services that hold connections to the two database clusters, in
/// start order: the vault, the cell, and the edge, whose unit requires the
/// cell (ADR-012 record of lane m10/backup-followups, row "Database
/// restart").
#[must_use]
pub fn database_clients(layout: &Layout) -> Vec<crate::svc::Service> {
    vec![
        stack::vault(layout),
        stack::cell(layout),
        stack::edge(layout),
    ]
}

/// Stops and starts every service of [`database_clients`] after a
/// database cluster restarted under it. The cell's store does not
/// reconnect, so without this every key record, and with it every
/// keystore snapshot and erasure step 5, failed until the next start. On
/// a systemd host the stop of a cluster already stopped the units that
/// require it, and only this starts them again.
fn restart_database_clients(layout: &Layout, m: &Manager) -> Result<(), RunFail> {
    let services = database_clients(layout);
    for s in services.iter().rev() {
        m.stop(s)?;
    }
    for s in &services {
        m.ensure(s)?;
    }
    out(&[Part::T(
        "  done     restarted the vault and the cell after the database restart",
    )]);
    Ok(())
}

/// `fstp-admin backup`: a base backup of both clusters now.
///
/// # Errors
///
/// [`Fail::Waits`] without an object store, [`Fail::Step`] when a backup
/// fails.
pub fn backup(layout: &Layout) -> Result<(), Fail> {
    if layout.cfg.backup.is_none() {
        return Err(Fail::Waits(
            "backups need \"backup\" in the configuration file, then fstp-admin setup",
        ));
    }
    let m = Manager::new(layout);
    for c in Cluster::ALL {
        let mut cmd = Command::new(layout.bin("fstp-backup"));
        let (k, v) = backup_env(layout, c);
        cmd.env(k, v).arg("base-backup");
        run_ok(&mut cmd, &m.log()).map_err(|e| Fail::Step("backup", e.into()))?;
        out(&[
            Part::T("  done     base backup of the "),
            Part::T(c.name()),
            Part::T(" database"),
        ]);
        publish_key_if_owed(layout, &m, c);
    }
    Ok(())
}

/// The mark of the key file last published for the second custodian, in
/// the agent's state directory (ADR-012 record of lane
/// m10/backup-followups, row "Publishing").
const PUBLISHED_MARK: &str = "key-published";

/// Whether the copy of `c`'s backup key file for the second custodian is
/// owed: the key file exists and the agent's `key-published` mark does
/// not hold its SHA-256 (ADR-012 record of lane m10/backup-followups, row
/// "Owed").
#[must_use]
pub fn key_copy_owed(layout: &Layout, c: Cluster) -> bool {
    let Ok(key) = std::fs::read(layout.creds(&format!("backup-{}", c.name())).join(KEY_FILE))
    else {
        return false;
    };
    let want = format!("{}\n", crate::pki::hex(&fstp_crypto::sha256(&key)));
    std::fs::read_to_string(layout.backup_state(c).join(PUBLISHED_MARK)).map_or(true, |m| m != want)
}

/// Sends the copy of `c`'s backup key file for the second custodian with
/// `fstp-backup publish-key` when it is owed. A failure is reported and
/// does not fail the caller: the copy stays owed, and `status` names it
/// (ADR-028 record of lane `m10/backup-followups`, row "The custodian's
/// key copy").
fn publish_key_if_owed(layout: &Layout, m: &Manager, c: Cluster) {
    if !key_copy_owed(layout, c) {
        return;
    }
    let mut cmd = Command::new(layout.bin("fstp-backup"));
    let (k, v) = backup_env(layout, c);
    cmd.env(k, v).arg("publish-key");
    match run_ok(&mut cmd, &m.log()) {
        Ok(()) => out(&[
            Part::T("  done     the backup key copy of the "),
            Part::T(c.name()),
            Part::T(" database for the custodian"),
        ]),
        Err(e) => {
            crate::fail::report(&Fail::Step("custodian key copy", e.into()));
            out(&[Part::T(
                "  The copy stays owed. fstp-admin backup sends it again.",
            )]);
        }
    }
}

/// The time of the newest base backup of `c`, from the agent's index.
#[must_use]
pub fn last_backup(layout: &Layout, c: Cluster) -> Option<i64> {
    let text = std::fs::read_to_string(layout.backup_state(c).join("base-backups.index")).ok()?;
    let line = text.lines().last()?;
    line.split_whitespace().nth(2)?.parse().ok()
}

/// The exit status of `fstp-backup restore` when the archive holds no
/// change after the target (ADR-012 record of lane `m10/backup-pitr`).
pub const ARCHIVE_ENDS_FIRST: i32 = 3;

/// How long a restored cluster may take to replay and promote.
const PROMOTION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3600);

/// The completion times of the base backups of `c`, from the agent's
/// index, in line order.
#[must_use]
pub fn backup_times(layout: &Layout, c: Cluster) -> Vec<u64> {
    std::fs::read_to_string(layout.backup_state(c).join("base-backups.index"))
        .map(|t| crate::pitr::index_times(&t))
        .unwrap_or_default()
}

/// Checks the target `t` against the clock and the base backups of both
/// clusters (ADR-028 record of lane `m10/backup-pitr`, row "Refusals").
///
/// # Errors
///
/// [`Fail::Time`] with the reason.
pub fn check_target(layout: &Layout, t: u64, now: u64) -> Result<(), Fail> {
    if t > now {
        return Err(Fail::Time(TimeRefusal::Future));
    }
    // Each cluster needs a base backup that finished before the target,
    // so the oldest usable time is the later of the two oldest backups.
    let mut first_ok = 0u64;
    for c in Cluster::ALL {
        let Some(oldest) = backup_times(layout, c).into_iter().min() else {
            return Err(Fail::Time(TimeRefusal::NoBackup));
        };
        first_ok = first_ok.max(oldest.saturating_add(1));
    }
    if t < first_ok {
        return Err(Fail::Time(TimeRefusal::BeforeOldest(first_ok)));
    }
    Ok(())
}

/// Prints the window a restore to `t` loses and what the witness makes of
/// it, and asks for `yes` (ADR-012 record of lane `m10/backup-pitr`, "What
/// a restored cell does at the witness").
fn confirm_loss(t: u64, now: u64) -> Result<(), Fail> {
    let (from, to) = (crate::pitr::format_time(t), crate::pitr::format_time(now));
    out(&[
        Part::T("Restoring to "),
        Part::Name(&from),
        Part::T(" loses every change from then until now, "),
        Part::Name(&to),
        Part::T(", in both databases."),
    ]);
    out(&[Part::T(
        "The audit witness holds receipts for the entries of that window. fstp-admin declares the restore at the witness, so the cell and the vault start again.",
    )]);
    out(&[Part::T(
        "The lost window stays in the audit log. Tenant admins see it on the System page and are asked to acknowledge it.",
    )]);
    out(&[Part::T(
        "Both databases are restored, or neither, and the current ones are kept beside them.",
    )]);
    match crate::say::ask("Type yes to go on: ").as_deref() {
        Some("yes") => Ok(()),
        _ => Err(Fail::Time(TimeRefusal::NotConfirmed)),
    }
}

/// Waits until cluster `c` has finished its recovery and promoted, then
/// resets the recovery settings, so no later standby inherits them
/// (ADR-028 record of lane `m10/backup-pitr`, row "Start").
fn await_promotion(layout: &Layout, c: Cluster) -> Result<(), Fail> {
    let begun = std::time::Instant::now();
    loop {
        match crate::pg::psql(
            layout,
            c,
            "postgres",
            "SELECT pg_is_in_recovery();\n",
            "the recovery check",
        ) {
            Ok(s) if s == "f" => break,
            _ if begun.elapsed() > PROMOTION_TIMEOUT => {
                return Err(Fail::Step(
                    "restore",
                    Cause::Run(RunFail::NotReady(crate::pg::service(layout, c).name)),
                ));
            }
            _ => std::thread::sleep(std::time::Duration::from_secs(5)),
        }
    }
    crate::pg::psql(
        layout,
        c,
        "postgres",
        "ALTER SYSTEM RESET restore_command;\nALTER SYSTEM RESET recovery_target;\n\
         ALTER SYSTEM RESET recovery_target_time;\nALTER SYSTEM RESET recovery_target_timeline;\n\
         ALTER SYSTEM RESET recovery_target_action;\nALTER SYSTEM RESET hot_standby;\n\
         SELECT pg_reload_conf();\n",
        "the reset of the recovery settings",
    )
    .map_err(|e| Fail::Step("restore", e.into()))?;
    Ok(())
}

/// The arguments of `fstp-backup restore` for `fresh` and `target`.
#[must_use]
pub fn restore_args(fresh: &Path, target: Option<u64>) -> Vec<std::ffi::OsString> {
    let mut a: Vec<std::ffi::OsString> = vec!["restore".into(), fresh.into()];
    if let Some(t) = target {
        a.push("--to".into());
        a.push(t.to_string().into());
    }
    a
}

/// `fstp-admin restore [--to <time>]`: both clusters to the newest point,
/// or to the time `target` (ADR-028 records of lanes L27 and
/// `m10/backup-pitr`). With the services stopped, the witness store is
/// rebuilt from its copies where it is missing or behind (ADR-012 record
/// of lane m10/witness-copy), then both clusters are
/// restored and checked in fresh directories. Only when both succeed are
/// both swapped in, and the old ones stay beside them. Then each restored
/// cluster promotes, each process keeps the newest copy of its keys that
/// opens, both audit chains are declared at the witness (ADR-012
/// record of lane `m10/declared-restore`), the services start, and a fresh base backup of both runs.
///
/// # Errors
///
/// [`Fail::Time`] for a refused target, [`Fail::Step`] when a part fails.
/// When a restore fails, nothing is swapped and the services start again.
/// When the keys of the vault or the cell open from no copy, the services
/// stay stopped.
pub fn restore(layout: &Layout, target: Option<u64>) -> Result<(), Fail> {
    if layout.cfg.backup.is_none() {
        return Err(Fail::Waits(
            "restore needs \"backup\" in the configuration file",
        ));
    }
    if let Some(t) = target {
        let now = u64::try_from(crate::pki::now()).unwrap_or(0);
        check_target(layout, t, now)?;
        confirm_loss(t, now)?;
    }
    let m = Manager::new(layout);
    // ADR-012 record of lane m10/witness-copy: the witness stops too, so
    // its store can be rebuilt before it starts again.
    for s in [
        stack::edge(layout),
        stack::cell(layout),
        stack::vault(layout),
        stack::witness(layout),
    ] {
        m.stop(&s).map_err(|e| Fail::Step("restore", e.into()))?;
    }
    // Decided by Daniel on 2026-11-24: the witness store comes back from
    // its copies before the databases, so a failure changes no database.
    if let Err(e) = crate::witness::rebuild(layout) {
        start(layout)?;
        return Err(e);
    }
    let stamp = crate::pki::now();
    let fresh = |c: Cluster| {
        layout
            .pg_data(c)
            .with_file_name(format!("{}.restored-{stamp}", c.name()))
    };
    // Decided by Daniel on 2026-11-24: both clusters are restored and
    // checked first, and neither is swapped unless both succeed.
    let mut failed = None;
    for c in Cluster::ALL {
        m.stop(&crate::pg::service(layout, c))
            .map_err(|e| Fail::Step("restore", e.into()))?;
        let mut cmd = Command::new(layout.bin("fstp-backup"));
        let (k, v) = backup_env(layout, c);
        cmd.env(k, v).args(restore_args(&fresh(c), target));
        match run_logged(&mut cmd, &m.log()) {
            Ok(Some(0)) => out(&[
                Part::T("  done     restored and checked the "),
                Part::T(c.name()),
                Part::T(" database in "),
                Part::P(&fresh(c)),
            ]),
            Ok(Some(ARCHIVE_ENDS_FIRST)) => {
                failed = Some(Fail::Time(TimeRefusal::ArchiveEndsFirst));
                break;
            }
            Ok(code) => {
                failed = Some(Fail::Step(
                    "restore",
                    Cause::Run(RunFail::Exit(layout.bin("fstp-backup"), code)),
                ));
                break;
            }
            Err(e) => {
                failed = Some(Fail::Step("restore", e.into()));
                break;
            }
        }
    }
    if let Some(f) = failed {
        for c in Cluster::ALL {
            let _ = std::fs::remove_dir_all(fresh(c));
        }
        out(&[Part::T(
            "  skipped  the swap: the current databases are unchanged",
        )]);
        start(layout)?;
        return Err(f);
    }
    // ADR-012 record of lane m10/backup-followups: the current TLS files go
    // into each restored directory before PostgreSQL starts on it.
    let tls = renew_server_tls_if_due(layout).and_then(|()| {
        Cluster::ALL
            .iter()
            .try_for_each(|c| put_current_tls(layout, *c, &fresh(*c)))
    });
    if let Err(e) = tls {
        for c in Cluster::ALL {
            let _ = std::fs::remove_dir_all(fresh(c));
        }
        start(layout)?;
        return Err(e);
    }
    if let Err(e) = swap_both(layout, &m, stamp, &fresh) {
        start(layout)?;
        return Err(e);
    }
    restore_keystores(layout, &m)?;
    // ADR-012 record of lane m10/declared-restore: both chains are
    // declared at the witness before the services start, so the cell and
    // the vault start and report the lost window. A failed declaration is
    // reported after the start, and the services then refuse as before.
    let declared = declare_restore(layout, &m);
    match &declared {
        Ok(()) => out(&[Part::T(
            "  done     declared the restore of both audit logs at the witness",
        )]),
        Err(e) => crate::fail::report(e),
    }
    let started = start(layout);
    // Decided by Daniel on 2026-11-24: a fresh base backup of both
    // clusters right after the restore, so the next restore starts on the
    // new timeline.
    match backup(layout) {
        Ok(()) => {}
        Err(e) => {
            crate::fail::report(&e);
            out(&[Part::T(
                "  The restore stands. Run fstp-admin backup once the cause is fixed.",
            )]);
        }
    }
    started.and(declared)
}

/// Declares the restore of both chains at the stopped witness (ADR-012
/// record of lane m10/declared-restore, [`crate::declare`]).
fn declare_restore(layout: &Layout, m: &Manager) -> Result<(), Fail> {
    let mut state = crate::state::State::load(&layout.admin_dir().join("state"))
        .map_err(|_| Fail::Step("declare restore", Cause::Io))?;
    let cell = crate::setup::cell_id(&mut state)?;
    crate::declare::declare_both(layout, m, &cell)
}

/// The TLS files of a cluster, in `<data>/tls` (ADR-028 "PostgreSQL"):
/// the server certificate, its expiry sidecar, its key and the CA.
pub const TLS_FILES: [&str; 4] = ["server.pem", "server.pem.expires", "server.key", "ca.pem"];

/// Puts the live TLS files of cluster `c` into the restored data
/// directory `restored`, before any PostgreSQL starts on it (ADR-012
/// record of lane m10/backup-followups, rows "TLS files after a restore"
/// and "TLS files in the drill"). A base backup carries the files of its
/// own time, and the cell and the vault pin the live server key (I-83).
///
/// # Errors
///
/// [`Fail::Step`] when a live file is missing or a copy fails.
pub fn put_current_tls(layout: &Layout, c: Cluster, restored: &Path) -> Result<(), Fail> {
    let step = "restore";
    let live = layout.pg_data(c).join("tls");
    let to = restored.join("tls");
    std::fs::create_dir_all(&to).map_err(io(step))?;
    for name in TLS_FILES {
        let bytes = std::fs::read(live.join(name)).map_err(io(step))?;
        write_atomic(&to.join(name), &bytes, 0o600).map_err(io(step))?;
    }
    out(&[
        Part::T("  done     put the current TLS files into the restored "),
        Part::T(c.name()),
        Part::T(" database"),
    ]);
    Ok(())
}

/// Before a restore copies the live TLS files: when a live server
/// certificate needs a new issue (`pki::needs_issue`), issues it from the
/// database CA, records its key and writes the service configurations
/// again, as `renew` does, so the restored directories get current files
/// (ADR-028 record of lane `m10/backup-followups`, row "TLS after a
/// restore"). The services are stopped then, and the restore starts them.
fn renew_server_tls_if_due(layout: &Layout) -> Result<(), Fail> {
    let due = Cluster::ALL
        .iter()
        .any(|c| crate::pki::needs_issue(&layout.pg_data(*c).join("tls").join("server.pem")));
    if !due {
        return Ok(());
    }
    let mut state = State::load(&layout.admin_dir().join("state")).map_err(io("restore"))?;
    let cell = crate::setup::cell_id(&mut state)?;
    let cas = crate::setup::cas(layout)?;
    let facts = crate::setup::credentials(layout, &mut state, &cas, cell)?;
    crate::setup::write_configs(layout, &facts)?;
    out(&[Part::T(
        "  done     renewed the database server certificates before the restore",
    )]);
    Ok(())
}

/// Swaps both fresh directories in, each live one moved to
/// `<cluster>.before-restore-<stamp>`. When a rename fails, every swap
/// done so far is put back.
fn swap_both(
    layout: &Layout,
    m: &Manager,
    stamp: i64,
    fresh: &dyn Fn(Cluster) -> PathBuf,
) -> Result<(), Fail> {
    let old = |c: Cluster| {
        layout
            .pg_data(c)
            .with_file_name(format!("{}.before-restore-{stamp}", c.name()))
    };
    let mut done: Vec<Cluster> = Vec::new();
    for c in Cluster::ALL {
        let data = layout.pg_data(c);
        let swapped = std::fs::rename(&data, old(c)).is_ok()
            && (std::fs::rename(fresh(c), &data).is_ok() || {
                let _ = std::fs::rename(old(c), &data);
                false
            });
        if !swapped {
            for d in done.iter().rev() {
                let _ = std::fs::rename(layout.pg_data(*d), fresh(*d));
                let _ = std::fs::rename(old(*d), layout.pg_data(*d));
            }
            return Err(Fail::Step("restore", Cause::Io));
        }
        done.push(c);
    }
    for c in Cluster::ALL {
        let data = layout.pg_data(c);
        if layout.cfg.services == Services::Systemd {
            let mut g = Command::new("chown");
            g.arg("-R").arg("postgres:postgres").arg(&data);
            run_ok(&mut g, &m.log()).map_err(|e| Fail::Step("restore", e.into()))?;
        }
        out(&[
            Part::T("  done     swapped in the "),
            Part::T(c.name()),
            Part::T(" database; the old one is in "),
            Part::P(&old(c)),
        ]);
    }
    Ok(())
}

/// After the clusters are restored (ADR-028 record of lane L27, row
/// "Restore"): starts the two clusters, then runs `fstp-vault
/// restore-keystore` and `fstp-cell restore-keystore`, in start order,
/// with both services stopped. Each keeps the newest copy of its keys that
/// opens: the restored database or the newest keystore snapshot.
///
/// # Errors
///
/// [`Fail::Refused`] naming the service whose keys open from no copy.
/// The services stay stopped then.
fn restore_keystores(layout: &Layout, m: &Manager) -> Result<(), Fail> {
    for c in Cluster::ALL {
        m.ensure(&crate::pg::service(layout, c))
            .map_err(|e| Fail::Step("restore", e.into()))?;
        // ADR-028 record of lane `m10/backup-pitr`: the restored cluster
        // replays and promotes before any key step reads it.
        await_promotion(layout, c)?;
    }
    // After `restore-keys` (ADR-028 record of lane `m10/guard-key`, part
    // 2): each held entry is released with the epochs of the restored
    // databases, before any keystore opens.
    crate::custodian::release_held(layout, m)?;
    for (step, user, bin, env, service) in [
        (
            "fstp-vault restore-keystore",
            stack::VAULT_USER,
            "fstp-vault",
            "FSTP_VAULT_CONFIG",
            "vault",
        ),
        (
            "fstp-cell restore-keystore",
            stack::CELL_USER,
            "fstp-cell",
            "FSTP_CELL_CONFIG",
            "cell",
        ),
    ] {
        let mut cmd = stack::as_user(layout, user, &layout.bin(bin));
        cmd.env(env, layout.config_file(service))
            .arg("restore-keystore");
        match crate::svc::run_logged(&mut cmd, &m.log())
            .map_err(|e| Fail::Step("restore", e.into()))?
        {
            Some(0) => out(&[
                Part::T("  done     checked the keys of the "),
                Part::T(service),
            ]),
            code => return Err(Fail::Refused(step, code)),
        }
    }
    Ok(())
}

/// The copy id in a key copy's clear header: bytes 26 to 41 (ADR-004
/// record of lane L16).
#[must_use]
pub fn copy_id(bytes: &[u8]) -> Option<String> {
    match bytes.get(0..4) {
        Some(b"FKX1") => bytes.get(26..42).map(crate::pki::hex),
        // A guarded copy (ADR-028 record of lane `m10/guard-key`).
        Some(b"FGC1") => bytes.get(12..28).map(crate::pki::hex),
        _ => None,
    }
}

/// `fstp-admin backup-keys <dest>`: one passphrase-sealed copy per custody
/// entry, each with its copy id in `<entry>.fkx.id`, and the sealed key
/// files beside them (ADR-028 "Simple key backup", lane L16). Each entry
/// stops for its copy and starts again.
///
/// # Errors
///
/// [`Fail::Waits`] in direct mode or when `fstp-keyd` has no `export` yet.
pub fn backup_keys(layout: &Layout, state: &mut State, dest: &Path) -> Result<(), Fail> {
    if layout.cfg.custody_simulator.is_some() {
        return Err(Fail::Waits(
            "the custody simulator keeps its keys in memory, so there is nothing to copy",
        ));
    }
    // Decided by Daniel on 2026-11-23: every copy is guarded by the
    // second custodian (ADR-028 record of lane `m10/guard-key`).
    if layout.cfg.custodian.is_none() && layout.cfg.services == crate::config::Services::Systemd {
        return Err(Fail::Waits(
            "the second custodian: run fstp-admin pair-custodian <host> first",
        ));
    }
    let step = "key copy";
    std::fs::create_dir_all(dest).map_err(io(step))?;
    let m = Manager::new(layout);
    for e in Entry::ALL {
        let file = dest.join(format!("{}.fkx", e.name()));
        if file.exists() {
            return Err(Fail::Missing(
                file,
                "nothing: pick an empty directory for the copy",
            ));
        }
        let services = stack::keyd(layout, e);
        for s in &services {
            m.stop(s).map_err(|c| Fail::Step(step, c.into()))?;
        }
        let creds = layout.admin_dir().join("keyd-credential");
        let _ = std::fs::remove_dir_all(&creds);
        let pass = std::fs::read(layout.keyd_passphrase(e)).map_err(io(step));
        let r = pass.and_then(|p| {
            write_atomic(&creds.join(fstp_keyd_credential()), &p, 0o600).map_err(io(step))?;
            let mut c = Command::new(layout.bin("fstp-keyd"));
            if let Some((host, port)) = &layout.cfg.custodian {
                crate::custodian::stage_credentials(layout, e, &creds).map_err(io(step))?;
                c.env(
                    "FSTP_KEYD_GUARD",
                    crate::custodian::target_text(host, *port),
                )
                .env("FSTP_KEYD_GUARD_ENTRY", e.name());
            }
            c.env("CREDENTIALS_DIRECTORY", &creds)
                .arg("export")
                .arg(layout.keyd_volume(e))
                .arg(&file);
            run_logged(&mut c, &m.log()).map_err(|e| Fail::Step(step, e.into()))
        });
        let _ = std::fs::remove_dir_all(&creds);
        for s in &services {
            m.ensure(s).map_err(|c| Fail::Step(step, c.into()))?;
        }
        match r? {
            Some(0) => {}
            Some(2) => {
                return Err(Fail::Waits(
                    "the installed fstp-keyd has no export command yet (lane L16)",
                ));
            }
            code => {
                return Err(Fail::Step(
                    step,
                    Cause::Run(RunFail::Exit(layout.bin("fstp-keyd"), code)),
                ));
            }
        }
        let bytes = std::fs::read(&file).map_err(io(step))?;
        let id = copy_id(&bytes).ok_or(Fail::Step(step, Cause::Io))?;
        write_atomic(
            &dest.join(format!("{}.fkx.id", e.name())),
            format!("{id}\n").as_bytes(),
            0o600,
        )
        .map_err(io(step))?;
        out(&[
            Part::T("  done     copy of the "),
            Part::T(e.name()),
            Part::T(" entry, id "),
            Part::Name(&id),
        ]);
    }
    for (from, to) in [
        (
            layout.creds("cell").join("cell-keys.sealed"),
            "cell-keys.sealed",
        ),
        (
            layout.creds("witness").join("receipt.key"),
            "witness-receipt.key",
        ),
        (
            layout.creds("backup-app").join("cluster-backup.key"),
            "backup-app.key",
        ),
        (
            layout.creds("backup-vault").join("cluster-backup.key"),
            "backup-vault.key",
        ),
    ] {
        if let Ok(b) = std::fs::read(&from) {
            write_atomic(&dest.join(to), &b, 0o600).map_err(io(step))?;
        }
    }
    state.mark("keys-copied").map_err(io(step))?;
    state
        .set(
            crate::status::KEYS_COPIED_AT,
            &crate::pki::now().to_string(),
        )
        .map_err(io(step))?;
    out(&[
        Part::T("The copy is in "),
        Part::P(dest),
        Part::T(". It opens only with the passphrases in "),
        Part::P(&layout.etc("keyd")),
        Part::T(": keep those apart from the copy."),
    ]);
    Ok(())
}

fn fstp_keyd_credential() -> &'static str {
    "fstp-keyd-passphrase"
}

fn sidecars(layout: &Layout) -> String {
    let mut out = String::new();
    for dir in ["cell", "vault", "witness", "edge"] {
        if let Ok(rd) = std::fs::read_dir(layout.creds(dir)) {
            let mut names: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
            names.sort();
            for p in names {
                if p.extension().is_some_and(|x| x == "expires") {
                    out.push_str(&std::fs::read_to_string(&p).unwrap_or_default());
                }
            }
        }
    }
    out
}

/// `fstp-admin renew`: issues again every certificate near its end,
/// restarts the services that read them, and updates the host's route
/// with the new pins (ADR-028 "Certificates").
///
/// # Errors
///
/// [`Fail::Step`] naming the part that failed.
pub fn renew(layout: &Layout) -> Result<(), Fail> {
    let mut state = State::load(&layout.admin_dir().join("state")).map_err(io("renew"))?;
    let cell = crate::setup::cell_id(&mut state)?;
    let cas = crate::setup::cas(layout)?;
    let before = sidecars(layout);
    let spki_before = (
        state.get("server-spki.app").map(str::to_owned),
        state.get("server-spki.vault").map(str::to_owned),
    );
    let facts = crate::setup::credentials(layout, &mut state, &cas, cell)?;
    crate::setup::write_configs(layout, &facts)?;
    let spki_after = (
        state.get("server-spki.app").map(str::to_owned),
        state.get("server-spki.vault").map(str::to_owned),
    );
    let m = Manager::new(layout);
    // ADR-028 record of lane `m10/guard-key`: the guard client
    // certificates renew with the others, and each fstp-keyd entry reads
    // its new one at a restart.
    if layout.cfg.services == crate::config::Services::Systemd
        && crate::custodian::ensure_clients(layout)?
    {
        for e in crate::custodian::guarded_entries() {
            for s in stack::keyd(layout, e) {
                m.stop(&s).map_err(|e| Fail::Step("renew", e.into()))?;
                m.ensure(&s).map_err(|e| Fail::Step("renew", e.into()))?;
            }
        }
        out(&[Part::T(
            "  done     custodian certificates renewed and key custody restarted",
        )]);
    }
    if before == sidecars(layout) && spki_before == spki_after {
        out(&[Part::T("  skipped  certificates (none near its end)")]);
    } else {
        let mut services = Vec::new();
        if spki_before != spki_after {
            services.extend(Cluster::ALL.iter().map(|c| crate::pg::service(layout, *c)));
        }
        services.extend([
            stack::witness(layout),
            stack::vault(layout),
            stack::cell(layout),
        ]);
        if crate::route::ROUTE_FEED {
            services.push(stack::control(layout));
        }
        services.push(stack::edge(layout));
        for s in services.iter().rev() {
            m.stop(s).map_err(|e| Fail::Step("renew", e.into()))?;
        }
        for s in &services {
            m.ensure(s).map_err(|e| Fail::Step("renew", e.into()))?;
        }
        out(&[Part::T(
            "  done     certificates renewed and services restarted",
        )]);
    }
    crate::route::ensure_own(layout, &m, cell)?;
    Ok(())
}

/// `fstp-admin start`: every service in order.
///
/// # Errors
///
/// [`Fail::Step`] naming the service that did not start.
pub fn start(layout: &Layout) -> Result<(), Fail> {
    let m = Manager::new(layout);
    for s in stack::all(layout) {
        m.ensure(&s).map_err(|e| Fail::Step("start", e.into()))?;
    }
    Ok(())
}

/// `fstp-admin stop`: every service in reverse order.
///
/// # Errors
///
/// [`Fail::Step`] naming the service that did not stop.
pub fn stop(layout: &Layout) -> Result<(), Fail> {
    let m = Manager::new(layout);
    for s in stack::all(layout).iter().rev() {
        m.stop(s).map_err(|e| Fail::Step("stop", e.into()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// I-81, ADR-012 record of lane m10/backup-followups, row "Database
    /// restart": the services restarted after a database cluster restart
    /// are the vault, the cell and the edge, in start order, each after the
    /// units it needs.
    #[test]
    fn adr012_bf_database_clients_restart_in_start_order() {
        let cfg = r#"{"domain":"grants.example.eu","operator_email":"admin@example.eu",
            "mail":{"relay":"smtp.example.eu","username":"cell"},"services":"direct"}"#;
        let layout =
            Layout::new(crate::config::decode(cfg.as_bytes()).unwrap_or_else(|_| panic!("config")));
        let names: Vec<String> = database_clients(&layout)
            .into_iter()
            .map(|s| s.name)
            .collect();
        assert_eq!(names, ["fstp-vault", "fstp-cell", "fstp-edge"]);
        let clients = database_clients(&layout);
        assert!(
            clients[0]
                .after
                .contains(&crate::pg::service(&layout, Cluster::Vault).name)
        );
        assert!(
            clients[1]
                .after
                .contains(&crate::pg::service(&layout, Cluster::App).name)
        );
        assert!(clients[1].after.iter().any(|a| a == "fstp-vault"));
        assert!(clients[2].after.iter().any(|a| a == "fstp-cell"));
    }

    /// I-83, ADR-012 record of lane m10/backup-followups, row "TLS files
    /// after a restore": the live server certificate, its expiry, its key
    /// and the CA replace the ones a restored directory carries from backup
    /// time, with mode 0600. A missing live file stops the step, so no
    /// restored directory starts with old files.
    #[test]
    fn adr012_bf_restore_puts_the_live_tls_files_in_place() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = std::env::temp_dir().join(format!(
            "fstp-admin-bf-tls-{}",
            crate::pki::random_hex(8).unwrap_or_default()
        ));
        let cfg = format!(
            r#"{{"domain":"grants.example.eu","operator_email":"admin@example.eu",
            "mail":{{"relay":"smtp.example.eu","username":"cell"}},
            "services":"direct",
            "paths":{{"state":"{0}/state","etc":"{0}/etc","bin":"{0}/bin"}}}}"#,
            root.display()
        );
        let layout =
            Layout::new(crate::config::decode(cfg.as_bytes()).unwrap_or_else(|_| panic!("config")));
        for c in Cluster::ALL {
            let live = layout.pg_data(c).join("tls");
            let restored = root.join(format!("{}.restored", c.name()));
            std::fs::create_dir_all(&live).unwrap();
            std::fs::create_dir_all(restored.join("tls")).unwrap();
            for name in TLS_FILES {
                std::fs::write(live.join(name), format!("current {name}")).unwrap();
                std::fs::write(restored.join("tls").join(name), format!("old {name}")).unwrap();
            }
            put_current_tls(&layout, c, &restored).unwrap();
            for name in TLS_FILES {
                let p = restored.join("tls").join(name);
                assert_eq!(
                    std::fs::read_to_string(&p).unwrap(),
                    format!("current {name}")
                );
                assert_eq!(
                    std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
            std::fs::remove_file(live.join("server.key")).unwrap();
            assert!(put_current_tls(&layout, c, &restored).is_err());
        }
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// ADR-028 record of lane `m10/backup-pitr`: `restore` takes an
    /// optional `--to <time>`. A malformed time is refused before any
    /// configuration is read, with exit status 2. The target reaches
    /// `fstp-backup restore` as Unix seconds after the other arguments.
    #[test]
    fn adr028_pitr_restore_takes_an_optional_target() {
        let s = |v: &[&str]| v.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>();
        for bad in ["2026-11-24", "2026-11-24T10:00:00+01:00", "yesterday"] {
            let args = s(&["--config", "/nonexistent/fstp.json", "restore", "--to", bad]);
            assert_eq!(crate::main_with(&args), crate::fail::USAGE, "{bad}");
        }
        assert_eq!(
            restore_args(Path::new("/x/app.restored-1"), Some(1_795_514_400)),
            vec![
                std::ffi::OsString::from("restore"),
                "/x/app.restored-1".into(),
                "--to".into(),
                "1795514400".into()
            ]
        );
        assert_eq!(restore_args(Path::new("/x/d"), None).len(), 2);
    }

    /// ADR-028 record of lane `m10/backup-pitr`, row "Refusals": a time in
    /// the future, a time not after the oldest backup of either database,
    /// and a database with no backup are refused, each with its reason.
    /// The earliest time that works is the later of the two oldest
    /// backups, plus one second.
    #[test]
    fn adr012_pitr_time_refusals_name_the_earliest_time() {
        let tag = fstp_crypto::random_array::<6>().unwrap_or([7; 6]);
        let dir = std::env::temp_dir().join(format!(
            "fstp-pitr-admin-{}",
            tag.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ));
        let cfg = format!(
            r#"{{"domain":"grants.example.eu","operator_email":"admin@example.eu",
            "mail":{{"relay":"smtp.example.eu","username":"cell"}},
            "services":"direct",
            "paths":{{"state":"{s}","etc":"{e}"}}}}"#,
            s = dir.join("state").display(),
            e = dir.join("etc").display(),
        );
        let layout = Layout::new(crate::config::decode(cfg.as_bytes()).expect("config"));
        let now = 1_795_514_400;
        assert_eq!(
            check_target(&layout, now, now),
            Err(Fail::Time(TimeRefusal::NoBackup))
        );
        let id = "ab".repeat(16);
        for (c, times) in [(Cluster::App, [100u64, 300]), (Cluster::Vault, [200, 400])] {
            let d = layout.backup_state(c);
            std::fs::create_dir_all(&d).expect("dir");
            let text: String = times.iter().map(|t| format!("{id} {id} {t} 5\n")).collect();
            std::fs::write(d.join("base-backups.index"), text).expect("index");
        }
        assert_eq!(backup_times(&layout, Cluster::Vault), vec![200, 400]);
        assert_eq!(
            check_target(&layout, now + 1, now),
            Err(Fail::Time(TimeRefusal::Future))
        );
        assert_eq!(
            check_target(&layout, 200, now),
            Err(Fail::Time(TimeRefusal::BeforeOldest(201)))
        );
        assert_eq!(check_target(&layout, 201, now), Ok(()));
        assert_eq!(check_target(&layout, now, now), Ok(()));
        assert_eq!(Fail::Time(TimeRefusal::BeforeOldest(201)).code(), 2);
        assert_eq!(Fail::Time(TimeRefusal::ArchiveEndsFirst).code(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ADR-004 record of lane L16: the copy id stands in bytes 26 to 41 of
    /// the clear header.
    #[test]
    fn adr004_l16_copy_id_is_read_from_the_header() {
        let mut h = b"FKX1".to_vec();
        h.extend_from_slice(&[0u8; 22]);
        h.extend_from_slice(&[0xab; 16]);
        h.extend_from_slice(&[0u8; 8]);
        assert_eq!(copy_id(&h).as_deref(), Some("ab".repeat(16).as_str()));
        assert_eq!(copy_id(b"XXXX"), None);
    }
}
