//! `fstp-admin status`: one screen with what runs, what is unhealthy, and
//! the single next thing to do (ADR-028 "Status").

use fstp_obs::host_status::{
    self, HostStatus, Next as HostNext, PartState, Parts, RouteState, WalArchive,
};

use crate::fail::{Cause, Fail, OK, UNHEALTHY};
use crate::layout::{Cluster, Layout};
use crate::say::{Part, out};
use crate::stack;
use crate::state::State;
use crate::svc::{Manager, is_ready};

/// The next thing to do, most urgent first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Next {
    /// Setup has not finished.
    RunSetup,
    /// A service is down.
    StartService,
    /// The second custodian does not answer, or a guard rotation is owed:
    /// erasures wait (ADR-028 record of lane `m10/guard-key`).
    Custodian,
    /// No second custodian is paired, or its pairing nears its end.
    PairCustodian,
    /// The route's pins do not match the current certificates.
    RenewRoute,
    /// A certificate is near its end.
    Renew,
    /// The origin certificate is self-signed.
    PublicCertificate,
    /// No object store is configured.
    ConfigureBackups,
    /// The WAL archive fails, or a finished segment waits too long for
    /// its upload (ADR-012 record of lane m10/backup-health).
    WalArchive,
    /// The copy of the witness store fails or is late (ADR-012 record of
    /// lane m10/witness-copy).
    WitnessCopy,
    /// The newest base backup is old or missing.
    Backup,
    /// No restore drill passed in 35 days, or the last one failed (ADR-012
    /// record of lane m10/backup-health).
    RestoreDrill,
    /// A fresh copy is owed to the second custodian: the last try failed
    /// (ADR-028 record of lane `m10/guard-key`, part 2).
    CustodianCopy,
    /// The copy of a cluster's backup key file for the second custodian is
    /// not in the object stores yet (ADR-012 record of lane
    /// m10/backup-followups, row "Owed").
    CustodianKeyCopy,
    /// A keystore snapshot failed, or none verified in a day and a half.
    KeystoreSnapshot,
    /// The web admins must enrol and invite the second admin first.
    WebAdmins,
    /// The host admin verifies the admins in person.
    VerifyAdmins,
    /// The keys were never copied off the host.
    CopyKeys,
    /// Nothing.
    Nothing,
}

/// The facts `status` decides on.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Findings {
    /// Setup finished.
    pub setup_done: bool,
    /// Every service runs and is ready.
    pub all_running: bool,
    /// The route is current, if it could be read.
    pub route_current: Option<bool>,
    /// The fewest days a certificate has left.
    pub min_days: Option<i64>,
    /// The origin certificate is self-signed.
    pub self_signed: bool,
    /// Backups are configured.
    pub backups: bool,
    /// Age in hours of the oldest newest-backup over both clusters.
    pub backup_age_hours: Option<i64>,
    /// The tenant admins `fstp-admin` last read.
    pub admins: Vec<String>,
    /// How many of them are verified.
    pub verified: usize,
    /// The keys were copied off the host.
    pub keys_copied: bool,
    /// When the newest key copy ran, Unix seconds, if recorded.
    pub keys_copied_at: Option<i64>,
    /// When `fstp-admin erase-identity` last erased an identity in the
    /// vault, Unix seconds (ADR-028 record of lane L20).
    pub vault_erased_at: Option<i64>,
    /// Age in hours of the older of the two processes' last verified
    /// keystore snapshot, if both verified one (ADR-028 record of lane
    /// L27).
    pub snapshot_age_hours: Option<i64>,
    /// The last keystore snapshot of a process failed.
    pub snapshot_failed: bool,
    /// The link to the second custodian, on a systemd host (ADR-028
    /// record of lane `m10/guard-key`). `None` where it does not apply.
    pub custodian: Option<crate::custodian::Link>,
    /// Days until the custodian's server certificate ends, if paired.
    pub pairing_days: Option<i64>,
    /// The state of the WAL archive, the worse of the two clusters
    /// (ADR-012 record of lane m10/backup-health).
    pub wal_archive: WalArchive,
    /// The older of the two clusters' last archived segments.
    pub wal_last: Option<i64>,
    /// The state of the witness store's copy (ADR-012 record of lane
    /// m10/witness-copy).
    pub witness_copy: WalArchive,
    /// When the witness store was last copied in full, Unix seconds.
    pub witness_copied: Option<i64>,
    /// The restore drill status file.
    pub drill: fstp_obs::drill_status::DrillStatus,
    /// A restore drill is due: none passed in 35 days, or the last one
    /// failed.
    pub drill_due: bool,
    /// The copy of a cluster's backup key file for the second custodian is
    /// owed: its `key-published` mark does not name the key file (ADR-012
    /// record of lane m10/backup-followups, row "Owed").
    pub custodian_key_owed: bool,
}

/// Whether the newest key copy is older than the last vault erasure, so
/// it still holds the erased key and the runbook asks for a new copy
/// (ADR-028 record of lane L20).
#[must_use]
pub fn key_copy_stale(f: &Findings) -> bool {
    f.vault_erased_at
        .is_some_and(|e| f.keys_copied_at.is_none_or(|c| c < e))
}

/// The single next thing to do.
#[must_use]
pub fn next(f: &Findings) -> Next {
    if !f.setup_done {
        Next::RunSetup
    } else if !f.all_running {
        Next::StartService
    } else if matches!(
        f.custodian,
        Some(crate::custodian::Link::Unreachable | crate::custodian::Link::Owed)
    ) {
        Next::Custodian
    } else if f.route_current == Some(false) {
        Next::RenewRoute
    } else if f.min_days.is_some_and(|d| d < 3) {
        Next::Renew
    } else if f.verified < 2 && f.admins.len() < 2 {
        Next::WebAdmins
    } else if f.verified < 2 {
        Next::VerifyAdmins
    } else if f.self_signed {
        Next::PublicCertificate
    } else if !f.backups {
        Next::ConfigureBackups
    } else if matches!(f.wal_archive, WalArchive::Failing | WalArchive::Late) {
        Next::WalArchive
    } else if matches!(f.witness_copy, WalArchive::Failing | WalArchive::Late) {
        Next::WitnessCopy
    } else if f.backup_age_hours.is_none_or(|h| h > 36) {
        Next::Backup
    } else if f.drill_due {
        Next::RestoreDrill
    } else if f.custodian == Some(crate::custodian::Link::CopyOwed) {
        Next::CustodianCopy
    } else if f.custodian_key_owed {
        Next::CustodianKeyCopy
    } else if f.snapshot_failed || f.snapshot_age_hours.is_none_or(|h| h > 36) {
        Next::KeystoreSnapshot
    } else if f.custodian == Some(crate::custodian::Link::Unpaired)
        || f.pairing_days
            .is_some_and(|d| d < crate::custodian::RENEW_PAIRING_BEFORE / 86_400)
    {
        Next::PairCustodian
    } else if !f.keys_copied || key_copy_stale(f) {
        Next::CopyKeys
    } else {
        Next::Nothing
    }
}

fn next_text(n: Next) -> &'static str {
    match n {
        Next::RunSetup => "run fstp-admin setup. It continues where it stopped.",
        Next::StartService => {
            "run fstp-admin start. If a service stays down, read its log: journalctl -u <its name>."
        }
        Next::Custodian => {
            "the second custodian does not answer, or a guard is still to be replaced, so erasures wait. Check that the custodian machine is on and reachable on port 7460 and that fstp-keyd-custodian runs there (systemctl status fstp-keyd-custodian), then run fstp-admin status again."
        }
        Next::PairCustodian => {
            "pair the second custodian: run fstp-admin pair-custodian <its host name>, copy the file it names to that machine and run fstp-admin custodian <file> there, then run fstp-admin setup here."
        }
        Next::RenewRoute => {
            "run fstp-admin renew. It puts the current certificate pins into the route."
        }
        Next::Renew => "run fstp-admin renew. A certificate ends within three days.",
        Next::PublicCertificate => {
            "browsers refuse the self-signed origin certificate. Get one for the domain and id.<domain> (for example with certbot), name it under \"tls\" in fstp.json, then run fstp-admin renew."
        }
        Next::ConfigureBackups => {
            "add \"backup\" with your object store to fstp.json, put its two key files in place, then run fstp-admin setup."
        }
        Next::WalArchive => {
            "the WAL archive does not keep up, so the backups miss the newest changes. Read the log of the database named above (journalctl -u fstp-postgres-app or fstp-postgres-vault) for the archive command's error, often the object store or its key files. Fix it, then run fstp-admin status."
        }
        Next::WitnessCopy => {
            "the audit witness's records are not reaching the object store, so a lost host would lose their history. Run fstp-admin witness-copy: it says what failed, often the object store or its key files. Its timer then tries every minute."
        }
        Next::Backup => "run fstp-admin backup. The newest backup is older than a day and a half.",
        Next::RestoreDrill => {
            "run fstp-admin drill. It restores both databases into a scratch copy and checks that they open. No drill passed in 35 days, or the last one failed: its line above names the step."
        }
        Next::CustodianCopy => {
            "the second custodian answers, but the fresh key copy after the last erasure did not reach it. fstp-keyd tries again every ten minutes. Check the free disk space on the custodian machine and its log (journalctl -u fstp-keyd-custodian), then run fstp-admin status again."
        }
        Next::CustodianKeyCopy => {
            "the copy of the backup key file for the second custodian is not in the object stores yet, so a restore on the custodian could not read the newest backups. Run fstp-admin backup, which sends it. If this stays, read admin/logs/fstp-admin.log for the object store's error, fix it, then run fstp-admin backup again."
        }
        Next::KeystoreSnapshot => {
            "the daily keystore snapshot failed or did not run. Read the log of fstp-cell and fstp-vault (journalctl -u <its name>), fix what it names, then run fstp-admin start: each service takes a snapshot a minute after it starts."
        }
        Next::WebAdmins => {
            "web admins: the first admin opens the invitation and enrols a passkey, then invites the second admin by email on Onboarding summary; the second admin opens the mailed link within 72 hours. Then the host admin runs fstp-admin verify."
        }
        Next::VerifyAdmins => {
            "host admin: check each admin's ID document in person, then run fstp-admin verify. It asks for the details of each admin listed above."
        }
        Next::CopyKeys => {
            "copy the keys off this host: fstp-admin backup-keys /media/usb/fstp-keys, and keep the passphrases apart. After an erasure, a new copy replaces the old one."
        }
        Next::Nothing => "nothing. Everything is in order.",
    }
}

fn min_days(layout: &Layout) -> Option<i64> {
    let now = crate::pki::now();
    let mut min: Option<i64> = None;
    for dir in ["cell", "vault", "witness", "edge"] {
        let Ok(rd) = std::fs::read_dir(layout.creds(dir)) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().is_some_and(|x| x == "expires")
                && let Some(at) = std::fs::read_to_string(&p)
                    .ok()
                    .and_then(|t| t.trim().parse::<i64>().ok())
            {
                let d = at.saturating_sub(now) / 86_400;
                min = Some(min.map_or(d, |m: i64| m.min(d)));
            }
        }
    }
    min
}

/// The keystore snapshot status of both processes (ADR-028 record of
/// lane L27): each one's `keystore-snapshot.status`, read from its
/// credentials directory. The host status file carries it to the System
/// page (ADR-028 record of lane L26).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Snapshots {
    /// The cell's App chain keystore.
    pub app: fstp_obs::snapshot_status::SnapshotStatus,
    /// The vault's keystore.
    pub vault: fstp_obs::snapshot_status::SnapshotStatus,
}

impl Snapshots {
    /// Whether the last snapshot of a process failed.
    #[must_use]
    pub fn failing(&self) -> bool {
        self.app.failing() || self.vault.failing()
    }

    /// The last verified snapshot of the process that verified longest
    /// ago, in Unix seconds, if both verified one.
    #[must_use]
    pub fn oldest_verified(&self) -> Option<u64> {
        Some(self.app.last_verified?.min(self.vault.last_verified?))
    }

    /// Hours since [`Snapshots::oldest_verified`].
    #[must_use]
    pub fn age_hours(&self) -> Option<i64> {
        let t = i64::try_from(self.oldest_verified()?).ok()?;
        Some(crate::pki::now().saturating_sub(t).max(0) / 3600)
    }
}

/// Reads [`Snapshots`] of the host.
#[must_use]
pub fn snapshot_status(layout: &Layout) -> Snapshots {
    use fstp_obs::snapshot_status::read;
    Snapshots {
        app: read(&layout.creds("cell")),
        vault: read(&layout.creds("vault")),
    }
}

/// The part of the host a service belongs to (ADR-028 record of lane L20).
fn part_slot<'a>(parts: &'a mut Parts, name: &str) -> &'a mut PartState {
    if name.starts_with("fstp-keyd") {
        &mut parts.keys
    } else {
        match name {
            "fstp-cell" => &mut parts.cell,
            "fstp-vault" => &mut parts.vault,
            "fstp-witness" => &mut parts.witness,
            "fstp-edge" | "fstp-control" => &mut parts.edge,
            // The two PostgreSQL clusters.
            _ => &mut parts.databases,
        }
    }
}

/// One service as `status` saw it.
struct Seen {
    name: String,
    what: &'static str,
    state: PartState,
}

/// Everything `status` and the host status file read (ADR-028 "Status",
/// record of lane L20).
struct Survey {
    seen: Vec<Seen>,
    parts: Parts,
    findings: Findings,
    /// The older of the two clusters' newest base backups.
    last_backup: Option<i64>,
    /// The newest key copy.
    last_key_copy: Option<i64>,
    /// The keystore snapshots of both processes.
    snapshots: Snapshots,
    /// The WAL archive facts of each cluster, empty without backups.
    archives: Vec<(Cluster, Option<crate::archive::Archiver>)>,
}

fn survey(layout: &Layout, state: &State) -> Survey {
    let m = Manager::new(layout);
    let mut parts = Parts::RUNNING;
    let mut seen = Vec::new();
    for s in stack::all(layout) {
        let running = m.running(&s);
        let st = if running && is_ready(&s.ready) {
            PartState::Running
        } else if running {
            PartState::Unhealthy
        } else {
            PartState::Stopped
        };
        let slot = part_slot(&mut parts, &s.name);
        *slot = slot.worst(st);
        seen.push(Seen {
            name: s.name,
            what: s.what,
            state: st,
        });
    }
    let all_running = seen.iter().all(|s| s.state == PartState::Running);
    let cell: Option<[u8; 16]> = state
        .get("cell")
        .and_then(crate::witness::unhex)
        .and_then(|b| b.try_into().ok());
    let route_current = cell.and_then(|c| crate::route::own_is_current(layout, c));
    let last_backup = Cluster::ALL
        .iter()
        .map(|c| crate::ops::last_backup(layout, *c))
        .try_fold(i64::MAX, |acc, t| t.map(|t| acc.min(t)))
        .filter(|t| *t != i64::MAX);
    let now = crate::pki::now();
    let snapshots = snapshot_status(layout);
    let archives = crate::archive::read_all(layout);
    let drill = fstp_obs::drill_status::read(&layout.admin_dir());
    let copy = fstp_obs::witness_copy::read(&layout.admin_dir());
    let findings = Findings {
        setup_done: state.done("first-admin") && cell.is_some(),
        all_running,
        route_current,
        min_days: min_days(layout),
        self_signed: layout.cfg.tls.is_none(),
        backups: layout.cfg.backup.is_some(),
        backup_age_hours: last_backup.map(|t| now.saturating_sub(t) / 3600),
        admins: crate::cellcmd::cached_admins(state),
        verified: crate::cellcmd::verified_count(state),
        keys_copied: state.done("keys-copied"),
        keys_copied_at: instant_of(state, KEYS_COPIED_AT),
        vault_erased_at: instant_of(state, VAULT_ERASED_AT),
        snapshot_age_hours: snapshots.age_hours(),
        snapshot_failed: snapshots.failing(),
        custodian: (layout.cfg.services == crate::config::Services::Systemd)
            .then(|| crate::custodian::host_link(layout)),
        pairing_days: crate::custodian::pairing_days(layout),
        wal_archive: crate::archive::host_state(&archives, now),
        wal_last: crate::archive::oldest_last_archived(&archives),
        witness_copy: copy.state(u64::try_from(now).unwrap_or(0)),
        witness_copied: copy.last_success.and_then(|t| i64::try_from(t).ok()),
        drill,
        drill_due: drill.due(u64::try_from(now).unwrap_or(0)),
        custodian_key_owed: layout.cfg.backup.is_some()
            && Cluster::ALL
                .iter()
                .any(|c| crate::ops::key_copy_owed(layout, *c)),
    };
    let last_key_copy = findings.keys_copied_at;
    Survey {
        seen,
        parts,
        findings,
        last_backup,
        last_key_copy,
        snapshots,
        archives,
    }
}

/// The state key of the newest key copy's time, Unix seconds.
pub const KEYS_COPIED_AT: &str = "keys-copied-at";

/// The state key of the last vault erasure's time, Unix seconds (ADR-028
/// record of lane L20).
pub const VAULT_ERASED_AT: &str = "vault-erased-at";

fn instant_of(state: &State, key: &str) -> Option<i64> {
    state
        .get(key)
        .and_then(|t| t.parse::<i64>().ok())
        .filter(|t| *t >= 0)
}

/// The word of the file for `n`.
#[must_use]
pub fn next_word(n: Next) -> HostNext {
    match n {
        Next::RunSetup => HostNext::RunSetup,
        Next::StartService => HostNext::StartService,
        Next::Custodian => HostNext::Custodian,
        Next::PairCustodian => HostNext::PairCustodian,
        Next::RenewRoute => HostNext::RenewRoute,
        Next::Renew => HostNext::Renew,
        Next::PublicCertificate => HostNext::PublicCertificate,
        Next::ConfigureBackups => HostNext::ConfigureBackups,
        Next::WalArchive => HostNext::WalArchive,
        Next::WitnessCopy => HostNext::WitnessCopy,
        Next::Backup => HostNext::Backup,
        Next::RestoreDrill => HostNext::RestoreDrill,
        Next::CustodianCopy => HostNext::CustodianCopy,
        Next::CustodianKeyCopy => HostNext::CustodianCopy,
        Next::KeystoreSnapshot => HostNext::KeystoreSnapshot,
        Next::WebAdmins => HostNext::WebAdmins,
        Next::VerifyAdmins => HostNext::VerifyAdmins,
        Next::CopyKeys => HostNext::CopyKeys,
        Next::Nothing => HostNext::Nothing,
    }
}

/// The host status file's content for the facts `f` (ADR-028 record of
/// lane L20). It holds no admin account: the cell knows its admins.
#[must_use]
pub fn host_status(
    f: &Findings,
    parts: Parts,
    last_backup: Option<i64>,
    last_key_copy: Option<i64>,
    snapshots: Snapshots,
    now: i64,
) -> HostStatus {
    let secs = |t: Option<u64>| {
        t.map(|t| {
            i64::try_from(t)
                .unwrap_or(i64::MAX)
                .clamp(0, host_status::MAX_INSTANT)
        })
    };
    HostStatus {
        written_at: now.clamp(0, host_status::MAX_INSTANT),
        setup_done: f.setup_done,
        parts,
        backups_configured: f.backups,
        last_backup: last_backup.map(|t| t.clamp(0, host_status::MAX_INSTANT)),
        last_key_copy: last_key_copy.map(|t| t.clamp(0, host_status::MAX_INSTANT)),
        last_vault_erasure: f
            .vault_erased_at
            .map(|t| t.clamp(0, host_status::MAX_INSTANT)),
        last_app_snapshot: secs(snapshots.app.last_verified),
        app_snapshot_failed: snapshots.app.failing(),
        last_vault_snapshot: secs(snapshots.vault.last_verified),
        vault_snapshot_failed: snapshots.vault.failing(),
        certificate_days: f
            .min_days
            .map(|d| d.clamp(-host_status::MAX_DAYS, host_status::MAX_DAYS)),
        self_signed: f.self_signed,
        route: match f.route_current {
            Some(true) => RouteState::Current,
            Some(false) => RouteState::Mismatch,
            None => RouteState::Unknown,
        },
        next: next_word(next(f)),
        custodian: match f.custodian {
            Some(
                crate::custodian::Link::Linked
                | crate::custodian::Link::Owed
                | crate::custodian::Link::CopyOwed,
            ) => host_status::CustodianState::Linked,
            Some(crate::custodian::Link::Unreachable) => host_status::CustodianState::Unreachable,
            Some(crate::custodian::Link::Unpaired) => host_status::CustodianState::Unpaired,
            None => host_status::CustodianState::NotUsed,
        },
        guard_owed: f.custodian == Some(crate::custodian::Link::Owed),
        guard_copy_owed: f.custodian == Some(crate::custodian::Link::CopyOwed)
            || f.custodian_key_owed,
        wal_archive: if f.backups {
            f.wal_archive
        } else {
            WalArchive::Unknown
        },
        last_wal_archived: f.wal_last.map(|t| t.clamp(0, host_status::MAX_INSTANT)),
        last_drill_passed: f.drill.last_pass.map(|t| {
            i64::try_from(t)
                .unwrap_or(i64::MAX)
                .clamp(0, host_status::MAX_INSTANT)
        }),
        drill_step: f.drill.failed,
        drill_seconds: f
            .drill
            .seconds
            .and_then(|s| i64::try_from(s).ok())
            .filter(|s| *s >= 1),
        witness_copy: if f.backups {
            f.witness_copy
        } else {
            WalArchive::Unknown
        },
        last_witness_copied: f
            .witness_copied
            .map(|t| t.clamp(0, host_status::MAX_INSTANT)),
    }
}

fn write_survey(layout: &Layout, s: &Survey) -> std::io::Result<()> {
    let st = host_status(
        &s.findings,
        s.parts,
        s.last_backup,
        s.last_key_copy,
        s.snapshots,
        crate::pki::now(),
    );
    let path = layout.host_status();
    crate::state::write_atomic(&path, host_status::encode(&st).as_bytes(), 0o644)?;
    // The directory and the file are readable by the cell's OS user: the
    // file holds no secret (R-NF-02).
    use std::os::unix::fs::PermissionsExt as _;
    if let Some(dir) = path.parent() {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))?;
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
}

/// `fstp-admin report`: writes the host status file the System page reads,
/// and nothing else (ADR-028 record of lane L20). The timer
/// `fstp-admin-report` runs it every 15 minutes.
///
/// # Errors
///
/// [`Fail::Step`] when the file cannot be written.
pub fn report(layout: &Layout) -> Result<(), Fail> {
    let state = State::load(&layout.admin_dir().join("state")).unwrap_or_default();
    write_survey(layout, &survey(layout, &state)).map_err(|_| Fail::Step("report", Cause::Io))
}

/// Writes the host status file after another command, quietly. A failure
/// leaves the old file, whose age the System page shows.
pub fn report_quietly(layout: &Layout) {
    let _ = report(layout);
}

fn minutes_since(t: i64, now: i64) -> u64 {
    now.saturating_sub(t).max(0).unsigned_abs() / 60
}

/// One `wal archive` line of the status screen (ADR-028 record of lane
/// `m10/backup-health`).
fn archive_line(c: Cluster, a: Option<&crate::archive::Archiver>, now: i64) {
    let name = match c {
        Cluster::App => "app  ",
        Cluster::Vault => "vault",
    };
    let head = [Part::T("  wal archive  "), Part::T(name)];
    let line = |tail: &[Part<'_>]| {
        let mut parts = head.to_vec();
        parts.extend_from_slice(tail);
        out(&parts);
    };
    let Some(a) = a else {
        return line(&[Part::T(" unknown: the database did not answer")]);
    };
    match crate::archive::state(Some(a), now) {
        WalArchive::Failing => line(&[
            Part::T(" FAILING: the last upload failed "),
            Part::N(a.last_failed.map_or(0, |t| minutes_since(t, now))),
            Part::T(" minutes ago"),
        ]),
        WalArchive::Late => line(&[
            Part::T(" LATE: a finished segment has waited "),
            Part::N(a.waited(now).map_or(0, |w| w.unsigned_abs() / 60)),
            Part::T(" minutes for its upload"),
        ]),
        WalArchive::Ok | WalArchive::Unknown => match a.last_archived {
            Some(t) => line(&[
                Part::T(" last change saved "),
                Part::N(minutes_since(t, now)),
                Part::T(" minutes ago"),
            ]),
            None => line(&[Part::T(" no change saved yet")]),
        },
    }
}

/// The `witness copy` line of the status screen (ADR-028 record of lane
/// `m10/witness-copy`).
fn witness_line(f: &Findings, now: i64) {
    let head = Part::T("  witness copy ");
    let ago = |t: i64| [Part::N(minutes_since(t, now)), Part::T(" minutes ago")];
    match (f.witness_copy, f.witness_copied) {
        (WalArchive::Failing, _) => out(&[
            head,
            Part::T(" FAILING: the last run failed; fstp-admin witness-copy shows why"),
        ]),
        (WalArchive::Late, Some(t)) => {
            let [n, unit] = ago(t);
            out(&[head, Part::T(" LATE: last copied "), n, unit]);
        }
        (WalArchive::Late, None) => out(&[head, Part::T(" LATE: never copied")]),
        (WalArchive::Ok, Some(t)) => {
            let [n, unit] = ago(t);
            out(&[head, Part::T(" last copied "), n, unit]);
        }
        (WalArchive::Ok | WalArchive::Unknown, _) => out(&[head, Part::T(" never run")]),
    }
}

/// The `restore drill` line of the status screen (ADR-028 record of lane
/// `m10/backup-health`).
fn drill_line(d: &fstp_obs::drill_status::DrillStatus, now: i64) {
    let head = Part::T("  restore drill  ");
    let days = |t: u64| {
        now.saturating_sub(i64::try_from(t).unwrap_or(i64::MAX))
            .max(0)
            .unsigned_abs()
            / 86_400
    };
    if let Some(step) = d.failed {
        out(&[
            head,
            Part::T("FAILED: "),
            Part::T(crate::drill::step_text(step)),
        ]);
    } else if let Some(t) = d.last_pass {
        out(&[
            head,
            Part::T("last passed "),
            Part::N(days(t)),
            Part::T(" days ago; restoring both databases took "),
            Part::N(d.seconds.unwrap_or(0)),
            Part::T(" seconds"),
        ]);
    } else {
        out(&[head, Part::T("never run")]);
    }
}

/// Prints the status screen and returns the exit code. It also writes the
/// host status file.
#[must_use]
pub fn run(layout: &Layout) -> u8 {
    let state = State::load(&layout.admin_dir().join("state")).unwrap_or_default();
    let s = survey(layout, &state);
    out(&[Part::T("fstp on "), Part::Name(&layout.cfg.domain)]);
    out(&[Part::T("")]);
    for x in &s.seen {
        let word = match x.state {
            PartState::Running => "running    ",
            PartState::Unhealthy => "UNHEALTHY  ",
            PartState::Stopped => "STOPPED    ",
        };
        out(&[
            Part::T("  "),
            Part::T(word),
            Part::Name(&x.name),
            Part::T("  ("),
            Part::T(x.what),
            Part::T(")"),
        ]);
    }
    let f = &s.findings;
    out(&[Part::T("")]);
    match f.route_current {
        Some(true) => out(&[Part::T("  route      current")]),
        Some(false) => out(&[Part::T(
            "  route      PIN MISMATCH: the edge pins an older certificate",
        )]),
        None => out(&[Part::T("  route      unknown")]),
    }
    if let Some(d) = f.min_days {
        out(&[
            Part::T("  certificates  the first ends in "),
            Part::N(u64::try_from(d.max(0)).unwrap_or(0)),
            Part::T(" days"),
        ]);
    }
    match f.backup_age_hours {
        Some(h) => out(&[
            Part::T("  backups    newest is "),
            Part::N(u64::try_from(h.max(0)).unwrap_or(0)),
            Part::T(" hours old"),
        ]),
        None if f.backups => out(&[Part::T("  backups    none yet")]),
        None => out(&[Part::T("  backups    not configured")]),
    }
    if f.backups {
        for (name, sn) in [("cell ", s.snapshots.app), ("vault", s.snapshots.vault)] {
            let line = |tail: &[Part<'_>]| {
                let mut parts = vec![Part::T("  snapshots  "), Part::T(name)];
                parts.extend_from_slice(tail);
                out(&parts);
            };
            match (sn.failing(), sn.last_verified) {
                // ADR-012 record of lane m10/backup-followups, row "Failure
                // reason": the step that failed, one word of a closed list.
                (true, _) => line(&[
                    Part::T(" FAILED: the last keystore snapshot did not verify (step: "),
                    Part::T(
                        sn.reason
                            .map_or("unknown", fstp_obs::SnapshotFailure::as_str),
                    ),
                    Part::T(")"),
                ]),
                (false, Some(t)) => line(&[
                    Part::T(" last verified "),
                    Part::N(
                        crate::pki::now()
                            .saturating_sub(i64::try_from(t).unwrap_or(i64::MAX))
                            .max(0)
                            .unsigned_abs()
                            / 3600,
                    ),
                    Part::T(" hours ago"),
                ]),
                (false, None) => line(&[Part::T(" none yet")]),
            }
        }
        let now = crate::pki::now();
        for (c, a) in &s.archives {
            archive_line(*c, a.as_ref(), now);
        }
        witness_line(f, now);
        drill_line(&f.drill, now);
    }
    out(&[Part::T(match f.custodian {
        Some(crate::custodian::Link::Linked) => "  custodian  linked, guard current",
        Some(crate::custodian::Link::CopyOwed) => {
            "  custodian  linked, a fresh copy is owed (retried every ten minutes)"
        }
        Some(crate::custodian::Link::Owed) => {
            "  custodian  A GUARD IS STILL TO BE REPLACED: erasures wait"
        }
        Some(crate::custodian::Link::Unreachable) => "  custodian  NOT ANSWERING: erasures wait",
        Some(crate::custodian::Link::Unpaired) => "  custodian  not paired",
        None => "  custodian  not used in direct mode",
    })]);
    if f.custodian_key_owed {
        out(&[Part::T(
            "  custodian  the backup key copy for the custodian is OWED (fstp-admin backup sends it)",
        )]);
    }
    out(&[Part::T(if key_copy_stale(f) {
        "  key copy   OLDER THAN THE LAST ERASURE: make a new copy"
    } else if f.keys_copied {
        "  key copy   made"
    } else {
        "  key copy   never made"
    })]);
    for (i, a) in f.admins.iter().enumerate() {
        let done = state.done(&format!("verified.{a}"));
        out(&[
            Part::T(if i == 0 {
                "  admin 1    "
            } else {
                "  admin 2    "
            }),
            Part::Name(a),
            Part::T(if done {
                "  verified"
            } else {
                "  not verified yet"
            }),
        ]);
    }
    if f.admins.len() < 2 && f.setup_done {
        out(&[Part::T(
            "  admins     fstp-admin verify reads the current admins when the second one has enrolled",
        )]);
    }
    if f.verified >= 2 {
        out(&[Part::T(
            "  web        the admins grant each other Financial and Legal signatory, save each onboarding step, then one asks to open the organisation and the other approves. Onboarding summary shows who acts next.",
        )]);
    }
    out(&[Part::T("")]);
    out(&[Part::T("Next: "), Part::T(next_text(next(f)))]);
    if write_survey(layout, &s).is_err() {
        out(&[
            Part::T("  The web page's status file did not write: "),
            Part::P(&layout.host_status()),
        ]);
    }
    let unhealthy =
        !f.all_running || f.route_current == Some(false) || f.min_days.is_some_and(|d| d < 1);
    if f.setup_done && unhealthy {
        UNHEALTHY
    } else {
        OK
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, reason = "test code")]

    use super::*;

    fn healthy() -> Findings {
        Findings {
            setup_done: true,
            all_running: true,
            route_current: Some(true),
            min_days: Some(5),
            self_signed: false,
            backups: true,
            backup_age_hours: Some(2),
            admins: vec!["a".into(), "b".into()],
            verified: 2,
            keys_copied: true,
            keys_copied_at: Some(1_700_000_000),
            vault_erased_at: None,
            snapshot_age_hours: Some(3),
            snapshot_failed: false,
            custodian: Some(crate::custodian::Link::Linked),
            pairing_days: Some(700),
            wal_archive: WalArchive::Ok,
            wal_last: Some(1_700_000_000),
            witness_copy: WalArchive::Ok,
            witness_copied: Some(1_700_000_000),
            drill: fstp_obs::drill_status::DrillStatus::default().after_pass(1_700_000_000, 300),
            drill_due: false,
            custodian_key_owed: false,
        }
    }

    /// F-044, ADR-012 record of lane m10/backup-followups, row "Owed": an
    /// owed copy of the backup key file for the custodian is named after
    /// the backups and an owed key entry copy, and reaches the host status
    /// file as `guard_copy_owed` with the next word `custodian_copy`, with
    /// no new member.
    #[test]
    fn adr012_bf_status_names_an_owed_custodian_key_copy() {
        use crate::custodian::Link;
        let mut f = healthy();
        f.custodian_key_owed = true;
        assert_eq!(next(&f), Next::CustodianKeyCopy);
        assert!(next_text(Next::CustodianKeyCopy).contains("fstp-admin backup"));
        f.custodian = Some(Link::CopyOwed);
        assert_eq!(next(&f), Next::CustodianCopy);
        f.custodian = Some(Link::Linked);
        f.backup_age_hours = Some(40);
        assert_eq!(next(&f), Next::Backup);
        f.backup_age_hours = Some(2);
        let s = host_status(&f, Parts::RUNNING, Some(1), None, Snapshots::default(), 2);
        assert_eq!(s.custodian, host_status::CustodianState::Linked);
        assert!(s.guard_copy_owed && !s.guard_owed);
        assert_eq!(s.next, HostNext::CustodianCopy);
        assert_eq!(
            host_status::decode(host_status::encode(&s).as_bytes()),
            Ok(s)
        );
        f.custodian_key_owed = false;
        assert!(
            !host_status(&f, Parts::RUNNING, Some(1), None, Snapshots::default(), 2)
                .guard_copy_owed
        );
    }

    /// ADR-028 record of lane `m10/guard-key`, part 2 (Q-F018-4), F-018:
    /// an owed fresh copy is named after the backups, and the host status
    /// file carries it with the custodian still linked.
    #[test]
    fn adr028_guard_status_names_an_owed_copy() {
        use crate::custodian::Link;
        let mut f = healthy();
        f.custodian = Some(Link::CopyOwed);
        assert_eq!(next(&f), Next::CustodianCopy);
        f.backup_age_hours = Some(40);
        assert_eq!(next(&f), Next::Backup);
        f.backup_age_hours = Some(2);
        let s = host_status(&f, Parts::RUNNING, Some(1), None, Snapshots::default(), 2);
        assert_eq!(s.custodian, host_status::CustodianState::Linked);
        assert!(s.guard_copy_owed && !s.guard_owed);
        assert_eq!(s.next, HostNext::CustodianCopy);
        assert_eq!(
            host_status::decode(host_status::encode(&s).as_bytes()),
            Ok(s)
        );
    }

    /// ADR-028 record of lane `m10/guard-key`, I-81: an unreachable
    /// custodian or an owed guard rotation comes right after a stopped
    /// service, since erasures wait. An unpaired custodian, or a pairing
    /// near its end, comes before the key copy, which needs it. The host
    /// status file carries the link and the owed rotation.
    #[test]
    fn adr028_guard_status_reads_guard_check() {
        use crate::custodian::Link;
        for (link, want, word, owed) in [
            (
                Link::Unreachable,
                Next::Custodian,
                host_status::CustodianState::Unreachable,
                false,
            ),
            (
                Link::Owed,
                Next::Custodian,
                host_status::CustodianState::Linked,
                true,
            ),
            (
                Link::Unpaired,
                Next::PairCustodian,
                host_status::CustodianState::Unpaired,
                false,
            ),
            (
                Link::Linked,
                Next::Nothing,
                host_status::CustodianState::Linked,
                false,
            ),
        ] {
            let mut f = healthy();
            f.custodian = Some(link);
            f.keys_copied = false;
            let n = next(&f);
            assert!(
                n == want || (want == Next::Nothing && n == Next::CopyKeys),
                "{link:?}"
            );
            let s = host_status(&f, Parts::RUNNING, Some(1), None, Snapshots::default(), 2);
            assert_eq!((s.custodian, s.guard_owed), (word, owed));
            let back = host_status::decode(host_status::encode(&s).as_bytes()).expect("decodes");
            assert_eq!(back, s);
        }
        let mut f = healthy();
        f.pairing_days = Some(10);
        assert_eq!(next(&f), Next::PairCustodian);
        f.all_running = false;
        f.custodian = Some(Link::Unreachable);
        assert_eq!(next(&f), Next::StartService);
    }

    /// ADR-028 "Status": exactly one next thing, the most urgent.
    #[test]
    fn adr028_status_names_the_most_urgent_thing() {
        assert_eq!(next(&healthy()), Next::Nothing);
        let mut f = healthy();
        f.keys_copied = false;
        assert_eq!(next(&f), Next::CopyKeys);
        f.verified = 1;
        assert_eq!(next(&f), Next::VerifyAdmins);
        f.admins.pop();
        assert_eq!(next(&f), Next::WebAdmins);
        f.route_current = Some(false);
        assert_eq!(next(&f), Next::RenewRoute);
        f.all_running = false;
        assert_eq!(next(&f), Next::StartService);
        f.setup_done = false;
        assert_eq!(next(&f), Next::RunSetup);
        let mut g = healthy();
        g.backup_age_hours = None;
        assert_eq!(next(&g), Next::Backup);
    }

    /// ADR-028 record of lane L20, R-NF-02: the facts of `status` map to
    /// the host status file, with the next thing as its word and no admin
    /// account in it.
    #[test]
    fn adr028_l20_findings_map_to_the_file() {
        let mut f = healthy();
        f.route_current = Some(false);
        f.admins = vec!["01234567-89ab-cdef-0123-456789abcdef".into()];
        let parts = Parts {
            edge: PartState::Unhealthy,
            ..Parts::RUNNING
        };
        let s = host_status(
            &f,
            parts,
            Some(1_700_000_000),
            None,
            Snapshots::default(),
            1_700_003_600,
        );
        assert_eq!(s.written_at, 1_700_003_600);
        assert_eq!(s.route, RouteState::Mismatch);
        assert_eq!(s.next, HostNext::RenewRoute);
        assert_eq!(s.parts.edge, PartState::Unhealthy);
        assert_eq!(s.certificate_days, Some(5));
        assert_eq!(s.last_backup, Some(1_700_000_000));
        assert_eq!(s.last_key_copy, None);
        let text = host_status::encode(&s);
        assert!(!text.contains("0123"), "{text}");
        assert_eq!(host_status::decode(text.as_bytes()), Ok(s));
        for n in [
            Next::RunSetup,
            Next::StartService,
            Next::RenewRoute,
            Next::Renew,
            Next::PublicCertificate,
            Next::ConfigureBackups,
            Next::WalArchive,
            Next::Backup,
            Next::RestoreDrill,
            Next::KeystoreSnapshot,
            Next::WebAdmins,
            Next::VerifyAdmins,
            Next::CopyKeys,
            Next::Nothing,
        ] {
            assert_eq!(format!("{n:?}"), format!("{:?}", next_word(n)));
        }
        let mut g = healthy();
        g.route_current = None;
        g.min_days = Some(i64::MAX);
        let s = host_status(&g, Parts::RUNNING, None, None, Snapshots::default(), -5);
        assert_eq!(s.route, RouteState::Unknown);
        assert_eq!(s.written_at, 0);
        assert_eq!(s.certificate_days, Some(host_status::MAX_DAYS));
    }

    /// ADR-028 record of lane L20: `fstp-admin report` writes the status
    /// file, readable by every local user, in the grammar the cell reads,
    /// and the part of a stopped host is `stopped`.
    #[test]
    fn adr028_l20_report_writes_the_status_file() {
        use std::os::unix::fs::PermissionsExt as _;
        let tag = fstp_crypto::random_array::<6>().unwrap_or([7; 6]);
        let dir = std::env::temp_dir().join(format!(
            "fstp-l20-{}",
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
        assert!(report(&layout).is_ok());
        let path = layout.host_status();
        assert_eq!(path, dir.join("state").join("status").join("host.json"));
        let bytes = std::fs::read(&path).expect("the file");
        let s = host_status::decode(&bytes).expect("the grammar");
        assert!(!s.setup_done);
        assert_eq!(s.next, HostNext::RunSetup);
        assert_eq!(s.parts.cell, PartState::Stopped);
        assert!(!s.backups_configured);
        let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o644);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ADR-028 record of lane L20: the runbook asks for a new key copy
    /// after each erasure, so a copy older than the last vault erasure
    /// makes the key copy the next thing, and the file carries the
    /// erasure's time.
    #[test]
    fn adr028_l20_key_copy_older_than_an_erasure_is_due() {
        let mut f = healthy();
        f.vault_erased_at = Some(1_699_999_999);
        assert!(!key_copy_stale(&f), "a copy after the erasure");
        assert_eq!(next(&f), Next::Nothing);
        f.vault_erased_at = Some(1_700_000_001);
        assert!(key_copy_stale(&f), "a copy before the erasure");
        assert_eq!(next(&f), Next::CopyKeys);
        f.keys_copied_at = None;
        assert!(key_copy_stale(&f), "a copy of unknown time");
        let s = host_status(
            &f,
            Parts::RUNNING,
            Some(1),
            None,
            Snapshots::default(),
            1_700_000_100,
        );
        assert_eq!(s.last_vault_erasure, Some(1_700_000_001));
        assert_eq!(s.next, HostNext::CopyKeys);
    }

    /// ADR-028 record of lane L27, row "Status": a failed keystore
    /// snapshot, or none verified in a day and a half, is the next thing
    /// to do on a host with backups, after the backups themselves.
    #[test]
    fn adr028_status_names_a_failed_keystore_snapshot() {
        let mut f = healthy();
        f.snapshot_failed = true;
        assert_eq!(next(&f), Next::KeystoreSnapshot);
        f.backup_age_hours = None;
        assert_eq!(next(&f), Next::Backup);
        let mut g = healthy();
        g.snapshot_age_hours = Some(40);
        assert_eq!(next(&g), Next::KeystoreSnapshot);
        g.snapshot_age_hours = None;
        assert_eq!(next(&g), Next::KeystoreSnapshot);
        let s = Snapshots {
            app: fstp_obs::snapshot_status::SnapshotStatus::default().after(None, 100),
            vault: fstp_obs::snapshot_status::SnapshotStatus::default()
                .after(None, 50)
                .after(Some(fstp_obs::SnapshotFailure::Fetch), 60),
        };
        assert!(s.failing());
        assert_eq!(s.oldest_verified(), Some(50));
        assert_eq!(Snapshots::default().oldest_verified(), None);
    }

    /// ADR-028 record of lane L26 (L20 and L27 joined): the host status
    /// file carries each process's last verified keystore snapshot and
    /// whether its last try failed, and the next thing names the snapshot.
    #[test]
    fn adr028_l26_snapshots_reach_the_host_status_file() {
        use fstp_obs::snapshot_status::SnapshotStatus;
        let snaps = Snapshots {
            app: SnapshotStatus::default().after(None, 1_700_000_000),
            vault: SnapshotStatus::default()
                .after(None, 1_699_990_000)
                .after(Some(fstp_obs::SnapshotFailure::Fetch), 1_700_000_050),
        };
        let mut f = healthy();
        f.snapshot_failed = snaps.failing();
        let s = host_status(
            &f,
            Parts::RUNNING,
            Some(1_700_000_000),
            Some(1_700_000_000),
            snaps,
            1_700_000_100,
        );
        assert_eq!(s.last_app_snapshot, Some(1_700_000_000));
        assert!(!s.app_snapshot_failed);
        assert_eq!(s.last_vault_snapshot, Some(1_699_990_000));
        assert!(s.vault_snapshot_failed);
        assert_eq!(s.next, HostNext::KeystoreSnapshot);
        assert_eq!(
            host_status::decode(host_status::encode(&s).as_bytes()),
            Ok(s)
        );
        let none = host_status(
            &healthy(),
            Parts::RUNNING,
            None,
            None,
            Snapshots::default(),
            1,
        );
        assert_eq!(
            (none.last_app_snapshot, none.last_vault_snapshot),
            (None, None)
        );
        assert!(!none.app_snapshot_failed && !none.vault_snapshot_failed);
    }

    /// ADR-028 record of lane `m10/backup-health`, row "Next words": a
    /// failing or late WAL archive comes before the backup, since a base
    /// backup restores only with the archived WAL from its start. An
    /// unknown archive names nothing: a stopped database comes first.
    #[test]
    fn adr028_bh_status_names_the_wal_archive_and_the_drill() {
        for (w, want) in [
            (WalArchive::Failing, Next::WalArchive),
            (WalArchive::Late, Next::WalArchive),
            (WalArchive::Ok, Next::Nothing),
            (WalArchive::Unknown, Next::Nothing),
        ] {
            let mut f = healthy();
            f.wal_archive = w;
            assert_eq!(next(&f), want, "{w:?}");
            f.backup_age_hours = None;
            if want == Next::WalArchive {
                assert_eq!(next(&f), Next::WalArchive, "before the backup");
            }
        }
        let mut f = healthy();
        f.wal_archive = WalArchive::Failing;
        f.backups = false;
        assert_eq!(next(&f), Next::ConfigureBackups);
        // The drill: due after a failure or 35 days without a pass, named
        // right after the backup and before the keystore snapshots.
        let mut f = healthy();
        f.drill_due = true;
        assert_eq!(next(&f), Next::RestoreDrill);
        f.snapshot_failed = true;
        assert_eq!(next(&f), Next::RestoreDrill);
        f.backup_age_hours = None;
        assert_eq!(next(&f), Next::Backup);
        f.wal_archive = WalArchive::Failing;
        assert_eq!(next(&f), Next::WalArchive);
    }

    /// ADR-028 record of lane `m10/witness-copy`, row "Next word": a
    /// failing or late witness copy comes right after the WAL archive and
    /// before the backup. Unknown names nothing, and without backups the
    /// backups come first.
    #[test]
    fn adr028_wc_status_names_the_witness_copy() {
        for (w, want) in [
            (WalArchive::Failing, Next::WitnessCopy),
            (WalArchive::Late, Next::WitnessCopy),
            (WalArchive::Ok, Next::Nothing),
            (WalArchive::Unknown, Next::Nothing),
        ] {
            let mut f = healthy();
            f.witness_copy = w;
            assert_eq!(next(&f), want, "{w:?}");
            f.backup_age_hours = None;
            if want == Next::WitnessCopy {
                assert_eq!(next(&f), Next::WitnessCopy, "before the backup");
                f.wal_archive = WalArchive::Late;
                assert_eq!(next(&f), Next::WalArchive, "after the WAL archive");
                f.backups = false;
                assert_eq!(next(&f), Next::ConfigureBackups);
            }
        }
    }

    /// ADR-028 record of lane `m10/witness-copy`, row "Host status
    /// members": the copy state and the time of the last full copy reach
    /// the file, and a host without backups reports `unknown`.
    #[test]
    fn adr028_wc_witness_copy_reaches_the_host_status_file() {
        let mut f = healthy();
        f.witness_copy = WalArchive::Failing;
        f.witness_copied = Some(1_700_000_070);
        let s = host_status(&f, Parts::RUNNING, Some(1), None, Snapshots::default(), 2);
        assert_eq!(s.witness_copy, WalArchive::Failing);
        assert_eq!(s.last_witness_copied, Some(1_700_000_070));
        assert_eq!(s.next, HostNext::WitnessCopy);
        assert_eq!(
            host_status::decode(host_status::encode(&s).as_bytes()),
            Ok(s)
        );
        f.backups = false;
        let s = host_status(&f, Parts::RUNNING, Some(1), None, Snapshots::default(), 2);
        assert_eq!(s.witness_copy, WalArchive::Unknown);
    }

    /// ADR-028 record of lane `m10/backup-health`, row "Host status
    /// members": the archive state and the last archived segment reach
    /// the file, and a host without backups reports `unknown`.
    #[test]
    fn adr028_bh_backup_health_reaches_the_host_status_file() {
        let mut f = healthy();
        f.wal_archive = WalArchive::Late;
        f.wal_last = Some(1_700_000_050);
        let s = host_status(&f, Parts::RUNNING, Some(1), None, Snapshots::default(), 2);
        assert_eq!(s.wal_archive, WalArchive::Late);
        assert_eq!(s.last_wal_archived, Some(1_700_000_050));
        assert_eq!(s.next, HostNext::WalArchive);
        assert_eq!(
            host_status::decode(host_status::encode(&s).as_bytes()),
            Ok(s)
        );
        f.backups = false;
        let s = host_status(&f, Parts::RUNNING, Some(1), None, Snapshots::default(), 2);
        assert_eq!(s.wal_archive, WalArchive::Unknown);
        // The drill: its last pass, its duration and a failed step.
        use fstp_obs::drill_status::Step;
        let mut f = healthy();
        f.drill = f.drill.after_fail(1_700_100_000, Step::Keystore);
        f.drill_due = true;
        let s = host_status(&f, Parts::RUNNING, Some(1), None, Snapshots::default(), 2);
        assert_eq!(s.last_drill_passed, Some(1_700_000_000));
        assert_eq!(s.drill_seconds, Some(300));
        assert_eq!(s.drill_step, Some(Step::Keystore));
        assert_eq!(s.next, HostNext::RestoreDrill);
        assert_eq!(
            host_status::decode(host_status::encode(&s).as_bytes()),
            Ok(s)
        );
        f.drill = fstp_obs::drill_status::DrillStatus::default();
        let s = host_status(&f, Parts::RUNNING, Some(1), None, Snapshots::default(), 2);
        assert_eq!(
            (s.last_drill_passed, s.drill_step, s.drill_seconds),
            (None, None, None)
        );
    }
}
