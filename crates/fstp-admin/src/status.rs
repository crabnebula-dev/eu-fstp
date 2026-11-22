//! `fstp-admin status`: one screen with what runs, what is unhealthy, and
//! the single next thing to do (ADR-028 "Status").

use fstp_obs::host_status::{self, HostStatus, Next as HostNext, PartState, Parts, RouteState};

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
    /// The route's pins do not match the current certificates.
    RenewRoute,
    /// A certificate is near its end.
    Renew,
    /// The origin certificate is self-signed.
    PublicCertificate,
    /// No object store is configured.
    ConfigureBackups,
    /// The newest base backup is old or missing.
    Backup,
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
    } else if f.backup_age_hours.is_none_or(|h| h > 36) {
        Next::Backup
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
        Next::Backup => "run fstp-admin backup. The newest backup is older than a day and a half.",
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
    };
    let last_key_copy = findings.keys_copied_at;
    Survey {
        seen,
        parts,
        findings,
        last_backup,
        last_key_copy,
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
        Next::RenewRoute => HostNext::RenewRoute,
        Next::Renew => HostNext::Renew,
        Next::PublicCertificate => HostNext::PublicCertificate,
        Next::ConfigureBackups => HostNext::ConfigureBackups,
        Next::Backup => HostNext::Backup,
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
    now: i64,
) -> HostStatus {
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
    }
}

fn write_survey(layout: &Layout, s: &Survey) -> std::io::Result<()> {
    let st = host_status(
        &s.findings,
        s.parts,
        s.last_backup,
        s.last_key_copy,
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
        }
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
        let s = host_status(&f, parts, Some(1_700_000_000), None, 1_700_003_600);
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
            Next::Backup,
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
        let s = host_status(&g, Parts::RUNNING, None, None, -5);
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
        let s = host_status(&f, Parts::RUNNING, Some(1), None, 1_700_000_100);
        assert_eq!(s.last_vault_erasure, Some(1_700_000_001));
        assert_eq!(s.next, HostNext::CopyKeys);
    }
}
