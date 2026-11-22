//! `fstp-admin status`: one screen with what runs, what is unhealthy, and
//! the single next thing to do (ADR-028 "Status").

use crate::fail::{OK, UNHEALTHY};
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
    } else if !f.keys_copied {
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
            "copy the keys off this host: fstp-admin backup-keys /media/usb/fstp-keys, and keep the passphrases apart."
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

/// Prints the status screen and returns the exit code.
#[must_use]
pub fn run(layout: &Layout) -> u8 {
    let m = Manager::new(layout);
    let state = State::load(&layout.admin_dir().join("state")).unwrap_or_default();
    out(&[Part::T("fstp on "), Part::Name(&layout.cfg.domain)]);
    out(&[Part::T("")]);
    let mut all_running = true;
    for s in stack::all(layout) {
        let running = m.running(&s);
        let ready = running && is_ready(&s.ready);
        all_running &= ready;
        let word = if ready {
            "running    "
        } else if running {
            "UNHEALTHY  "
        } else {
            "STOPPED    "
        };
        out(&[
            Part::T("  "),
            Part::T(word),
            Part::Name(&s.name),
            Part::T("  ("),
            Part::T(s.what),
            Part::T(")"),
        ]);
    }
    let cell: Option<[u8; 16]> = state
        .get("cell")
        .and_then(crate::witness::unhex)
        .and_then(|b| b.try_into().ok());
    let route_current = cell.and_then(|c| crate::route::own_is_current(layout, c));
    let backup_age_hours = Cluster::ALL
        .iter()
        .map(|c| crate::ops::last_backup(layout, *c))
        .try_fold(i64::MIN, |acc, t| {
            t.map(|t| acc.max(crate::pki::now().saturating_sub(t) / 3600))
        })
        .filter(|h| *h != i64::MIN);
    let f = Findings {
        setup_done: state.done("first-admin") && cell.is_some(),
        all_running,
        route_current,
        min_days: min_days(layout),
        self_signed: layout.cfg.tls.is_none(),
        backups: layout.cfg.backup.is_some(),
        backup_age_hours,
        admins: crate::cellcmd::cached_admins(&state),
        verified: crate::cellcmd::verified_count(&state),
        keys_copied: state.done("keys-copied"),
    };
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
    out(&[Part::T("Next: "), Part::T(next_text(next(&f)))]);
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
}
