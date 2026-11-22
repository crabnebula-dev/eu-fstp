//! `tenant.system`: the facts of the tenant admins' System page (ADR-028
//! record of lane L20).
//!
//! The cell adds what it knows itself, through
//! [`crate::port::TenantConfig::system`]: whether the vault answers,
//! whether outgoing mail works, and the host status file that
//! `fstp-admin` writes. The page decides the lights. Every value is an
//! instant, a count, a flag or one word of a closed list: no name, no
//! address, no path and no account (R-NF-02).

use fstp_domain::time::Timestamp;
use fstp_json::{Object, ToJson, Value};

/// How one part of the host runs, as the host reported it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PartState {
    /// Every service of the part runs and is ready.
    Running,
    /// A service runs but is not ready.
    Unhealthy,
    /// A service is not running.
    Stopped,
}

impl PartState {
    /// The wire word.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Unhealthy => "unhealthy",
            Self::Stopped => "stopped",
        }
    }
}

/// The parts of the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostParts {
    /// The platform cell.
    pub cell: PartState,
    /// The identity vault.
    pub vault: PartState,
    /// The witness.
    pub witness: PartState,
    /// The public edge and its route feed.
    pub edge: PartState,
    /// The database clusters.
    pub databases: PartState,
    /// The key custody entries.
    pub keys: PartState,
}

/// Whether the edge's route pins the current certificates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteState {
    /// The pins match.
    Current,
    /// The edge pins an older certificate.
    Mismatch,
    /// The host could not read the route.
    Unknown,
}

impl RouteState {
    /// The wire word.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Mismatch => "mismatch",
            Self::Unknown => "unknown",
        }
    }
}

/// The wire words of the one next thing on the host, as `fstp-admin
/// status` names it (ADR-028 "Status").
pub const HOST_NEXT: [&str; 11] = [
    "run_setup",
    "start_service",
    "renew_route",
    "renew",
    "public_certificate",
    "configure_backups",
    "backup",
    "web_admins",
    "verify_admins",
    "copy_keys",
    "nothing",
];

/// The one next thing on the host, an index into [`HOST_NEXT`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostNext(usize);

impl HostNext {
    /// The next thing of the wire word `w`, if it is one.
    #[must_use]
    pub fn of(w: &str) -> Option<HostNext> {
        HOST_NEXT.iter().position(|x| *x == w).map(HostNext)
    }

    /// The wire word.
    #[must_use]
    pub fn wire(self) -> &'static str {
        HOST_NEXT.get(self.0).copied().unwrap_or("nothing")
    }
}

/// The host's last report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostReport {
    /// When the host wrote it.
    pub written_at: Timestamp,
    /// Setup finished.
    pub setup_done: bool,
    /// How each part runs.
    pub parts: HostParts,
    /// Backups have an object store.
    pub backups_configured: bool,
    /// The older of the two databases' newest backups.
    pub last_backup: Option<Timestamp>,
    /// The newest key copy off the host.
    pub last_key_copy: Option<Timestamp>,
    /// Whole days until the first host certificate ends. The reply
    /// shows an ended one as 0.
    pub certificate_days: Option<i64>,
    /// The public certificate is self-signed.
    pub self_signed: bool,
    /// The route's pins.
    pub route: RouteState,
    /// The one next thing on the host.
    pub next: HostNext,
}

/// What the cell found of the host status file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostFile {
    /// The cell's configuration names no file.
    NotConfigured,
    /// The named file does not exist.
    Missing,
    /// The file exists and is not in the grammar.
    Unreadable,
    /// The file's report.
    Present(HostReport),
}

/// Whether outgoing mail works: the ADR-027 channel probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MailState {
    /// The cell names no relay.
    NotConfigured,
    /// The relay greeted over TLS.
    Works,
    /// The relay did not greet.
    Fails,
}

impl MailState {
    /// The wire word.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::NotConfigured => "not_configured",
            Self::Works => "works",
            Self::Fails => "fails",
        }
    }
}

/// What the cell knows of itself and its host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SystemFacts {
    /// The vault answered a question that names nobody.
    pub vault_answers: bool,
    /// Outgoing mail.
    pub mail: MailState,
    /// The host status file.
    pub host: HostFile,
}

impl Default for SystemFacts {
    /// A cell that knows nothing: the vault silent, no relay, no file.
    fn default() -> SystemFacts {
        SystemFacts {
            vault_answers: false,
            mail: MailState::NotConfigured,
            host: HostFile::NotConfigured,
        }
    }
}

/// The `tenant.system` reply: the facts and the cell clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SystemView {
    /// The cell clock at the read.
    pub now: Timestamp,
    /// The facts.
    pub facts: SystemFacts,
}

fn instant(t: Timestamp) -> Value {
    Value::String(t.micros().to_string())
}

fn put(o: &mut Object, k: &str, v: Value) {
    let _ = o.insert(k, v);
}

fn report_json(r: &HostReport) -> Value {
    let mut parts = Object::new();
    for (k, s) in [
        ("cell", r.parts.cell),
        ("vault", r.parts.vault),
        ("witness", r.parts.witness),
        ("edge", r.parts.edge),
        ("databases", r.parts.databases),
        ("keys", r.parts.keys),
    ] {
        put(&mut parts, k, Value::from(s.wire()));
    }
    let mut o = Object::new();
    put(&mut o, "written_at", instant(r.written_at));
    put(&mut o, "setup_done", Value::Bool(r.setup_done));
    put(&mut o, "parts", Value::Object(parts));
    put(
        &mut o,
        "backups_configured",
        Value::Bool(r.backups_configured),
    );
    put(
        &mut o,
        "last_backup",
        r.last_backup.map_or(Value::Null, instant),
    );
    put(
        &mut o,
        "last_key_copy",
        r.last_key_copy.map_or(Value::Null, instant),
    );
    put(
        &mut o,
        "certificate_days",
        // An ended certificate shows as 0 days: the wire int is never
        // negative.
        r.certificate_days
            .map_or(Value::Null, |d| Value::from(d.clamp(0, 36_500))),
    );
    put(&mut o, "self_signed", Value::Bool(r.self_signed));
    put(&mut o, "route", Value::from(r.route.wire()));
    put(&mut o, "next", Value::from(r.next.wire()));
    Value::Object(o)
}

impl ToJson for SystemView {
    fn to_json(&self) -> Value {
        let f = &self.facts;
        let (file, host) = match &f.host {
            HostFile::NotConfigured => ("not_configured", Value::Null),
            HostFile::Missing => ("missing", Value::Null),
            HostFile::Unreadable => ("unreadable", Value::Null),
            HostFile::Present(r) => ("present", report_json(r)),
        };
        let mut o = Object::new();
        put(&mut o, "now", instant(self.now));
        put(
            &mut o,
            "vault",
            Value::from(if f.vault_answers { "answers" } else { "silent" }),
        );
        put(&mut o, "mail", Value::from(f.mail.wire()));
        put(&mut o, "host_file", Value::from(file));
        put(&mut o, "host", host);
        Value::Object(o)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR-028 record of lane L20: the next words are those of the reply
    /// shape, and an unknown word is none.
    #[test]
    fn adr028_l20_host_next_words_are_the_reply_words() {
        assert_eq!(&HOST_NEXT[..], fstp_access::HOST_NEXT);
        for w in HOST_NEXT {
            assert_eq!(HostNext::of(w).map(HostNext::wire), Some(w));
        }
        assert_eq!(HostNext::of("reboot"), None);
    }
}
