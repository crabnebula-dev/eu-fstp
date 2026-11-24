//! The host status file (ADR-028 record of lane L20).
//!
//! `fstp-admin` writes it, and the cell reads it read-only to show the
//! tenant admins' System page. It holds operational facts only: every
//! value is an integer, a boolean, `null` or one word of a closed list.
//! No member can hold free text, a name, an address, a path, an account
//! or a domain (R-NF-02).
//!
//! ```text
//! {"app_snapshot_failed":false,"backups_configured":true,"certificate_days":5,
//!  "custodian":"linked","drill_seconds":412,"drill_step":"none",
//!  "guard_copy_owed":false,"guard_owed":false,
//!  "last_app_snapshot":1795000000,"last_backup":1795000000,
//!  "last_drill_passed":1795000000,
//!  "last_key_copy":null,"last_vault_erasure":null,
//!  "last_vault_snapshot":1795000000,"last_wal_archived":1795000000,
//!  "next":"nothing",
//!  "parts":{"cell":"running","databases":"running","edge":"running",
//!           "keys":"running","vault":"running","witness":"running"},
//!  "route":"current","self_signed":false,"setup_done":true,
//!  "vault_snapshot_failed":false,"version":1,"wal_archive":"ok",
//!  "written_at":1795000000}
//! ```
//!
//! [`encode`] writes one line, members sorted, with a trailing line
//! break. [`decode`] refuses an unknown, missing or repeated member and
//! any value outside its range. A refusal names its rule and never quotes
//! the input. The fuzz target `host_status_decode` covers [`decode`].

use std::fmt;

use fstp_json::{Object, ParseLimits, Value};

use crate::drill_status::{self, Step as DrillStep};

/// The grammar version this module reads and writes.
pub const VERSION: u64 = 1;

/// The longest file accepted, in bytes.
pub const MAX_LEN: usize = 4096;

/// The latest instant accepted, 9999-12-31T23:59:59Z in Unix seconds.
pub const MAX_INSTANT: i64 = 253_402_300_799;

/// The largest number of certificate days accepted, either sign.
pub const MAX_DAYS: i64 = 36_500;

/// How one part of the host runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PartState {
    /// Every service of the part runs and is ready.
    Running,
    /// A service runs but does not answer its readiness check.
    Unhealthy,
    /// A service is not running.
    Stopped,
}

impl PartState {
    /// Every state.
    pub const ALL: [PartState; 3] = [Self::Running, Self::Unhealthy, Self::Stopped];

    /// The word in the file.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Unhealthy => "unhealthy",
            Self::Stopped => "stopped",
        }
    }

    /// The worse of two states.
    #[must_use]
    pub const fn worst(self, other: PartState) -> PartState {
        match (self, other) {
            (Self::Stopped, _) | (_, Self::Stopped) => Self::Stopped,
            (Self::Unhealthy, _) | (_, Self::Unhealthy) => Self::Unhealthy,
            _ => Self::Running,
        }
    }
}

/// The parts of a host, each the worst of its services.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Parts {
    /// The platform cell.
    pub cell: PartState,
    /// The identity vault.
    pub vault: PartState,
    /// The witness.
    pub witness: PartState,
    /// The public edge and the route feed.
    pub edge: PartState,
    /// The two database clusters.
    pub databases: PartState,
    /// The key custody entries.
    pub keys: PartState,
}

impl Parts {
    /// Every part running.
    pub const RUNNING: Parts = Parts {
        cell: PartState::Running,
        vault: PartState::Running,
        witness: PartState::Running,
        edge: PartState::Running,
        databases: PartState::Running,
        keys: PartState::Running,
    };
}

/// Whether the edge's route pins the current certificates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RouteState {
    /// The pins match.
    Current,
    /// The edge pins an older certificate.
    Mismatch,
    /// The route could not be read.
    Unknown,
}

impl RouteState {
    /// Every state.
    pub const ALL: [RouteState; 3] = [Self::Current, Self::Mismatch, Self::Unknown];

    /// The word in the file.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Mismatch => "mismatch",
            Self::Unknown => "unknown",
        }
    }
}

/// The link to the second custodian, which guards the key copies
/// (ADR-028 record of lane `m10/guard-key`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CustodianState {
    /// Every erasing entry reaches it.
    Linked,
    /// An entry does not reach it: erasures wait.
    Unreachable,
    /// None is paired.
    Unpaired,
    /// The host runs in direct mode, where none is used.
    NotUsed,
}

impl CustodianState {
    /// Every state.
    pub const ALL: [CustodianState; 4] = [
        Self::Linked,
        Self::Unreachable,
        Self::Unpaired,
        Self::NotUsed,
    ];

    /// The word in the file.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Linked => "linked",
            Self::Unreachable => "unreachable",
            Self::Unpaired => "unpaired",
            Self::NotUsed => "not_used",
        }
    }
}

/// The state of the WAL archive of both clusters, the worse of the two
/// (ADR-012 record of lane m10/backup-health).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum WalArchive {
    /// Every finished segment reached the object store in time.
    Ok,
    /// A finished segment has waited too long for its upload.
    Late,
    /// The last upload failed, and none succeeded since.
    Failing,
    /// No backups, or a cluster did not answer.
    #[default]
    Unknown,
}

impl WalArchive {
    /// Every state.
    pub const ALL: [WalArchive; 4] = [Self::Ok, Self::Late, Self::Failing, Self::Unknown];

    /// The word in the file.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Late => "late",
            Self::Failing => "failing",
            Self::Unknown => "unknown",
        }
    }

    /// The worse of two states: failing, then late, then unknown.
    #[must_use]
    pub const fn worst(self, other: WalArchive) -> WalArchive {
        match (self, other) {
            (Self::Failing, _) | (_, Self::Failing) => Self::Failing,
            (Self::Late, _) | (_, Self::Late) => Self::Late,
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            _ => Self::Ok,
        }
    }
}

/// The one next thing `fstp-admin status` names (ADR-028 "Status").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Next {
    /// Setup has not finished.
    RunSetup,
    /// A service is down.
    StartService,
    /// The second custodian does not answer, or a guard rotation is owed.
    Custodian,
    /// No second custodian is paired, or its pairing nears its end.
    PairCustodian,
    /// A fresh copy is owed to the second custodian: the last try failed
    /// (ADR-004 "The custodian's copy").
    CustodianCopy,
    /// The route's pins differ from the current certificates.
    RenewRoute,
    /// A certificate is near its end.
    Renew,
    /// The public certificate is self-signed.
    PublicCertificate,
    /// No object store for backups is configured.
    ConfigureBackups,
    /// The WAL archive fails, or a finished segment waits too long for
    /// its upload (ADR-012 record of lane m10/backup-health).
    WalArchive,
    /// The newest backup is old or missing.
    Backup,
    /// No restore drill passed in 35 days, or the last one failed (ADR-012
    /// record of lane m10/backup-health).
    RestoreDrill,
    /// The web admins enrol and invite the second admin.
    WebAdmins,
    /// The host admin verifies the admins in person.
    VerifyAdmins,
    /// A keystore snapshot failed, or none verified in a day and a half
    /// (ADR-028 record of lane L27).
    KeystoreSnapshot,
    /// The keys were never copied off the host.
    CopyKeys,
    /// Nothing.
    Nothing,
}

impl Next {
    /// Every value.
    pub const ALL: [Next; 17] = [
        Self::RunSetup,
        Self::StartService,
        Self::Custodian,
        Self::PairCustodian,
        Self::RenewRoute,
        Self::Renew,
        Self::PublicCertificate,
        Self::ConfigureBackups,
        Self::WalArchive,
        Self::Backup,
        Self::RestoreDrill,
        Self::CustodianCopy,
        Self::KeystoreSnapshot,
        Self::WebAdmins,
        Self::VerifyAdmins,
        Self::CopyKeys,
        Self::Nothing,
    ];

    /// The word in the file.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::RunSetup => "run_setup",
            Self::StartService => "start_service",
            Self::Custodian => "custodian",
            Self::PairCustodian => "pair_custodian",
            Self::CustodianCopy => "custodian_copy",
            Self::RenewRoute => "renew_route",
            Self::Renew => "renew",
            Self::PublicCertificate => "public_certificate",
            Self::ConfigureBackups => "configure_backups",
            Self::WalArchive => "wal_archive",
            Self::Backup => "backup",
            Self::RestoreDrill => "restore_drill",
            Self::KeystoreSnapshot => "keystore_snapshot",
            Self::WebAdmins => "web_admins",
            Self::VerifyAdmins => "verify_admins",
            Self::CopyKeys => "copy_keys",
            Self::Nothing => "nothing",
        }
    }
}

/// One host status report.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HostStatus {
    /// When `fstp-admin` wrote it, in Unix seconds.
    pub written_at: i64,
    /// Setup finished.
    pub setup_done: bool,
    /// How each part runs.
    pub parts: Parts,
    /// An object store for backups is configured.
    pub backups_configured: bool,
    /// The older of the two clusters' newest base backups, in Unix seconds.
    pub last_backup: Option<i64>,
    /// The newest copy of the keys off the host, in Unix seconds.
    pub last_key_copy: Option<i64>,
    /// The newest identity erasure `fstp-admin erase-identity` ran in the
    /// vault, in Unix seconds. A key copy older than it holds the erased
    /// key, so the runbook asks for a new copy.
    pub last_vault_erasure: Option<i64>,
    /// When the cell's App chain keystore snapshot last verified, in Unix
    /// seconds (ADR-012 and ADR-028 records of lane L27).
    pub last_app_snapshot: Option<i64>,
    /// The cell's last keystore snapshot try failed.
    pub app_snapshot_failed: bool,
    /// When the vault's keystore snapshot last verified, in Unix seconds.
    pub last_vault_snapshot: Option<i64>,
    /// The vault's last keystore snapshot try failed.
    pub vault_snapshot_failed: bool,
    /// Whole days until the first host certificate ends.
    pub certificate_days: Option<i64>,
    /// The public origin certificate is self-signed.
    pub self_signed: bool,
    /// Whether the route pins the current certificates.
    pub route: RouteState,
    /// The one next thing to do on the host.
    pub next: Next,
    /// The link to the second custodian.
    pub custodian: CustodianState,
    /// A guard rotation is owed, so an erasure waits.
    pub guard_owed: bool,
    /// A fresh copy is owed to the custodian.
    pub guard_copy_owed: bool,
    /// The state of the WAL archive (ADR-012 record of lane
    /// m10/backup-health).
    pub wal_archive: WalArchive,
    /// The older of the two clusters' last archived segments, in Unix
    /// seconds.
    pub last_wal_archived: Option<i64>,
    /// When a restore drill last passed, in Unix seconds.
    pub last_drill_passed: Option<i64>,
    /// Where the last restore drill failed, `None` when it passed or none
    /// ran.
    pub drill_step: Option<DrillStep>,
    /// The restore duration of the last passed drill, in seconds.
    pub drill_seconds: Option<i64>,
}

/// Why a file was refused. Names a rule, never the input (R-NF-02).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostStatusError {
    /// Longer than [`MAX_LEN`].
    TooLong,
    /// Not JSON, nested too deep, or a member repeated.
    NotJson,
    /// Not one JSON object.
    NotAnObject,
    /// A member the grammar does not name.
    UnknownMember,
    /// A member is missing.
    MissingMember(&'static str),
    /// A member's value is out of its grammar.
    Invalid(&'static str),
    /// Another grammar version.
    Version,
}

impl fmt::Display for HostStatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong => f.write_str("the host status file is too long"),
            Self::NotJson => f.write_str("the host status file is not valid JSON"),
            Self::NotAnObject => f.write_str("the host status file is not one object"),
            Self::UnknownMember => f.write_str("the host status file names an unknown member"),
            Self::MissingMember(m) => write!(f, "the host status file has no member {m}"),
            Self::Invalid(m) => write!(f, "the host status member {m} is invalid"),
            Self::Version => f.write_str("the host status file has another version"),
        }
    }
}

impl std::error::Error for HostStatusError {}

const MEMBERS: [&str; 24] = [
    "app_snapshot_failed",
    "backups_configured",
    "certificate_days",
    "custodian",
    "drill_seconds",
    "drill_step",
    "guard_copy_owed",
    "guard_owed",
    "last_app_snapshot",
    "last_backup",
    "last_drill_passed",
    "last_key_copy",
    "last_vault_erasure",
    "last_vault_snapshot",
    "last_wal_archived",
    "next",
    "parts",
    "route",
    "self_signed",
    "setup_done",
    "vault_snapshot_failed",
    "version",
    "wal_archive",
    "written_at",
];

const PART_MEMBERS: [&str; 6] = ["cell", "databases", "edge", "keys", "vault", "witness"];

fn opt(v: Option<i64>) -> String {
    v.map_or_else(|| "null".to_owned(), |n| n.to_string())
}

/// The file text of `s`: one line of JSON, members sorted, and a line
/// break.
#[must_use]
pub fn encode(s: &HostStatus) -> String {
    let p = &s.parts;
    format!(
        "{{\"app_snapshot_failed\":{},\"backups_configured\":{},\"certificate_days\":{},\
         \"custodian\":\"{}\",\"drill_seconds\":{},\"drill_step\":\"{}\",\
         \"guard_copy_owed\":{},\"guard_owed\":{},\
         \"last_app_snapshot\":{},\"last_backup\":{},\"last_drill_passed\":{},\"last_key_copy\":{},\
         \"last_vault_erasure\":{},\"last_vault_snapshot\":{},\"last_wal_archived\":{},\
         \"next\":\"{}\",\"parts\":{{\"cell\":\"{}\",\
         \"databases\":\"{}\",\"edge\":\"{}\",\"keys\":\"{}\",\"vault\":\"{}\",\
         \"witness\":\"{}\"}},\"route\":\"{}\",\"self_signed\":{},\"setup_done\":{},\
         \"vault_snapshot_failed\":{},\"version\":{VERSION},\"wal_archive\":\"{}\",\
         \"written_at\":{}}}\n",
        s.app_snapshot_failed,
        s.backups_configured,
        opt(s.certificate_days),
        s.custodian.word(),
        opt(s.drill_seconds),
        s.drill_step.map_or("none", DrillStep::word),
        s.guard_copy_owed,
        s.guard_owed,
        opt(s.last_app_snapshot),
        opt(s.last_backup),
        opt(s.last_drill_passed),
        opt(s.last_key_copy),
        opt(s.last_vault_erasure),
        opt(s.last_vault_snapshot),
        opt(s.last_wal_archived),
        s.next.word(),
        p.cell.word(),
        p.databases.word(),
        p.edge.word(),
        p.keys.word(),
        p.vault.word(),
        p.witness.word(),
        s.route.word(),
        s.self_signed,
        s.setup_done,
        s.vault_snapshot_failed,
        s.wal_archive.word(),
        s.written_at,
    )
}

fn closed(o: &Object, names: &[&str]) -> Result<(), HostStatusError> {
    if o.keys().any(|k| !names.contains(&k)) {
        return Err(HostStatusError::UnknownMember);
    }
    Ok(())
}

fn member<'a>(o: &'a Object, name: &'static str) -> Result<&'a Value, HostStatusError> {
    o.get(name).ok_or(HostStatusError::MissingMember(name))
}

fn flag(o: &Object, name: &'static str) -> Result<bool, HostStatusError> {
    member(o, name)?
        .as_bool()
        .ok_or(HostStatusError::Invalid(name))
}

fn int_in(v: &Value, lo: i64, hi: i64, name: &'static str) -> Result<i64, HostStatusError> {
    v.as_i64()
        .filter(|n| (lo..=hi).contains(n))
        .ok_or(HostStatusError::Invalid(name))
}

fn opt_int(
    o: &Object,
    name: &'static str,
    lo: i64,
    hi: i64,
) -> Result<Option<i64>, HostStatusError> {
    let v = member(o, name)?;
    if v.is_null() {
        Ok(None)
    } else {
        int_in(v, lo, hi, name).map(Some)
    }
}

fn word<T: Copy>(
    v: &Value,
    all: &[T],
    word: fn(T) -> &'static str,
    name: &'static str,
) -> Result<T, HostStatusError> {
    let s = v.as_str().ok_or(HostStatusError::Invalid(name))?;
    all.iter()
        .copied()
        .find(|x| word(*x) == s)
        .ok_or(HostStatusError::Invalid(name))
}

fn part(o: &Object, name: &'static str, rule: &'static str) -> Result<PartState, HostStatusError> {
    word(member(o, name)?, &PartState::ALL, PartState::word, rule)
}

/// Reads a host status file.
///
/// # Errors
///
/// [`HostStatusError`] for any input outside the grammar.
pub fn decode(bytes: &[u8]) -> Result<HostStatus, HostStatusError> {
    if bytes.len() > MAX_LEN {
        return Err(HostStatusError::TooLong);
    }
    let limits = ParseLimits {
        max_input_bytes: MAX_LEN,
        max_depth: 2,
        max_string_bytes: 64,
        ..ParseLimits::default()
    };
    let value = fstp_json::parse_with(bytes, &limits).map_err(|_| HostStatusError::NotJson)?;
    let o = value.as_object().ok_or(HostStatusError::NotAnObject)?;
    closed(o, &MEMBERS)?;
    let version = member(o, "version")?;
    if version.as_u64() != Some(VERSION) {
        return Err(HostStatusError::Version);
    }
    let p = member(o, "parts")?
        .as_object()
        .ok_or(HostStatusError::Invalid("parts"))?;
    closed(p, &PART_MEMBERS)?;
    let parts = Parts {
        cell: part(p, "cell", "parts.cell")?,
        vault: part(p, "vault", "parts.vault")?,
        witness: part(p, "witness", "parts.witness")?,
        edge: part(p, "edge", "parts.edge")?,
        databases: part(p, "databases", "parts.databases")?,
        keys: part(p, "keys", "parts.keys")?,
    };
    Ok(HostStatus {
        written_at: int_in(member(o, "written_at")?, 0, MAX_INSTANT, "written_at")?,
        setup_done: flag(o, "setup_done")?,
        parts,
        backups_configured: flag(o, "backups_configured")?,
        last_backup: opt_int(o, "last_backup", 0, MAX_INSTANT)?,
        last_key_copy: opt_int(o, "last_key_copy", 0, MAX_INSTANT)?,
        last_vault_erasure: opt_int(o, "last_vault_erasure", 0, MAX_INSTANT)?,
        last_app_snapshot: opt_int(o, "last_app_snapshot", 0, MAX_INSTANT)?,
        app_snapshot_failed: flag(o, "app_snapshot_failed")?,
        last_vault_snapshot: opt_int(o, "last_vault_snapshot", 0, MAX_INSTANT)?,
        vault_snapshot_failed: flag(o, "vault_snapshot_failed")?,
        certificate_days: opt_int(o, "certificate_days", -MAX_DAYS, MAX_DAYS)?,
        self_signed: flag(o, "self_signed")?,
        route: word(
            member(o, "route")?,
            &RouteState::ALL,
            RouteState::word,
            "route",
        )?,
        next: word(member(o, "next")?, &Next::ALL, Next::word, "next")?,
        custodian: word(
            member(o, "custodian")?,
            &CustodianState::ALL,
            CustodianState::word,
            "custodian",
        )?,
        guard_owed: flag(o, "guard_owed")?,
        guard_copy_owed: flag(o, "guard_copy_owed")?,
        wal_archive: word(
            member(o, "wal_archive")?,
            &WalArchive::ALL,
            WalArchive::word,
            "wal_archive",
        )?,
        last_wal_archived: opt_int(o, "last_wal_archived", 0, MAX_INSTANT)?,
        last_drill_passed: opt_int(o, "last_drill_passed", 0, MAX_INSTANT)?,
        drill_step: match member(o, "drill_step")?.as_str() {
            Some("none") => None,
            _ => Some(word(
                member(o, "drill_step")?,
                &DrillStep::ALL,
                DrillStep::word,
                "drill_step",
            )?),
        },
        drill_seconds: opt_int(
            o,
            "drill_seconds",
            1,
            i64::try_from(drill_status::MAX_SECONDS).unwrap_or(i64::MAX),
        )?,
    })
}
