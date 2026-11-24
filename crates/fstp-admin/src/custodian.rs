//! The second custodian and its pairing (ADR-028 record of lane
//! `m10/guard-key`, ADR-004 "The guard key of Q-L16-1 (F-018)").
//!
//! Decided by Daniel on 2026-11-23: the second custodian is required. It
//! guards the key copies from another machine that stays on. The pilot
//! pairs with it once:
//!
//! ```text
//! pilot      fstp-admin pair-custodian <host>    writes the pairing file
//! custodian  fstp-admin custodian <file>         installs and starts it
//! pilot      fstp-admin setup                    links every fstp-keyd entry
//! ```
//!
//! The pilot's cell CA issues the custodian's server certificate and one
//! client certificate per `fstp-keyd` entry, so no new trust root is made.
//! The pairing file is the one file that crosses between the hosts. Its
//! decoder is fuzzed (`custodian_pairing_decode`).

use std::path::{Path, PathBuf};
use std::process::Command;

use fstp_json::Value;
use fstp_pki::cert::CertKind;

use crate::config::{CUSTODIAN_PORT, custodian_target};
use crate::fail::{Cause, Fail};
use crate::layout::{Entry, Layout};
use crate::pki::{Ca, Leaf, PkiFail, needs_issue, random_hex, write_pair};
use crate::say::{Part, out};
use crate::state::write_atomic;
use crate::svc::{Manager, RunFail, Service, run_logged};

/// The pairing file in the token directory of the pilot.
pub const PAIRING_FILE: &str = "fstp-custodian.pair";
/// The longest pairing file.
pub const MAX_PAIRING_LEN: usize = 32 * 1024;
/// How long the custodian's server certificate lives: two years.
pub const SERVER_LIFETIME: i64 = 730 * 86_400;
/// How long before its end `status` names a new pairing.
pub const RENEW_PAIRING_BEFORE: i64 = 30 * 86_400;
/// The CN of the custodian's server certificate.
pub const CUSTODIAN_CN: &str = "keyd-custodian";
/// The unit of the custodian.
pub const CUSTODIAN_UNIT: &str = "fstp-keyd-custodian";
/// The key volume of the custodian.
pub const CUSTODIAN_VOLUME: &str = "/var/lib/fstp-keyd-custodian";
/// The passphrase of the custodian's key volume.
pub const CUSTODIAN_PASSPHRASE: &str = "/etc/fstp/keyd/custodian.passphrase";
/// The TLS files of the custodian.
pub const CUSTODIAN_TLS_DIR: &str = "/etc/fstp/keyd-guard-server";
/// Where `fstp-keyd` is installed on the custodian.
pub const CUSTODIAN_BIN: &str = "/usr/local/bin/fstp-keyd";

/// The pairing file: the cell CA and the custodian's server certificate
/// and key, PEM, and the port it listens on.
#[derive(Clone, PartialEq, Eq)]
pub struct Pairing {
    /// The port.
    pub port: u16,
    /// The pilot's cell CA certificate.
    pub ca: String,
    /// The custodian's server certificate.
    pub cert: String,
    /// Its key.
    pub key: String,
}

impl std::fmt::Debug for Pairing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pairing")
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

/// Why a pairing file was refused. It names a rule, never the input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingError {
    /// Too long, not JSON, or not one object.
    NotJson,
    /// A member is missing, unknown or out of its grammar: its name.
    Member(&'static str),
}

impl std::fmt::Display for PairingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PairingError::NotJson => f.write_str("the pairing file is not one JSON object"),
            PairingError::Member(m) => write!(f, "the pairing file member {m} is wrong"),
        }
    }
}

impl std::error::Error for PairingError {}

const MEMBERS: [&str; 5] = ["ca", "cert", "key", "port", "version"];

fn pem_ok(text: &str, label: &str) -> bool {
    let begin = format!("-----BEGIN {label}-----\n");
    let end = format!("-----END {label}-----\n");
    text.len() <= 8192
        && text.starts_with(&begin)
        && text.ends_with(&end)
        && text.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b' ' | b'\n')
        })
}

fn json_string(text: &str) -> String {
    text.replace('\n', "\\n")
}

impl Pairing {
    /// The file text.
    #[must_use]
    pub fn encode(&self) -> String {
        format!(
            "{{\n  \"version\": 1,\n  \"port\": {},\n  \"ca\": \"{}\",\n  \"cert\": \"{}\",\n  \"key\": \"{}\"\n}}\n",
            self.port,
            json_string(&self.ca),
            json_string(&self.cert),
            json_string(&self.key),
        )
    }
}

/// Decodes a pairing file. Fuzzed (`custodian_pairing_decode`).
///
/// # Errors
///
/// [`PairingError`] for a file above [`MAX_PAIRING_LEN`], not one JSON
/// object, an unknown or missing member, another version, port 0, and a
/// certificate or key that is not one PEM block of its label.
pub fn decode_pairing(bytes: &[u8]) -> Result<Pairing, PairingError> {
    if bytes.len() > MAX_PAIRING_LEN {
        return Err(PairingError::NotJson);
    }
    let value: Value = fstp_json::parse(bytes).map_err(|_| PairingError::NotJson)?;
    let o = value.as_object().ok_or(PairingError::NotJson)?;
    if o.iter().any(|(n, _)| !MEMBERS.contains(&n)) {
        return Err(PairingError::Member("unknown"));
    }
    if o.get("version").and_then(Value::as_u64) != Some(1) {
        return Err(PairingError::Member("version"));
    }
    let port = o
        .get("port")
        .and_then(Value::as_u64)
        .and_then(|p| u16::try_from(p).ok())
        .filter(|p| *p > 0)
        .ok_or(PairingError::Member("port"))?;
    let text = |name: &'static str, label: &str| {
        o.get(name)
            .and_then(Value::as_str)
            .filter(|t| pem_ok(t, label))
            .map(str::to_owned)
            .ok_or(PairingError::Member(name))
    };
    Ok(Pairing {
        port,
        ca: text("ca", "CERTIFICATE")?,
        cert: text("cert", "CERTIFICATE")?,
        key: text("key", "PRIVATE KEY")?,
    })
}

// ---------------------------------------------------------------------------
// The pilot side.

/// The directory of the guard credentials on the pilot.
#[must_use]
pub fn guard_dir(layout: &Layout) -> PathBuf {
    layout.etc("keyd-guard")
}

fn client_files(layout: &Layout, e: Entry) -> (PathBuf, PathBuf) {
    let d = guard_dir(layout);
    (
        d.join(format!("client-{}.pem", e.name())),
        d.join(format!("client-{}.key", e.name())),
    )
}

/// Every `fstp-keyd` entry of this host, each guarded by its custodian:
/// the four of [`Entry::ALL`], and the route feed's when it runs.
#[must_use]
pub fn guarded_entries() -> Vec<Entry> {
    copy_entries(crate::route::ROUTE_FEED)
}

/// The entries of a host whose route feed runs when `route_feed`: the one
/// list that `backup-keys` copies and `restore-keys` requires (ADR-028
/// record of lane `m10/guard-key`, part 3).
#[must_use]
pub fn copy_entries(route_feed: bool) -> Vec<Entry> {
    let mut v = Entry::ALL.to_vec();
    if route_feed {
        v.push(Entry::Control);
    }
    v
}

/// The entries `restore-keys` requires a copy of.
#[must_use]
pub fn restore_entries(route_feed: bool) -> Vec<Entry> {
    copy_entries(route_feed)
}

/// The value of `FSTP_KEYD_GUARD` for the configured custodian.
#[must_use]
pub fn target_text(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// The environment and unit lines a pilot `fstp-keyd` entry gets from a
/// configured custodian, or nothing.
#[must_use]
pub fn keyd_guard(layout: &Layout, e: Entry) -> (Vec<(String, std::ffi::OsString)>, Vec<String>) {
    let Some((host, port)) = &layout.cfg.custodian else {
        return (Vec::new(), Vec::new());
    };
    let (cert, key) = client_files(layout, e);
    (
        vec![
            ("FSTP_KEYD_GUARD".into(), target_text(host, *port).into()),
            ("FSTP_KEYD_GUARD_ENTRY".into(), e.name().into()),
        ],
        vec![
            format!(
                "LoadCredential=guard-ca.pem:{}",
                guard_dir(layout).join("ca.pem").display()
            ),
            format!("LoadCredential=guard-client.pem:{}", cert.display()),
            format!("LoadCredential=guard-client.key:{}", key.display()),
        ],
    )
}

fn cell_ca(layout: &Layout) -> Result<Ca, Fail> {
    let dir = layout.ca_dir();
    std::fs::create_dir_all(&dir).map_err(|_| Fail::Step("custodian", Cause::Io))?;
    Ca::open_or_create(&dir, "fstp-cell-ca").map_err(|e| Fail::Step("custodian", Cause::Pki(e)))
}

/// Issues the guard client certificate of every entry that has none or
/// whose certificate is near its end, and writes the cell CA beside them.
/// Returns whether it issued one. Nothing happens without a custodian.
///
/// # Errors
///
/// [`Fail::Step`] when a certificate or file fails.
pub fn ensure_clients(layout: &Layout) -> Result<bool, Fail> {
    if layout.cfg.custodian.is_none() {
        return Ok(false);
    }
    let pki = |e: PkiFail| Fail::Step("custodian", Cause::Pki(e));
    let ca = cell_ca(layout)?;
    let dir = guard_dir(layout);
    std::fs::create_dir_all(&dir).map_err(|_| Fail::Step("custodian", Cause::Io))?;
    write_atomic(&dir.join("ca.pem"), &ca.pem, 0o600)
        .map_err(|_| Fail::Step("custodian", Cause::Io))?;
    let mut did = false;
    for e in guarded_entries() {
        let (cert, _) = client_files(layout, e);
        if !needs_issue(&cert) {
            continue;
        }
        let cn = format!("keyd-guard-{}", e.name());
        let issued = ca
            .issue(&Leaf {
                cn: &cn,
                ou: None,
                kind: CertKind::Client,
                dns: &[],
                ips: &[],
            })
            .map_err(pki)?;
        write_pair(
            &dir,
            &format!("client-{}.pem", e.name()),
            &format!("client-{}.key", e.name()),
            &issued,
        )
        .map_err(pki)?;
        did = true;
    }
    Ok(did)
}

/// Adds or replaces the member `custodian` of the configuration file at
/// `config`, keeping every other byte, and checks the result.
///
/// # Errors
///
/// [`Fail::Config`] when the result does not decode, and [`Fail::Step`]
/// when the file does not read or write.
pub fn set_member(config: &Path, value: &str) -> Result<(), Fail> {
    let io = |_| Fail::Step("custodian", Cause::Io);
    let text = std::fs::read_to_string(config).map_err(io)?;
    let line = format!("\"custodian\": \"{value}\"");
    let new = match text.find("\"custodian\"") {
        Some(at) => {
            let rest = text.get(at..).unwrap_or_default();
            let end = rest
                .char_indices()
                .skip_while(|(_, c)| *c != ':')
                .skip(1)
                .skip_while(|(_, c)| *c != '"')
                .skip(1)
                .find(|(_, c)| *c == '"')
                .map(|(i, _)| at.saturating_add(i).saturating_add(1))
                .ok_or(Fail::Step("custodian", Cause::Io))?;
            format!(
                "{}{line}{}",
                text.get(..at).unwrap_or_default(),
                text.get(end..).unwrap_or_default()
            )
        }
        None => {
            let open = text.find('{').ok_or(Fail::Step("custodian", Cause::Io))?;
            format!(
                "{}{{\n  {line},{}",
                text.get(..open).unwrap_or_default(),
                text.get(open.saturating_add(1)..).unwrap_or_default()
            )
        }
    };
    crate::config::decode(new.as_bytes()).map_err(|e| Fail::Config(config.to_owned(), e))?;
    write_atomic(config, new.as_bytes(), 0o600).map_err(io)
}

/// `fstp-admin pair-custodian <host>` on the pilot: the custodian's
/// server certificate, the pairing file, the configuration member and the
/// guard client certificates.
///
/// # Errors
///
/// [`Fail::Usage`] for a host that is not a name or an address, and
/// [`Fail::Step`] when a certificate or file fails.
pub fn pair(layout: &Layout, config: &Path, target: &str) -> Result<(), Fail> {
    let (host, port) = custodian_target(target).ok_or(Fail::Usage)?;
    let pki = |e: PkiFail| Fail::Step("custodian", Cause::Pki(e));
    let ca = cell_ca(layout)?;
    let ip: Vec<std::net::IpAddr> = host.parse().into_iter().collect();
    let dns: Vec<&str> = if ip.is_empty() {
        vec![host.as_str()]
    } else {
        Vec::new()
    };
    let issued = ca
        .issue_for(
            &Leaf {
                cn: CUSTODIAN_CN,
                ou: None,
                kind: CertKind::Server,
                dns: &dns,
                ips: &ip,
            },
            Some(SERVER_LIFETIME),
        )
        .map_err(pki)?;
    let pairing = Pairing {
        port,
        ca: String::from_utf8_lossy(&ca.pem).into_owned(),
        cert: String::from_utf8_lossy(&issued.cert_pem).into_owned(),
        key: String::from_utf8_lossy(&issued.key_pem).into_owned(),
    };
    decode_pairing(pairing.encode().as_bytes()).map_err(|_| Fail::Step("custodian", Cause::Io))?;
    let file = layout.cfg.paths.token_dir.join(PAIRING_FILE);
    write_atomic(&file, pairing.encode().as_bytes(), 0o600)
        .map_err(|_| Fail::Step("custodian", Cause::Io))?;
    let dir = guard_dir(layout);
    std::fs::create_dir_all(&dir).map_err(|_| Fail::Step("custodian", Cause::Io))?;
    write_atomic(
        &dir.join("custodian.pem.expires"),
        issued.not_after.to_string().as_bytes(),
        0o600,
    )
    .map_err(|_| Fail::Step("custodian", Cause::Io))?;
    set_member(config, &target_text(&host, port))?;
    let with_member = crate::config::decode(
        &std::fs::read(config).map_err(|_| Fail::Step("custodian", Cause::Io))?,
    )
    .map_err(|e| Fail::Config(config.to_owned(), e))?;
    ensure_clients(&Layout::new(with_member))?;
    out(&[Part::T("  done     pairing file "), Part::P(&file)]);
    out(&[Part::T(
        "Next: copy that file to the custodian machine, run fstp-admin custodian <file> there as root, then run fstp-admin setup here.",
    )]);
    Ok(())
}

/// The result of `fstp-keyd guard-check` for one entry (ADR-028 record of
/// lane `m10/guard-key`, row "Status").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Link {
    /// The custodian answers and nothing is owed.
    Linked,
    /// The custodian answers, but a fresh copy is owed to it: the last try
    /// failed (ADR-004 "The custodian's copy").
    CopyOwed,
    /// A rotation is owed: an erasure waits.
    Owed,
    /// The custodian does not answer.
    Unreachable,
    /// No custodian is configured.
    Unpaired,
}

impl Link {
    /// The link of a `guard-check` exit code.
    #[must_use]
    pub fn of_exit(code: Option<i32>) -> Link {
        match code {
            Some(0) => Link::Linked,
            Some(6) => Link::CopyOwed,
            Some(3) => Link::Owed,
            Some(5) => Link::Unpaired,
            _ => Link::Unreachable,
        }
    }

    /// The worse of two links.
    #[must_use]
    pub fn worse(self, other: Link) -> Link {
        let rank = |l: Link| match l {
            Link::Linked => 0,
            Link::CopyOwed => 1,
            Link::Unpaired => 2,
            Link::Owed => 3,
            Link::Unreachable => 4,
        };
        if rank(other) > rank(self) {
            other
        } else {
            self
        }
    }
}

/// Fills `dir` with the guard credentials of entry `e`, under the names
/// `fstp-keyd` reads from `$CREDENTIALS_DIRECTORY`.
///
/// # Errors
///
/// The I/O error of a copy.
pub fn stage_credentials(layout: &Layout, e: Entry, dir: &Path) -> std::io::Result<()> {
    let (cert, key) = client_files(layout, e);
    for (from, to) in [
        (guard_dir(layout).join("ca.pem"), "guard-ca.pem"),
        (cert, "guard-client.pem"),
        (key, "guard-client.key"),
    ] {
        write_atomic(&dir.join(to), &std::fs::read(from)?, 0o600)?;
    }
    Ok(())
}

/// Runs `fstp-keyd guard-check` for entry `e`.
#[must_use]
pub fn check(layout: &Layout, e: Entry) -> Link {
    let Some((host, port)) = &layout.cfg.custodian else {
        return Link::Unpaired;
    };
    let creds = layout
        .admin_dir()
        .join(format!("guard-credential-{}", e.name()));
    let _ = std::fs::remove_dir_all(&creds);
    let staged =
        std::fs::create_dir_all(&creds).and_then(|()| stage_credentials(layout, e, &creds));
    let link = staged.map_or(Link::Unreachable, |()| {
        let mut c = Command::new(layout.bin("fstp-keyd"));
        c.env("CREDENTIALS_DIRECTORY", &creds)
            .env("FSTP_KEYD_GUARD", target_text(host, *port))
            .env("FSTP_KEYD_GUARD_ENTRY", e.name())
            .arg("guard-check")
            .arg(layout.keyd_volume(e));
        Link::of_exit(run_logged(&mut c, &Manager::new(layout).log()).unwrap_or(None))
    });
    let _ = std::fs::remove_dir_all(&creds);
    link
}

/// The link of the whole host: the worst over the entries that erase.
#[must_use]
pub fn host_link(layout: &Layout) -> Link {
    if layout.cfg.custodian.is_none() {
        return Link::Unpaired;
    }
    check(layout, Entry::Cell).worse(check(layout, Entry::Vault))
}

// ---------------------------------------------------------------------------
// The custodian side.

/// The unit of the custodian, listening on `port`.
#[must_use]
pub fn custodian_service(bin: &Path, port: u16) -> Service {
    Service {
        name: CUSTODIAN_UNIT.into(),
        what: "second custodian (guard of the key copies)",
        program: bin.to_owned(),
        args: Vec::new(),
        env: vec![(
            "FSTP_KEYD_GUARD_LISTEN".into(),
            format!("0.0.0.0:{port}").into(),
        )],
        user: Some(crate::stack::KEYD_USER.into()),
        unit_lines: vec![
            format!("StateDirectory={}", CUSTODIAN_UNIT),
            format!("RuntimeDirectory={}", CUSTODIAN_UNIT),
            "RuntimeDirectoryPreserve=yes".into(),
            format!(
                "BindPaths={CUSTODIAN_VOLUME}:/var/lib/fstp-keyd /run/{CUSTODIAN_UNIT}:/run/fstp-keyd"
            ),
            format!("LoadCredential=fstp-keyd-passphrase:{CUSTODIAN_PASSPHRASE}"),
            format!("LoadCredential=guard-ca.pem:{CUSTODIAN_TLS_DIR}/ca.pem"),
            format!("LoadCredential=guard-server.pem:{CUSTODIAN_TLS_DIR}/server.pem"),
            format!("LoadCredential=guard-server.key:{CUSTODIAN_TLS_DIR}/server.key"),
        ],
        direct_credentials: None,
        hold_stdin: false,
        ready: crate::svc::Ready::Socket(PathBuf::from(format!(
            "/run/{CUSTODIAN_UNIT}/console.sock"
        ))),
        after: Vec::new(),
    }
}

fn run(step: &'static str, c: &mut Command, log: &Path) -> Result<(), Fail> {
    match run_logged(c, log) {
        Ok(Some(0)) => Ok(()),
        Ok(code) => Err(Fail::Step(
            step,
            Cause::Run(RunFail::Exit(PathBuf::from(c.get_program()), code)),
        )),
        Err(e) => Err(Fail::Step(step, e.into())),
    }
}

/// `fstp-admin custodian <file>` on the custodian machine: installs or
/// updates the custodian from the pairing file, starts it, and deletes
/// the file. Run again with a new file, it keeps the key volume and its
/// guards (a new pilot after the loss of the old one).
///
/// # Errors
///
/// [`Fail::Missing`] for a file that does not read or decode, and
/// [`Fail::Step`] when a step fails.
pub fn install(file: &Path) -> Result<(), Fail> {
    let step = "custodian";
    let io = |_| Fail::Step(step, Cause::Io);
    let bytes =
        std::fs::read(file).map_err(|_| Fail::Missing(file.to_owned(), "the pairing file"))?;
    let p = decode_pairing(&bytes).map_err(|_| {
        Fail::Missing(
            file.to_owned(),
            "a pairing file of fstp-admin pair-custodian",
        )
    })?;
    let log = PathBuf::from("/var/log/fstp-admin-custodian.log");
    if crate::stack::gid_of(crate::stack::KEYD_USER).is_none() {
        let mut c = Command::new("useradd");
        c.args([
            "--system",
            "--user-group",
            "--no-create-home",
            "--shell",
            "/usr/sbin/nologin",
            crate::stack::KEYD_USER,
        ]);
        run(step, &mut c, &log)?;
    }
    let tls = Path::new(CUSTODIAN_TLS_DIR);
    std::fs::create_dir_all(tls).map_err(io)?;
    write_atomic(&tls.join("ca.pem"), p.ca.as_bytes(), 0o600).map_err(io)?;
    write_atomic(&tls.join("server.pem"), p.cert.as_bytes(), 0o600).map_err(io)?;
    write_atomic(&tls.join("server.key"), p.key.as_bytes(), 0o600).map_err(io)?;
    let pass = Path::new(CUSTODIAN_PASSPHRASE);
    if !pass.is_file() {
        if let Some(dir) = pass.parent() {
            std::fs::create_dir_all(dir).map_err(io)?;
        }
        let secret = random_hex(32).map_err(|e| Fail::Step(step, Cause::Pki(e)))?;
        write_atomic(pass, format!("{secret}\n").as_bytes(), 0o600).map_err(io)?;
    }
    let s = custodian_service(Path::new(CUSTODIAN_BIN), p.port);
    write_atomic(
        &Path::new("/etc/systemd/system").join(format!("{CUSTODIAN_UNIT}.service")),
        Manager::unit_text(&s).as_bytes(),
        0o644,
    )
    .map_err(io)?;
    run(step, Command::new("systemctl").arg("daemon-reload"), &log)?;
    run(
        step,
        Command::new("systemctl").args(["enable", "--now", CUSTODIAN_UNIT]),
        &log,
    )?;
    run(
        step,
        Command::new("systemctl").args(["restart", CUSTODIAN_UNIT]),
        &log,
    )?;
    std::fs::remove_file(file).map_err(io)?;
    out(&[Part::T(
        "  done     second custodian running. Keep this machine on. Next, on the pilot: fstp-admin setup.",
    )]);
    Ok(())
}

// ---------------------------------------------------------------------------
// Restore after the loss of the host (ADR-028 record of lane
// `m10/guard-key`, part 2; decided by Daniel on 2026-11-24, Q-F018-5).

/// The length of the clear header of a guarded copy (ADR-004 record of
/// lane `m10/guard-key`, row "Outer seal of a copy").
pub const COPY_HEADER_LEN: usize = 36;

/// The clear header of a guarded copy: `"FGC1" | version u8 = 1 | kem u16
/// = 1 | entry u8 | generation u32 | copy id 16 | created u64`, integers
/// big-endian.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CopyHeader {
    /// The guard code of the pilot entry: 1 to 5.
    pub entry: u8,
    /// The guard generation the copy is sealed to, at least 1.
    pub generation: u32,
    /// The copy id.
    pub id: [u8; 16],
    /// When the copy was made, in Unix seconds.
    pub created: u64,
}

impl CopyHeader {
    /// The header bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; COPY_HEADER_LEN] {
        let parts: [&[u8]; 7] = [
            b"FGC1",
            &[1],
            &1u16.to_be_bytes(),
            &[self.entry],
            &self.generation.to_be_bytes(),
            &self.id,
            &self.created.to_be_bytes(),
        ];
        let mut out = [0u8; COPY_HEADER_LEN];
        for (o, b) in out.iter_mut().zip(parts.into_iter().flatten()) {
            *o = *b;
        }
        out
    }
}

/// `N` bytes of `b` from `at`.
fn take<const N: usize>(b: &[u8], at: usize) -> Option<[u8; N]> {
    b.get(at..at.checked_add(N)?)?.try_into().ok()
}

/// The guard code of entry `e`, as `fstp-keyd` numbers the pilot entries.
#[must_use]
pub fn guard_code(e: Entry) -> u8 {
    match e {
        Entry::Cell => 1,
        Entry::CellKeys => 2,
        Entry::Vault => 3,
        Entry::Witness => 4,
        Entry::Control => 5,
    }
}

/// Decodes the clear header at the start of `bytes`, which may hold the
/// rest of the copy. `None` for anything but a header of version 1, KEM
/// 1, a known entry and a generation of at least 1. Fuzzed
/// (`guarded_copy_header_decode`).
#[must_use]
pub fn decode_copy_header(bytes: &[u8]) -> Option<CopyHeader> {
    let [entry] = take::<1>(bytes, 7)?;
    let generation = u32::from_be_bytes(take(bytes, 8)?);
    let id = take::<16>(bytes, 12)?;
    let created = u64::from_be_bytes(take(bytes, 28)?);
    let fixed = take::<4>(bytes, 0)? == *b"FGC1"
        && take::<1>(bytes, 4)? == [1]
        && take::<2>(bytes, 5)? == 1u16.to_be_bytes();
    (fixed && (1..=5).contains(&entry) && generation > 0).then_some(CopyHeader {
        entry,
        generation,
        id,
        created,
    })
}

/// The header of a copy file, read from its first bytes only.
fn file_header(file: &Path) -> Option<CopyHeader> {
    use std::io::Read as _;
    let mut buf = [0u8; COPY_HEADER_LEN];
    std::fs::File::open(file).ok()?.read_exact(&mut buf).ok()?;
    decode_copy_header(&buf)
}

/// The header of `<dir>/<entry>.fkx`, when it is a guarded copy of `e`.
#[must_use]
pub fn stick_header(dir: &Path, e: Entry) -> Option<CopyHeader> {
    file_header(&dir.join(format!("{}.fkx", e.name()))).filter(|h| h.entry == guard_code(e))
}

/// Which copy `restore-keys` takes for one entry (ADR-028 record of lane
/// `m10/guard-key`, part 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pick {
    /// The directory's copy; the custodian holds none.
    Directory,
    /// The custodian's held copy; the directory holds none.
    Custodian,
    /// The directory's copy, of the custodian's generation and as new.
    DirectoryAsNew,
    /// The custodian's held copy, newer than the directory's.
    CustodianNewer,
}

/// The copy to take, from the directory's header and the custodian's held
/// copy's header. The custodian serves a held copy only of its newest
/// live generation, so it always opens. The directory's copy is taken
/// over it only at the same generation and at least as new. A copy of
/// any other generation is sealed to a destroyed guard, or to none of
/// this custodian's (I-81).
#[must_use]
pub fn pick(stick: Option<CopyHeader>, held: Option<CopyHeader>) -> Option<Pick> {
    match (stick, held) {
        (None, None) => None,
        (Some(_), None) => Some(Pick::Directory),
        (None, Some(_)) => Some(Pick::Custodian),
        (Some(s), Some(h)) if s.generation == h.generation && s.created >= h.created => {
            Some(Pick::DirectoryAsNew)
        }
        (Some(_), Some(_)) => Some(Pick::CustodianNewer),
    }
}

impl Pick {
    /// The end of the `done` line that names the copy and why.
    fn said(self) -> &'static str {
        match self {
            Pick::Directory => {
                " entry, from the copy in the directory; the second custodian holds none."
            }
            Pick::Custodian => {
                " entry, from the second custodian; the directory holds no copy of it."
            }
            Pick::DirectoryAsNew => {
                " entry, from the copy in the directory, which is as new as the second custodian's."
            }
            Pick::CustodianNewer => {
                " entry, from the second custodian, whose copy is newer than the one in the directory."
            }
        }
    }
}

/// The old host's passphrase of entry `e`, when `dir` holds one.
#[must_use]
pub fn passphrase_in(dir: &Path, e: Entry) -> Option<PathBuf> {
    let p = passphrase_file(dir, e);
    p.is_file().then_some(p)
}

/// The passphrase of entry `e` in a copy directory: the one name that
/// `backup-keys` writes and `restore-keys` reads.
fn passphrase_file(dir: &Path, e: Entry) -> PathBuf {
    dir.join(format!("{}.passphrase", e.name()))
}

/// The first file of `dest` that `backup-keys` would write over: a copy or
/// a passphrase of any entry (ADR-028 record of lane `m10/guard-key`,
/// part 3).
#[must_use]
pub fn occupied(dest: &Path) -> Option<PathBuf> {
    guarded_entries()
        .into_iter()
        .flat_map(|e| {
            [
                dest.join(format!("{}.fkx", e.name())),
                passphrase_file(dest, e),
            ]
        })
        .find(|p| p.exists())
}

/// Creates the copy directory `dest` with mode 0700, or sets an existing
/// one to 0700. A FAT or exFAT stick has no Unix modes and refuses the
/// change, so its mount options decide there.
///
/// # Errors
///
/// The I/O error of the creation.
pub fn private_dir(dest: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dest)?;
    let _ = std::fs::set_permissions(dest, std::fs::Permissions::from_mode(0o700));
    Ok(())
}

/// `backup-keys`, after every copy succeeded (ADR-028 record of lane
/// `m10/guard-key`, part 3, decided by Daniel on 2026-11-24): writes each
/// guarded entry's passphrase into `dest` as `<entry>.passphrase`, mode
/// 0600, so `restore-keys` asks for nothing. Only when `guarded`, that is
/// every copy is sealed to the custodian's guard: a plain copy opens with
/// its passphrase alone (I-80). An entry without a passphrase on this
/// host is skipped. Returns whether it wrote them. Nothing is printed or
/// logged.
///
/// # Errors
///
/// The I/O error of a passphrase that exists and does not copy.
pub fn write_passphrases(layout: &Layout, dest: &Path, guarded: bool) -> std::io::Result<bool> {
    if !guarded {
        return Ok(false);
    }
    private_dir(dest)?;
    for e in guarded_entries() {
        let from = layout.keyd_passphrase(e);
        if from.is_file() {
            crate::state::copy_atomic(&from, &passphrase_file(dest, e), 0o600)?;
        }
    }
    Ok(true)
}

/// `restore-keys`: when `dir` holds the old host's passphrase of entry
/// `e`, moves the current one aside as
/// `<entry>.passphrase.before-restore-<stamp>` and puts the old one in
/// its place, mode 0600. Returns whether `dir` held one.
///
/// # Errors
///
/// The I/O error of any step.
pub fn install_passphrase(
    layout: &Layout,
    dir: &Path,
    e: Entry,
    stamp: i64,
) -> std::io::Result<bool> {
    let Some(old) = passphrase_in(dir, e) else {
        return Ok(false);
    };
    let current = layout.keyd_passphrase(e);
    let aside = current.with_extension(format!("passphrase.before-restore-{stamp}"));
    if current.is_file() {
        std::fs::rename(&current, &aside)?;
    }
    crate::state::copy_atomic(&old, &current, 0o600)?;
    Ok(true)
}

/// Runs `fstp-keyd <args>` for entry `e` with its passphrase and guard
/// credentials staged, and returns the exit code.
fn keyd_with_credentials(
    layout: &Layout,
    e: Entry,
    args: &[&std::ffi::OsStr],
) -> Result<Option<i32>, Fail> {
    let step = "restore keys";
    let io = |_| Fail::Step(step, Cause::Io);
    let Some((host, port)) = &layout.cfg.custodian else {
        return Err(Fail::Waits(
            "the second custodian: run fstp-admin pair-custodian <host> first",
        ));
    };
    let creds = layout
        .admin_dir()
        .join(format!("restore-credential-{}", e.name()));
    let _ = std::fs::remove_dir_all(&creds);
    std::fs::create_dir_all(&creds).map_err(io)?;
    let staged = stage_credentials(layout, e, &creds).and_then(|()| {
        let pass = std::fs::read(layout.keyd_passphrase(e))?;
        write_atomic(&creds.join("fstp-keyd-passphrase"), &pass, 0o600)
    });
    let r = staged.map_err(io).and_then(|()| {
        let mut c = Command::new(layout.bin("fstp-keyd"));
        c.env("CREDENTIALS_DIRECTORY", &creds)
            .env("FSTP_KEYD_GUARD", target_text(host, *port))
            .env("FSTP_KEYD_GUARD_ENTRY", e.name())
            .args(args);
        run_logged(&mut c, &Manager::new(layout).log()).map_err(|f| Fail::Step(step, f.into()))
    });
    let _ = std::fs::remove_dir_all(&creds);
    r
}

fn exit_fail(layout: &Layout, code: Option<i32>) -> Fail {
    Fail::Step(
        "restore keys",
        Cause::Run(RunFail::Exit(layout.bin("fstp-keyd"), code)),
    )
}

/// The marker `restore-keys` leaves for the next `restore`: the restore
/// follows a host loss (ADR-012 record of lane m10/witness-copy, lead
/// answer 1). It holds the time it was written.
const HOST_LOSS_FILE: &str = "host-loss-restore";

/// Writes the host-loss marker.
///
/// # Errors
///
/// The I/O error of the write.
pub fn mark_host_loss(layout: &Layout) -> std::io::Result<()> {
    std::fs::create_dir_all(layout.admin_dir())?;
    write_atomic(
        &layout.admin_dir().join(HOST_LOSS_FILE),
        format!("{}\n", crate::pki::now()).as_bytes(),
        0o600,
    )
}

/// Whether the next `restore` follows `restore-keys` on this host.
#[must_use]
pub fn host_loss_pending(layout: &Layout) -> bool {
    layout.admin_dir().join(HOST_LOSS_FILE).is_file()
}

/// Removes the host-loss marker, once the witness store is rebuilt.
pub fn clear_host_loss(layout: &Layout) {
    let _ = std::fs::remove_file(layout.admin_dir().join(HOST_LOSS_FILE));
}

/// `fstp-admin restore-keys <dir>` on a new host, after `setup` and the
/// pairing: puts each `fstp-keyd` entry's keys back from its copy, held
/// until `fstp-admin restore` releases it. Every copy is found first, so a
/// missing one changes nothing. Each volume it replaces is moved aside,
/// never deleted.
///
/// # Errors
///
/// [`Fail::Waits`] before the pairing, [`Fail::Missing`] for an entry
/// with no copy in `dir` and none at the custodian, and [`Fail::Step`]
/// when a step fails. The services then stay stopped.
pub fn restore_keys(layout: &Layout, dir: &Path) -> Result<(), Fail> {
    let step = "restore keys";
    let io = |_| Fail::Step(step, Cause::Io);
    if layout.cfg.custodian.is_none() {
        return Err(Fail::Waits(
            "the second custodian: run fstp-admin pair-custodian <host> first",
        ));
    }
    let staging = layout.admin_dir().join("restore-keys");
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging).map_err(io)?;
    // Lead reading of 2026-11-24 (ADR-028 record of lane `m10/guard-key`,
    // part 3): the custodian's held copy, unless the directory's is of the
    // same live generation and as new. Never a copy of a destroyed guard
    // while a held copy exists (I-81).
    let mut copies = Vec::new();
    for e in restore_entries(crate::route::ROUTE_FEED) {
        let held_file = staging.join(format!("{}.fgc", e.name()));
        let held = match keyd_with_credentials(
            layout,
            e,
            &["fetch-copy".as_ref(), held_file.as_os_str()],
        )? {
            Some(0) => Some(file_header(&held_file).ok_or(Fail::Step(step, Cause::Io))?),
            Some(7) => None,
            code => return Err(exit_fail(layout, code)),
        };
        let file = match pick(stick_header(dir, e), held) {
            Some(p @ (Pick::Directory | Pick::DirectoryAsNew)) => {
                (p, dir.join(format!("{}.fkx", e.name())))
            }
            Some(p @ (Pick::Custodian | Pick::CustodianNewer)) => (p, held_file),
            None => {
                return Err(Fail::Missing(
                    dir.join(format!("{}.fkx", e.name())),
                    "a key copy of this entry: there is none here and none at the second custodian",
                ));
            }
        };
        copies.push((e, file));
    }
    crate::ops::stop(layout)?;
    let m = Manager::new(layout);
    let stamp = crate::pki::now();
    for (e, (chosen, file)) in &copies {
        install_passphrase(layout, dir, *e, stamp).map_err(io)?;
        let volume = layout.keyd_volume(*e);
        let aside = volume.with_file_name(format!(
            "{}.before-restore-{stamp}",
            volume
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("keyd")
        ));
        if volume.exists() {
            std::fs::rename(&volume, &aside).map_err(io)?;
        }
        let mut builder = std::fs::DirBuilder::new();
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(&volume).map_err(io)?;
        match keyd_with_credentials(
            layout,
            *e,
            &["import".as_ref(), file.as_os_str(), volume.as_os_str()],
        )? {
            Some(0) => {}
            code => {
                // Without a held copy, the directory's copy may be sealed
                // to a destroyed guard: the custodian refuses to open it
                // and nothing is written (I-81).
                crate::say::err(&[
                    Part::T("  failed   keys of the "),
                    Part::T(e.name()),
                    Part::T(
                        " entry: fstp-keyd import refused the copy and wrote nothing. A copy older than the last erasure of its entry never opens.",
                    ),
                ]);
                return Err(exit_fail(layout, code));
            }
        }
        if layout.cfg.services == crate::config::Services::Systemd {
            let owner = format!("{0}:{0}", crate::stack::KEYD_USER);
            let mut c = Command::new("chown");
            c.arg("-R").arg(&owner).arg(&volume);
            run(step, &mut c, &m.log())?;
        }
        out(&[
            Part::T("  done     keys of the "),
            Part::T(e.name()),
            Part::T(chosen.said()),
        ]);
    }
    for e in restore_entries(crate::route::ROUTE_FEED) {
        for s in crate::stack::keyd(layout, e) {
            m.ensure(&s).map_err(|f| Fail::Step(step, f.into()))?;
        }
    }
    let _ = std::fs::remove_dir_all(&staging);
    // ADR-012 record of lane m10/witness-copy, lead answer 1: the next
    // restore is a host-loss restore.
    mark_host_loss(layout).map_err(io)?;
    out(&[Part::T(
        "Next: run fstp-admin restore. It restores both databases and then releases these keys.",
    )]);
    Ok(())
}

/// The newest live epoch of `chain` (1 App, 2 Vault) in the one cell
/// database of cluster `c` whose name starts with `prefix`, or 0.
fn current_epoch(
    layout: &Layout,
    c: crate::layout::Cluster,
    prefix: &str,
    chain: u8,
) -> Result<u64, Fail> {
    let pg = |e| Fail::Step("restore", Cause::Pg(e));
    let db = crate::pg::psql(
        layout,
        c,
        "postgres",
        &format!(
            "SELECT datname FROM pg_database WHERE datname LIKE '{prefix}\\_%' ORDER BY datname LIMIT 1;"
        ),
        "the cell database",
    )
    .map_err(pg)?;
    if db.is_empty() || !db.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return Ok(0);
    }
    let text = crate::pg::psql(
        layout,
        c,
        &db,
        &format!(
            "SELECT coalesce(max(epoch), 0) FROM keystore.root WHERE state = 1 AND chain = {chain};"
        ),
        "the current key epoch",
    )
    .map_err(pg)?;
    text.trim()
        .parse()
        .map_err(|_| Fail::Step("restore", Cause::Io))
}

/// The `release` arguments of entry `e`: the cell's newest live App epoch
/// and the vault's newest live Vault epoch from the restored databases.
/// Every other entry holds no erasable chain.
#[must_use]
pub fn release_args(e: Entry, app: u64, vault: u64) -> Vec<String> {
    match (e, app, vault) {
        (Entry::Cell, a, _) if a > 0 => vec![format!("app={a}")],
        (Entry::Vault, _, v) if v > 0 => vec![format!("vault={v}")],
        _ => Vec::new(),
    }
}

/// Releases every held entry after `fstp-admin restore` restored the
/// databases (ADR-004 record of lane L16, rule 3). Each entry stops for
/// its release and starts again. Nothing happens on a host whose entries
/// are not held.
///
/// # Errors
///
/// [`Fail::Step`] naming the entry whose release refused: its copy is
/// older than the last erasure, or the custodian does not answer.
pub fn release_held(layout: &Layout, m: &Manager) -> Result<(), Fail> {
    let held: Vec<Entry> = guarded_entries()
        .into_iter()
        .filter(|e| layout.keyd_volume(*e).join("import.hold").exists())
        .collect();
    if held.is_empty() {
        return Ok(());
    }
    let app = current_epoch(layout, crate::layout::Cluster::App, "c", 1)?;
    let vault = current_epoch(layout, crate::layout::Cluster::Vault, "v", 2)?;
    for e in held {
        let services = crate::stack::keyd(layout, e);
        for s in &services {
            m.stop(s).map_err(|f| Fail::Step("restore", f.into()))?;
        }
        let volume = layout.keyd_volume(e);
        let rest = release_args(e, app, vault);
        let mut args: Vec<&std::ffi::OsStr> = vec!["release".as_ref(), volume.as_os_str()];
        args.extend(rest.iter().map(|a| std::ffi::OsStr::new(a.as_str())));
        let code = keyd_with_credentials(layout, e, &args)?;
        for s in &services {
            m.ensure(s).map_err(|f| Fail::Step("restore", f.into()))?;
        }
        if code != Some(0) {
            return Err(exit_fail(layout, code));
        }
        out(&[
            Part::T("  done     released the keys of the "),
            Part::T(e.name()),
            Part::T(" entry"),
        ]);
    }
    Ok(())
}

/// Days until the custodian's server certificate ends, if paired.
#[must_use]
pub fn pairing_days(layout: &Layout) -> Option<i64> {
    crate::pki::expires(&guard_dir(layout).join("custodian.pem"))
        .map(|at| at.saturating_sub(crate::pki::now()) / 86_400)
}

/// The default port, for the usage text.
pub const DEFAULT_PORT: u16 = CUSTODIAN_PORT;

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    fn sample() -> Pairing {
        Pairing {
            port: 7460,
            ca: "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n".into(),
            cert: "-----BEGIN CERTIFICATE-----\nREVG\n-----END CERTIFICATE-----\n".into(),
            key: "-----BEGIN PRIVATE KEY-----\nR0hJ\n-----END PRIVATE KEY-----\n".into(),
        }
    }

    /// ADR-028 record of lane `m10/guard-key`: the pairing file reads back
    /// what it was written with, and refuses an unknown member, another
    /// version, port 0 and a key that is not one PEM block.
    #[test]
    fn adr028_guard_pairing_file_round_trips() {
        let p = sample();
        assert_eq!(decode_pairing(p.encode().as_bytes()).unwrap(), p);
        let text = p.encode();
        for (from, to) in [
            ("\"version\": 1", "\"version\": 2"),
            ("\"port\": 7460", "\"port\": 0"),
            ("\"version\": 1", "\"other\": 1, \"version\": 1"),
            ("PRIVATE KEY-----\\nR0hJ", "PRIVATE KEY-----\\nR\\\"0hJ"),
        ] {
            let bad = text.replacen(from, to, 1);
            assert!(decode_pairing(bad.as_bytes()).is_err(), "{to}");
        }
    }

    /// ADR-028 record of lane `m10/guard-key`: with a custodian, every
    /// `fstp-keyd` unit of the pilot names it and its own entry, and loads
    /// the cell CA and its own guard client certificate and key. Without
    /// one, the units are as before.
    #[test]
    fn adr028_guard_keyd_units_carry_the_guard_credentials() {
        let base = r#"{"domain":"grants.example.eu","operator_email":"admin@example.eu",
            "mail":{"relay":"smtp.example.eu","username":"cell"}"#;
        let paired =
            crate::config::decode(format!(r#"{base},"custodian":"c.example.eu"}}"#).as_bytes())
                .unwrap();
        let layout = Layout::new(paired);
        for e in guarded_entries() {
            for s in crate::stack::keyd(&layout, e) {
                let t = Manager::unit_text(&s);
                for want in [
                    "Environment=FSTP_KEYD_GUARD=c.example.eu:7460\n".to_owned(),
                    format!("Environment=FSTP_KEYD_GUARD_ENTRY={}\n", e.name()),
                    "LoadCredential=guard-ca.pem:/etc/fstp/keyd-guard/ca.pem\n".to_owned(),
                    format!(
                        "LoadCredential=guard-client.key:/etc/fstp/keyd-guard/client-{}.key\n",
                        e.name()
                    ),
                ] {
                    assert!(t.contains(&want), "{want}");
                }
            }
        }
        let alone = Layout::new(crate::config::decode(format!("{base}}}").as_bytes()).unwrap());
        for s in crate::stack::keyd(&alone, Entry::Cell) {
            assert!(!Manager::unit_text(&s).contains("GUARD"));
        }
    }

    /// ADR-028 record of lane `m10/guard-key`: one command on the pilot
    /// writes a pairing file that decodes, names the custodian in the
    /// configuration file, and issues a guard client certificate for every
    /// entry under the cell CA, which the pairing file carries.
    #[test]
    fn adr028_guard_pair_custodian_writes_one_file_and_the_member() {
        let dir = std::env::temp_dir().join(format!("fstp-admin-pair-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let d = dir.display();
        let text = format!(
            r#"{{"domain":"grants.example.eu","operator_email":"admin@example.eu",
            "mail":{{"relay":"smtp.example.eu","username":"cell"}},
            "paths":{{"etc":"{d}/etc","state":"{d}/state","token_dir":"{d}"}}}}"#
        );
        let config = dir.join("fstp.json");
        std::fs::write(&config, &text).unwrap();
        let layout = Layout::new(crate::config::decode(text.as_bytes()).unwrap());
        pair(&layout, &config, "custodian.example.eu").unwrap();
        let p = decode_pairing(&std::fs::read(dir.join(PAIRING_FILE)).unwrap()).unwrap();
        assert_eq!(p.port, CUSTODIAN_PORT);
        let paired = crate::config::decode(&std::fs::read(&config).unwrap()).unwrap();
        assert_eq!(
            paired.custodian,
            Some(("custodian.example.eu".into(), CUSTODIAN_PORT))
        );
        let guard = guard_dir(&Layout::new(paired));
        assert_eq!(std::fs::read_to_string(guard.join("ca.pem")).unwrap(), p.ca);
        for e in guarded_entries() {
            assert!(guard.join(format!("client-{}.key", e.name())).is_file());
        }
        assert!(pairing_days(&layout).is_some_and(|d| d > 700));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ADR-028 record of lane `m10/guard-key`, part 2 (Q-F018-5, decided by
    /// Daniel on 2026-11-24), F-018: `restore-keys` takes each entry's copy
    /// from the directory when it holds one and from the custodian
    /// otherwise, takes the old passphrase only from the directory, refuses
    /// before the pairing, and releases the cell and the vault with their
    /// own current epochs only.
    #[test]
    fn adr028_guard_restore_keys_takes_each_copy_from_the_directory_or_the_custodian() {
        let dir = std::env::temp_dir().join(format!("fstp-admin-restore-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cell = header(Entry::Cell, 2, 50);
        std::fs::write(dir.join("cell.fkx"), cell.encode()).unwrap();
        std::fs::write(dir.join("vault.passphrase"), b"old\n").unwrap();
        assert_eq!(stick_header(&dir, Entry::Cell), Some(cell));
        assert_eq!(stick_header(&dir, Entry::Vault), None);
        assert_eq!(pick(stick_header(&dir, Entry::Vault), None), None);
        assert_eq!(
            pick(stick_header(&dir, Entry::Vault), Some(cell)),
            Some(Pick::Custodian)
        );
        assert_eq!(
            passphrase_in(&dir, Entry::Vault),
            Some(dir.join("vault.passphrase"))
        );
        assert_eq!(passphrase_in(&dir, Entry::Cell), None);
        assert_eq!(release_args(Entry::Cell, 7, 3), vec!["app=7".to_owned()]);
        assert_eq!(release_args(Entry::Vault, 7, 3), vec!["vault=3".to_owned()]);
        assert!(release_args(Entry::CellKeys, 7, 3).is_empty());
        assert!(release_args(Entry::Cell, 0, 3).is_empty());
        let unpaired = Layout::new(
            crate::config::decode(
                br#"{"domain":"grants.example.eu","operator_email":"admin@example.eu",
                "mail":{"relay":"smtp.example.eu","username":"cell"}}"#,
            )
            .unwrap(),
        );
        assert!(matches!(restore_keys(&unpaired, &dir), Err(Fail::Waits(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A synthetic clear header of a guarded copy of `e`.
    fn header(e: Entry, generation: u32, created: u64) -> CopyHeader {
        CopyHeader {
            entry: guard_code(e),
            generation,
            id: [0x5a; 16],
            created,
        }
    }

    /// ADR-028 record of lane `m10/guard-key`, part 3 (lead reading of
    /// 2026-11-24), F-018: `backup-keys` copies exactly the entries
    /// `restore-keys` requires, with the route feed on and off, so a
    /// restore never stops on an entry the copy left out.
    #[test]
    fn adr028_f018_backup_keys_and_restore_keys_agree_on_the_entries() {
        for route_feed in [false, true] {
            let backup = crate::ops::backup_entries(route_feed);
            let restore = restore_entries(route_feed);
            assert_eq!(backup, restore, "route feed {route_feed}");
            for e in Entry::ALL {
                assert!(backup.contains(&e), "{}", e.name());
            }
            assert_eq!(backup.contains(&Entry::Control), route_feed);
        }
        assert_eq!(
            crate::ops::backup_entries(crate::route::ROUTE_FEED),
            guarded_entries()
        );
    }

    /// I-81, ADR-028 record of lane `m10/guard-key`, part 3 (lead reading
    /// of 2026-11-24), F-018: `restore-keys` takes the custodian's held
    /// copy unless the directory's copy is of the same generation and as
    /// new, and takes the one copy there is when only one exists.
    #[test]
    fn i81_adr028_f018_restore_keys_takes_the_newer_live_copy() {
        let h = |g, c| Some(header(Entry::Vault, g, c));
        assert_eq!(pick(None, None), None);
        assert_eq!(pick(h(3, 100), None), Some(Pick::Directory));
        assert_eq!(pick(None, h(3, 100)), Some(Pick::Custodian));
        assert_eq!(pick(h(3, 200), h(3, 100)), Some(Pick::DirectoryAsNew));
        assert_eq!(pick(h(3, 100), h(3, 100)), Some(Pick::DirectoryAsNew));
        assert_eq!(pick(h(3, 100), h(3, 200)), Some(Pick::CustodianNewer));
    }

    /// I-81, ADR-028 record of lane `m10/guard-key`, part 3, F-018: the
    /// custodian serves a held copy only of its newest live generation. So
    /// a directory copy of any other generation is sealed to a destroyed
    /// guard, or to none of this custodian's, and is never taken while a
    /// held copy exists, however late it was made.
    #[test]
    fn i81_adr028_f018_restore_keys_never_takes_a_stick_copy_of_a_destroyed_guard() {
        let h = |g, c| Some(header(Entry::Cell, g, c));
        assert_eq!(pick(h(2, 999), h(3, 100)), Some(Pick::CustodianNewer));
        assert_eq!(pick(h(7, 999), h(2, 100)), Some(Pick::CustodianNewer));
        for sg in 1..6u32 {
            for hg in 1..6u32 {
                for (sc, hc) in [(1u64, 2u64), (2, 2), (3, 2)] {
                    let p = pick(h(sg, sc), h(hg, hc));
                    if matches!(p, Some(Pick::Directory | Pick::DirectoryAsNew)) {
                        assert_eq!(sg, hg, "stick {sg}/{sc}, held {hg}/{hc}");
                    }
                }
            }
        }
    }

    /// ADR-028 record of lane `m10/guard-key`, part 3, F-018: the clear
    /// header of a guarded copy reads back what it was written with, its
    /// copy id where `ops::copy_id` reads it, and refuses another magic,
    /// version or KEM, an unknown entry, generation 0 and a short input.
    #[test]
    fn adr028_f018_guarded_copy_header_decodes_and_refuses() {
        let h = header(Entry::Control, 9, 1_790_000_000);
        let bytes = h.encode();
        assert_eq!(bytes.len(), COPY_HEADER_LEN);
        assert_eq!(decode_copy_header(&bytes), Some(h));
        let mut long = bytes.to_vec();
        long.extend_from_slice(&[7; 64]);
        assert_eq!(decode_copy_header(&long), Some(h));
        assert_eq!(
            crate::ops::copy_id(&bytes).as_deref(),
            Some("5a".repeat(16).as_str())
        );
        assert_eq!(decode_copy_header(bytes.get(..35).unwrap()), None);
        for (at, value) in [(0, b'X'), (4, 2), (6, 2), (7, 0), (7, 6)] {
            let mut bad = bytes;
            *bad.get_mut(at).unwrap() = value;
            assert_eq!(decode_copy_header(&bad), None, "byte {at}");
        }
        let zero = CopyHeader { generation: 0, ..h };
        assert_eq!(decode_copy_header(&zero.encode()), None);
        let dir = fresh("copy-header");
        std::fs::write(dir.join("control.fkx"), &long).unwrap();
        assert_eq!(stick_header(&dir, Entry::Control), Some(h));
        std::fs::write(dir.join("cell.fkx"), &long).unwrap();
        assert_eq!(stick_header(&dir, Entry::Cell), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A host layout under `dir`, paired with a custodian when `paired`,
    /// with a synthetic passphrase per guarded entry tagged `host`.
    fn host(dir: &Path, paired: bool, host: &str) -> Layout {
        let d = dir.display();
        let custodian = if paired {
            r#","custodian":"c.example.eu""#
        } else {
            ""
        };
        let text = format!(
            r#"{{"domain":"grants.example.eu","operator_email":"admin@example.eu",
            "mail":{{"relay":"smtp.example.eu","username":"cell"}},
            "paths":{{"etc":"{d}/etc","state":"{d}/state","token_dir":"{d}"}}{custodian}}}"#
        );
        let layout = Layout::new(crate::config::decode(text.as_bytes()).unwrap());
        for e in guarded_entries() {
            write_atomic(
                &layout.keyd_passphrase(e),
                synthetic_passphrase(e, host).as_bytes(),
                0o600,
            )
            .unwrap();
        }
        layout
    }

    fn synthetic_passphrase(e: Entry, host: &str) -> String {
        format!("synthetic-{}-passphrase-of-host-{host}\n", e.name())
    }

    fn mode(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    fn fresh(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fstp-admin-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// ADR-028 record of lane `m10/guard-key`, part 3 (decided by Daniel
    /// on 2026-11-24), F-018: `backup-keys` writes every guarded entry's
    /// passphrase beside the copies, mode 0600 in a directory of mode
    /// 0700, in the name and format `restore-keys` reads. On a new host,
    /// `restore-keys` then finds each one and puts the old host's
    /// passphrase in place, with the new host's moved aside, so nothing is
    /// typed.
    #[test]
    fn adr028_f018_backup_keys_passphrases_round_trip_to_restore_keys() {
        let dir = fresh("pass-round-trip");
        let old = host(&dir.join("old"), true, "old");
        let new = host(&dir.join("new"), true, "new");
        let stick = dir.join("usb").join("fstp-keys");
        assert_eq!(occupied(&stick), None);
        assert!(write_passphrases(&old, &stick, true).unwrap());
        assert_eq!(mode(&stick), 0o700);
        for e in guarded_entries() {
            let p = passphrase_in(&stick, e).unwrap();
            assert_eq!(mode(&p), 0o600, "{}", e.name());
            assert_eq!(
                std::fs::read_to_string(&p).unwrap(),
                synthetic_passphrase(e, "old")
            );
        }
        for f in std::fs::read_dir(&stick).unwrap().flatten() {
            let name = f.file_name().into_string().unwrap();
            assert!(name.ends_with(".passphrase"), "{name}");
        }
        assert!(occupied(&stick).is_some());
        for e in guarded_entries() {
            assert!(install_passphrase(&new, &stick, e, 42).unwrap());
            let current = new.keyd_passphrase(e);
            assert_eq!(
                std::fs::read_to_string(&current).unwrap(),
                synthetic_passphrase(e, "old")
            );
            assert_eq!(mode(&current), 0o600);
            let aside = current.with_extension("passphrase.before-restore-42");
            assert_eq!(
                std::fs::read_to_string(aside).unwrap(),
                synthetic_passphrase(e, "new")
            );
        }
        let none = dir.join("empty");
        std::fs::create_dir_all(&none).unwrap();
        assert!(!install_passphrase(&new, &none, Entry::Cell, 43).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// I-80, ADR-028 record of lane `m10/guard-key`, part 3: a plain
    /// `"FKX1"` copy opens with its passphrase alone, so no passphrase is
    /// written beside one. Only a guarded `"FGC1"` copy, which also needs
    /// the custodian, gets its passphrase.
    #[test]
    fn i80_adr028_f018_backup_keys_writes_no_passphrase_beside_an_unguarded_copy() {
        let dir = fresh("pass-unguarded");
        let layout = host(&dir.join("dev"), false, "dev");
        let dest = dir.join("copy");
        assert!(!write_passphrases(&layout, &dest, false).unwrap());
        for e in guarded_entries() {
            assert_eq!(passphrase_in(&dest, e), None);
        }
        assert!(crate::ops::is_guarded(b"FGC1\x01rest"));
        assert!(!crate::ops::is_guarded(b"FKX1\x01rest"));
        assert!(!crate::ops::is_guarded(b"FG"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ADR-028 record of lane `m10/guard-key`, part 3: `backup-keys`
    /// refuses a directory that already holds a copy or a passphrase of
    /// any entry, before it stops anything, so no old passphrase is
    /// written over.
    #[test]
    fn adr028_f018_backup_keys_refuses_a_directory_that_holds_a_passphrase() {
        let dir = fresh("pass-occupied");
        let layout = host(&dir.join("pilot"), true, "pilot");
        let dest = dir.join("copy");
        assert_eq!(occupied(&dest), None);
        std::fs::create_dir_all(&dest).unwrap();
        assert_eq!(occupied(&dest), None);
        std::fs::write(dest.join("control.passphrase"), b"x\n").unwrap();
        assert_eq!(occupied(&dest), Some(dest.join("control.passphrase")));
        let mut state = crate::state::State::load(&dir.join("state")).unwrap();
        assert!(matches!(
            crate::ops::backup_keys(&layout, &mut state, &dest),
            Err(Fail::Missing(p, _)) if p == dest.join("control.passphrase")
        ));
        assert_eq!(
            std::fs::read(dest.join("control.passphrase")).unwrap(),
            b"x\n"
        );
        std::fs::remove_file(dest.join("control.passphrase")).unwrap();
        std::fs::write(dest.join("vault.fkx"), b"FGC1").unwrap();
        assert_eq!(occupied(&dest), Some(dest.join("vault.fkx")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ADR-028 record of lane `m10/guard-key`: the custodian's unit loads
    /// its passphrase and the three TLS files as credentials and names its
    /// listen address, and the custodian's address renders as the pilot
    /// reads it.
    #[test]
    fn adr028_guard_custodian_unit_carries_its_credentials() {
        let t = Manager::unit_text(&custodian_service(Path::new(CUSTODIAN_BIN), 7460));
        for want in [
            "Environment=FSTP_KEYD_GUARD_LISTEN=0.0.0.0:7460\n",
            "LoadCredential=guard-server.key:/etc/fstp/keyd-guard-server/server.key\n",
            "LoadCredential=fstp-keyd-passphrase:/etc/fstp/keyd/custodian.passphrase\n",
            "User=fstp-keyd\n",
        ] {
            assert!(t.contains(want), "{want}");
        }
        assert_eq!(target_text("2001:db8::1", 9), "[2001:db8::1]:9");
        assert_eq!(target_text("c.example.eu", 7460), "c.example.eu:7460");
        assert_eq!(Link::Linked.worse(Link::Owed), Link::Owed);
        assert_eq!(Link::of_exit(Some(4)), Link::Unreachable);
    }
}
