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
    let mut v = Entry::ALL.to_vec();
    if crate::route::ROUTE_FEED {
        v.push(Entry::Control);
    }
    v
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
    /// The custodian answers and no rotation is owed.
    Linked,
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
            Link::Unpaired => 1,
            Link::Owed => 2,
            Link::Unreachable => 3,
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
