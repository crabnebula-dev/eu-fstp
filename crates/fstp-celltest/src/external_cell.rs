//! A world cell run by the production `fstp-cell` binary from its
//! configuration file (lane L4, `docs/handoff/production-mcp-design.md`
//! section 4, ADR-026 "Configuration"). Test and local development only.
//!
//! The world provisions the cell's databases, its witness registration,
//! its vault, the relays and the edge as for an in-process cell. Instead of
//! `fstp_cell::process::start_with`, it then:
//!
//! 1. writes the credentials directory by the fixed names of ADR-026, and
//!    the sealed cell key file through the dedicated custody entry
//!    (`fstp_cell::keyfile::create`), with the keys the witness and the
//!    vault already pin;
//! 2. names the relay the caller runs, if any, as the platform relay,
//!    pinned by address (ADR-026 "Relay address"). The test passes the
//!    SMTP sink of `fstp-api-testkit`, which rule A9 keeps out of this
//!    library;
//! 3. writes `cell.json`, with the tunnel, internal and health ports drawn
//!    here, so the edge can route to the tunnel before the cell starts;
//! 4. runs `fstp-cell provision-tenant` (ADR-026 record of lane L18), then
//!    `fstp-cell first-admin --email`, then `fstp-cell` itself, and waits
//!    until `GET /healthz` answers 200.
//!
//! The binary's own process holds every key: this process never sees the
//! ledger keys of a start. The world reads a captured proof mail from the
//! relay ([`ExternalCell::mail_source`]), the way a mailbox holder reads
//! it. Every value is synthetic.

use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use fstp_cell::mail::ProofKind;

use crate::world::WorldError;
use crate::world_mail::CapturedMail;

/// How long the binary may take to reach `ready`.
pub const START_TIMEOUT: Duration = Duration::from_secs(180);

/// How long the binary may take to drain at SIGTERM.
pub const STOP_TIMEOUT: Duration = Duration::from_secs(60);

fn fail(what: &str, e: &dyn std::fmt::Display) -> WorldError {
    WorldError::Store(format!("the external cell: {what}: {e}"))
}

/// What a world needs to run its cell through the binary.
#[derive(Clone, Debug)]
pub struct ExternalSpec {
    /// The `fstp-cell` binary.
    pub binary: PathBuf,
    /// A directory of this run, where `cell.json`, the credentials
    /// directory and the first admin's token file go.
    pub dir: PathBuf,
    /// The socket of the dedicated custody entry of the key file root.
    pub key_file_custody: PathBuf,
    /// The platform relay the cell submits proof mail to, or `None` for a
    /// cell without mail.
    pub relay: Option<ExternalRelay>,
    /// The compiled web assets (`assets_dir` of ADR-026), or `None` for the
    /// stub journey shell and no auth pages.
    pub assets_dir: Option<PathBuf>,
    /// The creator shell settings (`shell` of ADR-027), or `None` for a
    /// cell whose probes are all absent.
    pub shell: Option<ExternalShell>,
}

/// The `shell` member of an external cell (ADR-027, ADR-026 record of
/// lane L18). Every value is synthetic.
#[derive(Clone, Debug)]
pub struct ExternalShell {
    /// The resolver of the sending domain probe, on loopback.
    pub resolver: SocketAddr,
    /// The DKIM selector.
    pub dkim_selector: String,
}

/// Every message a relay accepted so far, in order: its first recipient
/// and its bytes.
pub type RelayMessages = std::sync::Arc<dyn Fn() -> Vec<(String, Vec<u8>)> + Send + Sync>;

/// A submission relay the caller runs for the cell (module documentation).
#[derive(Clone)]
pub struct ExternalRelay {
    /// Where it listens, with implicit TLS.
    pub address: SocketAddr,
    /// The host name its certificate carries.
    pub relay: String,
    /// The AUTH PLAIN user.
    pub username: String,
    /// The AUTH PLAIN password. Synthetic.
    pub password: String,
    /// The CA of its certificate, PEM.
    pub ca_pem: Vec<u8>,
    /// The messages it accepted.
    pub messages: RelayMessages,
}

impl std::fmt::Debug for ExternalRelay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalRelay")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

/// One database login, as `fstp-pgtest` minted it.
pub(crate) struct DbLogin {
    pub(crate) password: String,
    pub(crate) cert_pem: Vec<u8>,
    pub(crate) key_pem: Vec<u8>,
}

/// A certificate chain and key in PEM.
pub(crate) struct Pem {
    pub(crate) cert: Vec<u8>,
    pub(crate) key: Vec<u8>,
}

/// The parts of a world cell the binary's files hold.
pub(crate) struct ExternalParts {
    pub(crate) cell: [u8; 16],
    pub(crate) host: String,
    pub(crate) self_hosted: bool,
    pub(crate) db_host: String,
    pub(crate) db_port: u16,
    pub(crate) dbname: String,
    pub(crate) db_ca: Vec<u8>,
    pub(crate) writer: DbLogin,
    pub(crate) app: DbLogin,
    pub(crate) keys: DbLogin,
    pub(crate) registered: Vec<([u8; 32], &'static str)>,
    pub(crate) keyd_socket: PathBuf,
    pub(crate) witness_addr: SocketAddr,
    pub(crate) witness_name: String,
    pub(crate) witness_ca: Vec<u8>,
    pub(crate) witness_ca_digest: [u8; 32],
    pub(crate) witness_client: Pem,
    pub(crate) receipt_keys: Vec<Vec<u8>>,
    pub(crate) vault_addr: SocketAddr,
    pub(crate) vault_ca: Vec<u8>,
    pub(crate) vault_client: Pem,
    pub(crate) tunnel: Pem,
    pub(crate) tunnel_ca: Vec<u8>,
    pub(crate) origin: Pem,
    pub(crate) internal: Pem,
    pub(crate) cell_ca: Vec<u8>,
    pub(crate) key_body: fstp_cell::keyfile::KeyBody,
}

/// A cell run by the `fstp-cell` binary (module documentation).
pub struct ExternalCell {
    spec: ExternalSpec,
    config: PathBuf,
    child: Mutex<Option<Child>>,
    relay: Option<ExternalRelay>,
    tunnel: SocketAddr,
    health: SocketAddr,
    starts: Mutex<u32>,
}

impl std::fmt::Debug for ExternalCell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalCell")
            .field("config", &self.config)
            .field("tunnel", &self.tunnel)
            .finish_non_exhaustive()
    }
}

/// The stderr lines of one serving start, as the binary wrote them.
type Lines = std::sync::Arc<Mutex<Vec<String>>>;

/// Copies the piped stderr of `child` to this process's stderr, line by
/// line, as the inherited stream showed it before, and keeps each line,
/// so a start that fails names what the binary wrote (test harness only).
fn tee_stderr(child: &mut Child) -> (Lines, Option<std::thread::JoinHandle<()>>) {
    let lines: Lines = std::sync::Arc::new(Mutex::new(Vec::new()));
    let Some(err) = child.stderr.take() else {
        return (lines, None);
    };
    let kept = std::sync::Arc::clone(&lines);
    let tee = std::thread::spawn(move || {
        use std::io::BufRead as _;
        for line in std::io::BufReader::new(err).lines() {
            let Ok(line) = line else { break };
            let _ = writeln!(std::io::stderr(), "{line}");
            kept.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(line);
        }
    });
    (lines, Some(tee))
}

/// The stderr lines of a binary that exited or was killed, once its copy
/// thread read to the end of the stream.
fn collected(lines: Lines, tee: Option<std::thread::JoinHandle<()>>) -> String {
    if let Some(t) = tee {
        let _ = t.join();
    }
    let lines = lines.lock().unwrap_or_else(PoisonError::into_inner);
    if lines.is_empty() {
        "(nothing)".to_owned()
    } else {
        lines.join(" | ")
    }
}

fn free_port() -> Result<SocketAddr, WorldError> {
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|e| fail("a free port", &e))?;
    l.local_addr().map_err(|e| fail("a free port", &e))
}

fn hex(bytes: &[u8]) -> String {
    crate::canary::lower_hex(bytes)
}

/// The bytes of `text`, exactly `2 * N` lowercase hex digits.
fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let bytes = text.as_bytes();
    if bytes.len() != N.saturating_mul(2) {
        return None;
    }
    let digit = |b: u8| match b {
        b'0'..=b'9' => Some(b.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(b.wrapping_sub(b'a').wrapping_add(10)),
        _ => None,
    };
    let mut out = [0u8; N];
    for (slot, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
        let [hi, lo] = pair else {
            return None;
        };
        *slot = (digit(*hi)? << 4) | digit(*lo)?;
    }
    Some(out)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), WorldError> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| fail("a credential file", &e))?;
    f.write_all(bytes)
        .map_err(|e| fail("a credential file", &e))
}

impl ExternalCell {
    /// Writes the files of `parts` under `spec.dir`, with the key file
    /// sealed through `spec.key_file_custody`. The cell does not run yet.
    pub(crate) fn prepare(
        rt: &fstp_rt::tokio::TokioRuntime,
        spec: &ExternalSpec,
        parts: ExternalParts,
    ) -> Result<ExternalCell, WorldError> {
        let creds = spec.dir.join("credentials");
        std::fs::create_dir_all(&creds).map_err(|e| fail("the credentials directory", &e))?;
        let files: Vec<(&str, Vec<u8>)> = vec![
            ("db-ca.pem", parts.db_ca.clone()),
            ("writer.pem", parts.writer.cert_pem.clone()),
            ("writer.key", parts.writer.key_pem.clone()),
            (
                "writer.password",
                parts.writer.password.clone().into_bytes(),
            ),
            ("app.pem", parts.app.cert_pem.clone()),
            ("app.key", parts.app.key_pem.clone()),
            ("app.password", parts.app.password.clone().into_bytes()),
            ("keys.pem", parts.keys.cert_pem.clone()),
            ("keys.key", parts.keys.key_pem.clone()),
            ("keys.password", parts.keys.password.clone().into_bytes()),
            ("tunnel.pem", parts.tunnel.cert.clone()),
            ("tunnel.key", parts.tunnel.key.clone()),
            ("tunnel-ca.pem", parts.tunnel_ca.clone()),
            ("origin.pem", parts.origin.cert.clone()),
            ("origin.key", parts.origin.key.clone()),
            ("internal.pem", parts.internal.cert.clone()),
            ("internal.key", parts.internal.key.clone()),
            ("cell-ca.pem", parts.cell_ca.clone()),
            ("witness.pem", parts.witness_client.cert.clone()),
            ("witness.key", parts.witness_client.key.clone()),
            ("witness-ca.pem", parts.witness_ca.clone()),
            (
                "witness-receipt-keys",
                fstp_cell::config::encode_receipt_keys(&parts.receipt_keys),
            ),
            ("vault.pem", parts.vault_client.cert.clone()),
            ("vault.key", parts.vault_client.key.clone()),
            ("vault-ca.pem", parts.vault_ca.clone()),
        ];
        for (name, bytes) in &files {
            write_private(&creds.join(name), bytes)?;
        }
        if let Some(r) = &spec.relay {
            write_private(&creds.join("mail.password"), r.password.as_bytes())?;
            write_private(&creds.join("mail-ca.pem"), &r.ca_pem)?;
        }
        // The key file, sealed through the dedicated custody entry.
        let custody = fstp_custody::KeydCustody::new(&spec.key_file_custody)
            .map_err(|e| fail("the key file custody", &e))?;
        let body = parts.key_body;
        let cell = parts.cell;
        let sealed = rt
            .block_on(fstp_cell::keyfile::create(&custody, cell, &body))
            .map_err(|e| fail("the key file", &e))?;
        fstp_cell::keyfile::write_atomic(&creds.join(fstp_cell::keyfile::KEY_FILE), &sealed)
            .map_err(|e| fail("the key file", &e))?;
        let tunnel = free_port()?;
        let internal = free_port()?;
        let health = free_port()?;
        let registered: Vec<String> = parts
            .registered
            .iter()
            .map(|(digest, kind)| format!(r#"{{"kind":"{kind}","spki_sha256":"{}"}}"#, hex(digest)))
            .collect();
        let config = format!(
            r#"{{{assets}"cell":"{cell}","credentials_dir":"{creds}","database":{{"dbname":"{dbname}","host":"{db_host}","port":{db_port}}},"host":"{host}","key_file_keyd_socket":"{kf}","keyd_socket":"{keyd}","listen":{{"health":"{health}","internal":"{internal}","tunnel":"{tunnel}"}},{mail}"mode":"{mode}","registered_servers":[{registered}],{shell}"vault":{{"address":"{vault}"}},"version":"0.3.0","witness":{{"address":"{waddr}","ca_spki_sha256":"{wdigest}","server_name":"{wname}"}}}}"#,
            assets = spec
                .assets_dir
                .as_ref()
                .map(|d| format!(r#""assets_dir":"{}","#, d.display()))
                .unwrap_or_default(),
            cell = hex(&parts.cell),
            creds = creds.display(),
            dbname = parts.dbname,
            db_host = parts.db_host,
            db_port = parts.db_port,
            host = parts.host,
            kf = spec.key_file_custody.display(),
            keyd = parts.keyd_socket.display(),
            mail = spec
                .relay
                .as_ref()
                .map(|r| {
                    format!(
                        r#""mail":{{"address":"{}","relay":"{}","sender":"noreply@{}","username":"{}"}},"#,
                        r.address, r.relay, parts.host, r.username
                    )
                })
                .unwrap_or_default(),
            shell = spec
                .shell
                .as_ref()
                .map(|s| {
                    format!(
                        r#""shell":{{"dkim_selector":"{}","resolver":"{}"}},"#,
                        s.dkim_selector, s.resolver
                    )
                })
                .unwrap_or_default(),
            mode = if parts.self_hosted {
                "self_hosted"
            } else {
                "saas"
            },
            registered = registered.join(","),
            vault = parts.vault_addr,
            waddr = parts.witness_addr,
            wdigest = hex(&parts.witness_ca_digest),
            wname = parts.witness_name,
        );
        // The file must decode as the binary reads it.
        fstp_cell::config::decode_file(config.as_bytes())
            .map_err(|e| fail("cell.json", &format!("{e:?}")))?;
        let path = spec.dir.join("cell.json");
        write_private(&path, config.as_bytes())?;
        Ok(ExternalCell {
            spec: spec.clone(),
            config: path,
            child: Mutex::new(None),
            relay: spec.relay.clone(),
            tunnel,
            health,
            starts: Mutex::new(0),
        })
    }

    /// The configuration file the binary reads.
    #[must_use]
    pub fn config_path(&self) -> &Path {
        &self.config
    }

    /// The tunnel listener the edge routes to.
    #[must_use]
    pub fn tunnel(&self) -> SocketAddr {
        self.tunnel
    }

    /// The loopback health listener.
    #[must_use]
    pub fn health(&self) -> SocketAddr {
        self.health
    }

    /// How many times the binary started to serve.
    #[must_use]
    pub fn starts(&self) -> u32 {
        *self.starts.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn command(&self) -> Command {
        let mut c = Command::new(&self.spec.binary);
        c.env("FSTP_CELL_CONFIG", &self.config)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        c
    }

    /// Runs `fstp-cell provision-tenant` (ADR-026 "Tenant provisioning"),
    /// with the synthetic agreement versions 1,1,1 on a SaaS cell, so the
    /// ledger holds a tenant part before the first admin is invited
    /// (ADR-026 record of lane L18).
    ///
    /// # Errors
    ///
    /// Fails when the command fails.
    pub fn provision_tenant(&self, saas: bool) -> Result<(), WorldError> {
        let mut c = self.command();
        c.arg("provision-tenant");
        if saas {
            c.arg("--agreements").arg("1,1,1");
        }
        let status = c
            .status()
            .map_err(|e| fail("fstp-cell provision-tenant", &e))?;
        if !status.success() {
            return Err(fail("fstp-cell provision-tenant", &status));
        }
        Ok(())
    }

    /// Runs `fstp-cell first-admin --email <email> <file>` (D4, ADR-026
    /// "First admin email") and gives the token as the first admin types
    /// it: both halves joined, or the whole token. The address becomes the
    /// first admin's login email.
    ///
    /// # Errors
    ///
    /// Fails when the command fails or its token file does not read.
    pub fn first_admin(&self, email: &str) -> Result<Vec<u8>, WorldError> {
        let out = self.spec.dir.join("first-admin.token");
        let status = self
            .command()
            .arg("first-admin")
            .arg("--email")
            .arg(email)
            .arg(&out)
            .status()
            .map_err(|e| fail("fstp-cell first-admin", &e))?;
        if !status.success() {
            return Err(fail("fstp-cell first-admin", &status));
        }
        let text = std::fs::read_to_string(&out).map_err(|e| fail("the token file", &e))?;
        let mut token = Vec::new();
        for line in text.lines() {
            let half = unhex::<32>(line)
                .ok_or_else(|| fail("the token file", &"a line is not 64 hex digits"))?;
            token.extend_from_slice(&half);
        }
        Ok(token)
    }

    /// Starts the binary to serve, and waits until its health listener
    /// answers 200.
    ///
    /// # Errors
    ///
    /// Fails when the binary does not start, exits, or is not ready
    /// within [`START_TIMEOUT`].
    pub fn start(&self) -> Result<(), WorldError> {
        let mut slot = self.child.lock().unwrap_or_else(PoisonError::into_inner);
        if slot.is_some() {
            return Err(fail("start", &"the cell runs already"));
        }
        let mut child = self
            .command()
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| fail("fstp-cell", &e))?;
        let (lines, tee) = tee_stderr(&mut child);
        let begun = Instant::now();
        loop {
            if let Ok(Some(status)) = child.try_wait() {
                return Err(fail(
                    "fstp-cell exited before ready",
                    &format!("{status}; its stderr: {}", collected(lines, tee)),
                ));
            }
            if healthz(self.health) {
                break;
            }
            if begun.elapsed() > START_TIMEOUT {
                let _ = child.kill();
                let _ = child.wait();
                return Err(fail(
                    "fstp-cell",
                    &format!("not ready in time; its stderr: {}", collected(lines, tee)),
                ));
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        *slot = Some(child);
        let mut starts = self.starts.lock().unwrap_or_else(PoisonError::into_inner);
        *starts = starts.saturating_add(1);
        Ok(())
    }

    /// The process id of the serving binary.
    #[must_use]
    pub fn pid(&self) -> Option<u32> {
        self.child
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(Child::id)
    }

    /// Sends SIGTERM and waits for a clean exit (ADR-002 drain).
    ///
    /// # Errors
    ///
    /// Fails when the binary does not exit in time, or exits with failure.
    pub fn stop(&self) -> Result<(), WorldError> {
        let Some(mut child) = self
            .child
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        else {
            return Ok(());
        };
        let sent = Command::new("kill")
            .arg("-TERM")
            .arg(child.id().to_string())
            .status()
            .map_err(|e| fail("kill -TERM", &e))?;
        if !sent.success() {
            return Err(fail("kill -TERM", &sent));
        }
        let begun = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) if status.success() => return Ok(()),
                Ok(Some(status)) => return Err(fail("fstp-cell exit", &status)),
                Ok(None) if begun.elapsed() > STOP_TIMEOUT => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(fail("fstp-cell", &"did not drain in time"));
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(100)),
                Err(e) => return Err(fail("fstp-cell wait", &e)),
            }
        }
    }

    /// A source of the proof mails the relay accepted, read back from
    /// their links (`fstp_cell::mail::proof_message`), for a world mail
    /// capture. `None` for a cell without a relay.
    #[must_use]
    pub fn mail_source(&self) -> Option<crate::world_mail::MailSource> {
        let messages = std::sync::Arc::clone(&self.relay.as_ref()?.messages);
        Some(std::sync::Arc::new(move || captured_from(&messages())))
    }
}

impl Drop for ExternalCell {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// Whether `GET /healthz` on `addr` answers 200.
fn healthz(addr: SocketAddr) -> bool {
    let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_secs(1)) else {
        return false;
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
    if s.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut head = [0u8; 12];
    s.read_exact(&mut head).is_ok() && head.starts_with(b"HTTP/1.1 200")
}

/// The proofs of `messages`: each message's link names its kind, case
/// and token (`fstp_cell::mail::proof_message`).
fn captured_from(messages: &[(String, Vec<u8>)]) -> Vec<CapturedMail> {
    messages
        .iter()
        .filter_map(|(to, data)| {
            let text = String::from_utf8_lossy(data);
            let to = to.clone();
            let (kind, token) = proof_of(&text)?;
            Some(CapturedMail { kind, to, token })
        })
        .collect()
}

/// The kind and token of the one proof link in `text`.
fn proof_of(text: &str) -> Option<(ProofKind, [u8; 32])> {
    let link = text
        .split_whitespace()
        .find(|w| w.starts_with("https://") && w.contains("/auth/"))?;
    let (path, fragment) = link.split_once('#')?;
    if path.ends_with("/auth/signup") {
        return Some((ProofKind::Signup, unhex::<32>(fragment)?));
    }
    if path.ends_with("/auth/magic") {
        return Some((ProofKind::MagicLink, unhex::<32>(fragment)?));
    }
    if path.ends_with("/auth/recovery") {
        let mut parts = fragment.split('.');
        let step = parts.next()?;
        let case = unhex::<16>(parts.next()?)?;
        let token = unhex::<32>(parts.next()?)?;
        return match step {
            "e" => Some((ProofKind::Recovery { case }, token)),
            "c" => Some((ProofKind::RecoveryEnrolment { case }, token)),
            _ => None,
        };
    }
    None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// The links of `fstp_cell::mail::proof_message` read back to the
    /// kind, case and token they carry.
    #[test]
    fn adr018_proof_links_read_back() {
        for kind in [
            ProofKind::Signup,
            ProofKind::MagicLink,
            ProofKind::Recovery { case: [3; 16] },
            ProofKind::RecoveryEnrolment { case: [4; 16] },
        ] {
            let m = fstp_cell::mail::proof_message("h.example.test", kind, "a@b.test", &[9; 32]);
            assert_eq!(proof_of(&m.text), Some((kind, [9; 32])));
        }
    }
}
