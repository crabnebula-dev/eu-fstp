//! A world vault run by the production `fstp-vault` binary from its
//! configuration file (lane L8, gap G12, ADR-026 record of lane L8). Test
//! and local development only.
//!
//! [`start_world`] starts a world whose cell runs as the `fstp-cell`
//! binary ([`crate::external_cell`]) and whose vault runs as the
//! `fstp-vault` binary. The world provisions the vault database, the
//! witness registration, the relays and the edge as for any cell. Its
//! start then hands the vault over here (`world::start_cell`, the block
//! marked "lane L8"):
//!
//! 1. The in-process vault the world started is shut down before any peer
//!    reached it. Its internal and tunnel listener addresses are kept, so
//!    the cell's relay and the edge route reach the binary unchanged.
//! 2. The credentials directory is written by the fixed names of
//!    ADR-026 record of lane L8, and `vault.json` beside it.
//! 3. The keystore is created through the vault's own custody entry
//!    ([`fstp_vault::run::genesis_with`]), with the Vault chain anchor key
//!    the witness already pins. `fstp-vault init-keys` makes fresh keys
//!    instead, which an operator then registers with the witness.
//! 4. `fstp-vault` runs with `FSTP_VAULT_CONFIG`, and this module waits
//!    until its internal listener accepts a connection.
//!
//! The binary's process holds the vault's keys once it started. Every
//! value is synthetic.

use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::world::{World, WorldError, WorldSpec};

/// How long the binary may take to listen.
pub const START_TIMEOUT: Duration = Duration::from_secs(120);

/// How long the binary may take to drain at SIGTERM.
pub const STOP_TIMEOUT: Duration = Duration::from_secs(60);

fn fail(what: &str, e: &dyn std::fmt::Display) -> WorldError {
    WorldError::Store(format!("the external vault: {what}: {e}"))
}

/// What a world needs to run its vault through the binary.
#[derive(Clone, Debug)]
pub struct ExternalVaultSpec {
    /// The `fstp-vault` binary.
    pub binary: PathBuf,
    /// A directory of this run, where `vault.json` and the credentials
    /// directory go.
    pub dir: PathBuf,
    /// The socket of the vault's own custody entry (`fstp-keyd` client
    /// role `vault`).
    pub keyd_socket: PathBuf,
}

/// The spec of the world now starting, and the vault it started.
struct Slot {
    pending: Option<ExternalVaultSpec>,
    started: Option<ExternalVault>,
}

static SLOT: Mutex<Slot> = Mutex::new(Slot {
    pending: None,
    started: None,
});

fn slot() -> std::sync::MutexGuard<'static, Slot> {
    SLOT.lock().unwrap_or_else(PoisonError::into_inner)
}

/// [`World::start_external`] whose vault runs as the `fstp-vault` binary
/// of `vault` (module documentation).
///
/// # Errors
///
/// As [`World::start_external`], and a vault that does not start.
pub fn start_world(
    spec: WorldSpec,
    custody: PathBuf,
    external: &crate::external_cell::ExternalSpec,
    vault: ExternalVaultSpec,
) -> Result<(World, ExternalVault), WorldError> {
    slot().pending = Some(vault);
    let world = World::start_external(spec, custody, external);
    let mut s = slot();
    s.pending = None;
    let started = s.started.take();
    drop(s);
    let world = world?;
    let vault = started.ok_or_else(|| fail("start", &"the world started no external vault"))?;
    Ok((world, vault))
}

/// The pending spec, if the world now starting runs its vault as the
/// binary. Called by `world::start_cell`.
pub(crate) fn pending() -> Option<ExternalVaultSpec> {
    slot().pending.clone()
}

/// One database login, as `fstp-pgtest` minted it.
pub(crate) struct Login {
    pub(crate) password: String,
    pub(crate) cert_pem: Vec<u8>,
    pub(crate) key_pem: Vec<u8>,
}

/// The parts of a world vault the binary's files hold.
pub(crate) struct VaultFiles {
    pub(crate) cell: [u8; 16],
    pub(crate) db_host: String,
    pub(crate) db_port: u16,
    pub(crate) dbname: String,
    pub(crate) db_ca: Vec<u8>,
    pub(crate) vault: Login,
    pub(crate) keys: Login,
    pub(crate) registered: Vec<([u8; 32], &'static str)>,
    pub(crate) internal: (Vec<u8>, Vec<u8>),
    pub(crate) cell_ca: Vec<u8>,
    pub(crate) tunnel: (Vec<u8>, Vec<u8>),
    pub(crate) tunnel_ca: Vec<u8>,
    pub(crate) origin: (Vec<u8>, Vec<u8>),
    pub(crate) origin_host: String,
    pub(crate) witness_client: (Vec<u8>, Vec<u8>),
    pub(crate) witness_ca: Vec<u8>,
    pub(crate) witness_ca_digest: [u8; 32],
    pub(crate) witness_addr: SocketAddr,
    pub(crate) witness_name: String,
    pub(crate) receipt_keys: Vec<Vec<u8>>,
    pub(crate) ticket_key: [u8; 32],
    pub(crate) internal_listen: SocketAddr,
    pub(crate) origin_listen: SocketAddr,
}

fn hex(bytes: &[u8]) -> String {
    crate::canary::lower_hex(bytes)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), WorldError> {
    use std::io::Write as _;
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

/// Writes the files of `f` for `spec`, creates the keystore with the
/// anchor key `anchor` the witness pins, runs the binary and waits until
/// it listens. The started vault waits in this module for
/// [`start_world`]. Called by `world::start_cell`, after the in-process
/// vault stopped.
pub(crate) fn launch(
    rt: &fstp_rt::tokio::TokioRuntime,
    spec: &ExternalVaultSpec,
    f: VaultFiles,
    anchor: fstp_crypto::composite::CompositeSigningKey,
) -> Result<(), WorldError> {
    let creds = spec.dir.join("vault-credentials");
    std::fs::create_dir_all(&creds).map_err(|e| fail("the credentials directory", &e))?;
    let files: Vec<(&str, &[u8])> = vec![
        ("db-ca.pem", &f.db_ca),
        ("vault.pem", &f.vault.cert_pem),
        ("vault.key", &f.vault.key_pem),
        ("vault.password", f.vault.password.as_bytes()),
        ("keys.pem", &f.keys.cert_pem),
        ("keys.key", &f.keys.key_pem),
        ("keys.password", f.keys.password.as_bytes()),
        ("internal.pem", &f.internal.0),
        ("internal.key", &f.internal.1),
        ("cell-ca.pem", &f.cell_ca),
        ("tunnel.pem", &f.tunnel.0),
        ("tunnel.key", &f.tunnel.1),
        ("tunnel-ca.pem", &f.tunnel_ca),
        ("origin.pem", &f.origin.0),
        ("origin.key", &f.origin.1),
        ("witness.pem", &f.witness_client.0),
        ("witness.key", &f.witness_client.1),
        ("witness-ca.pem", &f.witness_ca),
    ];
    for (name, bytes) in files {
        write_private(&creds.join(name), bytes)?;
    }
    let registered: Vec<String> = f
        .registered
        .iter()
        .map(|(digest, kind)| format!(r#"{{"kind":"{kind}","spki_sha256":"{}"}}"#, hex(digest)))
        .collect();
    let receipt: Vec<String> = f
        .receipt_keys
        .iter()
        .map(|k| format!("\"{}\"", hex(k)))
        .collect();
    // The canonical form of RFC 8785: members in key order, no space.
    let config = format!(
        r#"{{"cell":"{cell}","credentials_dir":"{creds}","database":{{"dbname":"{dbname}","host":"{db_host}","port":{db_port}}},"internal_listen":"{internal}","keyd_socket":"{keyd}","origin_host":"{origin_host}","origin_listen":"{origin}","registered_servers":[{registered}],"ticket_keys":["{ticket}"],"witness":{{"address":"{waddr}","ca_spki_sha256":"{wdigest}","receipt_keys":[{receipt}],"server_name":"{wname}"}}}}"#,
        cell = hex(&f.cell),
        creds = creds.display(),
        dbname = f.dbname,
        db_host = f.db_host,
        db_port = f.db_port,
        internal = f.internal_listen,
        keyd = spec.keyd_socket.display(),
        origin_host = f.origin_host,
        origin = f.origin_listen,
        registered = registered.join(","),
        ticket = hex(&f.ticket_key),
        waddr = f.witness_addr,
        wdigest = hex(&f.witness_ca_digest),
        receipt = receipt.join(","),
        wname = f.witness_name,
    );
    // The file must decode as the binary reads it.
    let cfg =
        fstp_vault::config::decode_config(config.as_bytes()).map_err(|e| fail("vault.json", &e))?;
    let path = spec.dir.join("vault.json");
    write_private(&path, config.as_bytes())?;
    // Genesis of the keystore through the vault's own custody entry, with
    // the anchor key the witness registration already names.
    let creds_read = fstp_vault::run::Credentials::read(&cfg.credentials_dir)
        .map_err(|e| fail("credentials", &e))?;
    let custody = fstp_custody::KeydCustody::new(&spec.keyd_socket)
        .map_err(|e| fail("the vault custody", &e))?;
    let keys = fstp_vault::keystore::VaultKeys::with_anchor(anchor)
        .map_err(|e| fail("the vault keys", &e))?;
    rt.block_on(fstp_vault::run::genesis_with(
        rt,
        &cfg,
        &creds_read,
        &custody,
        &keys,
    ))
    .map_err(|e| fail("the vault keystore genesis", &e))?;
    drop(keys);
    let vault = ExternalVault {
        spec: spec.clone(),
        config: path,
        internal: f.internal_listen,
        child: Mutex::new(None),
    };
    vault.start()?;
    slot().started = Some(vault);
    Ok(())
}

/// A vault run by the `fstp-vault` binary (module documentation).
pub struct ExternalVault {
    spec: ExternalVaultSpec,
    config: PathBuf,
    internal: SocketAddr,
    child: Mutex<Option<Child>>,
}

impl std::fmt::Debug for ExternalVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalVault")
            .field("config", &self.config)
            .field("internal", &self.internal)
            .finish_non_exhaustive()
    }
}

impl ExternalVault {
    /// The configuration file the binary reads.
    #[must_use]
    pub fn config_path(&self) -> &Path {
        &self.config
    }

    /// The internal listener the cell's relay reaches.
    #[must_use]
    pub fn internal(&self) -> SocketAddr {
        self.internal
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

    /// Starts the binary to serve, and waits until its internal listener
    /// accepts a connection.
    ///
    /// # Errors
    ///
    /// Fails when the binary does not start, exits, or does not listen
    /// within [`START_TIMEOUT`].
    pub fn start(&self) -> Result<(), WorldError> {
        let mut slot = self.child.lock().unwrap_or_else(PoisonError::into_inner);
        if slot.is_some() {
            return Err(fail("start", &"the vault runs already"));
        }
        let mut child = Command::new(&self.spec.binary)
            .env(fstp_vault::run::CONFIG_ENV, &self.config)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| fail("fstp-vault", &e))?;
        let begun = Instant::now();
        loop {
            if let Ok(Some(status)) = child.try_wait() {
                return Err(fail("fstp-vault exited before it listened", &status));
            }
            if TcpStream::connect_timeout(&self.internal, Duration::from_millis(500)).is_ok() {
                break;
            }
            if begun.elapsed() > START_TIMEOUT {
                let _ = child.kill();
                let _ = child.wait();
                return Err(fail("fstp-vault", &"not listening in time"));
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        *slot = Some(child);
        Ok(())
    }

    /// Runs `fstp-vault verify-first-admin <account> <file>` as the
    /// technical admin does on a pilot host (ADR-008, lane L13b; ADR-026
    /// record of lane L18): `account` in the UUID form, and the synthetic
    /// identity file `identity`, written to the run directory and removed
    /// after. The vault must be stopped, since the command takes the
    /// keystore lock.
    ///
    /// # Errors
    ///
    /// Fails when the file cannot be written or the command exits with a
    /// failure.
    pub fn verify_first_admin(&self, account: u128, identity: &str) -> Result<(), WorldError> {
        let hex = format!("{account:032x}");
        let uuid = format!(
            "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
            account >> 96,
            (account >> 80) & 0xffff,
            (account >> 64) & 0xffff,
            (account >> 48) & 0xffff,
            account & 0xffff_ffff_ffff
        );
        let file = self.spec.dir.join(format!("admin-{hex}.json"));
        std::fs::write(&file, identity).map_err(|e| fail("the identity file", &e))?;
        let status = Command::new(&self.spec.binary)
            .env(fstp_vault::run::CONFIG_ENV, &self.config)
            .arg("verify-first-admin")
            .arg(&uuid)
            .arg(&file)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .status();
        let _ = std::fs::remove_file(&file);
        let status = status.map_err(|e| fail("fstp-vault verify-first-admin", &e))?;
        if !status.success() {
            return Err(fail("fstp-vault verify-first-admin", &status));
        }
        Ok(())
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
                Ok(Some(status)) => return Err(fail("fstp-vault exit", &status)),
                Ok(None) if begun.elapsed() > STOP_TIMEOUT => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(fail("fstp-vault", &"did not drain in time"));
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(100)),
                Err(e) => return Err(fail("fstp-vault wait", &e)),
            }
        }
    }
}

impl Drop for ExternalVault {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
