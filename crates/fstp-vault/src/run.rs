//! The `fstp-vault` binary's commands over a configuration file (ADR-026
//! record of lane L8, gap G12).
//!
//! - [`serve`] starts the vault named by the file and serves it until
//!   SIGTERM or SIGINT drains it.
//! - [`init_keys`] creates the vault keystore at genesis and writes
//!   `anchor.pub`, the Vault chain anchor public key the witness registers
//!   (ADR-004 record of lane L8).
//! - [`erase_identity`] erases the identity of one account on the Vault
//!   chain, one batch of design section 3.5, while the vault is stopped
//!   (ADR-004 record of lane L11).
//! - [`restore_keystore`] keeps the newest keystore copy that opens after
//!   a restore: the restored rows or the newest snapshot (ADR-012 record
//!   of lane L17).
//!
//! Every start reads the credentials directory by fixed name
//! ([`crate::config::CREDENTIAL_FILES`]), runs the I-83 start check over
//! the `<dbname>_vault` login, opens the keystore through the
//! `<dbname>_keys` login and the vault's `fstp-keyd` entry, takes the
//! keystore lock and completes any stored erasure batch
//! ([`resume_keystore`]), then runs
//! [`crate::service::serve`] with the Vault chain writer. One tokio runtime
//! runs the vault, through `fstp-rt` (ADR-002). The vault never shares a
//! process or a database with the cell (R-NG-01, ADR-009, I-83).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use fstp_custody::Custody;
use fstp_pgwire::Client;
use fstp_rt::Runtime;
use fstp_rt::tokio::TokioRuntime;

use crate::VaultError;
use crate::chain::{VaultChain, VaultChainParts, VaultWitness};
use crate::config::{self, VaultConfig};
use crate::erasure::{ChainJournal, Registrar, Runner};
use crate::keystore::{self, IdentityKeys, VaultKeys};
use crate::origin::Vault;
use crate::service::{self, VaultHandle, VaultParts};
use fstp_backup::keyfile;
use fstp_backup::s3::S3Client;
use fstp_backup::snapshot::{SnapshotKey, SnapshotOwner, Snapshots};
use fstp_keys::erasure::Phase;

/// The environment variable that names the configuration file.
pub const CONFIG_ENV: &str = "FSTP_VAULT_CONFIG";

/// How long the vault drains at SIGTERM.
pub const DRAIN: Duration = Duration::from_secs(20);

/// The name of the anchor public key file `init-keys` writes.
pub const ANCHOR_PUB: &str = "anchor.pub";

/// The worker threads of the runtime.
const WORKERS: usize = 4;

/// How long a database connection may take to open.
const DB_CONNECT: Duration = Duration::from_secs(20);

fn cfg_err(rule: &'static str) -> VaultError {
    VaultError::Config(rule)
}

/// The bytes of the credentials directory, read by fixed name. Its debug
/// form shows no byte.
pub struct Credentials {
    files: Vec<(&'static str, Vec<u8>)>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials").finish_non_exhaustive()
    }
}

impl Credentials {
    /// Reads every file of [`config::CREDENTIAL_FILES`] from `dir`.
    ///
    /// # Errors
    ///
    /// [`VaultError::Config`] naming the first file that does not read.
    pub fn read(dir: &Path) -> Result<Credentials, VaultError> {
        let mut files = Vec::with_capacity(config::CREDENTIAL_FILES.len());
        for name in config::CREDENTIAL_FILES {
            let bytes = std::fs::read(dir.join(name)).map_err(|_| cfg_err(name))?;
            files.push((name, bytes));
        }
        Ok(Credentials { files })
    }

    fn get(&self, name: &'static str) -> Result<&[u8], VaultError> {
        self.files
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, b)| b.as_slice())
            .ok_or(cfg_err(name))
    }

    /// A one-line secret, without its line end.
    fn secret(&self, name: &'static str) -> Result<String, VaultError> {
        let text = std::str::from_utf8(self.get(name)?).map_err(|_| cfg_err(name))?;
        Ok(text.trim_end_matches(['\r', '\n']).to_owned())
    }
}

/// The database role a login names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Login {
    /// `<dbname>_vault`: the service.
    Vault,
    /// `<dbname>_keys`: the keystore.
    Keys,
}

/// The login `which` on the vault database, with the I-83 server check
/// of [`service::vault_server_check`] (ADR-026 record of lane L8, row
/// "Logins").
///
/// # Errors
///
/// [`VaultError::Config`] when a credential is refused.
pub fn login(
    cfg: &VaultConfig,
    creds: &Credentials,
    which: Login,
) -> Result<fstp_pgwire::Config, VaultError> {
    let (pem, key, password, suffix) = match which {
        Login::Vault => ("vault.pem", "vault.key", "vault.password", "vault"),
        Login::Keys => ("keys.pem", "keys.key", "keys.password", "keys"),
    };
    let tls =
        fstp_pgwire::ClientTls::new(creds.get("db-ca.pem")?, creds.get(pem)?, creds.get(key)?)
            .map_err(|_| cfg_err(pem))?;
    let password =
        fstp_pgwire::Password::new(creds.secret(password)?).map_err(|_| cfg_err(password))?;
    let user = format!("{}_{suffix}", cfg.database.dbname);
    Ok(fstp_pgwire::Config::new(
        cfg.database.host.clone(),
        cfg.database.port,
        user.as_str(),
        password,
        cfg.database.dbname.clone(),
        tls,
    )
    .map_err(|_| cfg_err("database"))?
    .connect_timeout(Some(DB_CONNECT))
    .server_check(service::vault_server_check(&cfg.registered_servers)))
}

fn connect_error(e: &fstp_pgwire::Error) -> VaultError {
    if e.kind() == fstp_pgwire::ErrorKind::ServerRefused {
        VaultError::Malformed("not a vault database (I-83)")
    } else {
        VaultError::Unavailable("the vault database")
    }
}

/// Runs the I-83 start check of design section 9.2 over the vault login,
/// before the keystore is touched: placement marker, server OU and
/// registered SPKI.
///
/// # Errors
///
/// [`VaultError::Malformed`] for a database that is not this vault's, and
/// [`VaultError::Unavailable`] when it cannot be reached.
pub async fn check_start<R: Runtime>(
    rt: &R,
    cfg: &VaultConfig,
    creds: &Credentials,
) -> Result<(), VaultError> {
    let db = login(cfg, creds, Login::Vault)?;
    let mut client: Client<R> = Client::connect(rt, &db)
        .await
        .map_err(|e| connect_error(&e))?;
    let checked = service::check_database(&mut client, &cfg.registered_servers).await;
    let _ = client.close().await;
    checked.map(|_| ())
}

async fn keys_client<R: Runtime>(
    rt: &R,
    cfg: &VaultConfig,
    creds: &Credentials,
) -> Result<Client<R>, VaultError> {
    let db = login(cfg, creds, Login::Keys)?;
    Client::connect(rt, &db)
        .await
        .map_err(|e| connect_error(&e))
}

/// Opens the keystore of `cfg` through `custody` (ADR-004 record of lane
/// L8, row "Load"). A keystore without rows is refused: the start never
/// runs genesis.
///
/// # Errors
///
/// [`VaultError::Unavailable`] for an empty keystore, a failed read or a
/// refused unwrap, and [`VaultError::Malformed`] for rows that do not
/// open.
pub async fn open_keystore<R: Runtime, C: Custody>(
    rt: &R,
    cfg: &VaultConfig,
    creds: &Credentials,
    custody: &C,
) -> Result<VaultKeys, VaultError> {
    let mut client = keys_client(rt, cfg, creds).await?;
    let rows = keystore::read_rows(&mut client).await;
    let _ = client.close().await;
    let rows = rows?.ok_or(VaultError::Unavailable(
        "the vault keystore: run fstp-vault init-keys",
    ))?;
    keystore::open(custody, cfg.cell, &rows).await
}

fn now_us() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_micros()).ok())
        .unwrap_or(0)
}

/// Genesis of the keystore of `cfg` with `keys`, through `custody`
/// (ADR-004 record of lane L8, row "Genesis"). It runs the I-83 start
/// check first, and refuses a keystore that holds a root row before it
/// creates a root. Returns the anchor public key.
///
/// # Errors
///
/// [`VaultError::Conflict`] for a keystore that exists, and the errors of
/// [`check_start`] and [`keystore::genesis`].
pub async fn genesis_with<R: Runtime, C: Custody>(
    rt: &R,
    cfg: &VaultConfig,
    creds: &Credentials,
    custody: &C,
    keys: &VaultKeys,
) -> Result<Vec<u8>, VaultError> {
    check_start(rt, cfg, creds).await?;
    let mut client = keys_client(rt, cfg, creds).await?;
    let written = async {
        if keystore::has_root(&mut client).await? {
            return Err(VaultError::Conflict("a vault keystore genesis"));
        }
        let rows = keystore::genesis(custody, cfg.cell, keys, now_us()).await?;
        keystore::write_rows(&mut client, &rows).await
    }
    .await;
    let _ = client.close().await;
    written.map(|()| keys.anchor_public())
}

/// The PostgreSQL advisory lock key of the vault keystore (ADR-004 record
/// of lane L11, row "Entry point"): the bytes `"fstpvkey"`. The serving
/// vault holds it on its keys connection for its lifetime, and
/// `erase-identity` holds it while it runs, so the two never meet.
pub const KEYSTORE_LOCK: i64 = 0x6673_7470_766b_6579;

/// Takes the keystore lock on the keys connection `client`.
///
/// # Errors
///
/// [`VaultError::Conflict`] when another connection holds it, such as a
/// running vault, and [`VaultError::Unavailable`] when the query fails.
pub async fn lock_keystore<R: Runtime>(client: &mut Client<R>) -> Result<(), VaultError> {
    let rows = client
        .query("SELECT pg_try_advisory_lock($1)", &[&KEYSTORE_LOCK])
        .await
        .map_err(|_| VaultError::Unavailable("the keystore lock"))?;
    let held: bool = rows
        .first()
        .and_then(|r| r.get(0).ok())
        .ok_or(VaultError::Unavailable("the keystore lock"))?;
    if held {
        Ok(())
    } else {
        Err(VaultError::Conflict(
            "the vault keystore lock: another vault process holds it",
        ))
    }
}

fn witness_of(cfg: &VaultConfig, creds: &Credentials) -> Result<VaultWitness, VaultError> {
    Ok(VaultWitness {
        addr: cfg.witness.address,
        server_name: cfg.witness.server_name.clone(),
        tls: fstp_tls::ClientConfig::mutual(
            creds.get("witness-ca.pem")?,
            creds.get("witness.pem")?,
            creds.get("witness.key")?,
        )
        .map_err(|_| cfg_err("witness.pem"))?,
        ca_digest: cfg.witness.ca_spki_sha256,
    })
}

/// The vault and its chain journal, for the erasure runner: the vault
/// login, the Vault chain opened and verified at the witness, and the
/// vault loaded from its rows.
async fn erasure_journal<R: Runtime>(
    rt: &R,
    cfg: &VaultConfig,
    creds: &Credentials,
    keys: VaultKeys,
    identities: Arc<IdentityKeys>,
) -> Result<(Vault, ChainJournal<R>), VaultError> {
    let (anchor_key, sealer) = keys.into_service_keys()?;
    let sealer: Arc<dyn crate::store::Sealer> = Arc::new(sealer.with_identities(identities));
    let db = login(cfg, creds, Login::Vault)?;
    let mut client: Client<R> = Client::connect(rt, &db)
        .await
        .map_err(|e| connect_error(&e))?;
    let parts = VaultChainParts {
        anchor_key,
        witness: witness_of(cfg, creds)?,
        witness_keys: cfg.witness.receipt_keys.clone(),
    };
    let chain = VaultChain::open(rt.clone(), cfg.cell, parts, &mut client).await?;
    let vault =
        crate::store::load(&mut client, sealer.as_ref(), cfg.cell, &cfg.ticket_keys).await?;
    Ok((
        vault,
        ChainJournal {
            client,
            chain,
            sealer,
        },
    ))
}

/// The keystore lock and the keys of `cfg` (ADR-004 record of lane L11):
/// takes the lock on a keys connection, loads the keystore and completes
/// any stored erasure batch before the vault serves. Returns the
/// registrar, whose keys connection holds the lock, and the service keys
/// (ADR-004 record of lane L13).
///
/// # Errors
///
/// [`VaultError::Conflict`] when another process holds the lock, and the
/// errors of [`Runner::load`], of the resumed batch and of
/// [`Runner::check_tuple_labels`].
pub async fn resume_keystore<R: Runtime, C: Custody>(
    rt: &R,
    cfg: &VaultConfig,
    creds: &Credentials,
    custody: &C,
) -> Result<(Registrar<R>, VaultKeys), VaultError> {
    let mut client = keys_client(rt, cfg, creds).await?;
    lock_keystore(&mut client).await?;
    let mut runner = load_runner(rt, cfg, client, custody).await?;
    if runner.phase() != Phase::Idle {
        let (mut vault, mut journal) = erasure_journal(
            rt,
            cfg,
            creds,
            runner.service_keys()?,
            runner.identity_keys(),
        )
        .await?;
        let done = runner.run_to_idle(&mut vault, &mut journal, now_us()).await;
        let _ = journal.client.close().await;
        done?;
    }
    // ADR-004 row "Normalisation": no tuple of an earlier label.
    runner.check_tuple_labels()?;
    let keys = runner.service_keys()?;
    Ok((runner.into_registrar()?, keys))
}

/// The vault's snapshot key file `vault-snapshot.key` in the credentials
/// directory of `cfg`, created through `custody` when it is missing
/// (ADR-004 record of lane L17, row "Genesis"): no operator step.
///
/// # Errors
///
/// [`VaultError::Unavailable`] when custody refuses the create, and
/// [`VaultError::Config`] for a file that does not read, write or decode.
pub async fn snapshot_key<C: Custody>(
    cfg: &VaultConfig,
    custody: &C,
) -> Result<SnapshotKey, VaultError> {
    let owner = SnapshotOwner::Vault;
    let path = cfg.credentials_dir.join(owner.key_file_name());
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let b = SnapshotKey::create(custody, cfg.cell, owner)
                .await
                .map_err(|_| VaultError::Unavailable("the vault snapshot key"))?;
            write_new(&path, &b)?;
            b
        }
        Err(_) => return Err(cfg_err(keyfile::VAULT_SNAPSHOT_KEY_FILE)),
    };
    SnapshotKey::decode(&bytes, cfg.cell, owner)
        .map_err(|_| cfg_err(keyfile::VAULT_SNAPSHOT_KEY_FILE))
}

/// The keystore snapshot writer of `cfg`, or `None` when no object store
/// is configured (ADR-012 record of lane L17, row "Fallback"). The
/// object store credentials come from the credentials directory by fixed
/// name, as for `fstp-backup`.
///
/// # Errors
///
/// The errors of [`snapshot_key`], and [`VaultError::Config`] for a
/// refused object store credential.
pub async fn snapshots_of<R: Runtime, C: Custody>(
    rt: &R,
    cfg: &VaultConfig,
    custody: &C,
) -> Result<Option<Snapshots>, VaultError> {
    let Some(endpoint) = cfg.object_store.clone() else {
        return Ok(None);
    };
    let dir = &cfg.credentials_dir;
    let credentials =
        fstp_backup::config::s3_credentials(dir).map_err(|_| cfg_err("s3-access-key-id"))?;
    let ca = fstp_backup::config::s3_ca(dir).map_err(|_| cfg_err("s3-ca.pem"))?;
    let client = S3Client::new(rt.clone(), endpoint, credentials, ca.as_deref())
        .map_err(|_| cfg_err("s3-ca.pem"))?;
    let key = snapshot_key(cfg, custody).await?;
    Ok(Some(Snapshots::new(Arc::new(client), key)))
}

/// The runner of `client` with the snapshot writer of `cfg`, if any.
async fn load_runner<'c, R: Runtime, C: Custody>(
    rt: &R,
    cfg: &VaultConfig,
    client: Client<R>,
    custody: &'c C,
) -> Result<Runner<'c, R, C>, VaultError> {
    let snapshots = snapshots_of(rt, cfg, custody).await?;
    let runner = Runner::load(client, cfg.cell, custody).await?;
    Ok(match snapshots {
        Some(s) => runner
            .with_snapshots(s)
            .with_snapshot_status(cfg.credentials_dir.clone()),
        None => runner,
    })
}

/// `fstp-vault restore-keystore [<snapshot id>]` over `custody` (ADR-012
/// record of lane L17, row "Restore command"), with the vault stopped:
/// takes the keystore lock and applies the restore rule
/// ([`crate::snapshot::restore_with`]). Returns where the kept copy came
/// from.
///
/// # Errors
///
/// [`VaultError::Conflict`] while the vault runs, and
/// [`VaultError::Unavailable`] when no copy opens or a step fails.
pub async fn restore_keystore_with<R: Runtime, C: Custody>(
    rt: &R,
    cfg: &VaultConfig,
    custody: &C,
    id: Option<[u8; 16]>,
) -> Result<crate::snapshot::Source, VaultError> {
    let creds = Credentials::read(&cfg.credentials_dir)?;
    let snapshots = snapshots_of(rt, cfg, custody).await?;
    let mut client = keys_client(rt, cfg, &creds).await?;
    let done = async {
        lock_keystore(&mut client).await?;
        crate::snapshot::restore_with(
            &mut client,
            custody,
            cfg.cell,
            snapshots.as_ref(),
            id,
            now_us(),
        )
        .await
    }
    .await;
    let _ = client.close().await;
    done
}

/// `fstp-vault erase-identity <account>` over `custody` (ADR-004 record
/// of lane L11): erases the identity of `account` on the Vault chain and
/// returns the destroyed epoch. The vault must be stopped: the keystore
/// lock refuses the command while it serves.
///
/// # Errors
///
/// [`VaultError::Conflict`] while the vault runs, for an account with no
/// identity, and for an identity with no stored tuple. The first step
/// that fails otherwise. A batch that fails after its request completes
/// at the next start of the vault, or at the next run of the command.
pub async fn erase_identity_with<R: Runtime, C: Custody>(
    rt: &R,
    cfg: &VaultConfig,
    custody: &C,
    account: u128,
) -> Result<u64, VaultError> {
    let creds = Credentials::read(&cfg.credentials_dir)?;
    check_start(rt, cfg, &creds).await?;
    let mut client = keys_client(rt, cfg, &creds).await?;
    lock_keystore(&mut client).await?;
    let mut runner = load_runner(rt, cfg, client, custody).await?;
    let (mut vault, mut journal) = erasure_journal(
        rt,
        cfg,
        &creds,
        runner.service_keys()?,
        runner.identity_keys(),
    )
    .await?;
    let done = async {
        // The registration of the account first, then its verification
        // (ADR-004 record of lane L13, row "Entry point").
        let registered = vault.registered(fstp_vault_proto::WireAccount(account));
        let person = match registered {
            Some(p) => p,
            None => {
                let rows = journal
                    .client
                    .query(
                        "SELECT identity_id FROM vault.account WHERE account_id = $1",
                        &[&fstp_pgwire::Uuid::from_bytes(account.to_be_bytes())],
                    )
                    .await
                    .map_err(|_| VaultError::Unavailable("the vault database"))?;
                let identity: fstp_pgwire::Uuid = rows
                    .first()
                    .and_then(|r| r.get::<Option<fstp_pgwire::Uuid>>(0).ok().flatten())
                    .ok_or(VaultError::Conflict("an account with no identity"))?;
                fstp_vault_core::Person(u128::from_be_bytes(*identity.as_bytes()))
            }
        };
        // A batch left by an earlier run completes first.
        runner
            .run_to_idle(&mut vault, &mut journal, now_us())
            .await?;
        let before = runner.epoch();
        runner.request_erasure(person).await?;
        runner
            .run_to_idle(&mut vault, &mut journal, now_us())
            .await?;
        Ok(before)
    }
    .await;
    let _ = journal.client.close().await;
    let _ = runner.into_client().close().await;
    done
}

/// The service parts of `cfg` from its credentials and opened keys.
///
/// # Errors
///
/// [`VaultError::Config`] for a refused credential, and the errors of
/// [`VaultKeys::into_service_keys`].
pub fn parts(
    cfg: &VaultConfig,
    creds: &Credentials,
    keys: VaultKeys,
    identities: Arc<IdentityKeys>,
) -> Result<VaultParts, VaultError> {
    let tls = |name: &'static str| move |_| cfg_err(name);
    let (anchor_key, sealer) = keys.into_service_keys()?;
    let witness = witness_of(cfg, creds)?;
    Ok(VaultParts {
        cell: cfg.cell,
        db: login(cfg, creds, Login::Vault)?,
        registered_servers: cfg.registered_servers.clone(),
        sealer: Arc::new(sealer.with_identities(identities)),
        ticket_keys: cfg.ticket_keys.clone(),
        internal_tls: fstp_tls::ServerConfig::mutual(
            creds.get("internal.pem")?,
            creds.get("internal.key")?,
            creds.get("cell-ca.pem")?,
        )
        .map_err(tls("internal.pem"))?,
        tunnel_tls: Arc::new(
            fstp_tls::ServerConfig::mutual(
                creds.get("tunnel.pem")?,
                creds.get("tunnel.key")?,
                creds.get("tunnel-ca.pem")?,
            )
            .map_err(tls("tunnel.pem"))?,
        ),
        origin_tls: Arc::new(
            fstp_tls::ServerConfig::new(creds.get("origin.pem")?, creds.get("origin.key")?)
                .map_err(tls("origin.pem"))?,
        ),
        origin_host: cfg.origin_host.clone(),
        internal_listen: cfg.internal_listen,
        origin_listen: cfg.origin_listen,
        chain: Some(VaultChainParts {
            anchor_key,
            witness,
            witness_keys: cfg.witness.receipt_keys.clone(),
        }),
        pages: match &cfg.assets_dir {
            Some(dir) => Some(Arc::new(crate::pages::VaultPages::load_installed(dir)?)),
            None => None,
        },
    })
}

/// Starts the vault of `cfg` on `rt` through `custody` (module
/// documentation): the I-83 start check, the keystore, then the service.
///
/// # Errors
///
/// The first step that fails.
pub async fn start_with<R: Runtime, C: Custody>(
    rt: R,
    cfg: &VaultConfig,
    custody: &C,
) -> Result<VaultHandle<R>, VaultError> {
    let creds = Credentials::read(&cfg.credentials_dir)?;
    check_start(&rt, cfg, &creds).await?;
    let (registrar, keys) = resume_keystore(&rt, cfg, &creds, custody).await?;
    let parts = parts(cfg, &creds, keys, registrar.identity_keys())?;
    // ADR-004 record of lane L13 "Existing facts": no identity fact may
    // be held under the shared Fact key, which no erasure destroys.
    let mut client: Client<R> = Client::connect(&rt, &parts.db)
        .await
        .map_err(|e| connect_error(&e))?;
    let checked = crate::store::check_identity_facts(&mut client, parts.sealer.as_ref()).await;
    let _ = client.close().await;
    checked?;
    // The registrar's keys connection holds the keystore lock while the
    // vault serves.
    // ADR-012 record of lane L27: the daily snapshot, over the vault's
    // own custody entry, when an object store is configured.
    let daily: Option<Arc<dyn crate::snapshot::DailySnapshot>> = match cfg.object_store {
        None => None,
        Some(_) => {
            let custody = keyd(cfg)?;
            match snapshots_of(&rt, cfg, &custody).await? {
                None => None,
                Some(snapshots) => Some(Arc::new(crate::snapshot::Daily {
                    cell: cfg.cell,
                    snapshots,
                    custody,
                    status_dir: Some(cfg.credentials_dir.clone()),
                })),
            }
        }
    };
    let registrar = service::RegistrarParts {
        registrar,
        keys_db: login(cfg, &creds, Login::Keys)?,
        check_every: service::KEYSTORE_CHECK,
        daily,
    };
    service::serve_with_registrar(rt, parts, Some(registrar)).await
}

fn keyd(cfg: &VaultConfig) -> Result<fstp_custody::KeydCustody, VaultError> {
    fstp_custody::KeydCustody::new(&cfg.keyd_socket).map_err(|_| cfg_err("keyd_socket"))
}

/// [`start_with`] over the vault's `fstp-keyd` entry at `keyd_socket`.
///
/// # Errors
///
/// As [`start_with`].
pub async fn start<R: Runtime>(rt: R, cfg: &VaultConfig) -> Result<VaultHandle<R>, VaultError> {
    let custody = keyd(cfg)?;
    start_with(rt, cfg, &custody).await
}

/// Reads the configuration file at `path`: at most
/// [`config::MAX_CONFIG_LEN`] bytes.
///
/// # Errors
///
/// [`VaultError::Config`] for a file that does not read or is too long.
pub fn read_config(path: &Path) -> Result<Vec<u8>, VaultError> {
    use std::io::Read as _;
    let file = std::fs::File::open(path).map_err(|_| cfg_err("configuration file"))?;
    let limit = u64::try_from(config::MAX_CONFIG_LEN)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::new();
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|_| cfg_err("configuration file"))?;
    if bytes.len() > config::MAX_CONFIG_LEN {
        return Err(cfg_err("length"));
    }
    Ok(bytes)
}

/// The configuration file named by [`CONFIG_ENV`], decoded.
///
/// # Errors
///
/// [`VaultError::Config`] for a missing or refused file.
pub fn load_config() -> Result<VaultConfig, VaultError> {
    let path = std::env::var_os(CONFIG_ENV).ok_or(cfg_err(CONFIG_ENV))?;
    config::decode_config(&read_config(Path::new(&path))?)
}

fn runtime() -> Result<TokioRuntime, VaultError> {
    TokioRuntime::new_multi_thread(WORKERS).map_err(|_| VaultError::Unavailable("the runtime"))
}

/// Serves the vault of `cfg` until SIGTERM or SIGINT drains it (module
/// documentation).
///
/// # Errors
///
/// The first step that fails.
pub fn serve(cfg: &VaultConfig) -> Result<(), VaultError> {
    use fstp_rt::signal::{Signals as _, TerminationListener as _};
    let rt = runtime()?;
    // Registered before the start, so a SIGTERM during it is queued.
    let mut term = rt
        .listen_termination()
        .map_err(|_| VaultError::Unavailable("the signal listener"))?;
    let task_rt = rt.clone();
    rt.block_on(async move {
        let running = start(task_rt.clone(), cfg).await?;
        let _ = fstp_obs::log_to_stderr(&fstp_obs::LogEvent::Started);
        // ADR-004 record of lane L13b "Fail closed": a vault that lost its
        // keystore lock drains and exits with status 1.
        let lost = async {
            while !running.stopped() {
                task_rt.sleep(Duration::from_millis(500)).await;
            }
        };
        let stopped = matches!(
            fstp_rt::future::race(term.recv(), lost).await,
            fstp_rt::future::Either::Right(())
        );
        let _ = fstp_obs::log_to_stderr(&fstp_obs::LogEvent::ShuttingDown);
        running.shutdown(DRAIN).await?;
        if stopped {
            return Err(VaultError::Unavailable("the vault keystore lock was lost"));
        }
        Ok(())
    })
}

/// Writes `text` to a new file `path` with mode 0600. An existing file is
/// refused.
fn write_new(path: &Path, text: &[u8]) -> Result<(), VaultError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| cfg_err("output file"))?;
    f.write_all(text)
        .and_then(|()| f.sync_all())
        .map_err(|_| cfg_err("output file"))
}

/// `fstp-vault init-keys <out dir>` (ADR-004 record of lane L8): creates
/// the keystore of `cfg` with fresh keys and writes [`ANCHOR_PUB`] to
/// `out`, in lowercase hex. It also creates `vault-snapshot.key` when it is
/// missing (ADR-004 record of lane L17). An existing output file or keystore is
/// refused.
///
/// # Errors
///
/// The first step that fails.
pub fn init_keys(cfg: &VaultConfig, out: &Path) -> Result<(), VaultError> {
    let target = out.join(ANCHOR_PUB);
    if std::fs::symlink_metadata(&target).is_ok() {
        return Err(cfg_err("output file"));
    }
    let creds = Credentials::read(&cfg.credentials_dir)?;
    let keys = VaultKeys::generate()?;
    let custody = keyd(cfg)?;
    let rt = runtime()?;
    let task_rt = rt.clone();
    let anchor = rt.block_on(async move {
        let anchor = genesis_with(&task_rt, cfg, &creds, &custody, &keys).await?;
        // ADR-004 record of lane L17: the snapshot key comes with the
        // keystore, so a bucket configured later needs no other step.
        snapshot_key(cfg, &custody).await?;
        Ok::<_, VaultError>(anchor)
    })?;
    let mut line: String = anchor.iter().map(|b| format!("{b:02x}")).collect();
    line.push('\n');
    write_new(&target, line.as_bytes())
}

/// `fstp-vault erase-identity <account>` ([`erase_identity_with`] over the
/// vault's `fstp-keyd` entry). It exits with status 0 once step 7 of the
/// batch is recorded.
///
/// # Errors
///
/// As [`erase_identity_with`].
pub fn erase_identity(cfg: &VaultConfig, account: u128) -> Result<(), VaultError> {
    let custody = keyd(cfg)?;
    let rt = runtime()?;
    let task_rt = rt.clone();
    rt.block_on(async move { erase_identity_with(&task_rt, cfg, &custody, account).await })
        .map(|_| ())
}

/// `fstp-vault restore-keystore [<snapshot id>]` ([`restore_keystore_with`]
/// over the vault's `fstp-keyd` entry). It exits with status 0 once a copy
/// that opens is written, and prints nothing.
///
/// # Errors
///
/// As [`restore_keystore_with`].
pub fn restore_keystore(cfg: &VaultConfig, id: Option<[u8; 16]>) -> Result<(), VaultError> {
    let custody = keyd(cfg)?;
    let rt = runtime()?;
    let task_rt = rt.clone();
    rt.block_on(async move { restore_keystore_with(&task_rt, cfg, &custody, id).await })
        .map(|_| ())
}

/// `fstp-vault check-keystore <port>` (ADR-012 record of lane
/// m10/backup-health, row "Check: keystore"): the restore drill's check
/// of a scratch cluster at `port` on the configured database host. It
/// reads the restored keystore rows over the keys login and opens them
/// through the vault's custody entry with the check of `restore-keystore`
/// ([`crate::erasure::check_rows`]). It writes nothing, takes no lock,
/// fetches no snapshot, reaches no witness and prints nothing.
///
/// # Errors
///
/// [`VaultError::Config`] for a refused configuration or credential,
/// [`VaultError::Unavailable`] when the scratch database does not answer
/// or holds no keystore, and [`VaultError::Malformed`] for rows that do
/// not open.
pub fn check_keystore(cfg: &VaultConfig, port: u16) -> Result<(), VaultError> {
    let custody = keyd(cfg)?;
    let rt = runtime()?;
    let task_rt = rt.clone();
    rt.block_on(async move {
        let mut scratch = cfg.clone();
        scratch.database.port = port;
        let creds = Credentials::read(&cfg.credentials_dir)?;
        let mut client = keys_client(&task_rt, &scratch, &creds).await?;
        let done =
            async {
                let rows = crate::keystore::read_rows(&mut client).await?.ok_or(
                    VaultError::Unavailable("a keystore in the scratch database"),
                )?;
                crate::erasure::check_rows(&custody, &cfg.cell, &rows).await
            }
            .await;
        let _ = client.close().await;
        done
    })
}

/// `fstp-vault verify-first-admin <account> <identity file>` over
/// `custody` (ADR-008 and ADR-004 record of lane L13b, decided by Daniel
/// on 2026-11-21): records the verification of a first admin with the
/// operator as verifier of record, and registers the identity. The vault
/// must be stopped: the keystore lock refuses the command while it
/// serves. A stored erasure batch completes first. The vault takes the
/// verification to the cell when it serves again.
///
/// # Errors
///
/// [`VaultError::Config`] for a refused identity file, and
/// [`VaultError::Conflict`] while the vault runs or once the first admins
/// are verified. The first step that fails otherwise.
pub async fn verify_first_admin_with<R: Runtime, C: Custody>(
    rt: &R,
    cfg: &VaultConfig,
    custody: &C,
    account: u128,
    file: &[u8],
) -> Result<(), VaultError> {
    let entry = crate::codec::decode_identity_file(file)?;
    let creds = Credentials::read(&cfg.credentials_dir)?;
    check_start(rt, cfg, &creds).await?;
    let mut client = keys_client(rt, cfg, &creds).await?;
    lock_keystore(&mut client).await?;
    let mut runner = load_runner(rt, cfg, client, custody).await?;
    let (mut vault, mut journal) = erasure_journal(
        rt,
        cfg,
        &creds,
        runner.service_keys()?,
        runner.identity_keys(),
    )
    .await?;
    let done = async {
        runner
            .run_to_idle(&mut vault, &mut journal, now_us())
            .await?;
        runner.check_tuple_labels()?;
        runner
            .verify_first_admin(
                &mut vault,
                &mut journal,
                fstp_vault_proto::WireAccount(account),
                &entry,
                now_us(),
            )
            .await
            .map(|_| ())
    }
    .await;
    let _ = journal.client.close().await;
    let _ = runner.into_client().close().await;
    done
}

/// `fstp-vault verify-first-admin` with the vault's `fstp-keyd` entry. The
/// file is read whole, at most [`crate::codec::MAX_IDENTITY_FILE`] bytes.
///
/// # Errors
///
/// As [`verify_first_admin_with`], and [`VaultError::Config`] for a file
/// that cannot be read.
pub fn verify_first_admin(cfg: &VaultConfig, account: u128, file: &Path) -> Result<(), VaultError> {
    use std::io::Read as _;
    let f = std::fs::File::open(file).map_err(|_| cfg_err("identity file"))?;
    let limit = u64::try_from(crate::codec::MAX_IDENTITY_FILE)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::new();
    f.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|_| cfg_err("identity file"))?;
    let custody = keyd(cfg)?;
    let rt = runtime()?;
    let task_rt = rt.clone();
    rt.block_on(
        async move { verify_first_admin_with(&task_rt, cfg, &custody, account, &bytes).await },
    )
}

/// What the binary was asked to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// Serve the vault.
    Serve,
    /// `init-keys <out dir>`.
    InitKeys(PathBuf),
    /// `erase-identity <account>`: the account id as 32 hex digits, with
    /// or without the dashes of the UUID form (ADR-004 record of lane
    /// L11).
    EraseIdentity(u128),
    /// `restore-keystore [<snapshot id>]`: the snapshot id as 32 hex
    /// digits, or the newest one (ADR-012 record of lane L17).
    RestoreKeystore(Option<[u8; 16]>),
    /// `check-keystore <port>`: open the keystore rows of a restore drill's
    /// scratch cluster at `port`, and write nothing (ADR-012 record of lane
    /// m10/backup-health).
    CheckKeystore(u16),
    /// `verify-first-admin <account> <identity file>`: the technical admin
    /// verifies a first admin on the host (ADR-008, Daniel, 2026-11-21).
    VerifyFirstAdmin(u128, PathBuf),
}

/// The account id of `text`: 32 hex digits, with or without the four
/// dashes of the UUID form.
fn account_of(text: &str) -> Option<u128> {
    let dashes = [8, 13, 18, 23];
    let hex: String = if text.len() == 36 {
        let ok = text
            .char_indices()
            .all(|(i, c)| dashes.contains(&i) == (c == '-'));
        if !ok {
            return None;
        }
        text.chars().filter(|c| *c != '-').collect()
    } else {
        text.to_owned()
    };
    if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u128::from_str_radix(&hex, 16).ok()
}

/// A port: a canonical decimal from 1 to 65535.
fn port_of(s: &str) -> Option<u16> {
    if s.is_empty() || s.len() > 5 || !s.bytes().all(|b| b.is_ascii_digit()) || s.starts_with('0') {
        return None;
    }
    s.parse::<u16>().ok()
}

/// Parses the binary's arguments, without the program name.
///
/// # Errors
///
/// [`VaultError::Config`] for any other form.
pub fn parse_args(args: &[String]) -> Result<Command, VaultError> {
    match args {
        [] => Ok(Command::Serve),
        [cmd, out] if cmd == "init-keys" => Ok(Command::InitKeys(PathBuf::from(out))),
        [cmd, account] if cmd == "erase-identity" => account_of(account)
            .map(Command::EraseIdentity)
            .ok_or(cfg_err("arguments")),
        [cmd] if cmd == "restore-keystore" => Ok(Command::RestoreKeystore(None)),
        [cmd, id] if cmd == "restore-keystore" => account_of(id)
            .filter(|_| id.len() == 32)
            .map(|n| Command::RestoreKeystore(Some(n.to_be_bytes())))
            .ok_or(cfg_err("arguments")),
        [cmd, port] if cmd == "check-keystore" => port_of(port)
            .map(Command::CheckKeystore)
            .ok_or(cfg_err("arguments")),
        [cmd, account, file] if cmd == "verify-first-admin" => account_of(account)
            .map(|a| Command::VerifyFirstAdmin(a, PathBuf::from(file)))
            .ok_or(cfg_err("arguments")),
        _ => Err(cfg_err("arguments")),
    }
}

/// Runs `command` over the configuration file of [`CONFIG_ENV`].
///
/// # Errors
///
/// The first step that fails.
pub fn run_command(command: &Command) -> Result<(), VaultError> {
    let cfg = load_config()?;
    match command {
        Command::Serve => serve(&cfg),
        Command::InitKeys(out) => init_keys(&cfg, out),
        Command::EraseIdentity(account) => erase_identity(&cfg, *account),
        Command::RestoreKeystore(id) => restore_keystore(&cfg, *id),
        Command::CheckKeystore(port) => check_keystore(&cfg, *port),
        Command::VerifyFirstAdmin(account, file) => verify_first_admin(&cfg, *account, file),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// G12: the binary takes no argument or `init-keys <dir>`, and refuses
    /// any other form.
    #[test]
    fn g12_vault_binary_takes_two_command_forms() {
        let s = |v: &[&str]| v.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>();
        assert_eq!(parse_args(&s(&[])).unwrap(), Command::Serve);
        assert_eq!(
            parse_args(&s(&["init-keys", "/tmp/d"])).unwrap(),
            Command::InitKeys(PathBuf::from("/tmp/d"))
        );
        for bad in [
            &["init-keys"][..],
            &["serve", "x"],
            &["init-keys", "a", "b"],
            &["seed", "facts.json"],
        ] {
            assert_eq!(parse_args(&s(bad)), Err(VaultError::Config("arguments")));
        }
    }

    /// ADR-008, decided by Daniel on 2026-11-21: `verify-first-admin` takes
    /// one account id and one file path, and refuses any other form.
    #[test]
    fn adr008_verify_first_admin_takes_an_account_and_a_file() {
        let s = |v: &[&str]| v.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>();
        let id = 0x0123_4567_89ab_cdef_0123_4567_89ab_cdef_u128;
        assert_eq!(
            parse_args(&s(&[
                "verify-first-admin",
                "01234567-89ab-cdef-0123-456789abcdef",
                "/root/admin.json"
            ]))
            .unwrap(),
            Command::VerifyFirstAdmin(id, PathBuf::from("/root/admin.json"))
        );
        for bad in [
            &["verify-first-admin"][..],
            &["verify-first-admin", "0123"],
            &["verify-first-admin", "0123", "/root/admin.json"],
            &["verify-first-admin", "0123456789abcdef0123456789abcdef"],
        ] {
            assert_eq!(parse_args(&s(bad)), Err(VaultError::Config("arguments")));
        }
    }

    /// R-KY-02, ADR-004 record of lane L11: `erase-identity` takes one
    /// account id, as 32 hex digits or in the UUID form, and refuses any
    /// other form.
    #[test]
    fn r_ky_02_vault_erase_identity_takes_one_account_id() {
        let s = |v: &[&str]| v.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>();
        let id = 0x0123_4567_89ab_cdef_0123_4567_89ab_cdef_u128;
        for form in [
            "0123456789abcdef0123456789abcdef",
            "01234567-89ab-cdef-0123-456789abcdef",
            "0123456789ABCDEF0123456789ABCDEF",
        ] {
            assert_eq!(
                parse_args(&s(&["erase-identity", form])).unwrap(),
                Command::EraseIdentity(id)
            );
        }
        for bad in [
            &["erase-identity"][..],
            &["erase-identity", "0123"],
            &["erase-identity", "0123456789abcdef0123456789abcdeg"],
            &["erase-identity", "0123456789-abcdef-0123-456789abcdef"],
            &["erase-identity", "+123456789abcdef0123456789abcdef"],
            &["erase-identity", "0123456789abcdef0123456789abcdef", "x"],
        ] {
            assert_eq!(parse_args(&s(bad)), Err(VaultError::Config("arguments")));
        }
    }

    /// ADR-012 record of lane L17: `restore-keystore` takes no argument or
    /// one snapshot id of 32 hex digits, and refuses any other form.
    #[test]
    fn adr012_vault_restore_keystore_takes_an_optional_snapshot_id() {
        let s = |v: &[&str]| v.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>();
        assert_eq!(
            parse_args(&s(&["restore-keystore"])).unwrap(),
            Command::RestoreKeystore(None)
        );
        assert_eq!(
            parse_args(&s(&["restore-keystore", &"0f".repeat(16)])).unwrap(),
            Command::RestoreKeystore(Some([0x0f; 16]))
        );
        for bad in [
            &["restore-keystore", "0f0f"][..],
            &["restore-keystore", "01234567-89ab-cdef-0123-456789abcdef"],
            &["restore-keystore", "a", "b"],
        ] {
            assert_eq!(parse_args(&s(bad)), Err(VaultError::Config("arguments")));
        }
    }

    /// ADR-012 record of lane m10/backup-health, row "Check: keystore":
    /// `check-keystore` takes exactly one port, a canonical decimal from 1
    /// to 65535, and refuses any other form.
    #[test]
    fn adr012_bh_vault_check_keystore_takes_a_port() {
        let s = |v: &[&str]| v.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>();
        assert_eq!(
            parse_args(&s(&["check-keystore", "5547"])).unwrap(),
            Command::CheckKeystore(5547)
        );
        for bad in [
            &["check-keystore"][..],
            &["check-keystore", "0"],
            &["check-keystore", "05547"],
            &["check-keystore", "70000"],
            &["check-keystore", "-1"],
            &["check-keystore", "5547", "x"],
        ] {
            assert!(parse_args(&s(bad)).is_err(), "{bad:?}");
        }
    }

    /// R-NF-02: a missing credential is named by its file, and the debug
    /// form of the credentials shows no byte.
    #[test]
    fn r_nf_02_vault_credentials_name_files_only() {
        let dir = std::env::temp_dir().join(format!(
            "fstp-vault-creds-{}-{}",
            std::process::id(),
            fstp_crypto::random_array::<4>()
                .map(u32::from_be_bytes)
                .unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(
            Credentials::read(&dir).unwrap_err(),
            VaultError::Config("db-ca.pem")
        );
        for name in config::CREDENTIAL_FILES {
            std::fs::write(dir.join(name), b"s3cr3tm4rk3r").unwrap();
        }
        let c = Credentials::read(&dir).unwrap();
        assert!(!format!("{c:?}").contains("s3cr3t"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
