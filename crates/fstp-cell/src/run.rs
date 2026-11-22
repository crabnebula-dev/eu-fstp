//! The `fstp-cell` binary's commands over a configuration file (ADR-026
//! "Configuration", lane L4, gaps G1, G8, G10 and G11).
//!
//! - [`serve`] starts the cell named by the file and serves it until
//!   SIGTERM or SIGINT drains it.
//! - [`first_admin`] starts the same cell with every listener on a loopback
//!   port the system picks, records the first admin's invitation, writes
//!   its token once to a new file, and stops (D4). With `--email` it also
//!   records the first admin's login email (ADR-026 "First admin email").
//! - [`provision_tenant`] starts the cell the same way, records
//!   `TenantProvisioned`, and stops (ADR-026 "Tenant provisioning").
//! - [`init_keys`] creates the sealed cell key file at genesis, through the
//!   dedicated custody entry, and writes the public keys the witness and
//!   the vault pin (ADR-004 record of L4).
//!
//! Every start reads the credentials directory by fixed name, opens the
//! cell key file, draws a new ledger key generation and rewrites the file
//! before any seal ([`crate::keyfile`]). One tokio runtime runs the cell,
//! through `fstp-rt` (ADR-002).

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use fstp_rt::Runtime;
use fstp_rt::tokio::TokioRuntime;

use crate::CellError;
use crate::config::{self, ConfigError, FileConfig, ServerKind};
use crate::engine::startup::ClusterRole;
use crate::keyfile;
use crate::process::{self, CellProcessParts, Listen, RegisteredSpki, StartOptions};

/// The environment variable that names the configuration file.
pub const CONFIG_ENV: &str = "FSTP_CELL_CONFIG";

/// How long the cell drains at SIGTERM.
pub const DRAIN: Duration = Duration::from_secs(20);

/// The worker threads of the runtime.
const WORKERS: usize = 4;

/// How long a database connection may take to open.
const DB_CONNECT: Duration = Duration::from_secs(20);

fn cfg_err(rule: &'static str) -> CellError {
    CellError::Config(ConfigError::Invalid(rule))
}

/// Reads the credential `name` of the credentials directory. The error
/// names the file, never its bytes.
fn read(dir: &Path, name: &'static str) -> Result<Vec<u8>, CellError> {
    std::fs::read(dir.join(name)).map_err(|_| cfg_err(name))
}

/// Reads a one-line secret, without its line end.
fn read_secret(dir: &Path, name: &'static str) -> Result<String, CellError> {
    let bytes = read(dir, name)?;
    let text = String::from_utf8(bytes).map_err(|_| cfg_err(name))?;
    Ok(text.trim_end_matches(['\r', '\n']).to_owned())
}

/// The configuration file named by [`CONFIG_ENV`], decoded.
///
/// # Errors
///
/// [`CellError::Config`] for a missing or refused file.
pub fn load_config() -> Result<FileConfig, CellError> {
    let path = std::env::var_os(CONFIG_ENV).ok_or(CellError::Config(ConfigError::Missing))?;
    let bytes = crate::read_config(Path::new(&path))?;
    config::decode_file(&bytes).map_err(CellError::Config)
}

/// One vault client shared by the engine and the API core.
#[derive(Clone)]
pub struct SharedVault<R: Runtime>(Arc<crate::vault::HttpVaultClient<R>>);

impl<R: Runtime> crate::engine::VaultClient for SharedVault<R> {
    fn epoch(
        &self,
    ) -> impl std::future::Future<
        Output = Result<fstp_domain::id::VaultEpoch, fstp_cell_core::driver::VaultFault>,
    > + Send {
        let v = Arc::clone(&self.0);
        async move { v.epoch().await }
    }

    fn ask(
        &self,
        queries: &[fstp_domain::oracle::Query],
        reaction_for: Option<fstp_domain::id::VaultEpoch>,
        at: fstp_domain::time::Timestamp,
    ) -> impl std::future::Future<
        Output = Result<fstp_domain::oracle::Answers, fstp_cell_core::driver::VaultFault>,
    > + Send {
        self.0.ask(queries, reaction_for, at)
    }

    fn ack(
        &self,
        epoch: fstp_domain::id::VaultEpoch,
        seq: fstp_ledger::Seq,
        link: [u8; 32],
    ) -> impl std::future::Future<Output = Result<(), fstp_cell_core::driver::VaultFault>> + Send
    {
        self.0.ack(epoch, seq, link)
    }
}

/// The login of `role` on the cell database, with its client certificate,
/// key and password from the credentials directory (ADR-026 "Logins").
fn login(cfg: &FileConfig, role: fstp_pgstore::Role) -> Result<fstp_pgwire::Config, CellError> {
    let dir = &cfg.credentials_dir;
    let (pem, key, password): (&'static str, &'static str, &'static str) = match role {
        fstp_pgstore::Role::Writer => ("writer.pem", "writer.key", "writer.password"),
        fstp_pgstore::Role::App => ("app.pem", "app.key", "app.password"),
        fstp_pgstore::Role::Keys => ("keys.pem", "keys.key", "keys.password"),
        _ => return Err(cfg_err("database role")),
    };
    let tls =
        fstp_pgwire::ClientTls::new(&read(dir, "db-ca.pem")?, &read(dir, pem)?, &read(dir, key)?)
            .map_err(|_| cfg_err(pem))?;
    let password =
        fstp_pgwire::Password::new(read_secret(dir, password)?).map_err(|_| cfg_err(password))?;
    let user = format!("{}_{}", cfg.database.dbname, role.suffix());
    Ok(fstp_pgwire::Config::new(
        cfg.database.host.clone(),
        cfg.database.port,
        user.as_str(),
        password,
        cfg.database.dbname.clone(),
        tls,
    )
    .map_err(|_| cfg_err("database"))?
    .connect_timeout(Some(DB_CONNECT)))
}

/// The parts and options of the cell of `cfg` on `rt`, with `keys` from
/// the opened key file and the listeners at `listen`.
fn parts(
    rt: &TokioRuntime,
    cfg: &FileConfig,
    keys: process::CellKeys,
    listen: Listen,
) -> Result<
    (
        CellProcessParts<SharedCustody, SharedVault<TokioRuntime>>,
        StartOptions,
    ),
    CellError,
> {
    let dir = &cfg.credentials_dir;
    let tls_err = |name: &'static str| move |_| cfg_err(name);
    let custody = SharedCustody(Arc::new(
        fstp_custody::KeydCustody::new(&cfg.keyd_socket).map_err(|_| cfg_err("keyd_socket"))?,
    ));
    let witness = crate::witness::link::WitnessEndpoint {
        addr: cfg.witness.address,
        server_name: cfg.witness.server_name.clone(),
        tls: fstp_tls::ClientConfig::mutual(
            &read(dir, "witness-ca.pem")?,
            &read(dir, "witness.pem")?,
            &read(dir, "witness.key")?,
        )
        .map_err(tls_err("witness.pem"))?,
        ca_digest: cfg.witness.ca_spki_sha256,
    };
    let witness_keys = config::decode_receipt_keys(&read(dir, "witness-receipt-keys")?)
        .map_err(CellError::Config)?;
    let vault = SharedVault(Arc::new(crate::vault::HttpVaultClient::new(
        rt.clone(),
        format!("https://{}", cfg.vault.address),
        fstp_tls::ClientConfig::mutual(
            &read(dir, "vault-ca.pem")?,
            &read(dir, "vault.pem")?,
            &read(dir, "vault.key")?,
        )
        .map_err(tls_err("vault.pem"))?,
    )));
    let tunnel_tls = crate::http::tunnel::TunnelTls {
        tunnel: Arc::new(
            fstp_tls::ServerConfig::mutual(
                &read(dir, "tunnel.pem")?,
                &read(dir, "tunnel.key")?,
                &read(dir, "tunnel-ca.pem")?,
            )
            .map_err(tls_err("tunnel.pem"))?,
        ),
        origin: Arc::new(
            fstp_tls::ServerConfig::new(&read(dir, "origin.pem")?, &read(dir, "origin.key")?)
                .map_err(tls_err("origin.pem"))?,
        ),
    };
    let internal_tls = Arc::new(
        fstp_tls::ServerConfig::mutual(
            &read(dir, "internal.pem")?,
            &read(dir, "internal.key")?,
            &read(dir, "cell-ca.pem")?,
        )
        .map_err(tls_err("internal.pem"))?,
    );
    let (pages, web_assets) = match &cfg.assets_dir {
        Some(assets) => {
            let auth = assets.join("auth");
            let pages = crate::http::pages::Pages::load(&auth, &auth)
                .map_err(|_| cfg_err("assets_dir/auth"))?;
            let app = process::load_web_assets(&assets.join("app"))
                .map_err(|_| cfg_err("assets_dir/app"))?;
            (Some(pages), app)
        }
        None => (
            None,
            process::stub_web_assets().map_err(|_| cfg_err("assets_dir"))?,
        ),
    };
    let registered_servers = cfg
        .registered_servers
        .iter()
        .map(|r| RegisteredSpki {
            digest: r.spki_sha256,
            role: match r.kind {
                ServerKind::Application => ClusterRole::Application,
                ServerKind::Vault => ClusterRole::Vault,
                ServerKind::Control | ServerKind::Witness => ClusterRole::Other,
            },
        })
        .collect();
    // D3: one platform relay for proof mail and for the API core's
    // delivered mail (role invitations, recovery approvals, lane L5).
    let mail_ca = match std::fs::read(dir.join("mail-ca.pem")) {
        Ok(pem) => Some(pem),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err(cfg_err("mail-ca.pem")),
    };
    let relay: Option<Arc<crate::mail::SmtpRelay<TokioRuntime>>> = match &cfg.mail {
        None => None,
        Some(m) => {
            let password = read_secret(dir, "mail.password")?;
            let credentials = fstp_smtp::client::Credentials::try_new(&m.username, &password)
                .map_err(|_| cfg_err("mail.password"))?;
            Some(Arc::new(
                crate::mail::SmtpRelay::new(
                    cfg.core.mode,
                    rt.clone(),
                    crate::mail::RelayParts {
                        relay: &m.relay,
                        address: m.address,
                        sender: &m.sender,
                        helo: &cfg.host,
                        credentials,
                        ca_pem: mail_ca.as_deref(),
                    },
                )
                .map_err(|_| cfg_err("mail"))?,
            ))
        }
    };
    let proof_mail: Arc<dyn crate::mail::ProofMail> = match &relay {
        None => Arc::new(crate::mail::NoProofMail),
        Some(r) => Arc::new(crate::mail::RelayProofMail::new(
            rt.clone(),
            Arc::clone(r) as Arc<dyn crate::mail::MailRelay>,
            &cfg.host,
        )),
    };
    let api_relay = relay.map(|r| r as process::ApiRelay);
    // ADR-027: the creator shell over the configured probes. The relay
    // probe checks the relay the cell submits to.
    let shell = cfg.shell.clone().unwrap_or_default();
    // ADR-026 record of lane L18: the same probes serve onboarding's
    // Domains and email and Channels steps through the API core.
    let (creator_shell, tenant_prober) = crate::shell::facts::production_probes(
        rt.clone(),
        crate::shell::facts::ShellSettings {
            resolver: shell.resolver,
            probes: crate::shell::probe::ProbeSettings {
                mail_relay: cfg.mail.as_ref().map(|m| m.relay.clone()),
                mail_address: cfg.mail.as_ref().and_then(|m| m.address),
                mail_ca_pem: mail_ca,
                sending_domain: shell.sending_domain,
                dkim_selector: shell.dkim_selector,
            },
            platform_url: shell.platform_url,
        },
    );
    let parts = CellProcessParts {
        cell: cfg.core.cell.0,
        mode: cfg.core.mode,
        host: cfg.host.clone(),
        writer: login(cfg, fstp_pgstore::Role::Writer)?,
        app: login(cfg, fstp_pgstore::Role::App)?,
        registered_servers,
        custody,
        keystore: login(cfg, fstp_pgstore::Role::Keys)?,
        keys,
        witness,
        witness_keys,
        vault,
        tunnel_tls,
        internal_tls,
        pages,
        listen,
    };
    let options = StartOptions {
        proof_mail,
        api_relay,
        creator_shell,
        // ADR-021, ADR-026 record of lane L18: the organisation port keeps
        // its default, "not active". Only the ledger activates.
        tenant_prober: Some(tenant_prober),
        web_assets: Some(web_assets),
        // ADR-028 record of lane L20: the System page's host status file.
        host_status: cfg.host_status.clone(),
        ..StartOptions::default()
    };
    Ok((parts, options))
}

/// Opens the cell key file through its dedicated custody entry, draws a
/// new ledger key generation and rewrites the file before any seal
/// (ADR-004 record of L4). The keys of the start.
async fn open_keys(cfg: &FileConfig) -> Result<process::CellKeys, CellError> {
    let path = cfg.credentials_dir.join(keyfile::KEY_FILE);
    let bytes = std::fs::read(&path).map_err(|_| cfg_err(keyfile::KEY_FILE))?;
    let custody = fstp_custody::KeydCustody::new(&cfg.key_file_keyd_socket)
        .map_err(|_| cfg_err("key_file_keyd_socket"))?;
    let (body, file) = keyfile::open_and_advance(&custody, cfg.core.cell.0, &bytes)
        .await
        .map_err(|e| CellError::Keys(e.0))?;
    keyfile::write_atomic(&path, &file).map_err(|e| CellError::Keys(e.0))?;
    crate::key_copy::report(&cfg.credentials_dir, &body);
    body.cell_keys().map_err(|e| CellError::Keys(e.0))
}

fn runtime() -> Result<TokioRuntime, CellError> {
    TokioRuntime::new_multi_thread(WORKERS).map_err(|e| CellError::Io(e.kind()))
}

fn listen_of(cfg: &FileConfig) -> Listen {
    Listen {
        tunnel: cfg.listen.tunnel,
        internal: cfg.listen.internal,
        health: cfg.listen.health,
    }
}

/// Serves the cell of `cfg` until SIGTERM or SIGINT drains it (module
/// documentation).
///
/// # Errors
///
/// The first step that fails, as a [`CellError`].
pub fn serve(cfg: &FileConfig) -> Result<(), CellError> {
    use fstp_rt::signal::{Signals as _, TerminationListener as _};
    let rt = runtime()?;
    // Registered before the start, so a SIGTERM during it is queued.
    let mut term = rt.listen_termination().map_err(|_| CellError::Signal)?;
    let task_rt = rt.clone();
    rt.block_on(async move {
        let keys = open_keys(cfg).await?;
        let (parts, options) = parts(&task_rt, cfg, keys, listen_of(cfg))?;
        let running = process::start_with(&task_rt, parts, options).await?;
        let _ = fstp_obs::log_to_stderr(&fstp_obs::LogEvent::Started);
        let _ = term.recv().await;
        let _ = fstp_obs::log_to_stderr(&fstp_obs::LogEvent::ShuttingDown);
        running.shutdown(DRAIN).await
    })
}

/// The first admin's token in the form `fstp-cell first-admin` writes:
/// one lowercase hex line per half.
#[must_use]
pub fn token_text(token: &process::FirstAdminToken) -> zeroize::Zeroizing<String> {
    let mut out = zeroize::Zeroizing::new(String::with_capacity(130));
    for half in std::iter::once(&token.first).chain(token.second.iter()) {
        for b in half {
            use std::fmt::Write as _;
            let _ = write!(out, "{b:02x}");
        }
        out.push('\n');
    }
    out
}

/// Writes `text` to a new file `path` with mode 0600. An existing file is
/// refused, so a token is written once.
fn write_new(path: &Path, text: &[u8]) -> Result<(), CellError> {
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

/// Starts the cell of `cfg` with every listener on a loopback port the
/// system picks, runs `f` on it, and stops it. The commands that act on a
/// stopped cell run this way (D4, ADR-026 "Tenant provisioning").
fn on_loopback<T>(
    cfg: &FileConfig,
    f: impl AsyncFnOnce(&process::RunningCell<TokioRuntime>) -> Result<T, CellError>,
) -> Result<T, CellError> {
    let rt = runtime()?;
    let task_rt = rt.clone();
    let loopback = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    rt.block_on(async move {
        let keys = open_keys(cfg).await?;
        let listen = Listen {
            tunnel: loopback,
            internal: loopback,
            health: loopback,
        };
        let (parts, options) = parts(&task_rt, cfg, keys, listen)?;
        let running = process::start_with(&task_rt, parts, options).await?;
        let done = f(&running).await;
        let stopped = running.shutdown(DRAIN).await;
        let out = done?;
        stopped.map(|()| out)
    })
}

/// `fstp-cell first-admin [--email <address>] <out>` (D4, module
/// documentation): records the first admin's invitation and writes its
/// token once to the new file `out`. With `email`, the address becomes
/// the first admin's login email (ADR-026 "First admin email", decided by
/// Daniel on 2026-11-21). Run it while the cell is stopped.
///
/// # Errors
///
/// The first step that fails, as a [`CellError`]. An existing `out` is
/// refused before the cell starts. A cell whose first admin is invited or
/// enrolled already refuses the invitation ([`CellError::Store`]), and so
/// does an address that is another account's login email
/// ([`CellError::Config`]).
pub fn first_admin(cfg: &FileConfig, out: &Path, email: Option<&str>) -> Result<(), CellError> {
    if std::fs::symlink_metadata(out).is_ok() {
        return Err(cfg_err("output file"));
    }
    on_loopback(cfg, async |running| {
        let token = running.first_admin_invitation(email).await?;
        write_new(out, token_text(&token).as_bytes())
    })
}

/// The account id `raw` in the form `fstp-vault verify-first-admin` takes:
/// 32 lowercase hex digits in the groups 8-4-4-4-12, as the onboarding
/// checklist shows it (ADR-026 record of lane L18).
#[must_use]
pub fn account_number(raw: u128) -> String {
    let h = format!("{raw:032x}");
    let (a, rest) = h.split_at(8);
    let (b, rest) = rest.split_at(4);
    let (c, rest) = rest.split_at(4);
    let (d, e) = rest.split_at(4);
    format!("{a}-{b}-{c}-{d}-{e}")
}

/// `fstp-cell admins <file>` (ADR-028 "Verify the first admins", lane
/// L19): writes the account of each tenant admin to the new file, one per
/// line in [`account_number`] form, the first admin first. Before the first
/// admin enrols, its line is the account `provision-tenant` drew. Run it
/// while the cell is stopped, as `first-admin`. An account id is a random
/// id, not an identity attribute (R-NF-02).
///
/// # Errors
///
/// [`CellError::Config`] for an existing file, and the first step that
/// fails, as a [`CellError`].
pub fn admins(cfg: &FileConfig, out: &Path) -> Result<(), CellError> {
    if std::fs::symlink_metadata(out).is_ok() {
        return Err(cfg_err("output file"));
    }
    on_loopback(cfg, async |running| {
        let state = running.engine().state();
        let tenant = &state.engine().tenant;
        let mut list: Vec<u128> = Vec::new();
        if let Some(p) = tenant.provisioning() {
            list.push(p.first_admin.raw());
        }
        if let Some(t) = tenant.state() {
            for a in t.admins() {
                if !list.contains(&a.raw()) {
                    list.push(a.raw());
                }
            }
        }
        let mut text = String::new();
        for a in list {
            text.push_str(&account_number(a));
            text.push('\n');
        }
        write_new(out, text.as_bytes())
    })
}

/// `fstp-cell provision-tenant [--agreements <saas_terms>,<dpa>,<sub_processors>]`
/// (ADR-026 "Tenant provisioning", decided by Daniel on 2026-11-21):
/// records `TenantProvisioned` in the cell's ledger, so the ADR-021 gate
/// reads a real tenant part. A SaaS cell needs the agreement versions the
/// tenant accepted (Q22). A self-hosted cell refuses them. Run it while
/// the cell is stopped, after `init-keys` and before `first-admin`.
///
/// # Errors
///
/// [`CellError::Config`] for agreement versions missing on a SaaS cell or
/// given on a self-hosted one, before the cell starts. Then the first step
/// that fails, as a [`CellError`]. A ledger that holds a tenant part
/// refuses it ([`CellError::Store`]).
pub fn provision_tenant(
    cfg: &FileConfig,
    agreements: Option<fstp_engine::AgreementVersions>,
) -> Result<(), CellError> {
    match (cfg.core.mode, agreements) {
        (config::Mode::Saas, None) | (config::Mode::SelfHosted, Some(_)) => {
            return Err(cfg_err("agreements"));
        }
        _ => {}
    }
    on_loopback(cfg, async |running| {
        running.provision_tenant(agreements).await.map(|_| ())
    })
}

/// `fstp-cell init-keys <out dir>` (ADR-004 record of L4): creates the
/// dedicated custody root and the sealed cell key file in the credentials
/// directory, and writes `anchor.pub` (the composite public key the
/// witness pins) and `ticket.pub` (the Ed25519 public key the vault pins)
/// to `out`, in lowercase hex. An existing key file is refused.
///
/// # Errors
///
/// The first step that fails, as a [`CellError`].
pub fn init_keys(cfg: &FileConfig, out: &Path) -> Result<(), CellError> {
    let path = cfg.credentials_dir.join(keyfile::KEY_FILE);
    if std::fs::symlink_metadata(&path).is_ok() {
        return Err(cfg_err(keyfile::KEY_FILE));
    }
    let body = keyfile::KeyBody::generate().map_err(|e| CellError::Keys(e.0))?;
    let anchor = body.anchor_public().map_err(|e| CellError::Keys(e.0))?;
    let ticket = body.ticket_public().map_err(|e| CellError::Keys(e.0))?;
    let rt = runtime()?;
    let bytes = rt.block_on(async {
        let custody = fstp_custody::KeydCustody::new(&cfg.key_file_keyd_socket)
            .map_err(|_| cfg_err("key_file_keyd_socket"))?;
        keyfile::create(&custody, cfg.core.cell.0, &body)
            .await
            .map_err(|e| CellError::Keys(e.0))
    })?;
    keyfile::write_atomic(&path, &bytes).map_err(|e| CellError::Keys(e.0))?;
    let line = |b: &[u8]| -> String {
        let mut s: String = b.iter().map(|x| format!("{x:02x}")).collect();
        s.push('\n');
        s
    };
    write_new(&out.join("anchor.pub"), line(&anchor).as_bytes())?;
    write_new(&out.join("ticket.pub"), line(&ticket).as_bytes())
}

/// `copy-key-file <out>` (ADR-004 record of lane L16, Q-L16-3): copies
/// the sealed cell key file to the new file `out` and records it.
///
/// # Errors
///
/// [`CellError::Keys`] naming the step that failed.
pub fn copy_key_file(cfg: &FileConfig, out: &Path) -> Result<(), CellError> {
    let rt = runtime()?;
    rt.block_on(async {
        let custody = fstp_custody::KeydCustody::new(&cfg.key_file_keyd_socket)
            .map_err(|_| cfg_err("key_file_keyd_socket"))?;
        crate::key_copy::copy_key_file(&custody, cfg.core.cell.0, &cfg.credentials_dir, out)
            .await
            .map(|_| ())
            .map_err(|e| CellError::Keys(e.0))
    })
}

/// What the binary was asked to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// Serve the cell.
    Serve,
    /// `first-admin [--email <address>] <out>`.
    FirstAdmin {
        /// The new token file.
        out: PathBuf,
        /// The first admin's login email, if any (ADR-026 "First admin
        /// email").
        email: Option<String>,
    },
    /// `init-keys <out dir>`.
    InitKeys(PathBuf),
    /// `admins <out>`: the tenant admins' account ids, for
    /// `fstp-vault verify-first-admin` (ADR-028 "Verify the first admins").
    Admins(PathBuf),
    /// `copy-key-file <out>`: an off-host copy of the cell key file,
    /// recorded in its copy register (ADR-004 record of lane L16).
    CopyKeyFile(PathBuf),
    /// `retire-key-file-copy <id>`: every copy of `id` is destroyed.
    RetireKeyFileCopy(fstp_custody::copies::CopyId),
    /// `provision-tenant [--agreements <saas_terms>,<dpa>,<sub_processors>]`
    /// (ADR-026 "Tenant provisioning").
    ProvisionTenant {
        /// The agreement versions the tenant accepted (Q22).
        agreements: Option<fstp_engine::AgreementVersions>,
    },
}

/// The longest login email the routes take (`POST /auth/magic/request`).
const MAX_EMAIL: usize = 254;

/// A login email as the routes take it: 1 to 254 bytes with an `@`. The
/// refusal names the rule, never the address (R-NF-02).
fn email_arg(s: &str) -> Result<String, CellError> {
    if s.is_empty() || s.len() > MAX_EMAIL || !s.contains('@') || s.chars().any(char::is_control) {
        return Err(cfg_err("email"));
    }
    Ok(s.to_owned())
}

/// One agreement version: a canonical decimal of 1 or more.
fn version_arg(s: &str) -> Option<u32> {
    let canonical = !s.is_empty()
        && s.len() <= 10
        && s.bytes().all(|b| b.is_ascii_digit())
        && !s.starts_with('0');
    if !canonical {
        return None;
    }
    s.parse::<u32>().ok()
}

/// `<saas_terms>,<dpa>,<sub_processors>`, each a version of 1 or more.
fn agreements_arg(s: &str) -> Result<fstp_engine::AgreementVersions, CellError> {
    let parts: Vec<&str> = s.split(',').collect();
    let [saas_terms, dpa, sub_processors] = parts.as_slice() else {
        return Err(cfg_err("agreements"));
    };
    let v = |p: &str| version_arg(p).ok_or_else(|| cfg_err("agreements"));
    Ok(fstp_engine::AgreementVersions {
        saas_terms: v(saas_terms)?,
        dpa: v(dpa)?,
        sub_processors: v(sub_processors)?,
    })
}

/// Parses the binary's arguments, without the program name.
///
/// # Errors
///
/// [`CellError::Config`] for any other form.
pub fn parse_args(args: &[String]) -> Result<Command, CellError> {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        [] => Ok(Command::Serve),
        ["first-admin", out] if !out.starts_with("--") => Ok(Command::FirstAdmin {
            out: PathBuf::from(out),
            email: None,
        }),
        ["first-admin", "--email", email, out] if !out.starts_with("--") => {
            Ok(Command::FirstAdmin {
                out: PathBuf::from(out),
                email: Some(email_arg(email)?),
            })
        }
        ["init-keys", out] => Ok(Command::InitKeys(PathBuf::from(out))),
        ["admins", out] => Ok(Command::Admins(PathBuf::from(out))),
        ["provision-tenant"] => Ok(Command::ProvisionTenant { agreements: None }),
        ["provision-tenant", "--agreements", v] => Ok(Command::ProvisionTenant {
            agreements: Some(agreements_arg(v)?),
        }),
        ["copy-key-file", out] => Ok(Command::CopyKeyFile(PathBuf::from(out))),
        ["retire-key-file-copy", id] => fstp_custody::copies::CopyId::parse(id)
            .map(Command::RetireKeyFileCopy)
            .ok_or_else(|| cfg_err("arguments")),
        _ => Err(cfg_err("arguments")),
    }
}

/// Runs `command` over the configuration file of [`CONFIG_ENV`].
///
/// # Errors
///
/// The first step that fails, as a [`CellError`].
pub fn run_command(command: &Command) -> Result<(), CellError> {
    let cfg = load_config()?;
    match command {
        Command::Serve => serve(&cfg),
        Command::FirstAdmin { out, email } => first_admin(&cfg, out, email.as_deref()),
        Command::InitKeys(out) => init_keys(&cfg, out),
        Command::Admins(out) => admins(&cfg, out),
        Command::ProvisionTenant { agreements } => provision_tenant(&cfg, *agreements),
        Command::CopyKeyFile(out) => copy_key_file(&cfg, out),
        Command::RetireKeyFileCopy(id) => {
            crate::key_copy::retire(&cfg.credentials_dir, *id).map_err(|e| CellError::Keys(e.0))
        }
    }
}

/// The cell's `fstp-keyd` client, shared by the engine, the keystore and
/// the erasure task.
#[derive(Clone, Debug)]
pub struct SharedCustody(Arc<fstp_custody::KeydCustody>);

impl fstp_custody::Custody for SharedCustody {
    fn create_root(
        &self,
        label: fstp_custody::RootLabel,
    ) -> impl std::future::Future<Output = Result<fstp_custody::RootRef, fstp_custody::CustodyError>>
    + Send {
        self.0.create_root(label)
    }

    fn wrap(
        &self,
        root: &fstp_custody::RootRef,
        key: &fstp_custody::SealKey,
        aad: &fstp_custody::Aad,
    ) -> impl std::future::Future<
        Output = Result<fstp_custody::WrappedSealKey, fstp_custody::CustodyError>,
    > + Send {
        self.0.wrap(root, key, aad)
    }

    fn unwrap(
        &self,
        root: &fstp_custody::RootRef,
        w: &fstp_custody::WrappedSealKey,
        aad: &fstp_custody::Aad,
    ) -> impl std::future::Future<Output = Result<fstp_custody::SealKey, fstp_custody::CustodyError>>
    + Send {
        self.0.unwrap(root, w, aad)
    }

    fn destroy(
        &self,
        root: &fstp_custody::RootRef,
    ) -> impl std::future::Future<
        Output = Result<fstp_custody::DestroyReceipt, fstp_custody::CustodyError>,
    > + Send {
        self.0.destroy(root)
    }

    fn sign(
        &self,
        key: &fstp_custody::SignKeyRef,
        digest: &[u8; 32],
    ) -> impl std::future::Future<
        Output = Result<fstp_custody::EcdsaSignature, fstp_custody::CustodyError>,
    > + Send {
        self.0.sign(key, digest)
    }

    fn usage_since(
        &self,
        root: &fstp_custody::RootRef,
        cursor: fstp_custody::UsageCursor,
    ) -> impl std::future::Future<
        Output = Result<fstp_custody::UsagePage, fstp_custody::CustodyError>,
    > + Send {
        self.0.usage_since(root, cursor)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// ADR-028 "Verify the first admins", ADR-026 record of lane L18: the
    /// `admins` command takes one file, and an account prints in the
    /// 8-4-4-4-12 hex form `fstp-vault verify-first-admin` reads.
    #[test]
    fn adr028_admins_command_and_account_number_form() {
        let args = |a: &[&str]| a.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert!(matches!(
            parse_args(&args(&["admins", "/tmp/a"])),
            Ok(Command::Admins(_))
        ));
        assert!(parse_args(&args(&["admins"])).is_err());
        assert!(parse_args(&args(&["admins", "/a", "/b"])).is_err());
        assert_eq!(
            account_number(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef),
            "01234567-89ab-cdef-0123-456789abcdef"
        );
        assert_eq!(account_number(1), "00000000-0000-0000-0000-000000000001");
    }

    /// D4, ADR-026 "Tenant provisioning" and "First admin email" (decided
    /// by Daniel on 2026-11-21): the binary takes no argument,
    /// `first-admin [--email <address>] <file>`, `init-keys <dir>` or
    /// `provision-tenant [--agreements <a>,<b>,<c>]`, and refuses any
    /// other form. A refused email or version names its rule and never
    /// quotes the argument (R-NF-02).
    #[test]
    fn adr026_binary_takes_its_command_forms() {
        let s = |v: &[&str]| v.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>();
        assert_eq!(parse_args(&s(&[])).unwrap(), Command::Serve);
        assert_eq!(
            parse_args(&s(&["first-admin", "/tmp/t"])).unwrap(),
            Command::FirstAdmin {
                out: PathBuf::from("/tmp/t"),
                email: None
            }
        );
        assert_eq!(
            parse_args(&s(&[
                "first-admin",
                "--email",
                "admin@example.test",
                "/tmp/t"
            ]))
            .unwrap(),
            Command::FirstAdmin {
                out: PathBuf::from("/tmp/t"),
                email: Some("admin@example.test".to_owned())
            }
        );
        assert_eq!(
            parse_args(&s(&["init-keys", "/tmp/d"])).unwrap(),
            Command::InitKeys(PathBuf::from("/tmp/d"))
        );
        assert_eq!(
            parse_args(&s(&["provision-tenant"])).unwrap(),
            Command::ProvisionTenant { agreements: None }
        );
        assert_eq!(
            parse_args(&s(&["provision-tenant", "--agreements", "1,2,3"])).unwrap(),
            Command::ProvisionTenant {
                agreements: Some(fstp_engine::AgreementVersions {
                    saas_terms: 1,
                    dpa: 2,
                    sub_processors: 3,
                })
            }
        );
        for bad in [
            &["first-admin"][..],
            &["first-admin", "--email"],
            &["first-admin", "--email", "a@b"],
            &["first-admin", "--email", "no-at-sign", "/tmp/t"],
            &["first-admin", "--email", "", "/tmp/t"],
            &["first-admin", "/tmp/t", "--email", "a@b"],
            &["serve", "x"],
            &["init-keys", "a", "b"],
            &["provision-tenant", "--agreements"],
            &["provision-tenant", "--agreements", "1,1"],
            &["provision-tenant", "--agreements", "1,1,0"],
            &["provision-tenant", "--agreements", "1,01,1"],
            &["provision-tenant", "--agreements", "1,1,1,1"],
            &["provision-tenant", "x"],
        ] {
            match parse_args(&s(bad)) {
                Err(CellError::Config(ConfigError::Invalid(rule))) => {
                    for arg in bad.iter().filter(|a| a.len() > 2) {
                        assert!(!rule.contains(*arg), "R-NF-02: {rule} quotes {arg}");
                    }
                }
                other => panic!("{bad:?}: {other:?}"),
            }
        }
    }

    /// D4, design section 8.3: a SaaS token is written as two halves on
    /// two lines, a self-hosted token as one line.
    #[test]
    fn adr026_first_admin_token_text_has_one_line_per_half() {
        let saas = process::FirstAdminToken {
            first: [0xab; 32],
            second: Some([0x01; 32]),
        };
        assert_eq!(
            token_text(&saas).as_str(),
            format!("{}\n{}\n", "ab".repeat(32), "01".repeat(32))
        );
        let own = process::FirstAdminToken {
            first: [0xcd; 32],
            second: None,
        };
        assert_eq!(token_text(&own).as_str(), format!("{}\n", "cd".repeat(32)));
    }
}
