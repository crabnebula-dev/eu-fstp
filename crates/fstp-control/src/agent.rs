//! The `fstp-pgagent` process: its executor, listener and run loop
//! (ADR-011 "fstp-pgagent", design sections 2.3, 4.1 and 9.2).
//!
//! The agent listens on the control-private port over mutual TLS. The
//! TLS handshake accepts only a client certificate that chains to the
//! control-plane CA. That CA also issues the cells' `CellToCp`
//! certificates, so the agent then requires the subject CN
//! [`CONTROL_PEER_CN`]. Interim, pending Daniel: ADR-011 names the issuer
//! but not the subject of the certificate it issues to `fstp-control`.
//!
//! One connection carries one job ([`crate::exchange`]): a frame of
//! [`crate::pgagent::encode_pgagent_job`] in, a [`JobOutcome`] frame out.
//! The agent renders a job only through [`AgentScope::statements`], so a
//! job for the other cluster kind is refused before any SQL exists (I-83).
//! A plain job frame of a destructive job is refused with
//! [`JobRefusal::ApprovalRequired`]. A destructive job runs only from an
//! approved frame ([`crate::pgagent::decode_approved_job`]), after the
//! agent verified both approvals itself against the staff passkeys pinned
//! in its configuration ([`AgentApprovals`], ADR-011 "Two-operator
//! approval"). An agent without pinned approvers refuses every
//! destructive job.
//!
//! The executor connects only to `127.0.0.1` as `fstp_super`, with mutual
//! TLS and SCRAM (ADR-005 D2). Before the startup message it checks that
//! the server certificate's subject OU is exactly the agent's cluster
//! kind (I-83, design section 1.3). It runs each rendered statement
//! through `fstp_pgwire::Client::execute_rendered_ddl`, the one entry
//! point for SQL that is not `&'static str`.
//!
//! [`PgagentJob::WriteHba`] reads the cell databases from the server,
//! renders `pg_hba.conf` with [`crate::pg::render_hba`], replaces the file
//! and reloads the server configuration. It refuses to write a file the
//! server does not read, and fails when a line of the new file does not
//! load.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use fstp_cp_proto::CellId;
use fstp_obs::{LogEvent, Method};
use fstp_pgwire::{Client, ClientTls, Config, Password, ServerCheck};
use fstp_rt::signal::{Signals, TerminationListener};
use fstp_rt::tokio::TokioRuntime;
use fstp_rt::{Runtime, Shutdown, ShutdownSignal};

use crate::ControlError;
use crate::approval::{AgentApprovals, ApprovedJob, DestructiveJob, PinnedApprovers};
use crate::config::{AGENT_FILES, PgagentConfig, decode_pgagent_config, read_credential};
use crate::pg::{CellDatabase, CellSubnet, render_hba};
use crate::pgagent::{
    APPROVED_VERSION, AgentScope, ApprovedFrame, DbIdent, JOB_VERSION, MAX_APPROVED_LEN,
    PgagentJob, Statement, Target, decode_approved_job, decode_pgagent_job, encode_approved_job,
    encode_pgagent_job,
};
use crate::placement::{ClusterKind, PlacementError};

/// The subject CN of the certificate the control-plane CA issues to
/// `fstp-control` for its agent link. Interim, pending Daniel.
pub const CONTROL_PEER_CN: &str = "fstp_control";

/// The environment variable that names the agent's configuration file.
pub const CONFIG_ENV: &str = "FSTP_PGAGENT_CONFIG";

/// The superuser the agent logs in as, over loopback only (ADR-011).
pub const SUPERUSER: &str = "fstp_super";

/// The only host the agent connects to (ADR-011).
pub const LOOPBACK: &str = "127.0.0.1";

/// How long the agent waits for its server to accept a session.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long one rendered statement may run.
pub const STATEMENT_TIMEOUT: Duration = Duration::from_secs(60);

/// How long a drain may take after SIGTERM.
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Outcomes.

/// Why the agent refused a job without running it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobRefusal {
    /// The job frame did not decode.
    Frame,
    /// The job names a database or role of another cluster kind (I-83),
    /// or a job this kind does not run.
    ClusterKind,
    /// A destructive job, which needs two operators (ADR-011).
    ApprovalRequired,
    /// A job this build does not run yet: [`PgagentJob::PrivilegeAudit`],
    /// whose result has no transport to `fstp-control` yet.
    NotBuilt,
}

/// What became of a job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobOutcome {
    /// Every statement ran, or had already taken effect.
    Done,
    /// The agent refused the job.
    Refused(JobRefusal),
    /// A statement or a step failed. The job may run again, since every
    /// job is idempotent.
    Failed,
}

/// The length of an outcome frame: [`JOB_VERSION`] and one code.
pub const OUTCOME_LEN: usize = 2;

const OUTCOME_DONE: u8 = 0;
const OUTCOME_FAILED: u8 = 1;
const OUTCOME_FRAME: u8 = 2;
const OUTCOME_CLUSTER_KIND: u8 = 3;
const OUTCOME_APPROVAL: u8 = 4;
const OUTCOME_NOT_BUILT: u8 = 5;

/// Encodes an outcome.
pub fn encode_job_outcome(o: JobOutcome) -> [u8; OUTCOME_LEN] {
    let code = match o {
        JobOutcome::Done => OUTCOME_DONE,
        JobOutcome::Failed => OUTCOME_FAILED,
        JobOutcome::Refused(JobRefusal::Frame) => OUTCOME_FRAME,
        JobOutcome::Refused(JobRefusal::ClusterKind) => OUTCOME_CLUSTER_KIND,
        JobOutcome::Refused(JobRefusal::ApprovalRequired) => OUTCOME_APPROVAL,
        JobOutcome::Refused(JobRefusal::NotBuilt) => OUTCOME_NOT_BUILT,
    };
    [JOB_VERSION, code]
}

/// Decodes an outcome. Fuzzed (`pgagent_outcome_decode`).
///
/// # Errors
///
/// [`ControlError::Job`] for any frame other than the two octets of one
/// outcome.
pub fn decode_job_outcome(bytes: &[u8]) -> Result<JobOutcome, ControlError> {
    let [JOB_VERSION, code] = bytes else {
        return Err(ControlError::Job("outcome frame"));
    };
    Ok(match *code {
        OUTCOME_DONE => JobOutcome::Done,
        OUTCOME_FAILED => JobOutcome::Failed,
        OUTCOME_FRAME => JobOutcome::Refused(JobRefusal::Frame),
        OUTCOME_CLUSTER_KIND => JobOutcome::Refused(JobRefusal::ClusterKind),
        OUTCOME_APPROVAL => JobOutcome::Refused(JobRefusal::ApprovalRequired),
        OUTCOME_NOT_BUILT => JobOutcome::Refused(JobRefusal::NotBuilt),
        _ => return Err(ControlError::Job("outcome code")),
    })
}

// ---------------------------------------------------------------------------
// The superuser session.

/// The agent's login to its local server: the port, the cluster CA, and
/// the `fstp_super` client certificate, key and password.
#[derive(Clone)]
pub struct PgLogin {
    /// The port on `127.0.0.1`.
    pub port: u16,
    /// The cluster CA (PEM).
    pub server_ca_pem: Vec<u8>,
    /// The `fstp_super` client certificate (PEM).
    pub client_cert_pem: Vec<u8>,
    /// Its private key (PEM).
    pub client_key_pem: Vec<u8>,
    /// The `fstp_super` password.
    pub password: String,
}

impl std::fmt::Debug for PgLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgLogin")
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

/// Everything the agent serves with, read from the configuration and its
/// credential files.
#[derive(Clone)]
pub struct AgentParts {
    /// The kind of the agent's cluster.
    pub cluster_kind: ClusterKind,
    /// The subnet of every `pg_hba` cell line.
    pub cell_subnet: CellSubnet,
    /// The `pg_hba.conf` path.
    pub hba_file: String,
    /// The listener address.
    pub listen: SocketAddr,
    /// The control-plane CA (PEM), the only root for client certificates.
    pub control_ca_pem: Vec<u8>,
    /// The listener certificate chain (PEM).
    pub cert_pem: Vec<u8>,
    /// The listener key (PEM).
    pub key_pem: Vec<u8>,
    /// The login to the local server.
    pub pg: PgLogin,
    /// The approvers of destructive jobs, pinned at installation. `None`
    /// refuses every destructive job.
    pub approvals: Option<PinnedApprovers>,
}

impl std::fmt::Debug for AgentParts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentParts")
            .field("cluster_kind", &self.cluster_kind)
            .field("listen", &self.listen)
            .finish_non_exhaustive()
    }
}

impl AgentParts {
    /// Reads the credential files of `cfg` ([`AGENT_FILES`]).
    ///
    /// # Errors
    ///
    /// [`ControlError::Io`] or [`ControlError::Config`] for a file that
    /// cannot be read, and [`ControlError::Config`] for a password that is
    /// not one line of printable ASCII.
    pub fn load(cfg: &PgagentConfig) -> Result<AgentParts, ControlError> {
        let dir = &cfg.credentials_dir;
        let [ca, cert, key, cluster_ca, su_cert, su_key, su_pw] = AGENT_FILES;
        let pw = read_credential(dir, su_pw)?;
        let pw = std::str::from_utf8(&pw)
            .map_err(|_| ControlError::Config("superuser password"))?
            .trim_end_matches('\n');
        if pw.is_empty() || !pw.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(ControlError::Config("superuser password"));
        }
        Ok(AgentParts {
            cluster_kind: cfg.cluster_kind,
            cell_subnet: cfg.cell_subnet,
            hba_file: cfg.hba_file.clone(),
            listen: cfg.listen,
            control_ca_pem: read_credential(dir, ca)?,
            cert_pem: read_credential(dir, cert)?,
            key_pem: read_credential(dir, key)?,
            pg: PgLogin {
                port: cfg.postgres_port,
                server_ca_pem: read_credential(dir, cluster_ca)?,
                client_cert_pem: read_credential(dir, su_cert)?,
                client_key_pem: read_credential(dir, su_key)?,
                password: pw.to_owned(),
            },
            approvals: cfg.approvals.clone(),
        })
    }

    /// The listener's TLS configuration: the agent certificate, and the
    /// control-plane CA as the only client root (R-NF-09).
    ///
    /// # Errors
    ///
    /// [`ControlError::Tls`] for PEM that does not build.
    pub fn server_tls(&self) -> Result<fstp_tls::ServerConfig, ControlError> {
        fstp_tls::ServerConfig::mutual(&self.cert_pem, &self.key_pem, &self.control_ca_pem)
            .map_err(|_| ControlError::Tls("agent listener"))
    }
}

/// The OU a server certificate of `kind` carries (design section 1.3).
fn kind_ou(kind: ClusterKind) -> &'static str {
    let ou = match kind {
        ClusterKind::Application => fstp_pki::cert::ClusterKindOu::Application,
        ClusterKind::Vault => fstp_pki::cert::ClusterKindOu::Vault,
        ClusterKind::Control => fstp_pki::cert::ClusterKindOu::Control,
        ClusterKind::Witness => fstp_pki::cert::ClusterKindOu::Witness,
    };
    ou.as_str()
}

/// The agent's executor of jobs over its local server.
pub struct Agent<R: Runtime> {
    rt: R,
    scope: AgentScope,
    pg: PgLogin,
    hba_file: String,
    cell_subnet: CellSubnet,
    approvals: Option<Mutex<AgentApprovals>>,
}

impl<R: Runtime> Agent<R> {
    /// The executor for `parts` on `rt`.
    ///
    /// # Errors
    ///
    /// [`ControlError::Job`] for a control cluster, which has no agent,
    /// and [`ControlError::Config`] for pinned approvers that
    /// [`AgentApprovals::new`] refuses.
    pub fn new(rt: R, parts: &AgentParts) -> Result<Agent<R>, ControlError> {
        let approvals = match &parts.approvals {
            Some(p) => Some(Mutex::new(AgentApprovals::new(p)?)),
            None => None,
        };
        Ok(Agent {
            rt,
            scope: AgentScope::new(parts.cluster_kind)?,
            pg: parts.pg.clone(),
            hba_file: parts.hba_file.clone(),
            cell_subnet: parts.cell_subnet,
            approvals,
        })
    }

    /// Runs the destructive job of `frame` at `now` (seconds): the
    /// cluster kind check, then the agent's own check of both approvals
    /// (ADR-011), then the job's statements.
    pub async fn run_approved(&self, frame: &ApprovedFrame, now: i64) -> JobOutcome {
        if self.scope.admits(&frame.job).is_err() {
            return JobOutcome::Refused(JobRefusal::ClusterKind);
        }
        let Some(book) = &self.approvals else {
            return JobOutcome::Refused(JobRefusal::ApprovalRequired);
        };
        let verified = {
            let mut book = book.lock().unwrap_or_else(PoisonError::into_inner);
            book.verify(&frame.job, &frame.approvals, now)
        };
        let statements = match verified.and_then(|v| self.scope.destructive_statements(&v)) {
            Ok(s) => s,
            Err(ControlError::Placement(_)) => return JobOutcome::Refused(JobRefusal::ClusterKind),
            Err(_) => return JobOutcome::Refused(JobRefusal::ApprovalRequired),
        };
        match self.run_rendered(&statements).await {
            Ok(()) => JobOutcome::Done,
            Err(_) => JobOutcome::Failed,
        }
    }

    /// Opens a superuser session to `database` on `127.0.0.1`.
    async fn session(&self, database: &str) -> Result<Client<R>, ControlError> {
        let tls = ClientTls::new(
            &self.pg.server_ca_pem,
            &self.pg.client_cert_pem,
            &self.pg.client_key_pem,
        )
        .map_err(|_| ControlError::Tls("superuser client"))?;
        let password = Password::new(self.pg.password.clone())
            .map_err(|_| ControlError::Database("password"))?;
        let want = kind_ou(self.scope.kind());
        let config = Config::new(LOOPBACK, self.pg.port, SUPERUSER, password, database, tls)
            .map_err(|_| ControlError::Database("configuration"))?
            .connect_timeout(Some(CONNECT_TIMEOUT))
            .statement_timeout(Some(STATEMENT_TIMEOUT))
            .server_check(ServerCheck::new(move |der| {
                matches!(
                    fstp_pgwire::x509::subject_organizational_units(der).as_deref(),
                    Ok([ou]) if *ou == want.as_bytes()
                )
            }));
        Client::connect(&self.rt, &config)
            .await
            .map_err(|_| ControlError::Database("connect"))
    }

    /// Runs `job` on the local server.
    pub async fn run_job(&self, job: &PgagentJob) -> JobOutcome {
        match self.scope.admits(job) {
            Ok(()) => {}
            Err(_) => return JobOutcome::Refused(JobRefusal::ClusterKind),
        }
        if job.is_destructive() {
            return JobOutcome::Refused(JobRefusal::ApprovalRequired);
        }
        let result = match job {
            PgagentJob::PrivilegeAudit => return JobOutcome::Refused(JobRefusal::NotBuilt),
            PgagentJob::WriteHba => self.write_hba().await,
            _ => self.run_statements(job).await,
        };
        match result {
            Ok(()) => JobOutcome::Done,
            Err(ControlError::ApprovalRequired) => {
                JobOutcome::Refused(JobRefusal::ApprovalRequired)
            }
            Err(ControlError::Placement(_)) => JobOutcome::Refused(JobRefusal::ClusterKind),
            Err(_) => JobOutcome::Failed,
        }
    }

    async fn run_statements(&self, job: &PgagentJob) -> Result<(), ControlError> {
        let statements = self.scope.statements(job)?;
        self.run_rendered(&statements).await
    }

    async fn run_rendered(&self, statements: &[Statement]) -> Result<(), ControlError> {
        let mut sessions: BTreeMap<String, Client<R>> = BTreeMap::new();
        let mut result = Ok(());
        for s in statements {
            let db = s.target.database_name();
            if !sessions.contains_key(&db) {
                match self.session(&db).await {
                    Ok(c) => {
                        sessions.insert(db.clone(), c);
                    }
                    Err(e) => {
                        result = Err(e);
                        break;
                    }
                }
            }
            let Some(client) = sessions.get_mut(&db) else {
                result = Err(ControlError::Database("session"));
                break;
            };
            match client.execute_rendered_ddl(&s.sql).await {
                Ok(_) => {}
                Err(e) if s.done_if_duplicate_database && e.code() == Some("42P04") => {}
                Err(_) => {
                    result = Err(ControlError::Database("statement"));
                    break;
                }
            }
        }
        for (_, c) in sessions {
            let _ = c.close().await;
        }
        result
    }

    async fn write_hba(&self) -> Result<(), ControlError> {
        let db = match self.scope.kind() {
            ClusterKind::Application => CellDatabase::App,
            ClusterKind::Vault => CellDatabase::Vault,
            ClusterKind::Control | ClusterKind::Witness => {
                return Err(ControlError::Placement(
                    PlacementError::NotAnApplicationCluster,
                ));
            }
        };
        let mut c = self.session(&Target::Maintenance.database_name()).await?;
        let result = self.write_hba_with(&mut c, db).await;
        let _ = c.close().await;
        result
    }

    async fn write_hba_with(
        &self,
        c: &mut Client<R>,
        db: CellDatabase,
    ) -> Result<(), ControlError> {
        let row = c
            .query_one("SELECT pg_catalog.current_setting('hba_file')", &[])
            .await
            .map_err(|_| ControlError::Database("hba_file setting"))?;
        let served: String = row
            .get(0)
            .map_err(|_| ControlError::Database("hba_file setting"))?;
        if served != self.hba_file {
            return Err(ControlError::Database("hba_file differs from the server's"));
        }
        let rows = c
            .query(
                "SELECT datname::text FROM pg_catalog.pg_database \
                 WHERE datname ~ '^[cv]_[0-9a-f]{32}$' ORDER BY datname",
                &[],
            )
            .await
            .map_err(|_| ControlError::Database("cell databases"))?;
        let mut cells: Vec<(CellId, CellSubnet)> = Vec::new();
        for r in &rows {
            let name: String = r
                .get(0)
                .map_err(|_| ControlError::Database("cell databases"))?;
            let d = DbIdent::parse(&name)?;
            if d.database() == db {
                cells.push((d.cell(), self.cell_subnet));
            }
        }
        let text = render_hba(db, &cells)?;
        replace_file(&self.hba_file, text.as_bytes())?;
        c.query_one("SELECT pg_catalog.pg_reload_conf()", &[])
            .await
            .map_err(|_| ControlError::Database("reload"))?;
        let row = c
            .query_one(
                "SELECT count(*) FROM pg_catalog.pg_hba_file_rules WHERE error IS NOT NULL",
                &[],
            )
            .await
            .map_err(|_| ControlError::Database("hba rules"))?;
        let errors: i64 = row
            .get(0)
            .map_err(|_| ControlError::Database("hba rules"))?;
        if errors != 0 {
            return Err(ControlError::Database("a pg_hba line did not load"));
        }
        Ok(())
    }
}

/// Replaces `path` with `bytes`: a sibling file is written, takes the
/// permissions of the old file, and is renamed over it, so the server
/// never reads half a file.
fn replace_file(path: &str, bytes: &[u8]) -> Result<(), ControlError> {
    let io = |e: std::io::Error| ControlError::Io(e.kind());
    let tmp = format!("{path}.fstp-pgagent");
    std::fs::write(&tmp, bytes).map_err(io)?;
    if let Ok(meta) = std::fs::metadata(path) {
        std::fs::set_permissions(&tmp, meta.permissions()).map_err(io)?;
    }
    std::fs::rename(&tmp, path).map_err(io)
}

/// The route template an agent logs a job under.
fn job_route(job: Option<&PgagentJob>) -> &'static str {
    match job {
        None => "/pgagent/job",
        Some(PgagentJob::HardenCluster) => "/pgagent/job/harden-cluster",
        Some(PgagentJob::CreateCellDatabase(_)) => "/pgagent/job/create-cell-database",
        Some(PgagentJob::CreateRoles(_)) => "/pgagent/job/create-roles",
        Some(PgagentJob::ApplyRevocations(_)) => "/pgagent/job/apply-revocations",
        Some(PgagentJob::SetRoleCredential { .. }) => "/pgagent/job/set-role-credential",
        Some(PgagentJob::ApplyGrants(_)) => "/pgagent/job/apply-grants",
        Some(PgagentJob::PrivilegeAudit) => "/pgagent/job/privilege-audit",
        Some(PgagentJob::WriteHba) => "/pgagent/job/write-hba",
        Some(PgagentJob::SetNoLogin(_)) => "/pgagent/job/set-nologin",
        Some(PgagentJob::DropCellDatabase(_)) => "/pgagent/job/drop-cell-database",
        Some(PgagentJob::DropRoles(_)) => "/pgagent/job/drop-roles",
    }
}

/// Logs one job as a typed event (ADR-011, R-NF-02).
fn log_job(job: Option<&PgagentJob>, outcome: JobOutcome, elapsed: Duration) {
    let route = job_route(job);
    let refused = |rule, status| LogEvent::Refused {
        method: Method::Other,
        route,
        rule,
        status,
    };
    let event = match outcome {
        JobOutcome::Done => LogEvent::Request {
            method: Method::Other,
            route,
            status: 200,
            elapsed,
        },
        JobOutcome::Failed => LogEvent::Request {
            method: Method::Other,
            route,
            status: 500,
            elapsed,
        },
        JobOutcome::Refused(JobRefusal::Frame) => refused("TH-26", 400),
        JobOutcome::Refused(JobRefusal::ClusterKind) => refused("I-83", 409),
        JobOutcome::Refused(JobRefusal::ApprovalRequired) => refused("ADR-011", 403),
        JobOutcome::Refused(JobRefusal::NotBuilt) => refused("ADR-011", 501),
    };
    let _ = fstp_obs::log_to_stderr(&event);
}

/// Answers one exchange: the peer must be `fstp-control`, then the job
/// runs. A peer with another certificate gets no reply.
async fn answer<R: Runtime>(
    agent: Arc<Agent<R>>,
    peer: Vec<u8>,
    request: Vec<u8>,
) -> Option<Vec<u8>> {
    if !crate::exchange::peer_is(&peer, CONTROL_PEER_CN) {
        let _ = fstp_obs::log_to_stderr(&LogEvent::Refused {
            method: Method::Other,
            route: job_route(None),
            rule: "R-NF-09",
            status: 403,
        });
        return None;
    }
    let started = Instant::now();
    let (job, outcome) = match request.first() {
        Some(&APPROVED_VERSION) => match decode_approved_job(&request) {
            Ok(frame) => {
                let outcome = agent.run_approved(&frame, unix_now()).await;
                (Some(frame.job), outcome)
            }
            Err(_) => (None, JobOutcome::Refused(JobRefusal::Frame)),
        },
        _ => match decode_pgagent_job(&request) {
            Ok(job) => {
                let outcome = agent.run_job(&job).await;
                (Some(job), outcome)
            }
            Err(_) => (None, JobOutcome::Refused(JobRefusal::Frame)),
        },
    };
    log_job(job.as_ref(), outcome, started.elapsed());
    Some(encode_job_outcome(outcome).to_vec())
}

/// The time in seconds since the Unix epoch, or 0 before it.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Serves jobs on `listener` until `signal` is triggered (design section
/// 2.3). The caller binds the listener, so a test can bind port 0.
///
/// # Errors
///
/// [`ControlError::Tls`] for a listener configuration that does not
/// build, and [`ControlError::Job`] for a control cluster.
pub async fn serve<R: Runtime>(
    rt: R,
    parts: &AgentParts,
    listener: R::TcpListener,
    signal: ShutdownSignal,
) -> Result<(), ControlError> {
    let tls = parts.server_tls()?;
    let agent = Arc::new(Agent::new(rt.clone(), parts)?);
    crate::exchange::serve(
        rt,
        listener,
        tls,
        MAX_APPROVED_LEN,
        signal,
        move |peer, request| answer(agent.clone(), peer, request),
    )
    .await;
    Ok(())
}

/// Sends `job` to the agent at `addr`, whose certificate carries
/// `server_name`, and returns its outcome. `tls` presents the
/// `fstp-control` certificate and trusts the agent's CA.
///
/// # Errors
///
/// [`ControlError::Job`] for a job that does not encode, and for a reply
/// that is not one outcome, as when the agent refused the peer.
/// [`ControlError::Io`] when the exchange failed.
pub async fn send_job<R: Runtime>(
    rt: &R,
    addr: SocketAddr,
    server_name: &str,
    tls: &fstp_tls::ClientConfig,
    job: &PgagentJob,
) -> Result<JobOutcome, ControlError> {
    let frame = encode_pgagent_job(job)?;
    let reply = crate::exchange::request(rt, addr, server_name, tls, &frame, OUTCOME_LEN)
        .await
        .map_err(|e| ControlError::Io(e.kind()))?;
    decode_job_outcome(&reply)
}

/// The approved frame of `approved`: its agent job and the evidence of
/// both approvals.
///
/// # Errors
///
/// [`ControlError::ApprovalRequired`] when `approved` is not an agent job
/// or lacks the evidence of either approval. The errors of
/// [`encode_approved_job`].
pub fn approved_frame(approved: &ApprovedJob) -> Result<ApprovedFrame, ControlError> {
    let DestructiveJob::Pgagent(agent_job) = approved.job() else {
        return Err(ControlError::ApprovalRequired);
    };
    let evidence = approved.evidence().ok_or(ControlError::ApprovalRequired)?;
    let frame = ApprovedFrame {
        job: agent_job.job().clone(),
        approvals: evidence.clone(),
    };
    encode_approved_job(&frame)?;
    Ok(frame)
}

/// Sends the approved destructive agent job `approved` to the agent at
/// `addr`, with the evidence of both approvals, and returns its outcome.
/// The agent checks the approvals again itself (ADR-011).
///
/// # Errors
///
/// The errors of [`approved_frame`] and of [`send_job`].
pub async fn send_approved_job<R: Runtime>(
    rt: &R,
    addr: SocketAddr,
    server_name: &str,
    tls: &fstp_tls::ClientConfig,
    approved: &ApprovedJob,
) -> Result<JobOutcome, ControlError> {
    let frame = encode_approved_job(&approved_frame(approved)?)?;
    let reply = crate::exchange::request(rt, addr, server_name, tls, &frame, OUTCOME_LEN)
        .await
        .map_err(|e| ControlError::Io(e.kind()))?;
    decode_job_outcome(&reply)
}

/// Serves until a termination signal, then drains (ADR-002, design
/// section 2.3). Logs `Started` once the listener is bound, then
/// `SignalReceived`, `ShuttingDown` and `Drained` or `DrainTimedOut`.
///
/// # Errors
///
/// [`ControlError::Io`] when the listener cannot bind, and the errors of
/// [`serve`].
pub async fn serve_until_terminated<R: Runtime, T: TerminationListener>(
    rt: R,
    parts: &AgentParts,
    mut term: T,
) -> Result<(), ControlError> {
    let listener = rt
        .bind_tcp(parts.listen)
        .await
        .map_err(|e| ControlError::Io(e.kind()))?;
    serve_listener_until_terminated(rt, parts, listener, &mut term).await
}

/// As [`serve_until_terminated`], over a bound listener.
///
/// # Errors
///
/// The errors of [`serve`].
pub async fn serve_listener_until_terminated<R: Runtime, T: TerminationListener>(
    rt: R,
    parts: &AgentParts,
    listener: R::TcpListener,
    term: &mut T,
) -> Result<(), ControlError> {
    // Both are checked before `Started`, so a refused start never logs it.
    parts.server_tls()?;
    AgentScope::new(parts.cluster_kind)?;
    let shutdown = Shutdown::new();
    let parts_owned = parts.clone();
    let serve_rt = rt.clone();
    let signal = shutdown.signal();
    let served = rt.spawn(async move { serve(serve_rt, &parts_owned, listener, signal).await });
    let _ = fstp_obs::log_to_stderr(&LogEvent::Started);
    crate::service::await_termination_and_drain(&rt, &shutdown, term, DRAIN_TIMEOUT).await;
    served
        .await
        .map_err(|_| ControlError::Io(std::io::ErrorKind::Other))?
}

/// Runs the agent named by [`CONFIG_ENV`] until SIGTERM. The binary's one
/// runtime is tokio behind `fstp_rt` (ADR-002).
///
/// # Errors
///
/// [`ControlError::Config`] for a missing or refused configuration,
/// [`ControlError::Io`] for an unreadable file or a listener that does not
/// bind, [`ControlError::Signal`] when SIGTERM cannot be caught, and the
/// errors of [`serve`].
pub fn run() -> Result<(), ControlError> {
    let bytes = crate::config::read_config_file(CONFIG_ENV)?;
    let cfg = decode_pgagent_config(&bytes)?;
    let parts = AgentParts::load(&cfg)?;
    let rt = TokioRuntime::new_multi_thread(2).map_err(|e| ControlError::Io(e.kind()))?;
    let term = rt.listen_termination().map_err(|_| ControlError::Signal)?;
    let rt2 = rt.clone();
    rt.block_on(serve_until_terminated(rt2, &parts, term))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// ADR-011, TH-26: every outcome round-trips, and every other frame is
    /// refused.
    #[test]
    fn adr011_job_outcomes_round_trip() {
        for o in [
            JobOutcome::Done,
            JobOutcome::Failed,
            JobOutcome::Refused(JobRefusal::Frame),
            JobOutcome::Refused(JobRefusal::ClusterKind),
            JobOutcome::Refused(JobRefusal::ApprovalRequired),
            JobOutcome::Refused(JobRefusal::NotBuilt),
        ] {
            assert_eq!(decode_job_outcome(&encode_job_outcome(o)), Ok(o));
        }
        for bad in [&b""[..], b"\x01", b"\x01\x06", b"\x02\x00", b"\x01\x00\x00"] {
            assert!(decode_job_outcome(bad).is_err(), "{bad:?}");
        }
    }

    /// I-83: the OU the agent requires is the cluster kind's.
    #[test]
    fn i83_agent_requires_the_ou_of_its_cluster_kind() {
        assert_eq!(kind_ou(ClusterKind::Application), "application");
        assert_eq!(kind_ou(ClusterKind::Vault), "vault");
        assert_eq!(kind_ou(ClusterKind::Witness), "witness");
    }
}
