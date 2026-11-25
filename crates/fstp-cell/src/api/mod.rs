//! The W6 composition: one `ApiCore` over the cell's engine, route
//! backend and PostgreSQL (ADR-026, decided by Daniel on 2026-11-20; M4
//! design section 1.3; production design gap G2).
//!
//! [`compose`] builds the opaque `ApiCore` from the cell's ports. One
//! module per port group:
//!
//! - `engine`: `AsyncEngine` over [`crate::engine::CellEngine`]. Every
//!   command goes through one of the gate's admissions: the agent
//!   admission for an MCP call, the API step-up admission for a web call
//!   (`fstp_cell_core::gate`). The dry run is the engine's own. The ledger
//!   reads come from the engine's mirror of its committed engine records.
//! - `session`: `Sessions` over the session cookie and `auth.session`,
//!   `StepUp` over the cell's own step-up ceremony, and a fail-closed
//!   `SessionsAdmin`.
//! - `audit`: `AuditSink` and `VaultAudit` as kind 2 events of the App
//!   chain, flushed through the engine's single writer before a call is
//!   answered (ADR-010 amendment of 2026-11-20).
//! - `facts`: the seam of the shell facts the engine port reads (lane L6
//!   plugs in at merge).
//! - `content`: `TextStore` over the cell's erasure task, `Sealer` and
//!   `Workspaces` over `workspace.drafts`, the `PendingActions` port over
//!   `api.pending_actions`, and a fail-closed `BlobStore`.
//! - `tenant`: `TenantConfig`, `Outbox`, `Clock` and `Ids`.
//! - `accounts`: `Accounts`, with the invitation of a programme role and
//!   its mail (ADR-026 record of lane L5).
//! - `mail`: the delivery of a message a port enqueued, through the
//!   cell's `Relay` (I-26).
//! - `closed`: the ports the production cell does not serve yet, each
//!   failing closed: the vault's intake and Q35 queries, `Precheck` and
//!   `BreakGlass`.
//! - `tenant` also holds the `Prober` of onboarding over the ADR-027
//!   probes (ADR-026 record of lane L18).
//!
//! The token store is lane L2's (`crate::oauth::tokens::CellTokens`),
//! through [`CellTokens`]: the `Tokens` port of `ApiCore` and the agent
//! grant the agent admission reads.

mod accounts;
mod admin;
mod audit;
mod closed;
mod content;
mod engine;
pub(crate) mod facts;
pub(crate) mod mail;
mod session;
mod system;
mod tenant;

// The stored text form, which the checks runner opens and writes as the
// text store does (`crate::tasks::checks`, lane m10/checks-runner).
pub(crate) use content::{header as text_header, parse as parse_text};

use std::sync::Arc;

use fstp_api_core::ApiCore;
use fstp_api_core::port::{self, CellPorts};
use fstp_cell_core::gate::AgentGrant;
use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;
use fstp_pgstore::ApiStore;
use fstp_rt::Runtime;

use crate::engine::{CellEngine, VaultClient};
use crate::public::OrganisationPort;
use crate::routes::pg::PgBackend;
use crate::tasks::erasure::ErasureHandle;

/// The token store of the cell, as `ApiCore` and the agent admission
/// reach it (ADR-026). Lane L2's store over the `mcp` schema implements
/// it.
pub(crate) trait CellTokens: port::Tokens + 'static {
    /// The grant behind the agent client `client` of `account` at `now`,
    /// as the gate's agent admission reads it, or `None` when no live
    /// grant exists. The agent admission refuses a command without one.
    fn agent_grant(
        &self,
        account: AccountId,
        client: port::AgentClientId,
        now: Timestamp,
    ) -> impl std::future::Future<Output = Option<AgentGrant>> + Send;
}

/// What the composition takes from the serving cell.
pub(crate) struct ApiParts<R: Runtime, V> {
    /// The cell.
    pub cell: [u8; 16],
    /// The engine handle: the only path into `DriverCore`.
    pub engine: CellEngine,
    /// The route backend over `auth.*`.
    pub backend: Arc<PgBackend<R>>,
    /// The API core's tables over the app role.
    pub store: ApiStore<R>,
    /// The cell's vault client.
    pub vault: V,
    /// The erasure task, which holds the text store.
    pub erasure: ErasureHandle,
    /// The organisation port of ADR-021.
    pub organisation: OrganisationPort,
    /// The cell host, whose origin the links of a message name.
    pub host: String,
    /// The app pool, over which a port writes `ops.delivery`.
    pub app: fstp_pgstore::Pool<R>,
    /// The relay the ports deliver through, if the cell has one (ADR-026
    /// record of lane L5).
    pub relay: Option<mail::SharedRelay>,
    /// The shell facts the engine port decides creator commands and
    /// publications with, and the API core's creator inputs (`facts`).
    /// `None` reads the route backend's facts, as before.
    pub facts: Option<Arc<dyn facts::ShellFacts>>,
    /// The onboarding probes of the `Prober` port (ADR-026 record of lane
    /// L18). `None` fails every probe (Q5).
    pub prober: Option<Arc<dyn crate::shell::probe::TenantProbe>>,
    /// The runtime, for the time limits of the System page's live checks.
    pub rt: R,
    /// The host status file of the System page (ADR-028 record of lane
    /// L20), if the configuration names one.
    pub host_status: Option<std::path::PathBuf>,
    /// The integrity findings the start-up found (ADR-012 record of lane
    /// m10/declared-restore).
    pub findings: Vec<fstp_api_core::system::Finding>,
}

/// The shared state of every port of one cell.
pub(crate) struct Inner<R: Runtime, V> {
    cell: [u8; 16],
    engine: CellEngine,
    backend: Arc<PgBackend<R>>,
    store: ApiStore<R>,
    vault: V,
    erasure: ErasureHandle,
    organisation: OrganisationPort,
    host: String,
    app: fstp_pgstore::Pool<R>,
    relay: Option<mail::SharedRelay>,
    facts: Arc<dyn facts::ShellFacts>,
    audit: audit::Buffer,
    stepups: session::Begun,
    // ADR-028 record of lane L20: the System page.
    rt: R,
    host_status: Option<std::path::PathBuf>,
    probe: Option<Arc<dyn crate::shell::probe::TenantProbe>>,
    // ADR-012 record of lane m10/declared-restore: the System page's
    // integrity findings.
    findings: Vec<fstp_api_core::system::Finding>,
}

impl<R: Runtime, V> Inner<R, V> {
    /// The cell clock.
    fn now(&self) -> Timestamp {
        Timestamp::from_micros(self.engine.now())
    }
}

/// Every port of one cell over `Inner`, with the token store `T`.
pub(crate) struct Ports<R: Runtime, V: VaultClient, T> {
    sessions: session::CellSessions<R, V>,
    step_up: session::CellStepUp<R, V>,
    sessions_admin: admin::CellSessionsAdmin<R, V>,
    accounts: accounts::CellAccounts<R, V>,
    vault: closed::CellVault<R, V>,
    engine: engine::CellAsyncEngine<R, V, T>,
    audit: audit::CellAudit<R, V>,
    vault_audit: audit::CellVaultAudit<R, V>,
    texts: content::CellTexts<R, V>,
    blobs: content::CellBlobs<R, V>,
    sealer: content::CellSealer<R, V>,
    workspaces: content::CellWorkspaces<R, V>,
    pending: content::CellPending<R, V>,
    recovery: admin::CellRecovery<R, V>,
    break_glass: closed::ClosedBreakGlass,
    tenant: tenant::CellTenant<R, V>,
    outbox: tenant::CellOutbox<R, V>,
    prober: tenant::CellTenantProber,
    clock: tenant::CellClock<R, V>,
    ids: tenant::CellIds,
    tokens: Arc<T>,
    /// The anonymous draft store of the route backend (ADR-032).
    anon: Option<Arc<dyn fstp_api_core::anon::AnonymousDrafts>>,
}

/// Builds the cell's `ApiCore` over `parts`, with the token store
/// `tokens` (ADR-026 "Composition"). Only the cell's process calls it.
pub(crate) fn compose<R, V, T>(parts: ApiParts<R, V>, tokens: T) -> ApiCore
where
    R: Runtime,
    V: VaultClient + Clone,
    T: CellTokens,
{
    let ApiParts {
        cell,
        engine,
        backend,
        store,
        vault,
        erasure,
        organisation,
        host,
        app,
        relay,
        facts,
        prober,
        rt,
        host_status,
        findings,
    } = parts;
    let facts = facts.unwrap_or_else(|| Arc::new(facts::BackendFacts(Arc::clone(&backend))));
    let anon = crate::routes::Backend::anonymous_drafts(backend.as_ref());
    let inner = Arc::new(Inner {
        cell,
        audit: audit::Buffer::new(engine.clone()),
        engine,
        backend,
        store,
        vault,
        erasure,
        organisation,
        host,
        app,
        relay,
        facts,
        stepups: session::Begun::default(),
        rt,
        host_status,
        probe: prober.clone(),
        findings,
    });
    let tokens = Arc::new(tokens);
    let ports = Ports {
        sessions: session::CellSessions(Arc::clone(&inner)),
        step_up: session::CellStepUp(Arc::clone(&inner)),
        sessions_admin: admin::CellSessionsAdmin(Arc::clone(&inner)),
        accounts: accounts::CellAccounts(Arc::clone(&inner)),
        vault: closed::CellVault(Arc::clone(&inner)),
        engine: engine::CellAsyncEngine::new(Arc::clone(&inner), Arc::clone(&tokens)),
        audit: audit::CellAudit(Arc::clone(&inner)),
        vault_audit: audit::CellVaultAudit(Arc::clone(&inner)),
        texts: content::CellTexts(Arc::clone(&inner)),
        blobs: content::CellBlobs(Arc::clone(&inner)),
        sealer: content::CellSealer(Arc::clone(&inner)),
        workspaces: content::CellWorkspaces(Arc::clone(&inner)),
        pending: content::CellPending(Arc::clone(&inner)),
        recovery: admin::CellRecovery(Arc::clone(&inner)),
        break_glass: closed::ClosedBreakGlass,
        tenant: tenant::CellTenant(Arc::clone(&inner)),
        outbox: tenant::CellOutbox(Arc::clone(&inner)),
        prober: tenant::CellTenantProber(prober),
        clock: tenant::CellClock(Arc::clone(&inner)),
        ids: tenant::CellIds,
        tokens,
        anon,
    };
    port::api_core(ports)
}

impl<R, V, T> CellPorts for Ports<R, V, T>
where
    R: Runtime,
    V: VaultClient + Clone,
    T: CellTokens,
{
    type Sessions = session::CellSessions<R, V>;
    type StepUp = session::CellStepUp<R, V>;
    type Accounts = accounts::CellAccounts<R, V>;
    type Vault = closed::CellVault<R, V>;
    type Engine = engine::CellAsyncEngine<R, V, T>;
    type Audit = audit::CellAudit<R, V>;
    type Texts = content::CellTexts<R, V>;
    type Blobs = content::CellBlobs<R, V>;
    type Precheck = closed::NoPrecheck;
    type Sealer = content::CellSealer<R, V>;
    type Workspaces = content::CellWorkspaces<R, V>;
    type VaultAudit = audit::CellVaultAudit<R, V>;
    type SessionsAdmin = admin::CellSessionsAdmin<R, V>;
    type Recovery = admin::CellRecovery<R, V>;
    type BreakGlass = closed::ClosedBreakGlass;
    type Tenant = tenant::CellTenant<R, V>;
    type Outbox = tenant::CellOutbox<R, V>;
    type Prober = tenant::CellTenantProber;
    type Clock = tenant::CellClock<R, V>;
    type Ids = tenant::CellIds;
    type Tokens = T;

    fn sessions(&self) -> &Self::Sessions {
        &self.sessions
    }
    fn step_up(&self) -> &Self::StepUp {
        &self.step_up
    }
    fn accounts(&self) -> &Self::Accounts {
        &self.accounts
    }
    fn vault(&self) -> &Self::Vault {
        &self.vault
    }
    fn engine(&self) -> &Self::Engine {
        &self.engine
    }
    fn audit(&self) -> &Self::Audit {
        &self.audit
    }
    fn texts(&self) -> &Self::Texts {
        &self.texts
    }
    fn blobs(&self) -> &Self::Blobs {
        &self.blobs
    }
    /// Q38: a production cell has no pre-check provider.
    fn precheck(&self) -> Option<&Self::Precheck> {
        None
    }
    fn sealer(&self) -> &Self::Sealer {
        &self.sealer
    }
    fn workspaces(&self) -> &Self::Workspaces {
        &self.workspaces
    }
    fn vault_audit(&self) -> &Self::VaultAudit {
        &self.vault_audit
    }
    fn sessions_admin(&self) -> &Self::SessionsAdmin {
        &self.sessions_admin
    }
    fn recovery(&self) -> &Self::Recovery {
        &self.recovery
    }
    fn break_glass(&self) -> &Self::BreakGlass {
        &self.break_glass
    }
    fn tenant(&self) -> &Self::Tenant {
        &self.tenant
    }
    fn outbox(&self) -> &Self::Outbox {
        &self.outbox
    }
    fn prober(&self) -> &Self::Prober {
        &self.prober
    }
    fn clock(&self) -> &Self::Clock {
        &self.clock
    }
    fn ids(&self) -> &Self::Ids {
        &self.ids
    }
    fn tokens(&self) -> &Self::Tokens {
        &self.tokens
    }
    /// ADR-032: the claim reads the draft routes' own store.
    fn anonymous_drafts(&self) -> Option<&dyn fstp_api_core::anon::AnonymousDrafts> {
        self.anon.as_deref()
    }
    /// ADR-026: pending actions live in `api.pending_actions`.
    fn pending_actions(&self) -> Option<&dyn port::PendingActions> {
        Some(&self.pending)
    }
}

/// A session id of the API core as the cell's 16 bytes.
fn session_bytes(s: port::SessionId) -> [u8; 16] {
    s.raw().to_be_bytes()
}

/// The cell's 16-byte session id as the API core's id.
fn session_id(s: [u8; 16]) -> port::SessionId {
    port::SessionId::from_raw(u128::from_be_bytes(s))
}

/// The API core's login method of a cell session method.
fn login_method(m: fstp_auth::Method) -> port::LoginMethod {
    match m {
        fstp_auth::Method::Passkey => port::LoginMethod::Passkey,
        fstp_auth::Method::MagicLink => port::LoginMethod::MagicLink,
        fstp_auth::Method::EudiWallet => port::LoginMethod::EudiWallet,
        fstp_auth::Method::Opaque => port::LoginMethod::Opaque,
    }
}

/// Whether a cell session method is phishing resistant (I-77).
fn phishing_resistant(m: fstp_auth::Method) -> bool {
    matches!(
        m,
        fstp_auth::Method::Passkey | fstp_auth::Method::EudiWallet
    )
}

/// The token store of a serving cell: lane L2's port over its
/// authorisation server. The agent admission takes the account's live
/// grants of the client: the oldest family start and a phishing-resistant
/// consent only if every live grant had one, so a doubt refuses (I-77,
/// I-79, I-85).
impl CellTokens for crate::oauth::tokens::CellTokens {
    async fn agent_grant(
        &self,
        account: AccountId,
        client: port::AgentClientId,
        now: Timestamp,
    ) -> Option<AgentGrant> {
        let grants = self
            .server()
            .read(|s, guard, _| {
                let a = fstp_oauth::Account::from_raw(account.raw());
                s.agents_of(a, now.micros())
                    .into_iter()
                    .filter(|g| u128::from(g.client.raw()) == client.raw())
                    .filter(|g| !guard.refused(a, g.start))
                    .map(|g| (g.start, g.consent_method))
                    .collect::<Vec<_>>()
            })
            .await
            .ok()?;
        let start = grants.iter().map(|(s, _)| *s).min()?;
        let strong = grants.iter().all(|(_, m)| {
            matches!(
                m,
                fstp_oauth::LoginMethod::Passkey | fstp_oauth::LoginMethod::EudiWallet
            )
        });
        Some(AgentGrant {
            account,
            family_started: Timestamp::from_micros(start),
            phishing_resistant: strong,
        })
    }
}
