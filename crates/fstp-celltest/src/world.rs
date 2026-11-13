//! Multi-cell worlds (design section 14.3). Lane W1a.
//!
//! A world runs real PostgreSQL clusters through `fstp-pgtest`, each with
//! its own cluster CA (design section 14.1, "Real topology"). Each cluster
//! is a named server, shared by every test in the test binary that asks
//! for the same name. Its server certificate carries the label of its kind
//! as the subject OU (design section 1.3). Role certificates are minted at
//! test time through [`fstp_pgtest::PgServer::create_login_role`].
//!
//! [`cluster_plan`] names the clusters of a world. A SaaS world in shared
//! mode runs one cluster of each kind, named by [`kind_label`]. In
//! dedicated mode each cell gets an application and a vault cluster of
//! its own. A self-hosted world runs two PostgreSQL instances of its own,
//! as the single-node install of design section 1.4 does, and its witness
//! keeps a file store. So no self-hosted world shares a cluster with a
//! SaaS world in the same test binary.
//!
//! Status after lane int5: a SaaS world with cells prepares each
//! self-operated cluster and provisions each cell as `fstp-control` and
//! `fstp-pgagent` would, from the production role plan, jobs, `pg_hba`
//! renderer and migration sets ([`World::start`], "Provisioning"). It then
//! starts real cells: the witness over its database, the edge on
//! loopback, and per cell its vault and its cell process over their
//! databases, with the first admin's split invitation ([`World::start`],
//! "Cells"). A self-hosted world with cells starts each cell the same way
//! in self-hosted mode, over its two instances, with a local witness of
//! its own over a file store (`fstp_witness::serve_local`, lane F-SELF).
//! B-06 defers `fstp-install`, so the world plays the install: it writes
//! the install files and registers the cell CA with the local witness.
//! The SaaS edge stays the harness's way into the cell.
//!
//! Scope of the self-hosted I-24 claim (ADR-010 open point 7, Daniel,
//! 2026-11-13): a root user on the cell node is outside what the local
//! witness detects. Only the optional external bucket would detect it.

use std::collections::BTreeMap;
use std::fmt;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use fstp_control::pg::{CellDatabase, CellSubnet, HBA_REJECT_LINES, RolePlan, render_hba};
use fstp_control::pgagent::{AgentScope, DbIdent, PgagentJob};
use fstp_control::placement::{Cluster, ClusterId, Placement};
use fstp_cp_proto::{CellId, RoleName};
use fstp_pgtest::RoleLogin;

use crate::NotImplemented;
use crate::egress::EgressLog;
use crate::scan::StoreSet;

pub use fstp_control::placement::ClusterKind;

/// How cells share database clusters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DbMode {
    /// Cells share clusters, one database per cell.
    Shared,
    /// Each cell has its own clusters.
    Dedicated,
}

/// Where the vault databases live.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultLayout {
    /// A vault cluster apart from the application cluster (I-83).
    SeparateCluster,
}

/// What a world holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorldSpec {
    /// The number of cells.
    pub cells: u8,
    /// The database mode.
    pub mode: DbMode,
    /// The vault layout.
    pub vault_layout: VaultLayout,
    /// Whether the cells are self-hosted.
    pub self_hosted: bool,
    /// Whether components run as real processes.
    pub process_mode: bool,
}

/// Why a world or cluster did not start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorldError {
    /// A part the world needs is not built yet. It names the part.
    NotImplemented(NotImplemented),
    /// A cluster failed to start. The message is `fstp-pgtest`'s.
    Cluster {
        /// The cluster's kind.
        kind: ClusterKind,
        /// What failed.
        message: String,
    },
    /// Reading a store failed, so the store set would be incomplete.
    Store(String),
}

impl fmt::Display for WorldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WorldError::NotImplemented(e) => write!(f, "{e} (NotImplemented)"),
            WorldError::Cluster { kind, message } => {
                write!(f, "the {} cluster failed: {message}", kind_label(*kind))
            }
            WorldError::Store(message) => write!(f, "cannot read a store: {message}"),
        }
    }
}

impl std::error::Error for WorldError {}

impl From<NotImplemented> for WorldError {
    fn from(e: NotImplemented) -> Self {
        WorldError::NotImplemented(e)
    }
}

/// One HTTP request to a cell listener, as a browser on the cell origin
/// sends it. The caller sets `Host`, `Origin`, `Cookie` and `Content-Type`
/// itself. The harness adds `Connection: close` and the `Content-Length`
/// of the body only, so a test controls every other byte the cell sees
/// above TLS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpRequest {
    /// The method, such as `POST`.
    pub method: String,
    /// The origin-form target, such as `/auth/passkey/login`.
    pub path: String,
    /// The header fields, in order.
    pub headers: Vec<(String, Vec<u8>)>,
    /// The body.
    pub body: Vec<u8>,
}

impl HttpRequest {
    /// A request with no field and no body.
    #[must_use]
    pub fn new(method: &str, path: &str) -> HttpRequest {
        HttpRequest {
            method: method.to_owned(),
            path: path.to_owned(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// The request with one more header field.
    #[must_use]
    pub fn header(mut self, name: &str, value: impl Into<Vec<u8>>) -> HttpRequest {
        self.headers.push((name.to_owned(), value.into()));
        self
    }

    /// The request with `body`.
    #[must_use]
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> HttpRequest {
        self.body = body.into();
        self
    }
}

/// The reply of a cell listener.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpReply {
    /// The status code.
    pub status: u16,
    /// The header fields, in order.
    pub headers: Vec<(String, Vec<u8>)>,
    /// The body.
    pub body: Vec<u8>,
}

impl HttpReply {
    /// Whether the status is 2xx.
    #[must_use]
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// The value of the first field named `name`, compared without case.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_slice())
    }
}

/// The first tenant admin's invitation of a SaaS cell, drawn by the cell
/// as two random halves (design sections 8.3 and 9.2 step 10, Q35). The
/// control plane relays `first` to the tenant contact, and a second staff
/// member hands `second` to the contract signatory. The world plays both
/// channels, so a test holds both halves.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FirstAdminInvitation {
    /// The half the control plane relays.
    pub first: [u8; 32],
    /// The half a second staff member hands over.
    pub second: [u8; 32],
}

impl fmt::Debug for FirstAdminInvitation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The halves are a credential: a debug line never shows them.
        f.write_str("FirstAdminInvitation(..)")
    }
}

/// Where the listeners of a started cell are reached on this host
/// (design sections 1.5, 2.3 and 9.4, ADR-009). `fstp-devstack` prints
/// them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CellUrls {
    /// The cell origin through the world's edge, `https://<host>/`. The
    /// relying party origin carries no port (I-20,
    /// `fstp_webauthn::RelyingParty`), and the front's `Origin` check and
    /// the client data check compare it byte for byte. So the origin has
    /// no port only when loopback port 443 reaches the edge: the edge
    /// listens there, or a forwarder does. Otherwise the edge's port is in
    /// the URL, and a browser on it is refused every POST with 403.
    pub cell: String,
    /// The vault origin through the same edge, `https://id.<host>/`.
    pub vault: String,
    /// The loopback health listener, `http://127.0.0.1:<port>/healthz`.
    pub health: String,
}

/// What `fstp-devstack e2e` fixes of one world cell
/// ([`World::start_with_dev_cells`]). Local development only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DevCell {
    /// The tenant host. The same host across world starts keeps a
    /// browser's origins, and so its manifest, valid.
    pub host: String,
    /// The instant the cell's clock shows at its start, in UTC
    /// microseconds. A browser drops a cookie whose expiry lies before
    /// its own clock, so a browser stack starts near the wall clock.
    pub clock_start: i64,
}

/// The instant a world cell's clock shows until a test sets it, in UTC
/// microseconds: one microsecond after the Unix epoch, before every
/// model's first instant (`fstp_domain_testkit::r#gen::roster::T0` is one
/// second). So a test may set the clock to any model instant after the
/// cell started, and the cell's own genesis entries never lie after it.
pub const WORLD_CLOCK_START: i64 = 1;

/// The test clock of one world cell (lane F-CYCLE2). It stands still at
/// [`WORLD_CLOCK_START`] until a test sets or advances it. The cell reads
/// it everywhere it reads time: its route backend, its store's commit
/// instant, its first admin invitation and its timeline and erasure tasks
/// (`fstp_cell::process::StartOptions`). Production cells run on the
/// system clock.
///
/// A clock that stands still makes every ledger instant a test's choice,
/// so a cell ledger can equal a reference ledger record for record. The
/// cell refuses a command whose instant lies before its latest recorded
/// instant, so a test moves the clock forward only.
#[derive(Clone, Debug)]
pub struct WorldClock(std::sync::Arc<std::sync::atomic::AtomicI64>);

impl Default for WorldClock {
    fn default() -> WorldClock {
        WorldClock(std::sync::Arc::new(std::sync::atomic::AtomicI64::new(
            WORLD_CLOCK_START,
        )))
    }
}

impl WorldClock {
    /// The current instant, in UTC microseconds.
    pub fn now(&self) -> i64 {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Sets the clock to `at`, in UTC microseconds.
    pub fn set(&self, at: i64) {
        self.0.store(at, std::sync::atomic::Ordering::SeqCst);
    }

    /// Moves the clock forward by `micros`, saturating.
    pub fn advance(&self, micros: i64) {
        let _ = self.0.fetch_update(
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
            |t| Some(t.saturating_add(micros.max(0))),
        );
    }

    /// The clock as the cell reads it.
    fn commit_clock(&self) -> fstp_cell::engine::CommitClock {
        let c = self.clone();
        std::sync::Arc::new(move || c.now())
    }
}

/// The login credentials of a cell's roles, by database and role. The
/// harness mints them at provisioning, as the cell and vault components
/// would at step 6 of design section 9.2: a random password and a client
/// certificate from the cluster CA per role.
pub type CellLogins = BTreeMap<(CellDatabase, RoleName), RoleLogin>;

/// One cell of a world: its id, its tenant host, its role logins, and the
/// transports the harness reaches its listeners through (design section
/// 14.3).
#[derive(Debug)]
pub struct CellHandle {
    index: u8,
    id: [u8; 16],
    host: String,
    logins: CellLogins,
    clock: WorldClock,
    mail: crate::world_mail::WorldMail,
    /// The control-plane signer of recovery operator tickets, whose public
    /// key the cell pins (design section 8.5, lane m3/login-m2http).
    operator: OperatorSigner,
    /// What the last cycle on this cell kept (lane F-CYCLE3).
    cycle: Mutex<Option<crate::cycle::CycleMemory>>,
    runtime: Option<std::sync::Arc<CellRuntime>>,
    /// The cell's backups and stored texts (lane F-ERASE).
    pub(crate) backups: crate::backups::CellBackups,
    /// The cell's `Ticket` key, whose public key the vault pins. The world
    /// holds it for the cell, whose route layer cannot sign a ticket yet
    /// (`crate::cycle::VERIFY_IDENTITY_SEAM`, lane m3/cycle-steps).
    ticket: TicketSigner,
    /// The replies the cell gave to sessions ([`crate::responses`]).
    responses: crate::responses::ResponseLog,
}

/// The refusal of a call on a cell that runs no listener.
const NOT_STARTED: &str = "fstp_celltest::world::CellHandle of a cell that runs no listener";

impl CellHandle {
    /// The login of `role` on the cell's `db` database, as provisioning
    /// minted it. `None` for a role outside that database's plan.
    pub fn role_login(&self, db: CellDatabase, role: RoleName) -> Option<&RoleLogin> {
        self.logins.get(&(db, role))
    }

    /// The cell's test clock ([`WorldClock`]).
    pub fn clock(&self) -> &WorldClock {
        &self.clock
    }

    /// The cell's mail capture ([`crate::world_mail`]).
    pub fn mail(&self) -> &crate::world_mail::WorldMail {
        &self.mail
    }

    /// The synthetic login email of the model account `model` on this
    /// cell (lane m3/login-m2http): the address an invitation names and
    /// the world's mail capture receives.
    pub fn login_email(&self, model: fstp_domain::id::AccountId) -> String {
        login_email_of(&self.host, model)
    }

    /// An operator ticket of recovery case `case` with the staff
    /// approvals `staff_1` and `staff_2`, signed by the world's
    /// control-plane key as `fstp_auth::codec::encode_operator_ticket`
    /// writes it (design section 8.5, ADR-008 "Operator process checks").
    /// Interim: the world stands in for the control plane and its two
    /// staff members, and claims built on it say so.
    ///
    /// # Errors
    ///
    /// Fails when the signature or the encoding fails.
    pub fn operator_ticket(
        &self,
        case: [u8; 16],
        staff_1: [u8; 16],
        staff_2: [u8; 16],
    ) -> Result<Vec<u8>, WorldError> {
        let ticket = fstp_auth::recovery::OperatorTicket {
            case,
            staff_1: fstp_auth::recovery::StaffRef(staff_1),
            staff_2: fstp_auth::recovery::StaffRef(staff_2),
        };
        let signature = self
            .operator
            .0
            .sign_with_context(&ticket.message(), fstp_auth::recovery::TICKET_CONTEXT)
            .map_err(|e| WorldError::Store(format!("the operator ticket signature: {e:?}")))?
            .to_bytes();
        fstp_auth::codec::encode_operator_ticket(&ticket, &signature)
            .map_err(|e| WorldError::Store(format!("the operator ticket: {e:?}")))
    }

    /// The cell's index in its world.
    pub fn index(&self) -> u8 {
        self.index
    }

    /// The random `CellId` of the cell (design section 4.1).
    pub fn id(&self) -> [u8; 16] {
        self.id
    }

    /// The tenant host: the exact relying party id and the cell origin
    /// `https://<host>` (I-20, B11). The vault origin is `id.<host>`
    /// (design section 1.5).
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The name of the cell's application database, `c_<hex>` (design
    /// section 4.1).
    pub fn app_database(&self) -> String {
        database_name(
            fstp_control::pg::CellDatabase::App,
            &fstp_cp_proto::CellId(self.id),
        )
    }

    /// The name of the cell's vault database, `v_<hex>` (design section
    /// 4.1).
    pub fn vault_database(&self) -> String {
        database_name(
            fstp_control::pg::CellDatabase::Vault,
            &fstp_cp_proto::CellId(self.id),
        )
    }

    fn runtime(&self) -> Result<&CellRuntime, WorldError> {
        self.runtime
            .as_deref()
            .ok_or(WorldError::NotImplemented(NotImplemented::new(NOT_STARTED)))
    }

    /// Sends `req` to the cell's tunnel listener, the way a browser
    /// reaches it: through the world's edge, with the cell host as SNI
    /// (design sections 1.4 and 9.4, ADR-009). The harness adds only
    /// `Connection: close`, and the answer is read to its end.
    ///
    /// # Errors
    ///
    /// Fails when the transport fails. A reply of any status is `Ok`.
    pub fn request(&self, req: &HttpRequest) -> Result<HttpReply, WorldError> {
        self.runtime()?.request(&self.host, req)
    }

    /// Where the cell's listeners are reached on this host.
    ///
    /// # Errors
    ///
    /// Fails when the cell runs no listener.
    pub fn urls(&self) -> Result<CellUrls, WorldError> {
        let rt = self.runtime()?;
        let port = rt.services.edge.addr.port();
        let suffix = if rt.port_443_reaches_edge(&self.host) {
            String::new()
        } else {
            format!(":{port}")
        };
        Ok(CellUrls {
            cell: format!("https://{}{suffix}/", self.host),
            vault: format!("https://id.{}{suffix}/", self.host),
            health: format!("http://{}/healthz", rt.health),
        })
    }

    /// Sends `req` to the cell's loopback health listener (design section
    /// 2.3, ADR-009).
    ///
    /// # Errors
    ///
    /// Fails when the transport fails. A reply of any status is `Ok`.
    pub fn health(&self, req: &HttpRequest) -> Result<HttpReply, WorldError> {
        self.runtime()?.health(req)
    }

    /// Sends `req` to the cell's vault origin `id.<host>` the way a
    /// browser reaches it: through the world's edge, with the vault origin
    /// host as SNI (design sections 1.5 and 6.5, lane m3/cycle-steps).
    ///
    /// # Errors
    ///
    /// Fails when the transport fails. A reply of any status is `Ok`.
    pub fn vault_origin_request(&self, req: &HttpRequest) -> Result<HttpReply, WorldError> {
        self.runtime()?.request(&self.vault_host(), req)
    }

    /// The vault origin host `id.<host>` (design section 1.5).
    pub fn vault_host(&self) -> String {
        format!("id.{}", self.host)
    }

    /// The signed ticket of `claims`: the canonical claims body, then the
    /// Ed25519 signature of the cell's `Ticket` key over it, the framing
    /// of `fstp_vault_proto::ticket` (design section 6.5).
    ///
    /// Interim, pending Daniel (lane m3/cycle-steps): the world signs for
    /// the cell. The cell's ticket routes answer 501 before the engine
    /// runs them, since the route layer holds no `Ticket` key
    /// (`crate::cycle::VERIFY_IDENTITY_SEAM`). Claims built on a ticket
    /// signed here say so.
    ///
    /// # Errors
    ///
    /// Fails when the claims have no canonical body or the signature
    /// fails.
    pub fn sign_ticket(
        &self,
        claims: &fstp_vault_proto::TicketClaims,
    ) -> Result<Vec<u8>, WorldError> {
        let mut out = claims
            .canonical()
            .map_err(|e| WorldError::Store(format!("the ticket claims: {e:?}")))?;
        let signature = self
            .ticket
            .0
            .sign(&out)
            .map_err(|e| WorldError::Store(format!("the ticket signature: {e:?}")))?;
        out.extend_from_slice(&signature);
        Ok(out)
    }

    /// The replies the cell gave to sessions of the cycle's auth client
    /// ([`crate::responses`]).
    pub fn responses(&self) -> &crate::responses::ResponseLog {
        &self.responses
    }

    /// The replies to every session of an account that held a Judging or
    /// Drafting role on the cell at any time: an account named by a
    /// `BindingGranted` record of such a role in the cell's ledger
    /// (I-17, design section 14.4).
    ///
    /// # Errors
    ///
    /// Fails when the ledger cannot be read.
    pub fn judging_and_drafting_responses(&self) -> Result<crate::scan::StoreSet, WorldError> {
        use fstp_domain::roles::Group;
        let accounts: std::collections::BTreeSet<fstp_domain::id::AccountId> = self
            .ledger()?
            .iter()
            .filter_map(|e| match &e.record {
                fstp_cell_core::CellRecord::Engine(fstp_engine::Record::Core(
                    fstp_domain::Record::BindingGranted(b),
                )) if matches!(b.role.group(), Group::Judging | Group::Drafting) => Some(b.account),
                _ => None,
            })
            .collect();
        Ok(self.responses.stores_of(&accounts))
    }

    /// The first tenant admin's invitation, as the two staff channels
    /// carried it (design section 8.3). The cell drew it at provisioning
    /// (design section 9.2 step 10).
    ///
    /// # Errors
    ///
    /// Fails when the world did not receive both halves.
    pub fn first_admin_invitation(&self) -> Result<FirstAdminInvitation, WorldError> {
        match lock(&self.runtime()?.running).invitation {
            Invitation::Split(i) => Ok(i),
            Invitation::Whole(_) => Err(WorldError::Store(
                "a self-hosted invitation is one whole token (first_admin_token)".to_owned(),
            )),
        }
    }

    /// The first tenant admin's token as the admin types it: both halves
    /// of a SaaS invitation joined, or the whole token of a self-hosted
    /// install, which `fstp-install` writes to its token file (design
    /// section 8.3, Q35).
    ///
    /// # Errors
    ///
    /// Fails when the cell runs no listener.
    pub fn first_admin_token(&self) -> Result<Vec<u8>, WorldError> {
        Ok(match lock(&self.runtime()?.running).invitation {
            Invitation::Split(i) => [i.first, i.second].concat(),
            Invitation::Whole(t) => t.to_vec(),
        })
    }

    /// Seeds the fact write `w` from `source` into the cell's seeded vault
    /// (design section 6.9, [`crate::seeded_vault`]). The fact becomes
    /// effective after the cell's reaction to its epoch (NOTE 4), which
    /// the cell runs before its next command that asks the vault.
    ///
    /// # Errors
    ///
    /// The vault core's refusal, or a cell that runs no vault.
    pub fn seed(
        &self,
        source: crate::vault_seed::SeedSource,
        w: fstp_vault_core::FactWrite,
    ) -> Result<Vec<fstp_vault_core::VaultEvent>, crate::vault_seed::SeedError> {
        let rt = self.runtime().map_err(|_| {
            crate::vault_seed::SeedError::NotImplemented(NotImplemented::new(NOT_STARTED))
        })?;
        let running = lock(&rt.running);
        rt.services.rt.block_on(running.vault.seed(source, w))
    }

    /// Seeds a synthetic verification of the cell account `account` with
    /// the identity of the synthetic attribute tuple `attributes`
    /// ([`crate::seeded_vault::SeededVault::seed_verification`]).
    ///
    /// # Errors
    ///
    /// As [`CellHandle::seed`].
    pub fn seed_verification(
        &self,
        account: fstp_domain::id::AccountId,
        attributes: &[u8],
    ) -> Result<Vec<fstp_vault_core::VaultEvent>, crate::vault_seed::SeedError> {
        self.seed_identity(account, attributes, None)
    }

    /// Seeds a synthetic verification of `account` with the identity of
    /// `attributes`, whose name canary is `name`, if any. Its match key
    /// comes from the cell's Vault chain keystore, which keeps the tuple
    /// (`crate::vault_keys`, lane m3/erase-steps).
    pub(crate) fn seed_identity(
        &self,
        account: fstp_domain::id::AccountId,
        attributes: &[u8],
        name: Option<crate::canary::Canary>,
    ) -> Result<Vec<fstp_vault_core::VaultEvent>, crate::vault_seed::SeedError> {
        let refused = |e: WorldError| {
            eprintln!("fstp_celltest::world seed_identity: {e}");
            crate::vault_seed::SeedError::NotImplemented(NotImplemented::new(
                "fstp_celltest::vault_keys: the Vault chain keystore refused the match key (the error is on standard error)",
            ))
        };
        let mk = crate::backups::vault_keys(self)
            .and_then(|k| k.match_key(attributes, name))
            .map_err(refused)?;
        let rt = self.runtime().map_err(|_| {
            crate::vault_seed::SeedError::NotImplemented(NotImplemented::new(NOT_STARTED))
        })?;
        let running = lock(&rt.running);
        rt.services
            .rt
            .block_on(running.vault.seed_verification_keyed(account.raw(), mk))
    }

    /// Moves the identities of the cell's seeded vault to new match keys
    /// (`crate::seeded_vault::SeededVault::rekey_identities`).
    pub(crate) fn rekey_identities(
        &self,
        rekey: &BTreeMap<[u8; 32], [u8; 32]>,
    ) -> Result<(), WorldError> {
        let rt = self.runtime()?;
        let running = lock(&rt.running);
        rt.services
            .rt
            .block_on(running.vault.rekey_identities(rekey))
            .map_err(|e| WorldError::Store(format!("the vault rekey: {e}")))
    }

    /// Seeds the synthetic vault fact `fact` from `source` into the cell's
    /// seeded vault ([`crate::seeded_vault::SeededVault::seed_vault_fact`]).
    ///
    /// # Errors
    ///
    /// As [`CellHandle::seed`].
    pub fn seed_vault_fact(
        &self,
        source: crate::vault_seed::SeedSource,
        fact: fstp_vault_core::fact::Fact,
    ) -> Result<Vec<fstp_vault_core::VaultEvent>, crate::vault_seed::SeedError> {
        let rt = self.runtime().map_err(|_| {
            crate::vault_seed::SeedError::NotImplemented(NotImplemented::new(NOT_STARTED))
        })?;
        let running = lock(&rt.running);
        rt.services
            .rt
            .block_on(running.vault.seed_vault_fact(source, fact))
    }

    /// The contract port's EFFECTIVE fact of `contract` on `proposal`,
    /// issued in process (`fstp_cell::process::RunningCell::contract_fact`,
    /// lane F-CYCLE3). It stands for a completed contract signature, which
    /// the cell cannot take over HTTP yet. Claims built on it say so.
    ///
    /// # Errors
    ///
    /// Fails when the cell refused the fact or runs no listener.
    pub fn contract_effective(
        &self,
        proposal: fstp_domain::id::ProposalId,
        contract: fstp_domain::id::ContractId,
    ) -> Result<(), WorldError> {
        let rt = self.runtime()?;
        let running = lock(&rt.running);
        let cell = running
            .cell
            .as_ref()
            .ok_or(WorldError::NotImplemented(NotImplemented::new(NOT_STARTED)))?;
        rt.services
            .rt
            .block_on(cell.contract_fact(
                proposal,
                contract,
                fstp_domain::command::ContractEvent::Effective,
            ))
            .map_err(|e| WorldError::Store(format!("the contract port's fact: {e}")))
    }

    /// One tick of the cell's timeline task at the world clock's instant
    /// (`fstp_cell::tasks::timeline::tick`, lane m3/money-drivers): the
    /// System commands due then, admitted by the gate under the system
    /// task `Timeline`, and the timeline step's plan and firings. The
    /// cell's own timeline task runs the same tick once the clock passes
    /// its next tick. It reads no session rows, so a due
    /// `EndSessionsAtBindingEnd` waits for that task.
    ///
    /// # Errors
    ///
    /// Fails when the cell runs no listener.
    pub fn timeline_tick(&self) -> Result<Vec<fstp_cell::tasks::timeline::TickItem>, WorldError> {
        let rt = self.runtime()?;
        let running = lock(&rt.running);
        let cell = running
            .cell
            .as_ref()
            .ok_or(WorldError::NotImplemented(NotImplemented::new(NOT_STARTED)))?;
        let now = fstp_domain::time::Timestamp::from_micros(self.clock().now());
        Ok(rt.services.rt.block_on(fstp_cell::tasks::timeline::tick(
            cell.engine(),
            &fstp_cell::tasks::timeline::NoSessions,
            now,
        )))
    }

    /// The cell's ledger after decryption, read through the cell's own
    /// store at a quiescent point (design sections 5.3 and 7.2), in
    /// sequence order.
    ///
    /// # Errors
    ///
    /// Fails when the store cannot be read or an entry does not decode.
    pub fn ledger(
        &self,
    ) -> Result<Vec<fstp_ledger::Entry<fstp_cell_core::CellRecord>>, WorldError> {
        let rt = self.runtime()?;
        let running = lock(&rt.running);
        let cell = running
            .cell
            .as_ref()
            .ok_or(WorldError::NotImplemented(NotImplemented::new(NOT_STARTED)))?;
        rt.services
            .rt
            .block_on(cell.ledger())
            .map_err(|e| WorldError::Store(format!("the cell ledger: {e}")))
    }

    /// The cell's erasure task (`fstp_cell::tasks::erasure`).
    /// The cell's custody, which shares its roots with the cell (lane
    /// F-ERASE).
    pub(crate) fn custody(&self) -> Result<WorldCustody, WorldError> {
        Ok(self.runtime()?.custody.clone())
    }

    /// Runs `f` on the cell's runtime to its end (lane F-ERASE).
    pub(crate) fn block_on<T>(
        &self,
        f: impl std::future::Future<Output = T>,
    ) -> Result<T, WorldError> {
        Ok(self.runtime()?.services.rt.block_on(f))
    }

    pub(crate) fn erasure(&self) -> Result<fstp_cell::tasks::erasure::ErasureHandle, WorldError> {
        let rt = self.runtime()?;
        let running = lock(&rt.running);
        running
            .cell
            .as_ref()
            .map(|c| c.erasure().clone())
            .ok_or(WorldError::NotImplemented(NotImplemented::new(NOT_STARTED)))
    }

    /// Stores `text` as text `id` of the cell's text store, in a fresh
    /// group of its own, through the cell's erasure task (design section
    /// 5.6, lane F-ISO). It runs in process: no route takes text bytes
    /// yet, and claims built on it say so. The ledger's `PutText` is the
    /// caller's, over HTTP.
    ///
    /// # Errors
    ///
    /// Fails when the task refuses the group or the text.
    pub fn store_text(&self, id: [u8; 16], text: &[u8]) -> Result<(), WorldError> {
        let erasure = self.erasure()?;
        let rt = self.runtime()?;
        let group = fstp_crypto::random_array::<16>()
            .map_err(|e| WorldError::Store(format!("a text group id: {e}")))?;
        rt.services
            .rt
            .block_on(async {
                erasure.add_group(group).await?;
                erasure.put_text(group, id, text.to_vec()).await
            })
            .map_err(|e| WorldError::Store(format!("the text store: {e}")))
    }

    /// Waits up to `deadline` until the cell's erasure task has completed
    /// the erasure of text `id` (design section 3.5, steps 1 to 7). The
    /// task runs a batch once something wakes it, and its tick follows
    /// the world clock, which only a test moves. So each poll wakes it
    /// with a keystore read, which it serves between two steps.
    ///
    /// # Errors
    ///
    /// Fails when the erasure did not complete in time.
    pub fn await_erased(&self, id: [u8; 16], deadline: Duration) -> Result<(), WorldError> {
        let erasure = self.erasure()?;
        let rt = self.runtime()?;
        let start = Instant::now();
        loop {
            if erasure.erased().contains(&id) {
                return Ok(());
            }
            if start.elapsed() > deadline {
                return Err(WorldError::Store(format!(
                    "the erasure of a text did not complete in {deadline:?} (events {:?})",
                    erasure.events()
                )));
            }
            rt.services.rt.block_on(async {
                let _ = erasure.keystore().await;
                fstp_rt::Runtime::sleep(&rt.services.rt, Duration::from_millis(50)).await;
            });
        }
    }
}

impl Drop for CellHandle {
    fn drop(&mut self) {
        if let Some(rt) = self.runtime.take() {
            rt.stop(&self.id);
        }
    }
}

/// A scripted call cycle.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CycleScript {
    /// The steps, by name.
    pub steps: Vec<String>,
}

/// The result of a cycle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CycleReport {
    /// Whether the cycle completed, or why not.
    pub result: Result<(), NotImplemented>,
}

/// A running world: clusters, cells, control plane, edge, witness, custody
/// simulator and recorders.
#[derive(Debug)]
pub struct World {
    spec: WorldSpec,
    cells: Vec<CellHandle>,
    clusters: Vec<ClusterHandle>,
    egress: EgressLog,
    /// The install slot of a self-hosted world, which names its two
    /// instances ([`install_cluster_plan`]). Dropped after the cells.
    #[allow(dead_code, reason = "held for its Drop, which frees the slot")]
    install: Option<InstallSlot>,
    /// In process mode, the processes that run the cells, their vaults
    /// and their custody ([`crate::world_host`], lane
    /// m3/custody-decisions). The world then holds no cell of its own.
    host: Option<crate::world_host::WorldHost>,
}

impl World {
    /// Starts a world with the clusters [`cluster_plan`] names.
    ///
    /// # Smoke test
    ///
    /// Design section 14.3, I-82 and I-83: a one-cell SaaS world in shared
    /// mode runs a real cell. Its handle is cell 0. Its databases follow the
    /// grammar `^[cv]_[0-9a-f]{32}$` of design section 4.1: `c_<cell>` on
    /// the application cluster and `v_<cell>` on the vault cluster. An empty
    /// cycle runs on it.
    ///
    /// ```
    /// use fstp_celltest::world::{
    ///     ClusterKind, CycleScript, DbMode, VaultLayout, World, WorldSpec,
    /// };
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let world = World::start(WorldSpec {
    ///     cells: 1,
    ///     mode: DbMode::Shared,
    ///     vault_layout: VaultLayout::SeparateCluster,
    ///     self_hosted: false,
    ///     process_mode: false,
    /// })?;
    /// assert_eq!(world.cell(0).map(|c| c.index()), Some(0));
    /// assert!(world.cell(1).is_none());
    ///
    /// let cell_db = |name: &str, prefix: &str| {
    ///     name.strip_prefix(prefix).is_some_and(|hex| {
    ///         hex.len() == 32 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    ///     })
    /// };
    /// let dbs = world.databases()?;
    /// let on = |kind: ClusterKind, prefix: &str| {
    ///     dbs.iter().filter(|d| d.kind == kind && cell_db(&d.name, prefix)).count()
    /// };
    /// assert_eq!((on(ClusterKind::Application, "c_"), on(ClusterKind::Vault, "v_")), (1, 1));
    ///
    /// world.run_cycle(0, &CycleScript::default()).result?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Provisioning
    ///
    /// A world provisions each cell through the production role plan,
    /// `fstp_control::pg::cell_role_plan` (I-82), the jobs of
    /// `fstp_control::provision` and the `pg_hba` renderer
    /// `fstp_control::pg::render_hba`, never through roles or grants of
    /// its own. Each job renders its SQL through
    /// `fstp_control::pgagent::AgentScope::statements` for the kind of its
    /// cluster (I-83), and runs as the cluster's superuser, as
    /// `fstp-pgagent` would.
    ///
    /// First each self-operated cluster of the world (every kind but
    /// `Control`, Q3 C) is prepared, once per cluster and process:
    ///
    /// 1. `HardenCluster`. It may repeat, so a cluster that other worlds
    ///    share takes it once.
    /// 2. The cluster install's replication role `fstp_repl`, with LOGIN
    ///    and REPLICATION only and a client certificate from the cluster
    ///    CA (design section 4.1, G22, Q4). It gets no CONNECT on any
    ///    database. [`ClusterHandle::replication_login`] holds its login.
    /// 3. The cluster's `pg_hba.conf` as `render_hba` gives it for the
    ///    cells on the cluster ([`install_hba`]).
    ///
    /// Then on each cell cluster, in the order of design section 9.2:
    ///
    /// 4. The plan's login roles of the database. The harness plays the
    ///    cell components of step 6: each role gets a random password and
    ///    a client certificate from the cluster CA. The cell's handle
    ///    keeps them ([`CellHandle::role_login`]). Then the database with
    ///    CONNECT for each role of the plan, and the cluster's
    ///    `pg_hba.conf` rendered again with the new cell.
    /// 5. `CreateCellDatabase`, which finds the database done,
    ///    `CreateRoles` and `ApplyRevocations`.
    /// 6. The database's migration set as its migrator:
    ///    `fstp_pgstore::MIGRATIONS` or `fstp_vault::MIGRATIONS`.
    /// 7. The `fstp_meta.placement` row as the migrator, then
    ///    `ApplyGrants`, which calls `fstp_meta.apply_grant` once per grant
    ///    row of the plan.
    ///
    /// Before the first cell starts, the control and witness clusters get
    /// one database per service migration set of their kind, with its
    /// migrator role (design section 4.4). A cell needs the `cp` and
    /// `witness` sets, so a missing one refuses with [`NotImplemented`].
    /// Today the `witness` set (lane W2g) has no migration files. The
    /// `licence` set (lane W2j) is provisioned once it exists, since no
    /// world part runs the licence service yet.
    ///
    /// Provisioning holds a lock per cluster for the process. Concurrent
    /// grants on one catalogue row fail in PostgreSQL, and `CREATE
    /// DATABASE` refuses while another session uses `template1`.
    ///
    /// A start that fails leaves the cells it provisioned in place, so a
    /// test can read how far provisioning got. The next world start with
    /// cells drops them first: their databases, their roles and their
    /// `pg_hba` lines ([`prepare_cluster`]). Cells of failed starts thus
    /// never pile up on the shared clusters, and a world that starts
    /// sees none of them.
    ///
    /// Readings of lane W3b:
    ///
    /// - The migration sets run through `psql` with `SET ROLE` to the
    ///   migrator, as the `fstp-control` provisioning tests run them, so
    ///   the sets leave no `fstp_migrate` ledger. No cell or vault start
    ///   reads one.
    /// - The roles get LOGIN at creation, through `fstp-pgtest`. The
    ///   `SetRoleCredential` job is not played, since no SCRAM verifier
    ///   helper exists, so `CreateRoles` takes its branch for an existing
    ///   role.
    /// - The cluster ids are random per cluster and process. No
    ///   `cp.cluster`, `cp.cell` or `cp.job` row is written, since no
    ///   production code writes them yet.
    /// - Of the service roles of design section 4.1, only
    ///   `witness_service` is created, with INSERT and SELECT on the
    ///   witness records and SELECT only on the registry of cell CAs and
    ///   anchor keys, which provisioning writes as the migrator. No world
    ///   part runs the control plane, so `cp_service` is not.
    /// - Every grant comes from the plan through `ApplyGrants`, the
    ///   placement marker that the I-83 start checks read included. No
    ///   grant follows outside the plan.
    ///
    /// # Cells
    ///
    /// Both cell databases provision completely, steps 4 to 7, with
    /// their placement rows and grant rows (lane int4). The `cp` and
    /// `witness` service databases follow. Then each cell starts
    /// ([`start_cell`], lane int5), with the production parts only:
    /// `fstp_witness::serve` over the witness database and
    /// `fstp_vault::service::serve` over `v_<cell>`, then
    /// `fstp_cell::process::start` over `c_<cell>`, which runs
    /// `fstp_cell::engine::startup::start_pg`. The world holds the test
    /// PKI, the custody roots and the edge, as design section 14.3 lists
    /// them, and reaches every cell through the edge with the cell host as
    /// SNI ([`CellHandle::request`]). The witness and the edge serve every
    /// world of the process. A cell stops when its handle drops.
    ///
    /// # Errors
    ///
    /// [`WorldError::NotImplemented`] naming the first missing production
    /// part of a world with cells. [`WorldError::Cluster`] for a cluster
    /// that does not start or a job, migration or grant that fails on it.
    pub fn start(spec: WorldSpec) -> Result<World, WorldError> {
        World::start_with_pages(spec, None)
    }

    /// [`World::start`] whose cells serve the compiled auth pages `pages`
    /// on their origin (design section 11.2, [`auth_pages`]), so a browser
    /// can log in there. `fstp-devstack` starts its world this way. Each
    /// started cell's front is then `fstp_cell::http::Front::with_pages`
    /// over these pages ([`start_cell`]).
    ///
    /// # Errors
    ///
    /// As [`World::start`].
    pub fn start_with_pages(
        spec: WorldSpec,
        pages: Option<fstp_cell::http::pages::Pages>,
    ) -> Result<World, WorldError> {
        World::start_with_dev_cells(spec, pages, &[])
    }

    /// [`World::start_with_pages`] with the host and the clock start of
    /// each cell fixed by `dev`, cell `i` by `dev[i]`. A cell past the end
    /// of `dev` gets a host from its id and the clock of [`WorldClock`].
    /// `fstp-devstack e2e` starts its world this way, so a browser keeps
    /// its origins when the stack starts the world again ([`DevCell`]).
    ///
    /// # Errors
    ///
    /// As [`World::start`].
    pub fn start_with_dev_cells(
        spec: WorldSpec,
        pages: Option<fstp_cell::http::pages::Pages>,
        dev: &[DevCell],
    ) -> Result<World, WorldError> {
        if spec.process_mode {
            if pages.is_some() || !dev.is_empty() {
                return Err(WorldError::NotImplemented(NotImplemented::new(
                    "fstp_celltest::world::World in process mode serves no auth pages and fixes no dev cells",
                )));
            }
            return Ok(World {
                spec,
                cells: Vec::new(),
                clusters: Vec::new(),
                egress: EgressLog::new(),
                install: None,
                host: Some(crate::world_host::WorldHost::start(&spec)?),
            });
        }
        World::start_in_process(spec, pages, dev, &[])
    }

    /// The world of a `fstp-world-host` process ([`crate::world_host`]):
    /// [`World::start`] in this process, with the custody of cell `i` on
    /// the socket `custody[i]`. The spec must not ask for process mode.
    ///
    /// # Errors
    ///
    /// As [`World::start`], and a refusal of a spec in process mode or a
    /// socket count other than the cell count.
    pub fn start_hosted(
        spec: WorldSpec,
        custody: &[std::path::PathBuf],
    ) -> Result<World, WorldError> {
        if spec.process_mode || custody.len() != usize::from(spec.cells) {
            return Err(WorldError::Store(
                "a hosted world runs in this process, with one custody socket per cell".to_owned(),
            ));
        }
        World::start_in_process(spec, None, &[], custody)
    }

    fn start_in_process(
        spec: WorldSpec,
        pages: Option<fstp_cell::http::pages::Pages>,
        dev: &[DevCell],
        custody: &[std::path::PathBuf],
    ) -> Result<World, WorldError> {
        // One world start at a time in the process (lead decision,
        // 2026-11-13, lane F-ERASE): worlds that start in parallel race
        // on the shared clusters. Only the start is serialised. A world
        // that started runs beside the others.
        let _turn = lock(start_lock());
        let mut plans = Vec::with_capacity(usize::from(spec.cells));
        for _ in 0..spec.cells {
            plans.push(cell_plan()?);
        }
        let install = spec.self_hosted.then(InstallSlot::take);
        let clusters = install_cluster_plan(&spec, install.as_ref())
            .iter()
            .map(|(kind, name)| ClusterHandle::start_named(*kind, name))
            .collect::<Result<Vec<_>, _>>()?;
        let mut cells = Vec::with_capacity(plans.len());
        let egress = EgressLog::new();
        if !plans.is_empty() {
            for cluster in clusters.iter().filter(|c| is_agent_kind(c.kind())) {
                prepare_cluster(cluster)?;
            }
            match start_cells(
                &spec,
                &clusters,
                &plans,
                pages.as_ref(),
                &egress,
                dev,
                custody,
            ) {
                Ok(started) => {
                    crate::backups::attach(&started, &clusters)?;
                    cells = started;
                }
                Err(e) => {
                    remember_failed(&spec, &clusters, &plans);
                    return Err(e);
                }
            }
        }
        Ok(World {
            spec,
            cells,
            clusters,
            egress,
            install,
            host: None,
        })
    }

    /// The spec the world started from.
    pub fn spec(&self) -> WorldSpec {
        self.spec
    }

    /// The cell at index `i`.
    pub fn cell(&self, i: u8) -> Option<&CellHandle> {
        self.cells.get(usize::from(i))
    }

    /// Runs a call cycle on one cell. An empty script runs on any cell of
    /// the world. Each step drives the cell's HTTP routes with software
    /// passkeys ([`crate::cycle`], lanes F-CYCLE1 and F-CYCLE2). The first
    /// step that the cell cannot run over HTTP yet ends the cycle with its
    /// seam.
    ///
    /// A second script on the same cell continues the first one's cycle:
    /// its passkeys, sessions, programme and call (lane F-CYCLE3).
    pub fn run_cycle(&self, cell: u8, script: &CycleScript) -> CycleReport {
        if let Some(host) = &self.host {
            if usize::from(cell) >= host.cells() {
                return CycleReport {
                    result: Err(NotImplemented::new(
                        "fstp_celltest::world::World::run_cycle on a cell the world does not hold",
                    )),
                };
            }
            return CycleReport {
                result: host.run_cycle(cell, script, &self.egress),
            };
        }
        let result = match self.cell(cell) {
            None => Err(NotImplemented::new(
                "fstp_celltest::world::World::run_cycle on a cell the world does not hold",
            )),
            Some(_) if script.steps.is_empty() => Ok(()),
            Some(handle) => {
                // A cycle continues from what the last script on this cell
                // kept (lane F-CYCLE3).
                let memory = lock(&handle.cycle).take();
                let mut cycle = match memory {
                    Some(m) => crate::cycle::Cycle::resume(handle, m),
                    None => crate::cycle::Cycle::new(handle),
                };
                let result = cycle.run(&script.steps);
                *lock(&handle.cycle) = Some(cycle.into_memory());
                result
            }
        };
        CycleReport { result }
    }

    /// Every database, object directory, log and metrics sink: each
    /// cluster's stores as [`cluster_stores`] gives them, the file store of
    /// each self-hosted local witness (`selfhosted_witness_<cell>/...`),
    /// each egress connection per direction (`egress/...`), and the
    /// edge's route table and connection log (`edge/routes`, `edge/log`).
    ///
    /// The set holds every write committed before the call, since each
    /// cluster runs a CHECKPOINT first. The clusters are shared by the
    /// test binary, so the set also holds what other tests wrote to them.
    ///
    /// # Errors
    ///
    /// Fails when a CHECKPOINT or a dump fails, or a file or directory
    /// cannot be read. A scan then never runs over stale or missing data.
    pub fn stores(&self) -> Result<StoreSet, WorldError> {
        if self.host.is_some() {
            return Err(WorldError::NotImplemented(NotImplemented::new(
                PROCESS_MODE_STORES,
            )));
        }
        let mut set = StoreSet::default();
        for cluster in &self.clusters {
            for (name, bytes) in cluster_stores(cluster.name(), cluster.server())?.stores {
                set.push(name, bytes);
            }
        }
        for c in &self.cells {
            let Some(local) = c.runtime.as_ref().and_then(|r| r.witness.local.as_ref()) else {
                continue;
            };
            let label = format!(
                "selfhosted_witness_{}",
                cell_label(&c.id).get(..12).unwrap_or("")
            );
            for (name, bytes) in read_tree(&local.dir.join(WITNESS_STORE_DIR))? {
                set.push(format!("{label}/{name}"), bytes);
            }
        }
        for (name, bytes) in self.egress.store_set().stores {
            set.push(name, bytes);
        }
        // What left the running system: the sealed backup objects (lane
        // F-ERASE).
        for (name, bytes) in self.backup_objects()? {
            set.push(format!("objects/{name}"), bytes);
        }
        // The edge's stores (lane F-ISO): its route table and its
        // connection log. The edge serves every world of the process, so
        // they hold other worlds' routes and connections too.
        if let Ok(s) = self.services() {
            set.push(
                "edge/routes",
                format!("{:#?}", *lock(&s.edge.table)).into_bytes(),
            );
            set.push("edge/log", lock(&s.edge.log).clone());
        }
        Ok(set)
    }

    /// Every database of every cluster, with what attributes a store to
    /// it ([`WorldDatabase::owns`]).
    ///
    /// # Errors
    ///
    /// Fails when a cluster cannot list its databases.
    pub fn databases(&self) -> Result<Vec<WorldDatabase>, WorldError> {
        if self.host.is_some() {
            return Err(WorldError::NotImplemented(NotImplemented::new(
                PROCESS_MODE_STORES,
            )));
        }
        let mut out = Vec::new();
        for cluster in &self.clusters {
            for (oid, name) in list_databases(cluster.name(), cluster.server())? {
                out.push(WorldDatabase {
                    cluster: cluster.name().to_owned(),
                    kind: cluster.kind(),
                    name,
                    oid,
                });
            }
        }
        Ok(out)
    }

    /// The plaintext captures above TLS on every outbound client.
    pub fn egress(&self) -> &EgressLog {
        &self.egress
    }

    /// One needle per custody root that any cell of the world created,
    /// destroyed roots included (I-80, design section 14.4, lane
    /// F-ERASE). The roots are the world custody's synthetic bytes, held
    /// in the test process only. A label names the cell and the order of
    /// creation, never the bytes. In process mode the roots live in each
    /// cell's custody process, which reports them to the test process
    /// only ([`crate::world_host`]).
    pub fn root_needles(&self) -> Vec<crate::scan::Needle> {
        if let Some(host) = &self.host {
            // A report that cannot be read gives no needle, which the
            // I-80 scans refuse as vacuous.
            return host.root_needles().unwrap_or_default();
        }
        let mut out = Vec::new();
        for c in &self.cells {
            let Some(rt) = c.runtime.as_ref() else {
                continue;
            };
            for (n, root) in lock(&rt.custody.made).iter().enumerate() {
                out.push(crate::scan::Needle {
                    label: format!("cell {} root {n}", c.index),
                    bytes: root.to_vec(),
                });
            }
        }
        out
    }

    /// In process mode, one needle per epoch seal key `S(e)` that a cell's
    /// custody process wrapped under a root of one of `chains`: only those
    /// whose root was destroyed when `destroyed_only` holds (I-80, ADR-004
    /// part 2, lane m3/custody-decisions). Custody sees every `S(e)` when
    /// it wraps it, so the test knows each one without asking the cell.
    ///
    /// # Errors
    ///
    /// Refuses a world that is not in process mode, whose custody runs in
    /// this process, and fails when a report cannot be read.
    pub fn epoch_seal_needles(
        &self,
        chains: &[fstp_custody::Chain],
        destroyed_only: bool,
    ) -> Result<Vec<crate::scan::Needle>, WorldError> {
        match &self.host {
            Some(host) => host.seal_needles(chains, destroyed_only),
            None => Err(WorldError::NotImplemented(NotImplemented::new(
                "fstp_celltest::world::World::epoch_seal_needles: only a world in process mode reports the seal keys its custody wrapped",
            ))),
        }
    }

    /// In process mode, the id of the process that runs `component` of
    /// cell `cell`: the `fstp-world-host` process for the cell and its
    /// vault ([`crate::world_host`], interim, pending Daniel). `None` for
    /// any other component, a cell the world does not hold, or a world
    /// whose cells run in this process.
    pub fn process_id(&self, cell: u8, component: crate::egress::Component) -> Option<u32> {
        let host = self.host.as_ref()?;
        let held = usize::from(cell) < host.cells();
        match component {
            crate::egress::Component::Cell | crate::egress::Component::Vault if held => {
                Some(host.pid())
            }
            _ => None,
        }
    }

    /// In process mode, the id of cell `cell`'s custody process.
    pub fn custody_process_id(&self, cell: u8) -> Option<u32> {
        self.host
            .as_ref()?
            .custody(cell)
            .map(crate::world_host::SimProcess::pid)
    }

    /// Every PostgreSQL cluster of the world, of every kind.
    pub fn clusters(&self) -> &[ClusterHandle] {
        &self.clusters
    }

    /// The world's first cluster of `kind`, if it has one.
    pub fn cluster(&self, kind: ClusterKind) -> Option<&ClusterHandle> {
        self.clusters.iter().find(|c| c.kind == kind)
    }

    /// The services of the world, once a cell started. A world without
    /// cells starts none.
    fn services(&self) -> Result<&'static Services, WorldError> {
        self.cells
            .iter()
            .find_map(|c| c.runtime.as_ref().map(|r| r.services))
            .ok_or(WorldError::NotImplemented(NotImplemented::new(
                WITNESS_SEAM,
            )))
    }

    /// The witness the world's cells anchor at: the SaaS witness, or the
    /// local witness of a self-hosted install.
    fn witness(&self) -> Result<&WorldWitness, WorldError> {
        self.cells
            .iter()
            .find_map(|c| c.runtime.as_ref().map(|r| &r.witness))
            .ok_or(WorldError::NotImplemented(NotImplemented::new(
                WITNESS_SEAM,
            )))
    }

    /// The files a self-hosted install writes outside its database
    /// clusters (design section 9.5): its configuration, and its
    /// credentials. B-06 defers `fstp-install`, so the world plays it
    /// and writes these files into the install directory of each cell
    /// ([`start_cell`]). Each file is read back from that directory.
    ///
    /// # Errors
    ///
    /// Fails for a SaaS world, and when a file cannot be read.
    pub fn install_files(&self) -> Result<InstallFiles, WorldError> {
        if !self.spec.self_hosted {
            return Err(WorldError::Store(
                "a SaaS world writes no install files".to_owned(),
            ));
        }
        let mut out = InstallFiles::default();
        for c in &self.cells {
            let Some(local) = c.runtime.as_ref().and_then(|r| r.witness.local.as_ref()) else {
                continue;
            };
            for (set, sub) in [
                (&mut out.config, INSTALL_CONFIG_DIR),
                (&mut out.credentials, INSTALL_CREDENTIALS_DIR),
            ] {
                for (name, bytes) in read_tree(&local.dir.join(sub))? {
                    set.push(format!("install/{sub}/{name}"), bytes);
                }
            }
        }
        Ok(out)
    }

    /// The witness's receipt public keys, encoded, as each cell of the
    /// world pins them (ADR-010 "Keys", I-90). A test checks every stored
    /// receipt under this set.
    ///
    /// # Errors
    ///
    /// Fails when the world runs no witness.
    pub fn witness_keys(&self) -> Result<Vec<Vec<u8>>, WorldError> {
        Ok(vec![self.witness()?.handle.receipt_public_key()])
    }

    /// Where the world's witness is reached on this host. It speaks the
    /// framed protocol of `fstp_witness::wire` over mutual TLS, so the
    /// URL names its scheme `https` for the TLS only.
    ///
    /// # Errors
    ///
    /// Fails when the world runs no witness.
    pub fn witness_url(&self) -> Result<String, WorldError> {
        Ok(format!("https://{}/", self.witness()?.handle.local_addr()))
    }

    /// The certificate of the CA that signs the world's public host
    /// certificates, PEM. A browser that trusts it reaches the cell and
    /// vault origins without a certificate warning (design section 9.2
    /// step 5, where a public CA signs them).
    ///
    /// # Errors
    ///
    /// Fails when the world runs no cell.
    pub fn origin_ca_pem(&self) -> Result<Vec<u8>, WorldError> {
        Ok(self.services()?.origin.pem.clone())
    }

    /// The SHA-256 digest of the SubjectPublicKeyInfo of the origin CA
    /// ([`World::origin_ca_pem`]). The cells of
    /// [`World::start_with_dev_cells`] serve the CA in their origin
    /// chains, so Chromium's `--ignore-certificate-errors-spki-list`
    /// with this digest reaches them, and keeps it across world starts.
    ///
    /// # Errors
    ///
    /// Fails when the world runs no cell.
    pub fn origin_ca_spki_digest(&self) -> Result<[u8; 32], WorldError> {
        Ok(self.services()?.origin.spki_digest)
    }

    /// Where the world's edge listens on loopback.
    ///
    /// # Errors
    ///
    /// Fails when the world runs no cell.
    pub fn edge_addr(&self) -> Result<SocketAddr, WorldError> {
        Ok(self.services()?.edge.addr)
    }
}

/// A world ends with its handle: each cell stops (its listeners, its
/// engine and its vault drain, [`CellHandle`]), and its databases, roles
/// and `pg_hba` lines go at the next world start, as those of a failed
/// start do. So the shared clusters hold the cells of live worlds only.
impl Drop for World {
    fn drop(&mut self) {
        let ids: Vec<CellId> = self.cells.iter().map(|c| CellId(c.id)).collect();
        self.cells.clear();
        retire(&self.spec, &self.clusters, &ids);
    }
}

/// The refusal of a store read in process mode: the stores belong to the
/// host process, and an empty set would pass any scan.
const PROCESS_MODE_STORES: &str = "fstp_celltest::world::World in process mode: the stores and databases belong to the fstp-world-host process, which does not report them";

/// The refusal of a world part that only a world with a started cell
/// runs: the witness and the edge start with the first cell.
const WITNESS_SEAM: &str = "fstp_celltest::world::World witness: the witness and the edge start with the first cell of the process";

/// A fresh cell id and its production role plan (I-82).
fn cell_plan() -> Result<RolePlan, WorldError> {
    let mut id = [0u8; 16];
    fstp_crypto::random_bytes(&mut id)
        .map_err(|_| WorldError::Store("no random cell id".to_owned()))?;
    fstp_control::pg::cell_role_plan(fstp_cp_proto::CellId(id))
        .map_err(|e| WorldError::Store(format!("the cell role plan refused: {e}")))
}

/// The name of a cell database, `c_<hex>` or `v_<hex>` (design section 4.1).
fn database_name(db: CellDatabase, cell: &fstp_cp_proto::CellId) -> String {
    fstp_control::pg::database_name(db, *cell)
}

/// The cluster of `kind` that holds cell `index`: the shared one, or the
/// cell's own in dedicated mode.
fn cell_cluster<'a>(
    spec: &WorldSpec,
    clusters: &'a [ClusterHandle],
    kind: ClusterKind,
    index: u8,
) -> Result<&'a ClusterHandle, WorldError> {
    let dedicated = format!("{}_{index}", kind_label(kind));
    clusters
        .iter()
        .find(|c| {
            c.kind() == kind
                && (spec.self_hosted || spec.mode == DbMode::Shared || c.name() == dedicated)
        })
        .ok_or_else(|| {
            WorldError::Store(format!("no {} cluster for cell {index}", kind_label(kind)))
        })
}

/// What the harness keeps of one cluster for the life of the process.
/// The clusters are named servers that every world of a test binary
/// shares, so this state is shared too. Its lock serialises provisioning
/// on the cluster ([`World::start`], "Provisioning").
struct ClusterState {
    /// The cluster's registered id, drawn at random once.
    id: ClusterId,
    /// Whether `HardenCluster` ran on it.
    hardened: bool,
    /// The login of the replication role [`REPLICATION_ROLE`], once it
    /// exists.
    replication: Option<RoleLogin>,
    /// The cells whose database exists on the cluster, in creation order.
    /// The cluster's `pg_hba.conf` holds their lines ([`install_hba`]).
    cells: Vec<CellId>,
    /// The cells of failed world starts, which the next start drops.
    failed: Vec<CellId>,
    /// The outcome of the service databases, once they were tried. A
    /// failure stays, so no later world runs over half a database.
    services: Option<Result<(), WorldError>>,
    /// The login of the service role of the cluster's service database:
    /// `witness_service` on the witness cluster (design section 4.1).
    service: Option<RoleLogin>,
}

/// The state of the cluster `name`, created on first use.
fn cluster_state(name: &str) -> Result<&'static Mutex<ClusterState>, WorldError> {
    type States = Mutex<BTreeMap<String, &'static Mutex<ClusterState>>>;
    static STATES: OnceLock<States> = OnceLock::new();
    let mut states = lock(STATES.get_or_init(States::default));
    if let Some(state) = states.get(name) {
        return Ok(state);
    }
    let mut id = [0u8; 16];
    fstp_crypto::random_bytes(&mut id)
        .map_err(|_| WorldError::Store("no random cluster id".to_owned()))?;
    let state: &'static Mutex<ClusterState> = Box::leak(Box::new(Mutex::new(ClusterState {
        id: ClusterId(id),
        hardened: false,
        replication: None,
        cells: Vec::new(),
        failed: Vec::new(),
        services: None,
        service: None,
    })));
    states.insert(name.to_owned(), state);
    Ok(state)
}

/// The registered id of cluster `name` (lane F-ERASE): the owner of its
/// ClusterBackup containers (ADR-012).
pub(crate) fn cluster_id(name: &str) -> Result<[u8; 16], WorldError> {
    Ok(lock(cluster_state(name)?).id.0)
}

/// The login of the replication role of cluster `name`, once it exists
/// (lane F-ERASE).
pub(crate) fn replication_of(name: &str) -> Result<Option<RoleLogin>, WorldError> {
    Ok(lock(cluster_state(name)?).replication.clone())
}

/// The process-wide turn of [`World::start_with_pages`]: one world start
/// at a time (lead decision, 2026-11-13).
fn start_lock() -> &'static Mutex<()> {
    static START: Mutex<()> = Mutex::new(());
    &START
}

/// Locks `m`. The harness holds no invariant that a panic could break
/// halfway, so a poisoned lock is taken as it is.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The SQLSTATE of a duplicate database (42P04), which `psql` prints with
/// verbose errors.
const DUPLICATE_DATABASE: &str = "42P04";

/// The error of a step on `cluster`.
fn step_failed(cluster: &ClusterHandle, what: &str, e: &dyn fmt::Display) -> WorldError {
    WorldError::Cluster {
        kind: cluster.kind(),
        message: format!("{}: {what}: {e}", cluster.name()),
    }
}

/// Runs `sql` in `dbname` on `cluster` as its superuser, with verbose
/// errors, so a refusal names its SQLSTATE.
fn superuser_sql(
    cluster: &ClusterHandle,
    dbname: &str,
    sql: &str,
) -> Result<String, fstp_pgtest::Error> {
    cluster
        .server()
        .psql(dbname, &format!("\\set VERBOSITY verbose\n{sql}"))
}

/// Runs `job` on `cluster` as `fstp-pgagent` would: its statements come
/// only from `AgentScope::statements` for the cluster's kind (ADR-011,
/// I-83), and each runs as the superuser in its target database. A
/// `CREATE DATABASE` whose database exists already is done.
fn run_job(cluster: &ClusterHandle, job: &PgagentJob) -> Result<(), WorldError> {
    let what = format!("the job {job:?}");
    let scope = AgentScope::new(cluster.kind()).map_err(|e| step_failed(cluster, &what, &e))?;
    let statements = scope
        .statements(job)
        .map_err(|e| step_failed(cluster, &what, &e))?;
    for s in statements {
        match superuser_sql(cluster, &s.target.database_name(), &s.sql) {
            Ok(_) => {}
            Err(e)
                if s.done_if_duplicate_database && e.to_string().contains(DUPLICATE_DATABASE) => {}
            Err(e) => return Err(step_failed(cluster, &what, &e)),
        }
    }
    Ok(())
}

/// Runs `sql` in `dbname` as the role `role`, through `SET ROLE` in a
/// superuser session. Privilege checks then apply to that role alone, and
/// every object the script creates belongs to it.
fn sql_as(cluster: &ClusterHandle, dbname: &str, role: &str, sql: &str) -> Result<(), WorldError> {
    superuser_sql(cluster, dbname, &format!("SET ROLE \"{role}\";\n{sql}"))
        .map(drop)
        .map_err(|e| step_failed(cluster, &format!("{dbname} as {role}"), &e))
}

/// The migration set of a cell database (design section 4.6).
fn migrations_of(db: CellDatabase) -> &'static [fstp_migrate::Migration] {
    match db {
        CellDatabase::App => fstp_pgstore::MIGRATIONS,
        CellDatabase::Vault => fstp_vault::MIGRATIONS,
    }
}

/// The `fstp_meta.placement.kind` of a cell database: 1 application, 2
/// vault (design section 4.1).
fn placement_kind(db: CellDatabase) -> u8 {
    match db {
        CellDatabase::App => 1,
        CellDatabase::Vault => 2,
    }
}

/// Whether the migrated database `dbname` defines the placement table
/// and the grant function that step 7 uses. Both migration sets define
/// them (`fstp_pgstore::MIGRATIONS` and `fstp_vault::MIGRATIONS`, design
/// section 4.6), so a database without them failed its migrations.
fn has_meta(cluster: &ClusterHandle, dbname: &str) -> Result<bool, WorldError> {
    let have = superuser_sql(
        cluster,
        dbname,
        "SELECT to_regclass('fstp_meta.placement') IS NOT NULL \
         AND to_regprocedure('fstp_meta.apply_grant(text, text, text)') IS NOT NULL",
    )
    .map_err(|e| step_failed(cluster, "the fstp_meta check", &e))?;
    Ok(have == "t")
}

/// The cluster install's replication role (design section 4.1, G22, Q4).
/// `fstp_control::pg::HBA_REPLICATION_LINE` names it.
pub const REPLICATION_ROLE: &str = "fstp_repl";

/// Whether `fstp-pgagent` manages clusters of `kind`: every self-operated
/// kind. The control-plane clusters are provider-managed (Q3 C).
pub(crate) fn is_agent_kind(kind: ClusterKind) -> bool {
    kind != ClusterKind::Control
}

/// The cell database a cluster of `kind` holds, if any.
fn cell_database_of(kind: ClusterKind) -> Option<CellDatabase> {
    match kind {
        ClusterKind::Application => Some(CellDatabase::App),
        ClusterKind::Vault => Some(CellDatabase::Vault),
        ClusterKind::Control | ClusterKind::Witness => None,
    }
}

/// Steps 1 to 3 of [`World::start`] on the self-operated cluster
/// `cluster`, after the cells of failed starts are dropped from it.
fn prepare_cluster(cluster: &ClusterHandle) -> Result<(), WorldError> {
    let mut state = lock(cluster_state(cluster.name())?);
    while let Some(cell) = state.failed.first().copied() {
        drop_cell(cluster, cell)?;
        state.failed.retain(|c| *c != cell);
        state.cells.retain(|c| *c != cell);
    }
    if !state.hardened {
        run_job(cluster, &PgagentJob::HardenCluster)?;
        state.hardened = true;
    }
    if state.replication.is_none() {
        let login = cluster
            .server()
            .create_replication_role(REPLICATION_ROLE)
            .map_err(|e| step_failed(cluster, "the replication role", &e))?;
        state.replication = Some(login);
    }
    install_hba(cluster, &state)
}

/// Drops what a failed start provisioned for `cell` on `cluster`: the
/// cell's database, then the roles of its plan for that database. Each
/// statement tolerates a part that was never created. The names come
/// from the production plan and grammar (ADR-011).
fn drop_cell(cluster: &ClusterHandle, cell: CellId) -> Result<(), WorldError> {
    let Some(db) = cell_database_of(cluster.kind()) else {
        return Ok(());
    };
    let what = "the drop of a failed start's cell";
    superuser_sql(
        cluster,
        "postgres",
        &format!(
            "DROP DATABASE IF EXISTS {} WITH (FORCE)",
            DbIdent::new(db, cell).render()
        ),
    )
    .map_err(|e| step_failed(cluster, what, &e))?;
    let plan =
        fstp_control::pg::cell_role_plan(cell).map_err(|e| step_failed(cluster, what, &e))?;
    for r in plan.roles.iter().filter(|r| r.database == db) {
        let name = fstp_control::pg::role_name(db, cell, r.role)
            .map_err(|e| step_failed(cluster, what, &e))?;
        superuser_sql(
            cluster,
            "postgres",
            &format!("DROP ROLE IF EXISTS \"{name}\""),
        )
        .map_err(|e| step_failed(cluster, what, &e))?;
    }
    Ok(())
}

/// Marks every cell of `plans` as failed on its clusters, so the next
/// world start drops what this one provisioned ([`prepare_cluster`]).
fn remember_failed(spec: &WorldSpec, clusters: &[ClusterHandle], plans: &[RolePlan]) {
    let cells: Vec<CellId> = plans.iter().map(|p| p.cell).collect();
    retire(spec, clusters, &cells);
}

/// Marks each cell of `cells`, at its index, as done on its clusters, so
/// the next world start drops its databases, roles and `pg_hba` lines
/// ([`prepare_cluster`]).
fn retire(spec: &WorldSpec, clusters: &[ClusterHandle], cells: &[CellId]) {
    for (i, cell) in cells.iter().enumerate() {
        let Ok(index) = u8::try_from(i) else {
            continue;
        };
        for kind in [ClusterKind::Application, ClusterKind::Vault] {
            let Ok(cluster) = cell_cluster(spec, clusters, kind, index) else {
                continue;
            };
            let Ok(state) = cluster_state(cluster.name()) else {
                continue;
            };
            let mut state = lock(state);
            if !state.failed.contains(cell) {
                state.failed.push(*cell);
            }
        }
    }
}

/// The address the harness's cell components connect from. Every
/// `fstp-pgtest` server listens on loopback only.
fn harness_subnet() -> Result<CellSubnet, fstp_control::ControlError> {
    CellSubnet::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 32)
}

/// How long a `pg_hba.conf` reload may take.
const HBA_RELOAD_WAIT: Duration = Duration::from_secs(20);

/// Installs the `pg_hba.conf` of `cluster` that the production renderer
/// `fstp_control::pg::render_hba` gives for the cells in `state`, from
/// [`harness_subnet`], and waits until the server has reloaded it (I-82,
/// design sections 4.1 and 9.2 step 4).
///
/// `fstp-pgtest` writes its own file whenever it adds a database or a
/// replication role, so this runs after each such call. An accepting line
/// of the current file that the render lacks and that names no cell
/// database stays, before the reject lines. Such a line belongs to a test
/// or service database that `fstp-pgtest` added, such as a witness
/// service database. Every cell line comes from the render alone, so the
/// lines of a dropped cell go.
///
/// Reading of lane W3b: `fstp-pgtest` has no call that installs a given
/// file, so the harness writes it and reloads the server itself. A later
/// `fstp-pgtest` write in another test can put its own form back until
/// the next world start. It keeps every accepting line.
fn install_hba(cluster: &ClusterHandle, state: &ClusterState) -> Result<(), WorldError> {
    let what = "the production pg_hba.conf";
    let fail = |e: &dyn fmt::Display| step_failed(cluster, what, e);
    let subnet = harness_subnet().map_err(|e| fail(&e))?;
    let cells: Vec<(CellId, CellSubnet)> = state.cells.iter().map(|c| (*c, subnet)).collect();
    // A cluster without cell databases renders the machinery and reject
    // lines only, whichever database kind is named.
    let db = cell_database_of(cluster.kind()).unwrap_or(CellDatabase::App);
    let rendered = render_hba(db, &cells).map_err(|e| fail(&e))?;
    let path = cluster.server().dir().join("data").join("pg_hba.conf");
    let current = std::fs::read_to_string(&path).map_err(|e| fail(&e))?;
    let text = with_foreign_lines(&rendered, &current);
    if text == current {
        return Ok(());
    }
    let server = cluster.server();
    let before = server
        .psql("postgres", "SELECT pg_conf_load_time()")
        .map_err(|e| fail(&e))?;
    std::fs::write(&path, &text).map_err(|e| fail(&e))?;
    let errors = server
        .psql(
            "postgres",
            "SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL",
        )
        .map_err(|e| fail(&e))?;
    if errors != "0" {
        return Err(fail(&format!("{errors} lines do not load")));
    }
    server
        .psql("postgres", "SELECT pg_reload_conf()")
        .map_err(|e| fail(&e))?;
    // Each psql run is a new backend, forked after the postmaster finished
    // any reload it had started, so a new load time means the new lines
    // are in force.
    let start = Instant::now();
    loop {
        let now = server
            .psql("postgres", "SELECT pg_conf_load_time()")
            .map_err(|e| fail(&e))?;
        if now != before {
            return Ok(());
        }
        if start.elapsed() >= HBA_RELOAD_WAIT {
            return Err(fail(&"the server did not reload pg_hba.conf"));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// `rendered` with each accepting line of `current` that it lacks and
/// that names no cell database (`^[cv]_[0-9a-f]{32}$`), in order and
/// once, before the first reject line ([`install_hba`]).
fn with_foreign_lines(rendered: &str, current: &str) -> String {
    let mut foreign: Vec<&str> = Vec::new();
    for line in current.lines().map(str::trim_end) {
        let names_cell = line
            .split_whitespace()
            .nth(1)
            .is_some_and(|db| DbIdent::parse(db).is_ok());
        if line.starts_with("hostssl ")
            && !names_cell
            && !rendered.lines().any(|r| r == line)
            && !foreign.contains(&line)
        {
            foreign.push(line);
        }
    }
    let mut out = String::with_capacity(rendered.len());
    let mut placed = false;
    for line in rendered.lines() {
        if !placed && HBA_REJECT_LINES.contains(&line) {
            for f in &foreign {
                out.push_str(f);
                out.push('\n');
            }
            placed = true;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// What a world cell serves on its origin and what `fstp-devstack e2e`
/// fixes of it ([`start_cell`]).
#[derive(Clone, Copy)]
struct CellServe<'a> {
    /// The compiled auth pages, if any.
    pages: Option<&'a fstp_cell::http::pages::Pages>,
    /// The fixed host and clock start, if any.
    dev: Option<&'a DevCell>,
    /// In a hosted world, the socket of the cell's custody process.
    custody: Option<&'a std::path::Path>,
}

/// Provisions every cell of `plans`, then the service databases, then
/// starts each cell over its databases ([`World::start`]).
fn start_cells(
    spec: &WorldSpec,
    clusters: &[ClusterHandle],
    plans: &[RolePlan],
    pages: Option<&fstp_cell::http::pages::Pages>,
    egress: &EgressLog,
    dev: &[DevCell],
    custody: &[std::path::PathBuf],
) -> Result<Vec<CellHandle>, WorldError> {
    let index = |i: usize| {
        u8::try_from(i).map_err(|_| WorldError::Store("a world holds at most 255 cells".to_owned()))
    };
    let mut logins = Vec::with_capacity(plans.len());
    for (i, plan) in plans.iter().enumerate() {
        logins.push(provision_cell(spec, clusters, index(i)?, plan)?);
    }
    provision_services(clusters)?;
    let mut cells = Vec::with_capacity(plans.len());
    for (i, (plan, logins)) in plans.iter().zip(logins).enumerate() {
        cells.push(start_cell(
            spec,
            clusters,
            index(i)?,
            plan,
            logins,
            CellServe {
                pages,
                dev: dev.get(i),
                custody: custody.get(i).map(std::path::PathBuf::as_path),
            },
            egress,
        )?);
    }
    Ok(cells)
}

/// Provisions the cell of `plan` on its clusters, as [`World::start`]
/// describes under "Provisioning", steps 4 to 7. The application database
/// comes first. It returns the logins of the cell's roles.
fn provision_cell(
    spec: &WorldSpec,
    clusters: &[ClusterHandle],
    index: u8,
    plan: &RolePlan,
) -> Result<CellLogins, WorldError> {
    let app = cell_cluster(spec, clusters, ClusterKind::Application, index)?;
    let vault = cell_cluster(spec, clusters, ClusterKind::Vault, index)?;
    let registered = |c: &ClusterHandle| -> Result<Cluster, WorldError> {
        Ok(Cluster {
            id: lock(cluster_state(c.name())?).id,
            kind: c.kind(),
        })
    };
    let placement = Placement::new(&registered(app)?, &registered(vault)?)
        .map_err(|e| WorldError::Store(format!("the placement of cell {index} refused: {e:?}")))?;
    let jobs = fstp_control::provision::database_jobs(plan.cell, &placement);
    let grants = fstp_control::provision::grant_jobs(plan.cell, &placement);
    let mut logins = CellLogins::new();
    for (cluster, db) in [(app, CellDatabase::App), (vault, CellDatabase::Vault)] {
        let mut state = lock(cluster_state(cluster.name())?);
        let id = state.id;
        let dbname = database_name(db, &plan.cell);
        let role = |r: RoleName| {
            fstp_control::pg::role_name(db, plan.cell, r)
                .map_err(|e| step_failed(cluster, "the role name", &e))
        };
        // Step 6 of design section 9.2, played by the harness: each
        // role's own credential.
        for r in plan.roles.iter().filter(|r| r.database == db) {
            let name = role(r.role)?;
            let login = cluster
                .server()
                .create_login_role(&name)
                .map_err(|e| step_failed(cluster, "the role credential", &e))?;
            logins.insert((db, r.role), login);
        }
        let connect = plan
            .hba
            .iter()
            .filter(|h| h.database == db)
            .map(|h| role(h.role))
            .collect::<Result<Vec<_>, _>>()?;
        let connect: Vec<&str> = connect.iter().map(String::as_str).collect();
        cluster
            .server()
            .create_database_for(&dbname, &connect)
            .map_err(|e| step_failed(cluster, "the database and its CONNECT grants", &e))?;
        if !state.cells.contains(&plan.cell) {
            state.cells.push(plan.cell);
        }
        install_hba(cluster, &state)?;
        for (_, job) in jobs
            .iter()
            .filter(|(c, j)| *c == id && *j != PgagentJob::HardenCluster)
        {
            run_job(cluster, job)?;
        }
        let migrator = role(RoleName::Migrator)?;
        for m in migrations_of(db) {
            sql_as(cluster, &dbname, &migrator, m.sql)?;
        }
        if !has_meta(cluster, &dbname)? {
            return Err(step_failed(
                cluster,
                &dbname,
                &"the migrations defined no fstp_meta.placement or fstp_meta.apply_grant",
            ));
        }
        let marker = placement_kind(db);
        sql_as(
            cluster,
            &dbname,
            &migrator,
            &format!(
                "INSERT INTO fstp_meta.placement (cell_id, cluster_id, kind) \
                 VALUES ('\\x{}'::bytea, '\\x{}'::bytea, {marker});",
                crate::canary::lower_hex(&plan.cell.0),
                crate::canary::lower_hex(&id.0)
            ),
        )?;
        for (_, job) in grants.iter().filter(|(c, _)| *c == id) {
            run_job(cluster, job)?;
        }
    }
    Ok(logins)
}

/// The refusal for a service migration set that a cell needs and that has
/// no migration directory yet, or `None` for a set no world part needs.
fn missing_service_seam(set: &str) -> Option<&'static str> {
    match set {
        "cp" => Some(
            "fstp_celltest::world::World::start with cells: the control-plane migration set crates/fstp-control/migrations/cp has no directory, so the world has no cp database (design section 4.4)",
        ),
        "witness" => Some(
            "fstp_celltest::world::World::start with cells: the witness migration set crates/fstp-witness/migrations/witness has no directory, so the world has no witness database (lane W2g)",
        ),
        _ => None,
    }
}

/// The service databases of a world's control and witness clusters
/// (design sections 4.1 and 4.4), once per cluster and process: one
/// database per migration set of the cluster's kind, named as the set,
/// owned by the superuser, with the set's migrator role `<set>_migrator`
/// holding CONNECT and CREATE. The set runs as that migrator. A set that
/// a cell needs and that has no migration directory refuses
/// ([`missing_service_seam`]). The `pg_hba.conf` of a self-operated
/// cluster is the production render again afterwards ([`install_hba`]).
fn provision_services(clusters: &[ClusterHandle]) -> Result<(), WorldError> {
    use crate::mc::place_model::db;
    for cluster in clusters
        .iter()
        .filter(|c| matches!(c.kind(), ClusterKind::Control | ClusterKind::Witness))
    {
        let mut state = lock(cluster_state(cluster.name())?);
        let outcome = match &state.services {
            Some(done) => done.clone(),
            None => {
                let sets: Vec<db::MigrationSet> = db::migration_sets()
                    .into_iter()
                    .filter(|s| s.kind == cluster.kind())
                    .collect();
                let mut outcome = Ok(());
                for set in &sets {
                    if let Err(e) = provision_service(cluster, set, &mut state) {
                        outcome = Err(e);
                        break;
                    }
                }
                if outcome.is_ok() && is_agent_kind(cluster.kind()) {
                    outcome = install_hba(cluster, &state);
                }
                state.services = Some(outcome.clone());
                outcome
            }
        };
        outcome?;
    }
    Ok(())
}

/// One service database of [`provision_services`].
fn provision_service(
    cluster: &ClusterHandle,
    set: &crate::mc::place_model::db::MigrationSet,
    state: &mut ClusterState,
) -> Result<(), WorldError> {
    use crate::mc::place_model::db;
    let dir = db::workspace_root()
        .join("crates")
        .join(set.krate)
        .join("migrations")
        .join(set.set);
    if !dir.is_dir() {
        return match missing_service_seam(set.set) {
            Some(seam) => Err(WorldError::NotImplemented(NotImplemented::new(seam))),
            None => Ok(()),
        };
    }
    let files = db::migration_files(set).map_err(|e| step_failed(cluster, set.set, &e))?;
    let migrator = format!("{}_migrator", set.set);
    cluster
        .server()
        .create_login_role(&migrator)
        .map_err(|e| step_failed(cluster, "the service migrator", &e))?;
    // The witness service connects as its own role (design section 4.1),
    // which holds CONNECT on the witness database only.
    let service = (set.set == WITNESS_SET)
        .then(|| {
            cluster
                .server()
                .create_login_role(WITNESS_SERVICE_ROLE)
                .map_err(|e| step_failed(cluster, "the witness service role", &e))
        })
        .transpose()?;
    let mut connect = vec![migrator.as_str()];
    if service.is_some() {
        connect.push(WITNESS_SERVICE_ROLE);
    }
    cluster
        .server()
        .create_database_for(set.set, &connect)
        .map_err(|e| step_failed(cluster, "the service database", &e))?;
    superuser_sql(
        cluster,
        "postgres",
        &format!("GRANT CREATE ON DATABASE \"{}\" TO \"{migrator}\"", set.set),
    )
    .map_err(|e| step_failed(cluster, "the service migrator's CREATE", &e))?;
    for file in files {
        let sql = std::fs::read_to_string(&file)
            .map_err(|e| step_failed(cluster, &file.display().to_string(), &e))?;
        sql_as(cluster, set.set, &migrator, &sql)?;
    }
    if let Some(login) = service {
        // Step 7 of design section 9.2 for the witness database: its
        // placement row, then the service role's rights. witness_service
        // holds INSERT and SELECT on the witness records only (design
        // section 4.1), and the tables refuse UPDATE and DELETE for every
        // role. It reads the registry of cell CAs and anchor keys but
        // cannot write it: provisioning registers a cell as the migrator
        // (`fstp_witness::store::registration_sql`).
        sql_as(
            cluster,
            set.set,
            &migrator,
            &format!(
                "INSERT INTO fstp_meta.placement (cluster_id, kind) VALUES ('\\x{}'::bytea, 4);\n\
                 GRANT USAGE ON SCHEMA fstp_meta, witness TO {WITNESS_SERVICE_ROLE};\n\
                 GRANT SELECT ON fstp_meta.placement TO {WITNESS_SERVICE_ROLE};\n\
                 GRANT SELECT, INSERT ON witness.anchor, witness.receipt, witness.withdrawal \
                 TO {WITNESS_SERVICE_ROLE};\n\
                 GRANT SELECT ON witness.cell_ca, witness.anchor_key TO {WITNESS_SERVICE_ROLE};",
                crate::canary::lower_hex(&state.id.0)
            ),
        )?;
        state.service = Some(login);
    }
    Ok(())
}

/// The witness service migration set.
const WITNESS_SET: &str = "witness";

/// The witness service role of design section 4.1.
pub const WITNESS_SERVICE_ROLE: &str = "witness_service";

// ---------------------------------------------------------------------------
// The running parts of a world: the PKI, custody, the witness, the edge,
// and each cell with its vault (lane int5).

/// The test PKI of a world: ECDSA P-256 CAs from `fstp_crypto::sig`,
/// certificates written by `fstp-pki` (design section 1.3).
mod pki {
    use std::net::IpAddr;

    use fstp_pki::cert::{
        CertKind, CertSpec, DistinguishedName, SignatureAlgorithm, Validity, assemble,
        key_identifier, tbs,
    };
    use fstp_pki::pem::{PemLabel, encode};

    use super::WorldError;

    /// How far in the past every certificate starts.
    const BACKDATE: i64 = 300;
    /// The lifetime of a CA: 30 days.
    const CA_LIFETIME: i64 = 2_592_000;
    /// The lifetime of a leaf: the 7 days of `fstp_pki::CLIENT_MAX_LIFETIME`.
    const LEAF_LIFETIME: i64 = 604_800;

    fn err(what: &str, e: &dyn std::fmt::Display) -> WorldError {
        WorldError::Store(format!("the world PKI: {what}: {e}"))
    }

    fn now() -> Result<i64, WorldError> {
        let d = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| err("the clock", &e))?;
        i64::try_from(d.as_secs()).map_err(|e| err("the clock", &e))
    }

    fn serial() -> Result<Vec<u8>, WorldError> {
        let mut s = fstp_crypto::random_array::<16>()
            .map_err(|e| err("a serial", &e))?
            .to_vec();
        if let Some(first) = s.first_mut() {
            *first = (*first & 0x7f) | 0x01;
        }
        Ok(s)
    }

    /// Unpadded-free standard base64 with padding, for the key PEM.
    fn base64(der: &[u8]) -> String {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = String::with_capacity(der.len().saturating_mul(2));
        for chunk in der.chunks(3) {
            let b = |i: usize| u32::from(chunk.get(i).copied().unwrap_or(0));
            let n = (b(0) << 16) | (b(1) << 8) | b(2);
            for k in 0..4usize {
                if k <= chunk.len() {
                    let shift = 18usize.saturating_sub(k.saturating_mul(6));
                    let idx = usize::try_from((n >> shift) & 63).unwrap_or(0);
                    s.push(char::from(A.get(idx).copied().unwrap_or(b'A')));
                } else {
                    s.push('=');
                }
            }
        }
        s
    }

    /// A PKCS#8 private key as PEM.
    pub(super) fn key_pem(der: &[u8]) -> Vec<u8> {
        let b64 = base64(der);
        let mut out = String::from("-----BEGIN PRIVATE KEY-----\n");
        for line in b64.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(line).unwrap_or(""));
            out.push('\n');
        }
        out.push_str("-----END PRIVATE KEY-----\n");
        out.into_bytes()
    }

    /// A certificate and its key.
    pub(super) struct Issued {
        /// The certificate, PEM.
        pub(super) cert_pem: Vec<u8>,
        /// Its private key, PEM.
        pub(super) key_pem: Vec<u8>,
    }

    /// Where a CA's key lives.
    enum CaKey {
        /// In the test process.
        Local(fstp_crypto::sig::EcdsaP256KeyPair),
        /// A `sign` key of the cell's world custody (ADR-004 "CA keys in
        /// custody", lane m3/erase-steps), with its SubjectPublicKeyInfo.
        Custody(super::WorldCustody, fstp_custody::SignKeyRef, Vec<u8>),
    }

    impl CaKey {
        fn spki_der(&self) -> Result<Vec<u8>, WorldError> {
            match self {
                CaKey::Local(k) => k.spki_der().map_err(|e| err("a CA key", &e)),
                CaKey::Custody(_, _, spki) => Ok(spki.clone()),
            }
        }

        /// The signature over `message`: locally, or through custody
        /// `sign` over its SHA-256 digest.
        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, WorldError> {
            match self {
                CaKey::Local(k) => k.sign(message).map_err(|e| err("a CA signature", &e)),
                CaKey::Custody(custody, key, _) => {
                    use fstp_custody::Custody as _;
                    fstp_rt::future::block_on(custody.sign(key, &fstp_crypto::sha256(message)))
                        .map(|s| s.0)
                        .map_err(|e| err("a CA signature in custody", &e))
                }
            }
        }
    }

    /// A CA of the world. Its key never leaves the test process, or the
    /// cell's world custody for a cell CA.
    pub(super) struct Ca {
        name: String,
        key: CaKey,
        /// The CA certificate, DER.
        pub(super) der: Vec<u8>,
        /// The CA certificate, PEM.
        pub(super) pem: Vec<u8>,
        /// The SHA-256 digest of its SubjectPublicKeyInfo.
        pub(super) spki_digest: [u8; 32],
    }

    impl Ca {
        /// A fresh self-signed CA named `name`.
        pub(super) fn new(name: &str) -> Result<Ca, WorldError> {
            let key =
                fstp_crypto::sig::EcdsaP256KeyPair::generate().map_err(|e| err("a CA key", &e))?;
            Ca::with_key(name, CaKey::Local(key))
        }

        /// A fresh self-signed CA named `name` whose key is a `sign` key
        /// made inside `custody` (design section 1.3, ADR-004 "CA keys in
        /// custody"). The cell CA is made so (lane m3/erase-steps).
        pub(super) fn in_custody(
            name: &str,
            custody: &super::WorldCustody,
        ) -> Result<Ca, WorldError> {
            let (key, spki) = custody
                .create_sign_key()
                .map_err(|e| err("a CA key in custody", &e))?;
            Ca::with_key(name, CaKey::Custody(custody.clone(), key, spki))
        }

        fn with_key(name: &str, key: CaKey) -> Result<Ca, WorldError> {
            let spki = key.spki_der()?;
            let dn = DistinguishedName {
                common_name: name.to_owned(),
                organizational_unit: None,
            };
            let now = now()?;
            let spec = CertSpec {
                serial: serial()?,
                issuer: dn.clone(),
                subject: dn,
                validity: Validity {
                    not_before: now.saturating_sub(BACKDATE),
                    not_after: now.saturating_add(CA_LIFETIME),
                },
                spki_der: spki.clone(),
                issuer_key_id: None,
                kind: CertKind::Ca,
                dns_names: Vec::new(),
                ip_addrs: Vec::new(),
                algorithm: SignatureAlgorithm::EcdsaP256Sha256,
            };
            let t = tbs(&spec).map_err(|e| err("a CA", &e))?;
            let sig = key.sign(t.as_der())?;
            let der = assemble(&t, &sig).map_err(|e| err("a CA", &e))?;
            let pem = encode(PemLabel::Certificate, &der)
                .map_err(|e| err("a CA", &e))?
                .into_bytes();
            Ok(Ca {
                name: name.to_owned(),
                key,
                der,
                pem,
                spki_digest: fstp_crypto::sha256(&spki),
            })
        }

        /// A leaf of `kind` with subject `cn` and `ou`, for `dns` and `ips`.
        pub(super) fn issue(
            &self,
            kind: CertKind,
            cn: &str,
            ou: Option<&str>,
            dns: &[&str],
            ips: &[IpAddr],
        ) -> Result<Issued, WorldError> {
            let key =
                fstp_crypto::sig::EcdsaP256KeyPair::generate().map_err(|e| err("a key", &e))?;
            let issuer_spki = self.key.spki_der()?;
            let now = now()?;
            let not_before = now.saturating_sub(BACKDATE);
            let spec = CertSpec {
                serial: serial()?,
                issuer: DistinguishedName {
                    common_name: self.name.clone(),
                    organizational_unit: None,
                },
                subject: DistinguishedName {
                    common_name: cn.to_owned(),
                    organizational_unit: ou.map(str::to_owned),
                },
                validity: Validity {
                    not_before,
                    not_after: not_before.saturating_add(LEAF_LIFETIME.saturating_sub(1)),
                },
                spki_der: key.spki_der().map_err(|e| err("a key", &e))?,
                issuer_key_id: Some(key_identifier(&issuer_spki).map_err(|e| err("a key id", &e))?),
                kind,
                dns_names: dns.iter().map(|d| (*d).to_owned()).collect(),
                ip_addrs: ips.to_vec(),
                algorithm: SignatureAlgorithm::EcdsaP256Sha256,
            };
            let t = tbs(&spec).map_err(|e| err("a leaf", &e))?;
            let sig = self.key.sign(t.as_der())?;
            let der = assemble(&t, &sig).map_err(|e| err("a leaf", &e))?;
            let cert_pem = encode(PemLabel::Certificate, &der)
                .map_err(|e| err("a leaf", &e))?
                .into_bytes();
            let pkcs8 = key.pkcs8_der().map_err(|e| err("a key", &e))?;
            Ok(Issued {
                cert_pem,
                key_pem: key_pem(&pkcs8),
            })
        }
    }
}

/// The custody of a world's cells: roots held in the test process,
/// seal keys wrapped under them with AES-256-GCM. It stands in for the
/// custody backend of design section 3.3 the way `fstp-custody-sim`
/// does, and holds synthetic roots only.
#[derive(Clone, Default)]
pub(crate) struct WorldCustody {
    roots: std::sync::Arc<Mutex<BTreeMap<Vec<u8>, [u8; 32]>>>,
    /// Every root it created, destroyed ones included, in order. The
    /// I-80 scans look for these bytes ([`World::root_needles`], lane
    /// F-ERASE).
    made: std::sync::Arc<Mutex<Vec<[u8; 32]>>>,
    /// The chain of every root it created, by handle (lane m3/erase-steps).
    chains: std::sync::Arc<Mutex<BTreeMap<Vec<u8>, fstp_keys::Chain>>>,
    /// The ECDSA P-256 `sign` keys it holds, by handle: the cell CA key
    /// (design section 1.3, ADR-004 "CA keys in custody", lane
    /// m3/erase-steps). They are made here and never leave.
    sign_keys: std::sync::Arc<Mutex<BTreeMap<Vec<u8>, fstp_crypto::sig::EcdsaP256KeyPair>>>,
    /// The reference of every root it created, by handle, so the control
    /// plane can name each live root of the cell (lane m3/erase-cell).
    refs: std::sync::Arc<Mutex<BTreeMap<Vec<u8>, fstp_custody::RootRef>>>,
    /// In process mode, the cell's custody process: its roots live there
    /// and never in this process ([`crate::custody_sim::serve`], lane
    /// m3/custody-decisions). The handles of its live roots are kept here.
    remote: Option<std::sync::Arc<fstp_custody::keyd::KeydCustody>>,
    remote_live: std::sync::Arc<Mutex<std::collections::BTreeSet<Vec<u8>>>>,
}

impl WorldCustody {
    /// The custody of a cell in process mode: every root operation goes to
    /// the custody process on `socket` through the production client
    /// `KeydCustody`, so no root byte enters this process (I-80). CA keys
    /// stay here, as in every world.
    ///
    /// # Errors
    ///
    /// Refuses an empty socket path.
    pub(crate) fn remote(socket: &std::path::Path) -> Result<WorldCustody, WorldError> {
        let client = fstp_custody::keyd::KeydCustody::new(socket)
            .map_err(|e| WorldError::Store(format!("the custody client: {e}")))?;
        Ok(WorldCustody {
            remote: Some(std::sync::Arc::new(client)),
            ..WorldCustody::default()
        })
    }

    /// The handle of every root that lives (lane F-ERASE).
    pub(crate) fn live_handles(&self) -> Vec<Vec<u8>> {
        let mut out: Vec<Vec<u8>> = lock(&self.roots).keys().cloned().collect();
        out.extend(lock(&self.remote_live).iter().cloned());
        out
    }

    /// Every key that lives: each root with its chain, and each `sign`
    /// key with no chain, by handle (lane m3/erase-steps).
    pub(crate) fn live_keys(&self) -> Vec<(Option<fstp_keys::Chain>, Vec<u8>)> {
        let chains = lock(&self.chains);
        let mut out: Vec<(Option<fstp_keys::Chain>, Vec<u8>)> = self
            .live_handles()
            .iter()
            .map(|h| (chains.get(h).copied(), h.clone()))
            .collect();
        out.extend(lock(&self.sign_keys).keys().map(|h| (None, h.clone())));
        out
    }

    /// Makes an ECDSA P-256 `sign` key inside custody and gives its
    /// reference and SubjectPublicKeyInfo (lane m3/erase-steps). The
    /// private key never leaves.
    pub(crate) fn create_sign_key(
        &self,
    ) -> Result<(fstp_custody::SignKeyRef, Vec<u8>), fstp_custody::CustodyError> {
        let key = fstp_crypto::sig::EcdsaP256KeyPair::generate()
            .map_err(fstp_custody::CustodyError::Crypto)?;
        let spki = key.spki_der().map_err(fstp_custody::CustodyError::Crypto)?;
        let handle =
            fstp_crypto::random_array::<16>().map_err(fstp_custody::CustodyError::Crypto)?;
        lock(&self.sign_keys).insert(handle.to_vec(), key);
        Ok((
            fstp_custody::SignKeyRef {
                backend: fstp_custody::BackendId::Simulator,
                handle: fstp_custody::CustodyHandle(handle.to_vec()),
            },
            spki,
        ))
    }

    /// Every live root, by its full reference, and every live `sign` key:
    /// what the control plane names for the cell's erasure (lane
    /// m3/erase-cell).
    pub(crate) fn cell_keys(&self) -> fstp_control::erase::CellKeys {
        let refs = lock(&self.refs);
        fstp_control::erase::CellKeys {
            roots: self
                .live_handles()
                .iter()
                .filter_map(|h| refs.get(h).cloned())
                .collect(),
            ca: lock(&self.sign_keys)
                .keys()
                .map(|h| fstp_custody::SignKeyRef {
                    backend: fstp_custody::BackendId::Simulator,
                    handle: fstp_custody::CustodyHandle(h.clone()),
                })
                .collect(),
        }
    }

    /// Destroys the `sign` key `handle`. Whether it lived (lane
    /// m3/erase-cell).
    pub(crate) fn remove_sign_key(&self, handle: &[u8]) -> bool {
        lock(&self.sign_keys).remove(handle).is_some()
    }
}

impl fstp_custody::Custody for WorldCustody {
    // In process mode each root operation goes to the cell's custody
    // process (`remote`). The `async fn` bodies run when the caller polls,
    // so the caller's request id is current for `KeydCustody`
    // (`fstp_custody::with_request`).

    async fn create_root(
        &self,
        label: fstp_custody::RootLabel,
    ) -> Result<fstp_custody::RootRef, fstp_custody::CustodyError> {
        let chain = label.chain;
        let root = match &self.remote {
            Some(remote) => {
                let root = remote.create_root(label).await?;
                lock(&self.remote_live).insert(root.handle.0.clone());
                root
            }
            None => {
                let key = fstp_crypto::random_array::<32>()
                    .map_err(fstp_custody::CustodyError::Crypto)?;
                let handle = fstp_crypto::random_array::<16>()
                    .map_err(fstp_custody::CustodyError::Crypto)?;
                lock(&self.roots).insert(handle.to_vec(), key);
                lock(&self.made).push(key);
                fstp_custody::RootRef {
                    backend: fstp_custody::BackendId::Simulator,
                    cell: label.cell,
                    chain: label.chain,
                    epoch: label.epoch,
                    handle: fstp_custody::CustodyHandle(handle.to_vec()),
                }
            }
        };
        lock(&self.chains).insert(root.handle.0.clone(), chain);
        lock(&self.refs).insert(root.handle.0.clone(), root.clone());
        Ok(root)
    }

    async fn wrap(
        &self,
        root: &fstp_custody::RootRef,
        key: &fstp_custody::SealKey,
        aad: &fstp_custody::Aad,
    ) -> Result<fstp_custody::WrappedSealKey, fstp_custody::CustodyError> {
        use fstp_custody::{CustodyError, Refusal};
        if let Some(remote) = &self.remote {
            return remote.wrap(root, key, aad).await;
        }
        let rk = *lock(&self.roots)
            .get(&root.handle.0)
            .ok_or(CustodyError::Refused(Refusal::UnknownRoot))?;
        let k = fstp_crypto::aead::Key::from_bytes(&rk).map_err(CustodyError::Crypto)?;
        let s = fstp_crypto::aead::seal(&k, &aad.0, key.expose()).map_err(CustodyError::Crypto)?;
        let mut out = s.nonce.to_vec();
        out.extend_from_slice(&s.body);
        Ok(fstp_custody::WrappedSealKey(out))
    }

    async fn unwrap(
        &self,
        root: &fstp_custody::RootRef,
        w: &fstp_custody::WrappedSealKey,
        aad: &fstp_custody::Aad,
    ) -> Result<fstp_custody::SealKey, fstp_custody::CustodyError> {
        use fstp_custody::{CustodyError, Refusal};
        if let Some(remote) = &self.remote {
            return remote.unwrap(root, w, aad).await;
        }
        let rk = *lock(&self.roots)
            .get(&root.handle.0)
            .ok_or(CustodyError::Refused(Refusal::UnknownRoot))?;
        let k = fstp_crypto::aead::Key::from_bytes(&rk).map_err(CustodyError::Crypto)?;
        let (nonce, body) =
            w.0.split_at_checked(fstp_crypto::aead::NONCE_LEN)
                .ok_or(CustodyError::Refused(Refusal::UnwrapFailed))?;
        let nonce: [u8; fstp_crypto::aead::NONCE_LEN] = nonce
            .try_into()
            .map_err(|_| CustodyError::Refused(Refusal::UnwrapFailed))?;
        let pt = fstp_crypto::aead::open(&k, &nonce, &aad.0, body)
            .map_err(|_| CustodyError::Refused(Refusal::UnwrapFailed))?;
        fstp_custody::SealKey::from_slice(&pt)
            .map_err(|_| CustodyError::Refused(Refusal::UnwrapFailed))
    }

    async fn destroy(
        &self,
        root: &fstp_custody::RootRef,
    ) -> Result<fstp_custody::DestroyReceipt, fstp_custody::CustodyError> {
        if let Some(remote) = &self.remote {
            let receipt = remote.destroy(root).await?;
            lock(&self.remote_live).remove(&root.handle.0);
            return Ok(receipt);
        }
        if lock(&self.roots).remove(&root.handle.0).is_some() {
            Ok(fstp_custody::DestroyReceipt(root.handle.0.clone()))
        } else {
            Err(fstp_custody::CustodyError::Refused(
                fstp_custody::Refusal::UnknownRoot,
            ))
        }
    }

    async fn sign(
        &self,
        key: &fstp_custody::SignKeyRef,
        digest: &[u8; 32],
    ) -> Result<fstp_custody::EcdsaSignature, fstp_custody::CustodyError> {
        use fstp_custody::{CustodyError, Refusal};
        match lock(&self.sign_keys).get(&key.handle.0) {
            Some(k) => k
                .sign_digest(digest)
                .map(fstp_custody::EcdsaSignature)
                .map_err(CustodyError::Crypto),
            None => Err(CustodyError::Refused(Refusal::NoSignKey)),
        }
    }

    async fn usage_since(
        &self,
        root: &fstp_custody::RootRef,
        cursor: fstp_custody::UsageCursor,
    ) -> Result<fstp_custody::UsagePage, fstp_custody::CustodyError> {
        match &self.remote {
            Some(remote) => remote.usage_since(root, cursor).await,
            None => Ok(fstp_custody::UsagePage::default()),
        }
    }
}

type Rt = fstp_rt::tokio::TokioRuntime;

/// The name the witness server certificate carries.
const WITNESS_NAME: &str = "witness.fstp.localhost";

/// The environment variable that names the edge port, when the edge
/// cannot bind loopback port 443 itself.
pub const EDGE_PORT_ENV: &str = "FSTP_EDGE_PORT";

/// The longest life of one edge connection.
const EDGE_CONNECTION_LIFETIME: Duration = Duration::from_secs(2 * 3600);

/// The edge of a world: the SNI router on loopback, with the route table
/// of every cell of the process (design section 9.4, ADR-009).
struct Edge {
    addr: SocketAddr,
    table: std::sync::Arc<Mutex<fstp_edge::RouteTable>>,
    /// The edge's connection log, one line per splice (lane F-ISO): the
    /// route kind and the byte counts each way, bucketed to powers of two
    /// as the metadata register gives the edge's form (ADR-009, Q36).
    log: std::sync::Arc<Mutex<Vec<u8>>>,
}

/// What every world of a test binary shares: the runtime, the CAs and
/// the edge. Like the clusters, they live for the process. The SaaS
/// witness is shared too ([`saas_witness`]), and each self-hosted install
/// starts a local witness of its own ([`start_local_witness`]).
struct Services {
    rt: Rt,
    /// The control-plane CA: the witness server certificate, the tunnel
    /// certificates and the edge's tunnel client certificate.
    control: pki::Ca,
    /// The CA of the public host certificates, which stands in for a
    /// public CA (design section 9.2 step 5). A browser trusts it once
    /// its certificate is installed ([`World::origin_ca_pem`]).
    origin: pki::Ca,
    edge: Edge,
}

impl fmt::Debug for Services {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Services")
            .field("edge", &self.edge.addr)
            .finish_non_exhaustive()
    }
}

/// The services of the process, started on first use.
fn services() -> Result<&'static Services, WorldError> {
    static SERVICES: OnceLock<Result<Services, WorldError>> = OnceLock::new();
    SERVICES
        .get_or_init(start_services)
        .as_ref()
        .map_err(Clone::clone)
}

fn start_services() -> Result<Services, WorldError> {
    let fail = |what: &str, e: &dyn fmt::Display| WorldError::Store(format!("{what}: {e}"));
    let rt = Rt::new_multi_thread(4).map_err(|e| fail("the world runtime", &e))?;
    let control = pki::Ca::new("fstp world control-plane CA")?;
    let origin = pki::Ca::new("fstp world origin CA")?;
    let edge = rt.block_on(start_edge(&rt, &control))?;
    Ok(Services {
        rt,
        control,
        origin,
        edge,
    })
}

/// The witness a world cell anchors at, and how the cell reaches it.
struct WorldWitness {
    handle: std::sync::Arc<fstp_witness::WitnessHandle<Rt>>,
    /// The CA that issued the witness server certificate, PEM.
    ca_pem: Vec<u8>,
    /// The SHA-256 digest of that CA's SubjectPublicKeyInfo, which the
    /// cell pins (R-NF-09).
    ca_digest: [u8; 32],
    /// The name the witness server certificate carries.
    name: String,
    /// A second server certificate for that name from the same CA, which
    /// the cell's recording relay to the witness presents
    /// ([`crate::relay`], lane F-ISO).
    relay_server: pki::Issued,
    /// The install of a self-hosted cell, whose local witness stops with
    /// the cell. `None` for the shared SaaS witness.
    local: Option<LocalInstall>,
}

/// The install directory of a self-hosted cell: its local witness's file
/// store and the install files ([`World::install_files`]). It is removed
/// when the cell's runtime drops.
struct LocalInstall {
    dir: std::path::PathBuf,
}

impl Drop for LocalInstall {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A local witness stops with its cell, also when the cell fails to start.
impl Drop for WorldWitness {
    fn drop(&mut self) {
        if self.local.is_some() {
            self.handle.trigger_shutdown();
        }
    }
}

/// The SaaS witness of the process, started on first use over the witness
/// cluster `witness` and its service login.
fn saas_witness(
    s: &'static Services,
    witness: &ClusterHandle,
) -> Result<std::sync::Arc<fstp_witness::WitnessHandle<Rt>>, WorldError> {
    type Witness = Result<std::sync::Arc<fstp_witness::WitnessHandle<Rt>>, WorldError>;
    static WITNESS: OnceLock<Witness> = OnceLock::new();
    WITNESS
        .get_or_init(|| start_saas_witness(s, witness).map(std::sync::Arc::new))
        .clone()
}

fn start_saas_witness(
    s: &Services,
    witness_cluster: &ClusterHandle,
) -> Result<fstp_witness::WitnessHandle<Rt>, WorldError> {
    let fail = |what: &str, e: &dyn fmt::Display| WorldError::Store(format!("{what}: {e}"));
    let (rt, control) = (&s.rt, &s.control);
    let login = lock(cluster_state(witness_cluster.name())?)
        .service
        .clone()
        .ok_or_else(|| WorldError::Store("the witness database has no service login".to_owned()))?;
    let db = pg_config(witness_cluster.server(), "witness", &login)?;
    let server = control.issue(
        fstp_pki::cert::CertKind::Server,
        WITNESS_NAME,
        None,
        &[WITNESS_NAME],
        &[],
    )?;
    let key = fstp_crypto::composite::generate().map_err(|e| fail("the receipt key", &e))?;
    let witness = rt
        .block_on(fstp_witness::serve(
            rt.clone(),
            fstp_witness::WitnessParts {
                db,
                receipt_key: key,
                server_chain_pem: server.cert_pem,
                server_key_pem: server.key_pem,
                listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            },
        ))
        .map_err(|e| fail("the witness", &e))?;
    Ok(witness)
}

/// The name the local witness server certificate of a self-hosted install
/// carries.
const LOCAL_WITNESS_NAME: &str = "witness.selfhosted.localhost";

/// The directory of the local witness's file store in an install
/// directory.
const WITNESS_STORE_DIR: &str = "witness";
/// The directory of the install configuration files.
const INSTALL_CONFIG_DIR: &str = "config";
/// The directory of the install credential files.
const INSTALL_CREDENTIALS_DIR: &str = "credentials";

/// Starts the local witness of a self-hosted install for `cell`, as
/// `fstp-install` would at first start (ADR-010 "Self-hosted witness",
/// design section 9.5 step 6). B-06 defers the installer, so the world
/// plays it:
///
/// - a fresh install directory, readable by its owner only, holds the
///   witness's file store;
/// - an install CA issues the witness server certificate;
/// - the composite receipt key is generated here. In production it is a
///   level 2 key of the witness's own `fstp-keyd` entry with its own
///   credential (ADR-004 part 2, "Self-hosted witness receipt key"). The
///   world runs no `fstp-keyd`, so it hands the key in;
/// - the witness listens on loopback, never on a CrabNebula host (I-38).
fn start_local_witness(s: &Services, cell: &[u8; 16]) -> Result<WorldWitness, WorldError> {
    let fail = |what: &str, e: &dyn fmt::Display| {
        WorldError::Store(format!("the local witness: {what}: {e}"))
    };
    let mut tag = [0u8; 6];
    fstp_crypto::random_bytes(&mut tag).map_err(|_| fail("randomness", &"none"))?;
    let dir = std::env::temp_dir().join(format!(
        "fstp-selfhosted-{}-{}-{}",
        std::process::id(),
        cell_label(cell).get(..12).unwrap_or(""),
        crate::canary::lower_hex(&tag)
    ));
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        b.mode(0o700);
    }
    b.create(&dir)
        .map_err(|e| fail("the install directory", &e))?;
    let install_ca = pki::Ca::new("self-hosted install CA")?;
    let server = install_ca.issue(
        fstp_pki::cert::CertKind::Server,
        LOCAL_WITNESS_NAME,
        None,
        &[LOCAL_WITNESS_NAME],
        &[],
    )?;
    let key = fstp_crypto::composite::generate().map_err(|e| fail("the receipt key", &e))?;
    let started = s.rt.block_on(fstp_witness::serve_local(
        s.rt.clone(),
        fstp_witness::LocalWitnessParts {
            dir: dir.join(WITNESS_STORE_DIR),
            receipt_key: key,
            server_chain_pem: server.cert_pem,
            server_key_pem: server.key_pem.clone(),
            listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        },
    ));
    let handle = match started {
        Ok(h) => h,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(fail("the start", &e));
        }
    };
    let relay_server = match install_ca.issue(
        fstp_pki::cert::CertKind::Server,
        LOCAL_WITNESS_NAME,
        None,
        &[LOCAL_WITNESS_NAME],
        &[],
    ) {
        Ok(i) => i,
        Err(e) => {
            handle.trigger_shutdown();
            let _ = std::fs::remove_dir_all(&dir);
            return Err(e);
        }
    };
    Ok(WorldWitness {
        handle: std::sync::Arc::new(handle),
        ca_pem: install_ca.pem.clone(),
        ca_digest: install_ca.spki_digest,
        name: LOCAL_WITNESS_NAME.to_owned(),
        relay_server,
        local: Some(LocalInstall { dir }),
    })
}

/// Writes the install files of a self-hosted cell into `dir`, as
/// `fstp-install` would (design section 9.5, R-NF-05): the install
/// configuration, and as credentials the first-admin token and each
/// role's password, certificate and key.
/// Every credential byte was generated for this install. Each file is
/// readable by its owner only.
fn write_install_files(
    dir: &Path,
    host: &str,
    logins: &CellLogins,
    token: &[u8; 32],
) -> Result<(), WorldError> {
    let fail = |e: std::io::Error| WorldError::Store(format!("an install file: {e}"));
    let write = |rel: &str, bytes: &[u8]| -> Result<(), WorldError> {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(fail)?;
        }
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let mut f = opts.open(&path).map_err(fail)?;
        std::io::Write::write_all(&mut f, bytes).map_err(fail)
    };
    write(
        &format!("{INSTALL_CONFIG_DIR}/fstp-install.conf"),
        format!("{{\"eudi_relying_party\":\"tenant_registration\",\"host\":\"{host}\"}}\n")
            .as_bytes(),
    )?;
    write(
        &format!("{INSTALL_CREDENTIALS_DIR}/first-admin-token"),
        crate::canary::lower_hex(token).as_bytes(),
    )?;
    for login in logins.values() {
        let base = format!("{INSTALL_CREDENTIALS_DIR}/roles/{}", login.role);
        write(&format!("{base}/password"), login.password.as_bytes())?;
        write(&format!("{base}/cert.pem"), &login.cert_pem)?;
        write(&format!("{base}/key.pem"), &login.key_pem)?;
    }
    Ok(())
}

/// Every regular file under `root`, as `(path relative to root, bytes)`,
/// in path order. A missing directory holds none.
fn read_tree(root: &Path) -> Result<Vec<(String, Vec<u8>)>, WorldError> {
    let fail = |e: std::io::Error| WorldError::Store(format!("{}: {e}", root.display()));
    let mut out = Vec::new();
    let mut todo = vec![root.to_path_buf()];
    while let Some(d) = todo.pop() {
        let entries = match std::fs::read_dir(&d) {
            Ok(e) => e,
            Err(e) if e.kind() == ErrorKind::NotFound => continue,
            Err(e) => return Err(fail(e)),
        };
        for entry in entries {
            let path = entry.map_err(fail)?.path();
            if path.is_dir() {
                todo.push(path);
            } else {
                let bytes = std::fs::read(&path).map_err(fail)?;
                let rel = path
                    .strip_prefix(root)
                    .map_err(|_| WorldError::Store("a path outside its tree".to_owned()))?
                    .to_string_lossy()
                    .into_owned();
                out.push((rel, bytes));
            }
        }
    }
    out.sort();
    Ok(out)
}

/// The pgwire configuration of `login` on `dbname` of `server`.
fn pg_config(
    server: &fstp_pgtest::PgServer,
    dbname: &str,
    login: &RoleLogin,
) -> Result<fstp_pgwire::Config, WorldError> {
    let fail = |e: fstp_pgwire::Error| WorldError::Store(format!("a database login: {e}"));
    let p = login.conn_params(server, dbname);
    let tls = fstp_pgwire::ClientTls::new(p.server_ca_pem, p.client_cert_pem, p.client_key_pem)
        .map_err(fail)?;
    Ok(fstp_pgwire::Config::new(
        p.host.clone(),
        p.port,
        p.user.as_str(),
        fstp_pgwire::Password::new(p.password.as_str()).map_err(fail)?,
        p.dbname.clone(),
        tls,
    )
    .map_err(fail)?
    .connect_timeout(Some(Duration::from_secs(20))))
}

/// Starts the edge: loopback port 443 when the process may bind it, and
/// otherwise the port in [`EDGE_PORT_ENV`] or a free one.
async fn start_edge(rt: &Rt, control: &pki::Ca) -> Result<Edge, WorldError> {
    use fstp_rt::{Listener as _, Runtime as _};
    let fail =
        |what: &str, e: &dyn fmt::Display| WorldError::Store(format!("the edge: {what}: {e}"));
    let listener = match rt
        .bind_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, 443)))
        .await
    {
        Ok(l) => l,
        Err(_) => {
            let port = std::env::var(EDGE_PORT_ENV)
                .ok()
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(0);
            rt.bind_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
                .await
                .map_err(|e| fail("the listener", &e))?
        }
    };
    let addr = listener
        .local_addr()
        .map_err(|e| fail("the listener", &e))?;
    let client = control.issue(fstp_pki::cert::CertKind::Client, "edge", None, &[], &[])?;
    let tls = fstp_tls::ClientConfig::mutual(&control.pem, &client.cert_pem, &client.key_pem)
        .map_err(|e| fail("the tunnel client", &e))?;
    let opener = fstp_edge::TlsTunnelOpener::new(rt.clone(), tls);
    let table = std::sync::Arc::new(Mutex::new(fstp_edge::RouteTable::new()));
    let log = std::sync::Arc::new(Mutex::new(Vec::new()));
    let loop_log = std::sync::Arc::clone(&log);
    let loop_table = std::sync::Arc::clone(&table);
    let loop_rt = rt.clone();
    drop(rt.spawn(async move {
        let mut listener = listener;
        loop {
            let Ok((client, peer)) = listener.accept().await else {
                loop_rt.sleep(Duration::from_millis(50)).await;
                continue;
            };
            let table = lock(&loop_table).clone();
            let opener = opener.clone();
            let splice_rt = loop_rt.clone();
            let splice_log = std::sync::Arc::clone(&loop_log);
            drop(loop_rt.spawn(async move {
                // The edge bounds each connection's life (fstp_edge::serve
                // leaves deadlines to its caller).
                let splice = fstp_edge::serve(client, peer, &table, &opener);
                if let Ok(Ok(s)) =
                    fstp_rt::timeout(&splice_rt, EDGE_CONNECTION_LIFETIME, splice).await
                {
                    let line = format!(
                        "{:?} to_cell<={} to_client<={}\n",
                        s.kind,
                        s.to_cell.checked_next_power_of_two().unwrap_or(u64::MAX),
                        s.to_client.checked_next_power_of_two().unwrap_or(u64::MAX),
                    );
                    lock(&splice_log).extend_from_slice(line.as_bytes());
                }
            }));
        }
    }));
    Ok(Edge { addr, table, log })
}

/// The DNS label of a cell id: its 32 lowercase hex digits.
fn cell_label(cell: &[u8; 16]) -> String {
    crate::canary::lower_hex(cell)
}

/// The tenant host of a world cell: three labels under `.localhost`, which
/// every browser and resolver sends to loopback (RFC 6761 section 6.3).
fn cell_host(cell: &[u8; 16]) -> String {
    format!(
        "c{}.fstp.localhost",
        cell_label(cell).get(..12).unwrap_or("")
    )
}

/// The parts of a started world cell.
struct Running {
    cell: Option<fstp_cell::process::RunningCell<Rt>>,
    vault: crate::seeded_vault::SeededVault,
    invitation: Invitation,
}

/// The files a self-hosted install writes outside its database clusters
/// (design section 9.5), as [`World::install_files`] reads them back.
#[derive(Clone, Debug, Default)]
pub struct InstallFiles {
    /// The configuration files, such as the `fstp-install` configuration.
    pub config: StoreSet,
    /// The credential files: the first-admin token and each role's
    /// password, certificate and key. Every byte is generated at install.
    pub credentials: StoreSet,
}

/// The first admin's invitation as a world cell drew it.
#[derive(Clone, Copy)]
enum Invitation {
    /// The two halves of a SaaS cell (Q35).
    Split(FirstAdminInvitation),
    /// The whole token of a self-hosted install.
    Whole([u8; 32]),
}

/// What a started cell's handle reaches (design section 14.3).
struct CellRuntime {
    services: &'static Services,
    running: Mutex<Running>,
    health: SocketAddr,
    witness: WorldWitness,
    /// The recording relays of the cell's links to its vault, its
    /// witness and the control plane ([`crate::relay`], lane F-ISO).
    relays: Mutex<Vec<crate::relay::Relay>>,
    /// The cell's custody, which shares its roots with the cell.
    custody: WorldCustody,
    /// What the cell restarts from (lane m3/licence-update).
    restart: RestartParts,
    /// The cell's CrabNebula stand-in and release clock (lane
    /// m3/licence-update).
    release: ReleaseWorld,
}

impl fmt::Debug for CellRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CellRuntime")
            .field("health", &self.health)
            .finish_non_exhaustive()
    }
}

/// How long a world cell may take to drain at the end of its world.
const CELL_DRAIN: Duration = Duration::from_secs(20);

impl CellRuntime {
    /// Stops the cell and its vault, and removes its routes.
    fn stop(&self, cell: &[u8; 16]) {
        let (running, vault_addr) = {
            let mut r = lock(&self.running);
            (r.cell.take(), r.vault.internal_addr())
        };
        let _ = vault_addr;
        if let Some(c) = running {
            let _ = self.services.rt.block_on(c.shutdown(CELL_DRAIN));
        }
        lock(&self.relays).clear();
        let r = lock(&self.running);
        let _ = self.services.rt.block_on(r.vault.shutdown(CELL_DRAIN));
        lock(&self.services.edge.table).remove_cell_by_id(cell);
        if let Some(local) = &self.witness.local {
            let _ = local;
            let _ = self
                .services
                .rt
                .block_on(self.witness.handle.shutdown(CELL_DRAIN));
        }
    }
}

/// The world's registration of cluster server keys (I-83, design section
/// 9.2): the SHA-256 digest of each cluster's server SubjectPublicKeyInfo
/// and the cluster's kind. The control plane records both at cluster
/// registration. Here the world reads the certificate `fstp-pgtest`
/// issued to each server from that server's TLS directory.
fn registered_server_keys(
    clusters: &[ClusterHandle],
) -> Result<Vec<([u8; 32], ClusterKind)>, WorldError> {
    let fail = |c: &ClusterHandle, what: &str| {
        WorldError::Store(format!("the server key of cluster {}: {what}", c.name()))
    };
    let mut out = Vec::with_capacity(clusters.len());
    for c in clusters {
        let path = c.server().dir().join("tls").join("server.pem");
        let pem = std::fs::read(&path).map_err(|e| fail(c, &e.to_string()))?;
        let text = std::str::from_utf8(&pem).map_err(|e| fail(c, &e.to_string()))?;
        let body: String = text
            .lines()
            .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE-----"))
            .skip(1)
            .take_while(|l| !l.starts_with("-----END"))
            .collect();
        let der = fstp_pgwire::base64::decode(body.as_bytes())
            .map_err(|_| fail(c, "the certificate PEM does not decode"))?;
        let cert = fstp_witness::peer::read_cert(&der)
            .map_err(|e| fail(c, &format!("the certificate does not read: {e:?}")))?;
        out.push((fstp_crypto::sha256(cert.spki), c.kind()));
    }
    Ok(out)
}

/// The name the world's control plane presents to a cell's heartbeat
/// link ([`fstp_cell::control`], lane F-ISO).
const CONTROL_PLANE_NAME: &str = "cp.fstp.localhost";

/// The upstreams of a cell's relays.
struct RelayUpstreams<'a> {
    /// The vault's internal listener.
    vault: SocketAddr,
    /// The cell's `cell-app` certificate and the roots of the vault's
    /// internal certificate.
    vault_client: (&'a pki::Issued, &'a [u8]),
    /// The cell's `cell-witness` certificate.
    witness_client: &'a pki::Issued,
    /// Whether the cell reaches the control plane: a SaaS cell does, and
    /// a self-hosted cell never does (B12).
    control_plane: bool,
}

/// A cell's relays and where the cell reaches each link through them.
struct CellRelays {
    relays: Vec<crate::relay::Relay>,
    vault: SocketAddr,
    witness: SocketAddr,
    control_plane: Option<SocketAddr>,
}

/// Starts the recording relays of world cell `index` (lane F-ISO,
/// [`crate::relay`]): to its vault, to its witness, and on a SaaS cell to
/// the world's control plane stand-in. Each relay presents a server
/// certificate from the CA the cell trusts for that peer, and requires a
/// client certificate under the cell CA, as the vault's internal listener
/// and the witness do. Each opens its upstream with the cell's own client
/// certificate. The captures and handshakes go to `egress`.
fn start_relays(
    s: &'static Services,
    egress: &EgressLog,
    index: u8,
    cell_ca: &pki::Ca,
    witness: &WorldWitness,
    up: RelayUpstreams<'_>,
) -> Result<CellRelays, WorldError> {
    use crate::egress::{Endpoint, Peer, Route};
    use crate::relay::Upstream;
    use fstp_pki::cert::CertKind;
    let fail =
        |what: &str, e: &dyn fmt::Display| WorldError::Store(format!("cell {index}: {what}: {e}"));
    let server = |cert: &pki::Issued| {
        fstp_tls::ServerConfig::builder(&cert.cert_pem, &cert.key_pem)
            .require_client_auth(&cell_ca.pem)
            .build()
            .map_err(|e| fail("a relay TLS", &e))
    };
    let start = |route: Route, cfg: fstp_tls::ServerConfig, upstream: Upstream| {
        s.rt.block_on(crate::relay::start(
            s.rt.clone(),
            egress.clone(),
            route,
            cfg,
            upstream,
        ))
        .map_err(|e| fail("a relay", &e))
    };
    let loopback = [IpAddr::V4(Ipv4Addr::LOCALHOST)];
    let (app, vault_roots) = up.vault_client;
    let vault_cert = cell_ca.issue(CertKind::Server, "vault relay", None, &[], &loopback)?;
    let vault = start(
        Route::new(Endpoint::cell(index), Peer::Vault, Some(index)),
        server(&vault_cert)?,
        Upstream::Tls {
            addr: up.vault,
            server_name: Ipv4Addr::LOCALHOST.to_string(),
            tls: fstp_tls::ClientConfig::mutual(vault_roots, &app.cert_pem, &app.key_pem)
                .map_err(|e| fail("the vault relay client TLS", &e))?,
        },
    )?;
    let witness_relay = start(
        Route::new(Endpoint::cell(index), Peer::Witness, None),
        server(&witness.relay_server)?,
        Upstream::Tls {
            addr: witness.handle.local_addr(),
            server_name: witness.name.clone(),
            tls: fstp_tls::ClientConfig::mutual(
                &witness.ca_pem,
                &up.witness_client.cert_pem,
                &up.witness_client.key_pem,
            )
            .map_err(|e| fail("the witness relay client TLS", &e))?,
        },
    )?;
    let mut out = CellRelays {
        vault: vault.addr(),
        witness: witness_relay.addr(),
        control_plane: None,
        relays: vec![vault, witness_relay],
    };
    if up.control_plane {
        let cert = s.control.issue(
            CertKind::Server,
            CONTROL_PLANE_NAME,
            None,
            &[CONTROL_PLANE_NAME],
            &[],
        )?;
        let cp = start(
            Route::new(Endpoint::cell(index), Peer::ControlPlane, None),
            server(&cert)?,
            Upstream::ControlPlane,
        )?;
        out.control_plane = Some(cp.addr());
        out.relays.push(cp);
    }
    Ok(out)
}

/// Starts world cell `index` of `plan` over its provisioned databases
/// (design section 9.2 steps 5, 6, 8, 9 and 10):
///
/// 1. The cell CA, the cell's keys and its custody. The witness pins the
///    cell CA and the App chain's anchor key. A SaaS cell registers at the
///    shared witness. A self-hosted cell starts its own local witness over
///    a file store in a fresh install directory, and registers there
///    ([`start_local_witness`]).
/// 2. The vault over `v_<cell>`, with its internal listener and its
///    origin's tunnel listener.
/// 3. The cell over `c_<cell>` through `fstp_cell::process::start`, which
///    creates epoch 0 of its key chain on its first start.
/// 4. The edge routes for `<cell host>` and `id.<cell host>`.
/// 5. The first tenant admin's invitation, drawn by the cell as two
///    halves. The world plays both staff channels and keeps both. A
///    self-hosted cell draws it whole, and the world writes it to the
///    install's token file with the other install files
///    ([`World::install_files`]).
#[allow(
    clippy::too_many_lines,
    reason = "one start, step by step, as the design lists it"
)]
fn start_cell(
    spec: &WorldSpec,
    clusters: &[ClusterHandle],
    index: u8,
    plan: &RolePlan,
    logins: CellLogins,
    serve: CellServe<'_>,
    egress: &EgressLog,
) -> Result<CellHandle, WorldError> {
    let CellServe {
        pages,
        dev,
        custody: custody_socket,
    } = serve;
    use fstp_cell::engine::startup::ClusterRole;
    use fstp_pki::cert::CertKind;
    let s = services()?;
    let fail =
        |what: &str, e: &dyn fmt::Display| WorldError::Store(format!("cell {index}: {what}: {e}"));
    let cell = plan.cell.0;
    let hex = cell_label(&cell);
    let host = dev.map_or_else(|| cell_host(&cell), |d| d.host.clone());
    let vault_host = format!("id.{host}");
    let login = |db: CellDatabase, role: RoleName| {
        logins
            .get(&(db, role))
            .cloned()
            .ok_or_else(|| WorldError::Store(format!("cell {index}: no {role:?} login")))
    };
    let app_cluster = cell_cluster(spec, clusters, ClusterKind::Application, index)?;
    let vault_cluster = cell_cluster(spec, clusters, ClusterKind::Vault, index)?;
    let server_keys = registered_server_keys(clusters)?;
    let app_db = database_name(CellDatabase::App, &plan.cell);
    let vault_db = database_name(CellDatabase::Vault, &plan.cell);
    // Step 1.
    // The cell CA key is a `sign` key of the cell's world custody, where the
    // cell's roots live too (ADR-004 "CA keys in custody", lane
    // m3/erase-steps).
    let custody = match custody_socket {
        Some(socket) => WorldCustody::remote(socket)?,
        None => WorldCustody::default(),
    };
    let cell_ca = pki::Ca::in_custody(
        &format!("cell CA {}", hex.get(..12).unwrap_or("")),
        &custody,
    )?;
    let anchor = fstp_crypto::composite::generate().map_err(|e| fail("the anchor key", &e))?;
    let anchor_public = anchor.public_key().to_bytes().to_vec();
    // The vault anchors its own chain under its own key (ADR-010 "The
    // vault chain is anchored by the vault only"), so the witness pins
    // both chains' anchor keys.
    let vault_anchor =
        fstp_crypto::composite::generate().map_err(|e| fail("the vault anchor key", &e))?;
    let registration = [
        (fstp_audit::ChainId::App, anchor_public),
        (
            fstp_audit::ChainId::Vault,
            vault_anchor.public_key().to_bytes().to_vec(),
        ),
    ];
    let witness = if spec.self_hosted {
        // A self-hosted install starts its own local witness over a file
        // store and registers the cell CA with it (ADR-010 "Self-hosted
        // witness", design section 9.5 step 6).
        let w = start_local_witness(s, &cell)?;
        s.rt.block_on(w.handle.register_cell(
            fstp_audit::CellId(cell),
            &cell_ca.der,
            &registration,
        ))
        .map_err(|e| fail("the witness registration", &e))?;
        w
    } else {
        // Provisioning writes the registration as the witness migrator,
        // and the witness reloads its registry: witness_service may only
        // read it.
        let witness_cluster = clusters
            .iter()
            .find(|c| c.kind() == ClusterKind::Witness)
            .ok_or_else(|| WorldError::Store("the world runs no witness cluster".to_owned()))?;
        let handle = saas_witness(s, witness_cluster)?;
        let registered_at = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| fail("the clock", &e))?
                .as_micros(),
        )
        .map_err(|e| fail("the clock", &e))?;
        sql_as(
            witness_cluster,
            WITNESS_SET,
            &format!("{WITNESS_SET}_migrator"),
            &fstp_witness::store::registration_sql(
                fstp_audit::CellId(cell),
                &cell_ca.der,
                &registration,
                registered_at,
            ),
        )?;
        s.rt.block_on(handle.reload_registry())
            .map_err(|e| fail("the witness registration", &e))?;
        WorldWitness {
            handle,
            ca_pem: s.control.pem.clone(),
            ca_digest: s.control.spki_digest,
            name: WITNESS_NAME.to_owned(),
            relay_server: s.control.issue(
                CertKind::Server,
                WITNESS_NAME,
                None,
                &[WITNESS_NAME],
                &[],
            )?,
            local: None,
        }
    };
    let loopback = [IpAddr::V4(Ipv4Addr::LOCALHOST)];
    let tunnel_name = format!("c{hex}.tunnel.fstp.localhost");
    let vault_tunnel_name = format!("v{hex}.tunnel.fstp.localhost");
    let tls_err = |what: &'static str| move |e: fstp_tls::TlsError| fail(what, &e);
    let server = |cert: &pki::Issued, roots: Option<&[u8]>| {
        let b = fstp_tls::ServerConfig::builder(&cert.cert_pem, &cert.key_pem);
        match roots {
            Some(r) => b.require_client_auth(r).build(),
            None => b.build(),
        }
    };
    // Step 2: the vault.
    let vault_internal = cell_ca.issue(CertKind::Server, "vault", None, &[], &loopback)?;
    let vault_tunnel = s.control.issue(
        CertKind::Server,
        &vault_tunnel_name,
        None,
        &[&vault_tunnel_name],
        &[],
    )?;
    // A dev cell serves the origin CA after each origin leaf, so a
    // browser that pins the CA's key reaches both origins
    // ([`World::origin_ca_spki_digest`]).
    let with_ca = |cert: pki::Issued| match dev {
        Some(_) => pki::Issued {
            cert_pem: [cert.cert_pem, s.origin.pem.clone()].concat(),
            key_pem: cert.key_pem,
        },
        None => cert,
    };
    let vault_origin =
        with_ca(
            s.origin
                .issue(CertKind::Server, &vault_host, None, &[&vault_host], &[])?,
        );
    let ticket =
        fstp_crypto::sig::Ed25519SigningKey::generate().map_err(|e| fail("the ticket key", &e))?;
    let vault_witness = cell_ca.issue(
        CertKind::Client,
        "vault-witness",
        Some(fstp_witness::peer::OU_VAULT_WITNESS),
        &[],
        &[],
    )?;
    // The seeded vault writes `vault_audit.chain` as `fstp_vault::service`
    // does (Q-C, lane m3/login-m2http): the former seam SEEDED_VAULT_CHAIN
    // is closed.
    let vault_chain = fstp_vault::chain::VaultChainParts {
        anchor_key: vault_anchor,
        witness: fstp_vault::chain::VaultWitness {
            addr: witness.handle.local_addr(),
            server_name: witness.name.clone(),
            tls: fstp_tls::ClientConfig::mutual(
                &witness.ca_pem,
                &vault_witness.cert_pem,
                &vault_witness.key_pem,
            )
            .map_err(tls_err("the vault witness TLS"))?,
            ca_digest: witness.ca_digest,
        },
        witness_keys: vec![witness.handle.receipt_public_key()],
    };
    let sealer = fstp_vault::service::AeadSealer::new(
        fstp_crypto::random_array::<16>().map_err(|e| fail("a key id", &e))?,
        fstp_crypto::aead::Key::generate().map_err(|e| fail("the vault data key", &e))?,
        fstp_crypto::random_array::<32>().map_err(|e| fail("the vault digest key", &e))?,
    );
    let clock = WorldClock::default();
    if let Some(d) = dev {
        clock.set(d.clock_start);
    }
    let mail = crate::world_mail::WorldMail::default();
    // The control plane's operator ticket key (design section 8.5). In
    // production it is a ControlPlane chain key held in custody.
    let operator = OperatorSigner(std::sync::Arc::new(
        fstp_crypto::composite::generate().map_err(|e| fail("the operator ticket key", &e))?,
    ));
    let vault =
        s.rt.block_on(crate::seeded_vault::SeededVault::start(
            s.rt.clone(),
            crate::seeded_vault::SeededParts {
                cell,
                db: pg_config(
                    vault_cluster.server(),
                    &vault_db,
                    &login(CellDatabase::Vault, RoleName::Vault)?,
                )?,
                // I-83: the vault reads the OU and the SPKI from its live
                // connection and looks the SPKI up in this registration.
                registered_servers: server_keys
                    .iter()
                    .map(|(digest, kind)| fstp_vault::service::RegisteredSpki {
                        digest: *digest,
                        role: match kind {
                            ClusterKind::Application => fstp_vault::start::ClusterRole::Application,
                            ClusterKind::Vault => fstp_vault::start::ClusterRole::Vault,
                            ClusterKind::Control | ClusterKind::Witness => {
                                fstp_vault::start::ClusterRole::Other
                            }
                        },
                    })
                    .collect(),
                sealer: std::sync::Arc::new(sealer),
                ticket_keys: vec![ticket.public_key()],
                internal_tls: server(&vault_internal, Some(&cell_ca.pem))
                    .map_err(tls_err("the vault internal TLS"))?,
                tunnel_tls: fstp_cell::http::tunnel::TunnelTls {
                    tunnel: std::sync::Arc::new(
                        server(&vault_tunnel, Some(&s.control.pem))
                            .map_err(tls_err("the vault tunnel TLS"))?,
                    ),
                    origin: std::sync::Arc::new(
                        server(&vault_origin, None).map_err(tls_err("the vault origin TLS"))?,
                    ),
                },
                origin_host: vault_host.clone(),
                clock: clock.clone(),
                chain: Some(vault_chain),
            },
        ))
        .map_err(|e| fail("the vault", &e))?;
    // Step 3: the cell.
    let cell_app = cell_ca.issue(
        CertKind::Client,
        "cell-app",
        Some(fstp_vault::service::CELL_APP_OU),
        &[],
        &[],
    )?;
    let cell_witness = cell_ca.issue(
        CertKind::Client,
        "cell-witness",
        Some(fstp_witness::peer::OU_CELL_WITNESS),
        &[],
        &[],
    )?;
    let cell_cp = cell_ca.issue(CertKind::Client, "cell-control-plane", None, &[], &[])?;
    // Lane F-ISO: the cell reaches its vault, its witness and the control
    // plane through recording relays ([`crate::relay`]).
    let relays = match start_relays(
        s,
        egress,
        index,
        &cell_ca,
        &witness,
        RelayUpstreams {
            vault: vault.internal_addr(),
            vault_client: (&cell_app, &cell_ca.pem),
            witness_client: &cell_witness,
            control_plane: !spec.self_hosted,
        },
    ) {
        Ok(r) => r,
        Err(e) => {
            let _ = s.rt.block_on(vault.shutdown(CELL_DRAIN));
            return Err(e);
        }
    };
    let vault_client = fstp_cell::vault::HttpVaultClient::new(
        s.rt.clone(),
        format!("https://{}", relays.vault),
        fstp_tls::ClientConfig::mutual(&cell_ca.pem, &cell_app.cert_pem, &cell_app.key_pem)
            .map_err(tls_err("the vault client TLS"))?,
    );
    let control_plane = match relays.control_plane {
        Some(addr) => Some(fstp_cell::control::ControlPlaneEndpoint {
            addr,
            server_name: CONTROL_PLANE_NAME.to_owned(),
            tls: fstp_tls::ClientConfig::mutual(
                &s.control.pem,
                &cell_cp.cert_pem,
                &cell_cp.key_pem,
            )
            .map_err(tls_err("the control plane client TLS"))?,
        }),
        None => None,
    };
    let witness_endpoint = fstp_cell::witness::link::WitnessEndpoint {
        addr: relays.witness,
        server_name: witness.name.clone(),
        tls: fstp_tls::ClientConfig::mutual(
            &witness.ca_pem,
            &cell_witness.cert_pem,
            &cell_witness.key_pem,
        )
        .map_err(tls_err("the witness client TLS"))?,
        ca_digest: witness.ca_digest,
    };
    let cell_tunnel =
        s.control
            .issue(CertKind::Server, &tunnel_name, None, &[&tunnel_name], &[])?;
    let cell_origin = with_ca(
        s.origin
            .issue(CertKind::Server, &host, None, &[&host], &[])?,
    );
    let cell_internal = cell_ca.issue(CertKind::Server, "cell", None, &[], &loopback)?;
    let ledger_key = fstp_pgstore::LedgerKey::new(
        1,
        fstp_keys::DekId(fstp_crypto::random_array::<16>().map_err(|e| fail("a key id", &e))?),
        fstp_crypto::aead::Key::generate().map_err(|e| fail("the ledger key", &e))?,
    );
    let parts = fstp_cell::process::CellProcessParts {
        cell,
        mode: if spec.self_hosted {
            fstp_cell::config::Mode::SelfHosted
        } else {
            fstp_cell::config::Mode::Saas
        },
        host: host.clone(),
        writer: pg_config(
            app_cluster.server(),
            &app_db,
            &login(CellDatabase::App, RoleName::Writer)?,
        )?,
        app: pg_config(
            app_cluster.server(),
            &app_db,
            &login(CellDatabase::App, RoleName::App)?,
        )?,
        // I-83: the cell reads the OU and the SPKI from its live
        // connections and looks each SPKI up in this registration.
        registered_servers: server_keys
            .iter()
            .map(|(digest, kind)| fstp_cell::process::RegisteredSpki {
                digest: *digest,
                role: match kind {
                    ClusterKind::Application => ClusterRole::Application,
                    ClusterKind::Vault => ClusterRole::Vault,
                    ClusterKind::Control | ClusterKind::Witness => ClusterRole::Other,
                },
            })
            .collect(),
        custody: custody.clone(),
        keystore: None,
        keys: fstp_cell::process::CellKeys {
            anchor,
            ledger: std::sync::Arc::new(fstp_pgstore::LedgerKeys::new(ledger_key)),
            cred_lookup: fstp_crypto::random_array::<32>()
                .map_err(|e| fail("the CredLookup key", &e))?,
        },
        witness: witness_endpoint,
        witness_keys: vec![witness.handle.receipt_public_key()],
        vault: SharedVault(std::sync::Arc::new(vault_client)),
        tunnel_tls: fstp_cell::http::tunnel::TunnelTls {
            tunnel: std::sync::Arc::new(
                server(&cell_tunnel, Some(&s.control.pem))
                    .map_err(tls_err("the cell tunnel TLS"))?,
            ),
            origin: std::sync::Arc::new(
                server(&cell_origin, None).map_err(tls_err("the cell origin TLS"))?,
            ),
        },
        internal_tls: std::sync::Arc::new(
            server(&cell_internal, Some(&cell_ca.pem)).map_err(tls_err("the cell internal TLS"))?,
        ),
        pages: pages.cloned(),
        listen: fstp_cell::process::Listen {
            tunnel: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            internal: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            health: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        },
    };
    // The fault point of the cell's record store (lane F-ERASE).
    let backups = crate::backups::CellBackups::default();
    // Lane m3/licence-update: the cell's CrabNebula stand-in, its first
    // licence token and the clock of its release tasks.
    let release = match start_release_world(s, egress, index, &clock) {
        Ok(r) => r,
        Err(e) => {
            let _ = s.rt.block_on(vault.shutdown(CELL_DRAIN));
            return Err(e);
        }
    };
    let options = fstp_cell::process::StartOptions {
        clock: clock.commit_clock(),
        creator_shell: std::sync::Arc::new(crate::world_shell::WorldShell),
        proof_mail: std::sync::Arc::new(mail.clone()),
        operator_key: Some(operator.0.public_key().to_bytes().to_vec()),
        // P-70: the world's tenant enables magic links, as the auth
        // machines' universe does (`mc::auth_model::ENABLED`).
        login_methods: fstp_auth::EnabledMethods {
            methods: vec![fstp_auth::Method::MagicLink],
        },
        control_plane,
        fault_point: Some(backups.fault().clone()),
        crabnebula: Some(fstp_cell::egress::SharedCnTransport::new(
            release.standin.transport(),
        )),
        licence: Some(release.first.clone()),
        release_clock: Some(release.clock()),
    };
    let restart = match RestartParts::of(&parts, &options) {
        Ok(r) => r,
        Err(e) => {
            let _ = s.rt.block_on(vault.shutdown(CELL_DRAIN));
            return Err(e);
        }
    };
    let running = match s
        .rt
        .block_on(fstp_cell::process::start_with(&s.rt, parts, options))
    {
        Ok(r) => r,
        Err(e) => {
            let _ = s.rt.block_on(vault.shutdown(CELL_DRAIN));
            return Err(fail("the cell", &e));
        }
    };
    let bound = running.bound();
    // Step 4: the routes.
    let route = || -> Result<(), WorldError> {
        let h = fstp_edge::HostName::parse(host.as_bytes())
            .map_err(|e| fail("the host", &format!("{e:?}")))?;
        lock(&s.edge.table)
            .add_cell(
                h,
                fstp_edge::CellEndpoint {
                    cell,
                    address: bound.tunnel,
                    tls_name: tunnel_name.clone(),
                },
                fstp_edge::CellEndpoint {
                    cell,
                    address: vault.origin_addr(),
                    tls_name: vault_tunnel_name.clone(),
                },
            )
            .map_err(|e| fail("the routes", &format!("{e:?}")))
    };
    // Step 5: the first admin's invitation.
    let invitation = route().and_then(|()| {
        s.rt.block_on(running.issue_first_admin_invitation())
            .map_err(|e| fail("the first admin invitation", &e))
            .and_then(|t| match (t.second, spec.self_hosted) {
                (Some(second), false) => Ok(Invitation::Split(FirstAdminInvitation {
                    first: t.first,
                    second,
                })),
                // A self-hosted install hands the token over whole, in its
                // token file (design section 8.3, Q35).
                (None, true) => Ok(Invitation::Whole(t.first)),
                (Some(_), true) => Err(WorldError::Store(format!(
                    "cell {index}: a self-hosted invitation came in halves"
                ))),
                (None, false) => Err(WorldError::Store(format!(
                    "cell {index}: a SaaS invitation came whole"
                ))),
            })
    });
    // A self-hosted install writes its configuration and credential
    // files once the token exists (design section 9.5, R-NF-05).
    let invitation = invitation.and_then(|i| match (&witness.local, &i) {
        (Some(local), Invitation::Whole(token)) => {
            write_install_files(&local.dir, &host, &logins, token).map(|()| i)
        }
        _ => Ok(i),
    });
    let invitation = match invitation {
        Ok(i) => i,
        Err(e) => {
            let _ = s.rt.block_on(running.shutdown(CELL_DRAIN));
            let _ = s.rt.block_on(vault.shutdown(CELL_DRAIN));
            lock(&s.edge.table).remove_cell_by_id(&cell);
            return Err(e);
        }
    };
    // The first admin's login email, as the tenant contact's address that
    // provisioning names (lane m3/login-m2http). Synthetic.
    let first_admin = {
        use fstp_auth::ceremony::{split_token_digest, token_digest};
        use fstp_auth::codec::Token;
        let digest = match &invitation {
            Invitation::Split(i) => split_token_digest(&Token(i.first), &Token(i.second)),
            Invitation::Whole(t) => token_digest(&Token(*t)),
        };
        let email = login_email_of(&host, fstp_domain_testkit::r#gen::roster::ADMIN);
        running.note_first_admin_email(digest, email.clone());
        (digest, email)
    };
    Ok(CellHandle {
        index,
        id: cell,
        host,
        logins,
        clock,
        mail,
        operator,
        cycle: Mutex::new(None),
        backups,
        ticket: TicketSigner(std::sync::Arc::new(ticket)),
        responses: crate::responses::ResponseLog::default(),
        runtime: Some(std::sync::Arc::new(CellRuntime {
            services: s,
            running: Mutex::new(Running {
                cell: Some(running),
                vault,
                invitation,
            }),
            health: bound.health,
            witness,
            relays: Mutex::new(relays.relays),
            custody,
            restart: RestartParts {
                first_admin,
                ..restart
            },
            release,
        })),
    })
}

/// One vault client shared by the cell's engine and its first start.
#[derive(Clone)]
struct SharedVault(std::sync::Arc<fstp_cell::vault::HttpVaultClient<Rt>>);

impl fstp_cell::engine::VaultClient for SharedVault {
    fn epoch(
        &self,
    ) -> impl std::future::Future<
        Output = Result<fstp_domain::id::VaultEpoch, fstp_cell_core::driver::VaultFault>,
    > + Send {
        let v = std::sync::Arc::clone(&self.0);
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

/// One HTTP/1.1 exchange over `stream`: `req` with `Connection: close`,
/// then the whole answer.
async fn exchange<S: fstp_rt::Connection>(
    mut stream: S,
    req: &HttpRequest,
) -> Result<HttpReply, WorldError> {
    use fstp_rt::IoExt as _;
    let fail =
        |what: &str, e: &dyn fmt::Display| WorldError::Store(format!("the exchange: {what}: {e}"));
    let method =
        fstp_http::Method::from_bytes(req.method.as_bytes()).map_err(|e| fail("the method", &e))?;
    let target = fstp_http::RequestTarget::origin(&req.path).map_err(|e| fail("the path", &e))?;
    let mut r = fstp_http::Request::new(method.clone(), target);
    for (name, value) in &req.headers {
        r = r
            .try_with_header(name, value.clone())
            .map_err(|e| fail("a header", &e))?;
    }
    r = r
        .try_with_header("connection", "close")
        .map_err(|e| fail("a header", &e))?;
    r.body = req.body.clone();
    let mut bytes = Vec::new();
    fstp_http::encode_request(&r, fstp_http::Framing::ContentLength, &mut bytes)
        .map_err(|e| fail("the request", &e))?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|e| fail("the write", &e))?;
    stream.flush().await.map_err(|e| fail("the write", &e))?;
    let mut answer = Vec::new();
    let _ = stream.read_to_end(&mut answer, 32 << 20).await;
    let limits = fstp_http::Limits {
        max_body_bytes: 16 << 20,
        ..fstp_http::Limits::default()
    };
    match fstp_http::parse_response(&answer, &method, &limits, true)
        .map_err(|e| fail("the answer", &e))?
    {
        fstp_http::Parsed::Complete { message, .. } => Ok(HttpReply {
            status: message.status.as_u16(),
            headers: message
                .headers
                .iter()
                .map(|(n, v)| (n.as_str().to_owned(), v.as_bytes().to_vec()))
                .collect(),
            body: message.body,
        }),
        fstp_http::Parsed::Incomplete => Err(WorldError::Store(
            "the exchange: the answer ended early".to_owned(),
        )),
    }
}

/// How long one exchange with a world listener may take.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(60);

impl CellRuntime {
    /// Sends `req` through the edge with `host` as SNI, as a browser does.
    fn request(&self, host: &str, req: &HttpRequest) -> Result<HttpReply, WorldError> {
        use fstp_rt::Runtime as _;
        let s = self.services;
        let tls = fstp_tls::ClientConfig::new(&s.origin.pem)
            .map_err(|e| WorldError::Store(format!("the browser TLS: {e}")))?;
        let addr = s.edge.addr;
        let host = host.to_owned();
        let req = req.clone();
        s.rt.block_on(async {
            let run = async {
                let tcp =
                    s.rt.connect_tcp(addr)
                        .await
                        .map_err(|e| WorldError::Store(format!("the edge: {e}")))?;
                let stream = fstp_tls::connect(&tls, &host, tcp)
                    .await
                    .map_err(|e| WorldError::Store(format!("the cell TLS: {e}")))?;
                exchange(stream, &req).await
            };
            fstp_rt::timeout(&s.rt, EXCHANGE_TIMEOUT, run)
                .await
                .map_err(|_| WorldError::Store("the exchange timed out".to_owned()))?
        })
    }

    /// Sends `req` to the loopback health listener over plain HTTP.
    fn health(&self, req: &HttpRequest) -> Result<HttpReply, WorldError> {
        use fstp_rt::Runtime as _;
        let s = self.services;
        let addr = self.health;
        let req = req.clone();
        s.rt.block_on(async {
            let run = async {
                let tcp =
                    s.rt.connect_tcp(addr)
                        .await
                        .map_err(|e| WorldError::Store(format!("the health listener: {e}")))?;
                exchange(tcp, &req).await
            };
            fstp_rt::timeout(&s.rt, EXCHANGE_TIMEOUT, run)
                .await
                .map_err(|_| WorldError::Store("the exchange timed out".to_owned()))?
        })
    }

    /// Whether `127.0.0.1:443` reaches this world's edge for `host`: a TLS
    /// handshake there for `host` verifies under the world's origin CA,
    /// which only this process's cells hold certificates of.
    fn port_443_reaches_edge(&self, host: &str) -> bool {
        use fstp_rt::Runtime as _;
        let s = self.services;
        if s.edge.addr.port() == 443 {
            return true;
        }
        let Ok(tls) = fstp_tls::ClientConfig::new(&s.origin.pem) else {
            return false;
        };
        let host = host.to_owned();
        s.rt.block_on(async {
            let probe = async {
                let tcp =
                    s.rt.connect_tcp(SocketAddr::from((Ipv4Addr::LOCALHOST, 443)))
                        .await
                        .ok()?;
                fstp_tls::connect(&tls, &host, tcp).await.ok()
            };
            matches!(
                fstp_rt::timeout(&s.rt, Duration::from_secs(5), probe).await,
                Ok(Some(_))
            )
        })
    }
}

/// The environment variable that names the `tsc` output directory of
/// `web/src/auth`, when it is not `web/dist/auth` of the workspace.
pub const AUTH_PAGES_ENV: &str = "FSTP_AUTH_PAGES";

/// The compiled auth pages a world cell serves on its origin (design
/// section 11.2): the `tsc` output of `web/src/auth` in
/// [`AUTH_PAGES_ENV`] or `web/dist/auth`, with the shell and stylesheet
/// of `web/src/auth` (`fstp_cell::http::pages::Pages::load`).
/// `tools/devstack/run.sh` compiles them with the pinned `tsc`.
///
/// `cargo test` never runs Node (design section 11.2), so a compiled
/// directory may be absent: that is `Ok(None)`, and a cell then serves no
/// page. [`World::start_with_pages`] passes these pages to each cell it
/// starts, whose front is `fstp_cell::http::Front::with_pages` over them.
///
/// # Errors
///
/// A compiled directory that exists but does not load, as
/// `fstp_cell::http::pages::PagesError` names it.
pub fn auth_pages() -> Result<Option<fstp_cell::http::pages::Pages>, WorldError> {
    use crate::mc::place_model::db;
    let web = db::workspace_root().join("web");
    let compiled = std::env::var_os(AUTH_PAGES_ENV)
        .map_or_else(|| web.join("dist").join("auth"), std::path::PathBuf::from);
    if !compiled.is_dir() {
        return Ok(None);
    }
    fstp_cell::http::pages::Pages::load(&compiled, &web.join("src").join("auth"))
        .map(Some)
        .map_err(|e| WorldError::Store(format!("the compiled auth pages: {e}")))
}

/// One database of a world's cluster.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorldDatabase {
    /// The cluster's name, the first part of its store names.
    pub cluster: String,
    /// The cluster's kind.
    pub kind: ClusterKind,
    /// The database name.
    pub name: String,
    /// The database oid, which names its directory under `base`.
    pub oid: u32,
}

impl WorldDatabase {
    /// Whether the store named `store` holds this database's data alone:
    /// one of its relation files (`<cluster>/data/base/<oid>/...`) or its
    /// logical dump (`<cluster>/dump/<name>`). The other stores of a
    /// cluster, such as its WAL, `global` catalog and server log, are
    /// shared by every database on it.
    #[must_use]
    pub fn owns(&self, store: &str) -> bool {
        store.starts_with(&format!("{}/data/base/{}/", self.cluster, self.oid))
            || store == format!("{}/dump/{}", self.cluster, self.name)
    }
}

/// The clusters of a world, as `(kind, server name)` pairs in start order.
///
/// - SaaS, shared mode: one cluster of each kind, named [`kind_label`].
/// - SaaS, dedicated mode: `application_<i>` and `vault_<i>` for each cell
///   `i`, then `control` and `witness`.
/// - Self-hosted, either mode: `selfhosted_application` and
///   `selfhosted_vault`, two instances of its own (design section 1.4).
///   Its witness keeps a file store.
#[must_use]
pub fn cluster_plan(spec: &WorldSpec) -> Vec<(ClusterKind, String)> {
    let named = |kind: ClusterKind| (kind, kind_label(kind).to_owned());
    if spec.self_hosted {
        return SELF_HOSTED_KINDS
            .iter()
            .map(|k| (*k, format!("selfhosted_{}", kind_label(*k))))
            .collect();
    }
    match spec.mode {
        DbMode::Shared => SAAS_KINDS.iter().map(|k| named(*k)).collect(),
        DbMode::Dedicated => {
            let mut out = Vec::new();
            for i in 0..spec.cells {
                for kind in [ClusterKind::Application, ClusterKind::Vault] {
                    out.push((kind, format!("{}_{i}", kind_label(kind))));
                }
            }
            out.push(named(ClusterKind::Control));
            out.push(named(ClusterKind::Witness));
            out
        }
    }
}

/// The install slot of a live self-hosted world. Two self-hosted worlds
/// alive at once are two installs, so each takes the lowest free slot and
/// runs instances of its own ([`install_cluster_plan`]). The slot is free
/// again when the world drops.
#[derive(Debug)]
struct InstallSlot(u32);

/// The slots of the live self-hosted worlds of the process.
fn install_slots() -> &'static Mutex<std::collections::BTreeSet<u32>> {
    static SLOTS: OnceLock<Mutex<std::collections::BTreeSet<u32>>> = OnceLock::new();
    SLOTS.get_or_init(Mutex::default)
}

impl InstallSlot {
    fn take() -> InstallSlot {
        let mut slots = lock(install_slots());
        let free = (0u32..).find(|n| !slots.contains(n)).unwrap_or(u32::MAX);
        slots.insert(free);
        InstallSlot(free)
    }
}

impl Drop for InstallSlot {
    fn drop(&mut self) {
        lock(install_slots()).remove(&self.0);
    }
}

/// The clusters a world starts: [`cluster_plan`], except that a
/// self-hosted world in install slot `k > 0` names its instances
/// `selfhosted<k>_<kind>`. So a second live install never shares the
/// first one's servers (R-NF-05).
fn install_cluster_plan(
    spec: &WorldSpec,
    slot: Option<&InstallSlot>,
) -> Vec<(ClusterKind, String)> {
    match slot {
        Some(InstallSlot(k)) if *k > 0 => SELF_HOSTED_KINDS
            .iter()
            .map(|kind| (*kind, format!("selfhosted{k}_{}", kind_label(*kind))))
            .collect(),
        _ => cluster_plan(spec),
    }
}

/// The clusters of a SaaS world in shared mode (design section 1.4).
const SAAS_KINDS: [ClusterKind; 4] = [
    ClusterKind::Application,
    ClusterKind::Vault,
    ClusterKind::Control,
    ClusterKind::Witness,
];

/// The clusters of a self-hosted world: two PostgreSQL instances on one
/// node. Its witness keeps a file store (design sections 1.4 and 2.1).
const SELF_HOSTED_KINDS: [ClusterKind; 2] = [ClusterKind::Application, ClusterKind::Vault];

/// The stores of one cluster, each named `<name>/...`:
///
/// - each regular file under the cluster's directory, as
///   `<name>/<relative path>`: relation files, the server log, and the
///   rest. A WAL segment (`<name>/data/pg_wal/<segment>`) is stored with
///   its page headers removed ([`wal_record_view`]), so a record that
///   crosses a page boundary is contiguous;
/// - a logical dump of each database that takes connections, as
///   `<name>/dump/<database>` ([`fstp_pgtest::PgServer::dump_data`]): the
///   rows of every table and populated materialized view, and every large
///   object. The raw files cannot show a value PostgreSQL compressed or
///   split into TOAST chunks. The dump shows it whole. The scanner reads
///   its COPY rows decoded ([`crate::scan`]).
///
/// The server runs a CHECKPOINT first, so the files hold every write
/// committed before the call. A value that survives only in the WAL in
/// compressed form is not decoded. Such WAL-only remnants are scanned on a
/// best-effort basis.
///
/// # Errors
///
/// Fails when the CHECKPOINT fails, when a file or directory cannot be
/// read for any reason other than having been removed meanwhile, or when
/// a database that still exists cannot be dumped.
pub fn cluster_stores(name: &str, server: &fstp_pgtest::PgServer) -> Result<StoreSet, WorldError> {
    let store_err =
        |what: &str, e: &dyn fmt::Display| WorldError::Store(format!("{name}: {what}: {e}"));
    server
        .psql("postgres", "CHECKPOINT")
        .map_err(|e| store_err("CHECKPOINT failed", &e))?;
    let block = server
        .psql("postgres", "SHOW wal_block_size")
        .map_err(|e| store_err("cannot read wal_block_size", &e))?;
    let block: usize = block
        .parse()
        .map_err(|e| store_err("bad wal_block_size", &e))?;
    let mut set = StoreSet::default();
    let root = server.dir();
    let files = FileWalk {
        root,
        prefix: name,
        wal_block: block,
    };
    files.collect(root, &mut set)?;
    for (_, dbname) in list_databases(name, server)? {
        if let Some(dump) = dump_database(name, server, &dbname)? {
            set.push(format!("{name}/dump/{dbname}"), dump);
        }
    }
    Ok(set)
}

/// The `(oid, name)` of every database of `server` that takes
/// connections, by name.
fn list_databases(
    name: &str,
    server: &fstp_pgtest::PgServer,
) -> Result<Vec<(u32, String)>, WorldError> {
    let rows = server
        .psql(
            "postgres",
            "SELECT oid::text || ' ' || datname FROM pg_database \
             WHERE datallowconn ORDER BY datname",
        )
        .map_err(|e| WorldError::Store(format!("{name}: cannot list databases: {e}")))?;
    rows.lines()
        .map(|line| {
            let (oid, db) = line
                .split_once(' ')
                .ok_or_else(|| WorldError::Store(format!("{name}: bad database row {line:?}")))?;
            let oid = oid
                .parse()
                .map_err(|_| WorldError::Store(format!("{name}: bad database oid {oid:?}")))?;
            Ok((oid, db.to_owned()))
        })
        .collect()
}

/// How often a dump is tried before a failure counts.
const DUMP_ATTEMPTS: u32 = 3;

/// The logical dump of `dbname`, or `None` when the database was dropped
/// meanwhile. A failed dump is retried, since another test may drop a
/// table while it runs. A dump blocked by a lock fails after
/// [`fstp_pgtest::DUMP_LOCK_WAIT`], so a test that holds a lock
/// gets an error and never a hang.
fn dump_database(
    name: &str,
    server: &fstp_pgtest::PgServer,
    dbname: &str,
) -> Result<Option<Vec<u8>>, WorldError> {
    let mut last = String::new();
    for _ in 0..DUMP_ATTEMPTS {
        match server.dump_data(dbname) {
            Ok(dump) => return Ok(Some(dump)),
            Err(e) => last = e.to_string(),
        }
        let still = server
            .psql(
                "postgres",
                &format!(
                    "SELECT count(*) FROM pg_database WHERE datname = '{}'",
                    dbname.replace('\'', "''")
                ),
            )
            .map_err(|e| WorldError::Store(format!("{name}: {e}")))?;
        if still == "0" {
            return Ok(None);
        }
    }
    Err(WorldError::Store(format!(
        "{name}: cannot dump {dbname}: {last}"
    )))
}

/// The size of the long WAL page header, on the first page of a segment
/// (`SizeOfXLogLongPHD`, PostgreSQL 16 on a 64-bit host).
pub const WAL_LONG_HEADER: usize = 40;

/// The size of the short WAL page header, on every other page
/// (`SizeOfXLogShortPHD`).
pub const WAL_SHORT_HEADER: usize = 24;

/// A WAL segment with its page headers removed: the first
/// [`WAL_LONG_HEADER`] bytes of the first page and the first
/// [`WAL_SHORT_HEADER`] bytes of each later page of `block` bytes. A
/// record that continues on the next page continues right after that
/// page's header, so the view holds it contiguous. The view reads no
/// header field. A `block` too small to hold a header leaves the segment
/// as it is.
#[must_use]
pub fn wal_record_view(segment: &[u8], block: usize) -> Vec<u8> {
    if block <= WAL_LONG_HEADER {
        return segment.to_vec();
    }
    let mut out = Vec::with_capacity(segment.len());
    for (i, page) in segment.chunks(block).enumerate() {
        let header = if i == 0 {
            WAL_LONG_HEADER
        } else {
            WAL_SHORT_HEADER
        };
        out.extend_from_slice(page.get(header..).unwrap_or_default());
    }
    out
}

/// Whether `rel` is a WAL segment file: `data/pg_wal/` and 24 uppercase
/// hex digits.
fn is_wal_segment(rel: &Path) -> bool {
    let Some(file) = rel.file_name().and_then(|f| f.to_str()) else {
        return false;
    };
    rel.parent() == Some(Path::new("data/pg_wal"))
        && file.len() == 24
        && file.bytes().all(|b| matches!(b, b'0'..=b'9' | b'A'..=b'F'))
}

/// A walk over a cluster directory.
struct FileWalk<'a> {
    root: &'a Path,
    prefix: &'a str,
    wal_block: usize,
}

impl FileWalk<'_> {
    /// Adds every regular file under `dir` to `set`, named by the prefix
    /// and the path relative to the root. Only an entry removed while the
    /// walk runs is skipped, such as a recycled WAL segment or a dropped
    /// database. Every other error fails the walk.
    fn collect(&self, dir: &Path, set: &mut StoreSet) -> Result<(), WorldError> {
        let fail =
            |path: &Path, e: &std::io::Error| WorldError::Store(format!("{}: {e}", path.display()));
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == ErrorKind::NotFound && dir != self.root => return Ok(()),
            Err(e) => return Err(fail(dir, &e)),
        };
        let mut paths = Vec::new();
        for entry in entries {
            match entry {
                Ok(entry) => paths.push(entry.path()),
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => return Err(fail(dir, &e)),
            }
        }
        paths.sort();
        for path in paths {
            let meta = match std::fs::symlink_metadata(&path) {
                Ok(meta) => meta,
                Err(e) if e.kind() == ErrorKind::NotFound => continue,
                Err(e) => return Err(fail(&path, &e)),
            };
            if meta.is_dir() {
                self.collect(&path, set)?;
            } else if meta.is_file() {
                let bytes = match std::fs::read(&path) {
                    Ok(bytes) => bytes,
                    Err(e) if e.kind() == ErrorKind::NotFound => continue,
                    Err(e) => return Err(fail(&path, &e)),
                };
                let rel = path.strip_prefix(self.root).unwrap_or(&path);
                let bytes = if is_wal_segment(rel) {
                    wal_record_view(&bytes, self.wal_block)
                } else {
                    bytes
                };
                set.push(format!("{}/{}", self.prefix, rel.display()), bytes);
            }
        }
        Ok(())
    }
}

/// The label of a cluster kind: the subject OU of the cluster's server
/// certificate and the name of its shared test server in shared mode
/// (design sections 1.3 and 4.1).
pub fn kind_label(kind: ClusterKind) -> &'static str {
    match kind {
        ClusterKind::Application => "application",
        ClusterKind::Vault => "vault",
        ClusterKind::Control => "control",
        ClusterKind::Witness => "witness",
    }
}

/// One PostgreSQL cluster of a world, started through `fstp-pgtest` with
/// its own cluster CA (design section 14.1, "Real topology").
#[derive(Debug)]
pub struct ClusterHandle {
    kind: ClusterKind,
    name: String,
    server: &'static fstp_pgtest::PgServer,
}

impl ClusterHandle {
    /// The shared cluster of `kind` for this test binary, named
    /// [`kind_label`]. See [`ClusterHandle::start_named`].
    ///
    /// # Errors
    ///
    /// Returns the start error of the server.
    pub fn start(kind: ClusterKind) -> Result<ClusterHandle, WorldError> {
        ClusterHandle::start_named(kind, kind_label(kind))
    }

    /// The cluster `name` of `kind`, shared by every test in this test
    /// binary that asks for the same name. It starts on first use as the
    /// named server `name`, whose server certificate carries
    /// [`kind_label`] of `kind` as its subject OU. Several clusters of one
    /// kind, such as `application_0` and `application_1` in dedicated
    /// mode, are separate servers with separate cluster CAs.
    ///
    /// # Errors
    ///
    /// Returns the start error of the server, or the refusal of a name
    /// already started with another kind.
    pub fn start_named(kind: ClusterKind, name: &str) -> Result<ClusterHandle, WorldError> {
        let server = fstp_pgtest::PgServer::shared_named(name, kind_label(kind)).map_err(|e| {
            WorldError::Cluster {
                kind,
                message: e.to_string(),
            }
        })?;
        Ok(ClusterHandle {
            kind,
            name: name.to_owned(),
            server,
        })
    }

    /// The cluster's kind.
    pub fn kind(&self) -> ClusterKind {
        self.kind
    }

    /// The cluster's name: its server name and the first part of its store
    /// names.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The cluster's server.
    pub fn server(&self) -> &'static fstp_pgtest::PgServer {
        self.server
    }

    /// The login of the cluster's replication role [`REPLICATION_ROLE`],
    /// once a world with cells prepared the cluster ([`World::start`]).
    /// In production only the `fstp-backup` OS user can read it (design
    /// section 4.1).
    ///
    /// # Errors
    ///
    /// Fails when the cluster's state cannot be created.
    pub fn replication_login(&self) -> Result<Option<RoleLogin>, WorldError> {
        Ok(lock(cluster_state(&self.name)?).replication.clone())
    }
}

/// The synthetic login email of the model account `model` on the cell
/// host `host` (lane m3/login-m2http). No real address: the host is a
/// world host under the reserved `.test` name.
pub fn login_email_of(host: &str, model: fstp_domain::id::AccountId) -> String {
    format!("account-{}@{host}", model.raw())
}

/// The world's control-plane signer of recovery operator tickets. Its
/// debug form shows no key.
#[derive(Clone)]
struct OperatorSigner(std::sync::Arc<fstp_crypto::composite::CompositeSigningKey>);

impl fmt::Debug for OperatorSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OperatorSigner(..)")
    }
}

/// The cell's `Ticket` key in the world (design section 6.5, lane
/// m3/cycle-steps). Its debug form shows no key.
#[derive(Clone)]
struct TicketSigner(std::sync::Arc<fstp_crypto::sig::Ed25519SigningKey>);

impl fmt::Debug for TicketSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TicketSigner(..)")
    }
}

// ---------------------------------------------------------------------------
// Lane m3/licence-update: the CrabNebula stand-in of each cell, the clock
// of its release tasks, and the restart of a cell (I-38, I-39).

/// The names the stand-in's server certificate carries: both service
/// hosts (design section 10.1).
const CRABNEBULA_NAMES: [&str; 2] = [
    fstp_release::egress::LICENCE_HOST,
    fstp_release::egress::UPDATE_HOST,
];

/// How long a release step waits for the cell's call, in real time.
const RELEASE_WAIT: Duration = Duration::from_secs(90);

/// How often a release step reads the cell's release view.
const RELEASE_POLL: Duration = Duration::from_millis(20);

/// How far a release step moves the release clock to make both calls due
/// at once: a day after an answer, and at most a day of backoff after a
/// failure (`fstp_cell::tasks::release::Schedule`), and a second more.
const RELEASE_KICK_US: i64 = 86_400_000_000 + 1_000_000;

/// How long a release step waits in real time before it moves the
/// release clock past a call's timeout, so a call that the stand-in
/// never answers ends (`fstp_cell::tasks::release::CALL_TIMEOUT_US`).
const RELEASE_TIMEOUT_NUDGE: Duration = Duration::from_millis(500);

/// How long a release step waits in real time, with no call in flight
/// and no call of its kind seen, before it moves the release clock by a
/// day again.
const RELEASE_REKICK: Duration = Duration::from_secs(2);

/// The CrabNebula side of one world cell (lane m3/licence-update): its
/// stand-in, the licence token it issued first, and the offset of the
/// cell's release clock from the cell's own clock.
struct ReleaseWorld {
    standin: crate::crabnebula::StandIn<Rt>,
    first: fstp_cell::tasks::release::LicenceHold,
    clock: WorldClock,
    offset: std::sync::Arc<std::sync::atomic::AtomicI64>,
}

impl fmt::Debug for ReleaseWorld {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReleaseWorld")
            .field("standin", &self.standin)
            .finish_non_exhaustive()
    }
}

impl ReleaseWorld {
    /// The release clock: the cell's clock plus the offset.
    fn clock(&self) -> fstp_cell::engine::CommitClock {
        let c = self.clock.clone();
        let offset = std::sync::Arc::clone(&self.offset);
        std::sync::Arc::new(move || {
            c.now()
                .saturating_add(offset.load(std::sync::atomic::Ordering::SeqCst))
        })
    }

    /// Waits until no call of the cell is in flight, at most
    /// `RELEASE_WAIT`. In mode `timed-out` the stand-in never answers,
    /// so the release clock moves past the call timeout to end the call.
    fn settle(&self, mode: crate::crabnebula::Mode) {
        let timed_out = crate::crabnebula::Mode::Down(crate::crabnebula::Fault::TimedOut);
        let past_timeout = fstp_cell::tasks::release::CALL_TIMEOUT_US.saturating_add(1_000_000);
        let start = Instant::now();
        let mut nudged = Instant::now();
        while self.standin.in_flight() > 0 && start.elapsed() < RELEASE_WAIT {
            if mode == timed_out && nudged.elapsed() > RELEASE_TIMEOUT_NUDGE {
                self.advance(past_timeout);
                nudged = Instant::now();
            }
            std::thread::sleep(RELEASE_POLL);
        }
    }

    /// Moves the release clock forward by `micros`, never the cell's.
    fn advance(&self, micros: i64) {
        let _ = self.offset.fetch_update(
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
            |o| Some(o.saturating_add(micros.max(0))),
        );
    }
}

/// Starts the CrabNebula stand-in of world cell `index` (lane
/// m3/licence-update, [`crate::crabnebula`]). A CA of its own issues the
/// server certificate for both service hosts, and a second CA, which the
/// cell does not trust, the certificate of the `failed-tls` fault. The
/// licence service holds one noncommercial licence for the cell, and
/// its key is the one key the cell pins. The first token is issued at
/// the release clock's start, as the registration page would issue it
/// (design section 10.2, Q41).
fn start_release_world(
    s: &'static Services,
    egress: &EgressLog,
    index: u8,
    clock: &WorldClock,
) -> Result<ReleaseWorld, WorldError> {
    use fstp_pki::cert::CertKind;
    let fail = |what: &str, e: &dyn fmt::Display| {
        WorldError::Store(format!(
            "cell {index}: the CrabNebula stand-in: {what}: {e}"
        ))
    };
    let ca = pki::Ca::new("fstp world CrabNebula stand-in CA")?;
    let other = pki::Ca::new("fstp world untrusted CA")?;
    let name = fstp_release::egress::LICENCE_HOST;
    let good = ca.issue(CertKind::Server, name, None, &CRABNEBULA_NAMES, &[])?;
    let bad = other.issue(CertKind::Server, name, None, &CRABNEBULA_NAMES, &[])?;
    let server = |cert: &pki::Issued| {
        fstp_tls::ServerConfig::new(&cert.cert_pem, &cert.key_pem)
            .map_err(|e| fail("a server TLS", &e))
    };
    let key = fstp_crypto::sig::Ed25519SigningKey::generate().map_err(|e| fail("the key", &e))?;
    let pinned = fstp_release::licence::Ed25519Public(key.public_key());
    let mut id = [0u8; 16];
    fstp_crypto::random_bytes(&mut id).map_err(|_| fail("the licence id", &"randomness"))?;
    let licence = fstp_release::licence::LicenceId(id);
    let offset = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(0));
    let partial = ReleaseClockSource {
        clock: clock.clone(),
        offset: std::sync::Arc::clone(&offset),
    };
    let standin =
        s.rt.block_on(crate::crabnebula::start(
            s.rt.clone(),
            egress.clone(),
            crate::crabnebula::StandInParts {
                cell: index,
                server: server(&good)?,
                untrusted: server(&bad)?,
                client: fstp_tls::ClientConfig::new(&ca.pem)
                    .map_err(|e| fail("the client TLS", &e))?,
                licence,
                key,
                clock: std::sync::Arc::new(move || partial.now()),
            },
        ))
        .map_err(|e| fail("the start", &e))?;
    let now_s = clock.now().div_euclid(1_000_000);
    let token = standin
        .first_token(now_s)
        .map_err(|e| fail("the first token", &format!("{e:?}")))?;
    let keys = fstp_release::licence::KeySet::shipped(&[pinned])
        .map_err(|e| fail("the pinned key set", &format!("{e:?}")))?;
    Ok(ReleaseWorld {
        standin,
        first: fstp_cell::tasks::release::LicenceHold { token, keys },
        clock: clock.clone(),
        offset,
    })
}

/// The release clock as the stand-in reads it.
struct ReleaseClockSource {
    clock: WorldClock,
    offset: std::sync::Arc<std::sync::atomic::AtomicI64>,
}

impl ReleaseClockSource {
    fn now(&self) -> i64 {
        self.clock
            .now()
            .saturating_add(self.offset.load(std::sync::atomic::Ordering::SeqCst))
    }
}

/// What a world cell restarts from (lane m3/licence-update): every part
/// of its first start but the keystore, which the running cell hands
/// over, and the listen addresses, which the restarted cell binds again.
/// The composite `Anchor` key is kept as its encoded bytes, since the
/// key has no `Clone`. The world is test-only and its keys synthetic.
#[derive(Clone)]
struct RestartParts {
    cell: [u8; 16],
    mode: fstp_cell::config::Mode,
    host: String,
    writer: fstp_pgwire::Config,
    app: fstp_pgwire::Config,
    registered_servers: Vec<fstp_cell::process::RegisteredSpki>,
    custody: WorldCustody,
    anchor: Vec<u8>,
    ledger: std::sync::Arc<fstp_pgstore::LedgerKeys>,
    cred_lookup: [u8; 32],
    witness: fstp_cell::witness::link::WitnessEndpoint,
    witness_keys: Vec<Vec<u8>>,
    vault: SharedVault,
    tunnel_tls: fstp_cell::http::tunnel::TunnelTls,
    internal_tls: std::sync::Arc<fstp_tls::ServerConfig>,
    pages: Option<fstp_cell::http::pages::Pages>,
    options: fstp_cell::process::StartOptions,
    /// The first admin's invitation digest and login email, which the
    /// restarted cell notes again (`RunningCell::note_first_admin_email`).
    first_admin: ([u8; 32], String),
}

impl RestartParts {
    /// The restart parts of a first start from `parts` and `options`.
    fn of(
        parts: &fstp_cell::process::CellProcessParts<WorldCustody, SharedVault>,
        options: &fstp_cell::process::StartOptions,
    ) -> Result<RestartParts, WorldError> {
        let anchor = parts
            .keys
            .anchor
            .to_bytes()
            .map_err(|e| WorldError::Store(format!("the anchor key bytes: {e}")))?;
        Ok(RestartParts {
            cell: parts.cell,
            mode: parts.mode,
            host: parts.host.clone(),
            writer: parts.writer.clone(),
            app: parts.app.clone(),
            registered_servers: parts.registered_servers.clone(),
            custody: parts.custody.clone(),
            anchor: anchor.to_vec(),
            ledger: std::sync::Arc::clone(&parts.keys.ledger),
            cred_lookup: parts.keys.cred_lookup,
            witness: parts.witness.clone(),
            witness_keys: parts.witness_keys.clone(),
            vault: parts.vault.clone(),
            tunnel_tls: parts.tunnel_tls.clone(),
            internal_tls: std::sync::Arc::clone(&parts.internal_tls),
            pages: parts.pages.clone(),
            options: options.clone(),
            first_admin: ([0; 32], String::new()),
        })
    }

    /// The process parts of a restart over `keystore`, bound at `listen`.
    fn parts(
        &self,
        keystore: fstp_cell::tasks::erasure::Keystore,
        listen: fstp_cell::process::Listen,
    ) -> Result<fstp_cell::process::CellProcessParts<WorldCustody, SharedVault>, WorldError> {
        let anchor = fstp_crypto::composite::CompositeSigningKey::from_bytes(&self.anchor)
            .map_err(|e| WorldError::Store(format!("the anchor key: {e}")))?;
        Ok(fstp_cell::process::CellProcessParts {
            cell: self.cell,
            mode: self.mode,
            host: self.host.clone(),
            writer: self.writer.clone(),
            app: self.app.clone(),
            registered_servers: self.registered_servers.clone(),
            custody: self.custody.clone(),
            keystore: Some(keystore),
            keys: fstp_cell::process::CellKeys {
                anchor,
                ledger: std::sync::Arc::clone(&self.ledger),
                cred_lookup: self.cred_lookup,
            },
            witness: self.witness.clone(),
            witness_keys: self.witness_keys.clone(),
            vault: self.vault.clone(),
            tunnel_tls: self.tunnel_tls.clone(),
            internal_tls: std::sync::Arc::clone(&self.internal_tls),
            pages: self.pages.clone(),
            listen,
        })
    }
}

/// Which call a release step waits for.
pub use fstp_cell::tasks::release::CallKind;

/// The refusal of a release step on a SaaS cell, which never reaches a
/// CrabNebula host (B12, I-38).
pub const SAAS_RELEASE: &str = "fstp_celltest::world release steps: a SaaS cell runs no licence refresh or update check (B12), so the step has no call to wait for";

/// A release step that saw no call of its kind in time.
pub const RELEASE_NO_CALL: &str = "fstp_celltest::world release steps: the cell made no call of the kind in time (the attempts are on standard error)";

impl CellHandle {
    /// Restarts the cell (lane m3/licence-update): the running process
    /// drains and stops, and a new one starts over the same databases,
    /// with the keystore the old one held and the licence token it held
    /// last. The vault, the witness, the relays and the stand-in keep
    /// running. The new process binds the same listen addresses, so the
    /// edge routes and the health address stay valid.
    ///
    /// Claims, Interim, pending Daniel: the keystore passes in process,
    /// since the keystore tables are not built, and the licence token
    /// passes the same way, since the sealed licence store is not built.
    /// What `fstp_cell::routes::pg` keeps in process memory between two
    /// ceremony steps is lost, so a restart falls between cycle steps.
    ///
    /// # Errors
    ///
    /// Fails when the cell runs no process, the old one gives no keystore
    /// or does not stop, or the new one does not start.
    pub fn restart(&self) -> Result<(), WorldError> {
        let rt = self.runtime()?;
        let s = rt.services;
        let mut running = lock(&rt.running);
        let old = running
            .cell
            .take()
            .ok_or(WorldError::NotImplemented(NotImplemented::new(NOT_STARTED)))?;
        let keystore = s.rt.block_on(old.erasure().keystore());
        let hold = old.release().hold();
        let bound = old.bound();
        let stopped = s.rt.block_on(old.shutdown(CELL_DRAIN));
        let keystore = keystore.ok_or_else(|| {
            WorldError::Store("the restart: the old process gave no keystore".to_owned())
        })?;
        stopped.map_err(|e| WorldError::Store(format!("the restart: the old process: {e}")))?;
        let parts = rt.restart.parts(keystore, bound)?;
        let mut options = rt.restart.options.clone();
        if hold.is_some() {
            options.licence = hold;
        }
        let new =
            s.rt.block_on(fstp_cell::process::start_with(&s.rt, parts, options))
                .map_err(|e| WorldError::Store(format!("the restart: the new process: {e}")))?;
        let (digest, email) = &rt.restart.first_admin;
        new.note_first_admin_email(*digest, email.clone());
        running.cell = Some(new);
        Ok(())
    }

    /// The payment port's `RecordChecks` of `request`, issued in process
    /// (`fstp_cell::process::RunningCell::payment_checks`, lane
    /// m3/licence-update). It stands for the M5 checks runner, which the
    /// cell does not run yet. Claims built on it say so.
    ///
    /// # Errors
    ///
    /// Fails when the cell refused the checks or runs no process.
    pub fn payment_checks(
        &self,
        request: fstp_domain::id::RequestId,
        phase: fstp_domain::payment::CheckPhase,
        results: Vec<fstp_domain::payment::CheckResult>,
        snapshot: fstp_domain::id::ContentDigest,
    ) -> Result<(), WorldError> {
        let rt = self.runtime()?;
        let running = lock(&rt.running);
        let cell = running
            .cell
            .as_ref()
            .ok_or(WorldError::NotImplemented(NotImplemented::new(NOT_STARTED)))?;
        rt.services
            .rt
            .block_on(cell.payment_checks(request, phase, results, snapshot))
            .map_err(|e| WorldError::Store(format!("the payment port's checks: {e}")))
    }

    /// The admin view of the cell's licence refresh and update check
    /// (`fstp_cell::tasks::release::ReleaseView`).
    ///
    /// # Errors
    ///
    /// Fails when the cell runs no process.
    pub fn release_view(&self) -> Result<fstp_cell::tasks::release::ReleaseView, WorldError> {
        let rt = self.runtime()?;
        let running = lock(&rt.running);
        running
            .cell
            .as_ref()
            .map(|c| c.release().clone())
            .ok_or(WorldError::NotImplemented(NotImplemented::new(NOT_STARTED)))
    }

    /// Sets how the cell's CrabNebula stand-in answers from now on
    /// (`services-down:<fault>`, I-39).
    ///
    /// # Errors
    ///
    /// Fails when the cell runs no process.
    pub fn set_crabnebula_mode(&self, mode: crate::crabnebula::Mode) -> Result<(), WorldError> {
        self.runtime()?.release.standin.set_mode(mode);
        Ok(())
    }

    /// The mode of the cell's CrabNebula stand-in.
    ///
    /// # Errors
    ///
    /// Fails when the cell runs no process.
    pub fn crabnebula_mode(&self) -> Result<crate::crabnebula::Mode, WorldError> {
        Ok(self.runtime()?.release.standin.mode())
    }

    /// Makes the cell's next licence refresh and update check due now,
    /// and waits until the cell made a call of `kind` (lane
    /// m3/licence-update). With `mode`, the stand-in answers in that mode
    /// until the call ended, then in its former mode again.
    ///
    /// The step moves the release clock, never the cell's own clock, by a
    /// day and a second: past the daily slot after an answer and past the
    /// longest backoff after a failure. Calls of earlier steps end first,
    /// and only a call that started after the move counts. While no call
    /// is in flight and none of its kind was seen, the step moves the
    /// clock again. In mode `timed-out` it moves the clock past the call
    /// timeout, so a call the stand-in never answers ends. A call made in
    /// mode up must be answered.
    ///
    /// # Errors
    ///
    /// [`SAAS_RELEASE`] on a SaaS cell, [`RELEASE_NO_CALL`] when no call
    /// of `kind` ended in time, and a store error for an unanswered call
    /// in mode up.
    pub fn release_call(
        &self,
        kind: CallKind,
        mode: Option<crate::crabnebula::Mode>,
    ) -> Result<fstp_cell::tasks::release::Attempt, WorldError> {
        use fstp_cell::tasks::release::Outcome;
        if self.runtime()?.restart.mode == fstp_cell::config::Mode::Saas {
            return Err(WorldError::NotImplemented(NotImplemented::new(
                SAAS_RELEASE,
            )));
        }
        let rt = self.runtime()?;
        let view = self.release_view()?;
        let former = rt.release.standin.mode();
        let used = mode.unwrap_or(former);
        let timed_out = crate::crabnebula::Mode::Down(crate::crabnebula::Fault::TimedOut);
        let past_timeout = fstp_cell::tasks::release::CALL_TIMEOUT_US.saturating_add(1_000_000);
        // Calls of earlier steps end first, in their own mode: a kick
        // would move the release clock past their timeout.
        rt.release.settle(former);
        let mut nudged = Instant::now();
        rt.release.standin.set_mode(used);
        rt.release.advance(RELEASE_KICK_US);
        // Only a call that started after the kick counts.
        let kick_at = (rt.release.clock())();
        let started = Instant::now();
        let mut kicked = Instant::now();
        let found = loop {
            if let Some(a) = view
                .attempts()
                .into_iter()
                .find(|a| a.kind == kind && a.started >= kick_at)
            {
                break Some(a);
            }
            if started.elapsed() > RELEASE_WAIT {
                break None;
            }
            let idle = rt.release.standin.in_flight() == 0;
            if used == timed_out && !idle && nudged.elapsed() > RELEASE_TIMEOUT_NUDGE {
                rt.release.advance(past_timeout);
                nudged = Instant::now();
            }
            // A call that ended just after the kick waits out its slot or
            // its backoff. With no call in flight, the next kick makes it
            // due again. A call in flight is never cut short by a kick.
            if idle && kicked.elapsed() > RELEASE_REKICK {
                rt.release.advance(RELEASE_KICK_US);
                kicked = Instant::now();
            }
            std::thread::sleep(RELEASE_POLL);
        };
        // The other call of the kick ends in the step's mode too.
        rt.release.settle(used);
        rt.release.standin.set_mode(former);
        let Some(attempt) = found else {
            eprintln!(
                "fstp_celltest::world release_call {kind:?}: attempts {:?}",
                view.attempts()
            );
            return Err(WorldError::NotImplemented(NotImplemented::new(
                RELEASE_NO_CALL,
            )));
        };
        if used == crate::crabnebula::Mode::Up && attempt.outcome != Outcome::Answered {
            return Err(WorldError::Store(format!(
                "the {kind:?} call in mode up was not answered: {attempt:?}"
            )));
        }
        Ok(attempt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wal_record_view_removes_page_headers() {
        let block = 64;
        let mut segment = Vec::new();
        segment.extend(std::iter::repeat_n(0xAA, WAL_LONG_HEADER));
        segment.extend(std::iter::repeat_n(b'a', block - WAL_LONG_HEADER));
        segment.extend(std::iter::repeat_n(0xBB, WAL_SHORT_HEADER));
        segment.extend(std::iter::repeat_n(b'b', block - WAL_SHORT_HEADER));
        let mut want = vec![b'a'; block - WAL_LONG_HEADER];
        want.extend(std::iter::repeat_n(b'b', block - WAL_SHORT_HEADER));
        assert_eq!(wal_record_view(&segment, block), want);
    }

    #[test]
    fn wal_segments_are_recognised_by_path() {
        assert!(is_wal_segment(Path::new(
            "data/pg_wal/000000010000000000000001"
        )));
        assert!(!is_wal_segment(Path::new("data/pg_wal/00000002.history")));
        assert!(!is_wal_segment(Path::new(
            "data/base/000000010000000000000001"
        )));
    }
}

#[cfg(test)]
mod review_tests {
    //! Independent review reproducers (lane W1a review). Each builds a
    //! world over the `fstp-pgtest` fixture server, which needs no minted
    //! certificate, and calls the production `World::stores`.

    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::canary::{Canary, CanaryKind};
    use crate::scan::scan;

    fn fixture_world() -> (World, &'static fstp_pgtest::PgServer) {
        world_on(fstp_pgtest::PgServer::shared().unwrap())
    }

    /// A world over a server of its own, so no other test's CHECKPOINT
    /// flushes its buffers. The server lives until the process exits.
    fn private_world() -> (World, &'static fstp_pgtest::PgServer) {
        world_on(Box::leak(Box::new(fstp_pgtest::PgServer::start().unwrap())))
    }

    fn world_on(server: &'static fstp_pgtest::PgServer) -> (World, &'static fstp_pgtest::PgServer) {
        let world = World {
            spec: WorldSpec {
                cells: 0,
                mode: DbMode::Shared,
                vault_layout: VaultLayout::SeparateCluster,
                self_hosted: false,
                process_mode: false,
            },
            cells: Vec::new(),
            clusters: vec![ClusterHandle {
                kind: ClusterKind::Vault,
                name: "vault".to_owned(),
                server,
            }],
            egress: EgressLog::new(),
            install: None,
            host: None,
        };
        (world, server)
    }

    /// I-19 instrument, design section 14.3: a committed row must be in
    /// the store of its own relation file, so a shared-mode scan can tell
    /// one cell's database from another's (the WAL is shared by both).
    /// `World::stores` reads the files without a CHECKPOINT, so the row
    /// still sits in shared buffers and the relation file lacks it.
    #[test]
    fn review_world_stores_hold_a_committed_row_in_its_relation_file() {
        let (world, server) = private_world();
        let c = Canary::generate(1, CanaryKind::Email).unwrap();
        let path = server
            .psql(
                "postgres",
                &format!(
                    "CREATE TABLE review_nockpt_{n} (v text);\n\
                     INSERT INTO review_nockpt_{n} VALUES ('{t}');\n\
                     SELECT pg_relation_filepath('review_nockpt_{n}');",
                    n = crate::canary::lower_hex(&c.nonce),
                    t = c.text()
                ),
            )
            .unwrap();
        let store = format!("vault/data/{path}");
        let report = scan(&world.stores().unwrap(), std::slice::from_ref(&c)).unwrap();
        assert!(
            report.hits.iter().any(|(s, _)| *s == store),
            "the committed canary is not in {store}; hits: {:?}",
            report.hits
        );
    }

    /// I-17, I-19 instrument, design sections 14.1 and 14.3: a proposal
    /// text canary inside a long, compressible text must be found in the
    /// store set. PostgreSQL stores such a value pglz-compressed, in the
    /// heap and in the WAL, so a raw file read never sees the canary
    /// bytes in one piece. The CHECKPOINT rules out the flush gap.
    #[test]
    fn review_world_stores_find_a_canary_in_a_compressed_value() {
        let (world, server) = fixture_world();
        let c = Canary::generate(1, CanaryKind::ProposalText).unwrap();
        let filler = "The applicant proposes a small study of local water use. ".repeat(80);
        server
            .psql(
                "postgres",
                &format!(
                    "CREATE TABLE IF NOT EXISTS review_compressed (v text);\n\
                     INSERT INTO review_compressed VALUES ('{filler}{t}{filler}');\n\
                     CHECKPOINT;",
                    t = c.text()
                ),
            )
            .unwrap();
        let report = scan(&world.stores().unwrap(), std::slice::from_ref(&c)).unwrap();
        assert!(
            !report.hits.is_empty(),
            "a canary inside a compressed value is invisible to World::stores"
        );
    }
}
