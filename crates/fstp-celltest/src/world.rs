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
//! Status after lane W3b: worlds without cells start. A world with cells
//! prepares each self-operated cluster and provisions each cell as
//! `fstp-control` and `fstp-pgagent` would, from the production role
//! plan, jobs, `pg_hba` renderer and migration sets ([`World::start`],
//! "Provisioning"). It then refuses with [`NotImplemented`], naming the
//! first production part that is still missing ([`World::start`],
//! "Cells").

use std::collections::BTreeMap;
use std::fmt;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr};
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
/// sends it. The harness adds no field: the caller sets `Host`, `Origin`,
/// `Cookie` and `Content-Type` itself, so a test controls every byte the
/// cell sees above TLS.
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
    /// edge listens on loopback port 443, since the relying party origin
    /// carries no port (I-20, [`CELL_FRONT_SEAM`]).
    pub cell: String,
    /// The vault origin through the same edge, `https://id.<host>/`.
    pub vault: String,
    /// The loopback health listener, `http://127.0.0.1:<port>/healthz`.
    pub health: String,
}

/// The seam of the transports and reads of a started cell (lane W3b).
/// A [`CellHandle`] exists only once [`World::start`] has started its
/// cell, so these refusals are never reached before the cell start of
/// lane W3b lands. That lane replaces each body.
const CELL_HANDLE_SEAM: &str =
    "fstp_celltest::world::CellHandle transports and reads of a started cell (lane W3b)";

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
}

impl CellHandle {
    /// The login of `role` on the cell's `db` database, as provisioning
    /// minted it. `None` for a role outside that database's plan.
    pub fn role_login(&self, db: CellDatabase, role: RoleName) -> Option<&RoleLogin> {
        self.logins.get(&(db, role))
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

    /// Sends `req` to the cell's tunnel listener, the way a browser
    /// reaches it: through the world's edge, with the cell host as SNI
    /// (design sections 1.4 and 9.4, ADR-009).
    ///
    /// # Errors
    ///
    /// Fails when the transport fails. A reply of any status is `Ok`.
    pub fn request(&self, req: &HttpRequest) -> Result<HttpReply, WorldError> {
        let _ = req;
        Err(WorldError::NotImplemented(NotImplemented::new(
            CELL_HANDLE_SEAM,
        )))
    }

    /// Where the cell's listeners are reached on this host.
    ///
    /// # Errors
    ///
    /// Fails when the cell runs no listener.
    pub fn urls(&self) -> Result<CellUrls, WorldError> {
        Err(WorldError::NotImplemented(NotImplemented::new(
            CELL_HANDLE_SEAM,
        )))
    }

    /// Sends `req` to the cell's loopback health listener (design section
    /// 2.3, ADR-009).
    ///
    /// # Errors
    ///
    /// Fails when the transport fails. A reply of any status is `Ok`.
    pub fn health(&self, req: &HttpRequest) -> Result<HttpReply, WorldError> {
        let _ = req;
        Err(WorldError::NotImplemented(NotImplemented::new(
            CELL_HANDLE_SEAM,
        )))
    }

    /// The first tenant admin's invitation, as the two staff channels
    /// carried it (design section 8.3). The cell drew it at provisioning
    /// (design section 9.2 step 10).
    ///
    /// # Errors
    ///
    /// Fails when the world did not receive both halves.
    pub fn first_admin_invitation(&self) -> Result<FirstAdminInvitation, WorldError> {
        Err(WorldError::NotImplemented(NotImplemented::new(
            CELL_HANDLE_SEAM,
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
        Err(WorldError::NotImplemented(NotImplemented::new(
            CELL_HANDLE_SEAM,
        )))
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
    /// cycle runs on it. This example is red until a cell starts (see
    /// "Cells" below).
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
    ///   migrator, as the `fstp-control` provisioning tests run them.
    ///   `fstp-celltest` cannot name `fstp-pgwire`, so it cannot run the
    ///   `fstp_migrate` runner, and the sets leave no `fstp_migrate` ledger.
    ///   The cell start needs that runner ([`start_cell`]).
    /// - The roles get LOGIN at creation, through `fstp-pgtest`. The
    ///   `SetRoleCredential` job is not played, since no SCRAM verifier
    ///   helper exists, so `CreateRoles` takes its branch for an existing
    ///   role.
    /// - The cluster ids are random per cluster and process. No
    ///   `cp.cluster`, `cp.cell` or `cp.job` row is written, since no
    ///   production code writes them yet.
    /// - The service roles of design section 4.1, such as `cp_service`
    ///   and `witness_service`, are not created. No world part runs a
    ///   service that would log in as one.
    ///
    /// # Cells
    ///
    /// Both cell databases provision completely, steps 4 to 7, with
    /// their placement rows and grant rows (lane int4). Past that, the
    /// `witness` service set has no migration directory, so the service
    /// databases refuse ([`missing_service_seam`]). Then a cell starts
    /// through `fstp_cell::engine::startup::start_pg`, whose production
    /// parts do not exist yet ([`start_cell`]). A world never stands in
    /// its own parts for them, so no sweep passes on the harness.
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
        let mut plans = Vec::with_capacity(usize::from(spec.cells));
        for _ in 0..spec.cells {
            plans.push(cell_plan()?);
        }
        let clusters = cluster_plan(&spec)
            .iter()
            .map(|(kind, name)| ClusterHandle::start_named(*kind, name))
            .collect::<Result<Vec<_>, _>>()?;
        let mut cells = Vec::with_capacity(plans.len());
        if !plans.is_empty() {
            for cluster in clusters.iter().filter(|c| is_agent_kind(c.kind())) {
                prepare_cluster(cluster)?;
            }
            match start_cells(&spec, &clusters, &plans, pages.as_ref()) {
                Ok(started) => cells = started,
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
            egress: EgressLog::new(),
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
    /// the world. Each step drives the cell's HTTP routes with the
    /// software authenticator, which lane W3a agent one and the slice of
    /// lane W3b build, so a script with steps refuses until they land.
    pub fn run_cycle(&self, cell: u8, script: &CycleScript) -> CycleReport {
        let result = if self.cell(cell).is_none() {
            Err(NotImplemented::new(
                "fstp_celltest::world::World::run_cycle on a cell the world does not hold",
            ))
        } else if script.steps.is_empty() {
            Ok(())
        } else {
            Err(NotImplemented::new(
                "fstp_celltest::world::World::run_cycle steps (the cell routes of lane W3a agent one and the slice of lane W3b)",
            ))
        };
        CycleReport { result }
    }

    /// Every database, object directory, log and metrics sink: each
    /// cluster's stores as [`cluster_stores`] gives them, and each egress
    /// connection per direction (`egress/...`).
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
        let mut set = StoreSet::default();
        for cluster in &self.clusters {
            for (name, bytes) in cluster_stores(cluster.name(), cluster.server())?.stores {
                set.push(name, bytes);
            }
        }
        for (name, bytes) in self.egress.store_set().stores {
            set.push(name, bytes);
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

    /// Every PostgreSQL cluster of the world, of every kind.
    pub fn clusters(&self) -> &[ClusterHandle] {
        &self.clusters
    }

    /// The world's first cluster of `kind`, if it has one.
    pub fn cluster(&self, kind: ClusterKind) -> Option<&ClusterHandle> {
        self.clusters.iter().find(|c| c.kind == kind)
    }

    /// The witness's receipt public keys, encoded, as each cell of the
    /// world pins them (ADR-010 "Keys", I-90). A test checks every stored
    /// receipt under this set.
    ///
    /// # Errors
    ///
    /// Fails when the world runs no witness.
    pub fn witness_keys(&self) -> Result<Vec<Vec<u8>>, WorldError> {
        Err(WorldError::NotImplemented(NotImplemented::new(
            WITNESS_SEAM,
        )))
    }

    /// Where the world's witness is reached on this host.
    ///
    /// # Errors
    ///
    /// Fails when the world runs no witness.
    pub fn witness_url(&self) -> Result<String, WorldError> {
        Err(WorldError::NotImplemented(NotImplemented::new(
            WITNESS_SEAM,
        )))
    }
}

/// The seam of the world's witness. No world runs one yet: the witness
/// service and its database store are not written (`fstp_witness::run`,
/// lane W2g), and no cell starts without one ([`World::start`]).
const WITNESS_SEAM: &str = "fstp_celltest::world::World witness: the witness service and its store (fstp_witness::run, lane W2g)";

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
    })));
    states.insert(name.to_owned(), state);
    Ok(state)
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
fn is_agent_kind(kind: ClusterKind) -> bool {
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
    for (i, plan) in plans.iter().enumerate() {
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
            if !state.failed.contains(&plan.cell) {
                state.failed.push(plan.cell);
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

/// Provisions every cell of `plans`, then the service databases, then
/// starts each cell over its databases ([`World::start`]).
fn start_cells(
    spec: &WorldSpec,
    clusters: &[ClusterHandle],
    plans: &[RolePlan],
    pages: Option<&fstp_cell::http::pages::Pages>,
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
        cells.push(start_cell(index(i)?, plan, logins, pages)?);
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
                    if let Err(e) = provision_service(cluster, set) {
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
    cluster
        .server()
        .create_database_for(set.set, &[migrator.as_str()])
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
    Ok(())
}

/// The seam of a cell start. A world cell starts through
/// `fstp_cell::engine::startup::start_pg`, with the custody simulator,
/// and its routes serve on the started listeners. Four production parts
/// of that start are missing, and a world stands in none of its own.
const CELL_START_SEAM: &str = "fstp_celltest::world::World::start with cells: the cell start needs the writer pool and the fstp_migrate runner over it, so each migration set leaves its ledger (fstp-celltest cannot name fstp-pgwire; the lead adds the in-house edge), the witness service and its store (fstp_witness::run, lane W2g), the cell's vault client over the vault service (fstp_vault::run, lanes W2d and W3a), and the route backend over the application database (fstp_cell::routes::Backend, lane W3a)";

/// How a world cell's front is wired once [`CELL_START_SEAM`] closes,
/// recorded for the lead (review findings of lane int4):
///
/// - The front is `fstp_cell::http::Front::with_pages` over the pages
///   [`World::start_with_pages`] took. That constructor needs the
///   `dev-pages` feature of `fstp-cell`, which this crate then enables on
///   its `fstp-cell` line. Cargo unifies features over one build, so a
///   release build of `fstp-cell` must not build this crate with it.
/// - The edge listens on loopback port 443, and [`CellUrls`] carry no
///   port. The relying party origin is `https://<host>` with no port
///   (I-20, `fstp_webauthn::RelyingParty`), and the front's `Origin`
///   check and the client data check compare it byte for byte. A cell on
///   another port would refuse every POST of a browser with 403.
pub const CELL_FRONT_SEAM: &str = "fstp_celltest::world cell front: Front::with_pages over the World::start_with_pages pages (fstp-cell feature dev-pages on the fstp-celltest line, a lead manifest change), and the edge on loopback port 443, since the relying party origin https://<host> carries no port (I-20)";

/// Starts cell `index` of `plan` over its provisioned databases, as its
/// roles log in with `logins`. It refuses with [`CELL_START_SEAM`]: no
/// in-memory ledger, witness, vault or route backend stands in for a
/// world cell. The started cell's handle keeps `logins`.
///
/// When the cell start lands, its front takes `pages` through
/// `fstp_cell::http::Front::with_pages` when they are given, and
/// `Front::new` otherwise ([`CELL_FRONT_SEAM`]).
fn start_cell(
    index: u8,
    plan: &RolePlan,
    logins: CellLogins,
    pages: Option<&fstp_cell::http::pages::Pages>,
) -> Result<CellHandle, WorldError> {
    let _ = (index, plan, logins, pages);
    Err(WorldError::NotImplemented(NotImplemented::new(
        CELL_START_SEAM,
    )))
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
/// starts, whose front serves them ([`CELL_FRONT_SEAM`]).
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
