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
//! Status after lane W3a: worlds without cells start. A world with cells
//! provisions each cell through the production role plan and runs it
//! over the PostgreSQL store. Neither exists yet (lanes W2h and W2e), so
//! a world with cells refuses with [`NotImplemented`] naming the missing
//! part ([`World::start`]).

use std::fmt;
use std::io::ErrorKind;
use std::path::Path;

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

/// One cell of a world: an HTTP client with a software authenticator.
#[derive(Debug)]
pub struct CellHandle {
    index: u8,
}

impl CellHandle {
    /// The cell's index in its world.
    pub fn index(&self) -> u8 {
        self.index
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
    /// cycle runs on it. This example is red until the role plan of lane
    /// W2h and the PostgreSQL store of lane W2e land (see "Cells" below).
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
    /// # Cells
    ///
    /// A world provisions each cell through the production role plan,
    /// `fstp_control::pg::cell_role_plan` (I-82), never through roles of
    /// its own. It creates the plan's login roles on the cell's clusters,
    /// then each database with its `pg_hba` lines. The grant rows need
    /// the application and vault migrations and `fstp_meta.apply_grant`.
    /// The cell then runs over `fstp_pgstore::PgRecordStore`.
    ///
    /// Lane W3a reading: the cell runtime of `fstp-cell` exists, but the
    /// role plan (lane W2h), the migrations and the PostgreSQL store (lane
    /// W2e) do not. A harness that made roles or stores of its own would
    /// let the I-82 and I-83 sweeps pass on the harness, not on
    /// production. So a world with cells refuses, naming the first
    /// missing part, before any cluster starts.
    ///
    /// # Errors
    ///
    /// [`WorldError::NotImplemented`] naming the missing production part
    /// of a world with cells. Returns the start error of any cluster.
    pub fn start(spec: WorldSpec) -> Result<World, WorldError> {
        let mut plans = Vec::with_capacity(usize::from(spec.cells));
        for _ in 0..spec.cells {
            plans.push(cell_plan()?);
        }
        let clusters = cluster_plan(&spec)
            .iter()
            .map(|(kind, name)| ClusterHandle::start_named(*kind, name))
            .collect::<Result<Vec<_>, _>>()?;
        let mut cells = Vec::with_capacity(plans.len());
        for (i, plan) in plans.iter().enumerate() {
            let index = u8::try_from(i)
                .map_err(|_| WorldError::Store("a world holds at most 255 cells".to_owned()))?;
            provision_cell(&spec, &clusters, index, plan)?;
            cells.push(start_cell(index)?);
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
}

/// A fresh cell id and its production role plan (I-82).
fn cell_plan() -> Result<fstp_control::pg::RolePlan, WorldError> {
    let mut id = [0u8; 16];
    fstp_crypto::random_bytes(&mut id)
        .map_err(|_| WorldError::Store("no random cell id".to_owned()))?;
    #[allow(
        unreachable_patterns,
        reason = "lane W2h adds typed refusals to ControlError; until then NotImplemented is its only variant"
    )]
    fstp_control::pg::cell_role_plan(fstp_cp_proto::CellId(id)).map_err(|e| match e {
        fstp_control::ControlError::NotImplemented(_) => {
            WorldError::NotImplemented(NotImplemented::new(
                "fstp_celltest::world::World::start with cells: the cell role plan fstp_control::pg::cell_role_plan (lane W2h) provisions each cell",
            ))
        }
        other => WorldError::Store(format!("the cell role plan refused: {other}")),
    })
}

/// The name of a cell database, `c_<hex>` or `v_<hex>` (design section 4.1).
fn database_name(db: fstp_control::pg::CellDatabase, cell: &fstp_cp_proto::CellId) -> String {
    let prefix = match db {
        fstp_control::pg::CellDatabase::App => "c",
        fstp_control::pg::CellDatabase::Vault => "v",
    };
    let hex: String = cell.0.iter().map(|b| format!("{b:02x}")).collect();
    format!("{prefix}_{hex}")
}

/// The cluster of `kind` that holds cell `index`: the shared one, or the
/// cell's own in dedicated mode.
fn cell_cluster(
    spec: &WorldSpec,
    clusters: &[ClusterHandle],
    kind: ClusterKind,
    index: u8,
) -> Result<&'static fstp_pgtest::PgServer, WorldError> {
    let dedicated = format!("{}_{index}", kind_label(kind));
    clusters
        .iter()
        .find(|c| {
            c.kind() == kind
                && (spec.self_hosted || spec.mode == DbMode::Shared || c.name() == dedicated)
        })
        .map(ClusterHandle::server)
        .ok_or_else(|| {
            WorldError::Store(format!("no {} cluster for cell {index}", kind_label(kind)))
        })
}

/// Applies `plan` to the cell's clusters: its login roles, then each
/// database with the `pg_hba` lines of its roles. The grant rows need the
/// migrations and `fstp_meta.apply_grant` of lane W2e, so a plan with
/// grant rows refuses here until they land.
fn provision_cell(
    spec: &WorldSpec,
    clusters: &[ClusterHandle],
    index: u8,
    plan: &fstp_control::pg::RolePlan,
) -> Result<(), WorldError> {
    use fstp_control::pg::CellDatabase;
    if !plan.grants.is_empty() {
        return Err(WorldError::NotImplemented(NotImplemented::new(
            "fstp_celltest::world::World::start with cells: the grant rows need the cell migrations and fstp_meta.apply_grant (lane W2e)",
        )));
    }
    for db in [CellDatabase::App, CellDatabase::Vault] {
        let kind = match db {
            CellDatabase::App => ClusterKind::Application,
            CellDatabase::Vault => ClusterKind::Vault,
        };
        let server = cell_cluster(spec, clusters, kind, index)?;
        let dbname = database_name(db, &plan.cell);
        let mut roles = Vec::new();
        for r in plan.roles.iter().filter(|r| r.database == db) {
            let role = format!("{dbname}_{}", r.role.suffix());
            server
                .create_login_role(&role)
                .map_err(|e| WorldError::Cluster {
                    kind,
                    message: e.to_string(),
                })?;
            if plan
                .hba
                .iter()
                .any(|h| h.database == db && h.role == r.role)
            {
                roles.push(role);
            }
        }
        let refs: Vec<&str> = roles.iter().map(String::as_str).collect();
        server
            .create_database_for(&dbname, &refs)
            .map_err(|e| WorldError::Cluster {
                kind,
                message: e.to_string(),
            })?;
    }
    Ok(())
}

/// Starts cell `index` over its provisioned databases. The cell runtime
/// of `fstp-cell` runs over `fstp_pgstore::PgRecordStore`, which lane W2e
/// builds, so this refuses until it lands. No in-memory ledger stands in
/// for a world cell.
fn start_cell(index: u8) -> Result<CellHandle, WorldError> {
    let _ = index;
    Err(WorldError::NotImplemented(NotImplemented::new(
        "fstp_celltest::world::World::start with cells: the cell ledger fstp_pgstore::PgRecordStore (lane W2e)",
    )))
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
