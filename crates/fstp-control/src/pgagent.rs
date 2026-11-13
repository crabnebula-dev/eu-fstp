//! The provisioning agent on each self-operated database host (ADR-011).
//!
//! `fstp-pgagent` runs only typed jobs. A job is a value of the closed
//! [`PgagentJob`] enum. No SQL text crosses the wire, and no job field
//! holds free text. Every name a job renders into DDL is a [`DbIdent`] or
//! a [`RoleIdent`]. Each is built only from a `CellId` and a closed enum,
//! or by parsing input against the grammar `^[cv]_[0-9a-f]{32}$` of
//! ADR-011. Neither has a constructor from an unchecked string.
//!
//! [`job_statements`] renders the SQL of a job, and [`AgentScope`] first
//! refuses a job for a database of the wrong cluster kind. Every template
//! has typed slots only. A slot holds a rendered identifier, the 32 hex
//! digits of a cell, a closed keyword, or a SCRAM verifier that passed its
//! grammar.
//! None of these can hold a quote, so quoting is a second line of defence.
//!
//! The job list is the interim list of ADR-011, pending Daniel. It adds
//! [`PgagentJob::HardenCluster`], which closes the G14 paths in the
//! `postgres` and `template1` databases and revokes PUBLIC's privileges on
//! the databases of `initdb`. A database created later copies the
//! `pg_catalog` of `template1`, so it starts with G14 closed too.

use fstp_cp_proto::{CellId, RoleName, ScramVerifier};

use crate::ControlError;
use crate::pg::{CellDatabase, Revocation, cell_hex, cell_role_plan, roles_of};
use crate::placement::{ClusterKind, PlacementError};

// ---------------------------------------------------------------------------
// Identifiers.

/// A cell database name of the ADR-011 grammar: `c_<cell>` or `v_<cell>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DbIdent {
    db: CellDatabase,
    cell: CellId,
}

impl DbIdent {
    /// The name of `db` for `cell`.
    pub const fn new(db: CellDatabase, cell: CellId) -> DbIdent {
        DbIdent { db, cell }
    }

    /// Parses `name` against `^[cv]_[0-9a-f]{32}$`. Nothing else parses:
    /// no surrounding space, no line end, no upper case, no other script.
    ///
    /// # Errors
    ///
    /// [`ControlError::Identifier`] for any other name.
    pub fn parse(name: &str) -> Result<DbIdent, ControlError> {
        let b = name.as_bytes();
        let (Some(prefix), Some(b'_'), Some(hex), 34) = (b.first(), b.get(1), b.get(2..), b.len())
        else {
            return Err(ControlError::Identifier);
        };
        let db = match prefix {
            b'c' => CellDatabase::App,
            b'v' => CellDatabase::Vault,
            _ => return Err(ControlError::Identifier),
        };
        let mut cell = [0u8; 16];
        for (out, pair) in cell.iter_mut().zip(hex.chunks_exact(2)) {
            let [hi, lo] = pair else {
                return Err(ControlError::Identifier);
            };
            *out = hex_digit(*hi)?
                .checked_mul(16)
                .and_then(|v| v.checked_add(hex_digit(*lo).ok()?))
                .ok_or(ControlError::Identifier)?;
        }
        Ok(DbIdent::new(db, CellId(cell)))
    }

    /// The database.
    pub const fn database(&self) -> CellDatabase {
        self.db
    }

    /// The cell.
    pub const fn cell(&self) -> CellId {
        self.cell
    }

    /// The bare name.
    pub fn name(&self) -> String {
        format!("{}_{}", self.db.prefix(), cell_hex(self.cell))
    }

    /// The name as a double-quoted SQL identifier.
    pub fn render(&self) -> String {
        format!("\"{}\"", self.name())
    }
}

fn hex_digit(c: u8) -> Result<u8, ControlError> {
    match c {
        b'0'..=b'9' => c.checked_sub(b'0').ok_or(ControlError::Identifier),
        b'a'..=b'f' => c
            .checked_sub(b'a')
            .and_then(|v| v.checked_add(10))
            .ok_or(ControlError::Identifier),
        _ => Err(ControlError::Identifier),
    }
}

/// A cell role name of the ADR-011 grammar: the database name, `_`, and a
/// suffix of that database's role set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RoleIdent {
    db: DbIdent,
    role: RoleName,
}

impl RoleIdent {
    /// The role `role` of the database `db`.
    ///
    /// # Errors
    ///
    /// [`ControlError::RoleOutsideDatabase`] for a role of the other
    /// database's set, such as `vault` in an application database.
    pub fn new(db: DbIdent, role: RoleName) -> Result<RoleIdent, ControlError> {
        if roles_of(db.database()).contains(&role) {
            Ok(RoleIdent { db, role })
        } else {
            Err(ControlError::RoleOutsideDatabase)
        }
    }

    /// The database.
    pub const fn database(&self) -> DbIdent {
        self.db
    }

    /// The role suffix.
    pub const fn role(&self) -> RoleName {
        self.role
    }

    /// The bare name.
    pub fn name(&self) -> String {
        format!("{}_{}", self.db.name(), self.role.suffix())
    }

    /// The name as a double-quoted SQL identifier.
    pub fn render(&self) -> String {
        format!("\"{}\"", self.name())
    }
}

/// Renders a cell database name as a quoted DDL identifier (ADR-011). Input
/// outside the grammar `^[cv]_[0-9a-f]{32}$` is refused, so the rendered
/// DDL never contains it. Fuzzed (`ddl_identifier_render`).
///
/// # Errors
///
/// [`ControlError::Identifier`] for a name outside the grammar, a role
/// name included.
pub fn render_ddl_identifier(name: &str) -> Result<String, ControlError> {
    DbIdent::parse(name).map(|d| d.render())
}

// ---------------------------------------------------------------------------
// Jobs.

/// A provisioning job (ADR-011 "fstp-pgagent", interim list).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PgagentJob {
    /// Closes the G14 paths in `postgres` and `template1`, and revokes every
    /// privilege of PUBLIC on the databases of [`CLUSTER_DATABASES`]. The
    /// first job on each cluster.
    HardenCluster,
    /// `CREATE DATABASE` for one cell database. The agent's superuser owns
    /// it, so no cell role can grant on it.
    CreateCellDatabase(DbIdent),
    /// The database's roles of the plan, as NOLOGIN without any elevated
    /// attribute, each with CONNECT on its own database. A role of that
    /// name that exists already gets the attributes again, and a role that
    /// is a member of any role, or has any member, is refused.
    CreateRoles(DbIdent),
    /// The revocations of the plan for the database.
    ApplyRevocations(DbIdent),
    /// Sets a role's SCRAM verifier and LOGIN.
    SetRoleCredential {
        /// The role.
        role: RoleIdent,
        /// The verifier the role's own component generated.
        verifier: ScramVerifier,
    },
    /// Calls `fstp_meta.apply_grant` once per grant row of the plan for the
    /// database, after its migrations ran.
    ApplyGrants(DbIdent),
    /// Reads the isolation auditor's catalogue rows (design section 9.3).
    PrivilegeAudit,
    /// Renders `pg_hba.conf` from the role plan of every cell database
    /// the cluster holds, and reloads the server configuration (ADR-011
    /// `WriteHba`). The agent reads the cell databases from its own
    /// server and the subnet from its own configuration, so the job holds
    /// no field. A line goes away only with its database, whose drop is
    /// destructive itself.
    WriteHba,
    /// Ends a role at once. Destructive.
    SetNoLogin(RoleIdent),
    /// `DROP DATABASE` for one cell database, by cell erasure (R-SW-02).
    /// Destructive.
    DropCellDatabase(DbIdent),
    /// `DROP ROLE` for the database's roles, after the database is gone.
    /// Destructive.
    DropRoles(DbIdent),
}

impl PgagentJob {
    /// Whether the job is destructive (ADR-011 job table), so it needs two
    /// operators' approvals.
    pub const fn is_destructive(&self) -> bool {
        matches!(
            self,
            PgagentJob::SetNoLogin(_) | PgagentJob::DropCellDatabase(_) | PgagentJob::DropRoles(_)
        )
    }
}

/// The version octet that opens every job frame. No SQL keyword starts
/// with it, so SQL text never decodes as a job.
pub const JOB_VERSION: u8 = 1;

const KIND_HARDEN_CLUSTER: u8 = 1;
const KIND_CREATE_DATABASE: u8 = 2;
const KIND_CREATE_ROLES: u8 = 3;
const KIND_APPLY_REVOCATIONS: u8 = 4;
const KIND_SET_ROLE_CREDENTIAL: u8 = 5;
const KIND_APPLY_GRANTS: u8 = 6;
const KIND_PRIVILEGE_AUDIT: u8 = 7;
const KIND_SET_NOLOGIN: u8 = 8;
const KIND_DROP_DATABASE: u8 = 9;
const KIND_DROP_ROLES: u8 = 10;
const KIND_WRITE_HBA: u8 = 11;

fn db_code(db: CellDatabase) -> u8 {
    match db {
        CellDatabase::App => 0,
        CellDatabase::Vault => 1,
    }
}

fn role_code(r: RoleName) -> u8 {
    match r {
        RoleName::Migrator => 0,
        RoleName::Writer => 1,
        RoleName::App => 2,
        RoleName::Keys => 3,
        RoleName::Auditor => 4,
        RoleName::Vault => 5,
    }
}

fn push_db(out: &mut Vec<u8>, d: &DbIdent) {
    out.push(db_code(d.database()));
    out.extend_from_slice(&d.cell().0);
}

fn push_role(out: &mut Vec<u8>, r: &RoleIdent) {
    push_db(out, &r.database());
    out.push(role_code(r.role()));
}

/// Encodes a job: [`JOB_VERSION`], a kind octet, then the database octet
/// and the 16 cell octets where the job names a database, the role octet
/// where it names a role, and a big-endian `u16` length and the verifier
/// for [`PgagentJob::SetRoleCredential`].
///
/// # Errors
///
/// [`ControlError::Job`] for a verifier that fails its grammar, such as
/// `ScramVerifier::empty()`.
pub fn encode_pgagent_job(job: &PgagentJob) -> Result<Vec<u8>, ControlError> {
    let mut out = vec![JOB_VERSION];
    match job {
        PgagentJob::HardenCluster => out.push(KIND_HARDEN_CLUSTER),
        PgagentJob::CreateCellDatabase(d) => {
            out.push(KIND_CREATE_DATABASE);
            push_db(&mut out, d);
        }
        PgagentJob::CreateRoles(d) => {
            out.push(KIND_CREATE_ROLES);
            push_db(&mut out, d);
        }
        PgagentJob::ApplyRevocations(d) => {
            out.push(KIND_APPLY_REVOCATIONS);
            push_db(&mut out, d);
        }
        PgagentJob::SetRoleCredential { role, verifier } => {
            ScramVerifier::parse(verifier.as_bytes())
                .map_err(|_| ControlError::Job("verifier grammar"))?;
            out.push(KIND_SET_ROLE_CREDENTIAL);
            push_role(&mut out, role);
            let len = u16::try_from(verifier.as_bytes().len())
                .map_err(|_| ControlError::Job("verifier length"))?;
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(verifier.as_bytes());
        }
        PgagentJob::ApplyGrants(d) => {
            out.push(KIND_APPLY_GRANTS);
            push_db(&mut out, d);
        }
        PgagentJob::PrivilegeAudit => out.push(KIND_PRIVILEGE_AUDIT),
        PgagentJob::WriteHba => out.push(KIND_WRITE_HBA),
        PgagentJob::SetNoLogin(r) => {
            out.push(KIND_SET_NOLOGIN);
            push_role(&mut out, r);
        }
        PgagentJob::DropCellDatabase(d) => {
            out.push(KIND_DROP_DATABASE);
            push_db(&mut out, d);
        }
        PgagentJob::DropRoles(d) => {
            out.push(KIND_DROP_ROLES);
            push_db(&mut out, d);
        }
    }
    Ok(out)
}

struct JobReader<'a> {
    rest: &'a [u8],
}

impl<'a> JobReader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ControlError> {
        if self.rest.len() < n {
            return Err(ControlError::Job("truncated"));
        }
        let (head, rest) = self.rest.split_at(n);
        self.rest = rest;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, ControlError> {
        let [b] = self.take(1)? else {
            return Err(ControlError::Job("truncated"));
        };
        Ok(*b)
    }

    fn db(&mut self) -> Result<DbIdent, ControlError> {
        let db = match self.u8()? {
            0 => CellDatabase::App,
            1 => CellDatabase::Vault,
            _ => return Err(ControlError::Job("unknown database")),
        };
        let cell: [u8; 16] = self
            .take(16)?
            .try_into()
            .map_err(|_| ControlError::Job("truncated"))?;
        Ok(DbIdent::new(db, CellId(cell)))
    }

    fn role(&mut self) -> Result<RoleIdent, ControlError> {
        let db = self.db()?;
        let role = RoleName::ALL
            .get(usize::from(self.u8()?))
            .copied()
            .ok_or(ControlError::Job("unknown role"))?;
        RoleIdent::new(db, role).map_err(|_| ControlError::Job("role outside its database"))
    }

    fn verifier(&mut self) -> Result<ScramVerifier, ControlError> {
        let len: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| ControlError::Job("truncated"))?;
        let bytes = self.take(usize::from(u16::from_be_bytes(len)))?;
        ScramVerifier::parse(bytes).map_err(|_| ControlError::Job("verifier grammar"))
    }
}

/// The longest job frame, in octets.
pub const MAX_JOB_LEN: usize = 1024;

/// Decodes a job. Fuzzed (`pgagent_job_decode`). A frame decodes only if
/// it is the one encoding of its job, so no byte is free.
///
/// # Errors
///
/// [`ControlError::Job`] naming the rule broken. SQL text, free text and
/// empty input are refused.
pub fn decode_pgagent_job(bytes: &[u8]) -> Result<PgagentJob, ControlError> {
    if bytes.is_empty() {
        return Err(ControlError::Job("empty"));
    }
    if bytes.len() > MAX_JOB_LEN {
        return Err(ControlError::Job("too long"));
    }
    let mut r = JobReader { rest: bytes };
    if r.u8()? != JOB_VERSION {
        return Err(ControlError::Job("unknown version"));
    }
    let job = match r.u8()? {
        KIND_HARDEN_CLUSTER => PgagentJob::HardenCluster,
        KIND_CREATE_DATABASE => PgagentJob::CreateCellDatabase(r.db()?),
        KIND_CREATE_ROLES => PgagentJob::CreateRoles(r.db()?),
        KIND_APPLY_REVOCATIONS => PgagentJob::ApplyRevocations(r.db()?),
        KIND_SET_ROLE_CREDENTIAL => PgagentJob::SetRoleCredential {
            role: r.role()?,
            verifier: r.verifier()?,
        },
        KIND_APPLY_GRANTS => PgagentJob::ApplyGrants(r.db()?),
        KIND_PRIVILEGE_AUDIT => PgagentJob::PrivilegeAudit,
        KIND_WRITE_HBA => PgagentJob::WriteHba,
        KIND_SET_NOLOGIN => PgagentJob::SetNoLogin(r.role()?),
        KIND_DROP_DATABASE => PgagentJob::DropCellDatabase(r.db()?),
        KIND_DROP_ROLES => PgagentJob::DropRoles(r.db()?),
        _ => return Err(ControlError::Job("unknown kind")),
    };
    if !r.rest.is_empty() {
        return Err(ControlError::Job("trailing bytes"));
    }
    if encode_pgagent_job(&job)? != bytes {
        return Err(ControlError::Job("not canonical"));
    }
    Ok(job)
}

// ---------------------------------------------------------------------------
// Rendered SQL.

/// The database a statement runs in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// The maintenance database `postgres`.
    Maintenance,
    /// The template database `template1`.
    Template,
    /// A cell database.
    Cell(DbIdent),
}

impl Target {
    /// The database name to connect to.
    pub fn database_name(&self) -> String {
        match self {
            Target::Maintenance => "postgres".to_owned(),
            Target::Template => "template1".to_owned(),
            Target::Cell(d) => d.name(),
        }
    }
}

/// One rendered statement and the database it runs in, as the superuser.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    /// Where it runs.
    pub target: Target,
    /// The SQL. Built from typed slots only.
    pub sql: String,
    /// Whether SQLSTATE `42P04` (duplicate database) means the statement
    /// already took effect. Only `CREATE DATABASE` sets it, since that one
    /// statement cannot sit in a DO block that checks first.
    pub done_if_duplicate_database: bool,
}

fn stmt(target: Target, sql: String) -> Statement {
    Statement {
        target,
        sql,
        done_if_duplicate_database: false,
    }
}

/// The views of [`G14_VIEWS`] as an SQL `text[]` literal. One macro, so
/// the revocation and the auditor's query name the same views.
macro_rules! g14_views_array {
    () => {
        "ARRAY['pg_stat_activity', 'pg_stat_database', 'pg_stat_database_conflicts', \
         'pg_stat_ssl', 'pg_stat_gssapi', 'pg_stat_replication', 'pg_stat_wal_receiver', \
         'pg_stat_subscription', 'pg_stat_progress_analyze', 'pg_stat_progress_basebackup', \
         'pg_stat_progress_cluster', 'pg_stat_progress_copy', 'pg_stat_progress_create_index', \
         'pg_stat_progress_vacuum', 'pg_locks', 'pg_prepared_xacts']::text[]"
    };
}
pub(crate) use g14_views_array;

/// The query of the G14 functions in the connected database, one
/// `regprocedure` per row: see [`G14_FUNCTIONS_QUERY`]. One macro, so the
/// revocation and the auditor's query name the same functions.
macro_rules! g14_functions_select {
    () => {
        concat!(
            "SELECT p.oid::pg_catalog.regprocedure FROM pg_catalog.pg_proc p \
             WHERE p.pronamespace = 'pg_catalog'::pg_catalog.regnamespace \
             AND (pg_catalog.starts_with(p.proname::text, 'pg_stat_get_backend_') \
             OR p.proname IN ('pg_lock_status', 'pg_prepared_xact') \
             OR p.proname IN (SELECT (pg_catalog.regexp_matches(pg_catalog.pg_get_viewdef(c.oid), \
             'pg_stat_get_[a-z0-9_]+', 'g'))[1] FROM pg_catalog.pg_class c \
             WHERE c.relnamespace = 'pg_catalog'::pg_catalog.regnamespace AND c.relkind = 'v' \
             AND c.relname::text = ANY (",
            crate::pgagent::g14_views_array!(),
            ")))"
        )
    };
}
pub(crate) use g14_functions_select;

/// The cross-database views that G14 revokes from PUBLIC. Each shows
/// other databases' sessions, activity, progress, locks or prepared
/// transactions. A name the server does not know is skipped, so the list
/// may name views of later PostgreSQL releases.
///
/// `pg_locks` and `pg_prepared_xacts` are not statistics views. They list
/// every session's locks and every prepared transaction with its database,
/// so they show other databases' activity just as `pg_stat_activity` does.
pub const G14_VIEWS: [&str; 16] = [
    "pg_stat_activity",
    "pg_stat_database",
    "pg_stat_database_conflicts",
    "pg_stat_ssl",
    "pg_stat_gssapi",
    "pg_stat_replication",
    "pg_stat_wal_receiver",
    "pg_stat_subscription",
    "pg_stat_progress_analyze",
    "pg_stat_progress_basebackup",
    "pg_stat_progress_cluster",
    "pg_stat_progress_copy",
    "pg_stat_progress_create_index",
    "pg_stat_progress_vacuum",
    "pg_locks",
    "pg_prepared_xacts",
];

/// The G14 functions of the connected database, one `regprocedure` per
/// row, every overload included:
///
/// - every `pg_stat_get_*` function that a view of [`G14_VIEWS`] names in
///   its definition (Daniel, 2026-10-29);
/// - every `pg_stat_get_backend_*` function. No view names them, yet
///   together they list every session of every database with its role and
///   start times, the rows `pg_stat_activity` shows;
/// - `pg_lock_status` and `pg_prepared_xact`, the functions behind
///   `pg_locks` and `pg_prepared_xacts`.
///
/// The names come from the server's own catalogue and view definitions,
/// never from memory, except the two functions behind `pg_locks` and
/// `pg_prepared_xacts`. The tests check that those two exist. The last two
/// items, and the two views they serve, are a wider reading of G14 than
/// Daniel's answer names, pending his confirmation. Static text.
pub const G14_FUNCTIONS_QUERY: &str = g14_functions_select!();

/// The G14 revocation inside one database (design section 4.1, Daniel
/// 2026-10-29). It revokes each view of [`G14_VIEWS`] from PUBLIC, and
/// EXECUTE on every function that [`G14_FUNCTIONS_QUERY`] returns.
/// Privileges on `pg_catalog` objects are kept per database, so it runs
/// in every database that takes connections. Static text, so it holds no
/// input at all.
pub const G14_REVOKE_SQL: &str = concat!(
    "DO $fstp_g14$
DECLARE
  v text;
  f regprocedure;
BEGIN
  FOREACH v IN ARRAY ",
    g14_views_array!(),
    "
  LOOP
    IF pg_catalog.to_regclass('pg_catalog.' || pg_catalog.quote_ident(v)) IS NOT NULL THEN
      EXECUTE pg_catalog.format('REVOKE ALL ON pg_catalog.%I FROM PUBLIC', v);
    END IF;
  END LOOP;
  FOR f IN ",
    g14_functions_select!(),
    "
  LOOP
    EXECUTE pg_catalog.format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
  END LOOP;
END
$fstp_g14$"
);

/// The databases that every cluster holds from `initdb`. Design section
/// 4.1 revokes CONNECT from PUBLIC on every database, and
/// [`PgagentJob::HardenCluster`] does so for these three. Only the agent's
/// superuser, which needs no grant, connects to them. The replication
/// role uses replication connections, which name no database.
pub const CLUSTER_DATABASES: [&str; 3] = ["postgres", "template1", "template0"];

/// The attributes every cell role is created with (design section 4.1).
const ROLE_ATTRIBUTES: &str =
    "NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT";

/// The attributes re-asserted on a cell role that exists already. LOGIN
/// is left alone, since `SetRoleCredential` may have set it on an earlier
/// run of the steps.
const ROLE_REASSERTED: &str =
    "NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT";

/// The statements of a non-destructive job, in order, each run as the
/// superuser in its target database.
///
/// A job is idempotent: each statement either checks first inside a DO
/// block, is a REVOKE or GRANT that may repeat, or is `CREATE DATABASE`
/// with [`Statement::done_if_duplicate_database`] set.
///
/// [`PgagentJob::PrivilegeAudit`] reads rows rather than running
/// statements, through `isolation_audit::read_catalogue`, so it renders
/// none here. [`PgagentJob::WriteHba`] writes a file through
/// [`crate::agent`], so it renders none either.
///
/// # Errors
///
/// [`ControlError::ApprovalRequired`] for a destructive job. ADR-011 needs
/// two operators' passkey approvals over the job digest, checked again
/// against a staff key set pinned at installation. That check is not
/// built, so no destructive SQL is rendered.
pub fn job_statements(job: &PgagentJob) -> Result<Vec<Statement>, ControlError> {
    if job.is_destructive() {
        return Err(ControlError::ApprovalRequired);
    }
    match job {
        PgagentJob::HardenCluster => Ok(harden_cluster()),
        PgagentJob::CreateCellDatabase(d) => Ok(vec![Statement {
            target: Target::Maintenance,
            sql: format!("CREATE DATABASE {}", d.render()),
            done_if_duplicate_database: true,
        }]),
        PgagentJob::CreateRoles(d) => create_roles(d),
        PgagentJob::ApplyRevocations(d) => revocations(d),
        PgagentJob::SetRoleCredential { role, verifier } => {
            // The grammar admits no quote or backslash, so the literal
            // cannot close early. It is checked again here.
            ScramVerifier::parse(verifier.as_bytes())
                .map_err(|_| ControlError::Job("verifier grammar"))?;
            Ok(vec![stmt(
                Target::Maintenance,
                format!(
                    "ALTER ROLE {} LOGIN PASSWORD '{}'",
                    role.render(),
                    verifier.as_str()
                ),
            )])
        }
        PgagentJob::ApplyGrants(d) => apply_grants(d),
        PgagentJob::PrivilegeAudit
        | PgagentJob::WriteHba
        | PgagentJob::SetNoLogin(_)
        | PgagentJob::DropCellDatabase(_)
        | PgagentJob::DropRoles(_) => Ok(Vec::new()),
    }
}

/// The statements of [`PgagentJob::HardenCluster`]: the G14 revocation in
/// `postgres` and `template1`, then every privilege of PUBLIC on each of
/// [`CLUSTER_DATABASES`]. A database created later copies the `pg_catalog`
/// privileges of `template1`, so it starts with G14 closed. Its own
/// database ACL starts at the default, which [`PgagentJob::ApplyRevocations`]
/// then revokes.
fn harden_cluster() -> Vec<Statement> {
    let mut out = vec![
        stmt(Target::Maintenance, G14_REVOKE_SQL.to_owned()),
        stmt(Target::Template, G14_REVOKE_SQL.to_owned()),
    ];
    for db in CLUSTER_DATABASES {
        out.push(stmt(
            Target::Maintenance,
            format!("REVOKE ALL ON DATABASE \"{db}\" FROM PUBLIC"),
        ));
    }
    out
}

fn plan_roles(d: &DbIdent) -> Result<Vec<RoleIdent>, ControlError> {
    let plan = cell_role_plan(d.cell())?;
    plan.roles
        .iter()
        .filter(|r| r.database == d.database())
        .map(|r| RoleIdent::new(*d, r.role))
        .collect()
}

fn create_roles(d: &DbIdent) -> Result<Vec<Statement>, ControlError> {
    let plan = cell_role_plan(d.cell())?;
    let mut out = Vec::new();
    for role in plan_roles(d)? {
        out.push(stmt(
            Target::Maintenance,
            format!(
                "DO $fstp_role$ BEGIN \
                 IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '{name}') THEN \
                 CREATE ROLE {ident} {ROLE_ATTRIBUTES}; \
                 ELSE \
                 ALTER ROLE {ident} {ROLE_REASSERTED}; \
                 END IF; \
                 IF EXISTS (SELECT FROM pg_catalog.pg_auth_members a \
                 JOIN pg_catalog.pg_roles r ON r.oid = a.member OR r.oid = a.roleid \
                 WHERE r.rolname = '{name}') THEN \
                 RAISE EXCEPTION 'a cell role has a membership outside the plan' \
                 USING ERRCODE = '42501'; \
                 END IF; END $fstp_role$",
                name = role.name(),
                ident = role.render(),
            ),
        ));
    }
    for p in plan
        .database_privileges
        .iter()
        .filter(|p| p.database == d.database())
    {
        let role = RoleIdent::new(*d, p.role)?;
        out.push(stmt(
            Target::Maintenance,
            format!(
                "GRANT {} ON DATABASE {} TO {}",
                p.privilege.keyword(),
                d.render(),
                role.render()
            ),
        ));
    }
    Ok(out)
}

/// The extension guard inside one cell database: an event trigger, owned
/// by the superuser, that refuses `CREATE EXTENSION` and `ALTER
/// EXTENSION` for every role. Static text. It checks first, so it may
/// run again.
pub const EXTENSION_GUARD_SQL: &str = "DO $fstp_guard$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_event_trigger WHERE evtname = 'fstp_refuse_extension') THEN
    CREATE SCHEMA IF NOT EXISTS fstp_guard;
    REVOKE ALL ON SCHEMA fstp_guard FROM PUBLIC;
    CREATE OR REPLACE FUNCTION fstp_guard.refuse_extension() RETURNS event_trigger
      LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $fstp_fn$
      BEGIN
        RAISE EXCEPTION 'extensions are refused in a cell database' USING ERRCODE = '42501';
      END $fstp_fn$;
    CREATE EVENT TRIGGER fstp_refuse_extension ON ddl_command_start
      WHEN TAG IN ('CREATE EXTENSION', 'ALTER EXTENSION')
      EXECUTE FUNCTION fstp_guard.refuse_extension();
  END IF;
END
$fstp_guard$";

fn revocations(d: &DbIdent) -> Result<Vec<Statement>, ControlError> {
    let plan = cell_role_plan(d.cell())?;
    let mut out = Vec::new();
    for r in &plan.revocations {
        match r {
            Revocation::DatabaseFromPublic(db) if *db == d.database() => out.push(stmt(
                Target::Maintenance,
                format!("REVOKE ALL ON DATABASE {} FROM PUBLIC", d.render()),
            )),
            Revocation::StatisticsFromPublic(db) if *db == d.database() => {
                out.push(stmt(Target::Cell(*d), G14_REVOKE_SQL.to_owned()));
            }
            Revocation::ExtensionGuard(db) if *db == d.database() => {
                out.push(stmt(Target::Cell(*d), EXTENSION_GUARD_SQL.to_owned()));
            }
            Revocation::DatabaseFromPublic(_)
            | Revocation::StatisticsFromPublic(_)
            | Revocation::ExtensionGuard(_) => {}
        }
    }
    Ok(out)
}

/// The grant statement: one DO block that takes the migrator's role, sets
/// `fstp.cell`, and calls `fstp_meta.apply_grant` once per grant row of
/// the database. The migrator owns every schema, and `apply_grant` grants
/// only on a schema its caller owns, so the superuser acts as the
/// migrator for these grants. Both settings are local to the block's
/// transaction.
fn apply_grants(d: &DbIdent) -> Result<Vec<Statement>, ControlError> {
    let plan = cell_role_plan(d.cell())?;
    let migrator = RoleIdent::new(*d, RoleName::Migrator)?;
    let mut sql = format!(
        "DO $fstp_grants$ BEGIN \
         PERFORM pg_catalog.set_config('role', '{}', true); \
         PERFORM pg_catalog.set_config('fstp.cell', '{}', true);",
        migrator.name(),
        cell_hex(d.cell())
    );
    for g in plan.grants.iter().filter(|g| g.database == d.database()) {
        sql.push_str(" PERFORM fstp_meta.apply_grant('");
        sql.push_str(&g.privs_argument());
        sql.push_str("', '");
        sql.push_str(g.object);
        sql.push_str("', '");
        sql.push_str(g.role.suffix());
        sql.push_str("');");
    }
    sql.push_str(" END $fstp_grants$");
    Ok(vec![stmt(Target::Cell(*d), sql)])
}

// ---------------------------------------------------------------------------
// The agent's own check of the cluster kind.

/// The cluster one agent serves (ADR-011 `CreateCellDatabases`, "as the
/// cluster kind allows", and I-83).
///
/// The agent takes its cluster's kind from its own local configuration at
/// start, never from a job. It renders a job only through
/// [`AgentScope::statements`], which refuses a database or role of the
/// wrong kind before any SQL exists. So an agent on an application host
/// never creates a vault database, even if `fstp-control` sends it that
/// job. `Placement` in `fstp-control` makes the same check first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentScope {
    kind: ClusterKind,
}

impl AgentScope {
    /// The scope of an agent on a cluster of `kind`.
    ///
    /// # Errors
    ///
    /// [`ControlError::Job`] for [`ClusterKind::Control`]. The control
    /// cluster is provider-managed and never a `fstp-pgagent` target.
    pub fn new(kind: ClusterKind) -> Result<AgentScope, ControlError> {
        match kind {
            ClusterKind::Control => Err(ControlError::Job("control cluster has no agent")),
            ClusterKind::Application | ClusterKind::Vault | ClusterKind::Witness => {
                Ok(AgentScope { kind })
            }
        }
    }

    /// The kind of the agent's cluster.
    pub const fn kind(&self) -> ClusterKind {
        self.kind
    }

    /// Whether the agent may run `job`. A job that names no database, such
    /// as [`PgagentJob::HardenCluster`], runs on every kind. A job that
    /// names a database or a role runs only on the kind of that database:
    /// `c_<cell>` on an application cluster, `v_<cell>` on a vault cluster.
    ///
    /// # Errors
    ///
    /// [`ControlError::Placement`] with
    /// [`PlacementError::NotAnApplicationCluster`] for an application
    /// database elsewhere, and [`PlacementError::NotAVaultCluster`] for a
    /// vault database elsewhere.
    pub fn admits(&self, job: &PgagentJob) -> Result<(), ControlError> {
        let db = match job {
            PgagentJob::HardenCluster | PgagentJob::PrivilegeAudit => return Ok(()),
            // The file holds the lines of cell databases, which only
            // application and vault clusters hold.
            PgagentJob::WriteHba => {
                return match self.kind {
                    ClusterKind::Application | ClusterKind::Vault => Ok(()),
                    ClusterKind::Control | ClusterKind::Witness => {
                        Err(ControlError::Job("no cell databases on this cluster kind"))
                    }
                };
            }
            PgagentJob::CreateCellDatabase(d)
            | PgagentJob::CreateRoles(d)
            | PgagentJob::ApplyRevocations(d)
            | PgagentJob::ApplyGrants(d)
            | PgagentJob::DropCellDatabase(d)
            | PgagentJob::DropRoles(d) => d.database(),
            PgagentJob::SetRoleCredential { role, .. } | PgagentJob::SetNoLogin(role) => {
                role.database().database()
            }
        };
        match (self.kind, db) {
            (ClusterKind::Application, CellDatabase::App)
            | (ClusterKind::Vault, CellDatabase::Vault) => Ok(()),
            (
                ClusterKind::Vault | ClusterKind::Control | ClusterKind::Witness,
                CellDatabase::App,
            ) => Err(ControlError::Placement(
                PlacementError::NotAnApplicationCluster,
            )),
            (
                ClusterKind::Application | ClusterKind::Control | ClusterKind::Witness,
                CellDatabase::Vault,
            ) => Err(ControlError::Placement(PlacementError::NotAVaultCluster)),
        }
    }

    /// The statements of `job` on this agent's cluster: [`Self::admits`]
    /// first, then [`job_statements`]. The agent's executor renders SQL
    /// through this function only.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::admits`], then those of [`job_statements`].
    pub fn statements(&self, job: &PgagentJob) -> Result<Vec<Statement>, ControlError> {
        self.admits(job)?;
        job_statements(job)
    }
}

/// Runs the agent until shutdown: [`crate::agent::run`].
///
/// # Errors
///
/// The errors of [`crate::agent::run`].
pub fn run() -> Result<(), ControlError> {
    crate::agent::run()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// ADR-011: a parsed name renders back to itself.
    #[test]
    fn adr011_db_ident_parse_inverts_name() {
        let d = DbIdent::new(CellDatabase::Vault, CellId([0x9c; 16]));
        assert_eq!(DbIdent::parse(&d.name()), Ok(d));
        assert_eq!(
            render_ddl_identifier(&d.name()),
            Ok(format!("\"{}\"", d.name()))
        );
    }

    /// ADR-011: every job round-trips through its encoding.
    #[test]
    fn adr011_pgagent_jobs_round_trip() {
        let d = DbIdent::new(CellDatabase::App, CellId([3; 16]));
        let r = RoleIdent::new(d, RoleName::Writer).unwrap();
        let v = ScramVerifier::parse(
            format!(
                "SCRAM-SHA-256$4096:{}${}:{}",
                "AAAAAAAAAAAAAAAAAAAAAA==",
                "A".repeat(43) + "=",
                "B".repeat(42) + "A="
            )
            .as_bytes(),
        )
        .unwrap();
        for job in [
            PgagentJob::HardenCluster,
            PgagentJob::CreateCellDatabase(d),
            PgagentJob::CreateRoles(d),
            PgagentJob::ApplyRevocations(d),
            PgagentJob::SetRoleCredential {
                role: r,
                verifier: v,
            },
            PgagentJob::ApplyGrants(d),
            PgagentJob::PrivilegeAudit,
            PgagentJob::SetNoLogin(r),
            PgagentJob::DropCellDatabase(d),
            PgagentJob::DropRoles(d),
        ] {
            let b = encode_pgagent_job(&job).unwrap();
            assert_eq!(decode_pgagent_job(&b), Ok(job.clone()), "{b:02x?}");
        }
    }

    /// ADR-011: a destructive job renders no SQL without approvals.
    #[test]
    fn adr011_destructive_jobs_need_approval() {
        let d = DbIdent::new(CellDatabase::App, CellId([3; 16]));
        let r = RoleIdent::new(d, RoleName::App).unwrap();
        for job in [
            PgagentJob::SetNoLogin(r),
            PgagentJob::DropCellDatabase(d),
            PgagentJob::DropRoles(d),
        ] {
            assert_eq!(job_statements(&job), Err(ControlError::ApprovalRequired));
        }
    }

    /// I-82, ADR-011: every grant statement carries only the cell's hex,
    /// closed keywords, catalogued objects and role suffixes.
    #[test]
    fn i82_grant_statement_names_only_the_cell() {
        let d = DbIdent::new(CellDatabase::App, CellId([0x42; 16]));
        let s = job_statements(&PgagentJob::ApplyGrants(d)).unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].target, Target::Cell(d));
        assert!(s[0].sql.contains(&format!("'{}'", "42".repeat(16))));
        assert!(
            s[0].sql
                .contains("fstp_meta.apply_grant('SELECT, INSERT', 'ledger.entry', 'writer')")
        );
    }

    /// I-82, G14: the revocation and the auditor's function query name
    /// exactly the views of `G14_VIEWS`, each once.
    #[test]
    fn i82_g14_sql_names_exactly_the_g14_views() {
        let array = g14_views_array!();
        assert_eq!(array.matches('\'').count(), 2 * G14_VIEWS.len());
        for v in G14_VIEWS {
            let quoted = format!("'{v}'");
            assert_eq!(array.matches(&quoted).count(), 1, "{v}");
            assert!(G14_REVOKE_SQL.contains(&quoted), "{v}");
            assert!(G14_FUNCTIONS_QUERY.contains(&quoted), "{v}");
        }
        for f in [
            "'pg_stat_get_backend_'",
            "'pg_lock_status'",
            "'pg_prepared_xact'",
        ] {
            assert!(G14_REVOKE_SQL.contains(f), "{f}");
        }
    }

    /// I-82, design section 4.1: `HardenCluster` closes G14 in `postgres`
    /// and `template1`, and revokes PUBLIC on every database of `initdb`.
    #[test]
    fn i82_harden_cluster_revokes_public_on_every_initdb_database() {
        let s = job_statements(&PgagentJob::HardenCluster).unwrap();
        let targets: Vec<Target> = s
            .iter()
            .filter(|s| s.sql == G14_REVOKE_SQL)
            .map(|s| s.target)
            .collect();
        assert_eq!(targets, vec![Target::Maintenance, Target::Template]);
        for db in ["postgres", "template1", "template0"] {
            let want = format!("REVOKE ALL ON DATABASE \"{db}\" FROM PUBLIC");
            assert!(
                s.iter()
                    .any(|s| s.target == Target::Maintenance && s.sql == want),
                "{want}"
            );
        }
    }

    /// I-82, ADR-011 `CreateRoles`: an existing role gets every attribute
    /// of the plan again, and a role with a membership is refused.
    #[test]
    fn i82_create_roles_reasserts_attributes_of_an_existing_role() {
        let d = DbIdent::new(CellDatabase::App, CellId([0x11; 16]));
        let s = job_statements(&PgagentJob::CreateRoles(d)).unwrap();
        for role in plan_roles(&d).unwrap() {
            let alter = format!(
                "ALTER ROLE {} NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT",
                role.render()
            );
            let block = s
                .iter()
                .find(|s| s.sql.contains(&alter))
                .unwrap_or_else(|| panic!("no re-assertion for {}", role.name()));
            assert!(block.sql.contains("pg_catalog.pg_auth_members"));
            assert!(block.sql.contains("RAISE EXCEPTION"));
        }
    }

    /// I-83, ADR-011 `CreateCellDatabases`: an agent refuses every job that
    /// names a database of another cluster kind, before any SQL exists.
    #[test]
    fn i83_agent_scope_refuses_the_other_kind() {
        let cell = CellId([0x21; 16]);
        let app = DbIdent::new(CellDatabase::App, cell);
        let vault = DbIdent::new(CellDatabase::Vault, cell);
        let jobs = |d: DbIdent| {
            let r = RoleIdent::new(d, RoleName::Migrator).unwrap();
            vec![
                PgagentJob::CreateCellDatabase(d),
                PgagentJob::CreateRoles(d),
                PgagentJob::ApplyRevocations(d),
                PgagentJob::ApplyGrants(d),
                PgagentJob::SetNoLogin(r),
                PgagentJob::DropCellDatabase(d),
                PgagentJob::DropRoles(d),
            ]
        };
        let app_agent = AgentScope::new(ClusterKind::Application).unwrap();
        let vault_agent = AgentScope::new(ClusterKind::Vault).unwrap();
        let witness_agent = AgentScope::new(ClusterKind::Witness).unwrap();
        assert!(AgentScope::new(ClusterKind::Control).is_err());
        for job in jobs(vault) {
            assert_eq!(
                app_agent.statements(&job),
                Err(ControlError::Placement(PlacementError::NotAVaultCluster)),
                "{job:?}"
            );
            assert!(witness_agent.admits(&job).is_err(), "{job:?}");
            assert_eq!(vault_agent.admits(&job), Ok(()), "{job:?}");
        }
        for job in jobs(app) {
            assert_eq!(
                vault_agent.statements(&job),
                Err(ControlError::Placement(
                    PlacementError::NotAnApplicationCluster
                )),
                "{job:?}"
            );
            assert!(witness_agent.admits(&job).is_err(), "{job:?}");
            assert_eq!(app_agent.admits(&job), Ok(()), "{job:?}");
        }
        for agent in [app_agent, vault_agent, witness_agent] {
            assert!(agent.statements(&PgagentJob::HardenCluster).is_ok());
            assert_eq!(agent.admits(&PgagentJob::PrivilegeAudit), Ok(()));
        }
        assert_eq!(
            app_agent.statements(&PgagentJob::CreateCellDatabase(app)),
            job_statements(&PgagentJob::CreateCellDatabase(app))
        );
    }
}
