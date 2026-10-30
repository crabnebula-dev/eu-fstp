//! The isolation auditor (I-82, design section 9.3).
//!
//! The auditor reads `pg_roles`, `pg_auth_members`, `pg_database.datacl`,
//! `pg_extension`, view grants and `pg_hba_file_rules`. The server expands
//! every array column through `aclexplode(datacl)` and `unnest()`, so the
//! auditor receives scalar text, integer and boolean values only, and no
//! array parser exists. It runs as a `fstp-pgagent` job, hourly in
//! production, and is the I-82 test oracle in CI.
//!
//! [`privilege_graph`] is the pure half. It builds the graph from scalar
//! catalogue rows that the job has read. [`read_catalogue`] and
//! [`read_extensions`] are the reading half, over an `fstp-pgwire` session
//! of the superuser. Each query is a fixed text whose result columns are
//! text, integer or boolean.
//!
//! The view grants are the G14 objects that PUBLIC can still read in a
//! database: the views of [`crate::pgagent::G14_VIEWS`] and the functions
//! of [`crate::pgagent::G14_FUNCTIONS_QUERY`]. The auditor also reads each
//! database's owner, who can grant itself CONNECT at any time. Both live
//! in [`AuditRows`] beside the [`CatalogueRows`], and [`privilege_graph`]
//! takes either through [`AuditSource`].

use std::collections::BTreeSet;

use fstp_pgwire::Client;
use fstp_rt::Runtime;

use crate::ControlError;
use crate::pgagent::{g14_functions_select, g14_views_array};

/// A row of `pg_roles`, reduced to the attributes I-82 constrains.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoleAttrs {
    /// `rolname`.
    pub name: String,
    /// `rolsuper`.
    pub superuser: bool,
    /// `rolcreaterole`.
    pub createrole: bool,
    /// `rolcreatedb`.
    pub createdb: bool,
    /// `rolreplication`.
    pub replication: bool,
    /// `rolbypassrls`.
    pub bypassrls: bool,
    /// `rolcanlogin`.
    pub login: bool,
}

/// A row of `pg_auth_members`, by role name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Membership {
    /// The member.
    pub member: String,
    /// The role it is a member of.
    pub role: String,
}

/// One `aclexplode(datacl)` row of `pg_database`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatabaseGrant {
    /// The database.
    pub database: String,
    /// The grantee, or `PUBLIC`.
    pub grantee: String,
    /// The privilege type, such as `CONNECT`.
    pub privilege: String,
}

/// One `pg_hba_file_rules` row, with each array member on its own row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HbaRule {
    /// The line number in `pg_hba.conf`.
    pub line: i64,
    /// The connection type, such as `hostssl`.
    pub kind: String,
    /// One database name.
    pub database: String,
    /// One user name.
    pub user: String,
    /// The address, empty for a local line.
    pub address: String,
    /// The authentication method.
    pub method: String,
}

/// The scalar catalogue rows of one cluster.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CatalogueRows {
    /// `pg_roles`.
    pub roles: Vec<RoleAttrs>,
    /// `pg_auth_members`.
    pub memberships: Vec<Membership>,
    /// `pg_database.datacl`, exploded.
    pub database_grants: Vec<DatabaseGrant>,
    /// `pg_extension.extname`.
    pub extensions: Vec<String>,
    /// `pg_hba_file_rules`, unnested.
    pub hba: Vec<HbaRule>,
}

/// One `pg_database.datdba` row, by role name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatabaseOwner {
    /// The database.
    pub database: String,
    /// The owning role. The owner holds every database privilege with
    /// grant option, even after its own ACL entry is revoked.
    pub owner: String,
}

/// A G14 object that PUBLIC can still use in one database: a view of
/// [`crate::pgagent::G14_VIEWS`] it can SELECT, or a function of
/// [`crate::pgagent::G14_FUNCTIONS_QUERY`] it can EXECUTE.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenG14Object {
    /// The database whose `pg_catalog` holds the grant.
    pub database: String,
    /// `view` or `function`.
    pub kind: String,
    /// The view name, or the function as `regprocedure` text.
    pub name: String,
    /// `SELECT` for a view, `EXECUTE` for a function.
    pub privilege: String,
}

/// What the `PrivilegeAudit` job reads: the [`CatalogueRows`] of the
/// cluster, the owner of each database, and the G14 objects still open to
/// PUBLIC. `pg_catalog` privileges are kept per database, so the job
/// merges [`read_open_g14`] over every database that [`read_databases`]
/// names.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuditRows {
    /// The rows of the cluster.
    pub catalogue: CatalogueRows,
    /// `pg_database.datdba`, by role name.
    pub database_owners: Vec<DatabaseOwner>,
    /// The G14 objects that PUBLIC can still use.
    pub open_g14: Vec<OpenG14Object>,
}

/// The rows [`privilege_graph`] reads. [`CatalogueRows`] alone gives no
/// owner and no open G14 object. [`AuditRows`] gives all three.
pub trait AuditSource {
    /// The rows of the cluster.
    fn catalogue(&self) -> &CatalogueRows;
    /// The owner of each database.
    fn database_owners(&self) -> &[DatabaseOwner];
    /// The G14 objects that PUBLIC can still use.
    fn open_g14(&self) -> &[OpenG14Object];
}

impl AuditSource for CatalogueRows {
    fn catalogue(&self) -> &CatalogueRows {
        self
    }
    fn database_owners(&self) -> &[DatabaseOwner] {
        &[]
    }
    fn open_g14(&self) -> &[OpenG14Object] {
        &[]
    }
}

impl AuditSource for AuditRows {
    fn catalogue(&self) -> &CatalogueRows {
        &self.catalogue
    }
    fn database_owners(&self) -> &[DatabaseOwner] {
        &self.database_owners
    }
    fn open_g14(&self) -> &[OpenG14Object] {
        &self.open_g14
    }
}

/// An edge of the privilege graph: `from` can reach `to`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PrivilegeEdge {
    /// A role, or a remote address class.
    pub from: String,
    /// A role or a database.
    pub to: String,
    /// What carries the edge, such as a membership or a CONNECT grant.
    pub via: String,
}

/// The privilege graph of one cluster.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PrivilegeGraph {
    /// Every edge.
    pub edges: Vec<PrivilegeEdge>,
}

/// The node a SUPERUSER role reaches. A superuser needs no CONNECT grant
/// and reads every file of the cluster, so it reaches every database.
pub const SUPERUSER_NODE: &str = "attribute:superuser";

/// The pseudo-role every role belongs to.
pub const PUBLIC: &str = "PUBLIC";

fn edge(from: &str, to: &str, via: String) -> PrivilegeEdge {
    PrivilegeEdge {
        from: from.to_owned(),
        to: to.to_owned(),
        via,
    }
}

/// Builds the privilege graph of one cluster from its catalogue rows
/// (I-82, design section 9.3).
///
/// Node names are as the catalogue spells them, with `PUBLIC` for the
/// pseudo-role. The graph holds:
///
/// - each `pg_auth_members` row as `member -> role`. A member can `SET
///   ROLE` to the role, since PostgreSQL 16 gives a grant the SET option by
///   default;
/// - each database privilege of `pg_database.datacl` as `grantee ->
///   database`, PUBLIC included, via the privilege type;
/// - each SUPERUSER role as `role -> attribute:superuser`, whether or not
///   it can log in, and each other elevated attribute as `role ->
///   attribute:<name>`;
/// - each accepting `pg_hba` line as `address:<address> -> user`, or
///   `local -> user` for a socket line;
/// - each extension as `PUBLIC -> extension:<name>`, since an extension
///   such as `dblink` gives every role a path out of its database;
/// - each database owner as `owner -> database`, via `owner`. The owner
///   can grant itself CONNECT, so it reaches the database even with no
///   ACL entry of its own;
/// - each G14 object still open to PUBLIC as `PUBLIC -> view:<db>.<name>`
///   or `PUBLIC -> function:<db>.<signature>`, via the privilege. Each
///   shows other databases' sessions or activity (G14).
///
/// `rows` is an [`AuditRows`] as the `PrivilegeAudit` job reads it, or a
/// bare [`CatalogueRows`], which has no owner or G14 rows.
///
/// The edges are sorted and distinct, so the graph does not depend on the
/// order of the rows.
///
/// # Errors
///
/// None today. The `Result` keeps room for rows that contradict each
/// other.
pub fn privilege_graph<S: AuditSource + ?Sized>(
    source: &S,
) -> Result<PrivilegeGraph, ControlError> {
    let rows = source.catalogue();
    let mut edges: BTreeSet<PrivilegeEdge> = BTreeSet::new();
    for m in &rows.memberships {
        edges.insert(edge(&m.member, &m.role, "member".to_owned()));
    }
    for g in &rows.database_grants {
        edges.insert(edge(&g.grantee, &g.database, g.privilege.clone()));
    }
    for r in &rows.roles {
        let attributes = [
            (r.superuser, SUPERUSER_NODE),
            (r.createrole, "attribute:createrole"),
            (r.createdb, "attribute:createdb"),
            (r.replication, "attribute:replication"),
            (r.bypassrls, "attribute:bypassrls"),
        ];
        for (held, node) in attributes {
            if held {
                edges.insert(edge(&r.name, node, "role attribute".to_owned()));
            }
        }
    }
    for h in rows.hba.iter().filter(|h| h.method != "reject") {
        let from = if h.address.is_empty() {
            "local".to_owned()
        } else {
            format!("address:{}", h.address)
        };
        edges.insert(edge(
            &from,
            &h.user,
            format!(
                "pg_hba line {} {} {} {}",
                h.line, h.kind, h.database, h.method
            ),
        ));
    }
    for e in &rows.extensions {
        edges.insert(edge(
            PUBLIC,
            &format!("extension:{e}"),
            "extension".to_owned(),
        ));
    }
    for o in source.database_owners() {
        edges.insert(edge(&o.owner, &o.database, "owner".to_owned()));
    }
    for g in source.open_g14() {
        edges.insert(edge(
            PUBLIC,
            &format!("{}:{}.{}", g.kind, g.database, g.name),
            g.privilege.clone(),
        ));
    }
    Ok(PrivilegeGraph {
        edges: edges.into_iter().collect(),
    })
}

// ---------------------------------------------------------------------------
// Reading the catalogue (the `PrivilegeAudit` job).

/// The roles and their attributes.
pub const ROLES_QUERY: &str = "SELECT rolname::text, rolsuper, rolcreaterole, rolcreatedb, \
     rolreplication, rolbypassrls, rolcanlogin FROM pg_catalog.pg_roles";

/// The memberships, by role name.
pub const MEMBERSHIPS_QUERY: &str = "SELECT m.rolname::text, r.rolname::text \
     FROM pg_catalog.pg_auth_members a \
     JOIN pg_catalog.pg_roles m ON m.oid = a.member \
     JOIN pg_catalog.pg_roles r ON r.oid = a.roleid";

/// The database privileges, exploded on the server. A NULL `datacl` reads
/// as the default ACL, so PUBLIC's default CONNECT is not missed.
pub const DATABASE_GRANTS_QUERY: &str = "SELECT d.datname::text, \
     CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE coalesce(g.rolname::text, a.grantee::text) END, \
     a.privilege_type::text FROM pg_catalog.pg_database d \
     CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(d.datacl, pg_catalog.acldefault('d', d.datdba))) a \
     LEFT JOIN pg_catalog.pg_roles g ON g.oid = a.grantee";

/// The owner of each database, by role name.
pub const DATABASE_OWNERS_QUERY: &str = "SELECT d.datname::text, \
     coalesce(r.rolname::text, d.datdba::text) FROM pg_catalog.pg_database d \
     LEFT JOIN pg_catalog.pg_roles r ON r.oid = d.datdba";

/// The G14 objects that PUBLIC can still use in the connected database:
/// each view of [`crate::pgagent::G14_VIEWS`] it can SELECT, and each
/// function of [`crate::pgagent::G14_FUNCTIONS_QUERY`] it can EXECUTE. The
/// lists are the ones `G14_REVOKE_SQL` revokes, from the same text. Every
/// result column is scalar text.
pub const OPEN_G14_QUERY: &str = concat!(
    "SELECT pg_catalog.current_database()::text, 'view'::text, v::text, 'SELECT'::text \
     FROM pg_catalog.unnest(",
    g14_views_array!(),
    ") v WHERE pg_catalog.has_table_privilege('public', \
     pg_catalog.to_regclass('pg_catalog.' || pg_catalog.quote_ident(v))::pg_catalog.oid, \
     'SELECT') \
     UNION ALL SELECT pg_catalog.current_database()::text, 'function'::text, f.p::text, \
     'EXECUTE'::text FROM (",
    g14_functions_select!(),
    ") f(p) WHERE pg_catalog.has_function_privilege('public', f.p::pg_catalog.oid, 'EXECUTE')"
);

/// The extensions of the connected database.
pub const EXTENSIONS_QUERY: &str = "SELECT extname::text FROM pg_catalog.pg_extension";

/// The number of `pg_hba` rules the server could not read.
pub const HBA_ERRORS_QUERY: &str =
    "SELECT count(*)::int8 FROM pg_catalog.pg_hba_file_rules WHERE error IS NOT NULL";

/// The `pg_hba` rules, with each database and user on its own row,
/// unnested on the server. Every result column is scalar.
pub const HBA_QUERY: &str = "SELECT r.line_number::int8, coalesce(r.type, ''), d, u, \
     coalesce(r.address, ''), coalesce(r.auth_method, '') \
     FROM pg_catalog.pg_hba_file_rules r \
     CROSS JOIN LATERAL unnest(coalesce(r.database, ARRAY['']::text[])) d \
     CROSS JOIN LATERAL unnest(coalesce(r.user_name, ARRAY['']::text[])) u";

/// The names of the databases that take connections, so the job can read
/// each one's extensions.
pub const DATABASES_QUERY: &str =
    "SELECT datname::text FROM pg_catalog.pg_database WHERE datallowconn";

fn cell<T: fstp_pgwire::FromSql>(
    row: &fstp_pgwire::Row,
    i: usize,
    query: &'static str,
) -> Result<T, ControlError> {
    row.get(i).map_err(|_| ControlError::Catalogue(query))
}

async fn rows<R: Runtime>(
    client: &mut Client<R>,
    query: &'static str,
) -> Result<Vec<fstp_pgwire::Row>, ControlError> {
    client
        .query(query, &[])
        .await
        .map_err(|_| ControlError::Catalogue(query))
}

/// Reads the cluster-wide catalogue rows and database owners, and the
/// extensions and open G14 objects of the connected database, as the
/// superuser. `pg_hba_file_rules` needs
/// superuser in PostgreSQL 16, so the `PrivilegeAudit` job runs on the
/// database host.
///
/// # Errors
///
/// [`ControlError::Catalogue`] naming the query that failed, or
/// [`HBA_ERRORS_QUERY`] when a `pg_hba` rule did not load.
pub async fn read_catalogue<R: Runtime>(client: &mut Client<R>) -> Result<AuditRows, ControlError> {
    let mut out = CatalogueRows::default();
    for r in rows(client, ROLES_QUERY).await? {
        out.roles.push(RoleAttrs {
            name: cell(&r, 0, ROLES_QUERY)?,
            superuser: cell(&r, 1, ROLES_QUERY)?,
            createrole: cell(&r, 2, ROLES_QUERY)?,
            createdb: cell(&r, 3, ROLES_QUERY)?,
            replication: cell(&r, 4, ROLES_QUERY)?,
            bypassrls: cell(&r, 5, ROLES_QUERY)?,
            login: cell(&r, 6, ROLES_QUERY)?,
        });
    }
    for r in rows(client, MEMBERSHIPS_QUERY).await? {
        out.memberships.push(Membership {
            member: cell(&r, 0, MEMBERSHIPS_QUERY)?,
            role: cell(&r, 1, MEMBERSHIPS_QUERY)?,
        });
    }
    for r in rows(client, DATABASE_GRANTS_QUERY).await? {
        out.database_grants.push(DatabaseGrant {
            database: cell(&r, 0, DATABASE_GRANTS_QUERY)?,
            grantee: cell(&r, 1, DATABASE_GRANTS_QUERY)?,
            privilege: cell(&r, 2, DATABASE_GRANTS_QUERY)?,
        });
    }
    out.extensions = read_extensions(client).await?;
    let errors = rows(client, HBA_ERRORS_QUERY).await?;
    let failed: i64 = match errors.first() {
        Some(r) => cell(r, 0, HBA_ERRORS_QUERY)?,
        None => return Err(ControlError::Catalogue(HBA_ERRORS_QUERY)),
    };
    if failed != 0 {
        return Err(ControlError::Catalogue(HBA_ERRORS_QUERY));
    }
    for r in rows(client, HBA_QUERY).await? {
        out.hba.push(HbaRule {
            line: cell(&r, 0, HBA_QUERY)?,
            kind: cell(&r, 1, HBA_QUERY)?,
            database: cell(&r, 2, HBA_QUERY)?,
            user: cell(&r, 3, HBA_QUERY)?,
            address: cell(&r, 4, HBA_QUERY)?,
            method: cell(&r, 5, HBA_QUERY)?,
        });
    }
    let mut owners = Vec::new();
    for r in rows(client, DATABASE_OWNERS_QUERY).await? {
        owners.push(DatabaseOwner {
            database: cell(&r, 0, DATABASE_OWNERS_QUERY)?,
            owner: cell(&r, 1, DATABASE_OWNERS_QUERY)?,
        });
    }
    Ok(AuditRows {
        catalogue: out,
        database_owners: owners,
        open_g14: read_open_g14(client).await?,
    })
}

/// Reads the G14 objects that PUBLIC can still use in the connected
/// database. `pg_catalog` privileges are kept per database, so the job
/// reads them in each database that [`read_databases`] names and merges
/// the rows.
///
/// # Errors
///
/// [`ControlError::Catalogue`] naming the query.
pub async fn read_open_g14<R: Runtime>(
    client: &mut Client<R>,
) -> Result<Vec<OpenG14Object>, ControlError> {
    let mut out = Vec::new();
    for r in rows(client, OPEN_G14_QUERY).await? {
        out.push(OpenG14Object {
            database: cell(&r, 0, OPEN_G14_QUERY)?,
            kind: cell(&r, 1, OPEN_G14_QUERY)?,
            name: cell(&r, 2, OPEN_G14_QUERY)?,
            privilege: cell(&r, 3, OPEN_G14_QUERY)?,
        });
    }
    Ok(out)
}

/// Reads the extension names of the connected database. `pg_extension`
/// is per database, so the job reads it in each database that
/// [`read_databases`] names and merges the names.
///
/// # Errors
///
/// [`ControlError::Catalogue`] naming the query.
pub async fn read_extensions<R: Runtime>(
    client: &mut Client<R>,
) -> Result<Vec<String>, ControlError> {
    rows(client, EXTENSIONS_QUERY)
        .await?
        .iter()
        .map(|r| cell(r, 0, EXTENSIONS_QUERY))
        .collect()
}

/// Reads the names of the databases that take connections.
///
/// # Errors
///
/// [`ControlError::Catalogue`] naming the query.
pub async fn read_databases<R: Runtime>(
    client: &mut Client<R>,
) -> Result<Vec<String>, ControlError> {
    rows(client, DATABASES_QUERY)
        .await?
        .iter()
        .map(|r| cell(r, 0, DATABASES_QUERY))
        .collect()
}
