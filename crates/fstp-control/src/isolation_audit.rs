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
//! catalogue rows that the job has read.
//!
//! Status: W0 stub. Lane W2h fills it. [`privilege_graph`] refuses with
//! [`ControlError::NotImplemented`] until then.

use crate::ControlError;

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

/// Builds the privilege graph of one cluster from its catalogue rows.
pub fn privilege_graph(rows: &CatalogueRows) -> Result<PrivilegeGraph, ControlError> {
    let _ = rows;
    Err(ControlError::NotImplemented(
        "fstp_control::isolation_audit::privilege_graph",
    ))
}
