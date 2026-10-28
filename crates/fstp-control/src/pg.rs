//! The cell role plan (I-82, design sections 4.1, 9.2 and 9.5, ADR-011).
//!
//! [`cell_role_plan`] is the single owner of every role, grant row and
//! `pg_hba` line of a cell's two databases. `fstp-pgagent` applies the
//! plan, and calls `fstp_meta.apply_grant` once per [`GrantRow`]. The
//! self-hosted `fstp-install` reuses the same plan, so the two modes share
//! one implementation.
//!
//! Status: W0 stub. Lane W2h fills it. [`cell_role_plan`] refuses with
//! [`ControlError::NotImplemented`] until then.

use fstp_cp_proto::{CellId, RoleName};

use crate::ControlError;

/// One of a cell's two databases.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CellDatabase {
    /// The application database `c_<cell>` on an application cluster.
    App,
    /// The vault database `v_<cell>` on a vault cluster.
    Vault,
}

/// A table privilege, as the `apply_grant` grammar takes it. Closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Privilege {
    /// `SELECT`.
    Select,
    /// `INSERT`.
    Insert,
    /// `UPDATE`.
    Update,
    /// `DELETE`.
    Delete,
}

/// A login role of a cell, created as NOLOGIN at provisioning.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RoleRow {
    /// The database whose prefix the role takes.
    pub database: CellDatabase,
    /// The role suffix.
    pub role: RoleName,
}

/// One grant, applied through `fstp_meta.apply_grant(privs, object,
/// suffix)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantRow {
    /// The database the grant runs in.
    pub database: CellDatabase,
    /// The privileges, in the grammar's order.
    pub privileges: Vec<Privilege>,
    /// The object as `schema.table`, from the database's catalogue.
    pub object: &'static str,
    /// The grantee.
    pub role: RoleName,
}

/// One `hostssl <db> <role> <cell subnet> scram-sha-256
/// clientcert=verify-full` line.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HbaLine {
    /// The database.
    pub database: CellDatabase,
    /// The role.
    pub role: RoleName,
}

/// The whole plan of one cell.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RolePlan {
    /// The cell.
    pub cell: CellId,
    /// The roles of both databases.
    pub roles: Vec<RoleRow>,
    /// The grant rows of both databases.
    pub grants: Vec<GrantRow>,
    /// The `pg_hba` lines, one per role and database. A final reject line
    /// follows them and is not a row.
    pub hba: Vec<HbaLine>,
}

/// The role plan of `cell` (I-82). The only source of grant rows.
pub fn cell_role_plan(cell: CellId) -> Result<RolePlan, ControlError> {
    let _ = cell;
    Err(ControlError::NotImplemented(
        "fstp_control::pg::cell_role_plan",
    ))
}
