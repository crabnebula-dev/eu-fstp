//! The cell role plan (I-82, design sections 4.1, 9.2 and 9.5, ADR-011).
//!
//! [`cell_role_plan`] is the single owner of every role, CONNECT grant,
//! revocation, grant row and `pg_hba` line of a cell's two databases.
//! `fstp-pgagent` applies the plan, and calls `fstp_meta.apply_grant` once
//! per [`GrantRow`]. The self-hosted `fstp-install` reuses the same plan,
//! so the two modes share one implementation.
//!
//! The rows never depend on the cell. Only [`RolePlan::cell`] names it,
//! and every rendered name is built from it and a closed suffix, so no row
//! can reach another cell's database.
//!
//! Readings of design section 4.1, the same that lane W1f wrote into the
//! reference of `fstp_celltest::mc::place_model`:
//!
//! - "full rights" are SELECT, INSERT, UPDATE and DELETE, the four
//!   privileges of the `apply_grant` grammar;
//! - "the stored ledger rows" for the auditor are `ledger.command` and
//!   `ledger.entry`;
//! - the `keys` role's DELETE on `blob` rows of completed erasures is a
//!   table grant on `blob.text`, with SELECT so that a DELETE can find one
//!   row by id. Row conditions are not in the grammar;
//! - in the vault database, "the same pattern" gives the `keys` role full
//!   rights on the keystore only and the `vault` role exactly INSERT and
//!   SELECT on `vault_audit`. On the `vault` tables the `vault` role holds
//!   SELECT, INSERT and UPDATE, except INSERT and SELECT only on
//!   `vault.ticket_used`, `vault.query_log` and
//!   `vault.country_condition`. The first two are logs, and an UPDATE of a
//!   used ticket would let it be presented again. A P-17 country
//!   condition is fixed once set (NOTE 6), and its table refuses UPDATE
//!   for every role. No vault role holds DELETE;
//! - the placement marker `fstp_meta.placement` (design section 4.1) is
//!   read at start by the role the process runs as: the `app` role in the
//!   application database and the `vault` role in the vault database
//!   (design section 9.2, "At start"). Each holds SELECT on it and nothing
//!   more. No other role reads it, and the migrator owns it.

use std::fmt::Write as _;
use std::net::IpAddr;

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

impl CellDatabase {
    /// Both databases.
    pub const ALL: [CellDatabase; 2] = [CellDatabase::App, CellDatabase::Vault];

    /// The name prefix: `c` or `v` (ADR-011 "DDL identifier grammar").
    pub const fn prefix(self) -> char {
        match self {
            CellDatabase::App => 'c',
            CellDatabase::Vault => 'v',
        }
    }
}

/// A table privilege, as the `apply_grant` grammar takes it. Closed. The
/// order of the variants is the order the grammar lists them in.
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

impl Privilege {
    /// The SQL keyword.
    pub const fn keyword(self) -> &'static str {
        match self {
            Privilege::Select => "SELECT",
            Privilege::Insert => "INSERT",
            Privilege::Update => "UPDATE",
            Privilege::Delete => "DELETE",
        }
    }
}

/// A login role of a cell, created as NOLOGIN at provisioning, with
/// NOSUPERUSER, NOCREATEDB, NOCREATEROLE, NOREPLICATION and NOBYPASSRLS,
/// a member of no role. It holds CONNECT on its own database only.
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
    /// The privileges, distinct and in the grammar's order.
    pub privileges: Vec<Privilege>,
    /// The object as `schema.table`, from the database's catalogue.
    pub object: &'static str,
    /// The grantee.
    pub role: RoleName,
}

impl GrantRow {
    /// The `privs` argument of `apply_grant`: the keywords joined by `", "`.
    pub fn privs_argument(&self) -> String {
        let words: Vec<&str> = self.privileges.iter().map(|p| p.keyword()).collect();
        words.join(", ")
    }
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

/// A revocation the plan applies to one of the cell's databases (design
/// section 4.1, G14, ADR-011 `ApplyRevocations`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Revocation {
    /// `REVOKE ALL ON DATABASE <db> FROM PUBLIC`: CONNECT, CREATE and
    /// TEMPORARY. CONNECT then goes only to the cell's own roles.
    DatabaseFromPublic(CellDatabase),
    /// The cross-database statistics views of G14, and EXECUTE on every
    /// `pg_stat_get_*` function behind them (Daniel, 2026-10-29), revoked
    /// from PUBLIC inside the database.
    StatisticsFromPublic(CellDatabase),
    /// An event trigger inside the database that refuses `CREATE
    /// EXTENSION` and `ALTER EXTENSION` for every role (design section
    /// 4.1). The migrator holds CREATE on its database to create its
    /// schemas, and that privilege alone would let it create a trusted
    /// extension.
    ExtensionGuard(CellDatabase),
}

/// A database privilege, as `GRANT ... ON DATABASE` takes it. Closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DatabasePrivilege {
    /// `CONNECT`.
    Connect,
    /// `CREATE`: new schemas. The migrator only, since it owns every
    /// schema (design section 4.1).
    Create,
}

impl DatabasePrivilege {
    /// The SQL keyword.
    pub const fn keyword(self) -> &'static str {
        match self {
            DatabasePrivilege::Connect => "CONNECT",
            DatabasePrivilege::Create => "CREATE",
        }
    }
}

/// One privilege of a cell role on its own database. Every role holds
/// CONNECT, and no role holds a privilege on another database.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DatabasePrivilegeRow {
    /// The database, the role's own.
    pub database: CellDatabase,
    /// The role.
    pub role: RoleName,
    /// The privilege.
    pub privilege: DatabasePrivilege,
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
    /// The revocations of both databases, applied after the databases and
    /// roles exist and before any role may log in.
    pub revocations: Vec<Revocation>,
    /// The database privileges of each role on its own database.
    pub database_privileges: Vec<DatabasePrivilegeRow>,
}

/// The login roles of the application database (ADR-011 "DDL identifier
/// grammar").
pub const APP_ROLES: [RoleName; 5] = [
    RoleName::Migrator,
    RoleName::Writer,
    RoleName::App,
    RoleName::Keys,
    RoleName::Auditor,
];

/// The login roles of the vault database (ADR-011).
pub const VAULT_ROLES: [RoleName; 3] = [RoleName::Migrator, RoleName::Vault, RoleName::Keys];

/// The login roles of `db`.
pub fn roles_of(db: CellDatabase) -> &'static [RoleName] {
    match db {
        CellDatabase::App => &APP_ROLES,
        CellDatabase::Vault => &VAULT_ROLES,
    }
}

/// The tables of the application database (design section 4.2, and the
/// journey read model of ADR-015 "Storage and roles"), in the order of
/// the migration set.
pub const APP_TABLES: [&str; 24] = [
    "ledger.command",
    "ledger.entry",
    "audit.chain",
    "audit.anchor",
    "blob.text",
    "keystore.root",
    "keystore.group_key",
    "keystore.data_key",
    "keystore.erasure_intent",
    "auth.session",
    "auth.challenge",
    "auth.sign_count",
    "auth.token",
    "auth_log.stepup_consumed",
    "auth_log.session_end",
    "ops.outbox",
    "ops.checkpoint",
    "ops.licence_state",
    "journey.entry",
    "journey.entry_text",
    "journey.projection_cursor",
    "journey.leg",
    "journey.route_start",
    "journey.assignment",
];

/// The tables of the vault database (design section 4.3, with the
/// keystore of section 4.2).
pub const VAULT_TABLES: [&str; 15] = [
    "vault.epoch",
    "vault.fact",
    "vault.identity",
    "vault.account",
    "vault.document",
    "vault.negotiation",
    "vault.ticket_used",
    "vault.query_log",
    "vault.country_condition",
    "keystore.root",
    "keystore.group_key",
    "keystore.data_key",
    "keystore.erasure_intent",
    "vault_audit.chain",
    "vault_audit.anchor",
];

/// The placement marker of both databases (design section 4.1,
/// `0000_meta.sql`). Each migration set defines it in `fstp_meta`.
pub const PLACEMENT_TABLE: &str = "fstp_meta.placement";

/// The tables of the `fstp_meta` schema that a cell role is granted on,
/// in either database: the placement marker only. `fstp_meta.apply_grant`
/// lives there too, and only its owner may call it.
pub const META_TABLES: [&str; 1] = [PLACEMENT_TABLE];

const S: &[Privilege] = &[Privilege::Select];
const SI: &[Privilege] = &[Privilege::Select, Privilege::Insert];
const SIU: &[Privilege] = &[Privilege::Select, Privilege::Insert, Privilege::Update];
const SD: &[Privilege] = &[Privilege::Select, Privilege::Delete];
const FULL: &[Privilege] = &[
    Privilege::Select,
    Privilege::Insert,
    Privilege::Update,
    Privilege::Delete,
];

fn schema_of(object: &str) -> &str {
    object.split_once('.').map_or(object, |(s, _)| s)
}

/// The privileges of `role` on the application table `object` (design
/// section 4.1, ADR-007).
fn app_privileges(role: RoleName, object: &str) -> &'static [Privilege] {
    let schema = schema_of(object);
    match role {
        // ADR-007: the writer "holds INSERT and SELECT only", on the
        // append-only tables.
        RoleName::Writer => match schema {
            "ledger" | "auth_log" => SI,
            "audit" if matches!(object, "audit.chain" | "audit.anchor") => SI,
            "ops" if object == "ops.outbox" => SI,
            _ => &[],
        },
        RoleName::App => match schema {
            "ledger" | "audit" | "auth_log" => S,
            "auth" => FULL,
            "ops" if object == "ops.outbox" => S,
            "ops" => FULL,
            "blob" => SI,
            // ADR-015: the projector runs as `app` and writes append-only
            // rows, so INSERT and SELECT only.
            "journey" => SI,
            // The I-83 start check of `fstp-cell` (design section 9.2).
            "fstp_meta" if object == PLACEMENT_TABLE => S,
            _ => &[],
        },
        RoleName::Keys => match schema {
            "keystore" => FULL,
            "blob" => SD,
            _ => &[],
        },
        RoleName::Auditor => match schema {
            "audit" | "ledger" => S,
            _ => &[],
        },
        // The migrator owns every schema. The vault role has no table here.
        RoleName::Migrator | RoleName::Vault => &[],
    }
}

/// The privileges of `role` on the vault table `object` (design section
/// 4.1 "same pattern", read as the module docs say).
fn vault_privileges(role: RoleName, object: &str) -> &'static [Privilege] {
    match (role, schema_of(object)) {
        (RoleName::Keys, "keystore") => FULL,
        (RoleName::Vault, "vault_audit") => SI,
        (RoleName::Vault, "vault") => match object {
            "vault.ticket_used" | "vault.query_log" | "vault.country_condition" => SI,
            _ => SIU,
        },
        // The I-83 start check of `fstp-vault` (design section 9.2).
        (RoleName::Vault, "fstp_meta") if object == PLACEMENT_TABLE => S,
        _ => &[],
    }
}

fn grant_rows(
    db: CellDatabase,
    tables: &[&'static str],
    privileges: fn(RoleName, &str) -> &'static [Privilege],
    out: &mut Vec<GrantRow>,
) {
    for object in tables {
        for role in roles_of(db) {
            let privs = privileges(*role, object);
            if !privs.is_empty() {
                out.push(GrantRow {
                    database: db,
                    privileges: privs.to_vec(),
                    object,
                    role: *role,
                });
            }
        }
    }
}

/// The role plan of `cell` (I-82). The only source of grant rows.
///
/// # Errors
///
/// None today. The `Result` keeps room for a plan that depends on a
/// registry read.
pub fn cell_role_plan(cell: CellId) -> Result<RolePlan, ControlError> {
    let mut roles = Vec::new();
    let mut hba = Vec::new();
    let mut revocations = Vec::new();
    let mut database_privileges = Vec::new();
    for db in CellDatabase::ALL {
        for role in roles_of(db) {
            roles.push(RoleRow {
                database: db,
                role: *role,
            });
            hba.push(HbaLine {
                database: db,
                role: *role,
            });
            database_privileges.push(DatabasePrivilegeRow {
                database: db,
                role: *role,
                privilege: DatabasePrivilege::Connect,
            });
            if *role == RoleName::Migrator {
                database_privileges.push(DatabasePrivilegeRow {
                    database: db,
                    role: *role,
                    privilege: DatabasePrivilege::Create,
                });
            }
        }
        revocations.push(Revocation::DatabaseFromPublic(db));
        revocations.push(Revocation::StatisticsFromPublic(db));
        revocations.push(Revocation::ExtensionGuard(db));
    }
    let mut grants = Vec::new();
    grant_rows(CellDatabase::App, &APP_TABLES, app_privileges, &mut grants);
    grant_rows(CellDatabase::App, &META_TABLES, app_privileges, &mut grants);
    grant_rows(
        CellDatabase::Vault,
        &VAULT_TABLES,
        vault_privileges,
        &mut grants,
    );
    grant_rows(
        CellDatabase::Vault,
        &META_TABLES,
        vault_privileges,
        &mut grants,
    );
    Ok(RolePlan {
        cell,
        roles,
        grants,
        hba,
        revocations,
        database_privileges,
    })
}

/// The 32 lowercase hex digits of `cell` (design section 4.1).
pub fn cell_hex(cell: CellId) -> String {
    let mut out = String::with_capacity(32);
    for b in cell.0 {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// The name of `db` for `cell`: `c_<cell>` or `v_<cell>`.
pub fn database_name(db: CellDatabase, cell: CellId) -> String {
    format!("{}_{}", db.prefix(), cell_hex(cell))
}

/// The name of `role` in `db` for `cell`: `<database>_<suffix>`.
///
/// # Errors
///
/// [`ControlError::RoleOutsideDatabase`] for a role of the other
/// database's set, such as `c_<cell>_vault`.
pub fn role_name(db: CellDatabase, cell: CellId, role: RoleName) -> Result<String, ControlError> {
    if !roles_of(db).contains(&role) {
        return Err(ControlError::RoleOutsideDatabase);
    }
    Ok(format!("{}_{}", database_name(db, cell), role.suffix()))
}

// ---------------------------------------------------------------------------
// pg_hba.conf (design section 4.1, ADR-005 D2, ADR-011).

/// The subnet a cell's components connect from, as a `pg_hba` address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CellSubnet {
    addr: IpAddr,
    prefix: u8,
}

impl CellSubnet {
    /// The subnet `addr/prefix`. The host bits of `addr` must be zero, so
    /// each subnet has one spelling.
    ///
    /// # Errors
    ///
    /// [`ControlError::Subnet`] for a prefix longer than the address or a
    /// host bit set.
    pub fn new(addr: IpAddr, prefix: u8) -> Result<CellSubnet, ControlError> {
        let (bits, value): (u32, u128) = match addr {
            IpAddr::V4(a) => (32, u128::from(u32::from(a))),
            IpAddr::V6(a) => (128, u128::from(a)),
        };
        let prefix32 = u32::from(prefix);
        if prefix32 > bits {
            return Err(ControlError::Subnet);
        }
        let host_bits = bits.checked_sub(prefix32).ok_or(ControlError::Subnet)?;
        let mask = 1u128
            .checked_shl(host_bits)
            .map_or(u128::MAX, |v| v.wrapping_sub(1));
        if value & mask != 0 {
            return Err(ControlError::Subnet);
        }
        Ok(CellSubnet { addr, prefix })
    }
}

impl std::fmt::Display for CellSubnet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// The loopback line of the superuser, the only line it has (G4, Q4 A).
pub const HBA_SUPERUSER_LINE: &str =
    "hostssl all fstp_super 127.0.0.1/32 scram-sha-256 clientcert=verify-full";

/// The loopback line of the replication role, the only line it has (G22,
/// Q4 A).
pub const HBA_REPLICATION_LINE: &str =
    "hostssl replication fstp_repl 127.0.0.1/32 scram-sha-256 clientcert=verify-full";

/// The final lines: every other connection is rejected.
pub const HBA_REJECT_LINES: [&str; 3] = [
    "local all all reject",
    "host all all 0.0.0.0/0 reject",
    "host all all ::/0 reject",
];

/// Renders the `pg_hba.conf` of a cluster that holds the `db` databases of
/// `cells`, each with the subnet its components connect from.
///
/// The file holds the superuser and replication lines, then one `hostssl
/// <db> <role> <subnet> scram-sha-256 clientcert=verify-full` line per
/// role and database of each cell's plan, then the reject lines. No line
/// names `all` for a cell role, a group, a file or another keyword.
///
/// # Errors
///
/// None today. The `Result` follows [`cell_role_plan`].
pub fn render_hba(
    db: CellDatabase,
    cells: &[(CellId, CellSubnet)],
) -> Result<String, ControlError> {
    let mut out = String::new();
    out.push_str("# Generated by fstp_control::pg::render_hba. Do not edit.\n");
    out.push_str(HBA_SUPERUSER_LINE);
    out.push('\n');
    out.push_str(HBA_REPLICATION_LINE);
    out.push('\n');
    for (cell, subnet) in cells {
        let plan = cell_role_plan(*cell)?;
        let database = database_name(db, *cell);
        for line in plan.hba.iter().filter(|h| h.database == db) {
            let role = role_name(db, *cell, line.role)?;
            let _ = writeln!(
                out,
                "hostssl {database} {role} {subnet} scram-sha-256 clientcert=verify-full"
            );
        }
    }
    for line in HBA_REJECT_LINES {
        out.push_str(line);
        out.push('\n');
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// I-82, design section 4.1: the rendered file has the machinery lines,
    /// one line per cell role naming its own database, and ends with a
    /// reject line.
    #[test]
    fn i82_render_hba_has_one_line_per_role_and_ends_with_reject() {
        let a = CellId([0xaa; 16]);
        let b = CellId([0xbb; 16]);
        let net = CellSubnet::new(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0)), 24).unwrap();
        let text = render_hba(CellDatabase::App, &[(a, net), (b, net)]).unwrap();
        let lines: Vec<&str> = text.lines().filter(|l| !l.starts_with('#')).collect();
        assert_eq!(lines.first(), Some(&HBA_SUPERUSER_LINE));
        assert_eq!(lines.last(), Some(&"host all all ::/0 reject"));
        let cell_lines: Vec<&&str> = lines.iter().filter(|l| l.contains(" c_")).collect();
        assert_eq!(cell_lines.len(), 2 * APP_ROLES.len());
        for l in cell_lines {
            let f: Vec<&str> = l.split(' ').collect();
            assert_eq!(f.len(), 6, "{l}");
            assert!(f[2].starts_with(f[1]), "{l}");
            assert_eq!(f[3], "10.1.0.0/24");
        }
    }

    /// I-82: a subnet with a host bit set, or a prefix too long, is
    /// refused, so the address has one spelling.
    #[test]
    fn i82_cell_subnet_refuses_host_bits_and_long_prefixes() {
        let v4 = |a, b, c, d| IpAddr::V4(Ipv4Addr::new(a, b, c, d));
        assert!(CellSubnet::new(v4(10, 0, 0, 0), 8).is_ok());
        assert!(CellSubnet::new(v4(10, 0, 0, 1), 32).is_ok());
        assert!(CellSubnet::new(v4(0, 0, 0, 0), 0).is_ok());
        assert_eq!(
            CellSubnet::new(v4(10, 0, 0, 1), 24),
            Err(ControlError::Subnet)
        );
        assert_eq!(
            CellSubnet::new(v4(10, 0, 0, 0), 33),
            Err(ControlError::Subnet)
        );
    }

    /// I-83, I-82, design sections 4.1 and 9.2: the plan grants SELECT on
    /// the placement marker to the role each start check reads it as, the
    /// `app` role in the application database and the `vault` role in the
    /// vault database, and to no other role. No row names a vault table
    /// outside the catalogue of design section 4.3.
    #[test]
    fn i83_plan_grants_the_placement_marker_to_the_start_check_roles_only() {
        let plan = cell_role_plan(CellId([7; 16])).unwrap();
        let placement: Vec<(CellDatabase, RoleName, Vec<Privilege>)> = plan
            .grants
            .iter()
            .filter(|g| g.object == PLACEMENT_TABLE)
            .map(|g| (g.database, g.role, g.privileges.clone()))
            .collect();
        assert_eq!(
            placement,
            vec![
                (CellDatabase::App, RoleName::App, vec![Privilege::Select]),
                (
                    CellDatabase::Vault,
                    RoleName::Vault,
                    vec![Privilege::Select]
                ),
            ]
        );
        for g in &plan.grants {
            let known = match g.database {
                CellDatabase::App => APP_TABLES.contains(&g.object),
                CellDatabase::Vault => VAULT_TABLES.contains(&g.object),
            };
            assert!(known || META_TABLES.contains(&g.object), "{g:?}");
        }
    }

    /// I-82, NOTE 6, design sections 4.1 and 4.3: the P-17 country
    /// conditions are granted through the plan. The `vault` role holds
    /// exactly SELECT and INSERT on `vault.country_condition`, since a
    /// condition is fixed once set, and no other role holds anything on
    /// it. The name fits the `apply_grant` object grammar of ADR-011.
    #[test]
    fn i82_plan_grants_the_country_condition_to_the_vault_role_only() {
        let plan = cell_role_plan(CellId([9; 16])).unwrap();
        let rows: Vec<(CellDatabase, RoleName, Vec<Privilege>)> = plan
            .grants
            .iter()
            .filter(|g| g.object == "vault.country_condition")
            .map(|g| (g.database, g.role, g.privileges.clone()))
            .collect();
        assert_eq!(
            rows,
            vec![(
                CellDatabase::Vault,
                RoleName::Vault,
                vec![Privilege::Select, Privilege::Insert]
            )]
        );
        let (schema, table) = "vault.country_condition".split_once('.').unwrap();
        for part in [schema, table] {
            assert!(
                (1..=30).contains(&part.len())
                    && part.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{part} is outside the apply_grant object grammar"
            );
        }
    }

    /// I-82, ADR-011: a role of the other database's set has no name.
    #[test]
    fn i82_role_name_refuses_a_role_of_the_other_database() {
        let cell = CellId([1; 16]);
        assert_eq!(
            role_name(CellDatabase::App, cell, RoleName::Vault),
            Err(ControlError::RoleOutsideDatabase)
        );
        assert_eq!(
            role_name(CellDatabase::Vault, cell, RoleName::Writer),
            Err(ControlError::RoleOutsideDatabase)
        );
        assert_eq!(
            role_name(CellDatabase::Vault, cell, RoleName::Keys).unwrap(),
            format!("v_{}_keys", "01".repeat(16))
        );
    }
}
