//! Shared helpers for the `fstp-control` integration tests (lane W2h, test
//! author): the reference role sets and schemas, the `apply_grant` argument
//! grammars, the refusal checks, and host names.
//!
//! The references come from the documents, never from the code under test.
//! ADR-011 "DDL identifier grammar" gives the role sets. Design sections
//! 4.2 and 4.3 give the schemas. Design section 4.1 gives the
//! `apply_grant` grammars, and the tests tie them to the shared SQL text.

#![allow(dead_code, unreachable_pub)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_control::ControlError;
use fstp_control::pg::{CellDatabase, Privilege};
use fstp_cp_proto::{CellId, RoleName};
use fstp_prop::Gen;

/// A random cell id.
pub fn random_cell(g: &mut Gen) -> CellId {
    let b = g.bytes(16..=16);
    CellId(b.try_into().unwrap_or([0; 16]))
}

/// The 32 lowercase hex digits of `cell` (design section 4.1).
pub fn cell_hex(cell: CellId) -> String {
    cell.0.iter().map(|b| format!("{b:02x}")).collect()
}

/// `c_<cell>` or `v_<cell>`.
pub fn database_name(db: CellDatabase, cell: CellId) -> String {
    let prefix = match db {
        CellDatabase::App => "c",
        CellDatabase::Vault => "v",
    };
    format!("{prefix}_{}", cell_hex(cell))
}

/// `<database>_<suffix>`.
pub fn role_name(db: CellDatabase, cell: CellId, role: RoleName) -> String {
    format!("{}_{}", database_name(db, cell), role.suffix())
}

/// The roles of each database, from the ADR-011 table "DDL identifier
/// grammar": the application roles take `migrator`, `writer`, `app`,
/// `keys` and `auditor`; the vault roles take `migrator`, `vault` and
/// `keys`.
pub fn adr011_roles(db: CellDatabase) -> &'static [RoleName] {
    match db {
        CellDatabase::App => &[
            RoleName::Migrator,
            RoleName::Writer,
            RoleName::App,
            RoleName::Keys,
            RoleName::Auditor,
        ],
        CellDatabase::Vault => &[RoleName::Migrator, RoleName::Vault, RoleName::Keys],
    }
}

/// The schemas of each database that hold tables a cell role may be
/// granted on: design section 4.2 for the application database, section
/// 4.3 and the keystore of section 4.2 for the vault database. Both hold
/// `fstp_meta`, whose `fstp_meta.placement` both migration sets define
/// (design section 4.1, `0000_meta.sql`) and both start checks read
/// (design section 9.2, "At start").
pub fn schemas_of(db: CellDatabase) -> &'static [&'static str] {
    match db {
        CellDatabase::App => &[
            "ledger",
            "audit",
            "blob",
            "keystore",
            "auth",
            "auth_log",
            "ops",
            "fstp_meta",
        ],
        CellDatabase::Vault => &["vault", "keystore", "vault_audit", "fstp_meta"],
    }
}

/// The schema part of `schema.table`.
pub fn schema_of(object: &str) -> &str {
    object.split_once('.').map_or(object, |(s, _)| s)
}

/// Whether `object` is append-only (ADR-007, I-24, design section 4.1):
/// the ledger, the audit chain and anchors, the auth side-effect log, the
/// outbox, and the vault's own audit chain. No role may UPDATE or DELETE
/// there.
pub fn append_only(db: CellDatabase, object: &str) -> bool {
    match db {
        CellDatabase::App => {
            matches!(schema_of(object), "ledger" | "auth_log")
                || matches!(object, "audit.chain" | "audit.anchor" | "ops.outbox")
        }
        CellDatabase::Vault => schema_of(object) == "vault_audit",
    }
}

/// The SQL keyword of a privilege.
pub fn keyword(p: Privilege) -> &'static str {
    match p {
        Privilege::Select => "SELECT",
        Privilege::Insert => "INSERT",
        Privilege::Update => "UPDATE",
        Privilege::Delete => "DELETE",
    }
}

/// The `privs` argument `fstp-pgagent` passes for a grant row: the
/// keywords joined by ", ", as the grammar spells a list.
pub fn privs_argument(ps: &[Privilege]) -> String {
    ps.iter()
        .map(|p| keyword(*p))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The privilege grammar of `apply_grant`, as design section 4.1 writes it.
pub const PRIVS_GRAMMAR: &str = "^(SELECT|INSERT|UPDATE|DELETE)(, (SELECT|INSERT|UPDATE|DELETE))*$";

/// The object grammar of `apply_grant`, as design section 4.1 writes it.
pub const OBJECT_GRAMMAR: &str = r"^[a-z_]{1,30}\.[a-z_]{1,30}$";

/// The cell grammar of `apply_grant`, as design section 4.1 writes it.
pub const CELL_GRAMMAR: &str = "^[0-9a-f]{32}$";

/// [`PRIVS_GRAMMAR`], by hand.
pub fn privs_fit(s: &str) -> bool {
    let words = ["SELECT", "INSERT", "UPDATE", "DELETE"];
    !s.is_empty() && s.split(", ").all(|w| words.contains(&w))
}

/// [`OBJECT_GRAMMAR`], by hand.
pub fn object_fits(s: &str) -> bool {
    let part = |p: &str| {
        (1..=30).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
    };
    match s.split_once('.') {
        Some((a, b)) => part(a) && part(b),
        None => false,
    }
}

/// Ok when `r` is a refusal by a real check. A `NotImplemented` error is a
/// stub, not a refusal, so it fails here.
pub fn refused<T: std::fmt::Debug>(what: &str, r: Result<T, ControlError>) -> Result<(), String> {
    #[allow(
        unreachable_patterns,
        reason = "lane W2h adds the refusal variants of ControlError"
    )]
    match r {
        Ok(v) => Err(format!("{what} was accepted as {v:?}")),
        Err(ControlError::NotImplemented(op)) => Err(format!("{op} is NotImplemented ({what})")),
        Err(_) => Ok(()),
    }
}

/// Whether `e` is the W0 stub error.
pub fn is_stub(e: &ControlError) -> bool {
    matches!(e, ControlError::NotImplemented(_))
}

/// Whether `name` is a DNS host name in lowercase LDH form. It has 1 to
/// 253 bytes in dot-separated labels. Each label holds 1 to 63 lowercase
/// letters, digits and hyphens, and starts and ends with no hyphen. The
/// last label is not all digits. This is the host form of the tunnel header
/// (ADR-009) and of fstp-pki dNSName entries.
pub fn is_ldh_host(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = name.split('.').collect();
    let label_ok = |l: &&str| {
        (1..=63).contains(&l.len())
            && l.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !l.starts_with('-')
            && !l.ends_with('-')
    };
    labels.iter().all(label_ok)
        && labels
            .last()
            .is_some_and(|l| !l.bytes().all(|b| b.is_ascii_digit()))
}
