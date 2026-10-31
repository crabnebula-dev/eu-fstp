//! I-82, design section 4.1, ADR-007, ADR-011: the cell role plan and its
//! grant rows.
//!
//! `fstp_control::pg::cell_role_plan` is the only source of a cell's roles,
//! `pg_hba` lines and grant rows (ADR-011 "The cell role plan"). These
//! tests check which roles exist and that rows never depend on the cell.
//! They check that each row fits the `fstp_meta.apply_grant` grammar of
//! the shared SQL text, and the rules design section 4.1 and ADR-007 set
//! per role. The full grant table, row by row, is pinned
//! by `i82_role_plan_matches_design_section_4_1` in `fstp-celltest`
//! (lane W1f). These tests take the same readings and add the per-rule
//! checks, so a failure names the rule it breaks.
//!
//! Lane W2h test author. Red until lane W2h writes the plan:
//! `cell_role_plan` is a W0 stub that refuses with
//! `ControlError::NotImplemented`. The two tests that tie the grammars to
//! the shared SQL text need no plan and pass today.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use std::collections::BTreeSet;

use common::{
    CELL_GRAMMAR, OBJECT_GRAMMAR, PRIVS_GRAMMAR, adr011_roles, append_only, cell_hex, object_fits,
    privs_argument, privs_fit, random_cell, role_name, schema_of, schemas_of,
};
use fstp_control::pg::{CellDatabase, GrantRow, Privilege, RolePlan, cell_role_plan};
use fstp_cp_proto::{CellId, ROLE_SUFFIX_GRAMMAR, RoleName};
use fstp_migrate::catalogue::APPLY_GRANT_SQL;
use fstp_prop::{Gen, prop_assert, prop_assert_eq};

const DATABASES: [CellDatabase; 2] = [CellDatabase::App, CellDatabase::Vault];

fn plan(cell: CellId) -> Result<RolePlan, String> {
    cell_role_plan(cell).map_err(|e| format!("cell_role_plan: {e}"))
}

/// The grant rows of a random cell's plan.
fn grants(g: &mut Gen) -> Result<Vec<GrantRow>, String> {
    Ok(plan(random_cell(g))?.grants)
}

/// Checks `rule` on every grant row of a random cell's plan.
fn every_grant(g: &mut Gen, rule: impl Fn(&GrantRow) -> Result<(), String>) -> Result<(), String> {
    let rows = grants(g)?;
    prop_assert!(!rows.is_empty(), "the plan has no grant rows");
    for row in &rows {
        rule(row)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Roles and pg_hba lines.

/// I-82, ADR-011: the plan names its own cell and holds exactly the roles
/// of the ADR-011 grammar for each database, each once.
#[test]
fn i82_role_plan_names_its_cell_and_the_adr011_roles() {
    fstp_prop::check(
        "i82_role_plan_names_its_cell_and_the_adr011_roles",
        |g: &mut Gen| {
            let cell = random_cell(g);
            let p = plan(cell)?;
            prop_assert_eq!(p.cell, cell);
            for db in DATABASES {
                let rows: Vec<RoleName> = p
                    .roles
                    .iter()
                    .filter(|r| r.database == db)
                    .map(|r| r.role)
                    .collect();
                let set: BTreeSet<RoleName> = rows.iter().copied().collect();
                prop_assert_eq!(
                    rows.len(),
                    set.len(),
                    "a role row of {db:?} twice: {rows:?}"
                );
                let want: BTreeSet<RoleName> = adr011_roles(db).iter().copied().collect();
                prop_assert_eq!(set, want, "roles of {db:?}");
            }
            Ok(())
        },
    );
}

/// I-82, design section 4.1: one `pg_hba` line per role and database, and
/// no line for a role the plan does not create.
#[test]
fn i82_role_plan_has_one_hba_line_per_role_and_database() {
    fstp_prop::check(
        "i82_role_plan_has_one_hba_line_per_role_and_database",
        |g: &mut Gen| {
            let p = plan(random_cell(g))?;
            let roles: BTreeSet<(CellDatabase, RoleName)> =
                p.roles.iter().map(|r| (r.database, r.role)).collect();
            let lines: Vec<(CellDatabase, RoleName)> =
                p.hba.iter().map(|h| (h.database, h.role)).collect();
            let set: BTreeSet<(CellDatabase, RoleName)> = lines.iter().copied().collect();
            prop_assert_eq!(lines.len(), set.len(), "a pg_hba line twice: {lines:?}");
            prop_assert_eq!(set, roles);
            Ok(())
        },
    );
}

/// I-82, design section 4.1: every rendered role name has at most 63
/// bytes, PostgreSQL's identifier limit, so no name is cut short into
/// another cell's name.
#[test]
fn i82_role_names_fit_postgresql_identifiers() {
    fstp_prop::check(
        "i82_role_names_fit_postgresql_identifiers",
        |g: &mut Gen| {
            let cell = random_cell(g);
            let p = plan(cell)?;
            for r in &p.roles {
                let name = role_name(r.database, cell, r.role);
                prop_assert!(name.len() <= 63, "{name} has {} bytes", name.len());
            }
            Ok(())
        },
    );
}

/// I-82, M-PLACE `I-82-plan`: the rows of a plan never depend on the cell.
/// Only `RolePlan::cell` names it, so no planned grant can reach another
/// cell's database.
#[test]
fn i82_role_plan_rows_do_not_depend_on_the_cell() {
    fstp_prop::check(
        "i82_role_plan_rows_do_not_depend_on_the_cell",
        |g: &mut Gen| {
            let a = plan(random_cell(g))?;
            let b = plan(random_cell(g))?;
            prop_assert_eq!(&a.roles, &b.roles);
            prop_assert_eq!(&a.grants, &b.grants);
            prop_assert_eq!(&a.hba, &b.hba);
            Ok(())
        },
    );
}

// ---------------------------------------------------------------------------
// Grant rows against the apply_grant grammar.

/// I-82, design section 4.1, ADR-011: each grant row renders to arguments
/// that `fstp_meta.apply_grant` accepts. The privileges are distinct and
/// in the grammar's order, the object fits the object grammar, the suffix
/// fits [`ROLE_SUFFIX_GRAMMAR`], and the grantee is a role of the row's
/// database.
#[test]
fn i82_grant_rows_fit_the_apply_grant_grammar() {
    fstp_prop::check(
        "i82_grant_rows_fit_the_apply_grant_grammar",
        |g: &mut Gen| {
            every_grant(g, |row| {
                prop_assert!(!row.privileges.is_empty(), "{row:?}");
                prop_assert!(
                    row.privileges.windows(2).all(|w| w[0] < w[1]),
                    "privileges not distinct and in grammar order: {row:?}"
                );
                let privs = privs_argument(&row.privileges);
                prop_assert!(privs_fit(&privs), "privs {privs:?} of {row:?}");
                prop_assert!(object_fits(row.object), "object of {row:?}");
                prop_assert!(
                    RoleName::ALL.contains(&row.role)
                        && ROLE_SUFFIX_GRAMMAR.contains(row.role.suffix()),
                    "suffix of {row:?}"
                );
                prop_assert!(
                    adr011_roles(row.database).contains(&row.role),
                    "{:?} is no role of {:?}: {row:?}",
                    row.role,
                    row.database
                );
                Ok(())
            })
        },
    );
}

/// I-82, design section 4.1: one grant row per database, role and object,
/// so `fstp-pgagent` applies each grant once.
#[test]
fn i82_grant_rows_are_unique_per_role_and_object() {
    fstp_prop::check(
        "i82_grant_rows_are_unique_per_role_and_object",
        |g: &mut Gen| {
            let rows = grants(g)?;
            let keys: Vec<(CellDatabase, RoleName, &str)> = rows
                .iter()
                .map(|r| (r.database, r.role, r.object))
                .collect();
            let set: BTreeSet<(CellDatabase, RoleName, &str)> = keys.iter().copied().collect();
            prop_assert_eq!(keys.len(), set.len(), "{keys:?}");
            Ok(())
        },
    );
}

/// I-82, design sections 4.2 and 4.3: every grant names a table in a
/// schema of its own database, so no application grant names a vault
/// table and no vault grant names an application table.
#[test]
fn i82_grant_rows_stay_in_their_database_schemas() {
    fstp_prop::check(
        "i82_grant_rows_stay_in_their_database_schemas",
        |g: &mut Gen| {
            every_grant(g, |row| {
                prop_assert!(
                    schemas_of(row.database).contains(&schema_of(row.object)),
                    "{row:?}"
                );
                Ok(())
            })
        },
    );
}

// ---------------------------------------------------------------------------
// The per-role rules of design section 4.1 and ADR-007.

/// I-82, I-24, ADR-007: no role holds UPDATE or DELETE on an append-only
/// table: `ledger.*`, `audit.chain`, `audit.anchor`, `auth_log.*`,
/// `ops.outbox` and `vault_audit.*`.
#[test]
fn i82_no_grant_row_updates_or_deletes_append_only_tables() {
    fstp_prop::check(
        "i82_no_grant_row_updates_or_deletes_append_only_tables",
        |g: &mut Gen| {
            every_grant(g, |row| {
                if append_only(row.database, row.object) {
                    prop_assert!(
                        !row.privileges.contains(&Privilege::Update)
                            && !row.privileges.contains(&Privilege::Delete),
                        "{row:?}"
                    );
                }
                Ok(())
            })
        },
    );
}

/// I-82, ADR-007: the writer "holds INSERT and SELECT only", on the
/// append-only tables only.
#[test]
fn i82_writer_holds_insert_and_select_only() {
    fstp_prop::check("i82_writer_holds_insert_and_select_only", |g: &mut Gen| {
        every_grant(g, |row| {
            if row.role == RoleName::Writer {
                prop_assert_eq!(row.database, CellDatabase::App, "{row:?}");
                prop_assert!(append_only(row.database, row.object), "{row:?}");
                prop_assert!(
                    row.privileges
                        .iter()
                        .all(|p| matches!(p, Privilege::Select | Privilege::Insert)),
                    "{row:?}"
                );
            }
            Ok(())
        })
    });
}

/// I-82, design section 4.1: the keys role holds rights on the keystore
/// only, plus SELECT and DELETE on `blob` in the application database for
/// rows of completed erasures. It never inserts or updates a blob.
#[test]
fn i82_keys_role_reaches_only_the_keystore_and_blob_deletion() {
    fstp_prop::check(
        "i82_keys_role_reaches_only_the_keystore_and_blob_deletion",
        |g: &mut Gen| {
            every_grant(g, |row| {
                if row.role == RoleName::Keys {
                    match (row.database, schema_of(row.object)) {
                        (_, "keystore") => {}
                        (CellDatabase::App, "blob") => prop_assert!(
                            row.privileges.contains(&Privilege::Delete)
                                && row
                                    .privileges
                                    .iter()
                                    .all(|p| matches!(p, Privilege::Select | Privilege::Delete)),
                            "{row:?}"
                        ),
                        _ => return Err(format!("keys role outside the keystore: {row:?}")),
                    }
                }
                Ok(())
            })
        },
    );
}

/// I-82, design section 4.1: the auditor holds SELECT only, on the audit
/// tables and the stored ledger rows.
#[test]
fn i82_auditor_holds_select_only_on_audit_and_ledger() {
    fstp_prop::check(
        "i82_auditor_holds_select_only_on_audit_and_ledger",
        |g: &mut Gen| {
            every_grant(g, |row| {
                if row.role == RoleName::Auditor {
                    prop_assert_eq!(&row.privileges, &vec![Privilege::Select], "{row:?}");
                    prop_assert!(
                        matches!(schema_of(row.object), "audit" | "ledger"),
                        "{row:?}"
                    );
                }
                Ok(())
            })
        },
    );
}

/// I-82, design section 4.1: the migrator owns every schema, so the plan
/// grants it nothing.
#[test]
fn i82_migrator_holds_no_grant_row() {
    fstp_prop::check("i82_migrator_holds_no_grant_row", |g: &mut Gen| {
        every_grant(g, |row| {
            prop_assert!(row.role != RoleName::Migrator, "{row:?}");
            Ok(())
        })
    });
}

/// I-82, design section 4.1: the application role reads the outbox and
/// never writes it, and holds SELECT only on the ledger, audit and auth
/// log tables.
#[test]
fn i82_app_role_reads_the_append_only_tables() {
    fstp_prop::check(
        "i82_app_role_reads_the_append_only_tables",
        |g: &mut Gen| {
            every_grant(g, |row| {
                if row.role == RoleName::App && append_only(row.database, row.object) {
                    prop_assert_eq!(&row.privileges, &vec![Privilege::Select], "{row:?}");
                }
                Ok(())
            })
        },
    );
}

// ---------------------------------------------------------------------------
// The grammars against the shared SQL text (no plan needed).

/// I-82, design section 4.1, `docs/handoff/m3-base.md` row "APPLY_GRANT_SQL
/// and RoleName": the suffix check of `fstp_meta.apply_grant` is
/// [`ROLE_SUFFIX_GRAMMAR`], the grammar `RoleName` is tied to.
#[test]
fn i82_apply_grant_sql_checks_the_role_suffix_grammar() {
    let check = format!("suffix !~ '{ROLE_SUFFIX_GRAMMAR}'");
    assert!(
        APPLY_GRANT_SQL.contains(&check),
        "APPLY_GRANT_SQL lacks {check:?}"
    );
}

/// I-82, design section 4.1: the cell, privilege and object checks of
/// `fstp_meta.apply_grant` are the grammars these tests render grant rows
/// against, so a row that fits here fits the database function.
#[test]
fn i82_apply_grant_sql_checks_the_grammars_rows_are_rendered_against() {
    let checks = [
        format!("cell !~ '{CELL_GRAMMAR}'"),
        format!("privs !~ '{PRIVS_GRAMMAR}'"),
        format!("object !~ '{OBJECT_GRAMMAR}'"),
    ];
    let missing: Vec<&String> = checks
        .iter()
        .filter(|c| !APPLY_GRANT_SQL.contains(c.as_str()))
        .collect();
    assert!(missing.is_empty(), "APPLY_GRANT_SQL lacks {missing:?}");
    // The hand-written matchers agree with the grammars on their edges.
    assert!(privs_fit("SELECT") && privs_fit("SELECT, INSERT, UPDATE, DELETE"));
    assert!(!privs_fit("") && !privs_fit("SELECT,INSERT") && !privs_fit("select"));
    assert!(!privs_fit("SELECT, ") && !privs_fit("TRUNCATE") && !privs_fit("SELECT,  INSERT"));
    assert!(object_fits("ledger.entry") && object_fits("auth_log.session_end"));
    assert!(!object_fits("ledger") && !object_fits("a.b.c") && !object_fits("Ledger.entry"));
    assert!(!object_fits(&format!("{}.t", "a".repeat(31))) && !object_fits(".t"));
    assert_eq!(cell_hex(CellId([0xab; 16])).len(), 32);
}
