//! I-82, I-83, ADR-015 "Storage and roles", ADR-011,
//! `SPEC/12-journey-ui.md` sections 3.2 and 11: the role plan rows of the
//! journey schema.
//!
//! The journey layer adds no database role. Its tables sit in the cell's
//! application database, in a `journey` schema, never in the vault
//! database. The projector runs under the existing `app` role:
//! `cell_role_plan` grants it SELECT on the ledger and INSERT and SELECT
//! on the journey tables, and nothing more. The ledger writer keeps
//! INSERT and SELECT only, and no other role holds a journey grant.
//!
//! Lane j2 test author. Red until the implementer adds the journey
//! tables to the plan: today `APP_TABLES` lists none. The ledger and
//! role-set tests are green and guard that the journey rows change
//! nothing else.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeSet;

use common::random_cell;
use fstp_control::pg::{
    APP_ROLES, APP_TABLES, CellDatabase, GrantRow, Privilege, VAULT_ROLES, VAULT_TABLES,
    cell_role_plan,
};
use fstp_cp_proto::RoleName;
use fstp_prop::{Gen, prop_assert, prop_assert_eq};

/// The tables of the section 11 data model sketch.
const SECTION_11_TABLES: [&str; 3] = [
    "journey.entry",
    "journey.entry_text",
    "journey.projection_cursor",
];

fn journey(object: &str) -> bool {
    object.split_once('.').is_some_and(|(s, _)| s == "journey")
}

fn grants(g: &mut Gen) -> Result<Vec<GrantRow>, String> {
    cell_role_plan(random_cell(g))
        .map(|p| p.grants)
        .map_err(|e| format!("cell_role_plan: {e}"))
}

/// I-83, ADR-015: the application database lists the journey tables of
/// section 11, and the vault database lists no journey table.
#[test]
fn i83_journey_tables_are_application_tables_only() {
    let app: BTreeSet<&str> = APP_TABLES.iter().copied().collect();
    let missing: Vec<&str> = SECTION_11_TABLES
        .into_iter()
        .filter(|t| !app.contains(t))
        .collect();
    assert!(missing.is_empty(), "ADR-015: APP_TABLES lacks {missing:?}");
    let in_vault: Vec<&str> = VAULT_TABLES.into_iter().filter(|t| journey(t)).collect();
    assert!(in_vault.is_empty(), "I-83: vault tables {in_vault:?}");
}

/// I-82, ADR-015: the `app` role holds exactly SELECT and INSERT on every
/// journey table, through one grant row each.
#[test]
fn i82_app_role_holds_select_and_insert_on_every_journey_table() {
    fstp_prop::check(
        "i82_app_role_holds_select_and_insert_on_every_journey_table",
        |g: &mut Gen| {
            let rows = grants(g)?;
            let tables: Vec<&str> = APP_TABLES.iter().copied().filter(|t| journey(t)).collect();
            prop_assert!(
                !tables.is_empty(),
                "ADR-015: no journey table in APP_TABLES"
            );
            for t in tables {
                let app: Vec<&GrantRow> = rows
                    .iter()
                    .filter(|r| r.role == RoleName::App && r.object == t)
                    .collect();
                prop_assert_eq!(app.len(), 1, "I-82: app grant rows on {t}: {app:?}");
                let row = app.first().copied().ok_or("no row")?;
                prop_assert_eq!(row.database, CellDatabase::App, "I-83: {row:?}");
                prop_assert_eq!(
                    &row.privileges,
                    &vec![Privilege::Select, Privilege::Insert],
                    "ADR-015: app privileges on {t}"
                );
            }
            Ok(())
        },
    );
}

/// I-82, I-83, ADR-015: no role but `app` holds a grant on a journey
/// table, and no grant on one runs in the vault database.
#[test]
fn i82_no_other_role_holds_a_journey_grant() {
    fstp_prop::check("i82_no_other_role_holds_a_journey_grant", |g: &mut Gen| {
        for row in grants(g)?.iter().filter(|r| journey(r.object)) {
            prop_assert_eq!(row.database, CellDatabase::App, "I-83: {row:?}");
            prop_assert_eq!(row.role, RoleName::App, "ADR-015: {row:?}");
        }
        Ok(())
    });
}

/// ADR-015, section 3.2: the projector reads the ledger as the `app`
/// role, with SELECT only, and the ledger writer keeps INSERT and SELECT
/// only. The journey rows leave the ledger grants as they were.
#[test]
fn i82_ledger_grants_stay_select_for_app_and_insert_select_for_writer() {
    fstp_prop::check(
        "i82_ledger_grants_stay_select_for_app_and_insert_select_for_writer",
        |g: &mut Gen| {
            let rows = grants(g)?;
            for t in ["ledger.command", "ledger.entry"] {
                for (role, want) in [
                    (RoleName::App, vec![Privilege::Select]),
                    (RoleName::Writer, vec![Privilege::Select, Privilege::Insert]),
                ] {
                    let got: Vec<&Vec<Privilege>> = rows
                        .iter()
                        .filter(|r| r.role == role && r.object == t)
                        .map(|r| &r.privileges)
                        .collect();
                    prop_assert_eq!(got, vec![&want], "ADR-015: {role:?} on {t}");
                }
            }
            Ok(())
        },
    );
}

/// ADR-015, ADR-011: the journey layer adds no database role. Each
/// database keeps the ADR-011 role set.
#[test]
fn i82_journey_layer_adds_no_role() {
    let app: Vec<RoleName> = APP_ROLES.to_vec();
    assert_eq!(
        app,
        vec![
            RoleName::Migrator,
            RoleName::Writer,
            RoleName::App,
            RoleName::Keys,
            RoleName::Auditor,
        ],
        "ADR-015: application roles"
    );
    let vault: Vec<RoleName> = VAULT_ROLES.to_vec();
    assert_eq!(
        vault,
        vec![RoleName::Migrator, RoleName::Vault, RoleName::Keys],
        "ADR-015: vault roles"
    );
}
