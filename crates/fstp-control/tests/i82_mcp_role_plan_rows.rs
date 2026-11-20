//! I-82, lane L2 (ADR-013 amendment of 2026-11-20, M4 design section 4.3
//! "Roles"): the role plan grants the `mcp` tables of the authorisation
//! server to the `app` role only, in the application database only.

mod common;

use common::random_cell;
use fstp_control::pg::{
    APP_TABLES, CellDatabase, GrantRow, Privilege, VAULT_TABLES, cell_role_plan,
};
use fstp_cp_proto::RoleName;
use fstp_prop::{Gen, prop_assert, prop_assert_eq};

const MCP_TABLES: [&str; 3] = ["mcp.client", "mcp.family", "mcp.refresh"];

fn mcp(object: &str) -> bool {
    object.split_once('.').is_some_and(|(s, _)| s == "mcp")
}

fn grants(g: &mut Gen) -> Result<Vec<GrantRow>, String> {
    cell_role_plan(random_cell(g))
        .map(|p| p.grants)
        .map_err(|e| format!("cell_role_plan: {e}"))
}

/// I-83: the `mcp` tables are application tables only.
#[test]
fn i83_mcp_tables_are_application_tables_only() {
    let app: Vec<&str> = APP_TABLES.iter().copied().filter(|t| mcp(t)).collect();
    assert_eq!(app, MCP_TABLES);
    assert!(VAULT_TABLES.iter().all(|t| !mcp(t)));
}

/// I-82: `app` holds SELECT, INSERT, UPDATE and DELETE on each `mcp`
/// table through one row, and no other role holds any grant on one.
#[test]
fn i82_role_plan_grants_mcp_to_app_only() {
    fstp_prop::check("i82_role_plan_grants_mcp_to_app_only", |g: &mut Gen| {
        let rows = grants(g)?;
        for t in MCP_TABLES {
            let on: Vec<&GrantRow> = rows.iter().filter(|r| r.object == t).collect();
            prop_assert_eq!(on.len(), 1, "I-82: grant rows on {t}: {on:?}");
            let row = on.first().copied().ok_or("no row")?;
            prop_assert_eq!(row.role, RoleName::App, "I-82: {row:?}");
            prop_assert_eq!(row.database, CellDatabase::App, "I-83: {row:?}");
            prop_assert_eq!(
                &row.privileges,
                &vec![
                    Privilege::Select,
                    Privilege::Insert,
                    Privilege::Update,
                    Privilege::Delete
                ],
                "I-82: app privileges on {t}"
            );
        }
        prop_assert!(
            rows.iter()
                .filter(|r| mcp(r.object))
                .all(|r| r.role == RoleName::App),
            "I-82: another role holds an mcp grant"
        );
        Ok(())
    });
}
