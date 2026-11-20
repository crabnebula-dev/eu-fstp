//! ADR-026, M4 design section 4.3: the role plan rows of the `api` and
//! `workspace` schemas (lane L1).
//!
//! The app role keeps the pending actions and the workspaces, with
//! SELECT, INSERT, UPDATE and DELETE. The ledger writer inserts the one
//! confirmation of a pending action inside its append, so it holds
//! INSERT and SELECT on `api.pending_confirmed`, and nothing else in
//! these schemas. The app role only reads that table. No other role holds
//! a grant there, and the vault database lists none of these tables.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use fstp_control::pg::{APP_TABLES, CellDatabase, Privilege, VAULT_TABLES, cell_role_plan};
use fstp_cp_proto::{CellId, RoleName};
use fstp_prop::Gen;

const FULL: [Privilege; 4] = [
    Privilege::Select,
    Privilege::Insert,
    Privilege::Update,
    Privilege::Delete,
];

fn api_or_workspace(object: &str) -> bool {
    matches!(
        object.split_once('.').map(|(s, _)| s),
        Some("api" | "workspace")
    )
}

/// I-82, TH-58, ADR-026: the `api` and `workspace` grants of every cell
/// are exactly the app role's rights and the writer's insert of a
/// confirmation. The vault database holds none of these tables (I-83).
#[test]
fn i82_role_plan_grants_api_and_workspace_to_app_only() {
    let tables: BTreeSet<&str> = APP_TABLES
        .iter()
        .copied()
        .filter(|t| api_or_workspace(t))
        .collect();
    let want: BTreeSet<&str> = [
        "api.pending_actions",
        "api.pending_confirmed",
        "workspace.drafts",
    ]
    .into_iter()
    .collect();
    assert_eq!(tables, want, "ADR-026: the api and workspace tables");
    assert!(
        !VAULT_TABLES.iter().any(|t| api_or_workspace(t)),
        "I-83: the vault database lists an api or workspace table"
    );
    fstp_prop::check(
        "i82_role_plan_grants_api_and_workspace_to_app_only",
        |g: &mut Gen| {
            let b = g.bytes(16..=16);
            let cell = CellId(b.try_into().unwrap_or([0; 16]));
            let plan = cell_role_plan(cell).map_err(|e| format!("{e:?}"))?;
            let mut seen: BTreeSet<(&str, RoleName)> = BTreeSet::new();
            for row in plan.grants.iter().filter(|r| api_or_workspace(r.object)) {
                fstp_prop::prop_assert_eq!(row.database, CellDatabase::App, "{row:?}");
                let want: &[Privilege] = match (row.role, row.object) {
                    (RoleName::App, "api.pending_confirmed") => &[Privilege::Select],
                    (RoleName::App, _) => &FULL,
                    (RoleName::Writer, "api.pending_confirmed") => {
                        &[Privilege::Select, Privilege::Insert]
                    }
                    _ => return Err(format!("I-82: an unexpected grant {row:?}")),
                };
                fstp_prop::prop_assert_eq!(row.privileges.as_slice(), want, "{row:?}");
                seen.insert((row.object, row.role));
            }
            for t in &want {
                fstp_prop::prop_assert!(
                    seen.contains(&(*t, RoleName::App)),
                    "ADR-026: the app role has no grant on {t}"
                );
            }
            fstp_prop::prop_assert!(
                seen.contains(&("api.pending_confirmed", RoleName::Writer)),
                "ADR-026: the writer cannot record a confirmation"
            );
            Ok(())
        },
    );
}

/// I-82, ADR-007, M4 design section 9: the app role, which now writes the
/// API core's tables, still holds SELECT only on the ledger, the audit
/// chain and the auth log of every cell. Only the writer appends there.
#[test]
fn t_db_app_role_has_no_ledger_update() {
    fstp_prop::check("t_db_app_role_has_no_ledger_update", |g: &mut Gen| {
        let b = g.bytes(16..=16);
        let cell = CellId(b.try_into().unwrap_or([0; 16]));
        let plan = cell_role_plan(cell).map_err(|e| format!("{e:?}"))?;
        for row in plan.grants.iter().filter(|r| r.role == RoleName::App) {
            let schema = row.object.split_once('.').map_or(row.object, |(s, _)| s);
            if matches!(schema, "ledger" | "audit" | "auth_log")
                || row.object == "api.pending_confirmed"
            {
                fstp_prop::prop_assert_eq!(
                    row.privileges.as_slice(),
                    &[Privilege::Select][..],
                    "{row:?}"
                );
            }
        }
        Ok(())
    });
}
