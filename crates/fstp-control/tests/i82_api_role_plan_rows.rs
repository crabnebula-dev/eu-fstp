//! ADR-026, M4 design section 4.3: the role plan rows of the `api` and
//! `workspace` schemas (lane L1).
//!
//! The app role keeps the pending actions and the workspaces, with
//! SELECT, INSERT, UPDATE and DELETE, except DELETE on `workspace.drafts`:
//! since F-017 only the keys role deletes a draft row, once its key is
//! gone (migration 15). The ledger writer inserts the one
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

const SIU: [Privilege; 3] = [Privilege::Select, Privilege::Insert, Privilege::Update];

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
        // Lane L25 (ADR-032): the anonymous drafts.
        "workspace.anonymous_drafts",
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
                    // F-017: the app role saves and replaces a draft only.
                    (RoleName::App, "workspace.drafts") => &SIU,
                    (RoleName::App, _) => &FULL,
                    (RoleName::Writer, "api.pending_confirmed") => {
                        &[Privilege::Select, Privilege::Insert]
                    }
                    // F-017: the keys role deletes an erased workspace's rows.
                    (RoleName::Keys, "workspace.drafts") => &[Privilege::Select, Privilege::Delete],
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

/// F-017, I-82, I-81 (ADR-026 section "Written by the M10 fix lane",
/// migration 15): only the keys role may delete a `workspace.drafts` row,
/// with exactly SELECT and DELETE there. The app role saves and replaces
/// drafts with exactly SELECT, INSERT and UPDATE. No other role holds a
/// grant on the table, and the anonymous drafts keep the app role's full
/// rights, since a claim or a sweep deletes them.
#[test]
fn m10_f017_i82_only_the_keys_role_deletes_draft_rows() {
    fstp_prop::check(
        "m10_f017_i82_only_the_keys_role_deletes_draft_rows",
        |g: &mut Gen| {
            let b = g.bytes(16..=16);
            let cell = CellId(b.try_into().unwrap_or([0; 16]));
            let plan = cell_role_plan(cell).map_err(|e| format!("{e:?}"))?;
            let drafts: Vec<_> = plan
                .grants
                .iter()
                .filter(|r| r.object == "workspace.drafts")
                .collect();
            let mut roles = BTreeSet::new();
            for row in &drafts {
                fstp_prop::prop_assert_eq!(row.database, CellDatabase::App, "{row:?}");
                let want: &[Privilege] = match row.role {
                    RoleName::App => &SIU,
                    RoleName::Keys => &[Privilege::Select, Privilege::Delete],
                    _ => return Err(format!("I-82: an unexpected grant {row:?}")),
                };
                fstp_prop::prop_assert_eq!(row.privileges.as_slice(), want, "{row:?}");
                roles.insert(row.role);
            }
            fstp_prop::prop_assert_eq!(
                roles,
                [RoleName::App, RoleName::Keys]
                    .into_iter()
                    .collect::<BTreeSet<_>>(),
                "F-017: the app role saves and the keys role deletes"
            );
            for row in plan
                .grants
                .iter()
                .filter(|r| r.privileges.contains(&Privilege::Delete))
                .filter(|r| r.object == "workspace.drafts")
            {
                fstp_prop::prop_assert_eq!(row.role, RoleName::Keys, "{row:?}");
            }
            for row in plan
                .grants
                .iter()
                .filter(|r| r.object == "workspace.anonymous_drafts")
            {
                fstp_prop::prop_assert_eq!(row.role, RoleName::App, "{row:?}");
                fstp_prop::prop_assert_eq!(row.privileges.as_slice(), &FULL[..], "{row:?}");
            }
            Ok(())
        },
    );
}
