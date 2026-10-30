//! I-82: no database role can read across databases of different cells
//! (design section 14.4, T-DB-ISO, B7, ADR-005, ADR-011).
//!
//! The pure tests drive `fstp_control::pg::cell_role_plan`,
//! `fstp_control::pgagent::render_ddl_identifier` and
//! `fstp_control::isolation_audit::privilege_graph` against the reference
//! of `fstp_celltest::mc::place_model`. The world tests read the catalogue
//! of every self-operated cluster after provisioning. Under Daniel's I-82
//! reading (design section 21.0) the managed control-plane cluster holds no
//! cell data, so only application, vault and witness clusters count.
//!
//! Lane W1f wrote these tests before the production code. They are red
//! until the control plane (lane W2h) and the cell runtime (lane W3a) land.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::{BTreeMap, BTreeSet};

use fstp_celltest::mc::place_model::db::{self, HbaRow};
use fstp_celltest::mc::place_model::{
    APP_TABLES, VAULT_TABLES, VaultPin, app_grants, cell_hex, database_name, is_ddl_identifier,
    plan_view, role_name, roles_of, schema_of, vault_pin,
};
use fstp_celltest::world::{
    ClusterHandle, ClusterKind, CycleScript, DbMode, VaultLayout, World, WorldSpec,
};
use fstp_control::ControlError;
use fstp_control::isolation_audit::{
    CatalogueRows, PrivilegeEdge, PrivilegeGraph, RoleAttrs, privilege_graph,
};
use fstp_control::pg::{CellDatabase, Privilege, RolePlan, cell_role_plan};
use fstp_control::pgagent::render_ddl_identifier;
use fstp_cp_proto::{CellId, RoleName};
use fstp_pgtest::PgServer;
use fstp_prop::{Gen, prop_assert, prop_assert_eq};

// ---------------------------------------------------------------------------
// Helpers.

fn plan(cell: CellId) -> Result<RolePlan, String> {
    cell_role_plan(cell).map_err(|e| format!("cell_role_plan: {e}"))
}

/// The placement marker of both cell databases (design section 4.1,
/// `0000_meta.sql`).
const PLACEMENT: &str = "fstp_meta.placement";

/// The one grant on [`PLACEMENT`] in `db`: SELECT for the role whose
/// process reads the marker at start (design section 9.2, "At start":
/// `fstp-vault` refuses a database whose `fstp_meta.placement.kind` is not
/// vault, and `fstp-cell` makes the mirror checks). That is the `app` role
/// of the application database and the `vault` role of the vault
/// database. No other role reads it, and the migrator owns it.
fn placement_grant(db: CellDatabase) -> (RoleName, &'static str, Vec<Privilege>) {
    let role = match db {
        CellDatabase::App => RoleName::App,
        CellDatabase::Vault => RoleName::Vault,
    };
    (role, PLACEMENT, vec![Privilege::Select])
}

fn graph(rows: &CatalogueRows) -> PrivilegeGraph {
    privilege_graph(rows).unwrap_or_else(|e| panic!("privilege_graph: {e}"))
}

/// The graph of the reference edges of `rows` alone. Teeth for the path
/// rule of `db::cross_cell_paths` use it, so they prove the rule before
/// production's `privilege_graph` exists.
fn reference_graph(rows: &CatalogueRows) -> PrivilegeGraph {
    PrivilegeGraph {
        edges: db::reference_edges(rows)
            .into_iter()
            .map(|(from, to)| PrivilegeEdge {
                from,
                to,
                via: "reference".to_owned(),
            })
            .collect(),
    }
}

fn random_cell(g: &mut Gen) -> CellId {
    let b = g.bytes(16..=16);
    CellId(b.try_into().unwrap_or([0; 16]))
}

fn world(cells: u8, mode: DbMode) -> World {
    World::start(WorldSpec {
        cells,
        mode,
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted: false,
        process_mode: false,
    })
    .unwrap_or_else(|e| panic!("the world did not start: {e}"))
}

/// The clusters `fstp-pgagent` manages: every self-operated kind (Q3 C).
fn agent_clusters(w: &World) -> Vec<&ClusterHandle> {
    w.clusters()
        .iter()
        .filter(|c| c.kind() != ClusterKind::Control)
        .collect()
}

const LOOPBACK: &str = "127.0.0.1";

fn is_loopback(h: &HbaRow) -> bool {
    h.rule.address == LOOPBACK && (h.netmask.is_empty() || h.netmask == "255.255.255.255")
}

fn accepting(h: &HbaRow) -> bool {
    h.rule.method != "reject"
}

// ---------------------------------------------------------------------------
// The role plan against the reference (design section 4.1).

/// I-82, design section 4.1: the plan of a cell names that cell, holds the
/// roles of the reference for each database, one `pg_hba` line per role
/// and database, and the reference grants of the application database.
/// Each database adds exactly one grant on the placement marker, to the
/// role its start check reads it as ([`placement_grant`], design sections
/// 4.1 and 9.2). In the vault database every other grant names a table
/// of design section 4.3,
/// the `keys` role reaches only the keystore, and no role holds UPDATE or
/// DELETE on `vault_audit`. Each vault grant matches the reference pin of
/// `place_model::vault_pin`: exact where design section 4.1 pins it, and a
/// floor of SELECT and INSERT for the `vault` role elsewhere.
#[test]
fn i82_role_plan_matches_design_section_4_1() {
    fstp_prop::check("i82_role_plan_matches_design_section_4_1", |g: &mut Gen| {
        let cell = random_cell(g);
        let p = plan(cell)?;
        prop_assert_eq!(p.cell, cell);
        for db in [CellDatabase::App, CellDatabase::Vault] {
            let got: BTreeSet<RoleName> = p
                .roles
                .iter()
                .filter(|r| r.database == db)
                .map(|r| r.role)
                .collect();
            let want: BTreeSet<RoleName> = roles_of(db).iter().copied().collect();
            prop_assert_eq!(&got, &want, "roles of {db:?}");
            let hba: Vec<RoleName> = p
                .hba
                .iter()
                .filter(|h| h.database == db)
                .map(|h| h.role)
                .collect();
            let hba_set: BTreeSet<RoleName> = hba.iter().copied().collect();
            prop_assert_eq!(
                hba.len(),
                hba_set.len(),
                "one pg_hba line per role in {db:?}"
            );
            prop_assert_eq!(&hba_set, &want, "pg_hba roles of {db:?}");
        }
        let app: BTreeSet<(RoleName, &str, Vec<Privilege>)> = p
            .grants
            .iter()
            .filter(|g| g.database == CellDatabase::App)
            .map(|g| (g.role, g.object, g.privileges.clone()))
            .collect();
        let mut want: BTreeSet<(RoleName, &str, Vec<Privilege>)> =
            app_grants().into_iter().collect();
        want.insert(placement_grant(CellDatabase::App));
        prop_assert_eq!(app, want, "application grants");
        let placement: Vec<(CellDatabase, RoleName, Vec<Privilege>)> = p
            .grants
            .iter()
            .filter(|g| g.object == PLACEMENT)
            .map(|g| (g.database, g.role, g.privileges.clone()))
            .collect();
        let want_placement: Vec<(CellDatabase, RoleName, Vec<Privilege>)> =
            [CellDatabase::App, CellDatabase::Vault]
                .into_iter()
                .map(|db| {
                    let (role, _, privs) = placement_grant(db);
                    (db, role, privs)
                })
                .collect();
        prop_assert_eq!(placement, want_placement, "placement grants");
        let mut vault: BTreeMap<(RoleName, &str), BTreeSet<Privilege>> = BTreeMap::new();
        // The vault placement row is pinned exactly above.
        for gr in p
            .grants
            .iter()
            .filter(|g| g.database == CellDatabase::Vault && g.object != PLACEMENT)
        {
            prop_assert!(
                roles_of(CellDatabase::Vault).contains(&gr.role),
                "vault grant to {:?}",
                gr.role
            );
            prop_assert!(VAULT_TABLES.contains(&gr.object), "{gr:?}");
            if gr.role == RoleName::Keys {
                prop_assert_eq!(schema_of(gr.object), "keystore", "{gr:?}");
            }
            if schema_of(gr.object) == "vault_audit" {
                prop_assert!(
                    !gr.privileges.contains(&Privilege::Update)
                        && !gr.privileges.contains(&Privilege::Delete),
                    "{gr:?}"
                );
            }
            vault
                .entry((gr.role, gr.object))
                .or_default()
                .extend(gr.privileges.iter().copied());
        }
        // The reference pins of the vault database (design section 4.1,
        // "same pattern"): exact where it pins them, a floor elsewhere.
        for role in roles_of(CellDatabase::Vault) {
            for object in VAULT_TABLES {
                let got = vault.get(&(*role, object)).cloned().unwrap_or_default();
                match vault_pin(*role, object) {
                    VaultPin::Exactly(want) => {
                        let want: BTreeSet<Privilege> = want.iter().copied().collect();
                        prop_assert_eq!(&got, &want, "vault grant of {role:?} on {object}");
                    }
                    VaultPin::AtLeast(floor) => {
                        for p in floor {
                            prop_assert!(
                                got.contains(p),
                                "vault grant of {role:?} on {object} lacks {p:?}: {got:?}"
                            );
                        }
                    }
                }
            }
        }
        Ok(())
    });
}

/// I-82, design section 4.1: every name a plan renders is the cell's
/// database or one of its role names, so it carries only the random cell
/// id and fixed words. Production's DDL identifier renderer quotes exactly
/// the grammar `^[cv]_[0-9a-f]{32}$`.
#[test]
fn i82_names_reveal_nothing() {
    fstp_prop::check("i82_names_reveal_nothing", |g: &mut Gen| {
        let cell = random_cell(g);
        let view = plan_view(&plan(cell)?);
        let mut allowed = BTreeSet::new();
        for db in [CellDatabase::App, CellDatabase::Vault] {
            allowed.insert(database_name(db, cell));
            for role in RoleName::ALL {
                allowed.insert(role_name(db, cell, role));
            }
        }
        for n in &view.names {
            prop_assert!(allowed.contains(n), "the plan renders {n}");
        }
        for db in [CellDatabase::App, CellDatabase::Vault] {
            let name = database_name(db, cell);
            #[allow(unreachable_patterns, reason = "lane W2h may add refusal variants")]
            match render_ddl_identifier(&name) {
                Err(ControlError::NotImplemented(op)) => {
                    return Err(format!("{op} is NotImplemented"));
                }
                Ok(out) => prop_assert_eq!(out, format!("\"{name}\"")),
                Err(e) => return Err(format!("{name} was refused: {e}")),
            }
        }
        Ok(())
    });
}

/// I-82, ADR-011: `render_ddl_identifier` accepts exactly the names of the
/// closed grammar, and the rendered text holds nothing else.
#[test]
fn i82_ddl_identifier_grammar_matches_reference() {
    fstp_prop::check(
        "i82_ddl_identifier_grammar_matches_reference",
        |g: &mut Gen| {
            let name = match g.u8_in(0..=3) {
                0 => format!("{}_{}", g.pick(&["c", "v"]), cell_hex(random_cell(g))),
                1 => {
                    let mut s = format!("{}_{}", g.pick(&["c", "v"]), cell_hex(random_cell(g)));
                    let i = g.usize_in(0..=s.len());
                    s.insert(
                        i.min(s.len()),
                        *g.pick(&['"', ';', 'A', ' ', 'g', '_', '\0']),
                    );
                    s
                }
                2 => g.ascii_string(0..=40),
                _ => g.string(0..=40),
            };
            let want = is_ddl_identifier(&name);
            #[allow(unreachable_patterns, reason = "lane W2h may add refusal variants")]
            match render_ddl_identifier(&name) {
                Err(ControlError::NotImplemented(op)) => Err(format!("{op} is NotImplemented")),
                Ok(out) => {
                    prop_assert!(want, "rendered {name:?} as {out:?}");
                    prop_assert_eq!(out, format!("\"{name}\""));
                    Ok(())
                }
                Err(e) => {
                    prop_assert!(!want, "refused {name:?}: {e}");
                    Ok(())
                }
            }
        },
    );
}

/// I-82, ADR-011: names outside the grammar are refused, so a tenant name
/// never reaches DDL.
///
/// Gap, reported by lane W1f: `ControlError` has no refusal variant yet,
/// only `NotImplemented`, so a refusal is not distinguishable from the
/// stub. The test is red until a refusal variant exists (lane W2h).
#[test]
fn i82_ddl_identifier_refuses_names_outside_the_grammar() {
    let names = [
        "c_acme",
        "c_ACME0000000000000000000000000000",
        "v_0123456789abcdef0123456789abcde",
        "c_0123456789abcdef0123456789abcdef; DROP DATABASE x",
        "x_0123456789abcdef0123456789abcdef",
        "",
    ];
    let mut refused = 0usize;
    for name in names {
        #[allow(
            unreachable_patterns,
            reason = "a refusal variant arrives with lane W2h"
        )]
        match render_ddl_identifier(name) {
            Ok(out) => panic!("{name:?} rendered as {out:?}"),
            Err(ControlError::NotImplemented(op)) => {
                panic!("{op} is NotImplemented, and no refusal variant exists yet for {name:?}")
            }
            Err(_) => refused += 1,
        }
    }
    assert_eq!(refused, names.len());
}

// ---------------------------------------------------------------------------
// The isolation auditor (design section 9.3).

/// A private server, so seeded grants never reach a shared cluster.
fn private_server() -> &'static PgServer {
    Box::leak(Box::new(PgServer::start().unwrap()))
}

/// Two synthetic cells on `s`, as the plan lays them out: per cell one
/// database, CONNECT revoked from PUBLIC and granted to its app role.
fn synthetic_cells(s: &PgServer) -> (String, String) {
    let mut a = [0u8; 16];
    let mut b = [0u8; 16];
    fstp_crypto::random_bytes(&mut a).unwrap();
    fstp_crypto::random_bytes(&mut b).unwrap();
    let (a, b) = (CellId(a), CellId(b));
    for c in [a, b] {
        let dbn = database_name(CellDatabase::App, c);
        let role = role_name(CellDatabase::App, c, RoleName::App);
        s.psql(
            "postgres",
            &format!(
                "CREATE ROLE {role} LOGIN;\nCREATE DATABASE {dbn};\n\
                 REVOKE ALL ON DATABASE {dbn} FROM PUBLIC;\n\
                 GRANT CONNECT ON DATABASE {dbn} TO {role};"
            ),
        )
        .unwrap();
    }
    (cell_hex(a), cell_hex(b))
}

/// I-82 teeth, design section 9.3: a CONNECT grant on cell B's database to
/// cell A's role is a cross-cell path in the privilege graph. Before the
/// seeded grant the graph holds each own grant and no cross-cell path.
#[test]
fn i82_teeth_seeded_connect_grant_is_caught() {
    let s = private_server();
    let (a, b) = synthetic_cells(s);
    let before = db::catalogue_rows(s).unwrap();
    let g = graph(&before);
    let edges: BTreeSet<(String, String)> = g
        .edges
        .iter()
        .map(|e| (e.from.clone(), e.to.clone()))
        .collect();
    for want in db::reference_edges(&before) {
        assert!(edges.contains(&want), "the graph lacks {want:?}");
    }
    assert!(
        db::cross_cell_paths(&g).is_empty(),
        "a cross-cell path before the seeded grant: {:?}",
        db::cross_cell_paths(&g)
    );
    s.psql(
        "postgres",
        &format!("GRANT CONNECT ON DATABASE c_{b} TO c_{a}_app"),
    )
    .unwrap();
    let paths = db::cross_cell_paths(&graph(&db::catalogue_rows(s).unwrap()));
    assert!(
        paths
            .iter()
            .any(|p| p == &format!("c_{a}_app reaches c_{b}")),
        "the seeded grant was not caught: {paths:?}"
    );
}

/// I-82 teeth: a default ACL that leaves PUBLIC's CONNECT on a cell
/// database is a cross-cell path too.
#[test]
fn i82_teeth_public_connect_is_caught() {
    let s = private_server();
    let (_a, b) = synthetic_cells(s);
    s.psql(
        "postgres",
        &format!("GRANT CONNECT ON DATABASE c_{b} TO PUBLIC"),
    )
    .unwrap();
    let paths = db::cross_cell_paths(&graph(&db::catalogue_rows(s).unwrap()));
    assert!(
        paths.iter().any(|p| p.ends_with(&format!("reaches c_{b}"))),
        "PUBLIC's CONNECT was not caught: {paths:?}"
    );
}

/// Seeds on `s` a cell role of cell `a` that reaches `pg_read_all_data`
/// through an intermediate role.
fn seed_indirect_reader(s: &PgServer, a: &str) {
    s.psql(
        "postgres",
        &format!(
            "CREATE ROLE w1f_teeth_reader NOLOGIN;\n\
             GRANT pg_read_all_data TO w1f_teeth_reader;\n\
             GRANT w1f_teeth_reader TO c_{a}_app;"
        ),
    )
    .unwrap();
}

/// I-82 teeth: a cell role that reaches `pg_read_all_data` through an
/// intermediate role reaches every database, and the path rule reports it
/// over the reference edges. Before the seed it reports no path.
#[test]
fn i82_teeth_indirect_predefined_membership_is_a_path() {
    let s = private_server();
    let (a, _b) = synthetic_cells(s);
    let clean = db::cross_cell_paths(&reference_graph(&db::catalogue_rows(s).unwrap()));
    assert!(clean.is_empty(), "a path before the seed: {clean:?}");
    seed_indirect_reader(s, &a);
    let paths = db::cross_cell_paths(&reference_graph(&db::catalogue_rows(s).unwrap()));
    assert!(
        paths
            .iter()
            .any(|p| p.starts_with(&format!("c_{a}_app reaches pg_read_all_data"))),
        "the indirect membership was not caught: {paths:?}"
    );
}

/// I-82 teeth, production twin: the same seed is a path in production's
/// privilege graph. Red until `privilege_graph` lands (lane W2h).
#[test]
fn i82_teeth_indirect_predefined_membership_is_a_path_in_the_production_graph() {
    let s = private_server();
    let (a, _b) = synthetic_cells(s);
    seed_indirect_reader(s, &a);
    let paths = db::cross_cell_paths(&graph(&db::catalogue_rows(s).unwrap()));
    assert!(
        paths
            .iter()
            .any(|p| p.starts_with(&format!("c_{a}_app reaches pg_read_all_data"))),
        "the indirect membership was not caught: {paths:?}"
    );
}

/// I-82 teeth, design section 4.1: a cell role that is a member of a
/// NOLOGIN SUPERUSER role can `SET ROLE` to it and read every database's
/// files. The path rule reports it over the reference edges, and the
/// attribute check reports it too. A clean cell role gives neither.
#[test]
fn i82_teeth_set_role_to_a_superuser_role_is_caught() {
    let c = ClusterHandle::start_named(ClusterKind::Application, "w1f_teeth_setrole").unwrap();
    let s = c.server();
    let mut raw = [0u8; 16];
    fstp_crypto::random_bytes(&mut raw).unwrap();
    let hex = cell_hex(CellId(raw));
    let app = format!("c_{hex}_app");
    s.create_login_role(&app).unwrap();
    s.create_database_for(&format!("c_{hex}"), &[&app]).unwrap();
    let rows = || db::catalogue_rows(s).unwrap();
    let mine = |paths: Vec<String>| -> Vec<String> {
        paths.into_iter().filter(|p| p.starts_with(&app)).collect()
    };
    let clean = mine(db::cross_cell_paths(&reference_graph(&rows())));
    assert!(clean.is_empty(), "a path before the seed: {clean:?}");
    let clean = attribute_breaches(&rows(), &db::hba_rows(s).unwrap());
    assert!(clean.is_empty(), "{clean:#?}");
    s.psql(
        "postgres",
        &format!("CREATE ROLE w1f_teeth_su SUPERUSER NOLOGIN;\nGRANT w1f_teeth_su TO {app};"),
    )
    .unwrap();
    let paths = mine(db::cross_cell_paths(&reference_graph(&rows())));
    assert!(
        paths.iter().any(|p| *p
            == format!(
                "{app} reaches {}, which crosses every database",
                db::SUPERUSER_NODE
            )),
        "the superuser membership is no path: {paths:?}"
    );
    let found = attribute_breaches(&rows(), &db::hba_rows(s).unwrap());
    assert!(
        found
            .iter()
            .any(|b| b.starts_with(&format!("{app} can SET ROLE to")) && b.contains("w1f_teeth_su")),
        "{found:#?}"
    );
}

/// I-82, design section 9.3: after provisioning three cells, the privilege
/// graph of every self-operated cluster holds each catalogue grant and
/// membership and no path from one cell's role to another cell's database
/// or role. No extension other than `plpgsql` exists.
#[test]
fn i82_privilege_graph_has_no_cross_cell_path() {
    let w = world(3, DbMode::Shared);
    for c in agent_clusters(&w) {
        let rows = db::catalogue_rows(c.server()).unwrap();
        let g = graph(&rows);
        let edges: BTreeSet<(String, String)> = g
            .edges
            .iter()
            .map(|e| (e.from.clone(), e.to.clone()))
            .collect();
        for want in db::reference_edges(&rows) {
            assert!(
                edges.contains(&want),
                "{}: the graph lacks {want:?}",
                c.name()
            );
        }
        let paths = db::cross_cell_paths(&g);
        assert!(paths.is_empty(), "{}: {paths:?}", c.name());
        let extra: Vec<&String> = rows.extensions.iter().filter(|e| *e != "plpgsql").collect();
        assert!(extra.is_empty(), "{}: extensions {extra:?}", c.name());
    }
}

// ---------------------------------------------------------------------------
// pg_hba and role attributes after provisioning (design section 4.1).

/// The `pg_hba` database keywords of PostgreSQL 16.
const HBA_DATABASE_KEYWORDS: [&str; 5] =
    ["all", "sameuser", "samerole", "samegroup", "replication"];

/// Why accepting line `h` breaks the one `<db> <role>` form of design
/// section 4.1, or `None`. Its user is one role by name: not `all`, not a
/// `+group` and not an `@file`. Its database is one database by name: not
/// an `@file`, and not a keyword, except `all` for `fstp_super` (G4) and
/// `replication` for `fstp_repl` (G22).
fn hba_form_breach(h: &HbaRow) -> Option<&'static str> {
    let (user, database) = (h.rule.user.as_str(), h.rule.database.as_str());
    if user == "all" {
        return Some("the user is all");
    }
    if user.starts_with('+') || user.starts_with('@') {
        return Some("the user is a group or a file");
    }
    if database.starts_with('@') {
        return Some("the database is a file");
    }
    let allowed = matches!(
        (database, user),
        ("all", "fstp_super") | ("replication", "fstp_repl")
    );
    if HBA_DATABASE_KEYWORDS.contains(&database) && !allowed {
        return Some("the database is a keyword");
    }
    None
}

/// I-82 teeth: the line form check refuses `all`, group, file and keyword
/// forms, and passes the superuser, replication and cell role lines.
#[test]
fn i82_teeth_hba_line_form_refuses_group_file_and_keyword_lines() {
    let line = |database: &str, user: &str| HbaRow {
        rule: fstp_control::isolation_audit::HbaRule {
            line: 1,
            kind: "hostssl".to_owned(),
            database: database.to_owned(),
            user: user.to_owned(),
            address: LOOPBACK.to_owned(),
            method: "scram-sha-256".to_owned(),
        },
        netmask: String::new(),
        options: "clientcert=verify-full".to_owned(),
    };
    let cell = format!("c_{}", "a".repeat(32));
    let role = format!("{cell}_app");
    for (database, user) in [
        ("all", "fstp_super"),
        ("replication", "fstp_repl"),
        (cell.as_str(), role.as_str()),
    ] {
        assert_eq!(
            hba_form_breach(&line(database, user)),
            None,
            "{database} {user}"
        );
    }
    for (database, user) in [
        (cell.as_str(), "all"),
        (cell.as_str(), "+cell_roles"),
        (cell.as_str(), "@roles"),
        ("@databases", role.as_str()),
        ("all", role.as_str()),
        ("sameuser", role.as_str()),
        ("samerole", role.as_str()),
        ("samegroup", role.as_str()),
        ("replication", role.as_str()),
        ("all", "fstp_repl"),
        ("replication", "fstp_super"),
    ] {
        assert!(
            hba_form_breach(&line(database, user)).is_some(),
            "{database} {user} passed"
        );
    }
}

/// I-82, G4, Q4: on every self-operated cluster the superuser has one
/// loopback line, and the last line rejects. Every accepting line has the
/// one `<db> <role>` form ([`hba_form_breach`]), so no line names `all`,
/// a group, a file or another keyword, except the machinery lines. Each
/// accepting line is `hostssl` with `scram-sha-256` and
/// `clientcert=verify-full`. Each cell role's line names its own cell's
/// database.
#[test]
fn i82_generated_hba_has_no_remote_superuser_and_no_all_line() {
    let w = world(3, DbMode::Shared);
    for c in agent_clusters(&w) {
        let rows = db::hba_rows(c.server()).unwrap();
        let name = c.name();
        let last = rows
            .last()
            .unwrap_or_else(|| panic!("{name}: empty pg_hba"));
        assert_eq!(last.rule.method, "reject", "{name}: last line {last:?}");
        let su: Vec<&HbaRow> = rows
            .iter()
            .filter(|h| h.rule.user == "fstp_super")
            .collect();
        assert_eq!(su.len(), 1, "{name}: superuser lines {su:?}");
        assert!(is_loopback(su[0]), "{name}: {:?}", su[0]);
        for h in rows.iter().filter(|h| accepting(h)) {
            assert_eq!(hba_form_breach(h), None, "{name}: {h:?}");
            assert_eq!(h.rule.kind, "hostssl", "{name}: {h:?}");
            assert_eq!(h.rule.method, "scram-sha-256", "{name}: {h:?}");
            assert!(
                h.options.split(',').any(|o| o == "clientcert=verify-full"),
                "{name}: {h:?}"
            );
            if let Some(cell) = db::cell_of(&h.rule.user) {
                assert_eq!(db::cell_of(&h.rule.database), Some(cell), "{name}: {h:?}");
            }
        }
    }
}

/// I-82, G22, Q4: `fstp_repl` is the only role with REPLICATION besides
/// the superuser. Its lines are loopback `replication` lines only, it
/// holds no CONNECT on any cell database and is no member of any role.
#[test]
fn i82_replication_role_has_loopback_line_only_and_no_connect() {
    let w = world(1, DbMode::Shared);
    for c in agent_clusters(&w) {
        let name = c.name();
        let rows = db::catalogue_rows(c.server()).unwrap();
        let repl: Vec<&str> = rows
            .roles
            .iter()
            .filter(|r| r.replication && !r.superuser)
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(repl, vec!["fstp_repl"], "{name}: replication roles");
        let lines: Vec<HbaRow> = db::hba_rows(c.server())
            .unwrap()
            .into_iter()
            .filter(|h| h.rule.user == "fstp_repl" && accepting(h))
            .collect();
        assert!(!lines.is_empty(), "{name}: fstp_repl has no line");
        for h in &lines {
            assert_eq!(h.rule.database, "replication", "{name}: {h:?}");
            assert!(is_loopback(h), "{name}: {h:?}");
        }
        for g in rows
            .database_grants
            .iter()
            .filter(|g| g.grantee == "fstp_repl")
        {
            assert!(db::cell_of(&g.database).is_none(), "{name}: {g:?}");
        }
        assert!(
            rows.memberships.iter().all(|m| m.member != "fstp_repl"),
            "{name}: fstp_repl is a member of a role"
        );
    }
}

/// The predefined roles no cell role may be a member of (design section
/// 4.1).
const PREDEFINED: [&str; 8] = db::CROSS_DATABASE_ROLES;

/// The cluster machinery roles, whose `pg_hba` lines are loopback only
/// (G4, G22, Q4). Their own tests are
/// `i82_generated_hba_has_no_remote_superuser_and_no_all_line` and
/// `i82_replication_role_has_loopback_line_only_and_no_connect`.
const MACHINERY: [&str; 2] = ["fstp_super", "fstp_repl"];

/// The roles `member` belongs to, directly or through other roles, given
/// `(member, role)` membership edges.
fn memberships_of(member: &str, edges: &[(String, String)]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut todo = vec![member.to_owned()];
    while let Some(m) = todo.pop() {
        for (from, to) in edges {
            if *from == m && out.insert(to.clone()) {
                todo.push(to.clone());
            }
        }
    }
    out
}

/// The roles that may log in from another host: every cell role, by name,
/// and every other role with an accepting `pg_hba` line, whatever its
/// address, except the cluster machinery.
///
/// Every `fstp-pgtest` line is loopback, so an address test would exempt
/// every role of a single-host world. Under Daniel's I-82 reading (design
/// section 21.0) the cell roles are the roles that log in from another
/// host, so the name decides.
fn remote_capable(rows: &CatalogueRows, hba: &[HbaRow]) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = rows
        .roles
        .iter()
        .filter(|r| db::cell_of(&r.name).is_some())
        .map(|r| r.name.clone())
        .collect();
    out.extend(
        hba.iter()
            .filter(|h| accepting(h) && !MACHINERY.contains(&h.rule.user.as_str()))
            .map(|h| h.rule.user.clone()),
    );
    out
}

/// Whether `r` holds an attribute that design section 4.1 denies every
/// cell role.
fn elevated(r: &RoleAttrs) -> bool {
    r.superuser || r.createrole || r.createdb || r.replication || r.bypassrls
}

/// The I-82 attribute breaches of one cluster's catalogue, one line each:
/// a remote-capable role with SUPERUSER, CREATEROLE, CREATEDB, REPLICATION
/// or BYPASSRLS, or a cell role that is a member of a [`PREDEFINED`] role
/// or of a role with one of those attributes, directly or through other
/// roles. PostgreSQL 16 gives a grant the SET option by default, so a
/// member can `SET ROLE` to the role and use its attributes.
fn attribute_breaches(rows: &CatalogueRows, hba: &[HbaRow]) -> Vec<String> {
    let mut out = Vec::new();
    let remote = remote_capable(rows, hba);
    for r in rows.roles.iter().filter(|r| remote.contains(&r.name)) {
        if elevated(r) {
            out.push(format!("remote role {r:?}"));
        }
    }
    let edges: Vec<(String, String)> = rows
        .memberships
        .iter()
        .map(|m| (m.member.clone(), m.role.clone()))
        .collect();
    let attrs: BTreeMap<&str, &RoleAttrs> =
        rows.roles.iter().map(|r| (r.name.as_str(), r)).collect();
    for r in rows.roles.iter().filter(|r| db::cell_of(&r.name).is_some()) {
        for p in memberships_of(&r.name, &edges) {
            if PREDEFINED.contains(&p.as_str()) {
                out.push(format!("{} is a member of {p}", r.name));
            }
            if let Some(a) = attrs.get(p.as_str()).filter(|a| elevated(a)) {
                out.push(format!("{} can SET ROLE to {a:?}", r.name));
            }
        }
    }
    out
}

/// I-82, design section 4.1: no cell role, and no other role with an
/// accepting `pg_hba` line besides the cluster machinery, holds SUPERUSER,
/// CREATEROLE, CREATEDB, REPLICATION or BYPASSRLS, whatever its address.
/// No cell role is a member, directly or through other roles, of a
/// predefined role that reads or writes across databases or reaches the
/// server's files.
///
/// Each cluster is checked against the login roles it holds by design
/// section 4.1: an application or vault cluster holds the roles of its
/// database for every cell of the world, and the witness cluster holds
/// `witness_service` and `witness_migrator`. Every one of them must exist
/// and be among the roles the attribute check covers. The check still
/// covers every other remote-capable role it finds, such as the cell
/// roles of other worlds on a shared cluster.
#[test]
fn i82_no_remote_role_has_createrole_or_createdb() {
    let w = world(3, DbMode::Shared);
    for c in agent_clusters(&w) {
        let rows = db::catalogue_rows(c.server()).unwrap();
        let hba = db::hba_rows(c.server()).unwrap();
        let held = cluster_login_roles(&w, c.kind());
        assert!(!held.is_empty(), "{}: no role to check", c.name());
        let names: BTreeSet<&str> = rows.roles.iter().map(|r| r.name.as_str()).collect();
        let remote = remote_capable(&rows, &hba);
        for role in &held {
            assert!(
                names.contains(role.as_str()),
                "{}: holds no role {role}",
                c.name()
            );
            assert!(
                remote.contains(role),
                "{}: the attribute check skips {role}",
                c.name()
            );
        }
        let found = attribute_breaches(&rows, &hba);
        assert!(found.is_empty(), "{}: {found:#?}", c.name());
    }
}

/// The login roles a self-operated cluster of `kind` holds in world `w`
/// by design section 4.1: the roles of the cluster's database for each
/// cell of the world, or the witness service and migrator roles.
fn cluster_login_roles(w: &World, kind: ClusterKind) -> BTreeSet<String> {
    let db = match kind {
        ClusterKind::Application => CellDatabase::App,
        ClusterKind::Vault => CellDatabase::Vault,
        ClusterKind::Witness => {
            return ["witness_service", "witness_migrator"]
                .into_iter()
                .map(str::to_owned)
                .collect();
        }
        ClusterKind::Control => return BTreeSet::new(),
    };
    let mut out = BTreeSet::new();
    for i in 0..w.spec().cells {
        let cell = CellId(w.cell(i).unwrap().id());
        for role in roles_of(db) {
            out.insert(role_name(db, cell, *role));
        }
    }
    out
}

/// I-82 teeth: a cell role with CREATEDB and CREATEROLE behind a loopback
/// line, and a cell role that reaches `pg_read_server_files` through an
/// intermediate role, are both reported. A clean cell role is not.
#[test]
fn i82_teeth_role_attributes_and_indirect_membership_are_caught() {
    let c = ClusterHandle::start_named(ClusterKind::Application, "w1f_teeth_attrs").unwrap();
    let s = c.server();
    let mut raw = [0u8; 16];
    fstp_crypto::random_bytes(&mut raw).unwrap();
    let hex = cell_hex(CellId(raw));
    let (app, keys) = (format!("c_{hex}_app"), format!("c_{hex}_keys"));
    for role in [&app, &keys] {
        s.create_login_role(role).unwrap();
    }
    s.create_database_for(&format!("c_{hex}"), &[&app, &keys])
        .unwrap();
    let breaches =
        || attribute_breaches(&db::catalogue_rows(s).unwrap(), &db::hba_rows(s).unwrap());
    let clean = breaches();
    assert!(clean.is_empty(), "{clean:#?}");
    s.psql(
        "postgres",
        &format!(
            "ALTER ROLE {app} CREATEDB CREATEROLE;\n\
             CREATE ROLE w1f_teeth_middle NOLOGIN;\n\
             GRANT pg_read_server_files TO w1f_teeth_middle;\n\
             GRANT w1f_teeth_middle TO {keys};"
        ),
    )
    .unwrap();
    let found = breaches();
    assert!(
        found
            .iter()
            .any(|b| b.contains(&app) && b.contains("createdb: true")),
        "{found:#?}"
    );
    assert!(
        found
            .iter()
            .any(|b| *b == format!("{keys} is a member of pg_read_server_files")),
        "{found:#?}"
    );
}

/// I-82, ADR-005, design section 4.7: after a cycle in each of two cells,
/// every server connection of a cell role is to its own cell's database,
/// so no pool serves two cells.
#[test]
fn i82_pool_serves_one_cell() {
    let w = world(2, DbMode::Shared);
    for i in 0..2 {
        let report = w.run_cycle(
            i,
            &CycleScript {
                steps: vec!["login".to_owned(), "create-programme".to_owned()],
            },
        );
        report
            .result
            .unwrap_or_else(|e| panic!("the cycle of cell {i} did not run: {e}"));
    }
    let mut seen = 0usize;
    for c in agent_clusters(&w) {
        let rows = c
            .server()
            .psql(
                "postgres",
                "SELECT usename || '|' || datname FROM pg_stat_activity \
                 WHERE usename IS NOT NULL AND datname IS NOT NULL",
            )
            .unwrap();
        for line in rows.lines() {
            let (user, dbn) = line.split_once('|').unwrap();
            if let Some(cell) = db::cell_of(user) {
                seen += 1;
                assert_eq!(db::cell_of(dbn), Some(cell), "{}: {line}", c.name());
            }
        }
    }
    assert!(seen > 0, "no cell connection was open after the cycles");
}

/// The non-owner table and column grants of the cell database `dbname` on
/// `server`, as `grantee|schema.table|PRIVILEGE` for a table and
/// `grantee|schema.table.column|PRIVILEGE` for a column. A grant to
/// PUBLIC names the grantee `PUBLIC`. The system schemas are left out.
fn live_table_acls(server: &PgServer, dbname: &str) -> BTreeSet<String> {
    let out = server
        .psql(
            dbname,
            "SELECT coalesce(r.rolname, 'PUBLIC') || '|' || n.nspname || '.' || c.relname \
               || '|' || a.privilege_type \
             FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
             CROSS JOIN LATERAL aclexplode(c.relacl) a \
             LEFT JOIN pg_roles r ON r.oid = a.grantee \
             WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') \
               AND n.nspname NOT LIKE 'pg_toast%' AND a.grantee <> c.relowner \
             UNION ALL \
             SELECT coalesce(r.rolname, 'PUBLIC') || '|' || n.nspname || '.' || c.relname \
               || '.' || t.attname || '|' || a.privilege_type \
             FROM pg_attribute t JOIN pg_class c ON c.oid = t.attrelid \
             JOIN pg_namespace n ON n.oid = c.relnamespace \
             CROSS JOIN LATERAL aclexplode(t.attacl) a \
             LEFT JOIN pg_roles r ON r.oid = a.grantee \
             WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') \
               AND n.nspname NOT LIKE 'pg_toast%' AND a.grantee <> c.relowner",
        )
        .unwrap();
    out.lines().map(str::to_owned).collect()
}

/// I-82, ADR-011, design section 4.1: in each cell database of a world,
/// the table and column grants beyond the owner's are exactly the rows of
/// `cell_role_plan` for that database, plus one named seam. The seam is
/// SELECT and INSERT on `vault.p17_condition` for the cell's own `vault`
/// role, in its vault database only
/// (`fstp_celltest::world::P17_CONDITION_GRANT_SEAM`). No grant goes to
/// PUBLIC, to a role of another cell or to any column.
///
/// The seam rows leave this test once Daniel settles the table's rename
/// or an ADR-011 amendment of the `apply_grant` object grammar.
#[test]
fn i82_cell_database_grants_are_the_plan_and_the_named_seam_only() {
    let w = world(2, DbMode::Shared);
    let mut checked = 0usize;
    for i in 0..2 {
        let cell = CellId(w.cell(i).unwrap().id());
        let p = plan(cell).unwrap();
        for (kind, db) in [
            (ClusterKind::Application, CellDatabase::App),
            (ClusterKind::Vault, CellDatabase::Vault),
        ] {
            let c = w.cluster(kind).unwrap();
            let mut want: BTreeSet<String> = BTreeSet::new();
            for g in p.grants.iter().filter(|g| g.database == db) {
                for privilege in &g.privileges {
                    want.insert(format!(
                        "{}|{}|{}",
                        role_name(db, cell, g.role),
                        g.object,
                        privilege.keyword()
                    ));
                }
            }
            if db == CellDatabase::Vault {
                for privilege in ["SELECT", "INSERT"] {
                    want.insert(format!(
                        "{}|{}|{privilege}",
                        role_name(db, cell, RoleName::Vault),
                        fstp_celltest::world::P17_CONDITION_TABLE
                    ));
                }
            }
            let dbname = database_name(db, cell);
            let live = live_table_acls(c.server(), &dbname);
            assert_eq!(live, want, "{}: {dbname}", c.name());
            checked += 1;
        }
    }
    assert_eq!(checked, 4);
}

/// I-82: the reference tables cover every application table of design
/// section 4.2 and each reference grant names one of them.
#[test]
fn i82_reference_grants_name_catalogued_tables() {
    for (_, object, _) in app_grants() {
        assert!(APP_TABLES.contains(&object), "{object}");
    }
}
