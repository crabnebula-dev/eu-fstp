//! I-82, design section 9.3, ADR-011: the pure half of the isolation
//! auditor, `fstp_control::isolation_audit::privilege_graph`.
//!
//! The auditor turns one cluster's scalar catalogue rows into a graph, and
//! the I-82 sweeps look for a path from one cell's role to another cell's
//! database. A path the graph leaves out is a path no sweep can find, so
//! these tests check that every edge the rows imply is there:
//!
//! - each `pg_auth_members` row as `member -> role`;
//! - each CONNECT grant of `pg_database.datacl` as `grantee -> database`,
//!   PUBLIC included;
//! - each SUPERUSER role as `role -> attribute:superuser`. A superuser
//!   needs no CONNECT grant and reads every file of the cluster.
//!
//! The node names follow the reading of lane W1f in
//! `fstp_celltest::mc::place_model::db`, whose `cross_cell_paths` reads
//! these graphs: role and database names as the catalogue spells them,
//! `PUBLIC` for the pseudo-role, and `attribute:superuser`. The graph may
//! hold more edges, such as `pg_hba` lines. The graph must not depend on
//! the order of the rows.
//!
//! The view grants of design section 9.3 and the database owners travel
//! in `AuditRows` beside the `CatalogueRows`, so the struct literals of
//! lane W1f stay valid. The last test here covers their edges, and
//! `i82_jobs_on_postgres.rs` reads them from a real server.
//!
//! Lane W2h test author. Red until lane W2h writes the graph:
//! `privilege_graph` is a W0 stub that refuses with
//! `ControlError::NotImplemented`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use std::collections::BTreeSet;

use common::{cell_hex, random_cell};
use fstp_control::isolation_audit::{
    CatalogueRows, DatabaseGrant, HbaRule, Membership, PrivilegeGraph, RoleAttrs, privilege_graph,
};
use fstp_cp_proto::CellId;
use fstp_prop::{Gen, prop_assert};

/// The node a SUPERUSER role reaches (lane W1f reading, see the module
/// docs).
const SUPERUSER_NODE: &str = "attribute:superuser";

/// The privilege types of `pg_database.datacl`.
const DATABASE_PRIVILEGES: [&str; 3] = ["CONNECT", "CREATE", "TEMPORARY"];

fn graph(rows: &CatalogueRows) -> Result<PrivilegeGraph, String> {
    privilege_graph(rows).map_err(|e| format!("privilege_graph: {e}"))
}

fn edges(g: &PrivilegeGraph) -> BTreeSet<(String, String)> {
    g.edges
        .iter()
        .map(|e| (e.from.clone(), e.to.clone()))
        .collect()
}

/// A role or database name: a cell role or database, a predefined or
/// machinery role, or an arbitrary name the catalogue could hold.
fn name(g: &mut Gen, cells: &[CellId]) -> String {
    match g.u8_in(0..=3) {
        0 => {
            let cell = *g.pick(cells);
            let suffix = *g.pick(&["", "_migrator", "_writer", "_app", "_keys", "_auditor"]);
            format!("{}_{}{suffix}", g.pick(&["c", "v"]), cell_hex(cell))
        }
        1 => (*g.pick(&[
            "fstp_super",
            "fstp_repl",
            "pg_read_all_data",
            "pg_monitor",
            "postgres",
            "template1",
        ]))
        .to_owned(),
        2 => g.ascii_string(1..=24),
        _ => g.string(1..=12),
    }
}

/// Catalogue rows of one cluster, as the auditor job reads them.
fn rows(g: &mut Gen) -> CatalogueRows {
    let cells = [random_cell(g), random_cell(g)];
    let roles = g.vec(0..=8, |g| RoleAttrs {
        name: name(g, &cells),
        superuser: g.bool(),
        createrole: g.bool(),
        createdb: g.bool(),
        replication: g.bool(),
        bypassrls: g.bool(),
        login: g.bool(),
    });
    let memberships = g.vec(0..=8, |g| Membership {
        member: name(g, &cells),
        role: name(g, &cells),
    });
    let database_grants = g.vec(0..=8, |g| DatabaseGrant {
        database: name(g, &cells),
        grantee: if g.bool() {
            "PUBLIC".to_owned()
        } else {
            name(g, &cells)
        },
        privilege: (*g.pick(&DATABASE_PRIVILEGES)).to_owned(),
    });
    let extensions = g.vec(0..=2, |g| (*g.pick(&["plpgsql", "dblink"])).to_owned());
    let hba = g.vec(0..=4, |g| HbaRule {
        line: g.i64_in(1..=200),
        kind: (*g.pick(&["hostssl", "local", "host"])).to_owned(),
        database: name(g, &cells),
        user: name(g, &cells),
        address: (*g.pick(&["127.0.0.1", "10.0.0.0", ""])).to_owned(),
        method: (*g.pick(&["scram-sha-256", "reject", "trust"])).to_owned(),
    });
    CatalogueRows {
        roles,
        memberships,
        database_grants,
        extensions,
        hba,
    }
}

/// I-82, design section 9.3: every `pg_auth_members` row is an edge from
/// the member to the role. A member can `SET ROLE` to the role, so a
/// missing edge hides a path.
#[test]
fn i82_privilege_graph_holds_every_membership_edge() {
    fstp_prop::check(
        "i82_privilege_graph_holds_every_membership_edge",
        |g: &mut Gen| {
            let r = rows(g);
            let have = edges(&graph(&r)?);
            for m in &r.memberships {
                prop_assert!(
                    have.contains(&(m.member.clone(), m.role.clone())),
                    "no edge for {m:?}"
                );
            }
            Ok(())
        },
    );
}

/// I-82, design section 9.3: every CONNECT grant of `pg_database.datacl`
/// is an edge from the grantee to the database, PUBLIC included.
#[test]
fn i82_privilege_graph_holds_every_connect_edge() {
    fstp_prop::check(
        "i82_privilege_graph_holds_every_connect_edge",
        |g: &mut Gen| {
            let r = rows(g);
            let have = edges(&graph(&r)?);
            for d in r
                .database_grants
                .iter()
                .filter(|d| d.privilege == "CONNECT")
            {
                prop_assert!(
                    have.contains(&(d.grantee.clone(), d.database.clone())),
                    "no edge for {d:?}"
                );
            }
            Ok(())
        },
    );
}

/// I-82, design section 4.1: every SUPERUSER role has an edge to
/// `attribute:superuser`, whether or not it can log in. A role that is a
/// member of a NOLOGIN superuser role can `SET ROLE` to it.
#[test]
fn i82_privilege_graph_holds_a_superuser_edge_for_every_superuser() {
    fstp_prop::check(
        "i82_privilege_graph_holds_a_superuser_edge_for_every_superuser",
        |g: &mut Gen| {
            let r = rows(g);
            let have = edges(&graph(&r)?);
            for role in r.roles.iter().filter(|a| a.superuser) {
                prop_assert!(
                    have.contains(&(role.name.clone(), SUPERUSER_NODE.to_owned())),
                    "no superuser edge for {role:?}"
                );
            }
            Ok(())
        },
    );
}

/// I-82, design section 9.3: the graph does not depend on the order in
/// which the job read the rows.
#[test]
fn i82_privilege_graph_ignores_row_order() {
    fstp_prop::check("i82_privilege_graph_ignores_row_order", |g: &mut Gen| {
        let r = rows(g);
        let mut s = r.clone();
        g.shuffle(&mut s.roles);
        g.shuffle(&mut s.memberships);
        g.shuffle(&mut s.database_grants);
        g.shuffle(&mut s.extensions);
        g.shuffle(&mut s.hba);
        let a: BTreeSet<_> = graph(&r)?.edges.into_iter().collect();
        let b: BTreeSet<_> = graph(&s)?.edges.into_iter().collect();
        prop_assert!(a == b, "{a:?}\n!=\n{b:?}");
        Ok(())
    });
}

/// I-82, design section 9.3: the graph of one clean cluster with two cells.
/// Each cell's app role holds CONNECT on its own database, PUBLIC holds
/// CONNECT on `postgres` only, and `fstp_super` is the superuser. The graph
/// holds every implied edge. It invents no edge from a cell role, or from
/// PUBLIC, to a cell database the rows grant it nothing on.
#[test]
fn i82_privilege_graph_of_a_clean_two_cell_cluster() {
    let a = cell_hex(CellId([0x0a; 16]));
    let b = cell_hex(CellId([0x0b; 16]));
    let role = |name: &str, superuser: bool| RoleAttrs {
        name: name.to_owned(),
        superuser,
        createrole: superuser,
        createdb: superuser,
        replication: superuser,
        bypassrls: superuser,
        login: true,
    };
    let connect = |database: &str, grantee: &str| DatabaseGrant {
        database: database.to_owned(),
        grantee: grantee.to_owned(),
        privilege: "CONNECT".to_owned(),
    };
    let rows = CatalogueRows {
        roles: vec![
            role("fstp_super", true),
            role(&format!("c_{a}_app"), false),
            role(&format!("c_{b}_app"), false),
        ],
        memberships: Vec::new(),
        database_grants: vec![
            connect("postgres", "PUBLIC"),
            connect(&format!("c_{a}"), &format!("c_{a}_app")),
            connect(&format!("c_{b}"), &format!("c_{b}_app")),
        ],
        extensions: vec!["plpgsql".to_owned()],
        hba: Vec::new(),
    };
    let have = edges(&graph(&rows).unwrap());
    let want: BTreeSet<(String, String)> = [
        ("fstp_super".to_owned(), SUPERUSER_NODE.to_owned()),
        ("PUBLIC".to_owned(), "postgres".to_owned()),
        (format!("c_{a}_app"), format!("c_{a}")),
        (format!("c_{b}_app"), format!("c_{b}")),
    ]
    .into_iter()
    .collect();
    let missing: Vec<_> = want.difference(&have).collect();
    assert!(missing.is_empty(), "missing edges {missing:?}");
    for (from, to) in [
        (format!("c_{a}_app"), format!("c_{b}")),
        (format!("c_{b}_app"), format!("c_{a}")),
        ("PUBLIC".to_owned(), format!("c_{a}")),
        ("PUBLIC".to_owned(), format!("c_{b}")),
    ] {
        assert!(
            !have.contains(&(from.clone(), to.clone())),
            "invented edge {from} -> {to}"
        );
    }
}

/// I-82, design section 9.3: an `AuditRows` adds an `owner -> database`
/// edge for each database owner, and a `PUBLIC -> view:<db>.<name>` or
/// `PUBLIC -> function:<db>.<signature>` edge for each G14 object still
/// open. Bare `CatalogueRows` give the same graph as `AuditRows` with
/// neither.
#[test]
fn i82_privilege_graph_holds_owner_and_open_g14_edges() {
    use fstp_control::isolation_audit::{AuditRows, DatabaseOwner, OpenG14Object};
    let a = cell_hex(CellId([0x0c; 16]));
    let rows = AuditRows {
        catalogue: CatalogueRows::default(),
        database_owners: vec![DatabaseOwner {
            database: format!("c_{a}"),
            owner: format!("c_{a}_app"),
        }],
        open_g14: vec![
            OpenG14Object {
                database: format!("c_{a}"),
                kind: "view".to_owned(),
                name: "pg_stat_activity".to_owned(),
                privilege: "SELECT".to_owned(),
            },
            OpenG14Object {
                database: "postgres".to_owned(),
                kind: "function".to_owned(),
                name: "pg_stat_get_backend_idset()".to_owned(),
                privilege: "EXECUTE".to_owned(),
            },
        ],
    };
    let have: BTreeSet<(String, String, String)> = privilege_graph(&rows)
        .unwrap()
        .edges
        .into_iter()
        .map(|e| (e.from, e.to, e.via))
        .collect();
    let want: BTreeSet<(String, String, String)> = [
        (format!("c_{a}_app"), format!("c_{a}"), "owner".to_owned()),
        (
            "PUBLIC".to_owned(),
            format!("view:c_{a}.pg_stat_activity"),
            "SELECT".to_owned(),
        ),
        (
            "PUBLIC".to_owned(),
            "function:postgres.pg_stat_get_backend_idset()".to_owned(),
            "EXECUTE".to_owned(),
        ),
    ]
    .into_iter()
    .collect();
    assert_eq!(have, want);
    assert_eq!(
        graph(&rows.catalogue).unwrap(),
        privilege_graph(&AuditRows::default()).unwrap()
    );
}
