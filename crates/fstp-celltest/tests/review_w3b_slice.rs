//! Independent review reproducers for lane W3b (slice fidelity and
//! isolation). Each starts a one-cell SaaS world. `World::start` still
//! refuses at the vault database, but by then the application and vault
//! clusters are hardened and the application database is provisioned. So
//! each check reads what the world left on those clusters.
//!
//! The tests share the named clusters of this binary, so a lock keeps
//! one world start and its check apart from the other's.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Mutex, PoisonError};

use fstp_celltest::world::{ClusterHandle, ClusterKind, DbMode, VaultLayout, World, WorldSpec};
use fstp_control::pg::{CellDatabase, CellSubnet, render_hba};
use fstp_control::pgagent::DbIdent;

static SERIAL: Mutex<()> = Mutex::new(());

/// Starts a one-cell SaaS world. The result is ignored: the provisioning
/// of the application database runs either way.
fn start_one_cell_world() {
    let _ = World::start(WorldSpec {
        cells: 1,
        mode: DbMode::Shared,
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted: false,
        process_mode: false,
    });
}

/// I-82, design sections 4.1 and 9.2 step 4, ADR-011: the `pg_hba.conf`
/// of a world's application cluster is the file the production plan
/// renders, `fstp_control::pg::render_hba`, for the cells it holds. The
/// world writes the `fstp-pgtest` file instead. It has another reject
/// tail and no `fstp_repl` line, so the I-82 `pg_hba` tests would check
/// the harness generator rather than production.
#[test]
fn review_w3b_world_pg_hba_is_the_production_render() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    start_one_cell_world();
    let app = ClusterHandle::start(ClusterKind::Application).unwrap();
    let server = app.server();
    let cells: Vec<_> = server
        .psql(
            "postgres",
            "SELECT datname FROM pg_database WHERE datname ~ '^c_[0-9a-f]{32}$' ORDER BY oid",
        )
        .unwrap()
        .lines()
        .map(|name| DbIdent::parse(name).unwrap().cell())
        .collect();
    assert!(
        !cells.is_empty(),
        "the world provisioned no application database"
    );
    let subnet = CellSubnet::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 32).unwrap();
    let with_subnet: Vec<_> = cells.iter().map(|c| (*c, subnet)).collect();
    let want = render_hba(CellDatabase::App, &with_subnet).unwrap();
    let got = std::fs::read_to_string(server.dir().join("data/pg_hba.conf")).unwrap();
    let rules = |text: &str| -> Vec<String> {
        let mut v: Vec<String> = text
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
            .map(str::to_owned)
            .collect();
        v.sort();
        v
    };
    assert_eq!(
        rules(&got),
        rules(&want),
        "I-82: the world's pg_hba.conf is not fstp_control::pg::render_hba:\n{got}"
    );
}

/// I-82, G22, Q4, design section 4.1: every self-operated cluster of a
/// world holds the replication role `fstp_repl`, the only role with
/// REPLICATION besides the superuser. The world never creates it, so
/// `i82_replication_role_has_loopback_line_only_and_no_connect` cannot
/// pass on a world that starts.
#[test]
fn review_w3b_world_clusters_hold_the_replication_role() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    start_one_cell_world();
    for kind in [ClusterKind::Application, ClusterKind::Vault] {
        let c = ClusterHandle::start(kind).unwrap();
        let repl = c
            .server()
            .psql(
                "postgres",
                "SELECT string_agg(rolname, ',' ORDER BY rolname) FROM pg_roles \
                 WHERE rolreplication AND NOT rolsuper",
            )
            .unwrap();
        assert_eq!(
            repl,
            "fstp_repl",
            "I-82, G22: the {} cluster's replication roles",
            c.name()
        );
    }
}
