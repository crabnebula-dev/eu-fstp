//! Self-tests of the world store set (M3 design sections 14.1 and 14.3,
//! lane W1a). Written by the W1a implementer.
//!
//! `World::stores` is the at-rest half of the I-17, I-19 and I-80 canary
//! scans. A canary written to a cluster must show up in the store set, and
//! a canary written nowhere must not. Each test that starts a world needs
//! a cluster with its own cluster CA, so it stays red until `fstp-pki`
//! (lane W1i) and the `fstp-crypto` signing module (lane W1h) land. The
//! `cluster_stores` tests run on the fixture server, through the same code
//! `World::stores` runs per cluster, and the plan tests need no server.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_celltest::canary::{Canary, CanaryKind};
use fstp_celltest::scan::scan;
use fstp_celltest::world::{
    ClusterKind, DbMode, VaultLayout, World, WorldDatabase, WorldSpec, cluster_plan, cluster_stores,
};

fn saas_world() -> World {
    World::start(WorldSpec {
        cells: 0,
        mode: DbMode::Shared,
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted: false,
        process_mode: false,
    })
    .unwrap()
}

/// I-19 instrument, design section 14.3: a canary written to the vault
/// cluster's data files is found in the world's store set, under that
/// cluster only, and a canary written nowhere is not found. A store set
/// that reads no data file fails the first half. The test runs no
/// CHECKPOINT itself, so it checks that `World::stores` flushes the
/// cluster first.
#[test]
fn harness_world_stores_hold_what_a_cluster_wrote() {
    let world = saas_world();
    let written = Canary::generate(1, CanaryKind::Email).unwrap();
    let absent = Canary::generate(1, CanaryKind::Name).unwrap();
    let vault = world.cluster(ClusterKind::Vault).unwrap().server();
    vault
        .psql(
            "postgres",
            &format!(
                "CREATE TABLE IF NOT EXISTS harness_world_canary (v text);\n\
                 INSERT INTO harness_world_canary VALUES ('{}');",
                written.text()
            ),
        )
        .unwrap();
    let report = scan(&world.stores().unwrap(), &[written.clone(), absent]).unwrap();
    assert!(!report.hits.is_empty(), "the written canary was not found");
    for (store, text) in &report.hits {
        assert_eq!(*text, written.text(), "{store}");
        assert!(store.starts_with("vault/"), "{store}");
    }
}

/// Design section 1.4: a self-hosted world without cells runs the
/// application and vault clusters only. Its witness keeps a file store.
#[test]
fn harness_world_self_hosted_runs_application_and_vault_clusters() {
    let world = World::start(WorldSpec {
        cells: 0,
        mode: DbMode::Shared,
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted: true,
        process_mode: false,
    })
    .unwrap();
    let kinds: Vec<ClusterKind> = world.clusters().iter().map(|c| c.kind()).collect();
    assert_eq!(kinds, vec![ClusterKind::Application, ClusterKind::Vault]);
}

/// Design sections 9.2 and 14.3, step W3a of section 19: a world with a
/// cell runs the real cell runtime. Cell 0 exists and no cell 1. Its
/// loopback health route answers 200 with the fixed body. A public route
/// answers through the edge with the cell host as SNI. The ledger holds
/// the first admin's invitation of step 10, split in two halves for a
/// SaaS cell (Q35), and the world holds both halves.
#[test]
fn harness_world_with_cells_starts_the_cell_runtime() {
    use fstp_celltest::world::HttpRequest;
    let world = World::start(WorldSpec {
        cells: 1,
        mode: DbMode::Shared,
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted: false,
        process_mode: false,
    })
    .unwrap_or_else(|e| panic!("the world did not start: {e}"));
    let cell = world.cell(0).expect("the world holds no cell 0");
    assert!(world.cell(1).is_none(), "the world holds a second cell");
    let urls = cell
        .urls()
        .unwrap_or_else(|e| panic!("the cell runs no listener: {e}"));
    let health_host = urls
        .health
        .strip_prefix("http://")
        .and_then(|rest| rest.strip_suffix("/healthz"))
        .unwrap_or_else(|| panic!("health URL {}", urls.health))
        .to_owned();
    let health = cell
        .health(&HttpRequest::new("GET", "/healthz").header("host", health_host))
        .unwrap_or_else(|e| panic!("the health listener: {e}"));
    assert_eq!(
        (health.status, health.body.as_slice()),
        (200, fstp_cell::http::front::HEALTH_BODY)
    );
    let options = cell
        .request(
            &HttpRequest::new("POST", "/auth/passkey/login/options")
                .header("host", cell.host())
                .header("origin", format!("https://{}", cell.host()))
                .header("content-type", "application/json")
                .body(b"{}".to_vec()),
        )
        .unwrap_or_else(|e| panic!("the edge did not reach the cell: {e}"));
    assert_eq!(
        options.status,
        200,
        "{}",
        String::from_utf8_lossy(&options.body)
    );
    assert!(
        String::from_utf8_lossy(&options.body).contains("\"challenge_id\":\""),
        "{}",
        String::from_utf8_lossy(&options.body)
    );
    let ledger = cell
        .ledger()
        .unwrap_or_else(|e| panic!("the cell ledger: {e}"));
    let invitations: Vec<(bool, bool)> = ledger
        .iter()
        .filter_map(|e| match &e.record {
            fstp_cell_core::CellRecord::Auth(fstp_auth::AuthRecord::InvitationIssued {
                first_admin,
                split,
                ..
            }) => Some((*first_admin, *split)),
            _ => None,
        })
        .collect();
    assert_eq!(invitations, vec![(true, true)], "the invitation records");
    let halves = cell
        .first_admin_invitation()
        .unwrap_or_else(|e| panic!("the first admin's invitation: {e}"));
    assert_ne!(halves.first, halves.second, "the two halves are equal");
}

fn spec(cells: u8, mode: DbMode, self_hosted: bool) -> WorldSpec {
    WorldSpec {
        cells,
        mode,
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted,
        process_mode: false,
    }
}

fn plan(spec: &WorldSpec) -> Vec<(ClusterKind, String)> {
    cluster_plan(spec)
}

fn named(kind: ClusterKind, name: &str) -> (ClusterKind, String) {
    (kind, name.to_owned())
}

/// Design section 1.4, I-83: a SaaS world in shared mode has one cluster
/// of each kind, named by kind. No server is needed.
#[test]
fn harness_world_shared_plan_has_one_cluster_per_kind() {
    assert_eq!(
        plan(&spec(2, DbMode::Shared, false)),
        vec![
            named(ClusterKind::Application, "application"),
            named(ClusterKind::Vault, "vault"),
            named(ClusterKind::Control, "control"),
            named(ClusterKind::Witness, "witness"),
        ]
    );
}

/// Design sections 1.4 and 14.2 (M-PLACE), I-83: in dedicated mode each
/// cell gets an application and a vault cluster of its own.
#[test]
fn harness_world_dedicated_plan_gives_each_cell_its_own_clusters() {
    assert_eq!(
        plan(&spec(2, DbMode::Dedicated, false)),
        vec![
            named(ClusterKind::Application, "application_0"),
            named(ClusterKind::Vault, "vault_0"),
            named(ClusterKind::Application, "application_1"),
            named(ClusterKind::Vault, "vault_1"),
            named(ClusterKind::Control, "control"),
            named(ClusterKind::Witness, "witness"),
        ]
    );
}

/// Design section 1.4: a self-hosted world runs two instances of its own,
/// which no SaaS world of the same test binary shares.
#[test]
fn harness_world_self_hosted_plan_shares_no_saas_cluster() {
    let saas = plan(&spec(0, DbMode::Shared, false));
    let own = plan(&spec(0, DbMode::Shared, true));
    assert_eq!(
        own,
        vec![
            named(ClusterKind::Application, "selfhosted_application"),
            named(ClusterKind::Vault, "selfhosted_vault"),
        ]
    );
    assert!(own.iter().all(|c| !saas.contains(c)), "{own:?}");
}

/// I-19 instrument, design section 14.3: a row committed just before the
/// store set is taken is in its database's relation file, with no
/// CHECKPOINT by the test. The fixture server runs with
/// `synchronous_commit = off`, as the named clusters do.
#[test]
fn harness_world_cluster_stores_hold_a_row_committed_just_before() {
    let server = fstp_pgtest::PgServer::shared().unwrap();
    let db = server.fresh_database().unwrap();
    let canary = Canary::generate(1, CanaryKind::Email).unwrap();
    let path = server
        .psql(
            &db.dbname,
            &format!(
                "CREATE TABLE fact (v text);\nINSERT INTO fact VALUES ('{}');\n\
                 SELECT pg_relation_filepath('fact');",
                canary.text()
            ),
        )
        .unwrap();
    let report = scan(
        &cluster_stores("fixture", server).unwrap(),
        std::slice::from_ref(&canary),
    )
    .unwrap();
    let store = format!("fixture/data/{path}");
    assert!(
        report.hits.iter().any(|(s, _)| *s == store),
        "{store} lacks the row: {:?}",
        report.hits
    );
}

/// I-17, I-19 instrument, design sections 14.1 and 14.3: a proposal text
/// canary in a compressed TOAST value is found in the database's logical
/// dump, which the store set attributes to that database alone.
#[test]
fn harness_world_cluster_stores_find_a_compressed_value_in_its_dump() {
    let server = fstp_pgtest::PgServer::shared().unwrap();
    let db = server.fresh_database().unwrap();
    let canary = Canary::generate(2, CanaryKind::ProposalText).unwrap();
    server
        .psql(
            &db.dbname,
            &format!(
                "CREATE TABLE proposal (body text);\n\
                 INSERT INTO proposal VALUES \
                 (repeat('synthetic proposal text. ', 300) || '{}' || \
                  repeat('synthetic proposal text. ', 300));",
                canary.text()
            ),
        )
        .unwrap();
    let report = scan(
        &cluster_stores("fixture", server).unwrap(),
        std::slice::from_ref(&canary),
    )
    .unwrap();
    assert!(
        report
            .hits
            .iter()
            .any(|(s, _)| *s == format!("fixture/dump/{}", db.dbname)),
        "{:?}",
        report.hits
    );
}

/// Design section 14.3, shared mode: a database owns its relation files
/// and its dump, and no cluster-wide store such as the WAL.
#[test]
fn harness_world_database_owns_its_own_stores_only() {
    let db = WorldDatabase {
        cluster: "application".to_owned(),
        kind: ClusterKind::Application,
        name: "c_a".to_owned(),
        oid: 16_384,
    };
    let owned = [
        "application/data/base/16384/16390",
        "application/dump/c_a",
        "application/data/base/16385/16390",
        "application/data/base/163840/1",
        "application/data/pg_wal/000000010000000000000001",
        "application/dump/c_b",
        "vault/data/base/16384/16390",
    ]
    .map(|s| db.owns(s));
    assert_eq!(owned, [true, true, false, false, false, false, false]);
}
