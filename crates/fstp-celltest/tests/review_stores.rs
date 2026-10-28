//! Review reproducers for the at-rest half of the canary scans (design
//! sections 14.1 and 14.3). `World::stores` hands `scan` the raw files of
//! each cluster directory. These tests write a canary the way PostgreSQL
//! really stores some values and require `scan` to find it. Written by
//! the independent reviewer.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_celltest::canary::{Canary, CanaryKind};
use fstp_celltest::scan::{StoreSet, scan};
use fstp_celltest::world::{ClusterKind, DbMode, VaultLayout, World, WorldSpec};

/// The stores of one cluster, as `World::stores` collects each cluster.
/// Fix round 1 rerouted this helper from a raw file walk through the
/// harness entry point, as the finding asked, so the scanner-level
/// reproducers check what the harness hands `scan`.
fn server_stores(server: &fstp_pgtest::PgServer) -> StoreSet {
    fstp_celltest::world::cluster_stores("fixture", server).unwrap()
}

/// Design section 14.1, canary kind "proposal text": a long proposal text
/// is TOAST-compressed by PostgreSQL (pglz, the PostgreSQL 16 default).
/// A canary inside it must still be found in the cluster's files, or every
/// I-19 scan of proposal text passes whether or not it leaked.
#[test]
fn review_scan_finds_a_canary_in_a_toast_compressed_column() {
    let server = fstp_pgtest::PgServer::shared().unwrap();
    let db = server.fresh_database().unwrap();
    let canary = Canary::generate(1, CanaryKind::ProposalText).unwrap();
    server
        .psql(
            &db.dbname,
            &format!(
                "CREATE TABLE proposal (body text);\n\
                 INSERT INTO proposal VALUES \
                 (repeat('synthetic proposal text. ', 200) || '{}' || \
                  repeat('synthetic proposal text. ', 200));\n\
                 CHECKPOINT;",
                canary.text()
            ),
        )
        .unwrap();
    // Control: the server holds the value, and stored it compressed.
    let method = server
        .psql(
            &db.dbname,
            "SELECT pg_column_compression(body) FROM proposal",
        )
        .unwrap();
    assert_eq!(method, "pglz");
    let report = scan(&server_stores(server), std::slice::from_ref(&canary)).unwrap();
    assert!(
        !report.is_clean(),
        "a canary in a TOAST-compressed column was not found in any file"
    );
}

/// Design section 14.1: an incompressible value over 2 kB is stored out
/// of line in TOAST chunks of 1996 bytes, each its own tuple. A canary
/// that straddles a chunk boundary must still be found.
#[test]
fn review_scan_finds_a_canary_across_toast_chunks() {
    let server = fstp_pgtest::PgServer::shared().unwrap();
    let db = server.fresh_database().unwrap();
    let canary = Canary::generate(1, CanaryKind::Document).unwrap();
    server
        .psql(
            &db.dbname,
            &format!(
                "CREATE TABLE document (body text);\n\
                 ALTER TABLE document ALTER COLUMN body SET STORAGE EXTERNAL;\n\
                 INSERT INTO document VALUES \
                 (repeat('x', 1980) || '{}' || repeat('y', 3000));\n\
                 CHECKPOINT;",
                canary.text()
            ),
        )
        .unwrap();
    // Control: the value is stored uncompressed and out of line.
    let shape = server
        .psql(
            &db.dbname,
            "SELECT coalesce(pg_column_compression(body), 'none') || ' ' || \
             pg_column_size(body) FROM document",
        )
        .unwrap();
    assert_eq!(shape, format!("none {}", 4980 + canary.text().len()));
    let report = scan(&server_stores(server), std::slice::from_ref(&canary)).unwrap();
    assert!(
        !report.is_clean(),
        "a canary across two TOAST chunks was not found in any file"
    );
}

/// Design section 14.3: `World::stores` is "every database". A row a test
/// has just committed must be in the database's own files when the store
/// set is taken. The harness servers run with `synchronous_commit = off`,
/// and dirty pages stay in shared buffers until a checkpoint, so a scan
/// taken without one misses the row and a per-database isolation check
/// passes on a leak. Needs `fstp-pki` (W1i) and `fstp_crypto::sig` (W1h)
/// to start the named cluster.
#[test]
fn review_world_stores_hold_a_row_written_just_before() {
    let world = World::start(WorldSpec {
        cells: 0,
        mode: DbMode::Shared,
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted: false,
        process_mode: false,
    })
    .unwrap();
    let vault = world.cluster(ClusterKind::Vault).unwrap().server();
    let db = vault.fresh_database().unwrap();
    let canary = Canary::generate(1, CanaryKind::Email).unwrap();
    vault
        .psql(
            &db.dbname,
            &format!(
                "CREATE TABLE fact (v text);\nINSERT INTO fact VALUES ('{}');",
                canary.text()
            ),
        )
        .unwrap();
    let oid = vault
        .psql(
            "postgres",
            &format!(
                "SELECT oid FROM pg_database WHERE datname = '{}'",
                db.dbname
            ),
        )
        .unwrap();
    let report = scan(&world.stores().unwrap(), std::slice::from_ref(&canary)).unwrap();
    let base = format!("vault/data/base/{oid}/");
    assert!(
        report.hits.iter().any(|(s, _)| s.starts_with(&base)),
        "the row is not in its database's files: {:?}",
        report.hits
    );
}

/// Design sections 14.1 and 14.3, through the harness entry point: a
/// document canary that straddles two TOAST chunks of a vault cluster
/// table is found in `World::stores`. Needs `fstp-pki` (W1i) and
/// `fstp_crypto::sig` (W1h) to start the named cluster; the raw-file
/// mechanism is shown by `review_scan_finds_a_canary_across_toast_chunks`.
#[test]
fn review_world_stores_find_a_canary_across_toast_chunks() {
    let world = World::start(WorldSpec {
        cells: 0,
        mode: DbMode::Shared,
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted: false,
        process_mode: false,
    })
    .unwrap();
    let vault = world.cluster(ClusterKind::Vault).unwrap().server();
    let db = vault.fresh_database().unwrap();
    let canary = Canary::generate(1, CanaryKind::Document).unwrap();
    vault
        .psql(
            &db.dbname,
            &format!(
                "CREATE TABLE document (body text);\n\
                 ALTER TABLE document ALTER COLUMN body SET STORAGE EXTERNAL;\n\
                 INSERT INTO document VALUES \
                 (repeat('x', 1980) || '{}' || repeat('y', 3000));\n\
                 CHECKPOINT;",
                canary.text()
            ),
        )
        .unwrap();
    let report = scan(&world.stores().unwrap(), std::slice::from_ref(&canary)).unwrap();
    assert!(
        !report.is_clean(),
        "a canary across two TOAST chunks is invisible to World::stores"
    );
}
