//! The seeded vault of a world writes `vault_audit.chain` as
//! `fstp_vault::service` does (I-24, ADR-010, Daniel's Q-C of
//! 2026-11-13). Lane m3/login-m2http.
//!
//! Q-C: each committed fact batch and each identity release or read is a
//! kind 1 row of the vault chain. A seeded verification is a fact batch,
//! so it commits with its kind 1 row and its anchor, receipted by the
//! world's witness.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_celltest::world::{ClusterKind, DbMode, VaultLayout, World, WorldSpec};
use fstp_domain::id::AccountId;

/// The number of rows of `table` in the vault database of cell 0 that
/// match `filter`.
fn count(world: &World, table: &str, filter: &str) -> u64 {
    let cell = world.cell(0).unwrap();
    let server = world.cluster(ClusterKind::Vault).unwrap().server();
    let out = server
        .psql(
            &cell.vault_database(),
            &format!("SELECT count(*) FROM {table} WHERE {filter}"),
        )
        .unwrap();
    out.trim().parse().unwrap()
}

/// I-24, Q-C: a seeded fact batch of a world cell commits with a kind 1
/// row of `vault_audit.chain` and an anchor of that row.
#[test]
fn i24_seeded_vault_fact_batch_is_a_kind_1_vault_chain_row() {
    let world = World::start(WorldSpec {
        cells: 1,
        mode: DbMode::Shared,
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted: false,
        process_mode: false,
    })
    .unwrap();
    let rows = count(&world, "vault_audit.chain", "kind = 1");
    let anchors = count(&world, "vault_audit.anchor", "true");
    world
        .cell(0)
        .unwrap()
        .seed_verification(AccountId::from_raw(0x5EED), b"synthetic-chain-person")
        .unwrap();
    assert!(
        count(&world, "vault_audit.chain", "kind = 1") > rows,
        "the seeded fact batch wrote no kind 1 vault chain row"
    );
    assert!(
        count(&world, "vault_audit.anchor", "true") > anchors,
        "the seeded fact batch was not anchored"
    );
}
