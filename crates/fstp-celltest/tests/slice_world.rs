//! The world harness's own hygiene on its shared clusters (design
//! section 14.3, step W3b of section 19). The one test of this binary
//! starts two worlds one after the other, so no other world start in the
//! binary runs between them.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use fstp_celltest::world::{ClusterHandle, ClusterKind, DbMode, VaultLayout, World, WorldSpec};

fn one_cell() -> WorldSpec {
    WorldSpec {
        cells: 1,
        mode: DbMode::Shared,
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted: false,
        process_mode: false,
    }
}

/// The cell databases on the shared cluster of `kind`.
fn cell_databases(kind: ClusterKind) -> BTreeSet<String> {
    ClusterHandle::start(kind)
        .unwrap()
        .server()
        .psql(
            "postgres",
            "SELECT datname FROM pg_database WHERE datname ~ '^[cv]_[0-9a-f]{32}$'",
        )
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

/// The roles of the cell database `db` on the shared cluster of `kind`:
/// every role named `<db>_<suffix>`.
fn roles_of(kind: ClusterKind, db: &str) -> String {
    ClusterHandle::start(kind)
        .unwrap()
        .server()
        .psql(
            "postgres",
            &format!(
                "SELECT coalesce(string_agg(rolname, ','), '') FROM pg_roles \
                 WHERE starts_with(rolname, '{db}_')"
            ),
        )
        .unwrap()
}

/// The `pg_hba.conf` lines of the shared cluster of `kind` whose database
/// column is `db`.
fn hba_lines_of(kind: ClusterKind, db: &str) -> Vec<String> {
    let c = ClusterHandle::start(kind).unwrap();
    std::fs::read_to_string(c.server().dir().join("data/pg_hba.conf"))
        .unwrap()
        .lines()
        .filter(|l| l.split_whitespace().nth(1) == Some(db))
        .map(str::to_owned)
        .collect()
}

/// Design section 14.3: a world start with cells that fails leaves its
/// cells for a test to read, and the next world start with cells drops
/// them first: their databases, their roles and their `pg_hba` lines. So
/// failed starts never pile up on the shared clusters. The cells of a
/// world that started stay.
#[test]
fn slice_world_cells_of_a_failed_start_are_dropped_by_the_next_start() {
    let kinds = [ClusterKind::Application, ClusterKind::Vault];
    let before: Vec<BTreeSet<String>> = kinds.iter().map(|k| cell_databases(*k)).collect();
    let first = World::start(one_cell());
    let after_first: Vec<BTreeSet<String>> = kinds.iter().map(|k| cell_databases(*k)).collect();
    let second = World::start(one_cell());
    let mut breaches = Vec::new();
    for (i, kind) in kinds.iter().enumerate() {
        let after_second = cell_databases(*kind);
        if after_first[i].difference(&before[i]).next().is_none() {
            breaches.push(format!(
                "{kind:?}: the first start created no cell database"
            ));
        }
        for db in after_first[i].difference(&before[i]) {
            let kept = after_second.contains(db);
            let roles = roles_of(*kind, db);
            let lines = hba_lines_of(*kind, db);
            match (&first, kept) {
                (Err(_), true) => breaches.push(format!("{kind:?}: {db} stays")),
                (Err(_), false) if !roles.is_empty() || !lines.is_empty() => {
                    breaches.push(format!(
                        "{kind:?}: {db} left roles {roles:?}, lines {lines:?}"
                    ));
                }
                (Ok(_), false) => breaches.push(format!("{kind:?}: started {db} was dropped")),
                _ => {}
            }
        }
    }
    assert!(
        breaches.is_empty(),
        "first start {:?}, second start {:?}: {breaches:?}",
        first.as_ref().err(),
        second.as_ref().err()
    );
}
