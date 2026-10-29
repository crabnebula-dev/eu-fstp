//! T-ISO for I-19: no tenant data crosses a cell boundary (design section
//! 14.4, B1 to B12).
//!
//! Three cells run a full cycle each, with that cell's canaries. Every
//! store and egress capture of the world is scanned for every cell's
//! canaries. A hit counts as a crossing unless it lies in one cell
//! database's own stores or in an egress capture inside the canary's cell
//! (the cell or its vault talking to that cell's vault). A hit in a cell
//! database is a crossing unless that database is the canary cell's own.
//! Shared cluster files, the control plane, the witness, custody traffic
//! and every shared log sink are outside every cell.
//!
//! `CellHandle` names no cell id, so the sweep learns each cell's own
//! databases from its cycle: the cell databases whose data changed during
//! that cell's cycle, matched one to one with the cycles ([`homes_of`]).
//! The matching tolerates a background write of another cell during a
//! cycle. That doubles as the positive control. A cell id on `CellHandle`
//! (lane W1a) would make it direct.
//!
//! Gap, reported by lane W1f: the world exposes no edge store, such as the
//! edge's logs and caches (design section 14.4). The sweep requires one,
//! named `edge/...`, so it stays red until the harness adds it (lane W1a).
//!
//! Gap, reported by lane W1f: `CycleScript` steps are names whose meaning
//! lane W3b defines. The steps here carry each canary as `<kind>:<text>`.
//! A cycle report that confirms each step was applied (lane W3b) would let
//! the positive control check each canary, not only each cycle.
//!
//! Lane W1f wrote these tests before the production code. They are red
//! until the cell runtime (lane W3a) and the slice runner (lane W3b) land.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::{BTreeMap, BTreeSet};

use fstp_celltest::canary::{Canary, generate_set};
use fstp_celltest::mc::place_model::db::{self, StoreOwner, store_owner};
use fstp_celltest::scan::{ScanReport, StoreSet, scan};
use fstp_celltest::world::{
    ClusterKind, CycleScript, DbMode, VaultLayout, World, WorldDatabase, WorldSpec,
};

/// The full cycle of design section 14.4 for one cell, carrying its
/// canaries.
fn script(canaries: &[Canary]) -> CycleScript {
    let mut steps = vec![
        "login".to_owned(),
        "create-programme".to_owned(),
        "publish-call".to_owned(),
    ];
    steps.extend(
        canaries
            .iter()
            .map(|c| format!("{}:{}", c.kind.label(), c.text())),
    );
    steps.extend(
        [
            "submit-proposal",
            "score",
            "rank",
            "negotiate",
            "grant",
            "erase-one-text",
        ]
        .map(str::to_owned),
    );
    CycleScript { steps }
}

/// The crossings in `report`, one line each. `homes` gives each cell's
/// own database hex. A hit in a cell database's stores is a crossing
/// unless the database is the canary cell's own, and a cell with no known
/// home has no database of its own.
fn crossings(
    report: &ScanReport,
    dbs: &[WorldDatabase],
    homes: &BTreeMap<u8, String>,
) -> Vec<String> {
    let mut out = Vec::new();
    for (store, text) in &report.hits {
        let Some(c) = Canary::parse(text) else {
            out.push(format!("{store}: an unparsed hit {text}"));
            continue;
        };
        match store_owner(store, dbs) {
            StoreOwner::Outside => out.push(format!("cell {} canary {text} in {store}", c.cell)),
            StoreOwner::CellInternal(i) if i != c.cell => {
                out.push(format!(
                    "cell {} canary {text} in cell {i}'s {store}",
                    c.cell
                ));
            }
            StoreOwner::CellInternal(_) => {}
            StoreOwner::Database(hex) => {
                if homes.get(&c.cell) != Some(&hex) {
                    out.push(format!(
                        "cell {} canary {text} in the database of cell {hex}: {store}",
                        c.cell
                    ));
                }
            }
        }
    }
    out
}

/// The data of every cell database of `w`, keyed by `(cell hex, database
/// name)`: its logical dump without the `\restrict` lines, whose key is
/// new in every dump.
fn cell_data(w: &World) -> BTreeMap<(String, String), Vec<u8>> {
    let mut out = BTreeMap::new();
    for d in w.databases().unwrap() {
        let Some(hex) = db::cell_of(&d.name) else {
            continue;
        };
        let c = w.clusters().iter().find(|c| c.name() == d.cluster).unwrap();
        let dump = c
            .server()
            .dump_data(&d.name)
            .unwrap_or_else(|e| panic!("cannot dump {}: {e}", d.name));
        let data: Vec<u8> = dump
            .split(|b| *b == b'\n')
            .filter(|l| !l.starts_with(b"\\restrict") && !l.starts_with(b"\\unrestrict"))
            .flat_map(|l| l.iter().copied().chain(*b"\n"))
            .collect();
        out.insert((hex.to_owned(), d.name.clone()), data);
    }
    out
}

/// The cell hexes whose database data differs between `before` and
/// `after`.
fn changed(
    before: &BTreeMap<(String, String), Vec<u8>>,
    after: &BTreeMap<(String, String), Vec<u8>>,
) -> BTreeSet<String> {
    after
        .iter()
        .filter(|(k, v)| before.get(*k) != Some(*v))
        .map(|((hex, _), _)| hex.clone())
        .collect()
}

/// Each cell's own database hex, by the rule of `db::match_homes`, which
/// tolerates a background write of another cell during a cycle. A cycle
/// left with none or several candidates gets no home, and a line in the
/// second value. So two cycles never share a home, and a cycle that
/// changed no database, or only another cycle's home, fails the positive
/// control.
fn homes_of(changes: &[BTreeSet<String>]) -> (BTreeMap<u8, String>, Vec<String>) {
    let homes = db::match_homes(changes);
    let taken: BTreeSet<&String> = homes.values().collect();
    let mut out = Vec::new();
    for (i, mine) in changes.iter().enumerate() {
        if homes.contains_key(&i) {
            continue;
        }
        let left: Vec<&String> = mine.iter().filter(|h| !taken.contains(h)).collect();
        if left.is_empty() {
            out.push(format!(
                "the cycle of cell {i} changed no cell database of its own ({mine:?}), so its \
                 canaries never reached it and the sweep would be vacuous"
            ));
        } else {
            out.push(format!(
                "the cycle of cell {i} changed the databases of {left:?}, so its own is unknown"
            ));
        }
    }
    let homes = homes
        .into_iter()
        .map(|(i, hex)| (u8::try_from(i).unwrap(), hex))
        .collect();
    (homes, out)
}

/// Runs the I-19 sweep and returns every crossing, one line each.
///
/// Positive control: each cell's cycle must complete and must change the
/// databases of a cell that [`homes_of`] gives it as its own home, and no
/// two cycles share a home. A cycle that wrote nothing, or a runner that
/// dropped the steps, fails the sweep, so a clean scan of an empty world
/// never passes as no crossing. The store set must hold control, witness
/// and edge stores, so none of them goes unscanned.
fn sweep(mode: DbMode) -> Vec<String> {
    let w = World::start(WorldSpec {
        cells: 3,
        mode,
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted: false,
        process_mode: false,
    })
    .unwrap_or_else(|e| panic!("the world did not start: {e}"));
    let mut all = Vec::new();
    let mut changes = Vec::new();
    for i in 0..3 {
        let canaries = generate_set(i).unwrap();
        let before = cell_data(&w);
        w.run_cycle(i, &script(&canaries))
            .result
            .unwrap_or_else(|e| panic!("the cycle of cell {i} did not run: {e}"));
        changes.push(changed(&before, &cell_data(&w)));
        all.extend(canaries);
    }
    // The positive control: a cell whose canaries never reached a database
    // of its own fails here, so the sweep is never vacuous.
    let (homes, mut out) = homes_of(&changes);
    let stores = w.stores().unwrap();
    let names: BTreeSet<&str> = stores.stores.iter().map(|(n, _)| n.as_str()).collect();
    for kind in [ClusterKind::Control, ClusterKind::Witness] {
        let c = w.cluster(kind).unwrap();
        assert!(
            names
                .iter()
                .any(|n| n.starts_with(&format!("{}/", c.name()))),
            "the store set holds no store of {}",
            c.name()
        );
    }
    assert!(
        names.iter().any(|n| n.starts_with("edge/")),
        "the store set holds no edge store (edge/...), so the edge goes unscanned \
         (gap raised by lane W1f for lane W1a)"
    );
    let report = scan(&stores, &all).unwrap();
    out.extend(crossings(&report, &w.databases().unwrap(), &homes));
    out
}

/// I-19, T-ISO, shared mode: three cells, one cycle each, and no canary of
/// one cell in any store or capture outside it.
#[test]
fn t_iso_i19_no_canary_crosses_a_cell_boundary() {
    let found = sweep(DbMode::Shared);
    assert!(found.is_empty(), "{found:#?}");
}

/// I-19, T-ISO, dedicated mode: the same sweep over cells with clusters of
/// their own.
#[test]
fn t_iso_i19_no_canary_crosses_a_cell_boundary_dedicated() {
    let found = sweep(DbMode::Dedicated);
    assert!(found.is_empty(), "{found:#?}");
}

// ---------------------------------------------------------------------------
// Teeth for the crossing rule.

fn database(cluster: &str, name: &str, oid: u32) -> WorldDatabase {
    WorldDatabase {
        cluster: cluster.to_owned(),
        kind: ClusterKind::Application,
        name: name.to_owned(),
        oid,
    }
}

/// I-19 teeth: the crossing rule flags a canary in the control plane, in
/// another cell's egress, and in another cell's database, and passes a
/// canary in its own cell's database and its own vault link.
#[test]
fn t_iso_i19_teeth_crossing_rule_flags_every_foreign_store() {
    let (a, b) = ("a".repeat(32), "b".repeat(32));
    let dbs = vec![
        database("application", &format!("c_{a}"), 16_001),
        database("application", &format!("c_{b}"), 16_002),
    ];
    let homes = BTreeMap::from([(0u8, a.clone()), (1u8, b.clone())]);
    let c0 = Canary::generate(0, fstp_celltest::canary::CanaryKind::Name).unwrap();
    let c1 = Canary::generate(1, fstp_celltest::canary::CanaryKind::Email).unwrap();
    let mut stores = StoreSet::default();
    let own = format!("application/dump/c_{a}");
    stores.push(own.clone(), c0.text().into_bytes());
    stores.push("egress/cell-0/vault-0/1/out", c0.text().into_bytes());
    let clean = crossings(
        &scan(&stores, &[c0.clone(), c1.clone()]).unwrap(),
        &dbs,
        &homes,
    );
    assert!(clean.is_empty(), "{clean:?}");
    stores.push("control/dump/cp", c1.text().into_bytes());
    stores.push("egress/cell-0/vault-0/2/out", c1.text().into_bytes());
    stores.push("application/data/base/16002/1234", c0.text().into_bytes());
    let found = crossings(&scan(&stores, &[c0, c1]).unwrap(), &dbs, &homes);
    assert_eq!(found.len(), 3, "{found:#?}");
}

/// I-19 teeth: a canary of cell 0 found only in cell 1's database, with no
/// hit in its own, is a crossing. Stored data is sealed, so this lone
/// leak is the usual shape of a breach. A cell with no known home owns no
/// database.
#[test]
fn t_iso_i19_teeth_lone_leak_into_another_cell_database_is_caught() {
    let (a, b) = ("a".repeat(32), "b".repeat(32));
    let dbs = vec![
        database("application", &format!("c_{a}"), 16_001),
        database("application", &format!("c_{b}"), 16_002),
    ];
    let c0 = Canary::generate(0, fstp_celltest::canary::CanaryKind::Phone).unwrap();
    let mut stores = StoreSet::default();
    stores.push(format!("application/dump/c_{b}"), c0.text().into_bytes());
    let report = scan(&stores, &[c0]).unwrap();
    let homes = BTreeMap::from([(0u8, a), (1u8, b.clone())]);
    let found = crossings(&report, &dbs, &homes);
    assert_eq!(found.len(), 1, "{found:#?}");
    let homeless = crossings(&report, &dbs, &BTreeMap::from([(1u8, b)]));
    assert_eq!(homeless.len(), 1, "{homeless:#?}");
}

/// I-19 teeth for the positive control: a cycle that changed no database
/// of its own, and one that changed two cells' databases that no other
/// cycle explains, each give no home and a failure line. Two cycles never
/// share a home. Three cycles that each changed one cell's databases give
/// three homes.
#[test]
fn t_iso_i19_teeth_positive_control_needs_one_home_per_cell() {
    let set =
        |hexes: &[&str]| -> BTreeSet<String> { hexes.iter().map(|h| (*h).to_owned()).collect() };
    let (homes, out) = homes_of(&[set(&["a"]), set(&["b"]), set(&["c"])]);
    assert_eq!(homes.len(), 3, "{homes:?}");
    assert!(out.is_empty(), "{out:?}");
    let (homes, out) = homes_of(&[set(&["a"]), set(&[]), set(&["b", "c"])]);
    assert_eq!(homes.len(), 1, "{homes:?}");
    assert_eq!(out.len(), 2, "{out:#?}");
    // Two cycles that changed only one cell's databases share no home.
    let (homes, out) = homes_of(&[set(&["a"]), set(&["a"])]);
    assert_eq!(homes, BTreeMap::from([(0u8, "a".to_owned())]));
    assert_eq!(out.len(), 1, "{out:#?}");
    // Two cycles that each changed the same two cells have no home.
    let (homes, out) = homes_of(&[set(&["a", "b"]), set(&["a", "b"])]);
    assert!(homes.is_empty(), "{homes:?}");
    assert_eq!(out.len(), 2, "{out:#?}");
}

/// I-19 teeth, design sections 2.5 and 9.6: a background task of cell 1
/// that writes its database during cell 0's cycle, and one of cell 0 that
/// writes during cell 2's cycle, leave every cell its own home.
#[test]
fn t_iso_i19_teeth_background_write_during_another_cycle_keeps_the_homes() {
    let set =
        |hexes: &[&str]| -> BTreeSet<String> { hexes.iter().map(|h| (*h).to_owned()).collect() };
    let (homes, out) = homes_of(&[set(&["a", "b"]), set(&["b"]), set(&["a", "c"])]);
    assert!(out.is_empty(), "{out:#?}");
    assert_eq!(
        homes,
        BTreeMap::from([
            (0u8, "a".to_owned()),
            (1u8, "b".to_owned()),
            (2u8, "c".to_owned()),
        ])
    );
}
