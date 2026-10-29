//! T-ISO for I-20: the platform stores no link between tenant accounts in
//! different tenants (design section 14.4).
//!
//! One synthetic person joins cells A and B with the same email address,
//! the same authenticator seed, the same client address and the same
//! identity attributes. The identifiers of each cell are then compared:
//! every store of the cell's own databases, the egress captures the cell
//! and its vault sent, and what the shared infrastructure stored during
//! that cell's cycle. Only the public constants that two fresh cells of
//! one build share may appear in both.
//!
//! The shared infrastructure is every store outside every cell
//! (`db::outside_stores`): shared cluster files such as WAL and server
//! logs, the control plane, the witness and egress captures of shared
//! components. What it stored during a cycle is the change of its stores
//! over that cycle ([`delta`]). A link that the control plane keeps once
//! per cell, such as a digest of the shared email under a global key,
//! therefore shows in both cells' identifiers.
//!
//! Gap, reported by lane W1f: `CycleScript` steps are names whose meaning
//! lane W3b defines. The steps here carry each value as `<kind>:<text>`
//! and the authenticator seed as `authenticator:<hex>`.
//!
//! Lane W1f wrote this test before the production code. It is red until
//! the cell runtime (lane W3a) and the slice runner (lane W3b) land.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::{BTreeMap, BTreeSet};

use fstp_celltest::canary::{CanaryKind, generate_set};
use fstp_celltest::mc::place_model::db::{match_homes, outside_stores, stores_by_cell};
use fstp_celltest::scan::{CellDump, PublicConstants, StoreSet, shared_identifiers};
use fstp_celltest::world::{CycleScript, DbMode, VaultLayout, World, WorldSpec};

/// The stores of `w` and its databases.
fn snapshot(w: &World) -> (StoreSet, Vec<fstp_celltest::world::WorldDatabase>) {
    (w.stores().unwrap(), w.databases().unwrap())
}

/// The two cells' database stores, in hex order, with their hexes.
fn two_cells(
    stores: &StoreSet,
    dbs: &[fstp_celltest::world::WorldDatabase],
) -> [(String, StoreSet); 2] {
    let by = stores_by_cell(stores, dbs);
    assert_eq!(by.len(), 2, "expected two cells, found {:?}", by.keys());
    let mut it = by.into_iter();
    [it.next().unwrap(), it.next().unwrap()]
}

/// The cell index of an egress store sent by a cell or its vault, from
/// its name `egress/<from>/...`, where `<from>` is `cell-<i>` or
/// `vault-<i>`.
fn egress_cell(name: &str) -> Option<u8> {
    let from = name.strip_prefix("egress/")?.split('/').next()?;
    let (kind, i) = from.rsplit_once('-')?;
    matches!(kind, "cell" | "vault")
        .then(|| i.parse().ok())
        .flatten()
}

/// What changed in the stores from `before` to `after`: a new store
/// whole, the new lines of a logical dump, the appended bytes of a store
/// that grew, and every other changed store whole.
fn delta(before: &StoreSet, after: &StoreSet) -> StoreSet {
    let old: BTreeMap<&str, &Vec<u8>> =
        before.stores.iter().map(|(n, b)| (n.as_str(), b)).collect();
    let mut out = StoreSet::default();
    for (name, bytes) in &after.stores {
        let Some(prev) = old.get(name.as_str()) else {
            out.push(name.clone(), bytes.clone());
            continue;
        };
        if *prev == bytes {
            continue;
        }
        if name.contains("/dump/") {
            let mut seen: BTreeMap<&[u8], usize> = BTreeMap::new();
            for l in prev.split(|b| *b == b'\n') {
                *seen.entry(l).or_default() += 1;
            }
            let mut new = Vec::new();
            for l in bytes.split(|b| *b == b'\n') {
                match seen.get_mut(l) {
                    Some(n) if *n > 0 => *n -= 1,
                    _ => {
                        new.extend_from_slice(l);
                        new.push(b'\n');
                    }
                }
            }
            out.push(name.clone(), new);
        } else if let Some(tail) = bytes.strip_prefix(prev.as_slice()) {
            out.push(name.clone(), tail.to_vec());
        } else {
            out.push(name.clone(), bytes.clone());
        }
    }
    out
}

/// The shared stores of a snapshot that no cell sent, and the egress
/// stores cell `i` or its vault sent.
fn split_outside(outside: &StoreSet) -> (StoreSet, BTreeMap<u8, StoreSet>) {
    let mut shared = StoreSet::default();
    let mut by_cell: BTreeMap<u8, StoreSet> = BTreeMap::new();
    for (name, bytes) in &outside.stores {
        match egress_cell(name) {
            Some(i) => by_cell
                .entry(i)
                .or_default()
                .push(name.clone(), bytes.clone()),
            None => shared.push(name.clone(), bytes.clone()),
        }
    }
    (shared, by_cell)
}

/// A settled read of `w`: the stores are read twice, so that the second
/// read holds what the first read caused, such as WAL records of hint
/// bits that a dump set. Returns the shared stores that no cell sent, and
/// the identifiers of each cell's databases by hex.
fn settled(w: &World) -> (StoreSet, BTreeMap<String, CellDump>) {
    let _ = snapshot(w);
    let (stores, dbs) = snapshot(w);
    let shared = split_outside(&outside_stores(&stores, &dbs)).0;
    let cells = stores_by_cell(&stores, &dbs)
        .into_iter()
        .map(|(hex, s)| (hex, CellDump::from_stores(&s)))
        .collect();
    (shared, cells)
}

/// The hexes of the cells whose database identifiers changed from
/// `before` to `after`.
fn changed_cells(
    before: &BTreeMap<String, CellDump>,
    after: &BTreeMap<String, CellDump>,
) -> BTreeSet<String> {
    after
        .iter()
        .filter(|(hex, d)| before.get(*hex) != Some(*d))
        .map(|(hex, _)| hex.clone())
        .collect()
}

/// Per cycle's cell hex: the cycle's index and its delta of `deltas`.
/// Each cycle's cell is its home by the rule of `db::match_homes`, which
/// tolerates a background write of another cell during a cycle. A cycle
/// without a home is an error, since its cell is unknown or its values
/// never reached it, and the comparison would be vacuous.
fn cycle_cells(
    changes: &[BTreeSet<String>],
    deltas: Vec<StoreSet>,
) -> Result<BTreeMap<String, (u8, StoreSet)>, String> {
    let homes = match_homes(changes);
    let mut out = BTreeMap::new();
    for (i, d) in deltas.into_iter().enumerate() {
        let hex = homes.get(&i).ok_or_else(|| {
            format!(
                "the cycle of cell {i} changed the databases of {:?}, and no one of them is \
                 its own, so its cell is unknown or its values never reached it and the \
                 comparison would be vacuous",
                changes.get(i)
            )
        })?;
        let cell = u8::try_from(i).map_err(|e| e.to_string())?;
        out.insert(hex.clone(), (cell, d));
    }
    Ok(out)
}

/// I-20 teeth for the cycle cells: a background write of cell B during
/// cell A's cycle still gives each cycle its own cell. Two cycles that
/// changed only one cell are refused.
#[test]
fn t_iso_i20_teeth_cycle_cells_tolerate_a_background_write() {
    let set = |h: &[&str]| -> BTreeSet<String> { h.iter().map(|x| (*x).to_owned()).collect() };
    let two = || vec![StoreSet::default(), StoreSet::default()];
    let got = cycle_cells(&[set(&["a", "b"]), set(&["b"])], two()).unwrap();
    let cells: BTreeMap<&str, u8> = got.iter().map(|(h, (i, _))| (h.as_str(), *i)).collect();
    assert_eq!(cells, BTreeMap::from([("a", 0u8), ("b", 1u8)]));
    assert!(cycle_cells(&[set(&["a"]), set(&["a"])], two()).is_err());
    assert!(cycle_cells(&[set(&["a"]), set(&[])], two()).is_err());
}

/// I-20, T-ISO: the same person in two tenants leaves no shared identifier
/// beyond the public constants of two fresh cells, over the cells' own
/// stores and the shared infrastructure.
#[test]
fn t_iso_i20_no_shared_identifier_across_tenants() {
    let w = World::start(WorldSpec {
        cells: 2,
        mode: DbMode::Shared,
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted: false,
        process_mode: false,
    })
    .unwrap_or_else(|e| panic!("the world did not start: {e}"));
    let (stores, dbs) = snapshot(&w);
    let [(hex_a, fresh_a), (hex_b, fresh_b)] = two_cells(&stores, &dbs);
    let (fresh_shared, fresh_cells) = settled(&w);
    // Allowed: what two fresh cells share, what the shared infrastructure
    // held before any account existed, and each cell's own random id,
    // which names a cell and no account.
    let mut public = PublicConstants::baseline(
        &CellDump::from_stores(&fresh_a),
        &CellDump::from_stores(&fresh_b),
    );
    public
        .values
        .extend(CellDump::from_stores(&fresh_shared).identifiers);
    for hex in [&hex_a, &hex_b] {
        public.values.insert(
            (0..16)
                .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
                .collect(),
        );
    }
    // One person: the same canaries in both cells.
    let person = generate_set(0).unwrap();
    let mut seed = [0u8; 16];
    fstp_crypto::random_bytes(&mut seed).unwrap();
    let mut steps = vec!["signup".to_owned()];
    steps.extend(
        person
            .iter()
            .filter(|c| {
                matches!(
                    c.kind,
                    CanaryKind::Name
                        | CanaryKind::Email
                        | CanaryKind::Phone
                        | CanaryKind::Country
                        | CanaryKind::Document
                        | CanaryKind::IpAddress
                )
            })
            .map(|c| format!("{}:{}", c.kind.label(), c.text())),
    );
    steps.push(format!(
        "authenticator:{}",
        fstp_celltest::mc::place_model::cell_hex(fstp_cp_proto::CellId(seed))
    ));
    steps.extend(["verify-identity", "submit-proposal"].map(str::to_owned));
    let script = CycleScript { steps };
    // Per cycle: the cell it wrote to, and what the shared infrastructure
    // stored meanwhile.
    let mut changes = Vec::new();
    let mut deltas = Vec::new();
    let (mut before, mut before_cells) = (fresh_shared, fresh_cells);
    for i in 0..2 {
        w.run_cycle(i, &script)
            .result
            .unwrap_or_else(|e| panic!("the cycle of cell {i} did not run: {e}"));
        let (after, after_cells) = settled(&w);
        changes.push(changed_cells(&before_cells, &after_cells));
        deltas.push(delta(&before, &after));
        (before, before_cells) = (after, after_cells);
    }
    let during = cycle_cells(&changes, deltas).unwrap_or_else(|e| panic!("{e}"));
    let (stores, dbs) = snapshot(&w);
    let sent = split_outside(&outside_stores(&stores, &dbs)).1;
    let dump = |hex: &str, own: StoreSet| {
        let (i, shared) = &during[hex];
        let mut all = own;
        if let Some(s) = sent.get(i) {
            all.stores.extend(s.stores.clone());
        }
        all.stores.extend(shared.stores.clone());
        CellDump::from_stores(&all)
    };
    let [(ha, a), (hb, b)] = two_cells(&stores, &dbs);
    let (da, db) = (dump(&ha, a), dump(&hb, b));
    assert!(
        da.identifiers.len() > public.values.len() && db.identifiers.len() > public.values.len(),
        "the cycles wrote no identifier, so the comparison is vacuous"
    );
    let shared = shared_identifiers(&da, &db, &public).unwrap();
    assert!(
        shared.is_empty(),
        "{} identifiers link the two tenants",
        shared.len()
    );
}

/// I-20 teeth: a digest that the control plane stores once per cell, with
/// no copy in either cell's database, is in both cells' shared deltas and
/// is reported. A shared store that only grew by one cell's bytes links
/// nothing.
#[test]
fn t_iso_i20_teeth_link_kept_by_shared_infrastructure_is_caught() {
    let digest = "5f3a9c27e1b04d68a2c7f0193b8e4d52a9f7c1e03b6d8a4f2c9e7b1d0a3f5c8e";
    let fresh = {
        let mut s = StoreSet::default();
        s.push(
            "control/dump/cp",
            b"COPY cp.cell (id) FROM stdin;\n".to_vec(),
        );
        s.push("application/log/server.log", b"start\n".to_vec());
        s
    };
    let mut after_a = StoreSet::default();
    after_a.push(
        "control/dump/cp",
        format!("COPY cp.cell (id) FROM stdin;\n1\t\\\\x{digest}\n").into_bytes(),
    );
    after_a.push(
        "application/log/server.log",
        b"start\nA 0d9b1f3c7e2a4b6d8f0a1c3e5b7d9f1a\n".to_vec(),
    );
    let mut after_b = StoreSet::default();
    after_b.push(
        "control/dump/cp",
        format!("COPY cp.cell (id) FROM stdin;\n1\t\\\\x{digest}\n2\t\\\\x{digest}\n").into_bytes(),
    );
    after_b.push(
        "application/log/server.log",
        b"start\nA 0d9b1f3c7e2a4b6d8f0a1c3e5b7d9f1a\nB 7c2e4a6b8d0f1e3c5a7b9d1f3e5c7a9b\n".to_vec(),
    );
    let (da, db) = (
        CellDump::from_stores(&delta(&fresh, &after_a)),
        CellDump::from_stores(&delta(&after_a, &after_b)),
    );
    let shared = shared_identifiers(&da, &db, &PublicConstants::default()).unwrap();
    assert_eq!(shared.len(), 1, "{shared:?}");
    assert_eq!(egress_cell("egress/cell-1/control-plane/3/out"), Some(1));
    assert_eq!(egress_cell("egress/vault-0/witness/1/out"), Some(0));
    assert_eq!(egress_cell("egress/control-plane/witness/1/out"), None);
}
