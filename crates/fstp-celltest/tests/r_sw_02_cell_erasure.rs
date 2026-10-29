//! R-SW-02: after the retrieval period (P-46), the tenant cell is fully
//! erased and the tenant receives an erasure confirmation. AC: after
//! erasure, no backup or replica can restore the cell (design sections
//! 3.7 and 14.4, I-81, TH-48).
//!
//! Lane W1d wrote these tests before the production code. The world test
//! is red until the control plane's `erase-cell` (lane W2h), the backup
//! agent (lane W2k) and the cell runtime (lane W3a) land. The symbolic
//! tests drive the cell erasure of design section 3.7 through M-SHRED
//! worlds of the cell's three chains, on the reference.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::BTreeSet;

use fstp_celltest::mc::shred_model::{
    Env, REQUESTS, Reference, ShredAction, ShredBackend, ShredModel, drain, walk,
};
use fstp_celltest::reference::keys::{
    CELL_CHAINS, CellCustodyKey, Layout, RefStep, RootId, Row, cell_erasure_destroys, closure,
};
use fstp_celltest::world::{CycleScript, DbMode, VaultLayout, World, WorldSpec};
use fstp_keys::Chain;
use fstp_mc::Model;

/// Every row a copy can hold: written, and in every snapshot.
fn every_row(env: &Env) -> BTreeSet<Row> {
    let mut rows = env.written.clone();
    for s in &env.snapshots {
        rows.extend(s.rows.iter().copied());
    }
    rows
}

/// The App chain: every request of M-SHRED's first order completed.
fn app_chain() -> Env {
    let m = ShredModel::new(Reference);
    let start =
        walk(&m, &vec![ShredAction::Request; REQUESTS.len()]).unwrap_or_else(|e| panic!("{e}"));
    let states = drain(&m, start.last().unwrap(), 128).unwrap_or_else(|e| panic!("{e}"));
    states.last().unwrap().env.clone()
}

/// The world of `m` after `script`, then fault-free steps up to and
/// including the first step that `stop` accepts.
fn steps_until(
    m: &ShredModel<Reference>,
    script: &[ShredAction],
    stop: impl Fn(&RefStep) -> bool,
) -> Env {
    let start = walk(m, script).unwrap_or_else(|e| panic!("{e}"));
    let mut s = start.last().unwrap().clone();
    loop {
        let step = m
            .backend()
            .next(s.plan.as_ref().unwrap())
            .unwrap()
            .expect("the run ended before the stop step");
        s = m
            .step(&s, &ShredAction::Step)
            .expect("the step could not run");
        if stop(&step) {
            return s.env;
        }
    }
}

/// The Vault chain caught mid-rotation: the document key's erasure has
/// committed epoch 2, and epoch 1 is not destroyed yet. Both epochs live.
fn vault_chain() -> Env {
    let m = ShredModel::with(Reference, Layout::document(), vec![0]);
    steps_until(&m, &[ShredAction::Request], |s| {
        matches!(s, RefStep::Commit(_))
    })
}

/// The CellBackup chain with an orphan root: a crash right after the
/// custody call of `NewEpoch(2)`, then the resumed run to completion. The
/// orphan of epoch 2 lives beside the committed root of epoch 2.
fn backup_chain() -> Env {
    let m = ShredModel::new(Reference);
    let start = walk(&m, &[ShredAction::Request]).unwrap_or_else(|e| panic!("{e}"));
    let mut s = start.last().unwrap().clone();
    loop {
        let step = m.backend().next(s.plan.as_ref().unwrap()).unwrap().unwrap();
        if matches!(step, RefStep::NewEpoch(_)) {
            s = m.step(&s, &ShredAction::StepThenCrash).unwrap();
            break;
        }
        s = m.step(&s, &ShredAction::Step).unwrap();
    }
    drain(&m, &s, 64)
        .unwrap_or_else(|e| panic!("{e}"))
        .last()
        .unwrap()
        .env
        .clone()
}

/// The three chains of one cell.
fn cell() -> Vec<(Chain, Env)> {
    vec![
        (Chain::App, app_chain()),
        (Chain::Vault, vault_chain()),
        (Chain::CellBackup, backup_chain()),
    ]
}

/// The live roots of each chain, as custody would list them.
fn live(chains: &[(Chain, Env)]) -> Vec<(Chain, BTreeSet<RootId>)> {
    chains.iter().map(|(c, e)| (*c, e.live_roots())).collect()
}

/// Destroys `keys` in custody: each named root of its chain dies.
fn destroy(chains: &mut [(Chain, Env)], keys: &BTreeSet<CellCustodyKey>) {
    for key in keys {
        if let CellCustodyKey::Root { chain, root } = key {
            for (c, env) in chains.iter_mut() {
                if c == chain {
                    env.roots[usize::from(*root)].alive = false;
                }
            }
        }
    }
}

/// What still opens in each chain, from every row of every copy under
/// the roots that are left alive.
fn still_open(chains: &[(Chain, Env)]) -> Vec<String> {
    let mut out = Vec::new();
    for (chain, env) in chains {
        let opened = closure(every_row(env).iter(), &env.live_roots());
        if !opened.deks.is_empty() || !opened.secrets.is_empty() || !opened.seal_keys.is_empty() {
            out.push(format!("{chain:?}: {opened:?}"));
        }
    }
    out
}

/// R-SW-02, design section 3.7 step 1 and ADR-004 part 2: the cell
/// erasure destroys the custody keys the reference lists for the cell's
/// three chains. One chain is caught mid-rotation with two live epochs,
/// and one holds the orphan root of a crashed rotation. After the destroy,
/// no row of any copy opens any key of any chain.
#[test]
fn r_sw_02_cell_erasure_leaves_nothing_openable() {
    let mut chains = cell();
    assert!(
        still_open(&chains).len() == chains.len(),
        "some chain opens nothing before the erasure: the check below tests nothing"
    );
    let keys = cell_erasure_destroys(&live(&chains));
    destroy(&mut chains, &keys);
    assert_eq!(still_open(&chains), Vec::<String>::new());
}

/// R-SW-02 teeth: a cell erasure that skips the CellBackup chain leaves
/// that chain's keys openable from its copies.
#[test]
fn r_sw_02_teeth_skipped_chain_keeps_keys_openable() {
    let mut chains = cell();
    let partial: Vec<(Chain, BTreeSet<RootId>)> = live(&chains)
        .into_iter()
        .filter(|(c, _)| *c != Chain::CellBackup)
        .collect();
    destroy(&mut chains, &cell_erasure_destroys(&partial));
    let open = still_open(&chains);
    assert!(
        open.len() == 1 && open[0].starts_with("CellBackup"),
        "{open:?}"
    );
}

/// R-SW-02 teeth: a cell erasure that destroys only each chain's
/// committed epoch, not every live root epoch, leaves the mid-rotation
/// chain's old epoch alive, and its keys open from the copies.
#[test]
fn r_sw_02_teeth_committed_epoch_only_keeps_keys_openable() {
    let mut chains = cell();
    let committed: Vec<(Chain, BTreeSet<RootId>)> = chains
        .iter()
        .map(|(c, env)| {
            let roots = env
                .live_roots()
                .into_iter()
                .filter(|r| env.roots[usize::from(*r)].epoch == env.epoch)
                .collect();
            (*c, roots)
        })
        .collect();
    destroy(&mut chains, &cell_erasure_destroys(&committed));
    let open = still_open(&chains);
    assert!(open.iter().any(|o| o.starts_with("Vault")), "{open:?}");
}

/// R-SW-02, ADR-004 part 2 "CA keys in custody": the reference destroy
/// list is the cell CA key and every live root of the App, Vault and
/// CellBackup chains, both epochs of a chain mid-rotation and an orphan
/// root included. A root of another chain is never listed. A self-check
/// of the reference, which the world test below compares against.
#[test]
fn r_sw_02_reference_destroy_list_is_the_ca_key_and_every_live_root() {
    let chains = cell();
    let mut roots = live(&chains);
    let vault = &roots[1].1;
    let backup = &roots[2].1;
    assert!(
        vault.len() >= 2,
        "the Vault chain is not mid-rotation: {vault:?}"
    );
    assert!(
        backup.len() >= 2,
        "the CellBackup chain holds no orphan: {backup:?}"
    );
    roots.push((Chain::ClusterBackup, BTreeSet::from([0])));
    let keys = cell_erasure_destroys(&roots);
    let mut expected = BTreeSet::from([CellCustodyKey::CellCa]);
    for (chain, live) in &roots {
        if CELL_CHAINS.contains(chain) {
            expected.extend(live.iter().map(|root| CellCustodyKey::Root {
                chain: *chain,
                root: *root,
            }));
        }
    }
    assert_eq!(keys, expected);
}

/// The seam of [`restore_cell`]: no harness call restores a cell from
/// one backup copy and reports what opened. Lanes W2k and W3b add it.
const RESTORE_SEAM: &str = "no harness call restores a cell from a backup copy and reports what opened (lanes W2k and W3b)";

/// The objects of cell `cell` that opened after restoring each copy.
fn restore_cell(world: &World, cell: u8) -> Result<Vec<String>, String> {
    let _ = (world, cell);
    Err(RESTORE_SEAM.to_owned())
}

/// One custody key of a cell, as the custody simulator lists it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct LiveKey {
    /// The chain of a root, or `None` for the cell CA key.
    chain: Option<Chain>,
    /// The custody handle.
    handle: Vec<u8>,
}

/// The seam of [`live_cell_keys`]: the world does not list the live
/// custody keys of one cell (every live root of its App, Vault and
/// CellBackup chains, and its cell CA key). Lanes W3a and W3b add it.
const LIVE_KEYS_SEAM: &str = "fstp_celltest::world::World does not list the live custody roots and the cell CA key of one cell (lanes W3a and W3b)";

/// The live custody keys of cell `cell`.
fn live_cell_keys(world: &World, cell: u8) -> Result<BTreeSet<LiveKey>, String> {
    let _ = (world, cell);
    Err(LIVE_KEYS_SEAM.to_owned())
}

/// The seam of [`erasure_confirmation`]: the world does not expose the
/// erasure confirmation the control plane issues (design section 3.7
/// step 4). Lanes W2h and W3b add it.
const CONFIRMATION_SEAM: &str =
    "fstp_celltest::world::World does not expose the cell erasure confirmation (lanes W2h and W3b)";

/// The confirmation's custody receipts, as the handle each one names, and
/// whether its composite signature verifies under the control plane's
/// key.
fn erasure_confirmation(world: &World, cell: u8) -> Result<(Vec<Vec<u8>>, bool), String> {
    let _ = (world, cell);
    Err(CONFIRMATION_SEAM.to_owned())
}

/// R-SW-02 AC, design section 3.7: backups and WAL archives of two cells
/// sharing clusters are taken, and then `fstp-control erase-cell` erases
/// cell 0. No copy restores any object of cell 0, while every copy still
/// restores cell 1. ADR-004 part 2: the confirmation lists one destroy
/// receipt for each custody key cell 0 held, the cell CA key and every
/// live root of its App, Vault and CellBackup chains, and no other. Its
/// signature verifies, and cell 1 keeps every key.
#[test]
fn r_sw_02_cell_erasure_kills_every_backup() {
    let world = World::start(WorldSpec {
        cells: 2,
        mode: DbMode::Shared,
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted: false,
        process_mode: false,
    })
    .unwrap_or_else(|e| panic!("{e}"));
    let steps = |s: &[&str]| CycleScript {
        steps: s.iter().map(|x| (*x).to_owned()).collect(),
    };
    for cell in 0..2 {
        let report = world.run_cycle(
            cell,
            &steps(&[
                "call-cycle",
                "base-backup",
                "wal-archive",
                "keystore-snapshot",
            ]),
        );
        if let Err(e) = report.result {
            panic!("cell {cell}: {e} (NotImplemented)");
        }
    }
    let before = live_cell_keys(&world, 0).unwrap_or_else(|e| panic!("{e}"));
    let other = live_cell_keys(&world, 1).unwrap_or_else(|e| panic!("{e}"));
    let kinds: BTreeSet<Option<Chain>> = before.iter().map(|k| k.chain).collect();
    let mut needed: BTreeSet<Option<Chain>> = CELL_CHAINS.iter().map(|c| Some(*c)).collect();
    needed.insert(None);
    assert_eq!(
        kinds, needed,
        "cell 0 does not hold the CA key and a root of each chain"
    );
    if let Err(e) = world.run_cycle(0, &steps(&["erase-cell"])).result {
        panic!("erase-cell: {e} (NotImplemented)");
    }
    let opened = restore_cell(&world, 0).unwrap_or_else(|e| panic!("{e}"));
    assert!(opened.is_empty(), "cell 0 restores {opened:?}");
    let still = restore_cell(&world, 1).unwrap_or_else(|e| panic!("{e}"));
    assert!(!still.is_empty(), "cell 1 no longer restores");
    let (receipts, signed) = erasure_confirmation(&world, 0).unwrap_or_else(|e| panic!("{e}"));
    assert!(signed, "the erasure confirmation does not verify");
    let named: BTreeSet<Vec<u8>> = receipts.iter().cloned().collect();
    assert_eq!(named.len(), receipts.len(), "a receipt is listed twice");
    let held: BTreeSet<Vec<u8>> = before.iter().map(|k| k.handle.clone()).collect();
    assert_eq!(
        named, held,
        "the receipts are not exactly the keys cell 0 held"
    );
    let after = live_cell_keys(&world, 0).unwrap_or_else(|e| panic!("{e}"));
    assert!(after.is_empty(), "cell 0 still holds {after:?}");
    let kept = live_cell_keys(&world, 1).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        kept, other,
        "the erasure of cell 0 changed the keys of cell 1"
    );
}
