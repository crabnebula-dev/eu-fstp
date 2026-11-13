//! R-ID-03: uploaded identity documents are deleted within P-19 after
//! verification, including from backups. AC: after verification, no
//! backup or replica can reproduce the document (design sections 3.6 and
//! 14.4, I-81).
//!
//! Lane W1d wrote these tests before the production code. They are red
//! until `fstp_keys::erasure` (lane W2f), the vault (lane W2d), the backup
//! agent (lane W2k) and the cell runtime (lane W3a) land.
//!
//! ADR-012 leaves open how a Vault chain snapshot is verified. Until that
//! is decided, no Vault chain rotation passes step 5, so the world test
//! stays red after the other lanes land, as ADR-012 says.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::BTreeSet;

use fstp_celltest::canary::{Canary, CanaryKind};
use fstp_celltest::mc::shred_model::{
    Production, Reference, ShredAction, ShredBackend, ShredModel, breaches, drain, walk,
};
use fstp_celltest::reference::keys::Layout;
use fstp_celltest::scan::{StoreSet, scan};
use fstp_celltest::world::{CycleScript, DbMode, VaultLayout, World, WorldSpec};

fn production() -> Production {
    Production::new().unwrap_or_else(|e| panic!("M-SHRED production backend: {e} (NotImplemented)"))
}

/// The erasure of the document key, `k0` alone in its `Document` group,
/// with no breach of I-81, no-data-loss or completion-after-receipt on
/// the way, and a completion for `k0` only.
fn document_dies<B: ShredBackend>(backend: B) {
    let m = ShredModel::with(backend, Layout::document(), vec![0]);
    let start = walk(&m, &[ShredAction::Request]).unwrap_or_else(|e| panic!("{e}"));
    let mut states = start.clone();
    states.extend(drain(&m, start.last().unwrap(), 64).unwrap_or_else(|e| panic!("{e}")));
    assert_eq!(breaches(&states, m.layout()), Vec::<String>::new());
    let end = &states.last().unwrap().env;
    assert_eq!(end.erased, BTreeSet::from([0]));
    assert_eq!(end.receipts, BTreeSet::from([1]), "epoch 1 has no receipt");
}

/// R-ID-03, ADR-004 part 2: a document key, alone in its `Document`
/// group, dies with the epoch the verification rotates, and the other
/// vault keys survive. Over production `fstp_keys::erasure`.
#[test]
fn r_id_03_document_key_dies_with_its_epoch() {
    document_dies(production());
}

/// R-ID-03: the reference twin of `r_id_03_document_key_dies_with_its_epoch`.
#[test]
fn r_id_03_document_key_dies_with_its_epoch_on_the_reference() {
    document_dies(Reference);
}

/// The canary document the world uploaded last (`World::uploaded_document`,
/// lane m3/erase-steps).
fn world_document(world: &World) -> Result<Canary, String> {
    let d = world.uploaded_document().map_err(|e| e.to_string())?;
    assert_eq!(d.kind, CanaryKind::Document);
    Ok(d)
}

/// The copies, by name, from which the document opens, the live store
/// among them. `World::document_opens` (lane m3/erase-steps) restores
/// each backup copy and tries the document's wrapped key under every
/// group secret that any key row gives under a live custody key.
fn document_opens(world: &World, document: &Canary) -> Result<Vec<String>, String> {
    world.document_opens(document).map_err(|e| e.to_string())
}

fn cycle(world: &World, steps: &[&str]) {
    let script = CycleScript {
        steps: steps.iter().map(|s| (*s).to_owned()).collect(),
    };
    if let Err(e) = world.run_cycle(0, &script).result {
        panic!("{e} (NotImplemented)");
    }
}

/// R-ID-03 AC, design section 3.6: a document is uploaded to the vault
/// origin, and backups and WAL archives are taken. Before the
/// verification the document opens from at least one copy, so the check
/// that follows tests something. The verification is recorded, and more
/// backups are taken. Then no copy opens the document under any live
/// custody key, and the document's canary bytes are in no store in any
/// encoding.
#[test]
fn r_id_03_document_unrecoverable_after_verification() {
    let world = World::start(WorldSpec {
        cells: 1,
        mode: DbMode::Shared,
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted: false,
        process_mode: false,
    })
    .unwrap_or_else(|e| panic!("{e}"));
    cycle(&world, &["upload-document", "base-backup", "wal-archive"]);
    let document = world_document(&world).unwrap_or_else(|e| panic!("{e}"));
    let before = document_opens(&world, &document).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        !before.is_empty(),
        "the document opens from no copy before verification"
    );
    cycle(
        &world,
        &["record-verification", "base-backup", "wal-archive"],
    );
    let opened = document_opens(&world, &document).unwrap_or_else(|e| panic!("{e}"));
    assert!(opened.is_empty(), "the document opens from {opened:?}");
    let stores: StoreSet = world.stores().unwrap_or_else(|e| panic!("{e}"));
    let report = scan(&stores, &[document]).unwrap();
    assert!(report.is_clean(), "{report:?}");
}
