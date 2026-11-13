//! The I-80 root needles of a world and the `erase-text` cycle step
//! (design sections 3.5 and 14.4, lane F-ERASE).
//!
//! `World::root_needles` is what the I-80 scans of `i80_custody.rs` look
//! for, the Linux memory scans included. This file exercises it on every
//! platform: a started cell holds the root of its epoch 0, and an
//! `erase-text` batch creates the root of the next epoch and destroys the
//! old one, whose needle stays.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_celltest::scan::scan_bytes;
use fstp_celltest::world::{CycleScript, DbMode, VaultLayout, World, WorldSpec};

/// I-80, design section 3.5: one needle per root the world custody made,
/// before and after a text erasure. A scan of every store of the world
/// after the erasure finds none of them.
#[test]
fn harness_i80_root_needles_cover_every_root_through_an_erasure() {
    let world = World::start(WorldSpec {
        cells: 1,
        mode: DbMode::Shared,
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted: false,
        process_mode: false,
    })
    .unwrap_or_else(|e| panic!("{e}"));
    let before = world.root_needles();
    assert!(!before.is_empty(), "the started cell made no root");
    let script = CycleScript {
        steps: ["login", "erase-text"].map(str::to_owned).to_vec(),
    };
    if let Err(e) = world.run_cycle(0, &script).result {
        panic!("{e}");
    }
    let after = world.root_needles();
    assert!(
        after.len() > before.len(),
        "the erasure made no new root: {} before, {} after",
        before.len(),
        after.len()
    );
    let report = scan_bytes(&world.stores().unwrap(), &after).unwrap();
    assert!(report.is_clean(), "{report:?}");
}
