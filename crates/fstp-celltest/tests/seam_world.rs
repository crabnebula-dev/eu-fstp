//! The M2 seams of design section 14.6 that need a running cell: the async
//! engine over PostgreSQL and the real vault, the M2 suites over the real
//! stack, and NOTE 6.
//!
//! Lane W1c wrote these tests before the production code. Each starts a
//! one-cell world and is red until the cell runtime of lane W3a exists.
//!
//! `CycleScript` names steps by text only, so the scripts below name the
//! M2 generators and suites by label. `fstp_celltest::cycle` reads those
//! labels (lane F-CYCLE2), and `CellHandle::ledger` gives the decrypted
//! ledger.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_celltest::NotImplemented;
use fstp_celltest::canary::{Canary, CanaryKind};
use fstp_celltest::m2_http::masked;
use fstp_celltest::mc::driver_model::paths;
use fstp_celltest::scan::{StoreSet, scan};
use fstp_celltest::world::{CycleScript, DbMode, VaultLayout, World, WorldSpec};
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::review::run_records;
use fstp_domain_testkit::scenario::Scenario;

fn one_cell_world() -> World {
    World::start(WorldSpec {
        cells: 1,
        mode: DbMode::Shared,
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted: false,
        process_mode: false,
    })
    .unwrap_or_else(|e| panic!("the one-cell world did not start: {e}"))
}

/// The refusal of the ledger read: the world holds no cell 0, or its
/// ledger cannot be read. `CellHandle::ledger` closed the former seam
/// (lane F-CYCLE2 wired it).
const LEDGER_READ_SEAM: &str =
    "fstp_celltest::world::CellHandle::ledger of cell 0 could not be read";

/// The M2 core records in cell 0's ledger, after decryption, in order.
fn cell_core_records(world: &World) -> Result<Vec<fstp_domain::Record>, NotImplemented> {
    let cell = world.cell(0).ok_or(NotImplemented::new(LEDGER_READ_SEAM))?;
    let ledger = cell
        .ledger()
        .map_err(|_| NotImplemented::new(LEDGER_READ_SEAM))?;
    Ok(ledger
        .into_iter()
        .filter_map(|e| match e.record {
            fstp_cell_core::CellRecord::Engine(fstp_engine::Record::Core(r)) => Some(r),
            _ => None,
        })
        .collect())
}

/// Design section 14.6: the M2 generators run through
/// `fstp_engine::Engine<MemStore, SyntheticVault>` and through `CellEngine`
/// with `PgRecordStore` and `fstp-vault`, seeded from the same ground
/// truth. The ledgers are equal record for record after decryption, with
/// the vault's digests and epochs left out: Daniel decided on 2026-11-13
/// (M3 exit audit, section 7, item 15) that comparisons against the real
/// vault leave them out. Every other field is compared.
#[test]
fn seam_async_engine_matches_reference_over_pg_and_real_vault() {
    let world = one_cell_world();
    let path = paths::to(StateTag::Negotiation).unwrap();
    let mut engine = Scenario::new(paths::truth(true)).unwrap();
    let mut want = Vec::new();
    for p in &path {
        if let Ok(records) = run_records(&mut engine, &p.step, p.at).unwrap() {
            want.extend(records);
        }
    }
    let script = CycleScript {
        steps: vec![
            "seed:ground-truth:life-setup-adult".to_owned(),
            "m2:path-to-negotiation".to_owned(),
        ],
    };
    world
        .run_cycle(0, &script)
        .result
        .unwrap_or_else(|e| panic!("the cycle did not run: {e}"));
    let got = cell_core_records(&world).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        masked(&got),
        masked(&want),
        "the cell ledger differs from the M2 engine's"
    );
}

/// Runs the reduced case of the M2 suite of invariant `suite` over the
/// real stack (design section 14.6, `seam_m2_suites_over_pg`).
fn m2_suite_over_pg(suite: &str) {
    let world = one_cell_world();
    let script = CycleScript {
        steps: vec![format!("m2-suite:{suite}:reduced")],
    };
    world
        .run_cycle(0, &script)
        .result
        .unwrap_or_else(|e| panic!("the {suite} suite did not run: {e}"));
}

/// I-03, design section 14.6 (`seam_m2_suites_over_pg`): the reduced I-03
/// machine over the real stack. Its reviewer facts come through the
/// section 6.8 write kinds, seeded by section 6.9.
#[test]
fn seam_m2_i03_suite_over_pg() {
    m2_suite_over_pg("I-03");
}

/// I-04, design section 14.6 (`seam_m2_suites_over_pg`): the reduced I-04
/// machine over the real stack. Its partner facts come through the
/// section 6.8 write kinds, seeded by section 6.9.
#[test]
fn seam_m2_i04_suite_over_pg() {
    m2_suite_over_pg("I-04");
}

/// I-06, design section 14.6 (`seam_m2_suites_over_pg`): the reduced I-06
/// machine over the real stack.
#[test]
fn seam_m2_i06_suite_over_pg() {
    m2_suite_over_pg("I-06");
}

/// I-13, design section 14.6 (`seam_m2_suites_over_pg`): the reduced I-13
/// machine over the real stack.
#[test]
fn seam_m2_i13_suite_over_pg() {
    m2_suite_over_pg("I-13");
}

/// I-14, design section 14.6 (`seam_m2_suites_over_pg`): the reduced I-14
/// machine over the real stack.
#[test]
fn seam_m2_i14_suite_over_pg() {
    m2_suite_over_pg("I-14");
}

/// I-15, design section 14.6 (`seam_m2_suites_over_pg`): the reduced I-15
/// machine over the real stack.
#[test]
fn seam_m2_i15_suite_over_pg() {
    m2_suite_over_pg("I-15");
}

/// I-23, design section 14.6 (`seam_m2_suites_over_pg`): the reduced I-23
/// machine over the real stack.
#[test]
fn seam_m2_i23_suite_over_pg() {
    m2_suite_over_pg("I-23");
}

/// I-35, design section 14.6 (`seam_m2_suites_over_pg`): the reduced I-35
/// machine over the real stack. Its proximity facts come through the
/// section 6.8 write kinds, seeded by section 6.9.
#[test]
fn seam_m2_i35_suite_over_pg() {
    m2_suite_over_pg("I-35");
}

/// NOTE 6: the P-17 country reaches only the vault. A country canary
/// written on the vault origin is found in no store and no egress capture
/// outside the vault cluster. Inside it the country is sealed (R-NF-08),
/// so no vault store holds it in clear either.
#[test]
fn seam_note6_country_reaches_only_the_vault() {
    let world = one_cell_world();
    let country = Canary::generate(0, CanaryKind::Country).unwrap();
    let script = CycleScript {
        steps: vec![
            "m2:path-to-submitted".to_owned(),
            format!("vault-origin:write:country_stated:{}", country.text()),
            "m2:path-to-ranked-with-tie".to_owned(),
        ],
    };
    world
        .run_cycle(0, &script)
        .result
        .unwrap_or_else(|e| panic!("the cycle did not run: {e}"));
    let mut stores = StoreSet::default();
    for (name, bytes) in world.stores().unwrap().stores {
        stores.push(name, bytes);
    }
    let report = scan(&stores, std::slice::from_ref(&country)).unwrap();
    assert!(
        report.is_clean(),
        "NOTE 6: the country canary was found: {:?}",
        report.hits
    );
}
