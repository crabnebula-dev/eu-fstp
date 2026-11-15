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
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_celltest::canary::{Canary, CanaryKind};
use fstp_celltest::m2_http::{builder_binding, compare};
use fstp_celltest::mc::driver_model::paths;
use fstp_celltest::scan::{StoreSet, scan};
use fstp_celltest::world::{CycleScript, DbMode, VaultLayout, World, WorldSpec};
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::activation::{APPROVER, relative_positions};
use fstp_domain_testkit::r#gen::review::run_records;
use fstp_domain_testkit::r#gen::roster::P1;
use fstp_domain_testkit::scenario::Scenario;
use fstp_ledger::Seq;

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

/// The M2 core records of `entries` with their ledger positions and
/// command ids, `GuidePublished` left out (an M4 record, I-52).
fn positioned<R>(
    entries: &[fstp_ledger::Entry<R>],
    core: impl Fn(&R) -> Option<&fstp_domain::Record>,
) -> Vec<(Seq, [u8; 16], fstp_domain::Record)> {
    entries
        .iter()
        .filter_map(|e| core(&e.record).map(|r| (e.seq, e.command, r.clone())))
        .filter(|(_, _, r)| !matches!(r, fstp_domain::Record::GuidePublished { .. }))
        .collect()
}

/// Splits `records` after the set-up, whose last entry holds the last
/// record `ends` admits. Returns the head at the scenario start, the
/// set-up's records and the scenario's records.
fn after_setup(
    records: Vec<(Seq, [u8; 16], fstp_domain::Record)>,
    ends: impl Fn(&fstp_domain::Record) -> bool,
) -> Result<(Seq, Vec<fstp_domain::Record>, Vec<fstp_domain::Record>), String> {
    let activation = records
        .iter()
        .rposition(|(_, _, r)| ends(r))
        .ok_or("no record ends the set-up")?;
    let command = records[activation].1;
    let end = records[activation..]
        .iter()
        .position(|(_, c, _)| *c != command)
        .map_or(records.len(), |n| activation + n);
    let start = records[end - 1].0;
    let (setup, scenario) = records.split_at(end);
    let strip = |rs: &[(Seq, [u8; 16], fstp_domain::Record)]| {
        rs.iter().map(|(_, _, r)| r.clone()).collect::<Vec<_>>()
    };
    Ok((start, strip(setup), strip(scenario)))
}

/// Design section 14.6: the M2 generators run through
/// `fstp_engine::Engine<MemStore, SyntheticVault>` and through `CellEngine`
/// with `PgRecordStore` and `fstp-vault`, seeded from the same ground
/// truth. The vault's digests and epochs are left out: Daniel decided on
/// 2026-11-13 (M3 exit audit, section 7, item 15) that comparisons against
/// the real vault leave them out. Every other field is compared.
///
/// Daniel's decision of 2026-11-15 ("Compare after set-up"): each side's
/// set-up is checked on its own. The cell's set-up seeds the vault and
/// runs the creator path up to the end of the harness builder's binding.
/// The engine's runs the test kit's composed entries up to the
/// activation. The scenario after it is
/// compared record for record, with ledger positions relative to each
/// side's start, and with the cell's extra vault answers split off as
/// `fstp_celltest::m2_http` splits them: `fstp-vault` lists every account
/// of a changed person as changed. As there, the engine's draft is
/// minor-flagged, since the cell flags every draft (Q13, interim).
#[test]
fn seam_async_engine_matches_reference_over_pg_and_real_vault() {
    let world = one_cell_world();
    let path = paths::to(StateTag::Negotiation).unwrap();
    let mut engine = Scenario::new(paths::truth(true)).unwrap();
    for (i, p) in path.iter().enumerate() {
        // The cell flags every draft (I-18, interim reading of Q13), so the
        // engine's draft is minor-flagged too, as `m2_http` rewrites a
        // machine's drafts.
        let mut step = p.step.clone();
        if let fstp_domain::Command::CreateDraft { minor, .. } = &mut step.cmd {
            *minor = true;
        }
        if let Err(r) = run_records(&mut engine, &step, p.at).unwrap() {
            panic!(
                "path step {i} {:?} refused by the engine: {r}",
                p.step.cmd.kind()
            );
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
    let cell = world
        .cell(0)
        .unwrap_or_else(|| panic!("{LEDGER_READ_SEAM}"))
        .ledger()
        .unwrap_or_else(|_| panic!("{LEDGER_READ_SEAM}"));
    let cell = positioned(&cell, |r| match r {
        fstp_cell_core::CellRecord::Engine(fstp_engine::Record::Core(c)) => Some(c),
        _ => None,
    });
    let want = positioned(&engine.entries().unwrap(), |r| match r {
        fstp_engine::Record::Core(c) => Some(c),
        _ => None,
    });
    // The cell's set-up ends when the first admin ends the harness
    // builder's binding (`fstp_celltest::m2_http`), the engine's with the
    // composed activation entry (`fstp_domain_testkit::activation`).
    let builder = builder_binding(P1);
    let (cell_start, cell_setup, cell_scenario) = after_setup(
        cell,
        |r| matches!(r, fstp_domain::Record::BindingEnded(e) if e.binding == builder),
    )
    .unwrap();
    let (engine_start, engine_setup, engine_scenario) = after_setup(
        want,
        |r| matches!(r, fstp_domain::Record::ProgrammeActivated(a) if a.programme() == P1),
    )
    .unwrap();
    // Each set-up on its own: it ends with the activation of P1 by the
    // setup's approver.
    for (side, setup) in [("cell", &cell_setup), ("engine", &engine_setup)] {
        let approved = setup.iter().any(|r| {
            matches!(r, fstp_domain::Record::ProgrammeActivated(a)
                if a.programme() == P1 && a.approver() == APPROVER)
        });
        assert!(
            approved,
            "the {side} set-up does not activate P1 by {APPROVER:?}"
        );
    }
    let cell_scenario = relative_positions(&cell_scenario, cell_start).unwrap();
    let engine_scenario = relative_positions(&engine_scenario, engine_start).unwrap();
    assert!(!engine_scenario.is_empty(), "the scenario appended nothing");
    compare(
        "the scenario after set-up",
        &engine_scenario,
        &cell_scenario,
    )
    .unwrap_or_else(|e| panic!("{e}"));
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
