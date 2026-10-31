//! Review reproducer (lane m4w1b, I-66, I-67, I-78, D1, D2): the M3 cell gate refuses every `ActivateProgramme`.
//!
//! D2 marks the new kind `high_risk()`. The gate table still maps the
//! activation row to `CreateProgramme` only, so `HighRiskAction::of`
//! fails closed with `Deny::NotPermitted` for `ActivateProgramme`. Since
//! D1 makes every programme a draft until it is activated, no programme
//! in an M3 cell can ever run a call. This test fails until the gate
//! classifies the activation as the `ActivateProgramme` action.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_cell_core::CellCommand;
use fstp_cell_core::gate::{Action, HighRiskAction};
use fstp_domain::id::ProgrammeId;

/// I-78, D2: the activation is classified as a high-risk action that
/// needs a step-up, not refused outright.
#[test]
fn review_i78_activate_programme_is_classified_by_the_gate() {
    let cmd = fstp_domain_testkit::activation::activate_command(ProgrammeId::from_raw(1));
    let action = Action::Command(CellCommand::Engine(fstp_engine::Command::Core(cmd)));
    assert_eq!(
        HighRiskAction::of(&action),
        Ok(Some(HighRiskAction::ActivateProgramme)),
        "the gate must let a stepped-up tenant admin activate a draft programme"
    );
}
