//! I-66 and I-67: the engine fold refuses an unpaired `ProgrammeActivated`
//! (M4 design section 3.4 D2e and 8.4, "Engine fold").
//!
//! An entry that holds a core `ProgrammeActivated` without a
//! `Creator(ActivationApproved)` for the same programme, revision and
//! report digest is refused by the fold, so `replay` refuses a ledger with
//! one. This keeps the single path to an active programme even for a
//! ledger written outside the engine.
//!
//! Red until `Record::ProgrammeActivated` (D2, lane W1b) and the fold
//! pairing (D2e, lane W2e) exist. Lane W2e lists the same test among its
//! tests first; the lead reconciles the two at merge.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_testkit::mc::activate_model::production;
use fstp_api_testkit::reference::creator::clean_plan;

/// I-66, I-67: the fold refuses `ProgrammeActivated` without its creator
/// approval in the same entry.
#[test]
fn i66_fold_refuses_unpaired_programme_activated() {
    let outcome = production::fold_unpaired_activation(&clean_plan())
        .unwrap_or_else(|e| panic!("production: {e}"));
    assert!(
        outcome.is_err(),
        "I-66: the fold accepted a ProgrammeActivated without ActivationApproved"
    );
}
