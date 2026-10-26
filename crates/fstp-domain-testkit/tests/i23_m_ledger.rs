//! I-23 on M-LEDGER (design 6.2 and 6.3).
//!
//! One proposal in STAGE1 from genesis, two reviewers, P-03 = 2, and a
//! small alphabet with corrections. The alphabet holds two scores, one
//! score correction, a policy edit and the end of the IRC member's
//! binding. It also holds a vault conflict that releases a reviewer, and
//! the stage 1 close. At most six I-23 records
//! follow the start. Each state carries the engine over its `MemStore` and
//! the ledger read back after the latest step.
//!
//! Properties:
//! - `transition("I-23")`: `before.ledger` is a strict prefix of
//!   `after.ledger`, field by field and by canonical bytes, and
//!   `replay(after.ledger) == after.state`;
//! - `always("I-23 corrections")`: every correction targets an existing
//!   record of the same kind;
//! - witnesses of a score correction, a second policy version, a binding
//!   end, a release and a stage 1 close after a correction.
//!
//! The run must store exactly [`M_LEDGER_STATES`] states. A smaller count
//! means production refused steps it accepted when the count was taken.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::harness::mc::check_exhaustive;
use fstp_domain_testkit::mc::ledger_model::{LedgerModel, M_LEDGER_STATES, m_ledger_properties};

/// I-23: on M-LEDGER every step extends the ledger it carries, the state
/// is the replay of that ledger, and every correction names an earlier
/// record of its own kind.
#[test]
fn i23_m_ledger() {
    let model = LedgerModel::new().unwrap_or_else(|e| panic!("{e}"));
    let properties = m_ledger_properties::<LedgerModel>();
    let outcome = match check_exhaustive(&model, &properties, M_LEDGER_STATES) {
        Ok(o) => o,
        Err(e) => panic!("{e}"),
    };
    assert_eq!(
        outcome.stats.states, M_LEDGER_STATES,
        "M-LEDGER stored another number of states than the measured count"
    );
}
