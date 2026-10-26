//! I-10 teeth on the twin machine (design 6.1 "Teeth" and 6.2).
//!
//! Two faults. In the first, the adapter folds a core transition into
//! twin B, through the public structural `apply`, whenever twin B receives
//! a finding command: PR1 is withdrawn where the fold allows it, or the
//! vault epoch moves. In the second, twin B decides core commands with a
//! decider that reads the finding store. The twin comparison must fail
//! with an I-10 message. A failure that names only another property, such
//! as the L-FIND-B seam, is an undetected fault.

use fstp_domain_testkit::harness::teeth::expect_prop_failure;
use fstp_domain_testkit::mc::findings_model::{TwinMachine, TwinStart};
use fstp_prop::{Config, run_machine};

/// I-10: a core transition driven by a finding is caught by the twin comparison.
#[test]
fn i10_teeth_finding_driven_transition_is_caught() {
    let machine = match TwinMachine::new(TwinStart::Stage1, true) {
        Ok(m) => m,
        Err(e) => panic!("twin start from genesis: {e}"),
    };
    let outcome = run_machine(
        "i10_teeth_finding_driven_transition_is_caught",
        Config::default(),
        &machine,
    );
    if let Err(e) = expect_prop_failure(&outcome, "I-10") {
        panic!("{e}");
    }
}

/// I-10: an engine decider whose core branch reads the finding store is
/// caught by the twin comparison. Twin B decides its core commands with
/// `FindingReadingDecider`, which refuses every core command while call 1
/// holds a finding.
#[test]
fn i10_teeth_core_decider_reading_findings_is_caught() {
    let machine = match TwinMachine::reading(TwinStart::Stage1) {
        Ok(m) => m,
        Err(e) => panic!("twin start from genesis: {e}"),
    };
    let outcome = run_machine(
        "i10_teeth_core_decider_reading_findings_is_caught",
        Config::default(),
        &machine,
    );
    if let Err(e) = expect_prop_failure(&outcome, "I-10") {
        panic!("{e}");
    }
}
