//! I-36 teeth: the narrower check that I-36 had before the decision of 2026-10-25 is caught by the property (design 6.1 "Teeth").
//!
//! The fault is the old check, injected as the engine on the references:
//! it refuses a former reviewer only in a call where a proposal it
//! reviewed is under evaluation now. The I-36 property must fail with a
//! counterexample that names I-36, and that fails again on replay.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::review::i36_property;
use fstp_domain_testkit::r#gen::roster::Backend;
use fstp_domain_testkit::harness::teeth::expect_prop_failure;
use fstp_prop::{Config, run};

/// I-36: the current-call-only check is caught.
#[test]
fn i36_teeth_current_call_only_check_is_caught() {
    let outcome = run(
        "i36_teeth_current_call_only_check_is_caught",
        Config::default().with_cases(96),
        |g| i36_property(g, Backend::Reference, true),
    );
    if let Err(e) = expect_prop_failure(&outcome, "I-36") {
        panic!("{e}");
    }
}
