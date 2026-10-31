//! Diagnostic: where the lifecycle stalls without withdrawal (design 6.4).
//!
//! Design section 6.4 notes that `deadlock_free` holds trivially before
//! GRANTED, because withdrawal stays enabled. This diagnostic runs
//! M-CONFORMANCE without withdrawal and lists every reachable state whose
//! proposal is not terminal and from which no sequence of actions ever
//! changes the proposal's state. It prints each such proposal state with
//! a count and a shortest action sequence to one example.
//!
//! It is a diagnostic, not an invariant test. Design 6.4 keeps it out of
//! CI until Daniel decides, so it is ignored by default. Run it with
//! `cargo test -p fstp-domain-testkit --test lifecycle_deadlock_diagnostic -- --ignored --nocapture`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    reason = "R-NF-02 print ban: test-only code that never ships, so it may print"
)]

use fstp_domain_testkit::mc::conformance::{
    ConformanceModel, M_CONFORMANCE_NO_WITHDRAW_STATES, stalls,
};

/// Design 6.4: lists the states where nothing else moves once withdrawal
/// is gone. Q3, Q6 and Q15 removed the stalls the design named, so what
/// remains is printed for review.
#[test]
#[ignore = "diagnostic, not an invariant test: design section 6.4 keeps it out of CI"]
fn lifecycle_deadlock_diagnostic() {
    let model = ConformanceModel::new(false)
        .unwrap_or_else(|e| panic!("M-CONFORMANCE start from genesis: {e}"));
    let (states, found) =
        stalls(&model, M_CONFORMANCE_NO_WITHDRAW_STATES).unwrap_or_else(|e| panic!("{e}"));
    eprintln!("lifecycle diagnostic: {states} states without withdrawal");
    if found.is_empty() {
        eprintln!("lifecycle diagnostic: no stall without withdrawal");
    }
    for (state, (count, path)) in &found {
        eprintln!(
            "lifecycle diagnostic: {} stalls in {count} states, for example after {path:?}",
            state.spec_name()
        );
    }
}
