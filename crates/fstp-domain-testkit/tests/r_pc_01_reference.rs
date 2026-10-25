//! R-PC-01 control: the reference and the generator of the R-PC-01 test
//! (`docs/handoff/m2-design.md` section 6.2).
//!
//! The control passes the reference as the scorer, so the R-PC-01 property
//! is shown to hold for a correct scorer. It also shows that the
//! generator only draws inputs that discriminate the two weightings.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain_testkit::r#gen::scores::TwoProgrammeCase;
use fstp_domain_testkit::harness::teeth::expect_prop_failure;
use fstp_domain_testkit::reference::scoring::{
    exact_two_programme_scorer, r_pc_01_property, weighted_reference,
};
use fstp_money::Ratio;
use fstp_prop::{Config, check, run};

/// R-PC-01 control: the reference passes the R-PC-01 property.
#[test]
fn r_pc_01_control_reference_scorer_passes() {
    check("r_pc_01_control_reference_scorer_passes", |g| {
        r_pc_01_property(g, exact_two_programme_scorer)
    });
}

/// R-PC-01: the AC is false when every criterion score is equal. With all
/// scores at 3, weights 30/40/30 and 40/30/30 give the same score. This is
/// why the generator never draws such inputs.
#[test]
fn r_pc_01_equal_criterion_scores_do_not_discriminate() {
    let vectors = vec![vec![3, 3, 3]; 2];
    let a = weighted_reference(4, &[30, 40, 30], &vectors).unwrap();
    let b = weighted_reference(4, &[40, 30, 30], &vectors).unwrap();
    assert!(a.same(b).unwrap());
}

/// A broken two-programme scorer that reads programme A's weights for both.
fn weights_of_a_for_both(case: &TwoProgrammeCase) -> Result<(Ratio, Ratio), String> {
    let a = weighted_reference(case.scale_max, &case.weights_a, &case.vectors)?.to_ratio()?;
    Ok((a, a))
}

/// R-PC-01 teeth: a scorer that ignores the second programme's weights
/// fails the R-PC-01 property.
#[test]
fn r_pc_01_teeth_shared_weights_are_caught() {
    let outcome = run(
        "r_pc_01_teeth_shared_weights_are_caught",
        Config::default(),
        |g| r_pc_01_property(g, weights_of_a_for_both),
    );
    expect_prop_failure(&outcome, "R-PC-01").unwrap();
}
