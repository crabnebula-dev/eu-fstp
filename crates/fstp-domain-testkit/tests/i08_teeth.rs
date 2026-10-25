//! I-08 teeth at the pure level (`docs/handoff/m2-design.md` section 6.1).
//!
//! Deliberately broken scorers are passed to the I-08 predicate as plain
//! function pointers. No production hook exists. One broken scorer
//! computes the exact score and then compares it with `>=` instead of
//! `>`. The predicate must catch it, which needs generators that favour
//! equality. The other scores the superseded value of a corrected score.
//!
//! The control test passes the unbroken reference to the same predicate,
//! so the teeth test cannot pass by a predicate that rejects everything.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::arithmetic_side_effects)]

use fstp_domain_testkit::r#gen::scores::Stage1Case;
use fstp_domain_testkit::harness::teeth::expect_prop_failure;
use fstp_domain_testkit::reference::scoring::{
    Judged, exact_scorer, i08_property, passes_reference, weighted_reference,
};
use fstp_money::Percent;
use fstp_prop::{Config, check, run};

/// A broken scorer: the exact score of the superseded vectors where a
/// reviewer corrected its score, so a correction does not replace the value.
fn superseded_value_scored(case: &Stage1Case) -> Result<Judged, String> {
    let first: Vec<Vec<u8>> = case
        .vectors
        .iter()
        .enumerate()
        .map(|(r, v)| {
            case.earlier
                .get(r)
                .cloned()
                .flatten()
                .unwrap_or_else(|| v.clone())
        })
        .collect();
    let exact = weighted_reference(case.scale_max, &case.weights, &first)?;
    Ok(Judged {
        score: exact.to_ratio()?,
        passed: passes_reference(exact, case.p02_bp)?,
    })
}

/// I-08, NOTE 3 teeth: a scorer that keeps the first value of a corrected
/// score fails the I-08 property with a counterexample.
#[test]
fn i08_teeth_superseded_value_scored_is_caught() {
    let outcome = run(
        "i08_teeth_superseded_value_scored_is_caught",
        Config::default(),
        |g| i08_property(g, superseded_value_scored),
    );
    expect_prop_failure(&outcome, "I-08").unwrap();
}

/// The exact score with the faulty comparison `score >= P-02`.
fn ge_instead_of_gt(case: &Stage1Case) -> Result<Judged, String> {
    let exact = weighted_reference(case.scale_max, &case.weights, &case.vectors)?;
    let lhs = exact.num * u128::from(Percent::MAX_BP);
    let rhs = u128::from(case.p02_bp) * exact.den;
    Ok(Judged {
        score: exact.to_ratio()?,
        passed: lhs >= rhs,
    })
}

/// I-08 teeth: a scorer that passes at exact equality with P-02 fails the
/// I-08 property with a counterexample.
#[test]
fn i08_teeth_ge_instead_of_gt_is_caught() {
    let outcome = run(
        "i08_teeth_ge_instead_of_gt_is_caught",
        Config::default(),
        |g| i08_property(g, ge_instead_of_gt),
    );
    expect_prop_failure(&outcome, "I-08").unwrap();
}

/// I-08 control: the exact reference passes its own property, including
/// the metamorphic checks, so the teeth test above is not vacuous.
#[test]
fn i08_teeth_control_exact_scorer_passes() {
    check("i08_teeth_control_exact_scorer_passes", |g| {
        i08_property(g, exact_scorer)
    });
}

/// I-08, NOTE 6: the reference gives exactly 3/4 for weights 30/40/30,
/// scale 0 to 4 and every score 3, which does not pass 75.00% but passes 74.99%.
#[test]
fn i08_reference_edge_case_is_exactly_75_percent() {
    for reviewers in 1..=64 {
        let vectors = vec![vec![3, 3, 3]; reviewers];
        let exact = weighted_reference(4, &[30, 40, 30], &vectors).unwrap();
        assert_eq!(exact.num * 4, exact.den * 3, "{exact}");
        assert!(!passes_reference(exact, 7_500).unwrap());
        assert!(passes_reference(exact, 7_499).unwrap());
    }
}

/// I-08, NOTE 6: the reference refuses inputs that NOTE 6 excludes: an
/// incomplete vector, a value above N, a zero weight and no reviewer.
#[test]
fn i08_reference_refuses_inputs_outside_note_6() {
    assert!(weighted_reference(4, &[1, 1], &[vec![1]]).is_err());
    assert!(weighted_reference(4, &[1, 1], &[vec![1, 5]]).is_err());
    assert!(weighted_reference(4, &[1, 0], &[vec![1, 1]]).is_err());
    assert!(weighted_reference(4, &[1, 1], &[]).is_err());
    assert!(weighted_reference(0, &[1], &[vec![0]]).is_err());
}
