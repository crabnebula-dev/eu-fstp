//! Krippendorff's alpha (T-LLM-CAL, `SPEC/07-test-plan/llm-evaluation.md`).
//!
//! The worked example is the reliability data matrix of four observers and
//! twelve units from Krippendorff's "Computing Krippendorff's
//! Alpha-Reliability" (2011). Its published values are 0.743 (nominal) and
//! 0.849 (interval). The exact fractions are computed by hand below.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use fstp_calib::{Alpha, Level, krippendorff_alpha};
use fstp_prop::{check, prop_assert, prop_assert_eq};

/// The worked example, one row per unit, missing values left out.
fn worked_example() -> Vec<Vec<i64>> {
    vec![
        vec![1, 1, 1],
        vec![2, 2, 3, 2],
        vec![3, 3, 3, 3],
        vec![3, 3, 3, 3],
        vec![2, 2, 2, 2],
        vec![1, 2, 3, 4],
        vec![4, 4, 4, 4],
        vec![1, 1, 2, 1],
        vec![2, 2, 2, 2],
        vec![5, 5, 5],
        vec![1, 1],
        vec![3],
    ]
}

/// T-LLM-CAL: nominal alpha of the worked example.
///
/// n = 40 pairable values. Observed disagreement sums to 8 (units 2, 6
/// and 8 give 6/3, 12/3 and 6/3). Expected disagreement is
/// 40^2 - (81 + 169 + 100 + 25 + 9) = 1216. Alpha is
/// 1 - 39 * 8 / 1216 = 904/1216 = 113/152, which rounds to 0.743.
#[test]
fn t_llm_cal_alpha_nominal_matches_worked_example() {
    let a = krippendorff_alpha(&worked_example(), Level::Nominal)
        .unwrap()
        .unwrap();
    assert_eq!(a, Alpha { num: 113, den: 152 });
    assert_eq!(a.ppm(), 743_421);
    assert_eq!(a.to_string(), "0.743421");
}

/// T-LLM-CAL: interval alpha of the worked example.
///
/// Observed disagreement is 2 + 40/3 + 2 = 52/3. Expected disagreement
/// is twice the sum over value pairs of n_c n_k (c - k)^2, 2 * 2240 =
/// 4480. Alpha is 1 - 39 * (52/3) / 4480 = 3804/4480 = 951/1120, which
/// rounds to 0.849.
#[test]
fn t_llm_cal_alpha_interval_matches_worked_example() {
    let a = krippendorff_alpha(&worked_example(), Level::Interval)
        .unwrap()
        .unwrap();
    assert_eq!(
        a,
        Alpha {
            num: 951,
            den: 1120
        }
    );
    assert_eq!(a.ppm(), 849_107);
}

/// T-LLM-CAL: perfect agreement with variation gives exactly 1.
#[test]
fn t_llm_cal_alpha_perfect_agreement_is_one() {
    let units = vec![vec![0, 0, 0], vec![1, 1], vec![2, 2, 2]];
    for level in [Level::Nominal, Level::Interval] {
        let a = krippendorff_alpha(&units, level).unwrap().unwrap();
        assert_eq!(a, Alpha { num: 1, den: 1 });
        assert_eq!(a.to_string(), "1.000000");
    }
}

/// T-LLM-CAL: alpha is undefined without variation or without a pairable
/// unit, so no figure is reported.
#[test]
fn t_llm_cal_alpha_undefined_without_variation() {
    assert_eq!(
        krippendorff_alpha(&[vec![1, 1], vec![1, 1, 1]], Level::Nominal).unwrap(),
        None
    );
    assert_eq!(
        krippendorff_alpha(&[vec![1], vec![2]], Level::Nominal).unwrap(),
        None
    );
    assert_eq!(krippendorff_alpha(&[], Level::Interval).unwrap(), None);
}

/// T-LLM-CAL: systematic disagreement gives a negative alpha, printed
/// with its sign.
///
/// Two units (0, 1) and (1, 0): n = 4, observed disagreement 2 + 2 = 4,
/// expected 16 - 8 = 8, alpha = 1 - 3 * 4 / 8 = -1/2.
#[test]
fn t_llm_cal_alpha_negative_is_signed() {
    let a = krippendorff_alpha(&[vec![0, 1], vec![1, 0]], Level::Nominal)
        .unwrap()
        .unwrap();
    assert_eq!(a, Alpha { num: -1, den: 2 });
    assert_eq!(a.ppm(), -500_000);
    assert_eq!(a.to_string(), "-0.500000");
}

/// T-LLM-CAL: alpha is deterministic. It does not depend on the order of
/// units or of values inside a unit, and it never exceeds 1.
#[test]
fn t_llm_cal_alpha_is_order_independent() {
    check("t_llm_cal_alpha_is_order_independent", |g| {
        let mut units = g.vec(0..=8, |g| g.vec(0..=5, |g| g.i64_in(-3..=3)));
        let level = if g.bool() {
            Level::Nominal
        } else {
            Level::Interval
        };
        let before = krippendorff_alpha(&units, level).map_err(|e| format!("{e:?}"))?;
        for u in &mut units {
            g.shuffle(u);
        }
        g.shuffle(&mut units);
        let after = krippendorff_alpha(&units, level).map_err(|e| format!("{e:?}"))?;
        prop_assert_eq!(before, after);
        if let Some(a) = after {
            prop_assert!(a.den > 0 && a.num <= a.den);
        }
        Ok(())
    });
}
