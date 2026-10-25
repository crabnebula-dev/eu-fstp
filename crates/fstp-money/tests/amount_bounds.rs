//! Sign-restricted amounts and inclusive amount ranges (ADR-006, design
//! section 2.3, I-13, R-NG-03, P-04).

#![allow(
    clippy::arithmetic_side_effects,
    reason = "test references compute in i128, which cannot overflow here"
)]

mod common;

use common::{eur, in_range_minor, non_neg_minor};
use fstp_money::{Amount, AmountRange, Currency, MoneyError, NonNegAmount, PosAmount};
use fstp_prop::{Config, Gen, check_with, prop_assert, prop_assert_eq};

/// Cases per property. `FSTP_PROP_CASES` still overrides it.
const CASES: u32 = 2_000;

#[track_caller]
fn check<F: Fn(&mut Gen) -> Result<(), String>>(name: &str, prop: F) {
    check_with(name, Config::default().with_cases(CASES), prop);
}

fn non_neg(minor: i64) -> Result<NonNegAmount, String> {
    NonNegAmount::new(eur(minor)?).map_err(|e| format!("NonNegAmount::new({minor}): {e:?}"))
}

/// ADR-006: `NonNegAmount` accepts zero and every positive amount, refuses
/// every negative amount with `Negative`, and keeps the wrapped amount.
#[test]
fn adr006_non_neg_amount_refuses_exactly_negative_values() {
    check(
        "adr006_non_neg_amount_refuses_exactly_negative_values",
        |g| {
            let m = in_range_minor(g);
            g.note("minor", &m);
            let a = eur(m)?;
            match NonNegAmount::new(a) {
                Ok(n) => {
                    prop_assert!(m >= 0, "accepted {m}");
                    prop_assert_eq!(n.amount(), a);
                }
                Err(e) => {
                    prop_assert!(m < 0, "refused {m} with {e:?}");
                    prop_assert_eq!(e, MoneyError::Negative);
                }
            }
            Ok(())
        },
    );
}

/// Design section 2.3: `PosAmount` accepts exactly the amounts above zero.
/// Zero is refused with `Zero` and a negative amount with `Negative`.
#[test]
fn adr006_pos_amount_refuses_zero_and_negative_values() {
    check("adr006_pos_amount_refuses_zero_and_negative_values", |g| {
        let m = in_range_minor(g);
        g.note("minor", &m);
        let a = eur(m)?;
        let got = PosAmount::new(a).map(PosAmount::amount);
        let want = match m {
            m if m > 0 => Ok(a),
            0 => Err(MoneyError::Zero),
            _ => Err(MoneyError::Negative),
        };
        prop_assert_eq!(got, want);
        Ok(())
    });
}

/// I-13, design section 2.3: `AmountRange::new` accepts exactly `min <= max`,
/// including `min == max`, and keeps both bounds.
#[test]
fn i13_amount_range_requires_min_at_most_max() {
    check("i13_amount_range_requires_min_at_most_max", |g| {
        let lo = non_neg_minor(g);
        let hi = if g.bool() { lo } else { non_neg_minor(g) };
        g.note("bounds", &(lo, hi));
        let (min, max) = (non_neg(lo)?, non_neg(hi)?);
        match AmountRange::new(min, max) {
            Ok(r) => {
                prop_assert!(lo <= hi, "accepted min {lo} above max {hi}");
                prop_assert_eq!(r.min(), min);
                prop_assert_eq!(r.max(), max);
            }
            Err(e) => prop_assert!(lo > hi, "refused {lo} to {hi} with {e:?}"),
        }
        Ok(())
    });
}

/// I-13, R-NG-03, P-04: `contains` is inclusive at both ends, decided on
/// 2026-10-25. It matches `min <= a <= max` for every amount, with the
/// bounds and their neighbours drawn often.
#[test]
fn i13_amount_range_contains_is_inclusive_at_both_ends() {
    check("i13_amount_range_contains_is_inclusive_at_both_ends", |g| {
        let x = non_neg_minor(g);
        let y = non_neg_minor(g);
        let (lo, hi) = (x.min(y), x.max(y));
        let candidates = [
            lo,
            hi,
            lo.saturating_sub(1),
            lo + 1,
            hi - 1,
            hi.saturating_add(1),
        ];
        let m = if g.bool() {
            *g.pick(&candidates)
        } else {
            non_neg_minor(g)
        };
        let m = m.clamp(0, common::MAX_ABS_MINOR);
        g.note("case", &(lo, m, hi));
        let range = AmountRange::new(non_neg(lo)?, non_neg(hi)?)
            .map_err(|e| format!("refused {lo} to {hi}: {e:?}"))?;
        prop_assert_eq!(range.contains(non_neg(m)?), Ok(lo <= m && m <= hi));
        Ok(())
    });
}

/// I-13, R-NG-03 acceptance criterion: an amount equal to either P-04 bound
/// is accepted. The P-04 default is 5k to 100k EUR, and one cent beyond
/// either bound is outside.
#[test]
fn i13_r_ng_03_p04_default_bounds_are_inclusive() {
    let at = |text: &str| -> NonNegAmount {
        let a = Amount::parse(text, Currency::Eur).expect("a canonical amount");
        NonNegAmount::new(a).expect("a non-negative amount")
    };
    let p04 = AmountRange::new(at("5000.00"), at("100000.00")).expect("a valid range");
    assert_eq!(p04.contains(at("5000.00")), Ok(true));
    assert_eq!(p04.contains(at("100000.00")), Ok(true));
    assert_eq!(p04.contains(at("50000.00")), Ok(true));
    assert_eq!(p04.contains(at("4999.99")), Ok(false));
    assert_eq!(p04.contains(at("100000.01")), Ok(false));
    assert_eq!(p04.contains(at("0.00")), Ok(false));
}
