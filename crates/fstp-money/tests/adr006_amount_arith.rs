//! Checked amount arithmetic and comparison against `i128` reference
//! arithmetic, including overflow at `Amount::MAX_ABS_MINOR` (ADR-006,
//! design section 2.3).
//!
//! The `CurrencyMismatch` paths of `checked_add`, `checked_sub`, `cmp_same`,
//! `checked_sum` and `AmountRange` are covered by the unit tests
//! `adr006_*_currency_mismatch` in `src/amount.rs`. They build a second
//! amount in the test-only `Currency::Xts`, which this crate-external test
//! cannot reach.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "test references compute in i128, which cannot overflow here"
)]

mod common;

use core::cmp::Ordering;

use common::{MAX_ABS_MINOR, eur, in_range_minor};
use fstp_money::{Amount, Currency, MoneyError, checked_sum};
use fstp_prop::{Config, Gen, check_with, prop_assert, prop_assert_eq};

/// Cases per property. `FSTP_PROP_CASES` still overrides it.
const CASES: u32 = 2_000;

#[track_caller]
fn check<F: Fn(&mut Gen) -> Result<(), String>>(name: &str, prop: F) {
    check_with(name, Config::default().with_cases(CASES), prop);
}

/// Whether `v` lies within plus or minus `MAX_ABS_MINOR`.
fn in_range(v: i128) -> bool {
    v.unsigned_abs() <= MAX_ABS_MINOR.unsigned_abs().into()
}

/// The reference result of a checked operation with exact value `v`.
fn reference(v: i128) -> Result<i64, MoneyError> {
    if in_range(v) {
        i64::try_from(v).map_err(|_| MoneyError::Overflow)
    } else {
        Err(MoneyError::Overflow)
    }
}

/// A minor value anywhere in `i64`, biased towards both range bounds of
/// `Amount` and of `i64`.
fn any_minor(g: &mut Gen) -> i64 {
    match g.u8_in(0..=2) {
        0 => *g.pick(&[
            i64::MIN,
            i64::MIN + 1,
            -MAX_ABS_MINOR - 1,
            -MAX_ABS_MINOR,
            -1,
            0,
            1,
            MAX_ABS_MINOR,
            MAX_ABS_MINOR + 1,
            i64::MAX,
        ]),
        1 => in_range_minor(g),
        _ => g.i64(),
    }
}

/// ADR-006, design section 2.3: `from_minor` accepts exactly the values
/// within plus or minus `MAX_ABS_MINOR` and refuses the rest with
/// `OutOfRange`. `i64::MIN` is never representable.
#[test]
fn adr006_from_minor_accepts_exactly_the_symmetric_range() {
    check(
        "adr006_from_minor_accepts_exactly_the_symmetric_range",
        |g| {
            let m = any_minor(g);
            g.note("minor", &m);
            match Amount::from_minor(m, Currency::Eur) {
                Ok(a) => {
                    prop_assert!(in_range(m.into()), "accepted {m}");
                    prop_assert_eq!(a.minor(), m);
                    prop_assert_eq!(a.currency(), Currency::Eur);
                }
                Err(e) => {
                    prop_assert!(!in_range(m.into()), "refused {m} with {e:?}");
                    prop_assert_eq!(e, MoneyError::OutOfRange);
                }
            }
            Ok(())
        },
    );
}

/// ADR-006: `checked_add` equals `i128` addition when the sum is in range
/// and refuses with `Overflow` otherwise.
#[test]
fn adr006_checked_add_matches_i128_reference() {
    check("adr006_checked_add_matches_i128_reference", |g| {
        let (x, y) = (in_range_minor(g), in_range_minor(g));
        g.note("operands", &(x, y));
        let got = eur(x)?.checked_add(eur(y)?).map(Amount::minor);
        prop_assert_eq!(got, reference(i128::from(x) + i128::from(y)));
        Ok(())
    });
}

/// ADR-006: `checked_sub` equals `i128` subtraction when the difference is in
/// range and refuses with `Overflow` otherwise.
#[test]
fn adr006_checked_sub_matches_i128_reference() {
    check("adr006_checked_sub_matches_i128_reference", |g| {
        let (x, y) = (in_range_minor(g), in_range_minor(g));
        g.note("operands", &(x, y));
        let got = eur(x)?.checked_sub(eur(y)?).map(Amount::minor);
        prop_assert_eq!(got, reference(i128::from(x) - i128::from(y)));
        Ok(())
    });
}

/// ADR-006: `neg` is total on the symmetric range, keeps the currency, and
/// is its own inverse.
#[test]
fn adr006_neg_matches_i128_reference() {
    check("adr006_neg_matches_i128_reference", |g| {
        let x = in_range_minor(g);
        g.note("minor", &x);
        let a = eur(x)?;
        let n = a.neg();
        prop_assert_eq!(i128::from(n.minor()), -i128::from(x));
        prop_assert_eq!(n.currency(), Currency::Eur);
        prop_assert_eq!(n.neg(), a);
        Ok(())
    });
}

/// ADR-006: `checked_sum` equals the `i128` sum when every partial sum is in
/// range, and refuses with `Overflow` when the total is out of range.
///
/// The design does not say whether a partial sum out of range fails when the
/// total is back in range. This property accepts both readings in that case.
#[test]
fn adr006_checked_sum_matches_i128_reference() {
    check("adr006_checked_sum_matches_i128_reference", |g| {
        let xs = g.vec(0..=8, in_range_minor);
        g.note("terms", &xs);
        let amounts = xs.iter().map(|&x| eur(x)).collect::<Result<Vec<_>, _>>()?;
        let got = checked_sum(Currency::Eur, amounts).map(Amount::minor);
        let mut total: i128 = 0;
        let mut partials_in_range = true;
        for &x in &xs {
            total += i128::from(x);
            partials_in_range &= in_range(total);
        }
        if partials_in_range || !in_range(total) {
            prop_assert_eq!(got, reference(total));
        } else {
            prop_assert!(
                got == reference(total) || got == Err(MoneyError::Overflow),
                "partial overflow gave {got:?}"
            );
        }
        Ok(())
    });
}

/// ADR-006, design section 2.3: the empty sum is zero.
#[test]
fn adr006_checked_sum_of_nothing_is_zero() {
    let sum = checked_sum(Currency::Eur, []);
    assert_eq!(sum, Ok(Amount::zero(Currency::Eur)));
}

/// ADR-006: overflow exactly at `MAX_ABS_MINOR`. The bound itself is
/// reachable, and one minor unit beyond it is refused in every operation.
#[test]
fn adr006_overflow_at_max_abs_minor() {
    let max = eur(MAX_ABS_MINOR).expect("MAX_ABS_MINOR is in range");
    let min = eur(-MAX_ABS_MINOR).expect("-MAX_ABS_MINOR is in range");
    let one = eur(1).expect("1 is in range");
    let zero = Amount::zero(Currency::Eur);
    assert_eq!(Amount::MAX_ABS_MINOR, MAX_ABS_MINOR);
    assert_eq!(
        Amount::from_minor(MAX_ABS_MINOR + 1, Currency::Eur),
        Err(MoneyError::OutOfRange)
    );
    assert_eq!(
        Amount::from_minor(-MAX_ABS_MINOR - 1, Currency::Eur),
        Err(MoneyError::OutOfRange)
    );
    assert_eq!(
        Amount::from_minor(i64::MIN, Currency::Eur),
        Err(MoneyError::OutOfRange)
    );
    assert_eq!(max.checked_add(zero), Ok(max));
    assert_eq!(max.checked_add(one), Err(MoneyError::Overflow));
    assert_eq!(min.checked_sub(one), Err(MoneyError::Overflow));
    assert_eq!(max.checked_sub(one.neg()), Err(MoneyError::Overflow));
    assert_eq!(max.checked_sub(min), Err(MoneyError::Overflow));
    assert_eq!(max.checked_add(min), Ok(zero));
    assert_eq!(max.neg(), min);
    assert_eq!(
        checked_sum(Currency::Eur, [max, one]),
        Err(MoneyError::Overflow)
    );
    assert_eq!(
        checked_sum(Currency::Eur, [max, max, max]),
        Err(MoneyError::Overflow)
    );
    assert_eq!(checked_sum(Currency::Eur, [max]), Ok(max));
}

/// ADR-006, design section 2.3: `cmp_same` orders two amounts of the same
/// currency as their minor units, and agrees with equality.
#[test]
fn adr006_cmp_same_matches_i128_reference() {
    check("adr006_cmp_same_matches_i128_reference", |g| {
        let x = in_range_minor(g);
        let y = if g.bool() { x } else { in_range_minor(g) };
        g.note("operands", &(x, y));
        let (a, b) = (eur(x)?, eur(y)?);
        let got = a.cmp_same(b);
        prop_assert_eq!(got, Ok(x.cmp(&y)));
        prop_assert_eq!(got == Ok(Ordering::Equal), a == b);
        prop_assert_eq!(b.cmp_same(a).map(Ordering::reverse), got);
        Ok(())
    });
}
