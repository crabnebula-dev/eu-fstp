//! Exact ratios and the strict I-08 comparison with P-02 (I-08, R-EV-03,
//! NOTE 6 of `policy-parameters.md`, design section 2.3).
//!
//! The reference compares `a/b` with `c/d` as `a*d` with `c*b`, and a ratio
//! with a percentage as `num * 10_000` with `bp * den`, all in `u128`.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "test references compute in u128, which cannot overflow here"
)]

mod common;

use core::cmp::Ordering;
use core::hash::{Hash, Hasher};
use core::num::NonZeroU64;
use std::collections::hash_map::DefaultHasher;

use common::{MAX_BP, format_two_decimals};
use fstp_money::{Percent, Ratio};
use fstp_prop::{Config, Gen, check_with, prop_assert, prop_assert_eq};

/// Cases per property. `FSTP_PROP_CASES` still overrides it.
const CASES: u32 = 2_000;

#[track_caller]
fn check<F: Fn(&mut Gen) -> Result<(), String>>(name: &str, prop: F) {
    check_with(name, Config::default().with_cases(CASES), prop);
}

/// A numerator and denominator pair, biased towards small values, shared
/// factors and the bounds of `u64`.
fn fraction(g: &mut Gen) -> (u64, NonZeroU64) {
    let num = match g.u8_in(0..=3) {
        0 => g.u64_in(0..=16),
        1 => *g.pick(&[0, 1, u64::MAX - 1, u64::MAX, 1 << 32, (1 << 32) + 1]),
        2 => g.u64_in(0..=10_000),
        _ => g.u64(),
    };
    let den = match g.u8_in(0..=3) {
        0 => g.u64_in(1..=16),
        1 => *g.pick(&[1, 2, 4, 10_000, u64::MAX - 1, u64::MAX]),
        2 => g.u64_in(1..=10_000),
        _ => g.u64_in(1..=u64::MAX),
    };
    (num, NonZeroU64::new(den).unwrap_or(NonZeroU64::MIN))
}

/// A fraction and a copy scaled by a common factor, when the copy fits.
fn scaled_pair(g: &mut Gen) -> ((u64, NonZeroU64), (u64, NonZeroU64)) {
    let (n, d) = fraction(g);
    let k = g.u64_in(1..=1_000);
    let copy = n
        .checked_mul(k)
        .zip(d.get().checked_mul(k).and_then(NonZeroU64::new));
    match copy {
        Some(scaled) => ((n, d), scaled),
        None => ((n, d), (n, d)),
    }
}

/// Two fractions, equal in value about half of the time.
fn two_fractions(g: &mut Gen) -> ((u64, NonZeroU64), (u64, NonZeroU64)) {
    if g.bool() {
        scaled_pair(g)
    } else {
        (fraction(g), fraction(g))
    }
}

/// The reference order of `a/b` and `c/d`.
fn reference_cmp((a, b): (u64, NonZeroU64), (c, d): (u64, NonZeroU64)) -> Ordering {
    (u128::from(a) * u128::from(d.get())).cmp(&(u128::from(c) * u128::from(b.get())))
}

/// The reference I-08 comparison: strictly above, never at equality.
fn reference_exceeds((n, d): (u64, NonZeroU64), bp: u16) -> bool {
    u128::from(n) * 10_000 > u128::from(bp) * u128::from(d.get())
}

fn ratio((n, d): (u64, NonZeroU64)) -> Ratio {
    Ratio::new(n, d)
}

fn hash_of(r: &Ratio) -> u64 {
    let mut h = DefaultHasher::new();
    r.hash(&mut h);
    h.finish()
}

fn percent(bp: u16) -> Result<Percent, String> {
    let text = format_two_decimals(u64::from(bp));
    let p = Percent::parse(&text).map_err(|e| format!("Percent::parse({text}): {e:?}"))?;
    if p.bp() == bp {
        Ok(p)
    } else {
        Err(format!("Percent::parse({text}) gave {} bp", p.bp()))
    }
}

#[allow(
    clippy::expect_used,
    reason = "every caller passes a non-zero literal or product"
)]
fn den(d: u64) -> NonZeroU64 {
    NonZeroU64::new(d).expect("a non-zero test denominator")
}

/// I-08, design section 2.3: a `Ratio` is kept in lowest terms, so derived
/// equality is value equality. `a/b == c/d` exactly when `a*d == c*b`.
#[test]
fn i08_ratio_eq_is_value_equality_in_lowest_terms() {
    check("i08_ratio_eq_is_value_equality_in_lowest_terms", |g| {
        let (x, y) = two_fractions(g);
        g.note("fractions", &(x, y));
        let want = reference_cmp(x, y) == Ordering::Equal;
        prop_assert_eq!(ratio(x) == ratio(y), want);
        Ok(())
    });
}

/// I-08, design section 2.3: equal ratios hash equally, whatever common
/// factor their numerator and denominator were built with.
#[test]
fn i08_ratio_hash_agrees_with_value_equality() {
    check("i08_ratio_hash_agrees_with_value_equality", |g| {
        let (x, y) = scaled_pair(g);
        g.note("fractions", &(x, y));
        let (rx, ry) = (ratio(x), ratio(y));
        prop_assert_eq!(rx, ry);
        prop_assert_eq!(hash_of(&rx), hash_of(&ry));
        Ok(())
    });
}

/// I-08, design section 2.3: `Ord` compares `a/b` with `c/d` as `a*d` with
/// `c*b` in `u128`, and agrees with `Eq`.
#[test]
fn i08_ratio_ord_is_cross_multiplication_in_u128() {
    check("i08_ratio_ord_is_cross_multiplication_in_u128", |g| {
        let (x, y) = two_fractions(g);
        g.note("fractions", &(x, y));
        let (rx, ry) = (ratio(x), ratio(y));
        let got = rx.cmp(&ry);
        prop_assert_eq!(got, reference_cmp(x, y));
        prop_assert_eq!(rx.partial_cmp(&ry), Some(got));
        prop_assert_eq!(got == Ordering::Equal, rx == ry);
        Ok(())
    });
}

/// I-08, R-EV-03: `exceeds` is `num * 10_000 > bp * den` in `u128`. The
/// comparison is strict and exact, with no rounding.
#[test]
fn i08_ratio_exceeds_matches_the_strict_u128_reference() {
    check("i08_ratio_exceeds_matches_the_strict_u128_reference", |g| {
        let bp = match g.u8_in(0..=1) {
            0 => *g.pick(&[0, 1, 7_499, 7_500, 7_501, 9_999, MAX_BP]),
            _ => g.u16_in(0..=MAX_BP),
        };
        let x = match g.u8_in(0..=2) {
            // Exactly at the threshold, and one step either side of it.
            0 => {
                let k = g.u64_in(1..=1_000);
                let at = u64::from(bp) * k;
                let n = match g.u8_in(0..=2) {
                    0 => at,
                    1 => at + 1,
                    _ => at.saturating_sub(1),
                };
                (n, den(10_000 * k))
            }
            _ => fraction(g),
        };
        g.note("case", &(x, bp));
        let got = ratio(x).exceeds(percent(bp)?);
        prop_assert_eq!(got, reference_exceeds(x, bp));
        Ok(())
    });
}

/// I-08, R-EV-03: a ratio equal to P-02 never exceeds it, and the next value
/// above it in the same denominator always does.
#[test]
fn i08_ratio_equal_to_the_threshold_never_exceeds() {
    check("i08_ratio_equal_to_the_threshold_never_exceeds", |g| {
        let bp = g.u16_in(0..=MAX_BP);
        let k = g.u64_in(1..=1_000_000);
        g.note("case", &(bp, k));
        let p = percent(bp)?;
        let at = Ratio::new(u64::from(bp) * k, den(10_000 * k));
        let above = Ratio::new(u64::from(bp) * k + 1, den(10_000 * k));
        prop_assert!(!at.exceeds(p), "{bp} bp exceeds itself at factor {k}");
        prop_assert!(
            above.exceeds(p),
            "one step above {bp} bp does not exceed it"
        );
        Ok(())
    });
}

/// I-08, R-EV-03, NOTE 6 of `policy-parameters.md`: with N = 4, the default
/// weights and every score at 3, the score is exactly 3/4, which is 75.00%.
/// It does not pass a P-02 of 75.00%. The neighbours on either side do.
#[test]
fn i08_r_ev_03_three_quarters_does_not_exceed_75_00() {
    let p75 = Percent::parse("75.00").expect("75.00 is canonical");
    assert_eq!(p75.bp(), 7_500);
    assert!(!Ratio::new(3, den(4)).exceeds(p75), "3/4 exceeds 75.00");
    assert!(
        !Ratio::new(75, den(100)).exceeds(p75),
        "75/100 exceeds 75.00"
    );
    assert!(!Ratio::new(7_500, den(10_000)).exceeds(p75));
    assert!(Ratio::new(7_501, den(10_000)).exceeds(p75), "75.01% fails");
    assert!(!Ratio::new(7_499, den(10_000)).exceeds(p75));
    assert!(Ratio::new(3_000_001, den(4_000_000)).exceeds(p75));
    let p7499 = Percent::parse("74.99").expect("74.99 is canonical");
    assert!(
        Ratio::new(3, den(4)).exceeds(p7499),
        "3/4 does not exceed 74.99"
    );
    assert_eq!(Ratio::new(3, den(4)), Ratio::new(75, den(100)));
}

/// I-08: the bounds of the percentage range. Zero never exceeds 0.00, the
/// whole never exceeds 100.00, and a ratio above one exceeds 100.00.
#[test]
fn i08_ratio_exceeds_at_the_percentage_bounds() {
    let p0 = Percent::parse("0.00").expect("0.00 is canonical");
    let p100 = Percent::parse("100.00").expect("100.00 is canonical");
    assert!(!Ratio::new(0, den(1)).exceeds(p0));
    assert!(!Ratio::new(0, den(u64::MAX)).exceeds(p0));
    assert!(Ratio::new(1, den(u64::MAX)).exceeds(p0));
    assert!(!Ratio::new(1, den(1)).exceeds(p100));
    assert!(!Ratio::new(u64::MAX, den(u64::MAX)).exceeds(p100));
    assert!(Ratio::new(u64::MAX, den(u64::MAX - 1)).exceeds(p100));
    assert!(Ratio::new(2, den(1)).exceeds(p100));
}
