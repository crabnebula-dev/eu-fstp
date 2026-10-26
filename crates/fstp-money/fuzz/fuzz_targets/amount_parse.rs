//! Fuzz target for the ADR-006 amount parser (TH-26, H-05).
//!
//! Checks, for any UTF-8 input:
//! - parsing never panics, and error offsets stay inside the input;
//! - a text is accepted exactly when it matches the byte-level EUR grammar
//!   below, which is written separately from the parser;
//! - an accepted text carries the value the grammar computes, and
//!   round-trips byte for byte through `Display`;
//! - checked arithmetic and comparisons on parsed values never panic and
//!   agree with `i128` reference arithmetic.

#![no_main]

use core::cmp::Ordering;

use fstp_money::{
    Amount, AmountParseErrorKind, Currency, MoneyError, NonNegAmount, PosAmount, checked_sum,
};
use libfuzzer_sys::fuzz_target;

/// `Amount::MAX_ABS_MINOR`, restated so that a change shows up here.
const MAX_ABS_MINOR: i128 = 999_999_999_999_999_999;

/// What the grammar says about one text.
enum Verdict {
    /// Canonical, with this value in minor units.
    Accept(i128),
    /// Canonical spelling, but above `MAX_ABS_MINOR`.
    OutOfRange,
    /// Not the grammar.
    Syntax,
}

/// The ADR-006 EUR grammar `(0|[1-9][0-9]*)\.[0-9]{2}`. ADR-006 states that
/// an amount is never negative and carries no sign, so no sign is allowed.
fn eur_grammar(text: &[u8]) -> Verdict {
    let Some(dot) = text.iter().position(|&b| b == b'.') else {
        return Verdict::Syntax;
    };
    let (int, rest) = text.split_at(dot);
    let frac = &rest[1..];
    let digits = |s: &[u8]| s.iter().all(u8::is_ascii_digit);
    let int_ok = match int {
        [b'0'] => true,
        [first, ..] => (b'1'..=b'9').contains(first) && digits(int),
        [] => false,
    };
    if !(int_ok && frac.len() == 2 && digits(frac)) {
        return Verdict::Syntax;
    }
    // At most 18 digits in all fit `MAX_ABS_MINOR`, and the integer part
    // has no leading zero, so the digit count decides the range.
    if int.len() + frac.len() > 18 {
        return Verdict::OutOfRange;
    }
    let value = int
        .iter()
        .chain(frac)
        .fold(0i128, |v, &b| v * 10 + i128::from(b - b'0'));
    Verdict::Accept(value)
}

/// The reference result of a checked operation with exact value `v`.
fn reference(v: i128) -> Result<i64, MoneyError> {
    if v.abs() <= MAX_ABS_MINOR {
        i64::try_from(v).map_err(|_| MoneyError::Overflow)
    } else {
        Err(MoneyError::Overflow)
    }
}

fn check_arithmetic(a: Amount) {
    let m = i128::from(a.minor());
    let n = a.neg();
    assert_eq!(i128::from(n.minor()), -m);
    assert_eq!(n.neg(), a);
    assert_eq!(a.checked_add(a).map(Amount::minor), reference(m + m));
    assert_eq!(a.checked_sub(n).map(Amount::minor), reference(m + m));
    assert_eq!(a.checked_add(n).map(Amount::minor), Ok(0));
    assert_eq!(a.cmp_same(n), Ok(m.cmp(&-m)));
    assert_eq!(a.cmp_same(a), Ok(Ordering::Equal));
    assert_eq!(
        checked_sum(Currency::Eur, [a, n, a]).map(Amount::minor),
        Ok(a.minor())
    );
    assert_eq!(
        checked_sum(Currency::Eur, [a, a, a]).map(Amount::minor),
        reference(3 * m)
    );
    assert_eq!(NonNegAmount::new(a).map(NonNegAmount::amount), Ok(a));
    let pos = PosAmount::new(a).map(PosAmount::amount);
    if m == 0 {
        assert_eq!(pos, Err(MoneyError::Zero));
    } else {
        assert_eq!(pos, Ok(a));
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    match (Amount::parse(text, Currency::Eur), eur_grammar(data)) {
        (Ok(a), Verdict::Accept(v)) => {
            assert_eq!(i128::from(a.minor()), v, "wrong value");
            assert_eq!(a.to_string(), text, "accepted text does not round-trip");
            assert_eq!(a.currency(), Currency::Eur);
            check_arithmetic(a);
        }
        (Ok(_), _) => panic!("accepted a non-canonical spelling"),
        (Err(_), Verdict::Accept(_)) => panic!("refused a canonical spelling"),
        (Err(e), verdict) => {
            assert!(e.offset <= data.len(), "error offset outside the input");
            let out_of_range = e.kind == AmountParseErrorKind::OutOfRange;
            assert_eq!(
                out_of_range,
                matches!(verdict, Verdict::OutOfRange),
                "range and syntax errors mixed up"
            );
            let _ = e.to_string();
        }
    }
});
