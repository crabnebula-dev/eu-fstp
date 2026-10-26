//! References, predicates and generators shared by the fstp-money tests.
//!
//! Everything here is written from the text of ADR-006, `m2-design.md`
//! section 2.3 and `policy-parameters.md` NOTE 6. Nothing here calls the
//! production parser or formatter, so each reference is independent of the
//! code it checks.

#![allow(
    dead_code,
    reason = "each test binary uses a different subset of the helpers"
)]

use fstp_money::{Amount, AmountParseErrorKind, Currency};
use fstp_prop::Gen;

/// `Amount::MAX_ABS_MINOR`, restated from design section 2.3 so that a
/// change to the constant shows up as a test failure.
pub(crate) const MAX_ABS_MINOR: i64 = 999_999_999_999_999_999;

/// The largest percentage, 100.00, in basis points.
pub(crate) const MAX_BP: u16 = 10_000;

/// The outcome of the reference grammar for one text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reference {
    /// The text is canonical and its value is in range.
    Accept(i128),
    /// The text follows the grammar, but its value is out of range.
    OutOfRange,
    /// The text does not follow the grammar.
    Syntax,
}

/// The ADR-006 EUR text grammar `(0|[1-9][0-9]*)\.[0-9]{2}`, with no sign.
///
/// ADR-006 states that an amount is never negative and carries no sign, so
/// any `-` or `+` is a syntax error. `max` is the largest value in minor units
/// that the caller allows. The check works on bytes, so any non-ASCII byte
/// fails the grammar.
pub(crate) fn decimal_grammar(text: &[u8], max: u128) -> Reference {
    let Some(dot) = text.iter().position(|&b| b == b'.') else {
        return Reference::Syntax;
    };
    let (int, rest) = text.split_at(dot);
    let frac = rest.split_first().map_or(rest, |(_, f)| f);
    let all_digits = |s: &[u8]| s.iter().all(|b| b.is_ascii_digit());
    let int_ok = match int {
        [] => false,
        [b'0'] => true,
        [first, ..] => (b'1'..=b'9').contains(first) && all_digits(int),
    };
    let frac_ok = frac.len() == 2 && all_digits(frac);
    if !(int_ok && frac_ok) {
        return Reference::Syntax;
    }
    let mut value: u128 = 0;
    for &b in int.iter().chain(frac.iter()) {
        value = value
            .saturating_mul(10)
            .saturating_add(u128::from(b - b'0'));
    }
    if value > max {
        Reference::OutOfRange
    } else {
        Reference::Accept(value as i128)
    }
}

/// The reference grammar for EUR amounts, bounded by `MAX_ABS_MINOR`.
pub(crate) fn amount_reference(text: &str) -> Reference {
    decimal_grammar(text.as_bytes(), MAX_ABS_MINOR as u128)
}

/// The reference grammar for percentages, bounded by 100.00.
pub(crate) fn percent_reference(text: &str) -> Reference {
    decimal_grammar(text.as_bytes(), u128::from(MAX_BP))
}

/// The canonical text of a value of two minor digits, written from the
/// grammar: integer part without leading zeros, a full stop, two digits.
pub(crate) fn format_two_decimals(value: u64) -> String {
    format!("{}.{:02}", value / 100, value % 100)
}

/// Every real parse error kind. The temporary W0 stub kind is not in the
/// list, so a stub refusal never counts as a correct refusal.
pub(crate) fn is_real_kind(kind: AmountParseErrorKind) -> bool {
    matches!(
        kind,
        AmountParseErrorKind::Empty
            | AmountParseErrorKind::UnexpectedByte
            | AmountParseErrorKind::LeadingZero
            | AmountParseErrorKind::WrongScale
            | AmountParseErrorKind::OutOfRange
    )
}

/// The kinds that report a syntax error, as opposed to a range error.
pub(crate) fn is_syntax_kind(kind: AmountParseErrorKind) -> bool {
    is_real_kind(kind) && kind != AmountParseErrorKind::OutOfRange
}

/// An EUR amount from minor units, failing the case when it is refused.
pub(crate) fn eur(minor: i64) -> Result<Amount, String> {
    Amount::from_minor(minor, Currency::Eur)
        .map_err(|e| format!("from_minor({minor}) refused an in-range value: {e:?}"))
}

/// An in-range minor value, biased towards zero, small values and both
/// bounds of the range.
pub(crate) fn in_range_minor(g: &mut Gen) -> i64 {
    match g.u8_in(0..=3) {
        0 => g.i64_in(-1_000..=1_000),
        1 => MAX_ABS_MINOR - g.i64_in(0..=1_000),
        2 => -(MAX_ABS_MINOR - g.i64_in(0..=1_000)),
        _ => g.i64_in(-MAX_ABS_MINOR..=MAX_ABS_MINOR),
    }
}

/// A non-negative in-range minor value.
pub(crate) fn non_neg_minor(g: &mut Gen) -> i64 {
    match g.u8_in(0..=2) {
        0 => g.i64_in(0..=1_000),
        1 => MAX_ABS_MINOR - g.i64_in(0..=1_000),
        _ => g.i64_in(0..=MAX_ABS_MINOR),
    }
}

/// A canonical EUR amount text and its value in minor units.
pub(crate) fn canonical_amount_text(g: &mut Gen) -> (String, i64) {
    let m = non_neg_minor(g);
    (format_two_decimals(m.unsigned_abs()), m)
}

/// Characters that often break decimal parsers, including signs,
/// separators, whitespace, exponents and non-ASCII digits.
const NOISE: &[char] = &[
    '0', '1', '5', '9', '.', '-', '+', 'e', 'E', ',', '_', '\'', ' ', '\t', '\n', '%', '\u{a0}',
    '\u{0}', '\u{660}', '\u{661}', '\u{ff11}', '\u{ff0e}', '\u{2212}', '\u{e9}', 'x',
];

fn digits(g: &mut Gen, len: usize, allow_leading_zero: bool) -> String {
    let mut out = String::new();
    for i in 0..len {
        let lo = if i == 0 && !allow_leading_zero { 1 } else { 0 };
        let d = g.u8_in(lo..=9);
        out.push(char::from(b'0' + d));
    }
    out
}

/// A text with an integer part, a separator and a fraction, each of which may
/// break the grammar, wrapped in an optional prefix and suffix.
fn structured_text(g: &mut Gen, max_int_len: usize) -> String {
    let prefix = *g.pick(&["", "", "", "-", "+", " ", "0", "\u{2212}"]);
    let int_len = g.usize_in(0..=max_int_len);
    let leading_zero = g.bool();
    let int = if int_len == 1 && leading_zero {
        "0".to_owned()
    } else {
        digits(g, int_len, leading_zero)
    };
    let sep = *g.pick(&[".", ".", ".", "", ",", ".."]);
    let frac_len = *g.pick(&[2usize, 2, 2, 0, 1, 3, 4]);
    let frac = digits(g, frac_len, true);
    let suffix = *g.pick(&["", "", "", " ", "\n", "0", "e3", "%", "\u{0}"]);
    format!("{prefix}{int}{sep}{frac}{suffix}")
}

/// A short text drawn from the noise alphabet.
fn noise_text(g: &mut Gen, max_len: usize) -> String {
    let len = g.usize_in(0..=max_len);
    (0..len).map(|_| *g.pick(NOISE)).collect()
}

/// One insertion, deletion or replacement of a character of `text`.
fn mutate(g: &mut Gen, text: &str) -> String {
    let mut chars: Vec<char> = text.chars().collect();
    let at = g.usize_in(0..=chars.len());
    match g.u8_in(0..=2) {
        0 => chars.insert(at, *g.pick(NOISE)),
        1 if at < chars.len() => {
            chars.remove(at);
        }
        _ => {
            let c = *g.pick(NOISE);
            match chars.get_mut(at) {
                Some(slot) => *slot = c,
                None => chars.push(c),
            }
        }
    }
    chars.into_iter().collect()
}

/// A text close to the amount grammar: canonical, nearly canonical or noise.
///
/// About half of the generated texts are canonical, so both directions of the
/// grammar comparison are exercised.
pub(crate) fn near_amount_text(g: &mut Gen) -> String {
    match g.u8_in(0..=4) {
        0 => canonical_amount_text(g).0,
        1 => structured_text(g, 20),
        2 => noise_text(g, 12),
        _ => {
            let (base, _) = canonical_amount_text(g);
            mutate(g, &base)
        }
    }
}

/// A canonical percentage text and its value in basis points.
pub(crate) fn canonical_percent_text(g: &mut Gen) -> (String, u16) {
    let bp = match g.u8_in(0..=2) {
        0 => *g.pick(&[0u16, 1, 7_499, 7_500, 7_501, 9_999, 10_000]),
        _ => g.u16_in(0..=MAX_BP),
    };
    (format_two_decimals(u64::from(bp)), bp)
}

/// A text close to the percentage grammar, including values above 100.00.
pub(crate) fn near_percent_text(g: &mut Gen) -> String {
    match g.u8_in(0..=4) {
        0 => canonical_percent_text(g).0,
        1 => structured_text(g, 4),
        2 => noise_text(g, 8),
        3 => format_two_decimals(g.u64_in(10_001..=1_000_000)),
        _ => {
            let (base, _) = canonical_percent_text(g);
            mutate(g, &base)
        }
    }
}
