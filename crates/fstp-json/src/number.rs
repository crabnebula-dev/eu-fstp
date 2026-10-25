//! JSON numbers that keep their exact lexeme, and exact decimals.
//!
//! A [`Number`] stores the text of the number exactly as it appeared in the
//! input, for example `12.50` or `1E+3`. Nothing converts it to a binary float
//! unless the caller asks for that with [`Number::as_f64_lossy`]. Integer
//! accessors are checked and never round. [`Decimal`] gives an exact decimal
//! value, which suits money.

use core::cmp::Ordering;
use core::fmt;
use core::str::FromStr;

/// Why a number lexeme failed the grammar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ScanError {
    /// The lexeme breaks the RFC 8259 number grammar.
    Invalid,
    /// An integer part starts with `0` followed by another digit.
    LeadingZero,
}

fn is_digit(b: Option<u8>) -> bool {
    matches!(b, Some(b'0'..=b'9'))
}

/// Scans the longest RFC 8259 number that starts at `start`.
///
/// Returns the end offset of the lexeme, or the offset and reason of the
/// first byte that breaks the grammar. The caller checks what follows.
pub(crate) fn scan_number(bytes: &[u8], start: usize) -> Result<usize, (usize, ScanError)> {
    let at = |i: usize| bytes.get(i).copied();
    let mut i = start;
    if at(i) == Some(b'-') {
        i = i.saturating_add(1);
    }
    match at(i) {
        Some(b'0') => {
            i = i.saturating_add(1);
            if is_digit(at(i)) {
                return Err((i, ScanError::LeadingZero));
            }
        }
        Some(b'1'..=b'9') => {
            i = i.saturating_add(1);
            while is_digit(at(i)) {
                i = i.saturating_add(1);
            }
        }
        _ => return Err((i, ScanError::Invalid)),
    }
    if at(i) == Some(b'.') {
        i = i.saturating_add(1);
        if !is_digit(at(i)) {
            return Err((i, ScanError::Invalid));
        }
        while is_digit(at(i)) {
            i = i.saturating_add(1);
        }
    }
    if matches!(at(i), Some(b'e' | b'E')) {
        i = i.saturating_add(1);
        if matches!(at(i), Some(b'+' | b'-')) {
            i = i.saturating_add(1);
        }
        if !is_digit(at(i)) {
            return Err((i, ScanError::Invalid));
        }
        while is_digit(at(i)) {
            i = i.saturating_add(1);
        }
    }
    Ok(i)
}

/// A string that is not a valid RFC 8259 number lexeme.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NumberError {
    offset: usize,
}

impl NumberError {
    /// Byte offset of the first byte that breaks the grammar.
    pub fn offset(&self) -> usize {
        self.offset
    }
}

impl fmt::Display for NumberError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid JSON number at byte {}", self.offset)
    }
}

impl std::error::Error for NumberError {}

/// A JSON number that keeps its exact lexeme.
///
/// Two numbers are equal when their lexemes are identical, so `1.0` and `1`
/// differ. Compare numeric values with [`Number::as_decimal`].
///
/// The compact serializer writes the lexeme unchanged. The canonical
/// serializer rewrites it in the ECMAScript form that RFC 8785 requires.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Number {
    lexeme: Box<str>,
}

impl Number {
    /// Parses a number lexeme in the strict RFC 8259 grammar.
    ///
    /// Leading zeros, a leading `+`, a bare `.`, `NaN`, `Infinity` and
    /// surrounding whitespace are all rejected.
    pub fn from_lexeme(lexeme: &str) -> Result<Number, NumberError> {
        match scan_number(lexeme.as_bytes(), 0) {
            Ok(end) if end == lexeme.len() => Ok(Number::from_validated(lexeme)),
            Ok(end) => Err(NumberError { offset: end }),
            Err((offset, _)) => Err(NumberError { offset }),
        }
    }

    /// Wraps a lexeme the caller has already validated.
    pub(crate) fn from_validated(lexeme: &str) -> Number {
        Number {
            lexeme: Box::from(lexeme),
        }
    }

    /// Formats a finite float as ECMAScript `Number.prototype.toString` does.
    ///
    /// This is the number form of RFC 8785. Returns `None` for NaN and the
    /// infinities, which JSON cannot represent. Negative zero becomes `0`.
    pub fn from_f64(value: f64) -> Option<Number> {
        ecmascript_string(value).map(|s| Number::from_validated(&s))
    }

    /// Builds the number for an exact decimal. See [`Decimal`]'s `Display`.
    pub fn from_decimal(value: &Decimal) -> Number {
        Number::from_validated(&value.to_string())
    }

    /// The exact lexeme.
    pub fn as_str(&self) -> &str {
        &self.lexeme
    }

    /// Returns true when the lexeme has no fraction and no exponent.
    ///
    /// The integer accessors accept only such lexemes. A lexeme such as `1.0`
    /// or `1e2` denotes an integer value, but the sender chose a non-integer
    /// form, so the integer accessors refuse it. Use [`Number::as_decimal`]
    /// to read it exactly.
    pub fn is_integer(&self) -> bool {
        !self.lexeme.bytes().any(|b| matches!(b, b'.' | b'e' | b'E'))
    }

    /// The value as an `i64`, when the lexeme is an integer in range.
    pub fn as_i64(&self) -> Option<i64> {
        self.as_i128().and_then(|v| i64::try_from(v).ok())
    }

    /// The value as a `u64`, when the lexeme is an integer in range.
    pub fn as_u64(&self) -> Option<u64> {
        self.as_u128().and_then(|v| u64::try_from(v).ok())
    }

    /// The value as an `i128`, when the lexeme is an integer in range.
    pub fn as_i128(&self) -> Option<i128> {
        if !self.is_integer() {
            return None;
        }
        let (negative, digits) = split_sign(&self.lexeme);
        let mut acc: i128 = 0;
        for b in digits.bytes() {
            let d = i128::from(digit_value(b)?);
            acc = acc.checked_mul(10)?;
            acc = if negative {
                acc.checked_sub(d)?
            } else {
                acc.checked_add(d)?
            };
        }
        Some(acc)
    }

    /// The value as a `u128`, when the lexeme is an integer in range.
    ///
    /// `-0` gives 0. Any other negative lexeme gives `None`.
    pub fn as_u128(&self) -> Option<u128> {
        if !self.is_integer() {
            return None;
        }
        let (negative, digits) = split_sign(&self.lexeme);
        let mut acc: u128 = 0;
        for b in digits.bytes() {
            acc = acc
                .checked_mul(10)?
                .checked_add(u128::from(digit_value(b)?))?;
        }
        if negative && acc != 0 {
            return None;
        }
        Some(acc)
    }

    /// Converts to the nearest `f64`. This conversion is lossy.
    ///
    /// Rounding is correct to nearest, ties to even. Values beyond the `f64`
    /// range become an infinity, and values too small become a zero. Never
    /// use this for money or identifiers.
    pub fn as_f64_lossy(&self) -> f64 {
        // The lexeme grammar is a subset of what `f64::from_str` accepts.
        self.lexeme.parse::<f64>().unwrap_or(f64::NAN)
    }

    /// The exact decimal value. Suitable for money.
    ///
    /// Fails only when the decimal exponent does not fit in an `i64`, which
    /// needs an exponent part with more than 18 digits.
    pub fn as_decimal(&self) -> Result<Decimal, DecimalError> {
        Decimal::from_lexeme(&self.lexeme)
    }
}

impl fmt::Display for Number {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.lexeme)
    }
}

impl fmt::Debug for Number {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Number({})", self.lexeme)
    }
}

impl FromStr for Number {
    type Err = NumberError;

    fn from_str(s: &str) -> Result<Number, NumberError> {
        Number::from_lexeme(s)
    }
}

macro_rules! number_from_int {
    ($($t:ty),*) => {
        $(
            impl From<$t> for Number {
                fn from(value: $t) -> Number {
                    Number::from_validated(&value.to_string())
                }
            }
        )*
    };
}

number_from_int!(
    i8, i16, i32, i64, i128, isize, u8, u16, u32, u64, u128, usize
);

fn split_sign(lexeme: &str) -> (bool, &str) {
    match lexeme.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, lexeme),
    }
}

fn digit_value(b: u8) -> Option<u8> {
    if b.is_ascii_digit() {
        Some(b.wrapping_sub(b'0'))
    } else {
        None
    }
}

/// Formats a float as ECMAScript `Number::toString` (ECMA-262, 6.1.6.1.20).
///
/// Rust's shortest round-trip formatting gives the digits `s` and the decimal
/// exponent. The ECMAScript rules then choose between plain and exponent form.
pub(crate) fn ecmascript_string(x: f64) -> Option<String> {
    if !x.is_finite() {
        return None;
    }
    if x == 0.0 {
        return Some("0".to_owned());
    }
    // `{:e}` gives the shortest digits that round-trip, as `d[.ddd]e[-]N`.
    let sci = format!("{:e}", x.abs());
    let (mantissa, exp) = sci.split_once('e')?;
    let e: i64 = exp.parse().ok()?;
    let mut digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let k = i64::try_from(digits.len()).ok()?;
    // x = s * 10^(n - k) with s the k digits.
    let n = e.checked_add(1)?;
    // Ties between two shortest candidates need at least 16 digits.
    if k >= 16
        && let Some(even) = tie_to_even(x.abs(), &digits, n.checked_sub(k)?)
    {
        digits = even;
    }
    let mut out = String::with_capacity(32);
    if x.is_sign_negative() {
        out.push('-');
    }
    if k <= n && n <= 21 {
        out.push_str(&digits);
        push_zeros(&mut out, n.checked_sub(k)?);
    } else if 0 < n && n <= 21 {
        let (int, frac) = digits.split_at_checked(usize::try_from(n).ok()?)?;
        out.push_str(int);
        out.push('.');
        out.push_str(frac);
    } else if -6 < n && n <= 0 {
        out.push_str("0.");
        push_zeros(&mut out, n.checked_neg()?);
        out.push_str(&digits);
    } else {
        let exp = n.checked_sub(1)?;
        let (first, rest) = digits.split_at_checked(1)?;
        out.push_str(first);
        if !rest.is_empty() {
            out.push('.');
            out.push_str(rest);
        }
        out.push('e');
        out.push(if exp < 0 { '-' } else { '+' });
        out.push_str(&exp.unsigned_abs().to_string());
    }
    Some(out)
}

/// Applies the ECMAScript tie rule to Rust's shortest digits.
///
/// ECMAScript picks, among the shortest digit strings that round-trip, the
/// one closest to `x`, and the even one when two are equally close. Rust's
/// shortest formatting rounds such exact ties up. A tie needs the exact value
/// of `x` to be `S * 10^z` with `S` ending in 5 and one digit longer than
/// `digits`. This checks that with exact integer arithmetic and returns the
/// even candidate when it differs from `digits` and also round-trips.
///
/// `x` is positive and finite. `q` is the exponent of the last digit, so the
/// candidate value is `digits * 10^q`.
fn tie_to_even(x: f64, digits: &str, q: i64) -> Option<String> {
    const TEN_18: u128 = 1_000_000_000_000_000_000;
    let bits = x.to_bits();
    let biased = i64::try_from((bits >> 52) & 0x7FF).ok()?;
    let fraction = bits & ((1u64 << 52) - 1);
    let (m, e) = if biased == 0 {
        (fraction, -1074i64)
    } else {
        (fraction | (1u64 << 52), biased.checked_sub(1075)?)
    };
    if m == 0 {
        return None;
    }
    // x = m * 2^e with m odd after removing factors of two.
    let twos = m.trailing_zeros();
    let m = m >> twos;
    let e = e.checked_add(i64::from(twos))?;
    // Write x = s * 10^z with s not divisible by 10.
    let (s, z) = if e < 0 {
        // x = m * 5^-e / 10^-e, and m * 5^-e is odd, so it is s.
        let mut s = u128::from(m);
        for _ in 0..e.unsigned_abs() {
            s = s.checked_mul(5)?;
            if s >= TEN_18 {
                return None;
            }
        }
        (s, e)
    } else {
        // An odd s needs 10^e to absorb every factor of two.
        let p = 5u64.checked_pow(u32::try_from(e).ok()?)?;
        if m.checked_rem(p)? != 0 {
            return None;
        }
        (u128::from(m.checked_div(p)?), e)
    };
    if s % 10 != 5 || z.checked_add(1)? != q {
        return None;
    }
    let lower = s / 10;
    if lower.to_string().len() != digits.len() {
        return None;
    }
    let even = if lower.is_multiple_of(2) {
        lower
    } else {
        lower.checked_add(1)?
    };
    let even = even.to_string();
    if even == digits || even.len() != digits.len() || even.ends_with('0') {
        return None;
    }
    let back: f64 = format!("{even}e{q}").parse().ok()?;
    (back == x).then_some(even)
}

fn push_zeros(out: &mut String, count: i64) {
    for _ in 0..count {
        out.push('0');
    }
}

/// Why a [`Decimal`] operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecimalError {
    /// The decimal exponent does not fit in an `i64`.
    ExponentOutOfRange,
    /// The value has more fractional digits than the requested scale allows.
    Inexact,
    /// The scaled value does not fit in the target integer type.
    Overflow,
    /// The text is not a valid JSON number lexeme.
    Syntax,
}

impl fmt::Display for DecimalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            DecimalError::ExponentOutOfRange => "decimal exponent out of range",
            DecimalError::Inexact => "value has more fractional digits than the scale allows",
            DecimalError::Overflow => "scaled value out of range",
            DecimalError::Syntax => "invalid JSON number",
        })
    }
}

impl std::error::Error for DecimalError {}

/// An exact decimal number: `coefficient * 10^exponent`.
///
/// The representation is normalized. The coefficient has no leading or
/// trailing zeros, and zero is `0 * 10^0` with no sign. Equality is therefore
/// numeric equality, and the ordering is the numeric ordering.
///
/// For money, read amounts with [`Decimal::to_scaled_i128`], which fails
/// instead of rounding, and write them with [`Decimal::from_scaled_i128`].
///
/// ```
/// use fstp_json::{Decimal, Number};
/// let n = Number::from_lexeme("1234.50").unwrap();
/// let d = n.as_decimal().unwrap();
/// assert_eq!(d.to_scaled_i128(2), Ok(123450));
/// assert!(d.to_scaled_i128(0).is_err());
/// assert_eq!(Decimal::from_scaled_i128(123450, 2).to_string(), "1234.5");
/// ```
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Decimal {
    negative: bool,
    coefficient: Box<str>,
    exponent: i64,
}

/// Plain notation is used while it needs at most this many padding zeros.
const PLAIN_ZEROS_MAX: u64 = 64;

impl Decimal {
    /// The value zero.
    pub fn zero() -> Decimal {
        Decimal {
            negative: false,
            coefficient: Box::from("0"),
            exponent: 0,
        }
    }

    /// Parses a JSON number lexeme exactly.
    pub fn parse(lexeme: &str) -> Result<Decimal, DecimalError> {
        match scan_number(lexeme.as_bytes(), 0) {
            Ok(end) if end == lexeme.len() => Decimal::from_lexeme(lexeme),
            _ => Err(DecimalError::Syntax),
        }
    }

    /// Converts a lexeme that already passed the grammar.
    fn from_lexeme(lexeme: &str) -> Result<Decimal, DecimalError> {
        let (negative, rest) = split_sign(lexeme);
        let (mantissa, exp_part) = match rest.find(['e', 'E']) {
            Some(i) => (
                rest.get(..i).unwrap_or(""),
                rest.get(i.saturating_add(1)..).unwrap_or(""),
            ),
            None => (rest, ""),
        };
        let (int_part, frac_part) = mantissa.split_once('.').unwrap_or((mantissa, ""));
        let digits: Vec<u8> = int_part.bytes().chain(frac_part.bytes()).collect();
        let first = digits.iter().position(|&b| b != b'0');
        let last = digits.iter().rposition(|&b| b != b'0');
        let (Some(first), Some(last)) = (first, last) else {
            return Ok(Decimal::zero());
        };
        let trailing = digits.len().saturating_sub(last).saturating_sub(1);
        let coefficient = digits.get(first..=last).ok_or(DecimalError::Syntax)?;
        let exp = parse_exponent(exp_part)?;
        let frac_len =
            i64::try_from(frac_part.len()).map_err(|_| DecimalError::ExponentOutOfRange)?;
        let trailing = i64::try_from(trailing).map_err(|_| DecimalError::ExponentOutOfRange)?;
        let exponent = exp
            .checked_sub(frac_len)
            .and_then(|e| e.checked_add(trailing))
            .ok_or(DecimalError::ExponentOutOfRange)?;
        let coefficient = core::str::from_utf8(coefficient).map_err(|_| DecimalError::Syntax)?;
        Ok(Decimal {
            negative,
            coefficient: Box::from(coefficient),
            exponent,
        })
    }

    /// Builds `value / 10^scale` exactly.
    pub fn from_scaled_i128(value: i128, scale: u32) -> Decimal {
        if value == 0 {
            return Decimal::zero();
        }
        let digits = value.unsigned_abs().to_string();
        let trimmed = digits.trim_end_matches('0');
        let trailing = digits.len().saturating_sub(trimmed.len());
        // At most 39 trailing zeros, so the conversion cannot fail.
        let trailing = i64::try_from(trailing).unwrap_or(0);
        Decimal {
            negative: value < 0,
            coefficient: Box::from(trimmed),
            exponent: trailing.saturating_sub(i64::from(scale)),
        }
    }

    /// Returns true for zero.
    pub fn is_zero(&self) -> bool {
        &*self.coefficient == "0"
    }

    /// Returns true for values below zero.
    pub fn is_negative(&self) -> bool {
        self.negative
    }

    /// The coefficient digits, with no leading or trailing zeros. `"0"` for zero.
    pub fn coefficient(&self) -> &str {
        &self.coefficient
    }

    /// The power of ten that multiplies the coefficient.
    pub fn exponent(&self) -> i64 {
        self.exponent
    }

    /// The number of significant fractional digits. 0 for integers.
    pub fn scale(&self) -> u64 {
        if self.exponent < 0 {
            self.exponent.unsigned_abs()
        } else {
            0
        }
    }

    /// Returns `value * 10^scale` as an `i128`, exactly.
    ///
    /// Fails with [`DecimalError::Inexact`] when the value has more than
    /// `scale` fractional digits, and with [`DecimalError::Overflow`] when the
    /// result does not fit. It never rounds.
    pub fn to_scaled_i128(&self, scale: u32) -> Result<i128, DecimalError> {
        if self.is_zero() {
            return Ok(0);
        }
        let shift = i128::from(self.exponent).saturating_add(i128::from(scale));
        if shift < 0 {
            return Err(DecimalError::Inexact);
        }
        // i128 holds at most 39 decimal digits.
        let len = i128::try_from(self.coefficient.len()).unwrap_or(i128::MAX);
        if len.saturating_add(shift) > 39 {
            return Err(DecimalError::Overflow);
        }
        let mut acc: i128 = 0;
        for b in self.coefficient.bytes() {
            let d = i128::from(digit_value(b).ok_or(DecimalError::Syntax)?);
            acc = acc.checked_mul(10).ok_or(DecimalError::Overflow)?;
            acc = if self.negative {
                acc.checked_sub(d)
            } else {
                acc.checked_add(d)
            }
            .ok_or(DecimalError::Overflow)?;
        }
        for _ in 0..shift {
            acc = acc.checked_mul(10).ok_or(DecimalError::Overflow)?;
        }
        Ok(acc)
    }

    /// Returns the value as an `i128` when it is an integer in range.
    pub fn to_i128(&self) -> Result<i128, DecimalError> {
        self.to_scaled_i128(0)
    }

    /// The position of the most significant digit: the value lies in
    /// `[10^(a-1), 10^a)` for the returned `a`. Only meaningful for non-zero values.
    fn adjusted(&self) -> i128 {
        let len = i128::try_from(self.coefficient.len()).unwrap_or(i128::MAX);
        i128::from(self.exponent).saturating_add(len)
    }

    fn cmp_magnitude(&self, other: &Decimal) -> Ordering {
        self.adjusted()
            .cmp(&other.adjusted())
            .then_with(|| self.coefficient.cmp(&other.coefficient))
    }
}

impl Ord for Decimal {
    fn cmp(&self, other: &Decimal) -> Ordering {
        let sign = |d: &Decimal| -> i8 {
            if d.is_zero() {
                0
            } else if d.negative {
                -1
            } else {
                1
            }
        };
        match sign(self).cmp(&sign(other)) {
            Ordering::Equal => match sign(self) {
                0 => Ordering::Equal,
                1 => self.cmp_magnitude(other),
                _ => other.cmp_magnitude(self),
            },
            unequal => unequal,
        }
    }
}

impl PartialOrd for Decimal {
    fn partial_cmp(&self, other: &Decimal) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Formats the value as a valid JSON number lexeme.
///
/// Plain notation is used, such as `-12.5` or `1000`, unless that needs more
/// than 64 padding zeros. Then the form is `coefficient` `e` `exponent`.
impl fmt::Display for Decimal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.negative {
            f.write_str("-")?;
        }
        let c = &*self.coefficient;
        let len = u64::try_from(c.len()).unwrap_or(u64::MAX);
        if self.exponent >= 0 {
            let zeros = self.exponent.unsigned_abs();
            if zeros <= PLAIN_ZEROS_MAX {
                f.write_str(c)?;
                for _ in 0..zeros {
                    f.write_str("0")?;
                }
                return Ok(());
            }
            return write!(f, "{c}e{}", self.exponent);
        }
        let frac = self.exponent.unsigned_abs();
        if frac < len {
            let split = usize::try_from(len.saturating_sub(frac)).unwrap_or(0);
            let (int, rest) = c.split_at_checked(split).unwrap_or((c, ""));
            return write!(f, "{int}.{rest}");
        }
        let zeros = frac.saturating_sub(len);
        if zeros <= PLAIN_ZEROS_MAX {
            f.write_str("0.")?;
            for _ in 0..zeros {
                f.write_str("0")?;
            }
            return f.write_str(c);
        }
        write!(f, "{c}e{}", self.exponent)
    }
}

impl fmt::Debug for Decimal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Decimal({self})")
    }
}

impl FromStr for Decimal {
    type Err = DecimalError;

    fn from_str(s: &str) -> Result<Decimal, DecimalError> {
        Decimal::parse(s)
    }
}

impl From<i64> for Decimal {
    fn from(value: i64) -> Decimal {
        Decimal::from_scaled_i128(i128::from(value), 0)
    }
}

impl From<u64> for Decimal {
    fn from(value: u64) -> Decimal {
        Decimal::from_scaled_i128(i128::from(value), 0)
    }
}

/// Parses an exponent part such as `+005` or `-12` into an `i64`.
fn parse_exponent(part: &str) -> Result<i64, DecimalError> {
    if part.is_empty() {
        return Ok(0);
    }
    let (negative, digits) = match part.as_bytes().first() {
        Some(b'-') => (true, part.get(1..).unwrap_or("")),
        Some(b'+') => (false, part.get(1..).unwrap_or("")),
        _ => (false, part),
    };
    let mut acc: i64 = 0;
    for b in digits.bytes() {
        let d = i64::from(digit_value(b).ok_or(DecimalError::Syntax)?);
        acc = acc
            .checked_mul(10)
            .and_then(|a| {
                if negative {
                    a.checked_sub(d)
                } else {
                    a.checked_add(d)
                }
            })
            .ok_or(DecimalError::ExponentOutOfRange)?;
    }
    Ok(acc)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dec(s: &str) -> Decimal {
        Decimal::parse(s).unwrap()
    }

    #[test]
    fn scan_accepts_only_the_rfc8259_grammar() {
        for ok in [
            "0", "-0", "1", "-1", "10", "0.5", "-0.0", "1e5", "1E+5", "1e-05", "0e0",
        ] {
            assert!(Number::from_lexeme(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "-",
            "+1",
            "01",
            "-01",
            "00",
            ".5",
            "1.",
            "1.e5",
            "1e",
            "1e+",
            "NaN",
            "Infinity",
            "-Infinity",
            "0x10",
            " 1",
            "1 ",
            "1_000",
            "١",
        ] {
            assert!(Number::from_lexeme(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn integer_accessors_are_checked() {
        let n = |s: &str| Number::from_lexeme(s).unwrap();
        assert_eq!(n("9223372036854775807").as_i64(), Some(i64::MAX));
        assert_eq!(n("-9223372036854775808").as_i64(), Some(i64::MIN));
        assert_eq!(n("9223372036854775808").as_i64(), None);
        assert_eq!(n("-9223372036854775809").as_i64(), None);
        assert_eq!(n("18446744073709551615").as_u64(), Some(u64::MAX));
        assert_eq!(n("18446744073709551616").as_u64(), None);
        assert_eq!(n("-1").as_u64(), None);
        assert_eq!(n("-0").as_u64(), Some(0));
        assert_eq!(n("1.0").as_i64(), None);
        assert_eq!(n("1e2").as_u64(), None);
        assert_eq!(n("1").as_f64_lossy(), 1.0);
        assert_eq!(n("1e400").as_f64_lossy(), f64::INFINITY);
    }

    #[test]
    fn decimal_is_normalized() {
        assert_eq!(dec("1234.50"), dec("123450e-2"));
        assert_eq!(dec("-0.000"), Decimal::zero());
        assert_eq!(dec("0e99999999999999999999999"), Decimal::zero());
        assert_eq!(dec("100").coefficient(), "1");
        assert_eq!(dec("100").exponent(), 2);
        assert_eq!(dec("0.0120").coefficient(), "12");
        assert_eq!(dec("0.0120").exponent(), -3);
        assert_eq!(dec("0.0120").scale(), 3);
        assert_eq!(
            Decimal::parse("1e99999999999999999999"),
            Err(DecimalError::ExponentOutOfRange)
        );
        assert_eq!(Decimal::parse("1.2.3"), Err(DecimalError::Syntax));
    }

    #[test]
    fn decimal_display_is_a_valid_lexeme() {
        for (input, shown) in [
            ("1234.50", "1234.5"),
            ("-0.001", "-0.001"),
            ("1E3", "1000"),
            ("12e-1", "1.2"),
            ("-0", "0"),
            ("1e65", "1e65"),
            (
                "1e64",
                "10000000000000000000000000000000000000000000000000000000000000000",
            ),
            ("1e-70", "1e-70"),
        ] {
            let d = dec(input);
            assert_eq!(d.to_string(), shown, "{input}");
            assert_eq!(dec(shown), d, "{input}");
            assert!(Number::from_lexeme(shown).is_ok());
        }
    }

    #[test]
    fn decimal_scaling_never_rounds() {
        assert_eq!(dec("12.34").to_scaled_i128(2), Ok(1234));
        assert_eq!(dec("12.34").to_scaled_i128(4), Ok(123_400));
        assert_eq!(dec("12.345").to_scaled_i128(2), Err(DecimalError::Inexact));
        assert_eq!(dec("-12.3").to_scaled_i128(2), Ok(-1230));
        assert_eq!(dec("1e38").to_i128(), Ok(10i128.pow(38)));
        assert_eq!(dec("1e39").to_i128(), Err(DecimalError::Overflow));
        assert_eq!(
            dec("170141183460469231731687303715884105727").to_i128(),
            Ok(i128::MAX)
        );
        assert_eq!(
            dec("-170141183460469231731687303715884105728").to_i128(),
            Ok(i128::MIN)
        );
        assert_eq!(
            dec("170141183460469231731687303715884105728").to_i128(),
            Err(DecimalError::Overflow)
        );
        assert_eq!(dec("1e9999999999").to_i128(), Err(DecimalError::Overflow));
        assert_eq!(Decimal::from_scaled_i128(-500, 2), dec("-5"));
        assert_eq!(
            Decimal::from_scaled_i128(i128::MIN, 0).to_i128(),
            Ok(i128::MIN)
        );
    }

    #[test]
    fn decimal_order_is_numeric() {
        let mut v = [
            dec("10"),
            dec("-1.5"),
            dec("0"),
            dec("9.99"),
            dec("-10"),
            dec("1e-3"),
            dec("-0.001"),
        ];
        v.sort();
        let shown: Vec<String> = v.iter().map(ToString::to_string).collect();
        assert_eq!(shown, ["-10", "-1.5", "-0.001", "0", "0.001", "9.99", "10"]);
        assert!(dec("12") < dec("121"));
        assert!(dec("13") > dec("121e-1"));
    }

    #[test]
    fn ecmascript_formatting_rules() {
        let f = |x: f64| ecmascript_string(x).unwrap();
        assert_eq!(f(0.0), "0");
        assert_eq!(f(-0.0), "0");
        assert_eq!(f(1.0), "1");
        assert_eq!(f(-1.5), "-1.5");
        assert_eq!(f(1e21), "1e+21");
        assert_eq!(f(1e20), "100000000000000000000");
        assert_eq!(f(1e-6), "0.000001");
        assert_eq!(f(1e-7), "1e-7");
        assert_eq!(f(1.5e-7), "1.5e-7");
        assert_eq!(f(123.456), "123.456");
        assert_eq!(f(5e-324), "5e-324");
        assert_eq!(f(f64::MAX), "1.7976931348623157e+308");
        assert_eq!(f(9007199254740992.0), "9007199254740992");
        // Exact ties between two 17-digit candidates take the even digit.
        assert_eq!(
            f(f64::from_bits(0x4314_3ff3_c1cb_0959)),
            "1424953923781206.2"
        );
        assert_eq!(f(2f64.powi(-25)), "2.9802322387695312e-8");
        assert_eq!(f(0.5), "0.5");
        assert_eq!(f(2.5), "2.5");
        assert_eq!(ecmascript_string(f64::NAN), None);
        assert_eq!(ecmascript_string(f64::INFINITY), None);
    }
}
