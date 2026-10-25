//! `numeric` as an exact decimal string.
//!
//! The binary format is a sign, a display scale, a weight and base-10000
//! digits. [`Numeric`] holds the canonical decimal text instead, so no
//! value is ever rounded through a float. The display scale is part of the
//! value: `1.50` and `1.5` are different `Numeric`s, as they are different
//! text in PostgreSQL.

use std::fmt;

use crate::types::{DecodeError, EncodeError, FromSql, IsNull, ToSql, Type, accepts};

const SIGN_POS: u16 = 0x0000;
const SIGN_NEG: u16 = 0x4000;
const SIGN_NAN: u16 = 0xC000;
const SIGN_PINF: u16 = 0xD000;
const SIGN_NINF: u16 = 0xF000;
const DSCALE_MASK: u16 = 0x3FFF;
const NBASE: u16 = 10_000;

/// Most digits before the decimal point that PostgreSQL stores.
pub const NUMERIC_MAX_INTEGER_DIGITS: usize = 131_072;
/// Most digits after the decimal point (the display scale limit).
pub const NUMERIC_MAX_SCALE: usize = 16_383;

/// An exact `numeric` value, held as canonical decimal text.
///
/// Canonical text is `NaN`, `Infinity`, `-Infinity`, or an optional `-`,
/// integer digits without leading zeros (a single `0` when the integer part
/// is zero), and optionally `.` with the fraction digits. Trailing zeros of
/// the fraction are kept, because they are the display scale. Negative zero
/// is normalised to zero, as the server does.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Numeric(String);

impl Numeric {
    /// `NaN`.
    #[must_use]
    pub fn nan() -> Numeric {
        Numeric("NaN".to_owned())
    }

    /// `Infinity` or `-Infinity`.
    #[must_use]
    pub fn infinity(negative: bool) -> Numeric {
        Numeric(if negative { "-Infinity" } else { "Infinity" }.to_owned())
    }

    /// Parses decimal text: an optional sign, digits, and optionally a `.`
    /// with more digits, at least one digit in all. `NaN`, `Infinity` and
    /// `-Infinity` are accepted in any case. Exponents are not accepted.
    ///
    /// # Errors
    ///
    /// Returns a [`DecodeError`] for other text, or when there are more
    /// than [`NUMERIC_MAX_INTEGER_DIGITS`] integer digits or [`NUMERIC_MAX_SCALE`] fraction
    /// digits.
    pub fn parse(s: &str) -> Result<Numeric, DecodeError> {
        let lower = s.to_ascii_lowercase();
        match lower.as_str() {
            "nan" => return Ok(Self::nan()),
            "infinity" | "+infinity" => return Ok(Self::infinity(false)),
            "-infinity" => return Ok(Self::infinity(true)),
            _ => {}
        }
        let bad = DecodeError("numeric must be decimal digits with an optional sign and point");
        let (negative, body) = match s.as_bytes().first() {
            Some(b'-') => (true, s.get(1..).unwrap_or_default()),
            Some(b'+') => (false, s.get(1..).unwrap_or_default()),
            _ => (false, s),
        };
        let (int, frac) = match body.split_once('.') {
            Some((i, f)) => (i, f),
            None => (body, ""),
        };
        if (int.is_empty() && frac.is_empty())
            || !int.bytes().all(|b| b.is_ascii_digit())
            || !frac.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(bad);
        }
        let int = int.trim_start_matches('0');
        if int.len() > NUMERIC_MAX_INTEGER_DIGITS || frac.len() > NUMERIC_MAX_SCALE {
            return Err(DecodeError("numeric has too many digits"));
        }
        Ok(Self::from_parts(negative, int, frac))
    }

    /// Builds canonical text from a sign, integer digits without leading
    /// zeros, and fraction digits.
    fn from_parts(negative: bool, int: &str, frac: &str) -> Numeric {
        let is_zero = int.bytes().all(|b| b == b'0') && frac.bytes().all(|b| b == b'0');
        let mut out = String::with_capacity(int.len().saturating_add(frac.len()).saturating_add(3));
        if negative && !is_zero {
            out.push('-');
        }
        if int.is_empty() {
            out.push('0');
        } else {
            out.push_str(int);
        }
        if !frac.is_empty() {
            out.push('.');
            out.push_str(frac);
        }
        Numeric(out)
    }

    /// The canonical text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True for `NaN`.
    #[must_use]
    pub fn is_nan(&self) -> bool {
        self.0 == "NaN"
    }

    /// True for `Infinity` and `-Infinity`.
    #[must_use]
    pub fn is_infinite(&self) -> bool {
        self.0 == "Infinity" || self.0 == "-Infinity"
    }

    /// The number of fraction digits (the display scale).
    #[must_use]
    pub fn scale(&self) -> usize {
        match self.0.split_once('.') {
            Some((_, f)) if !self.is_nan() && !self.is_infinite() => f.len(),
            _ => 0,
        }
    }

    /// The binary encoding.
    fn encode(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        let header = |out: &mut Vec<u8>, ndigits: u16, weight: i16, sign: u16, dscale: u16| {
            out.extend_from_slice(&ndigits.to_be_bytes());
            out.extend_from_slice(&weight.to_be_bytes());
            out.extend_from_slice(&sign.to_be_bytes());
            out.extend_from_slice(&dscale.to_be_bytes());
        };
        match self.0.as_str() {
            "NaN" => {
                header(out, 0, 0, SIGN_NAN, 0);
                return Ok(());
            }
            "Infinity" => {
                header(out, 0, 0, SIGN_PINF, 0);
                return Ok(());
            }
            "-Infinity" => {
                header(out, 0, 0, SIGN_NINF, 0);
                return Ok(());
            }
            _ => {}
        }
        let too_big = EncodeError("numeric has too many digits");
        let (negative, body) = match self.0.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, self.0.as_str()),
        };
        let (int, frac) = body.split_once('.').unwrap_or((body, ""));
        let int = if int == "0" { "" } else { int };
        let dscale = u16::try_from(frac.len()).map_err(|_| too_big.clone())?;
        if dscale > DSCALE_MASK {
            return Err(too_big);
        }

        // Base-10000 groups: the integer part aligned at the point from the
        // right, the fraction aligned at the point from the left.
        let int_groups = int.len().div_ceil(4);
        let lead = int_groups.saturating_mul(4).saturating_sub(int.len());
        let mut groups: Vec<u16> = Vec::new();
        let mut acc: u16 = 0;
        let mut n = 0usize;
        let int_digits = std::iter::repeat_n(b'0', lead).chain(int.bytes());
        let frac_digits = frac.bytes();
        let frac_pad = frac
            .len()
            .div_ceil(4)
            .saturating_mul(4)
            .saturating_sub(frac.len());
        for b in int_digits
            .chain(frac_digits)
            .chain(std::iter::repeat_n(b'0', frac_pad))
        {
            let d = u16::from(b.wrapping_sub(b'0'));
            acc = acc.wrapping_mul(10).wrapping_add(d);
            n = n.wrapping_add(1);
            if n.is_multiple_of(4) {
                groups.push(acc);
                acc = 0;
            }
        }
        let mut weight = i64::try_from(int_groups)
            .map_err(|_| too_big.clone())?
            .saturating_sub(1);
        // Strip leading and trailing zero groups.
        let first = groups.iter().position(|g| *g != 0);
        let (ndigits, weight, sign, digits): (u16, i16, u16, &[u16]) = match first {
            None => (0, 0, SIGN_POS, &[]),
            Some(first) => {
                let last = groups.iter().rposition(|g| *g != 0).unwrap_or(first);
                weight = weight.saturating_sub(i64::try_from(first).map_err(|_| too_big.clone())?);
                let digits = groups.get(first..=last).unwrap_or_default();
                let nd = u16::try_from(digits.len()).map_err(|_| too_big.clone())?;
                let w = i16::try_from(weight).map_err(|_| too_big.clone())?;
                (nd, w, if negative { SIGN_NEG } else { SIGN_POS }, digits)
            }
        };
        header(out, ndigits, weight, sign, dscale);
        for d in digits {
            out.extend_from_slice(&d.to_be_bytes());
        }
        Ok(())
    }

    /// Decodes the binary format strictly.
    fn decode(raw: &[u8]) -> Result<Numeric, DecodeError> {
        let bad = DecodeError("malformed numeric value");
        let field = |i: usize| -> Result<[u8; 2], DecodeError> {
            let end = i
                .checked_add(2)
                .ok_or(DecodeError("malformed numeric value"))?;
            raw.get(i..end)
                .and_then(|s| s.try_into().ok())
                .ok_or(DecodeError("malformed numeric value"))
        };
        let ndigits = usize::from(u16::from_be_bytes(field(0)?));
        let weight = i64::from(i16::from_be_bytes(field(2)?));
        let sign = u16::from_be_bytes(field(4)?);
        let dscale = u16::from_be_bytes(field(6)?);
        let expected = ndigits
            .checked_mul(2)
            .and_then(|n| n.checked_add(8))
            .ok_or(bad.clone())?;
        if raw.len() != expected {
            return Err(DecodeError("numeric length does not match its digit count"));
        }
        if dscale & DSCALE_MASK != dscale {
            return Err(DecodeError("numeric display scale out of range"));
        }
        match sign {
            SIGN_NAN | SIGN_PINF | SIGN_NINF => {
                // PostgreSQL sends a display scale of 32 for the infinities, an
                // artefact of its short header format, so only the digit count
                // and the weight are checked.
                if ndigits != 0 || weight != 0 {
                    return Err(DecodeError("special numeric value with digits"));
                }
                return Ok(match sign {
                    SIGN_NAN => Self::nan(),
                    SIGN_PINF => Self::infinity(false),
                    _ => Self::infinity(true),
                });
            }
            SIGN_POS | SIGN_NEG => {}
            _ => return Err(DecodeError("numeric has an invalid sign")),
        }
        let mut digits = Vec::with_capacity(ndigits);
        for i in 0..ndigits {
            let at = i
                .checked_mul(2)
                .and_then(|n| n.checked_add(8))
                .ok_or(bad.clone())?;
            let d = u16::from_be_bytes(field(at)?);
            if d >= NBASE {
                return Err(DecodeError("numeric digit out of range"));
            }
            digits.push(d);
        }
        // Group `i` has weight `weight - i`; missing groups are zero.
        let group = |w: i64| -> u16 {
            let i = weight.checked_sub(w).and_then(|i| usize::try_from(i).ok());
            i.and_then(|i| digits.get(i).copied()).unwrap_or(0)
        };
        let mut int = String::new();
        if weight >= 0 {
            let mut w = weight;
            while w >= 0 {
                let g = group(w);
                if int.is_empty() {
                    if g != 0 {
                        int.push_str(&g.to_string());
                    }
                } else {
                    int.push_str(&format!("{g:04}"));
                }
                w = w.saturating_sub(1);
            }
        }
        if int.len() > NUMERIC_MAX_INTEGER_DIGITS.saturating_add(4) {
            return Err(DecodeError("numeric has too many digits"));
        }
        let mut frac = String::with_capacity(usize::from(dscale));
        let mut j: i64 = 1;
        while frac.len() < usize::from(dscale) {
            let g = format!("{:04}", group(j.saturating_neg()));
            for c in g.chars() {
                if frac.len() < usize::from(dscale) {
                    frac.push(c);
                }
            }
            j = j.saturating_add(1);
        }
        Ok(Self::from_parts(sign == SIGN_NEG, &int, &frac))
    }
}

impl fmt::Display for Numeric {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Numeric {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Numeric({})", self.0)
    }
}

impl From<i64> for Numeric {
    fn from(v: i64) -> Numeric {
        Numeric(v.to_string())
    }
}

impl From<i32> for Numeric {
    fn from(v: i32) -> Numeric {
        Numeric(v.to_string())
    }
}

impl std::str::FromStr for Numeric {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Numeric, DecodeError> {
        Numeric::parse(s)
    }
}

accepts!(Numeric, Type::NUMERIC);

impl ToSql for Numeric {
    fn accepts(&self, ty: Type) -> bool {
        ty == Type::NUMERIC
    }

    fn rust_type(&self) -> &'static str {
        "Numeric"
    }

    fn to_sql(&self, _ty: Type, out: &mut Vec<u8>) -> Result<IsNull, EncodeError> {
        self.encode(out)?;
        Ok(IsNull::No)
    }
}

impl FromSql for Numeric {
    fn accepts(ty: Type) -> bool {
        ty == Type::NUMERIC
    }

    fn from_sql(_ty: Type, raw: &[u8]) -> Result<Self, DecodeError> {
        Self::decode(raw)
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    fn bin(s: &str) -> Vec<u8> {
        let mut out = Vec::new();
        Numeric::parse(s).unwrap().encode(&mut out).unwrap();
        out
    }

    fn words(v: &[i32]) -> Vec<u8> {
        let mut out = Vec::new();
        for (i, w) in v.iter().enumerate() {
            if i == 1 {
                out.extend_from_slice(&(*w as i16).to_be_bytes());
            } else {
                out.extend_from_slice(&(*w as u16).to_be_bytes());
            }
        }
        out
    }

    #[test]
    fn canonical_text() {
        assert_eq!(Numeric::parse("007.50").unwrap().as_str(), "7.50");
        assert_eq!(Numeric::parse("-0.00").unwrap().as_str(), "0.00");
        assert_eq!(Numeric::parse(".5").unwrap().as_str(), "0.5");
        assert_eq!(Numeric::parse("5.").unwrap().as_str(), "5");
        assert_eq!(Numeric::parse("+12").unwrap().as_str(), "12");
        assert_eq!(Numeric::parse("nan").unwrap().as_str(), "NaN");
        assert_eq!(Numeric::parse("-INFINITY").unwrap().as_str(), "-Infinity");
        for bad in ["", ".", "-", "1e5", "1.2.3", " 1", "0x10", "--1", "1_000"] {
            assert!(Numeric::parse(bad).is_err(), "{bad:?}");
        }
        assert_eq!(Numeric::parse("1.500").unwrap().scale(), 3);
    }

    #[test]
    fn binary_layout_matches_postgres() {
        // ndigits, weight, sign, dscale, digits...
        assert_eq!(bin("0"), words(&[0, 0, 0, 0]));
        assert_eq!(bin("0.00"), words(&[0, 0, 0, 2]));
        assert_eq!(bin("1"), words(&[1, 0, 0, 0, 1]));
        assert_eq!(bin("10000"), words(&[1, 1, 0, 0, 1]));
        assert_eq!(bin("12345.678"), words(&[3, 1, 0, 3, 1, 2345, 6780]));
        assert_eq!(bin("-0.0001"), words(&[1, -1, 0x4000, 4, 1]));
        assert_eq!(bin("0.00001"), words(&[1, -2, 0, 5, 1000]));
        assert_eq!(bin("NaN"), words(&[0, 0, 0xC000, 0]));
        assert_eq!(bin("-Infinity"), words(&[0, 0, 0xF000, 0]));
    }

    #[test]
    fn decode_is_strict() {
        let dec = |v: &[i32]| Numeric::decode(&words(v));
        assert_eq!(
            dec(&[3, 1, 0, 3, 1, 2345, 6780]).unwrap().as_str(),
            "12345.678"
        );
        assert!(dec(&[1, 0, 0, 0, 10_000]).is_err());
        assert!(dec(&[1, 0, 0x1234, 0, 1]).is_err());
        assert!(dec(&[0, 0, 0, 0x4000]).is_err());
        assert!(dec(&[1, 0, 0xC000, 0, 1]).is_err());
        assert!(dec(&[0, 1, 0xD000, 0]).is_err());
        assert_eq!(dec(&[0, 0, 0xD000, 32]).unwrap().as_str(), "Infinity");
        assert!(Numeric::decode(&words(&[2, 0, 0, 0, 1])).is_err());
        // Digits beyond the display scale are cut, as the server prints them.
        assert_eq!(dec(&[2, 0, 0, 1, 1, 2345]).unwrap().as_str(), "1.2");
        // Negative zero prints as zero.
        assert_eq!(dec(&[1, 0, 0x4000, 0, 0]).unwrap().as_str(), "0");
    }

    #[test]
    fn text_binary_round_trip_property() {
        fstp_prop::check("numeric_round_trip", |g| {
            let int: String = g
                .vec(0..=30, |g| char::from(b'0' + g.u8_in(0..=9)))
                .into_iter()
                .collect();
            let frac: String = g
                .vec(0..=20, |g| char::from(b'0' + g.u8_in(0..=9)))
                .into_iter()
                .collect();
            let neg = g.bool();
            let text = format!(
                "{}{}{}{}",
                if neg { "-" } else { "" },
                if int.is_empty() { "0" } else { &int },
                if frac.is_empty() { "" } else { "." },
                frac
            );
            let n = Numeric::parse(&text).unwrap();
            let mut out = Vec::new();
            n.encode(&mut out).unwrap();
            let back = Numeric::decode(&out).unwrap();
            fstp_prop::prop_assert_eq!(back, n);
            Ok(())
        });
    }
}
