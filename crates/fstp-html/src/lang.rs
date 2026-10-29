//! `Accept-Language` parsing and locale negotiation (R-NF-04, TH-26).
//!
//! Interim reading, pending Daniel. The grammar is RFC 9110 section
//! 12.5.4 with the weight of section 12.4.2 and the basic language range
//! of RFC 4647 section 2.1:
//!
//! - `#( language-range [ OWS ";" OWS "q=" qvalue ] )`, where empty list
//!   elements are allowed and `q` is case-insensitive;
//! - a range is `*` or `1*8ALPHA *( "-" 1*8alphanum )`;
//! - a qvalue is `0` with up to three decimals, or `1` with up to three
//!   zero decimals, held as a whole number of thousandths;
//! - OWS is spaces and tabs.
//!
//! The parser refuses a value over 4096 bytes, any byte outside ASCII,
//! and more than 32 ranges, so its work stays bounded. The header is
//! attacker-controlled, so the parser is fuzzed (`accept_language_parse`).
//!
//! Negotiation is RFC 4647 section 3.4 lookup. Ranges are tried by
//! descending weight, ties in header order. Each range is truncated one
//! subtag at a time, and a singleton left last is removed too. The first
//! available locale equal to a candidate, ignoring case, wins. `*` and
//! ranges of weight 0 never select. A locale named by a range of weight 0
//! is never chosen. With no match the default locale is chosen.

use crate::HtmlError;

/// The longest header value, in bytes.
pub const MAX_ACCEPT_LANGUAGE_BYTES: usize = 4096;

/// The most language ranges in one header.
pub const MAX_LANGUAGE_RANGES: usize = 32;

/// One language range with its weight.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LanguageRange {
    range: String,
    weight: u16,
}

impl LanguageRange {
    /// The range, lower-cased, or `*`.
    pub fn range(&self) -> &str {
        &self.range
    }

    /// The weight in thousandths, 0 to 1000.
    pub fn weight(&self) -> u16 {
        self.weight
    }
}

/// A parsed `Accept-Language` header: its ranges in header order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptLanguage {
    ranges: Vec<LanguageRange>,
}

fn refuse(rule: &'static str) -> HtmlError {
    HtmlError::AcceptLanguage { rule }
}

fn is_ows(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

fn trim_ows(s: &[u8]) -> &[u8] {
    let start = s.iter().position(|&b| !is_ows(b)).unwrap_or(s.len());
    let end = s
        .iter()
        .rposition(|&b| !is_ows(b))
        .map_or(start, |e| e.saturating_add(1));
    s.get(start..end).unwrap_or(&[])
}

fn is_range(r: &[u8]) -> bool {
    if r == b"*" {
        return true;
    }
    r.split(|&b| b == b'-').enumerate().all(|(i, sub)| {
        (1..=8).contains(&sub.len())
            && if i == 0 {
                sub.iter().all(u8::is_ascii_alphabetic)
            } else {
                sub.iter().all(u8::is_ascii_alphanumeric)
            }
    })
}

/// A qvalue in thousandths.
fn qvalue(v: &[u8]) -> Option<u16> {
    let (int, frac): (&[u8], &[u8]) = match v.iter().position(|&b| b == b'.') {
        Some(i) => (v.get(..i)?, v.get(i.saturating_add(1)..)?),
        None => (v, &[]),
    };
    if frac.len() > 3 || !frac.iter().all(u8::is_ascii_digit) {
        return None;
    }
    match int {
        b"0" => {
            let mut q: u16 = 0;
            for i in 0..3 {
                let d = frac
                    .get(i)
                    .map_or(0, |&b| u16::from(b.saturating_sub(b'0')));
                q = q.saturating_mul(10).saturating_add(d);
            }
            Some(q)
        }
        b"1" if frac.iter().all(|&b| b == b'0') => Some(1000),
        _ => None,
    }
}

/// Parses an `Accept-Language` header value. Fuzzed
/// (`accept_language_parse`).
pub fn parse_accept_language(bytes: &[u8]) -> Result<AcceptLanguage, HtmlError> {
    if bytes.len() > MAX_ACCEPT_LANGUAGE_BYTES {
        return Err(refuse("the header is over 4096 bytes"));
    }
    if !bytes.is_ascii() {
        return Err(refuse("the header holds a byte outside ASCII"));
    }
    let mut ranges = Vec::new();
    for element in bytes.split(|&b| b == b',') {
        let element = trim_ows(element);
        if element.is_empty() {
            continue;
        }
        let (range, weight) = match element.iter().position(|&b| b == b';') {
            Some(i) => (
                trim_ows(element.get(..i).unwrap_or(&[])),
                Some(trim_ows(element.get(i.saturating_add(1)..).unwrap_or(&[]))),
            ),
            None => (element, None),
        };
        if !is_range(range) {
            return Err(refuse("a language range is outside the grammar"));
        }
        let weight = match weight {
            None => 1000,
            Some(w) => {
                let v = w
                    .strip_prefix(b"q=")
                    .or_else(|| w.strip_prefix(b"Q="))
                    .ok_or(refuse("a parameter other than q"))?;
                qvalue(v).ok_or(refuse("a weight outside the grammar"))?
            }
        };
        ranges.push(LanguageRange {
            range: String::from_utf8_lossy(range).to_ascii_lowercase(),
            weight,
        });
        if ranges.len() > MAX_LANGUAGE_RANGES {
            return Err(refuse("the header holds more than 32 ranges"));
        }
    }
    Ok(AcceptLanguage { ranges })
}

impl AcceptLanguage {
    /// The ranges, in header order.
    pub fn ranges(&self) -> &[LanguageRange] {
        &self.ranges
    }

    /// The locale of `available` this header selects, or `default`.
    pub fn choose<'a>(&self, available: &[&'a str], default: &'a str) -> &'a str {
        let lower: Vec<String> = available.iter().map(|a| a.to_ascii_lowercase()).collect();
        let excluded: Vec<bool> = lower
            .iter()
            .map(|a| self.ranges.iter().any(|r| r.weight == 0 && r.range == *a))
            .collect();
        let mut order: Vec<&LanguageRange> = self
            .ranges
            .iter()
            .filter(|r| r.weight > 0 && r.range != "*")
            .collect();
        order.sort_by_key(|r| std::cmp::Reverse(r.weight));
        for r in order {
            let mut cand = r.range.clone();
            loop {
                let hit = available
                    .iter()
                    .zip(&lower)
                    .zip(&excluded)
                    .find(|((_, l), ex)| !**ex && **l == cand);
                if let Some(((a, _), _)) = hit {
                    return a;
                }
                let Some(i) = cand.rfind('-') else {
                    break;
                };
                cand.truncate(i);
                let n = cand.len();
                if n >= 2 && cand.as_bytes().get(n.saturating_sub(2)) == Some(&b'-') {
                    cand.truncate(n.saturating_sub(2));
                }
            }
        }
        default
    }
}

/// The locale of `available` that `header` selects. Returns `default`
/// when nothing matches or the header does not parse.
pub fn negotiate_locale(header: &[u8], available: &[&str], default: &str) -> String {
    match parse_accept_language(header) {
        Ok(al) => al.choose(available, default).to_owned(),
        Err(_) => default.to_owned(),
    }
}
