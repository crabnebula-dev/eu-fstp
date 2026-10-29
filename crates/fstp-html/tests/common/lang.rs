//! `Accept-Language`: the grammar and locale negotiation (R-NF-04, TH-26).
//!
//! Interim reading, pending Daniel. The grammar is RFC 9110 section
//! 12.5.4 with the weight of section 12.4.2 and the basic language range
//! of RFC 4647 section 2.1:
//!
//! - `#( language-range [ OWS ";" OWS "q=" qvalue ] )`, where empty list
//!   elements are allowed and `q` is case-insensitive;
//! - a range is `*` or `1*8ALPHA *( "-" 1*8alphanum )`;
//! - a qvalue is `0` with up to three decimals, or `1` with up to three
//!   zero decimals, held here as a whole number of thousandths;
//! - OWS is spaces and tabs.
//!
//! The parser refuses a value over 4096 bytes, any byte outside ASCII,
//! and more than 32 ranges, so its work stays bounded.
//!
//! Negotiation is RFC 4647 section 3.4 lookup. Ranges are tried by
//! descending weight, ties in header order. Each range is truncated one
//! subtag at a time, and a singleton left last is removed too. The first
//! available locale equal to a candidate, ignoring case, wins. `*` and
//! ranges of weight 0 never select. A locale named by a range of weight 0
//! is never chosen. With no match, or a header that does not parse, the
//! default locale is chosen.

/// The longest header value, in bytes.
pub(crate) const MAX_HEADER_BYTES: usize = 4096;
/// The most ranges in one header.
pub(crate) const MAX_RANGES: usize = 32;

/// One language range with its weight in thousandths.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Range {
    /// The range, lower-cased.
    pub(crate) range: String,
    /// The weight, 0 to 1000.
    pub(crate) q: u16,
}

fn is_ows(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

fn trim_ows(s: &[u8]) -> &[u8] {
    let start = s.iter().position(|&b| !is_ows(b)).unwrap_or(s.len());
    let end = s.iter().rposition(|&b| !is_ows(b)).map_or(start, |e| e + 1);
    s.get(start..end).unwrap_or(&[])
}

fn is_range(r: &[u8]) -> bool {
    if r == b"*" {
        return true;
    }
    let mut first = true;
    for sub in r.split(|&b| b == b'-') {
        let ok_len = (1..=8).contains(&sub.len());
        let ok_chars = if first {
            sub.iter().all(u8::is_ascii_alphabetic)
        } else {
            sub.iter().all(u8::is_ascii_alphanumeric)
        };
        if !ok_len || !ok_chars {
            return false;
        }
        first = false;
    }
    true
}

fn qvalue(v: &[u8]) -> Option<u16> {
    let (int, frac) = match v.iter().position(|&b| b == b'.') {
        Some(i) => (v.get(..i)?, Some(v.get(i + 1..)?)),
        None => (v, None),
    };
    let frac = frac.unwrap_or(&[]);
    if frac.len() > 3 || !frac.iter().all(u8::is_ascii_digit) {
        return None;
    }
    match int {
        b"0" => {
            let mut q: u16 = 0;
            for i in 0..3 {
                let d = frac.get(i).map_or(0, |&b| u16::from(b - b'0'));
                q = q * 10 + d;
            }
            Some(q)
        }
        b"1" if frac.iter().all(|&b| b == b'0') => Some(1000),
        _ => None,
    }
}

/// Parses a header value with the reference grammar.
pub(crate) fn parse(bytes: &[u8]) -> Result<Vec<Range>, String> {
    if bytes.len() > MAX_HEADER_BYTES {
        return Err(format!("header of {} bytes", bytes.len()));
    }
    if !bytes.is_ascii() {
        return Err("a byte outside ASCII".to_owned());
    }
    let mut out = Vec::new();
    for element in bytes.split(|&b| b == b',') {
        let element = trim_ows(element);
        if element.is_empty() {
            continue;
        }
        let (range, weight) = match element.iter().position(|&b| b == b';') {
            Some(i) => (
                trim_ows(element.get(..i).unwrap_or(&[])),
                Some(trim_ows(element.get(i + 1..).unwrap_or(&[]))),
            ),
            None => (element, None),
        };
        if !is_range(range) {
            return Err(format!("bad range {:?}", String::from_utf8_lossy(range)));
        }
        let q = match weight {
            None => 1000,
            Some(w) => {
                let v = w
                    .strip_prefix(b"q=")
                    .or_else(|| w.strip_prefix(b"Q="))
                    .ok_or("a parameter other than q")?;
                qvalue(v).ok_or("bad qvalue")?
            }
        };
        out.push(Range {
            range: String::from_utf8_lossy(range).to_ascii_lowercase(),
            q,
        });
        if out.len() > MAX_RANGES {
            return Err("too many ranges".to_owned());
        }
    }
    Ok(out)
}

/// Chooses a locale from `available` for `header`, or `default`.
pub(crate) fn negotiate(header: &[u8], available: &[&str], default: &str) -> String {
    let Ok(mut ranges) = parse(header) else {
        return default.to_owned();
    };
    let excluded = |a: &str| {
        ranges
            .iter()
            .any(|r| r.q == 0 && r.range == a.to_ascii_lowercase())
    };
    let excluded: Vec<bool> = available.iter().map(|a| excluded(a)).collect();
    ranges.sort_by_key(|r| std::cmp::Reverse(r.q));
    for r in ranges.iter().filter(|r| r.q > 0 && r.range != "*") {
        let mut cand = r.range.clone();
        loop {
            let hit = available
                .iter()
                .zip(&excluded)
                .find(|(a, ex)| !**ex && a.to_ascii_lowercase() == cand);
            if let Some((a, _)) = hit {
                return (*a).to_owned();
            }
            match cand.rfind('-') {
                None => break,
                Some(i) => {
                    cand.truncate(i);
                    let n = cand.len();
                    if n >= 2 && cand.as_bytes().get(n - 2) == Some(&b'-') {
                        cand.truncate(n - 2);
                    }
                }
            }
        }
    }
    default.to_owned()
}

/// The negotiation examples shared by the reference and the production
/// test: header, available locales, default, expected choice.
pub(crate) const EXAMPLES: &[(&str, &[&str], &str, &str)] = &[
    ("", &["en", "fr"], "en", "en"),
    ("fr", &["en", "fr"], "en", "fr"),
    ("FR", &["en", "fr"], "en", "fr"),
    ("fr-CA", &["en", "fr"], "en", "fr"),
    ("fr-CA, en;q=0.9", &["en", "fr-CA", "fr"], "en", "fr-CA"),
    ("de, fr;q=0.5", &["en", "fr"], "en", "fr"),
    ("de", &["en", "fr"], "en", "en"),
    ("en;q=0.5, fr;q=0.8", &["en", "fr"], "en", "fr"),
    ("en;q=0.8, fr;q=0.8", &["en", "fr"], "en", "en"),
    ("fr;q=0.8, en;q=0.8", &["en", "fr"], "en", "fr"),
    ("fr;q=0, *", &["en", "fr"], "en", "en"),
    ("*", &["fr", "en"], "en", "en"),
    ("fr-x-foo", &["en", "fr"], "en", "fr"),
    ("zh-Hant-TW", &["en", "zh-Hant"], "en", "zh-Hant"),
    ("fr;q=0, fr-CA", &["en", "fr"], "en", "en"),
    ("en_GB", &["en", "fr"], "fr", "fr"),
    ("fr;q=2", &["en", "fr"], "en", "en"),
];
