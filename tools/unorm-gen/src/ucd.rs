//! Parsers of the Unicode Character Database files that the normaliser
//! needs (ADR-029). Each parser takes the whole file as text, refuses any
//! line it does not understand with its line number, and never panics on
//! any input. The fuzz target `ucd_parse` runs all of them.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// The largest Unicode code point.
pub const MAX_CODE_POINT: u32 = 0x10_FFFF;

/// Why a file was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// The file, such as `UnicodeData.txt`.
    pub file: &'static str,
    /// The line number, from 1.
    pub line: usize,
    /// What is wrong.
    pub reason: &'static str,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}: {}", self.file, self.line, self.reason)
    }
}

impl std::error::Error for ParseError {}

/// The data of `UnicodeData.txt` that the normaliser uses.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct UnicodeData {
    /// The non-zero canonical combining classes, by code point.
    pub ccc: BTreeMap<u32, u8>,
    /// The one-level canonical decompositions, by code point: one code
    /// point, or two.
    pub canonical: BTreeMap<u32, Vec<u32>>,
}

/// The status C and F mappings of `CaseFolding.txt`, by code point. Each
/// mapping has one to three code points.
pub type CaseFolding = BTreeMap<u32, Vec<u32>>;

/// One line of `NormalizationTest.txt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormCase {
    /// The part the line belongs to, from `@Part<n>`.
    pub part: u8,
    /// The five columns, `c1` to `c5`.
    pub columns: [Vec<u32>; 5],
}

/// Parses one code point written in hex, with 4 to 6 digits.
fn code_point(s: &str) -> Option<u32> {
    if !(4..=6).contains(&s.len()) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(s, 16)
        .ok()
        .filter(|&c| c <= MAX_CODE_POINT)
}

/// Parses a code point that is a Unicode scalar value, so no surrogate.
fn scalar(s: &str) -> Option<u32> {
    code_point(s).filter(|&c| char::from_u32(c).is_some())
}

/// Parses a sequence of scalar values separated by spaces, with
/// `min..=max` members.
fn scalars(s: &str, min: usize, max: usize) -> Option<Vec<u32>> {
    let v = s
        .split(' ')
        .filter(|p| !p.is_empty())
        .map(scalar)
        .collect::<Option<Vec<u32>>>()?;
    (min..=max).contains(&v.len()).then_some(v)
}

/// The data part of a line: the text before any `#`, trimmed.
fn data(line: &str) -> &str {
    line.split('#').next().unwrap_or("").trim()
}

/// Parses `UnicodeData.txt`: fifteen fields per line. Field 0 is the code
/// point, field 3 the canonical combining class, and field 5 the
/// decomposition. A decomposition with a `<tag>` is a compatibility one,
/// which NFC and NFD do not use. A canonical decomposition has one or two
/// code points (the database guarantees it, and the tables rely on it).
pub fn parse_unicode_data(text: &str) -> Result<UnicodeData, ParseError> {
    const FILE: &str = "UnicodeData.txt";
    let mut out = UnicodeData::default();
    let mut seen = BTreeSet::new();
    for (i, line) in text.lines().enumerate() {
        let err = |reason| ParseError {
            file: FILE,
            line: i.saturating_add(1),
            reason,
        };
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split(';').collect();
        let [cp, _, _, ccc, _, decomp, ..] = fields.as_slice() else {
            return Err(err("fewer than fifteen fields"));
        };
        if fields.len() != 15 {
            return Err(err("not fifteen fields"));
        }
        let cp = code_point(cp).ok_or_else(|| err("bad code point"))?;
        if !seen.insert(cp) {
            return Err(err("code point listed twice"));
        }
        let ccc: u8 = ccc.parse().map_err(|_| err("bad combining class"))?;
        if ccc != 0 {
            out.ccc.insert(cp, ccc);
        }
        if decomp.is_empty() || decomp.starts_with('<') {
            continue;
        }
        if char::from_u32(cp).is_none() {
            return Err(err("a surrogate with a decomposition"));
        }
        let d = scalars(decomp, 1, 2).ok_or_else(|| err("bad canonical decomposition"))?;
        out.canonical.insert(cp, d);
    }
    Ok(out)
}

/// Parses `CompositionExclusions.txt`: one code point or one range
/// `A..B` per data line, with comments after `#`.
pub fn parse_composition_exclusions(text: &str) -> Result<BTreeSet<u32>, ParseError> {
    const FILE: &str = "CompositionExclusions.txt";
    let mut out = BTreeSet::new();
    for (i, line) in text.lines().enumerate() {
        let err = |reason| ParseError {
            file: FILE,
            line: i.saturating_add(1),
            reason,
        };
        let d = data(line);
        if d.is_empty() {
            continue;
        }
        let (lo, hi) = match d.split_once("..") {
            Some((a, b)) => (scalar(a.trim()), scalar(b.trim())),
            None => (scalar(d), scalar(d)),
        };
        let (Some(lo), Some(hi)) = (lo, hi) else {
            return Err(err("bad code point"));
        };
        if lo > hi || hi.saturating_sub(lo) > 0x1_0000 {
            return Err(err("bad range"));
        }
        out.extend(lo..=hi);
    }
    Ok(out)
}

/// Parses `CaseFolding.txt` and keeps the status C and F mappings, which
/// make up full case folding. Status S and T are checked for syntax and
/// skipped. A code point with two C or F mappings is refused.
pub fn parse_case_folding(text: &str) -> Result<CaseFolding, ParseError> {
    const FILE: &str = "CaseFolding.txt";
    let mut out = CaseFolding::new();
    for (i, line) in text.lines().enumerate() {
        let err = |reason| ParseError {
            file: FILE,
            line: i.saturating_add(1),
            reason,
        };
        let d = data(line);
        if d.is_empty() {
            continue;
        }
        let fields: Vec<&str> = d.split(';').map(str::trim).collect();
        let [cp, status, mapping, ""] = fields.as_slice() else {
            return Err(err("not three fields and a final semicolon"));
        };
        let cp = scalar(cp).ok_or_else(|| err("bad code point"))?;
        let mapping = scalars(mapping, 1, 3).ok_or_else(|| err("bad mapping"))?;
        match *status {
            "C" | "F" => {
                if out.insert(cp, mapping).is_some() {
                    return Err(err("two full mappings for one code point"));
                }
            }
            "S" | "T" => {}
            _ => return Err(err("bad status")),
        }
    }
    Ok(out)
}

/// Parses `NormalizationTest.txt`: `@Part<n>` lines, and data lines of
/// five columns of scalar values, each column ended by a semicolon.
pub fn parse_normalization_test(text: &str) -> Result<Vec<NormCase>, ParseError> {
    const FILE: &str = "NormalizationTest.txt";
    let mut out = Vec::new();
    let mut part: Option<u8> = None;
    for (i, line) in text.lines().enumerate() {
        let err = |reason| ParseError {
            file: FILE,
            line: i.saturating_add(1),
            reason,
        };
        let d = data(line);
        if d.is_empty() {
            continue;
        }
        if let Some(n) = d.strip_prefix("@Part") {
            part = Some(n.trim().parse().map_err(|_| err("bad part"))?);
            continue;
        }
        let p = part.ok_or_else(|| err("data before the first part"))?;
        let fields: Vec<&str> = d.split(';').collect();
        let [c1, c2, c3, c4, c5, ""] = fields.as_slice() else {
            return Err(err("not five columns"));
        };
        let col = |s: &str| scalars(s, 1, 64).ok_or_else(|| err("bad column"));
        out.push(NormCase {
            part: p,
            columns: [col(c1)?, col(c2)?, col(c3)?, col(c4)?, col(c5)?],
        });
    }
    Ok(out)
}

/// The version that the first line of a UCD file names, as in
/// `# CaseFolding-18.0.0.txt`. `None` when the line has another shape.
pub fn header_version<'a>(text: &'a str, file_stem: &str) -> Option<&'a str> {
    let first = text.lines().next()?;
    let rest = first.strip_prefix("# ")?.strip_prefix(file_stem)?;
    rest.strip_prefix('-')?.strip_suffix(".txt")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR-029: each parser refuses a malformed line with its line number,
    /// and reads the well-formed shapes of the vendored files.
    #[test]
    fn adr029_parsers_read_the_shapes_and_refuse_the_rest() {
        let ud = parse_unicode_data(
            "00C0;LATIN CAPITAL LETTER A WITH GRAVE;Lu;0;L;0041 0300;;;;N;;;;00E0;\n\
             0300;COMBINING GRAVE ACCENT;Mn;230;NSM;;;;;N;;;;;\n\
             00A0;NO-BREAK SPACE;Zs;0;CS;<noBreak> 0020;;;;N;;;;;\n",
        );
        let ud = ud.unwrap();
        assert_eq!(ud.canonical.get(&0xC0), Some(&vec![0x41, 0x300]));
        assert_eq!(ud.ccc.get(&0x300), Some(&230));
        assert!(!ud.canonical.contains_key(&0xA0));

        let bad = parse_unicode_data("0041;A;Lu;0;L;;;;;N;;;;\n").unwrap_err();
        assert_eq!(bad.line, 1);
        assert!(parse_unicode_data("0041;A;Lu;x;L;;;;;N;;;;;\n").is_err());
        assert!(parse_unicode_data("0041;A;Lu;0;L;0042 0043 0044;;;;N;;;;;\n").is_err());
        assert!(parse_unicode_data("0041;A;Lu;0;L;D800;;;;N;;;;;\n").is_err());
        assert!(
            parse_unicode_data("0041;A;Lu;0;L;;;;;N;;;;;\n0041;A;Lu;0;L;;;;;N;;;;;\n").is_err()
        );

        let ex = parse_composition_exclusions("# c\n0958 # x\n\n2ADC\n0340..0341\n").unwrap();
        assert_eq!(
            ex.into_iter().collect::<Vec<_>>(),
            vec![0x340, 0x341, 0x958, 0x2ADC]
        );
        assert!(parse_composition_exclusions("0341..0340\n").is_err());
        assert!(parse_composition_exclusions("zz\n").is_err());

        let cf = parse_case_folding(
            "0041; C; 0061; # A\n00DF; F; 0073 0073; # s\n1E9E; S; 00DF; # x\n0049; T; 0131; # i\n",
        )
        .unwrap();
        assert_eq!(cf.get(&0x41), Some(&vec![0x61]));
        assert_eq!(cf.get(&0xDF), Some(&vec![0x73, 0x73]));
        assert!(!cf.contains_key(&0x1E9E));
        assert!(!cf.contains_key(&0x49));
        assert!(parse_case_folding("0041; X; 0061; # A\n").is_err());
        assert!(parse_case_folding("0041; C; 0061\n").is_err());
        assert!(parse_case_folding("0041; C; 0061;\n0041; F; 0061 0061;\n").is_err());

        let nt = parse_normalization_test("@Part0 # x\n1E0A;1E0A;0044 0307;1E0A;0044 0307; # c\n")
            .unwrap();
        assert_eq!(nt.len(), 1);
        assert_eq!(nt[0].columns[2], vec![0x44, 0x307]);
        assert!(parse_normalization_test("1E0A;1E0A;0044 0307;1E0A;0044 0307;\n").is_err());
        assert!(parse_normalization_test("@Part0\n1E0A;1E0A;1E0A;1E0A;\n").is_err());

        assert_eq!(
            header_version("# CaseFolding-18.0.0.txt\n", "CaseFolding"),
            Some("18.0.0")
        );
        assert_eq!(header_version("# Other-18.0.0.txt\n", "CaseFolding"), None);
    }
}
