//! Stage 1 (M7 design section 3.2): extraction records and removes
//! zero-width, bidi-control and tag characters with their spans, and the
//! span map gives every cleaned span back as an original span (R-LA-02).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use fstp_assess::{MarkKind, extract_text};
use fstp_prop::{check, prop_assert, prop_assert_eq};

const HIDDEN: [char; 7] = [
    '\u{200b}',
    '\u{200d}',
    '\u{feff}',
    '\u{202e}',
    '\u{2066}',
    '\u{e0041}',
    '\u{e007f}',
];

/// TH-01: hidden characters are removed and recorded with their kind.
#[test]
fn th01_extract_records_and_removes_hidden_characters() {
    let s = "a\u{200b}b\u{202e}c\u{e0041}d";
    let x = extract_text(s);
    assert_eq!(x.text(), "abcd");
    let kinds: Vec<MarkKind> = x.marks().iter().map(|m| m.kind).collect();
    assert_eq!(kinds, [MarkKind::ZeroWidth, MarkKind::Bidi, MarkKind::Tag]);
    for m in x.marks() {
        assert!(s[m.start..m.end].chars().count() == 1);
    }
}

/// R-LA-02: cleaned text equals the original without hidden characters,
/// and every cleaned span maps to an original span holding the same text
/// once hidden characters are removed.
#[test]
fn r_la_02_extract_span_map_round_trips() {
    check("r_la_02_extract_span_map_round_trips", |g| {
        let mut s = String::new();
        for _ in 0..g.usize_in(0..=12) {
            if g.bool() {
                s.push(*g.pick(&HIDDEN));
            } else {
                s.push_str(&g.string(0..=6));
            }
        }
        let x = extract_text(&s);
        let expected: String = s
            .chars()
            .filter(|c| !HIDDEN.contains(c) && !fstp_assess::is_hidden(*c))
            .collect();
        prop_assert_eq!(x.text(), expected.as_str());
        let t = x.text();
        let bounds: Vec<usize> = t.char_indices().map(|(i, _)| i).chain([t.len()]).collect();
        let a = *g.pick(&bounds);
        let b = *g.pick(&bounds);
        let (a, b) = if a <= b { (a, b) } else { (b, a) };
        let (oa, ob) = x.map().span(a, b).unwrap();
        prop_assert!(oa <= ob && ob <= s.len());
        let orig: String = s[oa..ob]
            .chars()
            .filter(|c| !fstp_assess::is_hidden(*c))
            .collect();
        prop_assert_eq!(orig.as_str(), &t[a..b]);
        Ok(())
    });
}
