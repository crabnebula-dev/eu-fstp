//! Fuzz target `extract_unicode_marks` (M7 design section 8, TH-01, TH-26).
//!
//! Stage 1 never panics. The cleaned text holds no hidden character, each
//! mark covers exactly one hidden character of the original, and every
//! cleaned span maps to an original span holding the same visible text.

#![no_main]

use fstp_assess::{extract_text, is_hidden};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = core::str::from_utf8(data) else {
        return;
    };
    let x = extract_text(s);
    let t = x.text();
    assert!(!t.chars().any(is_hidden));
    for m in x.marks() {
        let c: Vec<char> = s.get(m.start..m.end).expect("mark span").chars().collect();
        assert!(c.len() == 1 && is_hidden(c[0]));
    }
    let bounds: Vec<usize> = t.char_indices().map(|(i, _)| i).chain([t.len()]).collect();
    let a = bounds[bounds.len() / 3];
    let b = bounds[bounds.len() * 2 / 3];
    let (oa, ob) = x.map().span(a, b).expect("span maps");
    let orig: String = s
        .get(oa..ob)
        .expect("original span")
        .chars()
        .filter(|c| !is_hidden(*c))
        .collect();
    assert_eq!(orig, t[a..b]);
});
