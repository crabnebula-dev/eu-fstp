//! Fuzz target `strip_patterns` (M7 design section 8, T-PRIV-CANARY,
//! TH-26).
//!
//! The pattern scanners and the synthetic name mask never panic, and
//! every hit is a non-empty, non-overlapping span on character boundaries.

#![no_main]

use fstp_assess::{SyntheticNameMask, detect};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = core::str::from_utf8(data) else {
        return;
    };
    let (handle_src, text) = s.split_at(s.char_indices().nth(8).map_or(s.len(), |(i, _)| i));
    let handles = vec![handle_src.to_owned()];
    let hits = detect(text, &handles);
    let mut last = 0;
    for h in &hits {
        assert!(h.start < h.end && h.start >= last);
        assert!(text.get(h.start..h.end).is_some());
        last = h.end;
    }
    let mask = SyntheticNameMask::new(vec![handle_src.to_owned()]);
    let mut last = 0;
    for n in mask.find(text) {
        assert!(n.start < n.end && n.start >= last);
        assert!(text.get(n.start..n.end).is_some());
        last = n.end;
    }
});
