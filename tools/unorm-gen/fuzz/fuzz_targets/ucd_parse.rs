//! Fuzz target for the Unicode Character Database parsers of `unorm-gen`
//! (ADR-029, TH-26).
//!
//! Checks, for any UTF-8 input:
//! - no parser panics, and an error names a line of the input;
//! - what `parse_unicode_data` accepts, `build` turns into tables or
//!   refuses without a panic, and `render` renders.

#![no_main]

use libfuzzer_sys::fuzz_target;
use unorm_gen::ucd;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let lines = text.lines().count();
    let line_ok = |e: &ucd::ParseError| e.line >= 1 && e.line <= lines;
    let ud = ucd::parse_unicode_data(text);
    let ex = ucd::parse_composition_exclusions(text);
    let cf = ucd::parse_case_folding(text);
    let nt = ucd::parse_normalization_test(text);
    for e in [
        ud.as_ref().err(),
        ex.as_ref().err(),
        cf.as_ref().err(),
        nt.as_ref().err(),
    ]
    .into_iter()
    .flatten()
    {
        assert!(line_ok(e), "error line {} outside 1..={lines}", e.line);
    }
    let _ = ucd::header_version(text, "CaseFolding");
    if let Ok(ud) = ud {
        let ex = ex.unwrap_or_default();
        let cf = cf.unwrap_or_default();
        if let Ok(t) = unorm_gen::build(&ud, &ex, &cf) {
            let _ = unorm_gen::render((18, 0, 0), &t);
        }
    }
});
