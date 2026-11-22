//! Fuzz target `wording_text_parse` of `fstp-report` (ADR-036 section 1,
//! L-08, TH-26).
//!
//! Over arbitrary bytes taken as an approved wording text:
//!
//! - parsing never panics, and parsing one input twice gives the same
//!   answer;
//! - an accepted text is its pieces joined again, each slot written
//!   `{{name}}`;
//! - an accepted text names only slots of the closed list.

#![no_main]

use fstp_report::wording::{Piece, Slot, parse_text};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let first = parse_text(text);
    assert_eq!(first, parse_text(text), "the parser is not deterministic");
    let Ok(pieces) = first else {
        return;
    };
    let mut joined = String::new();
    for p in &pieces {
        match p {
            Piece::Text(t) => joined.push_str(t),
            Piece::Slot(s) => {
                assert_eq!(Slot::from_name(s.name()), Some(*s));
                joined.push_str("{{");
                joined.push_str(s.name());
                joined.push_str("}}");
            }
        }
    }
    assert_eq!(joined, text, "an accepted text is its pieces");
});
