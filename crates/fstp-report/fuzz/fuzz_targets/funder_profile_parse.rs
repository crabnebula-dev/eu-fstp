//! Fuzz target `funder_profile_parse` of `fstp-report` (M9 design
//! sections 2.5 and 5, TH-26, I-44).
//!
//! Over arbitrary bytes taken as a funder profile file:
//!
//! - parsing never panics, and parsing one input twice gives the same
//!   answer;
//! - an accepted profile names only ledger folds, each at a level its
//!   output takes and the fold defines (I-44);
//! - an accepted profile pins the SHA-256 of the bytes it was read from.

#![no_main]

use fstp_report::profile::{Level, parse_profile};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = parse_profile(data);
    assert_eq!(first, parse_profile(data), "the parser is not deterministic");
    let Ok(p) = first else {
        return;
    };
    assert_eq!(p.digest().bytes(), fstp_crypto::sha256(data));
    for o in p.outputs() {
        for f in o.fields() {
            assert!(f.figure().levels().contains(&f.level()));
            assert!(Level::of_output(o.kind()).contains(&f.level()));
        }
    }
});
