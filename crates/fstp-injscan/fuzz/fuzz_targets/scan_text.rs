//! Fuzz target for the injection scan (ADR-035, TH-01, TH-26).
//!
//! Checks, for any UTF-8 input:
//! - neither `scan` nor `neutralise` panics;
//! - every detection lies on character boundaries of the input, and at
//!   most `MAX_DETECTIONS` are kept;
//! - the neutralised view is idempotent, never longer than the input,
//!   holds no removed character, and scanning it reports no hidden class.

#![no_main]

use fstp_injscan::{MAX_DETECTIONS, is_removed, neutralise, scan};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let r = scan(s);
    assert!(
        r.detections().len() <= MAX_DETECTIONS,
        "too many detections"
    );
    for d in r.detections() {
        assert!(d.start <= d.end && d.end <= s.len(), "span out of range");
        assert!(
            s.is_char_boundary(d.start) && s.is_char_boundary(d.end),
            "span off a character boundary"
        );
    }
    let n = neutralise(s);
    assert!(n.len() <= s.len(), "the neutralised view grew");
    assert_eq!(neutralise(&n), n, "neutralise is not idempotent");
    assert!(!n.chars().any(is_removed), "a removed character survived");
    assert!(
        !scan(&n).reasons().iter().any(|r| r.is_hidden()),
        "the neutralised view still holds a hidden class"
    );
});
