//! Fuzz target for RFC 8785 canonical output (TH-26, H-05).
//!
//! Checks, for any input that parses:
//! - canonical output is a fixed point: canonicalizing its parse gives the
//!   same bytes, in both number modes;
//! - canonical output is already compact output of its own parse, so its
//!   members are sorted and its numbers are canonical;
//! - strict mode accepts every canonical output, and agrees with lossy mode
//!   whenever it succeeds;
//! - the output never holds whitespace outside strings or raw control
//!   characters.

#![no_main]

use fstp_json::{
    CanonicalOptions, cmp_utf16, parse, parse_str, to_canonical, to_canonical_with, to_compact,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(v) = parse(data) else {
        return;
    };
    let lossy = CanonicalOptions {
        allow_lossy_numbers: true,
    };
    let strict = to_canonical(&v);
    let loose = to_canonical_with(&v, lossy);
    if let Ok(s) = &strict {
        assert_eq!(loose.as_ref().ok(), Some(s), "strict and lossy disagree");
    }
    let Ok(text) = loose else {
        assert!(strict.is_err());
        return;
    };
    assert!(text.bytes().all(|b| b >= 0x20), "raw control character");

    let w = parse_str(&text).expect("canonical output parses");
    assert_eq!(
        to_compact(&w),
        text,
        "canonical output is not compact and sorted"
    );
    assert_eq!(
        to_canonical(&w).as_deref(),
        Ok(text.as_str()),
        "strict rejects canonical output"
    );
    assert_eq!(
        to_canonical_with(&w, lossy).as_deref(),
        Ok(text.as_str()),
        "not a fixed point"
    );

    // Members appear in UTF-16 order at every level.
    let mut stack = vec![&w];
    while let Some(node) = stack.pop() {
        if let Some(a) = node.as_array() {
            stack.extend(a.iter());
        }
        if let Some(o) = node.as_object() {
            let keys: Vec<&str> = o.keys().collect();
            assert!(
                keys.windows(2).all(|p| cmp_utf16(p[0], p[1]).is_lt()),
                "unsorted members"
            );
            stack.extend(o.values());
        }
    }
});
