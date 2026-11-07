//! Fuzz target `branding_parse` of `fstp-brand` (I-68, I-70, M9 design
//! section 3, lane B1).
//!
//! Checks: the parser is total over any bytes. An accepted input is typed
//! data: the name holds no angle bracket or control character, the
//! canonical text parses back to the same tokens, and the failing pairs
//! are exactly those that fail `meets_aa`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(t) = fstp_brand::parse(data) else {
        return;
    };
    let name = t.name.as_str();
    assert!(!name.is_empty() && name.len() <= fstp_brand::MAX_NAME_BYTES);
    assert!(!name.chars().any(|c| c.is_control() || c == '<' || c == '>'));
    let text = fstp_brand::canonical(&t);
    assert_eq!(fstp_brand::parse(text.as_bytes()).ok().as_ref(), Some(&t));
    let failing = fstp_brand::failing_pairs(&t);
    for p in fstp_brand::Pair::ALL {
        let (fg, bg) = p.colours(&t);
        assert_eq!(failing.contains(p), !fstp_creator::meets_aa(fg, bg));
    }
});
