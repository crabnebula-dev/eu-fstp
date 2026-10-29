//! Fuzz target `accept_language_parse` of `fstp-html` (TH-26, H-05, M4 design section 9).
//!
//! Design checks: the Accept-Language header.
//!
//! This target checks that no input panics and that the result is the
//! same twice. An accepted header must meet the outer bounds of the
//! grammar in `crates/fstp-html/tests/common/lang.rs`: at most 4096
//! bytes, of printable ASCII and tab only. The tests compare the
//! parser with the full reference grammar.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = fstp_html::parse_accept_language(data);
    assert_eq!(first, fstp_html::parse_accept_language(data));
    match first {
        Ok(_) => {
            assert!(data.len() <= 4096, "accepted a header over 4096 bytes");
            assert!(
                data.iter()
                    .all(|&b| b == b'\t' || (0x20..0x7f).contains(&b)),
                "accepted a byte outside printable ASCII and tab"
            );
        }
        Err(e) => assert!(!e.to_string().is_empty()),
    }
});
