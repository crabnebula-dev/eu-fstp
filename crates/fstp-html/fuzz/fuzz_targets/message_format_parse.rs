//! Fuzz target `message_format_parse` of `fstp-html` (TH-26, H-05, M4 design section 9).
//!
//! Design checks: catalogue syntax.
//!
//! This target checks that no input panics and that the result is the
//! same twice. An accepted message must meet the outer bounds of the
//! grammar in `crates/fstp-html/tests/common/message.rs`: UTF-8 of 1 to
//! 4096 bytes, with no control character except tab and line feed. The
//! tests compare the parser with the full reference grammar.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = fstp_html::parse_message_format(data);
    assert_eq!(first, fstp_html::parse_message_format(data));
    match first {
        Ok(_) => {
            assert!(
                !data.is_empty() && data.len() <= 4096,
                "accepted out of bounds"
            );
            let s = std::str::from_utf8(data).ok();
            assert!(s.is_some(), "accepted bytes that are not UTF-8");
            let controls = s
                .unwrap_or_default()
                .chars()
                .any(|c| c.is_control() && c != '\t' && c != '\n');
            assert!(!controls, "accepted a control character");
        }
        Err(e) => assert!(!e.to_string().is_empty()),
    }
});
