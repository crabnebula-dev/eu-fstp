//! Fuzz target for the percentage parser (TH-26, H-05).
//!
//! Checks, for any UTF-8 input:
//! - parsing never panics;
//! - every accepted value lies from 0.00 to 100.00;
//! - every accepted text is the canonical two-decimal spelling of its value,
//!   computed here from the basis points.

#![no_main]

use fstp_money::Percent;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    match Percent::parse(text) {
        Ok(p) => {
            let bp = p.bp();
            assert!(bp <= 10_000, "above 100.00");
            let canonical = format!("{}.{:02}", bp / 100, bp % 100);
            assert_eq!(canonical, text, "accepted a non-canonical spelling");
        }
        Err(e) => {
            let _ = e.to_string();
        }
    }
});
