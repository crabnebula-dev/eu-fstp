//! R-PR-02, TH-26: licence detection on untrusted licence file bytes
//! never panics, and a found expression is valid.
#![no_main]

use fstp_checks::detect::{Detected, detect};
use fstp_checks::spdx::parse;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Detected::Found(e) = detect(data) {
        assert!(parse(&e.to_string()).is_ok());
    }
});
