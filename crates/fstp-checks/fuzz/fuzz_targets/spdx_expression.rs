//! R-PR-02, TH-26: the SPDX expression parser never panics, and a parsed
//! expression renders to a form that parses to the same tree.
#![no_main]

use fstp_checks::spdx::parse;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(e) = parse(s) {
        let again = parse(&e.to_string());
        assert_eq!(again.as_ref(), Ok(&e));
        assert!(e.same(&e));
    }
});
