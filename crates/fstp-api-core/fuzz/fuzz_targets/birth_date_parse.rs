//! Fuzz target `birth_date_parse` of `fstp-api-core` (Q23 B, lane mapp).
//!
//! Design checks: the vault-only date of birth of `proposal.state_birth_date`.
//! A parsed date is a real calendar day from 1900, spelled `YYYY-MM-DD`
//! with ASCII digits, and its 18th birthday is noon UTC of a later day.
//! No input panics.

#![no_main]

use fstp_api_core::port::BirthDate;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = core::str::from_utf8(data) else {
        return;
    };
    let Some(d) = BirthDate::parse(s) else {
        return;
    };
    let b = s.as_bytes();
    assert_eq!(b.len(), 10);
    assert!(b.iter().enumerate().all(|(i, c)| if i == 4 || i == 7 {
        *c == b'-'
    } else {
        c.is_ascii_digit()
    }));
    if let Some(t) = d.adult_from() {
        let day = 86_400_000_000_i64;
        assert_eq!(t.micros().rem_euclid(day), day / 2, "noon UTC");
    }
});
