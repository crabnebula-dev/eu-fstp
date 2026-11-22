//! The 6-digit registration code (Daniel, 2026-11-22, ADR-008
//! "Registration code"): the code is a function of the proof token, so
//! the link and the code in one email name the same proof.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_auth::ceremony::{SIGNUP_CODE_DIGITS, parse_signup_code, signup_code};
use fstp_prop::check;

/// ADR-008: every proof token gives exactly 6 ASCII digits, the same ones
/// every time, and the parser reads them back.
#[test]
fn adr008_signup_code_is_six_digits_of_the_token() {
    check("adr008_signup_code_is_six_digits_of_the_token", |g| {
        let t: [u8; 32] = g.bytes(32..=32).try_into().unwrap();
        let c = signup_code(&t);
        if c.len() != SIGNUP_CODE_DIGITS || !c.iter().all(u8::is_ascii_digit) {
            return Err(format!("{c:?}"));
        }
        if signup_code(&t) != c {
            return Err("not deterministic".to_owned());
        }
        match parse_signup_code(std::str::from_utf8(&c).unwrap()) {
            Some(back) if back == c => Ok(()),
            other => Err(format!("parsed {other:?}")),
        }
    });
}

/// ADR-008: different tokens give codes spread over the whole range, so
/// a code reveals nothing useful about its token.
#[test]
fn adr008_signup_codes_spread() {
    let mut seen = std::collections::BTreeSet::new();
    for i in 0..2000u32 {
        let mut t = [0u8; 32];
        t[..4].copy_from_slice(&i.to_be_bytes());
        seen.insert(signup_code(&t));
    }
    assert!(seen.len() > 1990, "{} distinct of 2000", seen.len());
}

/// ADR-008, TH-26: only exactly 6 ASCII digits spell a code.
#[test]
fn adr008_signup_code_parse_refuses_other_spellings() {
    assert!(parse_signup_code("012345").is_some());
    for bad in [
        "",
        "12345",
        "1234567",
        "12345a",
        " 12345",
        "١٢٣٤٥٦",
        "12 345",
    ] {
        assert!(parse_signup_code(bad).is_none(), "{bad:?}");
    }
}
