//! Fuzz target `anon_draft_decode` of `fstp-api-core` (ADR-032, TH-26,
//! R-NF-08).
//!
//! `anon::Draft::decode` opens the sealed text of an anonymous draft, and
//! `anon::Token::parse` reads the token of a resume link:
//!
//! - No input panics.
//! - A decoded draft fits its limits and survives its own encoding: it
//!   encodes, and the encoding decodes to the same draft.
//! - A parsed token writes back to the same 64 characters, and its
//!   `Debug` text shows none of them.

#![no_main]

use fstp_api_core::anon::{Draft, Token};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Some(d) = Draft::decode(data) {
        assert!(d.fits());
        let again = d.encode().expect("a decoded draft encodes");
        assert_eq!(Draft::decode(&again), Some(d));
    }
    if let Ok(s) = std::str::from_utf8(data)
        && let Some(t) = Token::parse(s)
    {
        assert_eq!(t.hex(), s);
        assert_eq!(format!("{t:?}"), "Token(..)");
    }
});
