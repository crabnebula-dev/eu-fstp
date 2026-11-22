//! Fuzz target `anon_draft_body_decode` of `fstp-cell` (ADR-032, TH-26,
//! H-05, I-18, R-NF-02).
//!
//! The three body decoders of the anonymous draft routes
//! (`fstp_cell::routes::drafts`) over the same bytes:
//!
//! - No input panics, and every refusal formats.
//! - Each decoder is a function of the input: the same bytes give the
//!   same answer twice.
//! - An accepted save holds a draft within its limits, and the token of
//!   an accepted body never shows in its `Debug` text.
//! - No body is accepted by two decoders, since their member sets differ.
//!
//! The seeds under `fuzz/seeds/anon_draft_body_decode` are accepted
//! bodies of each route.

#![no_main]

use fstp_cell::routes::drafts::{decode_save, decode_start, decode_token};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let start = decode_start(data);
    let token = decode_token(data);
    let save = decode_save(data);
    assert_eq!(start, decode_start(data));
    assert_eq!(token, decode_token(data));
    assert_eq!(save, decode_save(data));
    for e in [
        start.as_ref().err(),
        token.as_ref().err(),
        save.as_ref().err(),
    ]
    .into_iter()
    .flatten()
    {
        assert!(!e.to_string().is_empty());
    }
    if let Ok(t) = &token {
        assert_eq!(format!("{t:?}"), "Token(..)");
    }
    if let Ok((t, d)) = &save {
        assert!(d.fits(), "an accepted save holds a draft over its limits");
        assert_eq!(format!("{t:?}"), "Token(..)");
    }
    let accepted = [start.is_ok(), token.is_ok(), save.is_ok()]
        .into_iter()
        .filter(|ok| *ok)
        .count();
    assert!(accepted <= 1, "one body decoded for two routes");
});
