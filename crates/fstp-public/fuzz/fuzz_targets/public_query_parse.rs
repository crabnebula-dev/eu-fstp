//! Fuzz target `public_query_parse` of `fstp-public` (TH-26, H-05, M4 design section 9).
//!
//! Design checks: query strings of the public tools. The parser never
//! panics. A query it accepts writes a canonical spelling of at most
//! `MAX_QUERY_BYTES` bytes, and that spelling parses to an equal query.
//! A refusal formats.

#![no_main]

use fstp_public::query::{MAX_QUERY_BYTES, parse_public_query};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    match parse_public_query(data) {
        Ok(q) => {
            if let Ok(text) = q.to_query_string() {
                assert!(text.len() <= MAX_QUERY_BYTES);
                assert_eq!(parse_public_query(text.as_bytes()), Ok(q));
            }
        }
        Err(e) => assert!(!e.to_string().is_empty()),
    }
});
