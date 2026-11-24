//! Fuzz target `chain_head_parse` (ADR-012 record of lane
//! m10/declared-restore): the head of a restored chain as `psql` prints
//! it for `fstp-admin restore`.
//!
//! Design checks: no panic, and one spelling only: an accepted head
//! prints back to the same text.

#![no_main]

use fstp_admin::declare::{Head, parse_head};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    match parse_head(&text) {
        Some(Head::Empty) => assert!(text.is_empty()),
        Some(Head::At(n, link)) => assert_eq!(format!("{n} {link}"), text),
        None => {}
    }
});
