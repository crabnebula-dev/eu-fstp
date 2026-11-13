//! Fuzz target `wal_name_parse` of `fstp-backup` (TH-26, H-05, M3 design section 15).
//!
//! Design checks: no panic, and one spelling only: a name that parses
//! spells back to the same bytes (ADR-012 "Object names", lane F-ERASE).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    match fstp_backup::parse_wal_name(&text) {
        Ok(name) => assert_eq!(name.file_name(), text),
        Err(e) => assert!(!e.to_string().is_empty()),
    }
});
