//! Fuzz target `usage_record_decode` of `fstp-custody` (ADR-004
//! "Reconciliation").
//!
//! Design checks: no panic, and an accepted record re-encodes byte for
//! byte. A damage marker decodes as one and is never a record.

#![no_main]

use fstp_custody::usage::{UsageEntry, decode_entry, encode_record};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    match decode_entry(data) {
        Ok(UsageEntry::Record(r)) => {
            assert_eq!(&encode_record(&r)[..], data, "not one spelling");
        }
        Ok(UsageEntry::Damaged { index }) => {
            assert_eq!(data.len(), 9, "a marker of another length");
            assert_eq!(data.get(1..), Some(&index.to_be_bytes()[..]), "marker index");
        }
        Err(e) => assert!(!format!("{e:?}").is_empty()),
    }
});
