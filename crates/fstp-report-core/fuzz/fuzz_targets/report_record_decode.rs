//! Fuzz target `report_record_decode` of `fstp-report-core` (TH-26, I-23).
//!
//! Over arbitrary bytes taken as a stored `Report` envelope record:
//!
//! - decoding never panics;
//! - an accepted record encodes to canonical JSON that decodes to the same
//!   record, so the stored form has one spelling.

#![no_main]

use fstp_json::{FromJson, ToJson};
use fstp_report_core::ReportRecord;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(v) = fstp_json::parse(data) else {
        return;
    };
    let Ok(r) = ReportRecord::from_json(&v) else {
        return;
    };
    let text = r
        .to_json()
        .to_canonical()
        .expect("an accepted record has a canonical form");
    let back = fstp_json::parse(text.as_bytes()).expect("canonical JSON parses");
    assert_eq!(
        ReportRecord::from_json(&back).ok(),
        Some(r),
        "the record changed over its stored form"
    );
});
