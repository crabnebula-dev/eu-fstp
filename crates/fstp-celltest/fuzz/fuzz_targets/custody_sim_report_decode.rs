//! Fuzz target `custody_sim_report_decode` of `fstp-celltest` (I-80, lane
//! m3/custody-decisions).
//!
//! Design check: no panic. The decoder is a test-only parser, but the I-80
//! scans take their needles from what it accepts, so an accepted input
//! must also re-encode to itself:
//!
//! - the input is a whole number of records;
//! - encoding the records gives back the input, byte for byte;
//! - decoding is deterministic.

#![no_main]

use fstp_celltest::custody_sim::report::{RECORD_LEN, Record, decode};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(records) = decode(data) else {
        return;
    };
    assert_eq!(records.len() * RECORD_LEN, data.len(), "a partial record");
    let encoded: Vec<u8> = records.iter().flat_map(Record::encode).collect();
    assert_eq!(encoded, data, "an accepted report does not re-encode");
    assert_eq!(
        decode(data).ok(),
        Some(records),
        "decoding is not deterministic"
    );
});
