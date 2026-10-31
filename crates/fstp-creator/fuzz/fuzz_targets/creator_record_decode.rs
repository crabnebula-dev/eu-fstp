//! Fuzz target `creator_record_decode` of `fstp-creator` (TH-26, H-05, M4 design section 9).
//!
//! Design checks: never panics; round trip. A decoded record encodes to
//! canonical JSON that decodes to the same record.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(record) = fstp_creator::decode_record(data) else {
        return;
    };
    let Ok(text) = fstp_creator::encode_record(&record) else {
        panic!("a decoded record has no canonical text");
    };
    match fstp_creator::decode_record(text.as_bytes()) {
        Ok(back) => assert_eq!(back, record, "round trip changed the record"),
        Err(e) => panic!("the encoded record does not decode: {e}"),
    }
});
