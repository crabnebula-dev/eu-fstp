//! Fuzz target `contract_record_decode` of `fstp-contract` (TH-26, I-23,
//! I-30, R-NF-02).
//!
//! The input is read as JSON and decoded as a `Contract` envelope record.
//! A record that decodes must encode back to a value that decodes to the
//! same record, and folding it into an empty store must return a typed
//! result. The input is also read as a digest spelling.

#![no_main]

use fstp_contract::{ContractRecord, ContractStore, Digest, apply};
use fstp_json::{FromJson, ToJson, parse};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Some(d) = Digest::from_hex(s) {
            assert_eq!(d.hex(), s);
        }
    }
    let Ok(value) = parse(data) else {
        return;
    };
    let Ok(record) = ContractRecord::from_json(&value) else {
        return;
    };
    let back = ContractRecord::from_json(&record.to_json()).expect("a decoded record re-decodes");
    assert_eq!(back, record);
    let mut store = ContractStore::default();
    let _ = apply(&mut store, &record);
});
