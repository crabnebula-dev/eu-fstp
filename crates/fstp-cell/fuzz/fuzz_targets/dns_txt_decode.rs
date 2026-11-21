//! Fuzz target `dns_txt_decode` of `fstp-cell` (ADR-027): the in-house DNS
//! answer parser of the sending domain probe.
//!
//! Design checks: no panic on any bytes; at most `MAX_RECORDS` records;
//! no record longer than the message; and a question encodes for every
//! name the encoder accepts.

#![no_main]

use libfuzzer_sys::fuzz_target;

use fstp_cell::shell::dns::{MAX_RECORDS, decode_txt_response, txt_query};

fuzz_target!(|data: &[u8]| {
    let id = match data {
        [a, b, ..] => u16::from_be_bytes([*a, *b]),
        _ => 0,
    };
    if let Ok(records) = decode_txt_response(data, id) {
        assert!(records.len() <= MAX_RECORDS);
        assert!(records.iter().all(|r| r.len() <= data.len()));
    }
    if let Ok(name) = std::str::from_utf8(data)
        && let Ok(q) = txt_query(id, name)
    {
        assert!(q.len() >= 17);
    }
});
