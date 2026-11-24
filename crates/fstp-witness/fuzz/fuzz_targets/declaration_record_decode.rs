//! Fuzz target `declaration_record_decode` of `fstp-witness` (TH-26,
//! I-24, ADR-012 record of lane m10/declared-restore).
//!
//! Checks, for the one layout of
//! `fstp_witness::message::encode_declaration_record`:
//!
//! - no panic, and decoding is deterministic.
//! - an accepted record re-encodes byte for byte (round trip).
//! - neither the input without its last byte nor the input with one more
//!   byte decodes.
//! - a decoded window never ends before its head, and the bytes never
//!   decode as a witness message, so no connection carries one.

#![no_main]

use fstp_witness::decode_witness_message;
use fstp_witness::message::{decode_declaration_record, encode_declaration_record};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = decode_declaration_record(data);
    assert_eq!(first, decode_declaration_record(data), "not deterministic");
    let Ok((cell, chain, d)) = first else {
        return;
    };
    assert_eq!(
        encode_declaration_record(cell, chain, &d).as_deref(),
        Ok(data),
        "not one spelling"
    );
    assert!(
        d.fields.lost_to >= d.fields.head.0,
        "a window before its head"
    );
    assert!(d.fields.witness_seq >= 1, "witness sequence 0");
    assert!(
        decode_witness_message(data).is_err(),
        "a declaration travels"
    );
    if let Some((_, shorter)) = data.split_last() {
        assert!(decode_declaration_record(shorter).is_err(), "a cut decodes");
    }
    let mut longer = data.to_vec();
    longer.push(0);
    assert!(
        decode_declaration_record(&longer).is_err(),
        "trailing bytes"
    );
});
