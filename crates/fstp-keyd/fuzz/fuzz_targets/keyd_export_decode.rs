//! Fuzz target `keyd_export_decode` of `fstp-keyd` (TH-26, H-05, ADR-004
//! record of lane L16).
//!
//! Design checks: no panic; one spelling only; limits enforced.
//!
//! The input feeds the three decoders of the off-host copy: the clear
//! header of a copy, the opened body, and the register of copies. An
//! accepted header encodes back to the input's first 50 bytes. An
//! accepted body or register encodes back to the input. Every refusal has
//! a short display, so no error carries input bytes.

#![no_main]

use fstp_keyd::export::{
    EXPORT_HEADER_LEN, MAX_EXPORT_LEN, decode_export, decode_export_body, decode_register,
    encode_export_body, encode_register_record,
};
use libfuzzer_sys::fuzz_target;

fn short<E: std::fmt::Display>(e: &E) {
    let shown = e.to_string();
    assert!(!shown.is_empty() && shown.len() <= 512);
}

fuzz_target!(|data: &[u8]| {
    match decode_export(data) {
        Ok((header, rest)) => {
            assert!(data.len() <= MAX_EXPORT_LEN);
            assert_eq!(&header.encode()[..], &data[..EXPORT_HEADER_LEN]);
            assert_eq!(rest.len() + EXPORT_HEADER_LEN, data.len());
        }
        Err(e) => short(&e),
    }
    match decode_export_body(data) {
        Ok(files) => assert_eq!(encode_export_body(&files).unwrap(), data),
        Err(e) => short(&e),
    }
    match decode_register(data) {
        Ok(records) => {
            let mut again = Vec::new();
            for r in &records {
                again.extend(encode_register_record(r).unwrap());
            }
            assert_eq!(again, data);
        }
        Err(e) => short(&e),
    }
});
