//! Fuzz target `backup_custodian_decode` of `fstp-backup` (TH-26, H-05,
//! ADR-012 record of lane L16).
//!
//! Design checks: no panic; one spelling only.
//!
//! The input feeds the two decoders of the second custodian: the request
//! file and the plaintext of an escrow. An accepted request encodes back
//! to the input. An accepted escrow plaintext has the fixed length, and
//! its secret's public half is the public key it names.

#![no_main]

use fstp_backup::custodian::{
    ESCROW_PLAIN_LEN, decode_escrow_plain, decode_request, encode_request,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(r) = decode_request(data) {
        assert_eq!(encode_request(&r), data);
    }
    if let Ok(p) = decode_escrow_plain(data) {
        assert_eq!(data.len(), ESCROW_PLAIN_LEN);
        assert_eq!(p.secret.public().to_bytes(), p.public);
    }
});
