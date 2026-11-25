//! Fuzz target `backup_custodian_decode` of `fstp-backup` (TH-26, H-05,
//! ADR-012 records of lanes L16 and m10/backup-followups).
//!
//! Design checks: no panic; one spelling only.
//!
//! The input feeds the decoders of the second custodian: the request
//! file, the plaintext of an escrow and, since lane m10/backup-followups,
//! the published key file. An accepted request encodes back to the
//! input. An accepted escrow plaintext has the fixed length, and its
//! secret's public half is the public key it names. An accepted published
//! key file encodes back to the input, and its key file decodes or not
//! without a panic.

#![no_main]

use fstp_backup::custodian::{
    ESCROW_PLAIN_LEN, decode_escrow_plain, decode_published, decode_request, encode_published,
    encode_request,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok((file, tag)) = decode_published(data) {
        assert_eq!(encode_published(file, &tag).unwrap(), data);
        let _ = fstp_backup::keyfile::decode(file);
    }
    if let Ok(r) = decode_request(data) {
        assert_eq!(encode_request(&r), data);
    }
    if let Ok(p) = decode_escrow_plain(data) {
        assert_eq!(data.len(), ESCROW_PLAIN_LEN);
        assert_eq!(p.secret.public().to_bytes(), p.public);
    }
});
