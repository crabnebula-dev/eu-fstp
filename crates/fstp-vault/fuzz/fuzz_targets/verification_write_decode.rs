//! Fuzz target `verification_write_decode` of `fstp-vault` (R-ID-02, I-17,
//! ADR-004 record of lane L13b, row "Origin body").
//!
//! `decode_verification_write` reads the body a recorder posts with a
//! `write:verification_recorded` ticket on the vault origin. For every
//! input:
//!
//! - it never panics and is deterministic;
//! - an accepted body re-encodes to exactly its own bytes, so it has one
//!   spelling;
//! - the identity tuple of an accepted body starts with its label and is
//!   the same for the decoded and the re-decoded body.
//! - the host's identity file decoder (`decode_identity_file`), which
//!   takes any JSON spelling, never panics, and an accepted file
//!   re-encodes to a body the strict decoder takes.

#![no_main]

use fstp_vault::codec::{
    TUPLE_LABEL, decode_identity_file, decode_verification_write, encode_verification_write,
    identity_tuple,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let got = decode_verification_write(data);
    assert_eq!(
        got,
        decode_verification_write(data),
        "decoding is not deterministic"
    );
    if let Ok(w) = got {
        let bytes = encode_verification_write(&w).expect("an accepted body re-encodes");
        assert_eq!(bytes, data, "an accepted body has another spelling");
        let tuple = identity_tuple(&w.identity);
        assert!(tuple.starts_with(TUPLE_LABEL), "the tuple lost its label");
        let again = decode_verification_write(&bytes).expect("the re-encoding decodes");
        assert_eq!(identity_tuple(&again.identity), tuple);
    }
    if let Ok(e) = decode_identity_file(data) {
        let bytes = encode_verification_write(&e).expect("an accepted file re-encodes");
        assert_eq!(decode_verification_write(&bytes).as_ref(), Ok(&e));
    }
});
