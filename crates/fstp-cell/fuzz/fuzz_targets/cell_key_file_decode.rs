//! Fuzz target `cell_key_file_decode` of `fstp-cell` (ADR-004 record of
//! lane L4, I-80, R-NF-02).
//!
//! `fstp_cell::keyfile::decode_key_file` reads the sealed cell key file,
//! and `decode_body` its plain body once opened.
//!
//! - No input panics, and every refusal formats without the input.
//! - An accepted file re-encodes to the same bytes.
//! - An accepted body re-encodes to the same bytes, holds 1 to
//!   `MAX_GENERATIONS` generations with increasing indexes and distinct
//!   data key ids, and draws a next generation above them all.
//! - The input split at its first byte is tried as both forms, so the
//!   body decoder is reached without a valid file around it.

#![no_main]

use fstp_cell::keyfile;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(f) = keyfile::decode_key_file(data) {
        assert_eq!(
            keyfile::encode_key_file(&f).as_deref().ok(),
            Some(data),
            "the key file does not re-encode"
        );
        assert!(!format!("{f:?}").is_empty());
    } else if let Err(e) = keyfile::decode_key_file(data) {
        assert!(!format!("{e:?} {e}").is_empty());
    }
    let body = data.get(1..).unwrap_or_default();
    for bytes in [data, body] {
        let Ok(mut b) = keyfile::decode_body(bytes) else {
            continue;
        };
        let again = keyfile::encode_body(&b).expect("an accepted body encodes");
        assert_eq!(&again[..], bytes, "the body does not re-encode");
        assert!(!b.generations.is_empty() && b.generations.len() <= keyfile::MAX_GENERATIONS);
        for w in b.generations.windows(2) {
            assert!(w[0].key_ix < w[1].key_ix, "generations out of order");
        }
        let top = b.generations.iter().map(|g| g.key_ix).max();
        if b.next_generation().is_ok() {
            let new = b.generations.last().expect("a generation");
            assert!(Some(new.key_ix) > top, "a generation index was reused");
            let deks = b.generations.iter().filter(|g| g.dek == new.dek).count();
            assert_eq!(deks, 1, "a data key id was reused");
        }
    }
});
