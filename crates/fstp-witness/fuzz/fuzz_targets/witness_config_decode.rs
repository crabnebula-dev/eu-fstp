//! Fuzz target `witness_config_decode` of `fstp-witness` (TH-26, ADR-010
//! open point 6, ADR-004 part 2). Lane F-CP.
//!
//! Checks, for the process configuration and the receipt key file:
//!
//! - no panic, and both decoders are deterministic.
//! - an accepted key file re-encodes byte for byte (round trip), and the
//!   file without its last byte or with one more byte is refused.
//! - an accepted configuration names exactly one store for its mode.

#![no_main]

use fstp_witness::config::{
    WitnessStore, decode_config, decode_receipt_key_file, encode_receipt_key_file,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let config = decode_config(data);
    assert_eq!(config, decode_config(data), "not deterministic");
    if let Ok(c) = &config {
        match &c.store {
            WitnessStore::Database { port, .. } => assert_ne!(*port, 0, "port 0 accepted"),
            WitnessStore::Files { dir } => {
                assert!(!dir.as_os_str().is_empty(), "an empty store dir accepted");
            }
        }
    }
    let key = decode_receipt_key_file(data);
    assert_eq!(
        key.as_ref().ok().map(encode_receipt_key_file),
        decode_receipt_key_file(data)
            .as_ref()
            .ok()
            .map(encode_receipt_key_file),
        "not deterministic"
    );
    let Ok(f) = key else {
        return;
    };
    assert_eq!(
        encode_receipt_key_file(&f).ok().as_deref(),
        Some(data),
        "an accepted key file does not re-encode to its input"
    );
    if let Some((_, head)) = data.split_last() {
        assert!(
            decode_receipt_key_file(head).is_err(),
            "a cut file accepted"
        );
    }
    let mut longer = data.to_vec();
    longer.push(0);
    assert!(
        decode_receipt_key_file(&longer).is_err(),
        "a trailing byte accepted"
    );
});
