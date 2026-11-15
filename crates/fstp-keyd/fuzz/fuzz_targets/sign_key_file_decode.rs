//! Fuzz target `sign_key_file_decode` of `fstp-keyd` (TH-26, H-05, ADR-004
//! "Decided by Daniel, 2026-11-15 (late)"). Lane m3/erase-prod.
//!
//! Design checks: no panic; limits enforced.
//!
//! The structural decoder of a sign-key file reads its header and bounds
//! its sealed PKCS#8 document without a key. An accepted file is at most
//! the longest file, names a sign key whose handle reads back to the same
//! name, and seals 1 to `MAX_PKCS8_LEN` bytes. Every refusal has a short
//! display, so no error carries file bytes.

#![no_main]

use fstp_keyd::SignKeyName;
use fstp_keyd::sign_key::{MAX_PKCS8_LEN, MAX_SIGN_KEY_FILE_LEN, decode_sign_key_file};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = decode_sign_key_file(data);
    assert_eq!(
        format!("{first:?}"),
        format!("{:?}", decode_sign_key_file(data)),
        "not deterministic"
    );
    match first {
        Ok((name, sealed)) => {
            assert!(data.len() <= MAX_SIGN_KEY_FILE_LEN);
            assert!((1..=MAX_PKCS8_LEN).contains(&sealed));
            assert_eq!(SignKeyName::from_handle(&name.handle()), Some(name));
        }
        Err(e) => {
            let shown = e.to_string();
            assert!(!shown.is_empty() && shown.len() <= 512);
        }
    }
});
