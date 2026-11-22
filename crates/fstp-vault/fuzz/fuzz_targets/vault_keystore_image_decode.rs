//! Fuzz target `vault_keystore_image_decode` of `fstp-vault` (H-05,
//! ADR-012 record of lane L17).
//!
//! Design checks: no panic, and one spelling only: an accepted image
//! encodes back to the same bytes. A refusal names a rule and never
//! quotes the input (R-NF-02).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    match fstp_vault::snapshot::decode_image(data) {
        Ok((cell, rows)) => {
            assert_eq!(
                fstp_vault::snapshot::encode_image(&cell, &rows).unwrap(),
                data,
                "a second spelling of a keystore image"
            );
        }
        Err(e) => {
            let shown = format!("{e:?}");
            assert!(shown.len() < 80, "an error quotes input: {shown}");
        }
    }
});
