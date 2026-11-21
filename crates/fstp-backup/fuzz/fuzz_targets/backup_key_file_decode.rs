//! Fuzz target `backup_key_file_decode` of `fstp-backup` (TH-26, H-05,
//! ADR-012 record of lane L10).
//!
//! Design checks: no panic, and one spelling only: an accepted file
//! encodes back to the same bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(f) = fstp_backup::keyfile::decode(data) {
        assert_eq!(fstp_backup::keyfile::encode(&f).unwrap(), data);
        let _ = f.public_key();
    }
});
