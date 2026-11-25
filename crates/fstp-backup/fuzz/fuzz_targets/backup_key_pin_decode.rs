//! Fuzz target `backup_key_pin_decode` of `fstp-backup` (F-044, TH-51,
//! ADR-012 record of lane m10/key-pin-reason).
//!
//! Design checks: no panic, and one spelling only: an accepted pin file
//! is 65 bytes and encodes back to the same bytes for its digest.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(digest) = fstp_backup::keypin::decode(data) {
        assert_eq!(data.len(), fstp_backup::keypin::PIN_LEN);
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(format!("{hex}\n").as_bytes(), data);
    }
});
