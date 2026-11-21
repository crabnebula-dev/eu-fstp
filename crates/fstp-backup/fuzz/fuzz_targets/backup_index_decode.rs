//! Fuzz target `backup_index_decode` of `fstp-backup` (TH-26, H-05,
//! ADR-012 record of lane L10).
//!
//! Design checks: no panic, and one spelling only: the accepted lines
//! encode back to the same bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(entries) = fstp_backup::index::decode(data) {
        let text: String = entries
            .iter()
            .map(fstp_backup::index::encode_line)
            .collect();
        assert_eq!(text.as_bytes(), data);
    }
});
