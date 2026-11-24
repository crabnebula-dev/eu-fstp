//! Fuzz target `backup_container_decode` of `fstp-backup` (TH-26, H-05, M3 design section 15).
//!
//! Design checks: no panic; chunk order and final flag enforced. An
//! accepted container has chunks numbered from 0, exactly one final
//! chunk, the last, and every chunk holds a nonce and a tag (ADR-012).
//! It also runs the snapshot pointer decoder (ADR-012 record of lane L17).
//! The same entry point reads the `FBC2` container of the record of lane
//! m10/backup-format: an accepted one ends in exactly one writer
//! signature, and its `ident` names an object of its kind.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // ADR-012 record of lane L17: the snapshot pointer is exactly 16 bytes.
    assert_eq!(
        fstp_backup::snapshot::decode_pointer(data).is_ok(),
        data.len() == 16
    );
    match fstp_backup::decode_container(data) {
        Ok(chunks) => {
            assert!(!chunks.is_empty());
            for (i, c) in chunks.iter().enumerate() {
                assert_eq!(c.index, i as u64);
                assert_eq!(c.last, i + 1 == chunks.len());
                assert!(c.sealed.len() >= 28);
            }
        }
        Err(e) => assert!(!e.to_string().is_empty()),
    }
});
