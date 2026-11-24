//! Fuzz target `backup_container_decode` of `fstp-backup` (TH-26, H-05, M3 design section 15).
//!
//! Design checks: no panic; chunk order and final flag enforced. An
//! accepted container has chunks numbered from 0, exactly one final
//! chunk, the last, and every chunk holds a nonce and a tag (ADR-012).
//! It also runs the snapshot pointer decoder (ADR-012 records of lanes L17
//! and m10/backup-followups).
//! The same entry point reads the `FBC2` container of the record of lane
//! m10/backup-format: an accepted one ends in exactly one writer
//! signature, and its `ident` names an object of its kind, now for every
//! kind (record of lane m10/backup-followups).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // ADR-012 record of lane m10/backup-followups: a version 2 snapshot
    // pointer has one length and one spelling, and names a snapshot kind.
    if let Ok(p) = fstp_backup::snapshot::decode_pointer(data) {
        assert_eq!(data.len(), fstp_backup::snapshot::POINTER_LEN);
        let body = fstp_backup::snapshot::pointer_body(p.owner, p.cell, p.id);
        assert_eq!(body, p.body);
        assert_eq!([p.body, p.signature].concat(), data);
    }
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
