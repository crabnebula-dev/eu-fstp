//! Fuzz target `wal_name_parse` of `fstp-backup` (TH-26, H-05, M3 design section 15).
//!
//! Design checks: no panic, and one spelling only: a name that parses
//! spells back to the same bytes (ADR-012 "Object names", lane F-ERASE).
//! Lane L10 adds the archive name parser, whose accepted names are
//! object key safe, and the start segment of a `backup_label`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    match fstp_backup::parse_wal_name(&text) {
        Ok(name) => assert_eq!(name.file_name(), text),
        Err(e) => assert!(!e.to_string().is_empty()),
    }
    if fstp_backup::parse_archive_name(&text).is_ok() {
        assert!(fstp_backup::s3::key_ok(&format!("c/wal/{text}")));
    }
    // Lane m10/backup-pitr: the start location parses with the segment,
    // and the segment is the one the start parser returns.
    if let Ok((seg, _lsn)) = fstp_backup::backup_label_location(data) {
        assert_eq!(fstp_backup::backup_label_start(data).ok(), Some(seg));
    }
    if let Ok(start) = fstp_backup::backup_label_start(data) {
        for size in [1u64 << 20, 16 << 20, 1 << 30] {
            if let Some(next) = start.next(size) {
                assert!(next > start);
            }
        }
    }
});
