//! Fuzz target `restore_time_parse` (ADR-012 and ADR-028 records of lane
//! `m10/backup-pitr`): the time an operator gives `fstp-admin restore
//! --to`, and the times of the backup agent's index file.
//!
//! Design checks: no panic, and one spelling only: an accepted time spells
//! back to the same text, and a spelled time parses back to itself.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    if let Some(t) = fstp_admin::pitr::parse_time(&text) {
        assert_eq!(fstp_admin::pitr::format_time(t), text);
    }
    if let Some(bytes) = data.get(..8) {
        let mut n = [0u8; 8];
        n.copy_from_slice(bytes);
        let t = u64::from_be_bytes(n) % 253_402_300_800;
        assert_eq!(
            fstp_admin::pitr::parse_time(&fstp_admin::pitr::format_time(t)),
            Some(t)
        );
    }
    let _ = fstp_admin::pitr::index_times(&text);
});
