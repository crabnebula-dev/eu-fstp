//! Fuzz target `backup_tar_label_decode` of `fstp-backup` (TH-26, H-05,
//! ADR-012 record of lane m10/backup-format, row "Start segment").
//!
//! Design checks: no panic. An accepted head starts with one 512-byte
//! header, and the label it gives lies inside the input right after it,
//! at most 64 KiB long. The start segment parser then runs on it.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(label) = fstp_backup::tar::backup_label(data) {
        assert!(label.len() <= fstp_backup::tar::MAX_LABEL_LEN);
        assert_eq!(
            data.get(fstp_backup::tar::BLOCK..fstp_backup::tar::BLOCK + label.len()),
            Some(label)
        );
        let _ = fstp_backup::backup_label_start(label);
    }
});
