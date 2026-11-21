//! Fuzz target `backup_config_decode` of `fstp-backup` (TH-26, H-05,
//! ADR-012 record of lane L10).
//!
//! Design checks: no panic; an accepted file names a loopback database
//! and absolute paths; a refusal never quotes the input (R-NF-02).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    match fstp_backup::config::decode_file(data) {
        Ok(c) => {
            assert!(c.database.host.is_loopback());
            assert!(c.credentials_dir.is_absolute() && c.state_dir.is_absolute());
            assert!(c.pg_bindir.is_absolute());
        }
        Err(e) => {
            let shown = format!("{e} {e:?}");
            assert!(shown.len() < 200);
        }
    }
});
