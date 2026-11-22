//! Fuzz target `backup_key_file_decode` of `fstp-backup` (TH-26, H-05,
//! ADR-012 records of lanes L10 and L16).
//!
//! Design checks: no panic, and one spelling only: an accepted file
//! encodes back to the same bytes. A group key file and a second
//! custodian's key file never decode as each other.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let group = fstp_backup::keyfile::decode(data);
    let custodian = fstp_backup::keyfile::decode_custodian(data);
    assert!(group.is_err() || custodian.is_err());
    for f in [group, custodian].into_iter().flatten() {
        assert_eq!(fstp_backup::keyfile::encode(&f).unwrap(), data);
        let _ = f.public_key();
    }
});
