//! Fuzz target `backup_key_file_decode` of `fstp-backup` (TH-26, H-05,
//! ADR-012 records of lanes L10, L16 and L17).
//!
//! Design checks: no panic, and one spelling only: an accepted file
//! encodes back to the same bytes. No input decodes as two kinds of key
//! file: a group key file, a second custodian's key file and the two
//! snapshot key files each have their own magic.

#![no_main]

use fstp_backup::keyfile::{self, FileKind};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut accepted = 0;
    for kind in FileKind::ALL {
        if let Ok(f) = keyfile::decode_kind(data, kind) {
            accepted += 1;
            assert_eq!(f.kind, kind);
            assert_eq!(keyfile::encode(&f).unwrap(), data);
            let _ = f.public_key();
            let _ = f.root();
        }
    }
    assert!(accepted <= 1);
});
