//! Fuzz target `backup_key_file_decode` of `fstp-backup` (TH-26, H-05,
//! ADR-012 records of lanes L10, L16, L17 and m10/backup-format).
//!
//! Design checks: no panic, and one spelling only: an accepted file
//! encodes back to the same bytes. No input decodes as two kinds of key
//! file: the version 2 and version 1 group key files, a second
//! custodian's key file and the two snapshot key files each have their
//! own magic. The writer key file `"FBW1"` decodes in one spelling too,
//! and an accepted version 2 file's binding check never panics.

#![no_main]

use fstp_backup::keyfile::{self, FileKind};
use fstp_backup::writer::WriterKey;
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
            assert_eq!(f.binding.is_some(), kind.bound());
            let _ = f.check_binding();
        }
    }
    assert!(accepted <= 1);
    if let Ok(w) = WriterKey::decode(data) {
        assert_eq!(accepted, 0);
        assert_eq!(&w.encode().unwrap()[..], data);
    }
});
