//! Fuzz target `backup_index_decode` of `fstp-backup` (TH-26, H-05,
//! ADR-012 records of lanes L10 and m10/backup-format).
//!
//! Design checks: no panic, and one spelling only: the accepted lines,
//! of four or six fields, encode back to the same bytes, and the entries
//! are those of the lines.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let lines = fstp_backup::index::decode_lines(data);
    let entries = fstp_backup::index::decode(data);
    assert_eq!(lines.is_ok(), entries.is_ok());
    if let (Ok(lines), Ok(entries)) = (lines, entries) {
        let text: String = lines
            .iter()
            .map(fstp_backup::index::encode_index_line)
            .collect();
        assert_eq!(text.as_bytes(), data);
        assert_eq!(lines.iter().map(|l| l.entry).collect::<Vec<_>>(), entries);
    }
});
