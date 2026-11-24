//! Fuzz target `df_available_decode` (ADR-012 record of lane
//! m10/backup-health): the output of `df -Pk` that the restore drill
//! reads before it restores anything.
//!
//! Design checks: no panic, deterministic, and an accepted output names
//! an available size that is one of its own decimal fields.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let first = fstp_admin::drill::parse_df(text);
        assert_eq!(first, fstp_admin::drill::parse_df(text), "not deterministic");
        if let Some(n) = first {
            assert!(
                text.split_whitespace().any(|f| f == n.to_string()),
                "a size not in the text"
            );
        }
    }
});
