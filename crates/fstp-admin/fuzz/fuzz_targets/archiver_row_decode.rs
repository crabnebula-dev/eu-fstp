//! Fuzz target `archiver_row_decode` (ADR-012 record of lane
//! m10/backup-health): the one line of the WAL archive query that
//! `fstp-admin status` reads from each cluster.
//!
//! Design checks: no panic, and one spelling only: an accepted line
//! writes back to the same text.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data)
        && let Some(a) = fstp_admin::archive::parse_row(text)
    {
        assert_eq!(fstp_admin::archive::row_text(&a), text);
    }
});
