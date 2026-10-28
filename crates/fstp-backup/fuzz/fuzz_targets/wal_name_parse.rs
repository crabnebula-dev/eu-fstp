//! Fuzz target `wal_name_parse` of `fstp-backup` (TH-26, H-05, M3 design section 15).
//!
//! Design checks: no panic.
//!
//! W0 skeleton. The code under test is a stub that refuses every input
//! with a typed `NotImplemented` error. Until lane W2k lands it, the
//! target checks only that no input panics and that a refusal formats.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let shown = format!("{:?}", fstp_backup::parse_wal_name(&text));
    assert!(!shown.is_empty());
});
