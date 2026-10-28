//! Fuzz target `backup_container_decode` of `fstp-backup` (TH-26, H-05, M3 design section 15).
//!
//! Design checks: no panic; chunk order and final flag enforced.
//!
//! W0 skeleton. The code under test is a stub that refuses every input
//! with a typed `NotImplemented` error. Until lane W2k lands it, the
//! target checks only that no input panics and that a refusal formats.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let shown = format!("{:?}", fstp_backup::decode_container(data));
    assert!(!shown.is_empty());
});
